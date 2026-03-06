//! Main database implementation for function metadata storage.

use crate::api::metrics::METRICS;
use crate::common::demangle::demangle;
use crate::common::{addr_off, addr_seg};
use crate::config::Config;
use crate::engine::{BinaryRefHit, EngineRuntime, IndexError, Record, SearchDocument, SearchHit, UpsertResult};
use crate::protocol::lumina::metadata::parse_metadata;

use super::failure_cache::FailureCache;
use super::types::{
    BinaryCompareItem, BinaryFacetSummary, BinarySummary, FuncLatest, OwnedPushContext,
    PushContext, QueryContext,
};

use log::*;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Main database handle for function metadata.
#[derive(Clone)]
pub struct Database {
    rt: Arc<EngineRuntime>,
    pub failure_cache: FailureCache,
}

impl Database {
    /// Open or create a database with the given configuration.
    pub async fn open(cfg: Arc<Config>) -> io::Result<Arc<Self>> {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;

        // Initialize metrics with current database stats
        let stats = rt.get_stats();
        if let Err(e) = METRICS.init(
            &rt.index_db,
            stats.indexed_funcs,
            stats.total_records,
            stats.storage_bytes,
            stats.search_docs,
            stats.unique_binaries,
        ) {
            warn!("Failed to initialize persistent metrics: {}", e);
        }

        Ok(Arc::new(Self {
            rt: Arc::new(rt),
            failure_cache: FailureCache::new(),
        }))
    }

    fn update_search_entry(&self, key: u128, name: &str, ts: u64) {
        self.update_search_entry_no_commit(key, name, ts);
        if let Err(e) = self.rt.search.commit() {
            log::warn!("failed to commit search index: {}", e);
        }
    }

    fn update_search_entry_no_commit(&self, key: u128, name: &str, ts: u64) {
        // Get basenames, but still index even if this fails
        let basenames = match self.rt.ctx_index.resolve_basenames_for_key(key) {
            Ok(b) => b,
            Err(e) => {
                log::debug!("no basenames for key {:032x}: {}", key, e);
                Vec::new()
            }
        };

        // Pre-compute demangled name
        let demangle_result = demangle(name);
        let (func_name_demangled, lang) = if demangle_result.demangled {
            (
                demangle_result.name,
                demangle_result.lang.unwrap_or("").to_string(),
            )
        } else {
            (String::new(), String::new())
        };

        let doc = SearchDocument {
            key,
            func_name: name.to_string(),
            func_name_demangled,
            lang,
            binary_names: basenames,
            ts,
        };
        if let Err(e) = self.rt.search.index_function_no_commit(&doc) {
            log::warn!("failed to update search index for key {:032x}: {}", key, e);
        }
    }

    fn commit_search_index(&self) {
        if let Err(e) = self.rt.search.commit() {
            log::warn!("failed to commit search index: {}", e);
        }
    }

    /// Get the latest version of a function by key.
    pub async fn get_latest(&self, key: u128) -> io::Result<Option<FuncLatest>> {
        let addr = self.rt.index.get(key);
        if addr == 0 {
            return Ok(None);
        }
        let seg_id = addr_seg(addr);
        let off = addr_off(addr);
        let reader = self
            .rt
            .segments
            .get_reader(seg_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "segment not found"))?;
        let rec = reader.read_at(off)?;
        if rec.flags & 0x01 == 0x01 {
            return Ok(None);
        }
        Ok(Some(FuncLatest {
            popularity: rec.popularity,
            len_bytes: rec.len_bytes,
            ts_sec: rec.ts_sec,
            name: rec.name,
            data: rec.data,
        }))
    }

    /// Push function metadata without context.
    pub async fn push(&self, items: &[(u128, u32, u32, &str, &[u8])]) -> io::Result<Vec<u32>> {
        let null_ctx = PushContext {
            md5: None,
            basename: None,
            hostname: None,
        };
        self.push_with_ctx(items, &null_ctx).await
    }

    /// Push function metadata with context information.
    pub async fn push_with_ctx(
        &self,
        items: &[(u128, u32, u32, &str, &[u8])],
        ctx: &PushContext<'_>,
    ) -> io::Result<Vec<u32>> {
        // Convert to owned data for spawn_blocking ('static requirement)
        let owned_items: Vec<(u128, u32, u32, String, Vec<u8>)> = items
            .iter()
            .map(|(k, p, l, n, d)| (*k, *p, *l, n.to_string(), d.to_vec()))
            .collect();
        let owned_ctx = OwnedPushContext {
            md5: ctx.md5,
            basename: ctx.basename.map(|s| s.to_string()),
            hostname: ctx.hostname.map(|s| s.to_string()),
        };
        let rt = self.rt.clone();

        // Move blocking sled I/O to dedicated thread pool
        tokio::task::spawn_blocking(move || Self::push_with_ctx_sync(&rt, &owned_items, &owned_ctx))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("spawn_blocking: {}", e)))?
    }

    /// Synchronous implementation of push_with_ctx (runs on blocking thread pool).
    fn push_with_ctx_sync(
        rt: &EngineRuntime,
        items: &[(u128, u32, u32, String, Vec<u8>)],
        ctx: &OwnedPushContext,
    ) -> io::Result<Vec<u32>> {
        let mut status = Vec::with_capacity(items.len());
        for (key, pop, _len_bytes_decl, name, data) in items.iter() {
            if name.len() > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "name too long (> u16::MAX)",
                ));
            }
            if data.len() > u32::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "data large (> u32::MAX)",
                ));
            }

            let old = rt.index.get(*key);

            if old != 0 {
                let seg_id = addr_seg(old);
                let off = addr_off(old);
                match rt.segments.get_reader(seg_id) {
                    Some(reader) => {
                        match reader.read_at(off) {
                            Ok(existing) => {
                                if existing.name == *name && existing.data == *data {
                                    status.push(2);
                                    // Still record context observation even if unchanged
                                    if let Some(md5) = ctx.md5 {
                                        let ts = now_ts_sec();
                                        let vid = version_id(*key, name, data);
                                        let _ = rt.ctx_index.record_binary_meta(
                                            md5,
                                            ctx.basename.as_deref().unwrap_or(""),
                                            ctx.hostname.as_deref().unwrap_or(""),
                                            ts,
                                        );
                                        let _ = rt.ctx_index.record_key_observation(
                                            *key,
                                            md5,
                                            Some(vid),
                                            ts,
                                            ctx.basename.as_deref(),
                                        );
                                    }
                                    Self::update_search_entry_no_commit_static(
                                        rt,
                                        *key,
                                        name,
                                        existing.ts_sec,
                                    );
                                    continue;
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "Failed to read existing record at seg={}, off={}: {}",
                                    seg_id,
                                    off,
                                    e
                                );
                            }
                        }
                    }
                    None => {
                        log::warn!("Segment {} not found for existing record", seg_id);
                    }
                }
            }

            let rec = Record {
                key: *key,
                ts_sec: now_ts_sec(),
                prev_addr: old,
                len_bytes: data.len() as u32,
                popularity: *pop,
                name: name.to_string(),
                data: data.to_vec(),
                flags: 0,
            };
            let addr = rt.segments.append(&rec)?;
            match rt.index.upsert(*key, addr) {
                Ok(UpsertResult::Inserted) => {
                    status.push(1);
                    METRICS.inc_indexed_funcs();
                    METRICS.inc_total_records();
                }
                Ok(UpsertResult::Replaced(_)) => {
                    status.push(0);
                    METRICS.inc_total_records();
                }
                Err(IndexError::Full) => {
                    METRICS.inc_append_failures();
                    return Err(io::Error::new(io::ErrorKind::Other, "index full"));
                }
                Err(IndexError::Io(e)) => {
                    METRICS.inc_append_failures();
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("index io error: {}", e),
                    ));
                }
            }

            if let Some(md5) = ctx.md5 {
                let ts = rec.ts_sec;
                let vid = version_id(*key, name, data);
                let _ = rt.ctx_index.record_binary_meta(
                    md5,
                    ctx.basename.as_deref().unwrap_or(""),
                    ctx.hostname.as_deref().unwrap_or(""),
                    ts,
                );
                let _ = rt.ctx_index.record_key_observation(
                    *key,
                    md5,
                    Some(vid),
                    ts,
                    ctx.basename.as_deref(),
                );
            }
            Self::update_search_entry_no_commit_static(rt, *key, name, rec.ts_sec);
        }
        // Commit all search index changes at once
        if let Err(e) = rt.search.commit() {
            log::warn!("failed to commit search index: {}", e);
        }
        Ok(status)
    }

    fn update_search_entry_no_commit_static(rt: &EngineRuntime, key: u128, name: &str, ts: u64) {
        // Get basenames, but still index even if this fails
        let basenames = match rt.ctx_index.resolve_basenames_for_key(key) {
            Ok(b) => b,
            Err(e) => {
                log::debug!("no basenames for key {:032x}: {}", key, e);
                Vec::new()
            }
        };

        // Pre-compute demangled name
        let demangle_result = demangle(name);
        let (func_name_demangled, lang) = if demangle_result.demangled {
            (
                demangle_result.name,
                demangle_result.lang.unwrap_or("").to_string(),
            )
        } else {
            (String::new(), String::new())
        };

        let doc = SearchDocument {
            key,
            func_name: name.to_string(),
            func_name_demangled,
            lang,
            binary_names: basenames,
            ts,
        };
        if let Err(e) = rt.search.index_function_no_commit(&doc) {
            log::warn!("failed to update search index for key {:032x}: {}", key, e);
        }
    }

    /// Delete function metadata by keys.
    pub async fn delete_keys(&self, keys: &[u128]) -> io::Result<u32> {
        let mut deleted = 0u32;
        for &key in keys {
            let old = self.rt.index.get(key);
            let rec = Record {
                key,
                ts_sec: now_ts_sec(),
                prev_addr: old,
                len_bytes: 0,
                popularity: 0,
                name: String::new(),
                data: Vec::new(),
                flags: 0x01,
            };
            let addr = self.rt.segments.append(&rec)?;
            let _ = self.rt.index.upsert(key, addr);
            let _ = self.rt.search.delete(key);
            if old != 0 {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// Get function history by key.
    pub async fn get_history(
        &self,
        key: u128,
        mut limit: u32,
    ) -> io::Result<Vec<(u64, String, Vec<u8>)>> {
        if limit == 0 {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut addr = self.rt.index.get(key);
        while addr != 0 && limit > 0 {
            let r = self
                .rt
                .segments
                .get_reader(addr_seg(addr))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "seg"))?;
            let rec = r.read_at(addr_off(addr))?;
            if rec.flags & 0x01 == 0 {
                out.push((rec.ts_sec, rec.name, rec.data));
                limit -= 1;
            }
            addr = rec.prev_addr;
        }
        Ok(out)
    }

    /// Search functions by query string. Returns up to `limit` results.
    pub async fn search_functions(&self, query: &str, limit: usize) -> io::Result<Vec<SearchHit>> {
        let mut hits = self.rt.search.search(query, limit)?;
        self.attach_binary_refs(&mut hits)?;
        Ok(hits)
    }

    /// Search functions with pagination. Returns (results, total_count).
    pub async fn search_functions_paginated(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        let (mut hits, total) = self.rt.search.search_paginated(query, offset, limit)?;
        self.attach_binary_refs(&mut hits)?;
        Ok((hits, total))
    }

    pub async fn get_popular_functions(&self, limit: usize) -> io::Result<Vec<FuncLatest>> {
        let top_keys = self.rt.ctx_index.get_top_popular_keys(limit)?;
        let mut results = Vec::with_capacity(top_keys.len());

        for (key, pop) in top_keys {
            if let Ok(Some(mut func)) = self.get_latest(key).await {
                // Overwrite the segment popularity with the live context popularity
                func.popularity = pop;
                results.push(func);
            }
        }

        Ok(results)
    }

    /// Get binary basenames associated with a function key.
    pub fn get_basenames_for_key(&self, key: u128) -> io::Result<Vec<String>> {
        self.rt.ctx_index.resolve_basenames_for_key(key)
    }

    /// Get structured binary references associated with a function key.
    pub fn get_binary_refs_for_key(&self, key: u128, limit: usize) -> io::Result<Vec<BinaryRefHit>> {
        Ok(self
            .rt
            .ctx_index
            .get_binary_refs_for_key(key, limit)?
            .into_iter()
            .map(|meta| BinaryRefHit {
                md5_hex: hex_md5(&meta.md5),
                short_id: short_md5(&meta.md5),
                basename: meta.basename.clone(),
                display_name: format!("{} · {}", meta.basename, short_md5(&meta.md5)),
            })
            .collect())
    }

    pub async fn search_binaries_paginated(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<BinarySummary>, usize)> {
        let norm = query.trim().to_ascii_lowercase();
        if norm.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let mut matches = self.rt.ctx_index.search_binary_meta(query)?;
        matches.sort_by(|a, b| {
            score_binary_meta(b, &norm)
                .partial_cmp(&score_binary_meta(a, &norm))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.last_seen_ts.cmp(&a.last_seen_ts))
        });
        let total = matches.len();
        let rows = matches
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|meta| binary_summary_from_meta(&meta, score_binary_meta(&meta, &norm)))
            .collect();
        Ok((rows, total))
    }

    pub async fn get_binary_summary(&self, md5: [u8; 16]) -> io::Result<Option<BinarySummary>> {
        Ok(self
            .rt
            .ctx_index
            .get_binary_meta(&md5)?
            .map(|meta| binary_summary_from_meta(&meta, 0.0)))
    }

    pub async fn get_binary_function_hits(
        &self,
        md5: [u8; 16],
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        let (entries, total) = self.rt.ctx_index.get_binary_function_entries(&md5, offset, limit)?;
        let mut entries = entries;
        entries.sort_by(|a, b| b.obs_count.cmp(&a.obs_count).then_with(|| b.last_ts_sec.cmp(&a.last_ts_sec)));
        let mut hits = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(func) = self.get_latest(entry.key).await? {
                let demangle_result = demangle(&func.name);
                let (func_name_demangled, lang) = if demangle_result.demangled {
                    (
                        Some(demangle_result.name),
                        demangle_result.lang.map(|s| s.to_string()),
                    )
                } else {
                    (None, None)
                };
                hits.push(SearchHit {
                    key_hex: format!("{:032x}", entry.key),
                    func_name: func.name,
                    func_name_demangled,
                    lang,
                    binary_names: self.get_basenames_for_key(entry.key).unwrap_or_default(),
                    binaries: self.get_binary_refs_for_key(entry.key, 12).unwrap_or_default(),
                    ts: func.ts_sec,
                    score: entry.obs_count as f32,
                });
            }
        }
        Ok((hits, total))
    }

    pub async fn get_binary_overlap(
        &self,
        md5: [u8; 16],
        limit: usize,
    ) -> io::Result<Vec<(BinarySummary, u64)>> {
        let seed_keys = self.rt.ctx_index.get_binary_function_keys(&md5, 4096)?;
        let mut overlap: HashMap<[u8; 16], u64> = HashMap::new();
        for key in seed_keys {
            for meta in self.rt.ctx_index.get_binary_refs_for_key(key, usize::MAX)? {
                if meta.md5 == md5 {
                    continue;
                }
                *overlap.entry(meta.md5).or_insert(0) += 1;
            }
        }
        let mut rows: Vec<(BinarySummary, u64)> = Vec::new();
        for (other_md5, shared) in overlap.into_iter() {
            if let Some(meta) = self.rt.ctx_index.get_binary_meta(&other_md5)? {
                rows.push((binary_summary_from_meta(&meta, shared as f32), shared));
            }
        }
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.last_seen_ts.cmp(&a.0.last_seen_ts)));
        rows.truncate(limit);
        Ok(rows)
    }

    pub async fn get_binary_facets(&self, md5: [u8; 16], limit: usize) -> io::Result<BinaryFacetSummary> {
        if let Some(meta) = self.rt.ctx_index.get_binary_meta(&md5)? {
            if let Some(cached) = self.rt.ctx_index.get_binary_facets(&md5)? {
                if cached.function_count == meta.function_count && cached.cached_at_ts >= meta.last_seen_ts {
                    return Ok(cached);
                }
            }
        }
        let keys = self.rt.ctx_index.get_binary_function_keys(&md5, limit)?;
        let mut out = BinaryFacetSummary {
            function_count: keys.len() as u64,
            ..BinaryFacetSummary::default()
        };
        for key in keys {
            let Some(func) = self.get_latest(key).await? else {
                continue;
            };
            let parsed = parse_metadata(&func.data);
            if parsed.type_parts.is_some() {
                out.typed_functions += 1;
            }
            if parsed.frame_desc.is_some() {
                out.framed_functions += 1;
            }
            if parsed.fcmt.is_some() || parsed.frptcmt.is_some() || !parsed.insn_cmts.is_empty() || !parsed.rpt_insn_cmts.is_empty() {
                out.commented_functions += 1;
            }
            if !parsed.errors.is_empty() {
                out.parse_partial_functions += 1;
            }
            if parsed
                .insn_cmts
                .iter()
                .chain(parsed.rpt_insn_cmts.iter())
                .any(|c| c.cmt.starts_with("switch ") || c.cmt.starts_with("jumptable "))
            {
                out.switch_functions += 1;
            }
            if demangle(&func.name).demangled {
                out.demangled_functions += 1;
            }
        }
        out.cached_at_ts = now_ts_sec();
        let _ = self.rt.ctx_index.set_binary_facets(&md5, &out);
        Ok(out)
    }

    pub async fn get_binary_graph(
        &self,
        md5: [u8; 16],
        depth: usize,
        limit: usize,
    ) -> io::Result<(Vec<BinarySummary>, Vec<(String, String, u64)>)> {
        let depth = depth.clamp(1, 3);
        let limit = limit.clamp(1, 24);
        let Some(seed) = self.get_binary_summary(md5).await? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut nodes = vec![seed.clone()];
        let mut seen = std::collections::HashSet::from([seed.md5_hex.clone()]);
        let mut frontier = vec![seed.md5_hex.clone()];
        let mut edges = Vec::new();
        for _ in 0..depth {
            let mut next = Vec::new();
            for node_md5_hex in frontier {
                let Some(node_md5) = parse_md5_hex_local(&node_md5_hex) else { continue; };
                for (neighbor, shared) in self.get_binary_overlap(node_md5, limit).await? {
                    edges.push((node_md5_hex.clone(), neighbor.md5_hex.clone(), shared));
                    if seen.insert(neighbor.md5_hex.clone()) {
                        next.push(neighbor.md5_hex.clone());
                        nodes.push(neighbor);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() || nodes.len() >= 48 {
                break;
            }
        }
        Ok((nodes, edges))
    }

    pub async fn compare_binaries(
        &self,
        left: [u8; 16],
        right: [u8; 16],
        sample_limit: usize,
    ) -> io::Result<(BinaryFacetSummary, BinaryFacetSummary, usize, usize, usize, Vec<BinaryCompareItem>, Vec<BinaryCompareItem>, Vec<BinaryCompareItem>, Vec<BinaryCompareItem>, Vec<BinaryCompareItem>)> {
        let left_keys = self.rt.ctx_index.get_binary_function_keys(&left, 8192)?;
        let right_keys = self.rt.ctx_index.get_binary_function_keys(&right, 8192)?;
        let left_set: HashSet<u128> = left_keys.iter().copied().collect();
        let right_set: HashSet<u128> = right_keys.iter().copied().collect();
        let mut shared = Vec::new();
        let mut left_only = Vec::new();
        let mut right_only = Vec::new();
        let mut recent = Vec::new();
        let mut metadata_rich = Vec::new();
        for key in left_set.intersection(&right_set).take(sample_limit) {
            if let Some(func) = self.get_latest(*key).await? {
                shared.push(BinaryCompareItem { key_hex: format!("{:032x}", key), name: func.name, ts: func.ts_sec });
            }
        }
        for key in left_set.difference(&right_set).take(sample_limit) {
            if let Some(func) = self.get_latest(*key).await? {
                left_only.push(BinaryCompareItem { key_hex: format!("{:032x}", key), name: func.name, ts: func.ts_sec });
            }
        }
        for key in right_set.difference(&left_set).take(sample_limit) {
            if let Some(func) = self.get_latest(*key).await? {
                right_only.push(BinaryCompareItem { key_hex: format!("{:032x}", key), name: func.name, ts: func.ts_sec });
            }
        }
        let mut union_items = Vec::new();
        for key in left_set.union(&right_set).take(sample_limit.saturating_mul(4).max(sample_limit)) {
            if let Some(func) = self.get_latest(*key).await? {
                let parsed = parse_metadata(&func.data);
                let richness = usize::from(parsed.type_parts.is_some())
                    + usize::from(parsed.frame_desc.is_some())
                    + usize::from(parsed.fcmt.is_some() || parsed.frptcmt.is_some())
                    + usize::from(!parsed.insn_cmts.is_empty() || !parsed.rpt_insn_cmts.is_empty())
                    + usize::from(!parsed.errors.is_empty())
                    + usize::from(parsed.vd_elapsed.is_some());
                union_items.push((
                    richness,
                    BinaryCompareItem {
                        key_hex: format!("{:032x}", key),
                        name: func.name,
                        ts: func.ts_sec,
                    },
                ));
            }
        }
        let mut by_recent = union_items.clone();
        by_recent.sort_by(|a, b| b.1.ts.cmp(&a.1.ts).then_with(|| a.1.name.cmp(&b.1.name)));
        recent.extend(by_recent.into_iter().take(sample_limit).map(|(_, item)| item));
        union_items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.ts.cmp(&a.1.ts)));
        metadata_rich.extend(union_items.into_iter().take(sample_limit).map(|(_, item)| item));
        let shared_count = left_set.intersection(&right_set).count();
        let left_only_count = left_set.difference(&right_set).count();
        let right_only_count = right_set.difference(&left_set).count();
        let left_facets = self.get_binary_facets(left, 8192).await?;
        let right_facets = self.get_binary_facets(right, 8192).await?;
        Ok((left_facets, right_facets, shared_count, left_only_count, right_only_count, shared, left_only, right_only, recent, metadata_rich))
    }

    fn attach_binary_refs(&self, hits: &mut [SearchHit]) -> io::Result<()> {
        for hit in hits.iter_mut() {
            let key = match u128::from_str_radix(&hit.key_hex, 16) {
                Ok(key) => key,
                Err(_) => continue,
            };
            let refs = self.get_binary_refs_for_key(key, 12)?;
            if !refs.is_empty() {
                hit.binary_names = refs.iter().map(|item| item.basename.clone()).collect();
                hit.binaries = refs;
            }
        }
        Ok(())
    }

    /// Select best versions for a batch of keys using scoring.
    pub async fn select_versions_for_batch(
        &self,
        ctx: &QueryContext<'_>,
    ) -> io::Result<Vec<Option<(u32, u32, String, Vec<u8>)>>> {
        use std::sync::atomic::Ordering::Relaxed;
        use std::time::Instant;
        METRICS.inc_scoring_batches();
        let start = Instant::now();

        if self.rt.ctx_index.approx_is_empty() {
            METRICS.inc_scoring_fallback();
            let mut out = Vec::with_capacity(ctx.keys.len());
            for &k in ctx.keys {
                out.push(
                    self.get_latest(k)
                        .await?
                        .map(|f| (f.popularity, f.len_bytes, f.name, f.data)),
                );
            }
            METRICS
                .scoring_time_ns
                .fetch_add(start.elapsed().as_nanos() as u64, Relaxed);
            return Ok(out);
        }

        // Build P(md5 | Q)
        let mut vote: HashMap<[u8; 16], f64> = HashMap::new();
        for &k in ctx.keys {
            let md5_list = self.rt.ctx_index.get_md5_bins_for_key(k)?;
            if md5_list.is_empty() {
                continue;
            }
            let df = md5_list.len() as f64;
            let w_k = 1.0f64 / (1.0 + (1.0 + df).ln());
            for e in md5_list.into_iter() {
                let v = vote.entry(e.md5).or_insert(0.0);
                *v += w_k * (e.obs_count as f64);
            }
        }
        let sum_votes: f64 = vote.values().copied().sum();
        let pmd5: HashMap<[u8; 16], f64> = if sum_votes > 0.0 {
            vote.into_iter().map(|(m, v)| (m, v / sum_votes)).collect()
        } else {
            HashMap::new()
        };

        // For each key, enumerate versions and score
        let mut results = Vec::with_capacity(ctx.keys.len());
        let mut versions_considered_total: u64 = 0;

        for &k in ctx.keys {
            // Walk history up to cap
            let cap = self.rt.scoring.max_versions_per_key;
            let mut versions: Vec<(Record, [u8; 32])> = Vec::new();
            let mut addr = self.rt.index.get(k);
            let mut seen_addrs = HashSet::new();
            while addr != 0 && versions.len() < cap && !seen_addrs.contains(&addr) {
                seen_addrs.insert(addr);
                let seg_id = addr_seg(addr);
                let off = addr_off(addr);
                let reader = match self.rt.segments.get_reader(seg_id) {
                    Some(r) => r,
                    None => break,
                };
                match reader.read_at(off) {
                    Ok(rec) => {
                        if rec.flags & 0x01 == 0 {
                            let vid = version_id(k, &rec.name, &rec.data);
                            versions.push((rec.clone(), vid));
                        }
                        addr = rec.prev_addr;
                    }
                    Err(_) => break,
                }
            }

            versions_considered_total += versions.len() as u64;

            if versions.is_empty() {
                results.push(None);
                continue;
            }
            if versions.len() == 1 {
                let rec = &versions[0].0;
                results.push(Some((
                    rec.popularity,
                    rec.len_bytes,
                    rec.name.clone(),
                    rec.data.clone(),
                )));
                continue;
            }

            // Compute per-version signals
            let ts_min = versions.iter().map(|(r, _)| r.ts_sec).min().unwrap();
            let ts_max = versions.iter().map(|(r, _)| r.ts_sec).max().unwrap();

            let max_total_obs = {
                let mut m = 0u32;
                for (_, vid) in &versions {
                    if let Ok(Some(vs)) = self.rt.ctx_index.get_version_stats(vid) {
                        if vs.total_obs > m {
                            m = vs.total_obs;
                        }
                    }
                }
                if m == 0 {
                    1
                } else {
                    m
                }
            };

            let mut max_bins = 1u32;
            for (_, vid) in &versions {
                if let Ok(Some(vs)) = self.rt.ctx_index.get_version_stats(vid) {
                    let nb = if vs.num_binaries == 0 {
                        vs.top_md5s.len() as u32
                    } else {
                        vs.num_binaries
                    };
                    if nb > max_bins {
                        max_bins = nb;
                    }
                }
            }

            let mut best_idx = 0usize;
            let mut best_score = f64::NEG_INFINITY;

            for (idx, (rec, vid)) in versions.iter().enumerate() {
                // s_md5
                let s_md5 = if let Some(md5q) = ctx.md5 {
                    match self.rt.ctx_index.get_key_md5_stats(k, &md5q)? {
                        Some(st) if st.last_version_id == *vid => 1.0,
                        Some(_) => 0.0,
                        None => 0.0,
                    }
                } else {
                    0.0
                };

                // s_name
                let s_name = if let Some(bq) = ctx.basename {
                    if let Ok(Some(vs)) = self.rt.ctx_index.get_version_stats(vid) {
                        let mut best = 0.0f64;
                        for e in vs.top_md5s.iter().take(self.rt.scoring.max_md5_per_version) {
                            if let Ok(Some(bm)) = self.rt.ctx_index.get_binary_meta(&e.md5) {
                                let sim = name_suffix_similarity(&bm.basename, bq);
                                if sim > best {
                                    best = sim;
                                }
                            }
                        }
                        best
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

                // s_coh
                let s_coh = if !pmd5.is_empty() {
                    if let Ok(Some(vs)) = self.rt.ctx_index.get_version_stats(vid) {
                        let mut sum = 0.0f64;
                        for e in vs.top_md5s.iter().take(self.rt.scoring.max_md5_per_version) {
                            if let Some(p) = pmd5.get(&e.md5) {
                                sum += *p;
                            }
                        }
                        sum
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

                // s_stab
                let s_stab = if let Ok(Some(vs)) = self.rt.ctx_index.get_version_stats(vid) {
                    (vs.total_obs as f64) / ((max_total_obs as f64) + f64::EPSILON)
                } else {
                    0.5
                };

                // s_rec
                let s_rec = if ts_max == ts_min {
                    1.0
                } else {
                    (rec.ts_sec.saturating_sub(ts_min) as f64) / ((ts_max - ts_min) as f64)
                };

                // s_pop_bin
                let s_pop_bin = if let Ok(Some(vs)) = self.rt.ctx_index.get_version_stats(vid) {
                    let nb = if vs.num_binaries == 0 {
                        vs.top_md5s.len() as u32
                    } else {
                        vs.num_binaries
                    };
                    let denom = (1.0 + (max_bins as f64)).ln();
                    if denom > 0.0 {
                        ((1.0 + (nb as f64)).ln()) / denom
                    } else {
                        0.5
                    }
                } else {
                    0.5
                };

                // host/origin not tracked presently
                let s_host = 0.0f64;
                let s_origin = 0.0f64;

                let w = &self.rt.scoring;
                let score = w.w_md5 * s_md5
                    + w.w_name * s_name
                    + w.w_coh * s_coh
                    + w.w_stab * s_stab
                    + w.w_rec * s_rec
                    + w.w_pop_bin * s_pop_bin
                    + w.w_host * s_host
                    + w.w_origin * s_origin;

                if score > best_score {
                    best_score = score;
                    best_idx = idx;
                } else if (score - best_score).abs() < 1e-12 {
                    // tie-breakers: prefer md5 match, then newer
                    let mut cur_md5 = 0.0f64;
                    if let Some(md5q) = ctx.md5 {
                        if let Some(st) = self.rt.ctx_index.get_key_md5_stats(k, &md5q)? {
                            if st.last_version_id == versions[idx].1 {
                                cur_md5 = 1.0;
                            }
                        }
                    }
                    let mut best_md5_sig = 0.0f64;
                    if let Some(md5q) = ctx.md5 {
                        if let Some(st) = self.rt.ctx_index.get_key_md5_stats(k, &md5q)? {
                            if st.last_version_id == versions[best_idx].1 {
                                best_md5_sig = 1.0;
                            }
                        }
                    }
                    if cur_md5 > best_md5_sig {
                        best_idx = idx;
                    } else if (cur_md5 - best_md5_sig).abs() < 1e-12 {
                        // prefer newer
                        if versions[idx].0.ts_sec > versions[best_idx].0.ts_sec {
                            best_idx = idx;
                        }
                    }
                }
            }

            let rec = &versions[best_idx].0;
            results.push(Some((
                rec.popularity,
                rec.len_bytes,
                rec.name.clone(),
                rec.data.clone(),
            )));
        }

        METRICS.inc_scoring_versions(versions_considered_total);
        METRICS
            .scoring_time_ns
            .fetch_add(start.elapsed().as_nanos() as u64, Relaxed);
        Ok(results)
    }
}

// Helper functions

fn now_ts_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute version ID from key, name, and data.
fn version_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    name.hash(&mut h);
    data.hash(&mut h);
    let hash = h.finish();
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&key.to_le_bytes()[0..8]);
    out[8..16].copy_from_slice(&key.to_le_bytes()[8..16]);
    out[16..24].copy_from_slice(&hash.to_le_bytes());
    out[24..32].copy_from_slice(&(name.len() as u64).to_le_bytes());
    out
}

fn name_suffix_similarity(a: &str, b: &str) -> f64 {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = ab.len();
    let mut j = bb.len();
    let mut l = 0usize;
    while i > 0 && j > 0 {
        let ca = ab[i - 1].to_ascii_lowercase();
        let cb = bb[j - 1].to_ascii_lowercase();
        if ca == cb {
            l += 1;
            i -= 1;
            j -= 1;
        } else {
            break;
        }
    }
    let denom = ab.len().max(bb.len()) as f64;
    if denom <= 0.0 {
        0.0
    } else {
        (l as f64) / denom
    }
}

fn hex_md5(md5: &[u8; 16]) -> String {
    md5.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn short_md5(md5: &[u8; 16]) -> String {
    hex_md5(md5)[0..8].to_string()
}

fn parse_md5_hex_local(md5_hex: &str) -> Option<[u8; 16]> {
    if md5_hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in md5_hex.as_bytes().chunks(2).enumerate() {
        out[idx] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

fn score_binary_meta(meta: &crate::engine::BinaryMeta, norm_query: &str) -> f32 {
    let name = meta.basename.to_ascii_lowercase();
    let base = if name == norm_query {
        100.0
    } else if name.starts_with(norm_query) {
        70.0
    } else if name.contains(norm_query) {
        40.0
    } else {
        0.0
    };
    base + (meta.function_count.min(10_000) as f32).ln_1p() * 6.0 + (meta.obs_count.min(1_000_000) as f32).ln_1p()
}

fn binary_summary_from_meta(meta: &crate::engine::BinaryMeta, score: f32) -> BinarySummary {
    BinarySummary {
        md5_hex: hex_md5(&meta.md5),
        short_id: short_md5(&meta.md5),
        basename: meta.basename.clone(),
        display_name: format!("{} · {}", meta.basename, short_md5(&meta.md5)),
        hostname: meta.hostname.clone(),
        first_seen_ts: meta.first_seen_ts,
        last_seen_ts: meta.last_seen_ts,
        obs_count: meta.obs_count,
        function_count: meta.function_count,
        version_count: meta.version_count,
        host_count: meta.host_count,
        score,
    }
}
