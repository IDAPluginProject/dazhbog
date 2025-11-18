use crate::config::Config;
use crate::engine::{EngineRuntime, IndexError, Record, UpsertResult};
use crate::util::{addr_off, addr_seg};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io};

const FAILURE_CACHE_TTL_SECS: u64 = 86400; // 24 hours

/// Thread-safe cache for tracking upstream fetch failures
#[derive(Clone)]
pub struct FailureCache {
    inner: Arc<RwLock<FailureCacheInner>>,
}

struct FailureCacheInner {
    // Maps key (symbol hash) to timestamp when failure was recorded
    entries: HashMap<u128, u64>,
}

impl FailureCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(FailureCacheInner {
                entries: HashMap::new(),
            })),
        }
    }

    /// Check if a key is in the failure cache and not expired
    pub fn is_failed(&self, key: u128) -> bool {
        let now = now_ts_sec();
        if let Ok(cache) = self.inner.read() {
            if let Some(&ts) = cache.entries.get(&key) {
                // Check if entry has expired
                if now - ts < FAILURE_CACHE_TTL_SECS {
                    return true;
                }
            }
        }
        false
    }

    /// Add a key to the failure cache with current timestamp
    pub fn insert(&self, key: u128) {
        let now = now_ts_sec();
        if let Ok(mut cache) = self.inner.write() {
            cache.entries.insert(key, now);
        }
    }

    /// Remove a key from the failure cache
    pub fn remove(&self, key: u128) {
        if let Ok(mut cache) = self.inner.write() {
            cache.entries.remove(&key);
        }
    }
}

fn now_ts_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone)]
pub struct Database {
    rt: Arc<EngineRuntime>,
    pub failure_cache: FailureCache,
}

#[derive(Debug, Clone)]
pub struct FuncLatest {
    pub popularity: u32,
    pub len_bytes: u32,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PushContext<'a> {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    pub hostname: Option<&'a str>,
}

#[derive(Clone)]
pub struct QueryContext<'a> {
    pub keys: &'a [u128],
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    #[allow(dead_code)]
    pub hostname: Option<&'a str>,
}

impl Database {
    pub async fn open(cfg: Arc<Config>) -> io::Result<Arc<Self>> {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        Ok(Arc::new(Self {
            rt: Arc::new(rt),
            failure_cache: FailureCache::new(),
        }))
    }

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
            name: rec.name,
            data: rec.data,
        }))
    }

    pub async fn push(&self, items: &[(u128, u32, u32, &str, &[u8])]) -> io::Result<Vec<u32>> {
        let null_ctx = PushContext {
            md5: None,
            basename: None,
            hostname: None,
        };
        self.push_with_ctx(items, &null_ctx).await
    }

    pub async fn push_with_ctx(
        &self,
        items: &[(u128, u32, u32, &str, &[u8])],
        ctx: &PushContext<'_>,
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

            let old = self.rt.index.get(*key);

            if old != 0 {
                let seg_id = crate::util::addr_seg(old);
                let off = crate::util::addr_off(old);
                match self.rt.segments.get_reader(seg_id) {
                    Some(reader) => {
                        match reader.read_at(off) {
                            Ok(existing) => {
                                if existing.name == *name && existing.data == *data {
                                    status.push(2);
                                    // Still record context observation even if unchanged
                                    if let Some(md5) = ctx.md5 {
                                        let ts = crate::util::now_ts_sec();
                                        let vid = crate::util::version_id(*key, name, data);
                                        let _ = self.rt.ctx_index.record_binary_meta(
                                            md5,
                                            ctx.basename.unwrap_or(""),
                                            ctx.hostname.unwrap_or(""),
                                            ts,
                                        );
                                        let _ = self.rt.ctx_index.record_key_observation(
                                            *key,
                                            md5,
                                            Some(vid),
                                            ts,
                                        );
                                    }
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
                ts_sec: crate::util::now_ts_sec(),
                prev_addr: old,
                len_bytes: (*data).len() as u32,
                popularity: *pop,
                name: name.to_string(),
                data: data.to_vec(),
                flags: 0,
            };
            let addr = self.rt.segments.append(&rec)?;
            match self.rt.index.upsert(*key, addr) {
                Ok(UpsertResult::Inserted) => status.push(1),
                Ok(UpsertResult::Replaced(_)) => status.push(0),
                Err(IndexError::Full) => {
                    crate::metrics::METRICS
                        .append_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(io::Error::new(io::ErrorKind::Other, "index full"));
                }
                Err(IndexError::Io(e)) => {
                    crate::metrics::METRICS
                        .append_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("index io error: {}", e),
                    ));
                }
            }

            if let Some(md5) = ctx.md5 {
                let ts = rec.ts_sec;
                let vid = crate::util::version_id(*key, name, data);
                let _ = self.rt.ctx_index.record_binary_meta(
                    md5,
                    ctx.basename.unwrap_or(""),
                    ctx.hostname.unwrap_or(""),
                    ts,
                );
                let _ = self
                    .rt
                    .ctx_index
                    .record_key_observation(*key, md5, Some(vid), ts);
            }
        }
        Ok(status)
    }

    pub async fn delete_keys(&self, keys: &[u128]) -> io::Result<u32> {
        let mut deleted = 0u32;
        for &key in keys {
            let old = self.rt.index.get(key);
            let rec = Record {
                key,
                ts_sec: crate::util::now_ts_sec(),
                prev_addr: old,
                len_bytes: 0,
                popularity: 0,
                name: String::new(),
                data: Vec::new(),
                flags: 0x01,
            };
            let addr = self.rt.segments.append(&rec)?;
            let _ = self.rt.index.upsert(key, addr);
            if old != 0 {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

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

    pub async fn select_versions_for_batch(
        &self,
        ctx: &QueryContext<'_>,
    ) -> io::Result<Vec<Option<(u32, u32, String, Vec<u8>)>>> {
        use std::time::Instant;
        crate::metrics::METRICS
            .scoring_batches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let start = Instant::now();

        if self.rt.ctx_index.approx_is_empty() {
            crate::metrics::METRICS
                .scoring_fallback_latest
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut out = Vec::with_capacity(ctx.keys.len());
            for &k in ctx.keys {
                out.push(
                    self.get_latest(k)
                        .await?
                        .map(|f| (f.popularity, f.len_bytes, f.name, f.data)),
                );
            }
            crate::metrics::METRICS.scoring_time_ns.fetch_add(
                start.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
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
            let mut versions: Vec<(crate::engine::Record, [u8; 32])> = Vec::new();
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
                            let vid = crate::util::version_id(k, &rec.name, &rec.data);
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
                    // tie-breakers: prefer md5 match, then coh, then stab, then newer
                    // recompute minimal signals used for tiebreak quickly
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

        crate::metrics::METRICS
            .scoring_versions_considered
            .fetch_add(
                versions_considered_total,
                std::sync::atomic::Ordering::Relaxed,
            );
        crate::metrics::METRICS.scoring_time_ns.fetch_add(
            start.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(results)
    }
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
