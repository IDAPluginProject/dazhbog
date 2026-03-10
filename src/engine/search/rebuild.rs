//! Search index rebuild from engine data.

use super::index::SearchIndex;
use super::types::SearchDocument;
use crate::common::demangle::demangle;
use crate::common::hash::version_id;
use crate::common::{addr_off, addr_seg};
use crate::db::semantic::analyze_function;
use crate::engine::{ContextIndex, OpenSegments, ShardedIndex};
use log::info;
use std::collections::{HashMap, HashSet};
use std::io;

/// Rebuild the search index from engine data.
pub fn rebuild_from_engine(
    search: &SearchIndex,
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
) -> io::Result<()> {
    let mut latest: HashMap<u128, (u64, String, Vec<u8>)> = HashMap::new();
    segments.for_each_record(|_seg_id, _off, rec| {
        if rec.flags & 0x01 != 0 {
            return Ok(());
        }
        let entry =
            latest
                .entry(rec.key)
                .or_insert((rec.ts_sec, rec.name.clone(), rec.data.clone()));
        if rec.ts_sec >= entry.0 {
            *entry = (rec.ts_sec, rec.name.clone(), rec.data.clone());
        }
        Ok(())
    })?;

    if index.entry_count() > 0 {
        latest.retain(|k, _| index.get(*k) != 0);
    }

    let mut docs = Vec::with_capacity(latest.len());
    for (key, fallback_latest) in latest.into_iter() {
        let (ts, name, data) =
            resolve_canonical_or_latest_record(segments, index, ctx_index, key, fallback_latest)?;

        let basenames = ctx_index.resolve_basenames_for_key(key).unwrap_or_default();
        let binary_refs = ctx_index
            .get_binary_refs_for_key(key, 8)
            .unwrap_or_default();
        let origin_tokens: Vec<String> = binary_refs
            .into_iter()
            .filter_map(|meta| {
                if meta.origin_token.is_empty() {
                    None
                } else {
                    Some(meta.origin_token)
                }
            })
            .collect();

        let demangle_result = demangle(&name);
        let (func_name_demangled, lang) = if demangle_result.demangled {
            (
                demangle_result.name,
                demangle_result.lang.unwrap_or("").to_string(),
            )
        } else {
            (String::new(), String::new())
        };

        let analysis = analyze_function(&name, &data);
        docs.push(SearchDocument {
            key,
            func_name: name,
            func_name_demangled,
            lang: if lang.is_empty() {
                analysis.fingerprint.language.clone()
            } else {
                lang
            },
            binary_names: basenames,
            origin_tokens,
            prototype_tokens: analysis.fingerprint.prototype_tokens,
            frame_tokens: analysis.fingerprint.frame_tokens,
            comment_tokens: analysis.fingerprint.comment_tokens,
            operand_tokens: analysis.fingerprint.operand_tokens,
            semantic_tokens: analysis.fingerprint.tokens,
            ts,
        });
    }

    info!("rebuilding full-text index for {} functions", docs.len());
    search.rebuild(docs)?;
    Ok(())
}

fn resolve_canonical_or_latest_record(
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
    key: u128,
    fallback_latest: (u64, String, Vec<u8>),
) -> io::Result<(u64, String, Vec<u8>)> {
    let Some(canonical_vid) = ctx_index
        .get_canonical_version(key)?
        .map(|cv| cv.version_id)
    else {
        return Ok(fallback_latest);
    };

    let mut addr = index.get(key);
    let mut seen = HashSet::new();
    while addr != 0 && !seen.contains(&addr) {
        seen.insert(addr);
        let seg_id = addr_seg(addr);
        let off = addr_off(addr);
        let Some(reader) = segments.get_reader(seg_id) else {
            break;
        };
        let rec = reader.read_at(off)?;
        let next = rec.prev_addr;
        if rec.flags & 0x01 == 0 {
            let vid = version_id(key, &rec.name, &rec.data);
            if vid == canonical_vid {
                return Ok((rec.ts_sec, rec.name, rec.data));
            }
        }
        addr = next;
    }

    Ok(fallback_latest)
}
