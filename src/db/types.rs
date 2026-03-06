//! Database type definitions.

use serde::Serialize;

/// Latest function metadata from the database.
#[derive(Debug, Clone)]
pub struct FuncLatest {
    pub popularity: u32,
    pub len_bytes: u32,
    pub ts_sec: u64,
    pub name: String,
    pub data: Vec<u8>,
}

/// Context information for push operations.
#[derive(Clone, Debug)]
pub struct PushContext<'a> {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    pub hostname: Option<&'a str>,
}

/// Owned version of PushContext for use in spawn_blocking.
#[derive(Clone, Debug)]
pub struct OwnedPushContext {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<String>,
    pub hostname: Option<String>,
}

/// Context information for query operations.
#[derive(Clone)]
pub struct QueryContext<'a> {
    pub keys: &'a [u128],
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    #[allow(dead_code)]
    pub hostname: Option<&'a str>,
}

/// Summary row for binary search and binary detail views.
#[derive(Debug, Clone, Serialize)]
pub struct BinarySummary {
    pub md5_hex: String,
    pub short_id: String,
    pub basename: String,
    pub display_name: String,
    pub hostname: String,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
    pub obs_count: u64,
    pub function_count: u64,
    pub version_count: u64,
    pub host_count: u64,
    pub typed_functions: u64,
    pub commented_functions: u64,
    pub switch_functions: u64,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BinaryFacetSummary {
    pub function_count: u64,
    pub typed_functions: u64,
    pub framed_functions: u64,
    pub commented_functions: u64,
    pub switch_functions: u64,
    pub parse_partial_functions: u64,
    pub demangled_functions: u64,
    pub cached_at_ts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryCompareItem {
    pub key_hex: String,
    pub name: String,
    pub ts: u64,
    pub rarity_score: usize,
    pub richness_score: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryCompareBucket {
    pub label: String,
    pub items: Vec<BinaryCompareItem>,
}
