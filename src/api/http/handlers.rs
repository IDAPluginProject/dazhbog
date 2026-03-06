//! HTTP request handlers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, Request, Response, StatusCode};
use log::*;
use percent_encoding::percent_decode_str;
use serde::Serialize;
use std::sync::Arc;

use crate::api::metrics::METRICS;
use crate::db::Database;
use crate::engine::SearchHit;
use crate::protocol::lumina::metadata::parse_metadata;

/// Search response structure with pagination.
#[derive(Serialize)]
pub struct SearchResponse {
    query: String,
    results: Vec<SearchHit>,
    total: usize,
    page: usize,
    per_page: usize,
    total_pages: usize,
}

#[derive(Serialize)]
pub struct TypePartsJson {
    pub userti: bool,
    pub declaration: Option<String>,
    pub decode_error: Option<String>,
}

#[derive(Serialize)]
pub struct SerializedTinfoJson {
    pub declaration: Option<String>,
    pub decode_error: Option<String>,
}

#[derive(Serialize)]
pub struct FrameMemJson {
    pub name: Option<String>,
    pub tinfo: Option<SerializedTinfoJson>,
    pub cmt: Option<String>,
    pub rptcmt: Option<String>,
    pub offset: Option<u64>,
    pub nbytes: Option<u64>,
    pub has_info: bool,
}

#[derive(Serialize)]
pub struct FrameDescJson {
    pub frsize: u64,
    pub argsize: u64,
    pub frregs: u16,
    pub members: Vec<FrameMemJson>,
}

#[derive(Serialize)]
pub struct InsnCmtJson {
    pub fchunk_nr: u32,
    pub fchunk_off: u32,
    pub cmt: String,
}

/// Parsed metadata for JSON response.
#[derive(Serialize)]
pub struct ParsedMetadataJson {
    pub raw_size: usize,
    pub bytes_parsed: usize,
    pub errors: Vec<String>,
    pub type_parts: Option<TypePartsJson>,
    pub frame_desc: Option<FrameDescJson>,
    pub vd_elapsed: Option<u64>,
    pub fcmt: Option<String>,
    pub frptcmt: Option<String>,
    pub insn_cmts: Vec<InsnCmtJson>,
    pub rpt_insn_cmts: Vec<InsnCmtJson>,
}

/// Function detail response with full metadata.
#[derive(Serialize)]
pub struct FunctionDetailResponse {
    pub key_hex: String,
    pub name: String,
    pub popularity: u32,
    pub ts: u64,
    pub data_size: usize,
    pub metadata: Option<ParsedMetadataJson>,
    pub binary_names: Vec<String>,
}

/// Metrics snapshot for JSON API.
#[derive(Serialize)]
pub struct MetricsSnapshot {
    // Database stats
    indexed_funcs: u64,
    total_records: u64,
    storage_bytes: u64,
    search_docs: u64,
    unique_binaries: u64,
    uptime_secs: u64,
    start_time: u64,

    // Traffic counters
    pulls: u64,
    pushes: u64,
    new_funcs: u64,
    queried_funcs: u64,
    active_connections: u64,

    // Protocol counters
    lumina_v0_4: u64,
    lumina_v5p: u64,

    // Error counters
    errors: u64,
    timeouts: u64,
    index_overflows: u64,
    append_failures: u64,
    decoder_rejects: u64,

    // Upstream counters
    upstream_requests: u64,
    upstream_fetched: u64,
    upstream_errors: u64,

    // Scoring counters
    scoring_batches: u64,
    scoring_versions_considered: u64,
    scoring_fallback_latest: u64,
}

/// Get current metrics snapshot.
pub fn metrics_snapshot() -> MetricsSnapshot {
    use std::sync::atomic::Ordering::Relaxed;
    MetricsSnapshot {
        // Database stats
        indexed_funcs: METRICS.indexed_funcs.load(Relaxed),
        total_records: METRICS.total_records.load(Relaxed),
        storage_bytes: METRICS.storage_bytes.load(Relaxed),
        search_docs: METRICS.search_docs.load(Relaxed),
        unique_binaries: METRICS.unique_binaries.load(Relaxed),
        uptime_secs: METRICS.uptime_secs(),
        start_time: METRICS.start_time.load(Relaxed),

        // Traffic counters
        pulls: METRICS.pulls.load(Relaxed),
        pushes: METRICS.pushes.load(Relaxed),
        new_funcs: METRICS.new_funcs.load(Relaxed),
        queried_funcs: METRICS.queried_funcs.load(Relaxed),
        active_connections: METRICS.active_connections.load(Relaxed),

        // Protocol counters
        lumina_v0_4: METRICS.lumina_v0_4.load(Relaxed),
        lumina_v5p: METRICS.lumina_v5p.load(Relaxed),

        // Error counters
        errors: METRICS.errors.load(Relaxed),
        timeouts: METRICS.timeouts.load(Relaxed),
        index_overflows: METRICS.index_overflows.load(Relaxed),
        append_failures: METRICS.append_failures.load(Relaxed),
        decoder_rejects: METRICS.decoder_rejects.load(Relaxed),

        // Upstream counters
        upstream_requests: METRICS.upstream_requests.load(Relaxed),
        upstream_fetched: METRICS.upstream_fetched.load(Relaxed),
        upstream_errors: METRICS.upstream_errors.load(Relaxed),

        // Scoring counters
        scoring_batches: METRICS.scoring_batches.load(Relaxed),
        scoring_versions_considered: METRICS.scoring_versions_considered.load(Relaxed),
        scoring_fallback_latest: METRICS.scoring_fallback_latest.load(Relaxed),
    }
}

/// Parse a query parameter from a request.
pub fn parse_query_param(req: &Request<Incoming>, key: &str) -> Option<String> {
    let query = req.uri().query()?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        if k == key {
            let raw = it.next().unwrap_or_default();
            return percent_decode_str(raw)
                .decode_utf8()
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}

/// Create a JSON response.
pub fn json_response<T: Serialize>(value: &T, status: StatusCode) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut r = Response::new(Full::new(Bytes::from(body)));
            *r.status_mut() = status;
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
            r
        }
        Err(e) => {
            error!("json serialize error: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from_static(
                    b"{\"error\":\"serialization\"}",
                )))
                .unwrap()
        }
    }
}

/// Handle function detail API request.
pub async fn handle_function_detail(db: Arc<Database>, key_hex: &str) -> Response<Full<Bytes>> {
    // Parse the key from hex
    let key = match u128::from_str_radix(key_hex, 16) {
        Ok(k) => k,
        Err(_) => {
            return json_response(
                &serde_json::json!({"error": "invalid key format"}),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // Fetch the function from database
    match db.get_latest(key).await {
        Ok(Some(func)) => {
            // Parse the metadata
            let parsed = parse_metadata(&func.data);

            let metadata = Some(ParsedMetadataJson {
                raw_size: parsed.raw_size,
                bytes_parsed: parsed.bytes_parsed,
                errors: parsed.errors,
                vd_elapsed: parsed.vd_elapsed,
                fcmt: parsed.fcmt,
                frptcmt: parsed.frptcmt,
                insn_cmts: parsed
                    .insn_cmts
                    .into_iter()
                    .map(|c| InsnCmtJson {
                        fchunk_nr: c.fchunk_nr,
                        fchunk_off: c.fchunk_off,
                        cmt: c.cmt,
                    })
                    .collect(),
                rpt_insn_cmts: parsed
                    .rpt_insn_cmts
                    .into_iter()
                    .map(|c| InsnCmtJson {
                        fchunk_nr: c.fchunk_nr,
                        fchunk_off: c.fchunk_off,
                        cmt: c.cmt,
                    })
                    .collect(),
                type_parts: parsed.type_parts.map(|tp| TypePartsJson {
                    userti: tp.userti,
                    declaration: tp.declaration,
                    decode_error: tp.decode_error,
                }),
                frame_desc: parsed.frame_desc.map(|fd| FrameDescJson {
                    frsize: fd.frsize,
                    argsize: fd.argsize,
                    frregs: fd.frregs,
                    members: fd
                        .members
                        .into_iter()
                        .map(|m| FrameMemJson {
                            name: m.name,
                            tinfo: m.tinfo.map(|t| SerializedTinfoJson {
                                declaration: t.declaration,
                                decode_error: t.decode_error,
                            }),
                            cmt: m.cmt,
                            rptcmt: m.rptcmt,
                            offset: m.offset,
                            nbytes: m.nbytes,
                            has_info: m.info.is_some(),
                        })
                        .collect(),
                }),
            });

            // Get binary names from context index
            let binary_names = db.get_basenames_for_key(key).unwrap_or_default();

            json_response(
                &FunctionDetailResponse {
                    key_hex: format!("{:032x}", key),
                    name: func.name,
                    popularity: func.popularity,
                    ts: func.ts_sec,
                    data_size: func.data.len(),
                    metadata,
                    binary_names,
                },
                StatusCode::OK,
            )
        }
        Ok(None) => json_response(
            &serde_json::json!({"error": "function not found"}),
            StatusCode::NOT_FOUND,
        ),
        Err(e) => {
            error!("get_latest failed for key {}: {}", key_hex, e);
            json_response(
                &serde_json::json!({"error": "database error"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

/// Handle search API request.
pub async fn handle_search(db: Arc<Database>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let Some(q) = parse_query_param(&req, "q") else {
        return json_response(
            &serde_json::json!({"error": "missing query"}),
            StatusCode::BAD_REQUEST,
        );
    };

    // Parse pagination parameters
    const DEFAULT_PER_PAGE: usize = 25;
    const MAX_PER_PAGE: usize = 100;

    let page: usize = parse_query_param(&req, "page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);

    let per_page: usize = parse_query_param(&req, "per_page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PER_PAGE)
        .clamp(1, MAX_PER_PAGE);

    let offset = (page - 1) * per_page;

    match db.search_functions_paginated(&q, offset, per_page).await {
        Ok((results, total)) => {
            let total_pages = (total + per_page - 1) / per_page;
            json_response(
                &SearchResponse {
                    query: q,
                    results,
                    total,
                    page,
                    per_page,
                    total_pages,
                },
                StatusCode::OK,
            )
        }
        Err(e) => {
            error!("search failed: {}", e);
            json_response(
                &serde_json::json!({"error": "search failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}
