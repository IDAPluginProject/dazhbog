//! Semantic analysis helpers for canonicalization, bundle synthesis, and search indexing.

use crate::common::demangle::demangle;
use crate::protocol::lumina::{
    parse_metadata, serialize_metadata_chunks, FunctionMetadata, MdKey, MetadataChunk,
};
use std::collections::{BTreeMap, HashMap, HashSet};

const DEFAULT_NAME_PREFIXES: &[&str] = &[
    "sub_", "nullsub_", "j_", "unknown_", "loc_", "__imp_", "thunk_", "func_",
];

const CONSISTENCY_STOPWORDS: &[&str] = &[
    "arg", "argsize", "byte", "bytes", "case", "char", "chunk", "const", "default", "dword",
    "entry", "field", "frame", "frregs", "frsize", "int", "loc", "long", "member", "offset",
    "param", "ptr", "qword", "reg", "regs", "return", "short", "signed", "size", "state", "struct",
    "sub", "switch", "this", "type", "uint", "ulong", "unsigned", "ushort", "var", "void", "word",
];

const KNOWN_MDKEY_ORDER: [MdKey; 11] = [
    MdKey::Type,
    MdKey::VdElapsed,
    MdKey::Fcmt,
    MdKey::Frptcmt,
    MdKey::Cmts,
    MdKey::Rptcmts,
    MdKey::Extracmts,
    MdKey::UserStkpnts,
    MdKey::FrameDesc,
    MdKey::Ops,
    MdKey::OpsEx,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SemanticBundle {
    Type,
    Timing,
    Comments,
    Frame,
    Operands,
    Other(u32),
}

#[derive(Debug, Clone, Default)]
pub struct SemanticFingerprint {
    pub name_tokens: Vec<String>,
    pub tokens: Vec<String>,
    pub prototype_tokens: Vec<String>,
    pub frame_tokens: Vec<String>,
    pub comment_tokens: Vec<String>,
    pub operand_tokens: Vec<String>,
    pub language: String,
}

#[derive(Debug, Clone)]
pub struct SemanticAnalysis {
    pub metadata: FunctionMetadata,
    pub fingerprint: SemanticFingerprint,
    pub quality_score: f64,
    pub consistency_score: f64,
}

#[derive(Debug, Clone)]
pub struct SynthesisInput<'a> {
    pub score: f64,
    pub name: &'a str,
    pub raw_data: &'a [u8],
    pub metadata: &'a FunctionMetadata,
}

pub fn bundle_for_mdkey(mdkey: MdKey) -> SemanticBundle {
    match mdkey {
        MdKey::Type => SemanticBundle::Type,
        MdKey::VdElapsed => SemanticBundle::Timing,
        MdKey::Fcmt | MdKey::Frptcmt | MdKey::Cmts | MdKey::Rptcmts | MdKey::Extracmts => {
            SemanticBundle::Comments
        }
        MdKey::UserStkpnts | MdKey::FrameDesc => SemanticBundle::Frame,
        MdKey::Ops | MdKey::OpsEx => SemanticBundle::Operands,
        MdKey::Other(raw) => SemanticBundle::Other(raw),
        MdKey::None => SemanticBundle::Other(0),
    }
}

pub fn analyze_function(name: &str, data: &[u8]) -> SemanticAnalysis {
    let metadata = parse_metadata(data);
    let fingerprint = build_fingerprint(name, &metadata);
    let consistency_score =
        cross_field_consistency_score_with_fingerprint(name, &metadata, &fingerprint);
    let quality_score = metadata_quality_score_with_fingerprint(name, &metadata, &fingerprint);
    SemanticAnalysis {
        metadata,
        fingerprint,
        quality_score,
        consistency_score,
    }
}

pub fn build_fingerprint(name: &str, metadata: &FunctionMetadata) -> SemanticFingerprint {
    let demangled = demangle(name);
    let mut name_tokens = tokenize_semantic_text(name);
    if demangled.demangled {
        name_tokens.extend(tokenize_semantic_text(&demangled.name));
    }
    dedup_tokens(&mut name_tokens);
    let mut tokens = name_tokens.clone();
    let language = demangled.lang.unwrap_or("").to_string();

    let mut prototype_tokens = Vec::new();
    if let Some(type_parts) = &metadata.type_parts {
        if let Some(decl) = &type_parts.declaration {
            prototype_tokens.extend(tokenize_semantic_text(decl));
            tokens.extend(tokenize_semantic_text(decl));
        }
    }

    let mut frame_tokens = Vec::new();
    if let Some(frame) = &metadata.frame_desc {
        frame_tokens.extend(tokenize_semantic_text(&format!(
            "frsize {} argsize {} frregs {}",
            frame.frsize, frame.argsize, frame.frregs
        )));
        for member in &frame.members {
            if let Some(name) = &member.name {
                frame_tokens.extend(tokenize_semantic_text(name));
            }
            if let Some(tinfo) = &member.tinfo {
                if let Some(decl) = &tinfo.declaration {
                    frame_tokens.extend(tokenize_semantic_text(decl));
                }
            }
            if let Some(cmt) = &member.cmt {
                frame_tokens.extend(tokenize_semantic_text(cmt));
            }
            if let Some(rptcmt) = &member.rptcmt {
                frame_tokens.extend(tokenize_semantic_text(rptcmt));
            }
        }
        tokens.extend(frame_tokens.iter().cloned());
    }

    let mut comment_tokens = Vec::new();
    if let Some(fcmt) = &metadata.fcmt {
        comment_tokens.extend(tokenize_semantic_text(fcmt));
    }
    if let Some(frptcmt) = &metadata.frptcmt {
        comment_tokens.extend(tokenize_semantic_text(frptcmt));
    }
    for cmt in &metadata.insn_cmts {
        comment_tokens.extend(tokenize_semantic_text(&cmt.cmt));
    }
    for cmt in &metadata.rpt_insn_cmts {
        comment_tokens.extend(tokenize_semantic_text(&cmt.cmt));
    }
    for cmt in &metadata.extra_cmts {
        comment_tokens.extend(tokenize_semantic_text(cmt));
    }
    tokens.extend(comment_tokens.iter().cloned());

    let mut operand_tokens = Vec::new();
    if let Some(blob) = &metadata.user_stkpnts {
        for text in &blob.printable_texts {
            operand_tokens.extend(tokenize_semantic_text(text));
        }
    }
    if let Some(blob) = &metadata.ops {
        for text in &blob.printable_texts {
            operand_tokens.extend(tokenize_semantic_text(text));
        }
    }
    if let Some(blob) = &metadata.ops_ex {
        for text in &blob.printable_texts {
            operand_tokens.extend(tokenize_semantic_text(text));
        }
    }
    tokens.extend(operand_tokens.iter().cloned());

    dedup_tokens(&mut tokens);
    dedup_tokens(&mut prototype_tokens);
    dedup_tokens(&mut frame_tokens);
    dedup_tokens(&mut comment_tokens);
    dedup_tokens(&mut operand_tokens);

    SemanticFingerprint {
        name_tokens,
        tokens,
        prototype_tokens,
        frame_tokens,
        comment_tokens,
        operand_tokens,
        language,
    }
}

pub fn metadata_quality_score(name: &str, metadata: &FunctionMetadata) -> f64 {
    let fingerprint = build_fingerprint(name, metadata);
    metadata_quality_score_with_fingerprint(name, metadata, &fingerprint)
}

fn metadata_quality_score_with_fingerprint(
    name: &str,
    metadata: &FunctionMetadata,
    fingerprint: &SemanticFingerprint,
) -> f64 {
    let mut score = 0.0;

    score += name_quality(name);

    if let Some(type_parts) = &metadata.type_parts {
        score += 2.0;
        if type_parts.declaration.is_some() {
            score += 2.5;
        }
        if type_parts.decode_error.is_some() {
            score -= 0.75;
        }
    }

    if let Some(frame) = &metadata.frame_desc {
        score += 1.5;
        score += (frame.members.len().min(16) as f64) * 0.2;
    }

    score += usize_to_f64(metadata.insn_cmts.len().min(32)) * 0.15;
    score += usize_to_f64(metadata.rpt_insn_cmts.len().min(32)) * 0.15;
    score += usize_to_f64(metadata.extra_cmts.len().min(32)) * 0.1;
    score += usize_to_f64(metadata.component_count()) * 0.1;
    score += usize_to_f64(metadata.raw_chunks.len().min(16)) * 0.05;
    score += usize::from(metadata.fcmt.is_some()) as f64 * 0.75;
    score += usize::from(metadata.frptcmt.is_some()) as f64 * 0.5;
    score += usize::from(metadata.user_stkpnts.is_some()) as f64 * 0.4;
    score += usize::from(metadata.ops.is_some()) as f64 * 0.35;
    score += usize::from(metadata.ops_ex.is_some()) as f64 * 0.35;
    score += usize_to_f64(fingerprint.prototype_tokens.len().min(24)) * 0.03;
    score += usize_to_f64(fingerprint.frame_tokens.len().min(24)) * 0.02;
    score += usize_to_f64(fingerprint.comment_tokens.len().min(24)) * 0.015;
    score += usize_to_f64(fingerprint.operand_tokens.len().min(24)) * 0.015;

    if let Some(vd) = metadata.vd_elapsed {
        score += if vd > 0 { 0.15 } else { 0.05 };
    }

    score -= usize_to_f64(metadata.errors.len().min(8)) * 0.5;
    score
}

pub fn cross_field_consistency_score(name: &str, metadata: &FunctionMetadata) -> f64 {
    let fingerprint = build_fingerprint(name, metadata);
    cross_field_consistency_score_with_fingerprint(name, metadata, &fingerprint)
}

fn cross_field_consistency_score_with_fingerprint(
    name: &str,
    metadata: &FunctionMetadata,
    fingerprint: &SemanticFingerprint,
) -> f64 {
    let name_is_generic = name_quality(name) <= 0.35;
    let name_tokens = signal_token_set(&fingerprint.name_tokens);
    let prototype_tokens = signal_token_set(&fingerprint.prototype_tokens);
    let frame_tokens = signal_token_set(&fingerprint.frame_tokens);
    let comment_tokens = signal_token_set(&fingerprint.comment_tokens);
    let operand_tokens = signal_token_set(&fingerprint.operand_tokens);

    let populated = [
        !name_tokens.is_empty(),
        !prototype_tokens.is_empty(),
        !frame_tokens.is_empty(),
        !comment_tokens.is_empty(),
        !operand_tokens.is_empty(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    if populated <= 1 {
        return if metadata.raw_chunks.is_empty() {
            0.0
        } else {
            0.45
        };
    }

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for (lhs_name, lhs_tokens, rhs_name, rhs_tokens, base_weight) in [
        ("name", &name_tokens, "prototype", &prototype_tokens, 0.28),
        ("name", &name_tokens, "frame", &frame_tokens, 0.16),
        ("name", &name_tokens, "comment", &comment_tokens, 0.14),
        ("prototype", &prototype_tokens, "frame", &frame_tokens, 0.24),
        (
            "prototype",
            &prototype_tokens,
            "comment",
            &comment_tokens,
            0.08,
        ),
        ("frame", &frame_tokens, "comment", &comment_tokens, 0.06),
        ("frame", &frame_tokens, "operand", &operand_tokens, 0.04),
    ] {
        if lhs_tokens.is_empty() || rhs_tokens.is_empty() {
            continue;
        }
        let mut weight = base_weight;
        if name_is_generic && (lhs_name == "name" || rhs_name == "name") {
            weight *= 0.4;
        }
        weighted_sum += weight * token_overlap_score(lhs_tokens, rhs_tokens);
        total_weight += weight;
    }

    let mean_overlap = if total_weight > f64::EPSILON {
        weighted_sum / total_weight
    } else {
        0.0
    };
    let consensus = consensus_token_bonus(&[
        &name_tokens,
        &prototype_tokens,
        &frame_tokens,
        &comment_tokens,
        &operand_tokens,
    ]);
    let comment_bridge = if !comment_tokens.is_empty()
        && ((!prototype_tokens.is_empty()
            && token_overlap_score(&comment_tokens, &prototype_tokens) > 0.0)
            || (!frame_tokens.is_empty()
                && token_overlap_score(&comment_tokens, &frame_tokens) > 0.0))
    {
        0.08
    } else {
        0.0
    };
    let mismatch_penalty = if populated >= 3 && mean_overlap < 0.03 && !name_is_generic {
        0.15
    } else {
        0.0
    };

    (0.35 + 0.55 * mean_overlap + 0.20 * consensus + comment_bridge - mismatch_penalty)
        .clamp(0.0, 1.0)
}

pub fn name_quality(name: &str) -> f64 {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return -1.0;
    }
    let lower = trimmed.to_ascii_lowercase();
    if DEFAULT_NAME_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return 0.25;
    }
    let demangled = demangle(trimmed);
    if demangled.demangled {
        return 2.5;
    }
    if trimmed.contains("::") || trimmed.contains('.') {
        return 1.5;
    }
    if trimmed.chars().any(|c| c.is_ascii_alphabetic()) && trimmed.len() >= 3 {
        return 1.0;
    }
    0.5
}

pub fn tokenize_semantic_text(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let push_cur = |cur: &mut String, out: &mut Vec<String>| {
        if cur.len() >= 2 {
            out.push(cur.to_ascii_lowercase());
        }
        cur.clear();
    };

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else {
            push_cur(&mut cur, &mut out);
        }
    }
    push_cur(&mut cur, &mut out);
    dedup_tokens(&mut out);
    out
}

pub fn normalize_origin_token(input: &str) -> String {
    let input = input.trim().replace('\\', "/");
    if input.is_empty() {
        return String::new();
    }
    let mut base = input
        .rsplit('/')
        .next()
        .unwrap_or(&input)
        .to_ascii_lowercase();
    if let Some(dot) = base.rfind('.') {
        if dot > 0 {
            base.truncate(dot);
        }
    }
    let tokens = tokenize_semantic_text(&base);
    let mut token = tokens.into_iter().take(4).collect::<Vec<_>>().join("_");
    if token.len() > 96 {
        token.truncate(96);
    }
    token
}

pub fn normalize_requested_mdkeys(requested_mdkeys: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(requested_mdkeys.len());
    let mut seen = HashSet::new();
    for &raw_key in requested_mdkeys {
        if seen.insert(raw_key) {
            out.push(raw_key);
        }
    }
    out
}

pub fn shape_metadata_for_request(data: &[u8], requested_mdkeys: &[u32]) -> Vec<u8> {
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    if requested.is_empty() {
        return data.to_vec();
    }
    let parsed = parse_metadata(data);
    if parsed.raw_chunks.is_empty() {
        return Vec::new();
    }
    let shaped = filter_chunks_for_request(&parsed.raw_chunks, &requested);
    serialize_metadata_chunks(&shaped)
}

pub fn fingerprint_similarity(tokens: &[String], weights: &HashMap<String, f64>) -> f64 {
    if weights.is_empty() || tokens.is_empty() {
        return 0.0;
    }
    let mut seen = HashSet::new();
    let mut hit = 0.0;
    let mut total = 0.0;
    for token in tokens {
        if !seen.insert(token) {
            continue;
        }
        total += 1.0;
        hit += weights.get(token).copied().unwrap_or(0.0);
    }
    if total <= f64::EPSILON {
        0.0
    } else {
        hit / total
    }
}

pub fn choose_canonical_name<'a>(inputs: &[SynthesisInput<'a>]) -> &'a str {
    inputs
        .iter()
        .max_by(|a, b| {
            let sa = a.score + name_quality(a.name);
            let sb = b.score + name_quality(b.name);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|input| input.name)
        .unwrap_or("")
}

pub fn synthesize_metadata(inputs: &[SynthesisInput<'_>], requested_mdkeys: &[u32]) -> Vec<u8> {
    if inputs.is_empty() {
        return Vec::new();
    }
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    if inputs.len() == 1 {
        return fallback_metadata(inputs, &requested);
    }

    let mut base_input = &inputs[0];
    for input in &inputs[1..] {
        if input.score > base_input.score {
            base_input = input;
        }
    }

    if base_input.metadata.raw_chunks.is_empty() {
        return fallback_metadata(inputs, &requested);
    }

    let requested_set: HashSet<u32> = requested.iter().copied().collect();
    let mut selected_by_bundle: BTreeMap<SemanticBundle, usize> = BTreeMap::new();
    let mut bundle_score: BTreeMap<SemanticBundle, f64> = BTreeMap::new();

    for (idx, input) in inputs.iter().enumerate() {
        for chunk in &input.metadata.raw_chunks {
            if !requested_set.is_empty() && !requested_set.contains(&chunk.raw_key) {
                continue;
            }
            let bundle = bundle_for_mdkey(chunk.key);
            let score = input.score + bundle_chunk_bonus(input.metadata, bundle);
            let replace = match bundle_score.get(&bundle) {
                Some(prev) => score > *prev,
                None => true,
            };
            if replace {
                bundle_score.insert(bundle, score);
                selected_by_bundle.insert(bundle, idx);
            }
        }
    }

    let mut merged = filter_chunks_for_request(&base_input.metadata.raw_chunks, &requested);
    for (bundle, selected_idx) in &selected_by_bundle {
        let selected = &inputs[*selected_idx];
        let replacements: Vec<MetadataChunk> = selected
            .metadata
            .raw_chunks
            .iter()
            .filter(|chunk| {
                bundle_for_mdkey(chunk.key) == *bundle
                    && (requested_set.is_empty() || requested_set.contains(&chunk.raw_key))
            })
            .cloned()
            .collect();
        merged.retain(|chunk| {
            if bundle_for_mdkey(chunk.key) != *bundle {
                return true;
            }
            if requested_set.is_empty() {
                return false;
            }
            !requested_set.contains(&chunk.raw_key)
        });
        merged.extend(replacements);
    }

    merged.sort_by_key(|chunk| metadata_order_key(chunk.key, chunk.raw_key));
    if !requested_set.is_empty() {
        merged = filter_chunks_for_request(&merged, &requested);
    }

    let chosen_name = choose_canonical_name(inputs);
    if !synthesized_chunks_are_compatible(
        inputs,
        &selected_by_bundle,
        &merged,
        &requested,
        chosen_name,
    ) {
        return fallback_metadata(inputs, &requested);
    }
    serialize_metadata_chunks(&merged)
}

fn metadata_order_key(mdkey: MdKey, raw_key: u32) -> (usize, u32) {
    let pos = KNOWN_MDKEY_ORDER
        .iter()
        .position(|candidate| *candidate == mdkey)
        .unwrap_or(KNOWN_MDKEY_ORDER.len());
    (pos, raw_key)
}

fn bundle_chunk_bonus(metadata: &FunctionMetadata, bundle: SemanticBundle) -> f64 {
    match bundle {
        SemanticBundle::Type => metadata
            .type_parts
            .as_ref()
            .map(|parts| {
                1.25 + parts.declaration.as_ref().map(|_| 0.75).unwrap_or(0.0)
                    - parts.decode_error.as_ref().map(|_| 0.25).unwrap_or(0.0)
            })
            .unwrap_or(0.0),
        SemanticBundle::Timing => metadata.vd_elapsed.map(|_| 0.15).unwrap_or(0.0),
        SemanticBundle::Comments => {
            metadata.fcmt.as_ref().map(|_| 0.5).unwrap_or(0.0)
                + metadata.frptcmt.as_ref().map(|_| 0.3).unwrap_or(0.0)
                + usize_to_f64(metadata.insn_cmts.len().min(32)) * 0.1
                + usize_to_f64(metadata.rpt_insn_cmts.len().min(32)) * 0.08
                + usize_to_f64(metadata.extra_cmts.len().min(32)) * 0.05
        }
        SemanticBundle::Frame => {
            metadata
                .frame_desc
                .as_ref()
                .map(|fd| 0.8 + usize_to_f64(fd.members.len().min(16)) * 0.15)
                .unwrap_or(0.0)
                + metadata.user_stkpnts.as_ref().map(|_| 0.3).unwrap_or(0.0)
        }
        SemanticBundle::Operands => {
            metadata.ops.as_ref().map(|_| 0.25).unwrap_or(0.0)
                + metadata.ops_ex.as_ref().map(|_| 0.25).unwrap_or(0.0)
        }
        SemanticBundle::Other(_) => 0.05,
    }
}

fn filter_chunks_for_request(
    chunks: &[MetadataChunk],
    requested_mdkeys: &[u32],
) -> Vec<MetadataChunk> {
    if requested_mdkeys.is_empty() {
        return chunks.to_vec();
    }
    let requested: HashSet<u32> = requested_mdkeys.iter().copied().collect();
    chunks
        .iter()
        .filter(|chunk| requested.contains(&chunk.raw_key))
        .cloned()
        .collect()
}

fn fallback_metadata(inputs: &[SynthesisInput<'_>], requested_mdkeys: &[u32]) -> Vec<u8> {
    let mut best = &inputs[0];
    for input in &inputs[1..] {
        if input.score > best.score {
            best = input;
        }
    }
    shape_metadata_for_request(best.raw_data, requested_mdkeys)
}

fn synthesized_chunks_are_compatible(
    inputs: &[SynthesisInput<'_>],
    selected_by_bundle: &BTreeMap<SemanticBundle, usize>,
    merged: &[MetadataChunk],
    requested_mdkeys: &[u32],
    chosen_name: &str,
) -> bool {
    if merged.is_empty() {
        return requested_mdkeys.is_empty();
    }

    let merged_data = serialize_metadata_chunks(merged);
    let merged_metadata = parse_metadata(&merged_data);
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    if !requested.is_empty() {
        let requested_set: HashSet<u32> = requested.iter().copied().collect();
        if merged_metadata
            .raw_chunks
            .iter()
            .any(|chunk| !requested_set.contains(&chunk.raw_key))
        {
            return false;
        }
        let best_requested_coverage = inputs
            .iter()
            .map(|input| input.metadata.requested_coverage(&requested))
            .max()
            .unwrap_or(0);
        if merged_metadata.requested_coverage(&requested) < best_requested_coverage {
            return false;
        }
    }

    let min_errors = inputs
        .iter()
        .map(|input| input.metadata.errors.len())
        .min()
        .unwrap_or(0);
    if merged_metadata.errors.len() > min_errors + 1 {
        return false;
    }

    let merged_analysis = analyze_function(chosen_name, &merged_data);
    let merged_total = merged_analysis.quality_score + (merged_analysis.consistency_score * 2.0);

    let mut best_input_total = f64::NEG_INFINITY;
    for input in inputs {
        let candidate_data = shape_metadata_for_request(input.raw_data, &requested);
        if candidate_data.is_empty() {
            continue;
        }
        let analysis = analyze_function(input.name, &candidate_data);
        let total = analysis.quality_score + (analysis.consistency_score * 2.0);
        if total > best_input_total {
            best_input_total = total;
        }
    }
    if best_input_total.is_finite() && merged_total + 0.35 < best_input_total {
        return false;
    }

    let mut structured_languages = HashSet::new();
    for (bundle, idx) in selected_by_bundle {
        if !is_structural_bundle(*bundle) {
            continue;
        }
        let lang = demangle(inputs[*idx].name).lang.unwrap_or("");
        if !lang.is_empty() {
            structured_languages.insert(lang.to_string());
        }
    }
    if structured_languages.len() > 1 && merged_analysis.consistency_score < 0.45 {
        return false;
    }

    true
}

fn is_structural_bundle(bundle: SemanticBundle) -> bool {
    matches!(
        bundle,
        SemanticBundle::Type | SemanticBundle::Frame | SemanticBundle::Operands
    )
}

fn signal_token_set(tokens: &[String]) -> HashSet<String> {
    tokens
        .iter()
        .filter(|token| token.len() >= 3)
        .filter(|token| !token.chars().all(|ch| ch.is_ascii_digit()))
        .filter(|token| !CONSISTENCY_STOPWORDS.contains(&token.as_str()))
        .cloned()
        .collect()
}

fn token_overlap_score(lhs: &HashSet<String>, rhs: &HashSet<String>) -> f64 {
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }
    let intersection = lhs.intersection(rhs).count();
    if intersection == 0 {
        return 0.0;
    }
    (2.0 * usize_to_f64(intersection)) / usize_to_f64(lhs.len() + rhs.len())
}

fn consensus_token_bonus(token_sets: &[&HashSet<String>]) -> f64 {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for set in token_sets {
        for token in set.iter() {
            *counts.entry(token.as_str()).or_insert(0) += 1;
        }
    }
    let shared_across_three = counts.values().filter(|&&count| count >= 3).count();
    let shared_across_two = counts.values().filter(|&&count| count >= 2).count();
    ((usize_to_f64(shared_across_three.min(8)) * 0.06)
        + (usize_to_f64(shared_across_two.min(12)) * 0.02))
        .min(0.35)
}

fn dedup_tokens(tokens: &mut Vec<String>) {
    tokens.sort();
    tokens.dedup();
}

fn usize_to_f64(v: usize) -> f64 {
    v as f64
}
