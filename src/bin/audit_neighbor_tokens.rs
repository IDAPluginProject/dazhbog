use dazhbog::db::semantic::analyze_function;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;

const GENERIC_NEIGHBOR_TOKENS: &[&str] = &[
    "__cdecl",
    "__fastcall",
    "__stdcall",
    "__thiscall",
    "__vectorcall",
    "__usercall",
    "__userpurge",
    "__hidden",
    "__int16",
    "__int64",
    "__cxx11",
    "__src",
    "__dst",
    "__formal",
    "__return_ptr",
    "__struct_ptr",
    "cdecl",
    "fastcall",
    "stdcall",
    "thiscall",
    "vectorcall",
    "usercall",
    "userpurge",
    "arg",
    "args",
    "argsize",
    "argloc",
    "bool",
    "byte",
    "bytes",
    "char",
    "const",
    "dword",
    "double",
    "default",
    "defaults",
    "dispatcher",
    "dispatch",
    "error",
    "errors",
    "err",
    "uuu",
    "u20",
    "u7b",
    "u7d",
    "0ca",
    "far",
    "field",
    "fields",
    "float",
    "frame",
    "frregs",
    "frsize",
    "int",
    "loc",
    "long",
    "near",
    "offset",
    "param",
    "params",
    "backend",
    "frontend",
    "engine",
    "context",
    "module",
    "common",
    "generic",
    "internal",
    "impl",
    "handler",
    "manager",
    "table",
    "jumptable",
    "switch",
    "case",
    "cases",
    "emulator",
    "x86",
    "x64",
    "x86_64",
    "amd64",
    "arm",
    "arm64",
    "aarch64",
    "mips",
    "ppc",
    "sse",
    "avx",
    "neon",
    "qeaa",
    "qeax",
    "qeba",
    "qeav",
    "qeaaxxz",
    "ueaa",
    "ueba",
    "ueaapeaxi",
    "ueaaxxz",
    "aeaa",
    "aeav",
    "aeaaxxz",
    "aebv",
    "aeaufframe",
    "peav",
    "yapeavufunction",
    "yapeavuclass",
    "sapeavuclass",
    "sapeavuscriptstruct",
    "saxpeavuobject",
    "zzappendmembergetprev",
    "vfmember",
    "back_chain",
    "sender_sp",
    "retstr",
    "saved_r4",
    "deleting",
    "cold",
    "v_0",
    "_lambda_1_",
    "ptr",
    "qword",
    "oword",
    "ref",
    "ret",
    "return",
    "short",
    "signed",
    "size",
    "stack",
    "struct",
    "this",
    "type",
    "uint",
    "ulong",
    "unsigned",
    "ushort",
    "var",
    "void",
    "word",
];

const MAGIC: u32 = 0x4C4D4E31;

#[derive(Clone)]
struct Record {
    key: u128,
    ts_sec: u64,
    name: String,
    data: Vec<u8>,
}

#[derive(Default)]
struct TokenStats {
    docs: u64,
    semantic: u64,
    prototype: u64,
    frame: u64,
    comment: u64,
    operand: u64,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: audit_neighbor_tokens <segments_db_dir> [top_n]\nexample: audit_neighbor_tokens /private/tmp/dazhbog_segments_clone 200"
        );
        std::process::exit(2);
    }

    let seg_db_dir = PathBuf::from(&args[1]);
    let top_n = args
        .get(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200);

    let db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {e}")))?;

    let mut tree_names: Vec<String> = db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();
    tree_names.sort();

    let mut latest: HashMap<u128, (u64, usize, u64, Record)> = HashMap::new();
    let mut total_records = 0usize;

    for (seg_idx, name) in tree_names.iter().enumerate() {
        let tree = db
            .open_tree(name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open tree {name}: {e}")))?;
        for item in tree.iter() {
            let (offset_bytes, record_bytes) = match item {
                Ok(value) => value,
                Err(_) => continue,
            };
            let off = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());
            let Some(rec) = parse_record(&record_bytes) else {
                continue;
            };
            total_records += 1;
            let replace = match latest.get(&rec.key) {
                Some((ts, old_seg, old_off, _)) => {
                    rec.ts_sec > *ts
                        || (rec.ts_sec == *ts
                            && (seg_idx > *old_seg || (seg_idx == *old_seg && off > *old_off)))
                }
                None => true,
            };
            if replace {
                latest.insert(rec.key, (rec.ts_sec, seg_idx, off, rec));
            }
        }
    }

    let mut stats: HashMap<String, TokenStats> = HashMap::new();
    for (_, _, _, rec) in latest.values() {
        let analysis = analyze_function(&rec.name, &rec.data);
        let semantic = filtered_tokens(&analysis.fingerprint.tokens);
        let prototype = filtered_tokens(&analysis.fingerprint.prototype_tokens);
        let frame = filtered_tokens(&analysis.fingerprint.frame_tokens);
        let comment = filtered_tokens(&analysis.fingerprint.comment_tokens);
        let operand = filtered_tokens(&analysis.fingerprint.operand_tokens);

        let mut doc_seen: HashSet<String> = HashSet::new();
        for token in &semantic {
            stats.entry(token.clone()).or_default().semantic += 1;
            doc_seen.insert(token.clone());
        }
        for token in &prototype {
            stats.entry(token.clone()).or_default().prototype += 1;
            doc_seen.insert(token.clone());
        }
        for token in &frame {
            stats.entry(token.clone()).or_default().frame += 1;
            doc_seen.insert(token.clone());
        }
        for token in &comment {
            stats.entry(token.clone()).or_default().comment += 1;
            doc_seen.insert(token.clone());
        }
        for token in &operand {
            stats.entry(token.clone()).or_default().operand += 1;
            doc_seen.insert(token.clone());
        }
        for token in doc_seen {
            stats.entry(token).or_default().docs += 1;
        }
    }

    let mut rows: Vec<(String, TokenStats)> = stats.into_iter().collect();
    rows.sort_by(|a, b| {
        b.1.docs
            .cmp(&a.1.docs)
            .then_with(|| {
                (b.1.semantic + b.1.prototype + b.1.frame + b.1.comment + b.1.operand)
                    .cmp(&(a.1.semantic + a.1.prototype + a.1.frame + a.1.comment + a.1.operand))
            })
            .then_with(|| a.0.cmp(&b.0))
    });

    println!("latest functions scanned: {}", latest.len());
    println!("records scanned: {}", total_records);
    println!(
        "top {} surviving neighbor tokens after current filter:\n",
        top_n.min(rows.len())
    );
    println!(
        "{:>4}  {:<32} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "#", "token", "docs", "sem", "proto", "frame", "cmt", "op"
    );
    for (idx, (token, stat)) in rows.into_iter().take(top_n).enumerate() {
        println!(
            "{:>4}  {:<32} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6}",
            idx + 1,
            token,
            stat.docs,
            stat.semantic,
            stat.prototype,
            stat.frame,
            stat.comment,
            stat.operand
        );
    }

    Ok(())
}

fn parse_record(bytes: &[u8]) -> Option<Record> {
    if bytes.len() < 12 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != MAGIC {
        return None;
    }
    let rec_len = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    if rec_len != bytes.len() {
        return None;
    }
    let body = &bytes[12..];
    if body.len() < 52 {
        return None;
    }

    let lo = u64::from_le_bytes(body[0..8].try_into().ok()?);
    let hi = u64::from_le_bytes(body[8..16].try_into().ok()?);
    let key = ((hi as u128) << 64) | (lo as u128);
    let ts_sec = u64::from_le_bytes(body[16..24].try_into().ok()?);
    let name_len = u16::from_le_bytes(body[40..42].try_into().ok()?) as usize;
    let data_len = u32::from_le_bytes(body[42..46].try_into().ok()?) as usize;

    let name_start = 52;
    if name_start + name_len + data_len > body.len() {
        return None;
    }
    let name = std::str::from_utf8(&body[name_start..name_start + name_len])
        .ok()?
        .to_string();
    let data_start = name_start + name_len;
    let data = body[data_start..data_start + data_len].to_vec();

    Some(Record {
        key,
        ts_sec,
        name,
        data,
    })
}

fn filtered_tokens(tokens: &[String]) -> Vec<String> {
    let mut out: Vec<String> = tokens
        .iter()
        .filter(|token| !is_generic_neighbor_token(token))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

fn is_generic_neighbor_token(token: &str) -> bool {
    let raw_lower = token.trim().to_ascii_lowercase();
    let normalized = normalize_neighbor_token(token);
    normalized.len() < 3
        || normalized.chars().all(|ch| ch.is_ascii_digit())
        || GENERIC_NEIGHBOR_TOKENS.contains(&raw_lower.as_str())
        || GENERIC_NEIGHBOR_TOKENS.contains(&normalized.as_str())
        || (normalized.starts_with("__") && normalized.ends_with("call"))
        || matches!(
            normalized.as_str(),
            "x86" | "x64" | "x86_64" | "amd64" | "arm" | "arm64" | "aarch64" | "mips" | "ppc"
        )
        || matches!(
            normalized.as_str(),
            "rax"
                | "rbx"
                | "rcx"
                | "rdx"
                | "rsi"
                | "rdi"
                | "rbp"
                | "rsp"
                | "eax"
                | "ebx"
                | "ecx"
                | "edx"
                | "esi"
                | "edi"
                | "ebp"
                | "esp"
                | "ax"
                | "bx"
                | "cx"
                | "dx"
                | "si"
                | "di"
                | "bp"
                | "sp"
                | "lr"
                | "pc"
                | "fp"
        )
        || normalized
            .strip_prefix('r')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || normalized
            .strip_prefix('x')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || normalized
            .strip_prefix('w')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || normalized
            .strip_prefix("__m")
            .map(|rest| !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false)
}

fn normalize_neighbor_token(token: &str) -> String {
    token
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .to_ascii_lowercase()
}
