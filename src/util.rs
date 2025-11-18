pub fn now_ts_sec() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[inline]
pub const fn pack_addr(seg_id: u16, offset: u64, flags: u8) -> u64 {
    ((seg_id as u64) << 48) | ((offset & ((1u64 << 40) - 1)) << 8) | (flags as u64)
}
#[inline]
pub const fn addr_seg(addr: u64) -> u16 {
    (addr >> 48) as u16
}
#[inline]
pub const fn addr_off(addr: u64) -> u64 {
    (addr >> 8) & ((1u64 << 40) - 1)
}

#[inline]
pub fn wyhash64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

#[allow(dead_code)]
#[inline]
pub fn key_tag(key: u128) -> u64 {
    let lo = key as u64;
    let hi = (key >> 64) as u64;
    wyhash64(lo ^ hi)
}

pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    let limit = data.len().min(max_bytes);
    let mut result = String::new();

    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        result.push_str(&format!("{:04x}: ", i * 16));

        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x} ", byte));
        }

        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        result.push_str(" |");

        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }

        result.push_str("|\n");
    }

    if data.len() > max_bytes {
        result.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
    }

    result
}

/// Stable version identifier: 16-byte key (LE) + 8-byte hash(name) + 8-byte hash(data).
pub fn version_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&key.to_le_bytes());
    let name_hash = wyhash64(hash_bytes64(name.as_bytes()));
    let data_hash = wyhash64(hash_bytes64(data));
    out[16..24].copy_from_slice(&name_hash.to_le_bytes());
    out[24..32].copy_from_slice(&data_hash.to_le_bytes());
    out
}

#[inline]
fn hash_bytes64(b: &[u8]) -> u64 {
    // Simple streaming mix into a u64 seed
    let mut h: u64 = 0x9e3779b185ebca87;
    let mut i = 0usize;
    while i + 8 <= b.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i..i + 8]);
        let v = u64::from_le_bytes(w);
        h = h.wrapping_add(v);
        h = wyhash64(h);
        i += 8;
    }
    if i < b.len() {
        let mut tail = [0u8; 8];
        let remain = &b[i..];
        tail[..remain.len()].copy_from_slice(remain);
        let v = u64::from_le_bytes(tail);
        h = h.wrapping_add(v);
        h = wyhash64(h);
    }
    h ^ (b.len() as u64)
}
