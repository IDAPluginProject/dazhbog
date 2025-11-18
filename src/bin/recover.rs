use std::{io, path::PathBuf};
use std::collections::HashMap;

const MAGIC: u32 = 0x4C4D4E31;

mod crc32c_impl {
    use std::sync::Once;

    const POLY_REFLECTED: u32 = 0x82F63B78;
    const POLY_NONREFLECTED: u32 = 0x1EDC6F41;

    static INIT_REF: Once = Once::new();
    static mut TABLE_REF: [u32; 256] = [0; 256];

    static INIT_LEGACY: Once = Once::new();
    static mut TABLE_LEGACY: [u32; 256] = [0; 256];

    fn init_reflected() {
        unsafe {
            for i in 0..256 {
                let mut crc = i as u32;
                for _ in 0..8 {
                    if (crc & 1) != 0 {
                        crc = (crc >> 1) ^ POLY_REFLECTED;
                    } else {
                        crc >>= 1;
                    }
                }
                TABLE_REF[i] = crc;
            }
        }
    }

    fn init_legacy() {
        unsafe {
            for i in 0..256 {
                let mut crc = i as u32;
                for _ in 0..8 {
                    if (crc & 1) != 0 {
                        crc = (crc >> 1) ^ POLY_NONREFLECTED;
                    } else {
                        crc >>= 1;
                    }
                }
                TABLE_LEGACY[i] = crc;
            }
        }
    }

    pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
        INIT_REF.call_once(init_reflected);
        crc = !crc;
        for &b in data {
            let idx = (crc ^ (b as u32)) & 0xFF;
            let t = unsafe { TABLE_REF[idx as usize] };
            crc = (crc >> 8) ^ t;
        }
        !crc
    }

    pub fn crc32c_legacy(mut crc: u32, data: &[u8]) -> u32 {
        INIT_LEGACY.call_once(init_legacy);
        crc = !crc;
        for &b in data {
            let idx = (crc ^ (b as u32)) & 0xFF;
            let t = unsafe { TABLE_LEGACY[idx as usize] };
            crc = (crc >> 8) ^ t;
        }
        !crc
    }
}

#[derive(Clone)]
struct Record {
    key: u128,
    ts_sec: u64,
    prev_addr: u64,
    len_bytes: u32,
    popularity: u32,
    name: String,
    data: Vec<u8>,
    flags: u8,
}

fn scan_segment_tree(tree: &sled::Tree) -> io::Result<Vec<(u64, Record)>> {
    let mut records = Vec::new();
    println!("Scanning tree {} ({} records)", String::from_utf8_lossy(&tree.name()), tree.len());

    for item in tree.iter() {
        let (offset_bytes, record_bytes) = match item {
            Ok(i) => i,
            Err(e) => {
                eprintln!("  Error iterating tree: {}", e);
                continue;
            }
        };

        let off = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());

        if record_bytes.len() < 12 {
            continue;
        }
        let hdr: &[u8] = &record_bytes[0..12];

        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != MAGIC {
            eprintln!("  Skipping record at offset {} (bad magic)", off);
            continue;
        }

        let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if rec_len != record_bytes.len() {
            eprintln!("  Skipping record at offset {} (length mismatch)", off);
            continue;
        }

        let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let body = &record_bytes[12..];

        // Verify CRC
        let computed_crc = crc32c_impl::crc32c(0, body);
        let crc_valid = if computed_crc == stored_crc {
            true
        } else {
            let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
            computed_crc_legacy == stored_crc
        };

        if !crc_valid {
            println!("  Skipping corrupt record at offset {}", off);
            continue;
        }

        // Parse record
        if body.len() < 52 {
            continue;
        }

        let p = body;
        let lo = u64::from_le_bytes(p[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(p[8..16].try_into().unwrap());
        let key = ((hi as u128) << 64) | (lo as u128);
        let ts_sec = u64::from_le_bytes(p[16..24].try_into().unwrap());
        let prev_addr = u64::from_le_bytes(p[24..32].try_into().unwrap());
        let len_bytes = u32::from_le_bytes(p[32..36].try_into().unwrap());
        let popularity = u32::from_le_bytes(p[36..40].try_into().unwrap());
        let name_len = u16::from_le_bytes(p[40..42].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(p[42..46].try_into().unwrap()) as usize;
        let flags = p[46];

        let name_start = 52;
        if name_start + name_len + data_len > body.len() {
            continue;
        }

        let name = match std::str::from_utf8(&p[name_start..name_start + name_len]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let data_start = name_start + name_len;
        let data = p[data_start..data_start + data_len].to_vec();

        let rec = Record {
            key,
            ts_sec,
            prev_addr,
            len_bytes,
            popularity,
            name,
            data,
            flags,
        };

        records.push((off, rec));
    }

    println!("  Found {} valid records", records.len());
    Ok(records)
}

fn write_record_to_tree(tree: &sled::Tree, offset: u64, rec: &Record) -> io::Result<usize> {
    let name_len = rec.name.len() as u16;
    let data_len = rec.data.len() as u32;
    let body_len: usize = 8+8+8+8+4+4+2+4+1+5 + (name_len as usize) + (data_len as usize);
    let total_len = 4 + 4 + 4 + body_len;

    let mut buf = Vec::with_capacity(total_len);
    let rec_len = total_len as u32;

    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&rec_len.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf.extend_from_slice(&(rec.key as u64).to_le_bytes());
    buf.extend_from_slice(&((rec.key >> 64) as u64).to_le_bytes());
    buf.extend_from_slice(&rec.ts_sec.to_le_bytes());
    buf.extend_from_slice(&rec.prev_addr.to_le_bytes());
    buf.extend_from_slice(&rec.len_bytes.to_le_bytes());
    buf.extend_from_slice(&rec.popularity.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.push(rec.flags);
    buf.extend_from_slice(&[0u8; 5]);
    buf.extend_from_slice(rec.name.as_bytes());
    buf.extend_from_slice(&rec.data);

    let crc = crc32c_impl::crc32c(0, &buf[12..]);
    buf[8..12].copy_from_slice(&crc.to_le_bytes());

    tree.insert(offset.to_be_bytes(), buf.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(total_len)
}

fn main() -> io::Result<()> {
    let data_dir = PathBuf::from("data");
    let seg_db_dir = data_dir.join("segments_db");
    let backup_dir = PathBuf::from("data.backup");
    let temp_dir = PathBuf::from("data.recovered");

    if !seg_db_dir.exists() {
        eprintln!("Error: data/segments_db directory not found. This tool requires the new sled-based storage.");
        eprintln!("If you have old seg.*.dat files, run the main dazhbog server once to migrate them.");
        std::process::exit(1);
    }

    println!("=== Dazhbog Segment Recovery Tool (sled-based) ===\n");

    // Scan all segment trees in the sled database
    let mut all_records: HashMap<u128, Vec<Record>> = HashMap::new();
    let mut total_valid = 0;

    let db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    let mut tree_names: Vec<_> = db.tree_names().into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();

    tree_names.sort();

    for name in tree_names {
        let tree = db.open_tree(&name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {}", e)))?;

        match scan_segment_tree(&tree) {
            Ok(records) => {
                total_valid += records.len();
                for (_off, rec) in records {
                    all_records.entry(rec.key)
                        .or_insert_with(Vec::new)
                        .push(rec);
                }
            }
            Err(e) => {
                eprintln!("Error scanning tree {}: {}", name, e);
            }
        }
    }

    println!("\n=== Scan Results ===");
    println!("Total valid records: {}", total_valid);
    println!("Unique keys: {}", all_records.len());

    // Keep only the latest version of each key
    let mut final_records: Vec<Record> = Vec::new();
    for (_key, mut versions) in all_records {
        versions.sort_by(|a, b| b.ts_sec.cmp(&a.ts_sec));
        if let Some(latest) = versions.into_iter().next() {
            if latest.flags & 0x01 == 0 {
                final_records.push(latest);
            }
        }
    }

    println!("Records to recover (after dedup): {}", final_records.len());

    if final_records.is_empty() {
        println!("\nNo records to recover!");
        return Ok(());
    }

    // Create temp directory for new sled db
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }
    std::fs::create_dir_all(&temp_dir)?;

    // Write recovered records to new segment db
    println!("\n=== Writing recovered data ===");
    let recovered_db = sled::open(&temp_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open temp db: {}", e)))?;
    let recovered_tree = recovered_db.open_tree("seg.00001")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open temp tree: {}", e)))?;

    let mut offset = 0u64;
    for (i, rec) in final_records.iter().enumerate() {
        let len = write_record_to_tree(&recovered_tree, offset, rec)?;
        offset += len as u64;

        if (i + 1) % 1000 == 0 {
            println!("  Written {} records...", i + 1);
        }
    }

    recovered_db.flush()?;
    println!("  Written {} records to new database in {}", final_records.len(), temp_dir.display());
    drop(recovered_db);

    // Backup old segments
    println!("\n=== Creating backup ===");
    if backup_dir.exists() {
        std::fs::remove_dir_all(&backup_dir)?;
    }
    std::fs::create_dir_all(&backup_dir)?;
    std::fs::rename(&seg_db_dir, backup_dir.join("segments_db"))?;
    println!("  Old segment database backed up to {}", backup_dir.join("segments_db").display());

    // Move recovered segments to data directory
    std::fs::rename(&temp_dir, &seg_db_dir)?;
    println!("  Recovered segment database moved to {}", seg_db_dir.display());

    println!("\n=== Recovery Complete ===");
    println!("✓ Recovered {} unique records", final_records.len());
    println!("✓ Old segments backed up to: {}", backup_dir.display());
    println!("✓ New segments ready at: {}", data_dir.display());
    println!("\nYou can now restart the dazhbog server.");

    Ok(())
}
