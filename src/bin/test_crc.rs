use std::io;

mod crc {
    pub fn crc32c_inline(mut crc: u32, data: &[u8]) -> u32 {
        const POLY: u32 = 0x82F63B78;
        crc = !crc;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ POLY;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    pub fn crc32c_table(mut crc: u32, data: &[u8]) -> u32 {
        const POLY: u32 = 0x82F63B78;
        let mut table = [0u32; 256];
        for i in 0..256 {
            let mut c = i as u32;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = (c >> 1) ^ POLY;
                } else {
                    c >>= 1;
                }
            }
            table[i] = c;
        }

        crc = !crc;
        for &b in data {
            let idx = (crc ^ (b as u32)) & 0xFF;
            crc = (crc >> 8) ^ table[idx as usize];
        }
        !crc
    }
}

fn main() -> io::Result<()> {
    let seg_db_path = "data/segments_db";
    println!("Opening sled database at: {}", seg_db_path);
    let db = sled::open(seg_db_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    let tree_name = "seg.00001";
    println!("Opening tree: {}", tree_name);
    let tree = db
        .open_tree(tree_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {}", e)))?;

    let first_item = tree.iter().next();

    let record_bytes = match first_item {
        Some(Ok((_, val))) => val,
        Some(Err(e)) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled iter: {}", e),
            ))
        }
        None => {
            eprintln!("Tree {} is empty or could not read first item.", tree_name);
            return Ok(());
        }
    };

    if record_bytes.len() < 12 {
        eprintln!("First record is too short.");
        return Ok(());
    }

    let hdr = &record_bytes[0..12];
    let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

    let body = &record_bytes[12..];

    println!("Record length: {}", rec_len);
    println!("Body length:   {}", body.len());

    let computed_inline = crc::crc32c_inline(0, body);
    let computed_table = crc::crc32c_table(0, body);

    println!("Stored CRC:      0x{:08x}", stored_crc);
    println!(
        "Computed inline: 0x{:08x} {}",
        computed_inline,
        if stored_crc == computed_inline {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "Computed table:  0x{:08x} {}",
        computed_table,
        if stored_crc == computed_table {
            "✓"
        } else {
            "✗"
        }
    );

    Ok(())
}
