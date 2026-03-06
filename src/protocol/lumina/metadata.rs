//! Lumina function metadata parser.
//!
//! This module parses the binary metadata payloads that IDA Pro stores and retrieves
//! from Lumina servers. The metadata contains function-level information encoded as a
//! sequence of key-value pairs (mdkey_t).

use super::type_decoder::decode_tinfo_decl;
use super::wire::{unpack_dd, unpack_dq, unpack_dw, unpack_ea64, unpack_var_bytes_capped};

/// Known Lumina metadata keys (mdkey_t).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MdKey {
    None = 0,
    Type = 1,
    VdElapsed = 2,
    Fcmt = 3,
    Frptcmt = 4,
    Cmts = 5,
    Rptcmts = 6,
    Extracmts = 7,
    UserStkpnts = 8,
    FrameDesc = 9,
    Ops = 10,
    OpsEx = 11,
    Other(u32),
}

impl From<u32> for MdKey {
    fn from(val: u32) -> Self {
        match val {
            0 => MdKey::None,
            1 => MdKey::Type,
            2 => MdKey::VdElapsed,
            3 => MdKey::Fcmt,
            4 => MdKey::Frptcmt,
            5 => MdKey::Cmts,
            6 => MdKey::Rptcmts,
            7 => MdKey::Extracmts,
            8 => MdKey::UserStkpnts,
            9 => MdKey::FrameDesc,
            10 => MdKey::Ops,
            11 => MdKey::OpsEx,
            other => MdKey::Other(other),
        }
    }
}

/// Extracted type information from `MDK_TYPE` (Key 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdTypeParts {
    /// True if this is a user-defined type
    pub userti: bool,
    /// Raw IDA type_t bytes
    pub type_bytes: Vec<u8>,
    /// Raw IDA p_list bytes
    pub fields_bytes: Vec<u8>,
    /// Decoded declaration rendered from the raw bytes
    pub declaration: Option<String>,
    /// Decode failure, if any
    pub decode_error: Option<String>,
}

/// Serialized `tinfo_t` from `MDK_FRAME_DESC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedTinfo {
    pub type_bytes: Vec<u8>,
    pub fields_bytes: Vec<u8>,
    pub declaration: Option<String>,
    pub decode_error: Option<String>,
}

/// A member of a stack frame (stack variable, register save, etc).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameMem {
    pub name: Option<String>,
    pub tinfo: Option<SerializedTinfo>,
    pub cmt: Option<String>,
    pub rptcmt: Option<String>,
    pub offset: Option<u64>,
    /// We parse oprepr_t enough to skip it, but optionally keep the raw bytes.
    pub info: Option<Vec<u8>>,
    pub nbytes: Option<u64>,
}

/// Frame description and layout from `MDK_FRAME_DESC` (Key 9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameDesc {
    pub frsize: u64,
    pub argsize: u64,
    pub frregs: u16,
    pub members: Vec<FrameMem>,
}

/// An instruction site comment (MDK_CMTS / MDK_RPTCMTS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsnCmt {
    pub fchunk_nr: u32,
    pub fchunk_off: u32,
    pub cmt: String,
}

/// Complete parsed function metadata.
#[derive(Debug, Clone, Default)]
pub struct FunctionMetadata {
    pub raw_size: usize,
    /// Parsed MDK_TYPE data if present
    pub type_parts: Option<MdTypeParts>,
    /// Parsed MDK_FRAME_DESC data if present
    pub frame_desc: Option<FrameDesc>,
    /// Decompile time in seconds (MDK_VD_ELAPSED)
    pub vd_elapsed: Option<u64>,
    /// Function regular comment (MDK_FCMT)
    pub fcmt: Option<String>,
    /// Function repeatable comment (MDK_FRPTCMT)
    pub frptcmt: Option<String>,
    /// Instruction regular comments (MDK_CMTS)
    pub insn_cmts: Vec<InsnCmt>,
    /// Instruction repeatable comments (MDK_RPTCMTS)
    pub rpt_insn_cmts: Vec<InsnCmt>,
    /// Other metadata parts could be added here
    pub bytes_parsed: usize,
    pub errors: Vec<String>,
}

impl FunctionMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn component_count(&self) -> usize {
        let mut count = 0;
        if self.type_parts.is_some() {
            count += 1;
        }
        if let Some(fd) = &self.frame_desc {
            count += fd.members.len();
        }
        count
    }
}

pub struct MetadataParser<'a> {
    data: &'a [u8],
    offset: usize,
    result: FunctionMetadata,
}

impl<'a> MetadataParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            result: FunctionMetadata {
                raw_size: data.len(),
                ..Default::default()
            },
        }
    }

    pub fn parse(data: &'a [u8]) -> FunctionMetadata {
        let mut parser = Self::new(data);
        parser.do_parse();
        parser.result
    }

    fn read_dd(&mut self) -> Option<u32> {
        let (val, consumed) = unpack_dd(&self.data[self.offset..]);
        if consumed == 0 {
            return None;
        }
        self.offset += consumed;
        Some(val)
    }

    fn do_parse(&mut self) {
        while self.offset < self.data.len() {
            let key_val = match self.read_dd() {
                Some(k) => k,
                None => break,
            };
            let mdkey = MdKey::from(key_val);
            if mdkey == MdKey::None {
                break; // 0 marks end or invalid
            }

            let len = match self.read_dd() {
                Some(l) => l as usize,
                None => break,
            };

            if self.offset + len > self.data.len() {
                self.result
                    .errors
                    .push(format!("Chunk length {} exceeds payload size", len));
                break;
            }

            let chunk = &self.data[self.offset..self.offset + len];
            self.offset += len;

            match mdkey {
                MdKey::Type => {
                    if let Some(parts) = parse_mdk_type(chunk) {
                        self.result.type_parts = Some(parts);
                    } else {
                        self.result.errors.push("Failed to parse MDK_TYPE".into());
                    }
                }
                MdKey::FrameDesc => {
                    if let Some(fd) = parse_frame_desc(chunk) {
                        self.result.frame_desc = Some(fd);
                    } else {
                        self.result
                            .errors
                            .push("Failed to parse MDK_FRAME_DESC".into());
                    }
                }
                MdKey::Fcmt => {
                    let s = String::from_utf8_lossy(chunk).into_owned();
                    self.result.fcmt = Some(s.trim_end_matches('\0').to_string());
                }
                MdKey::Frptcmt => {
                    let s = String::from_utf8_lossy(chunk).into_owned();
                    self.result.frptcmt = Some(s.trim_end_matches('\0').to_string());
                }
                MdKey::Cmts => {
                    if let Some(cmts) = parse_insn_cmts(chunk) {
                        self.result.insn_cmts = cmts;
                    } else {
                        self.result.errors.push("Failed to parse MDK_CMTS".into());
                    }
                }
                MdKey::Rptcmts => {
                    if let Some(cmts) = parse_insn_cmts(chunk) {
                        self.result.rpt_insn_cmts = cmts;
                    } else {
                        self.result
                            .errors
                            .push("Failed to parse MDK_RPTCMTS".into());
                    }
                }
                MdKey::VdElapsed => {
                    let (val, consumed) = unpack_dq(chunk);
                    if consumed > 0 {
                        self.result.vd_elapsed = Some(val);
                    }
                }
                _ => {
                    // Ignore other keys for now
                }
            }
        }
        self.result.bytes_parsed = self.offset;
    }
}

fn parse_mdk_type(data: &[u8]) -> Option<MdTypeParts> {
    if data.is_empty() {
        return None;
    }
    let userti = data[0] != 0;
    let rest = &data[1..];

    let (type_bytes, fields_bytes) = if let Some(nul_pos) = rest.iter().position(|&b| b == 0) {
        let type_bytes = rest[..nul_pos].to_vec();
        let mut fields_bytes = rest[nul_pos + 1..].to_vec();
        while fields_bytes.last().copied() == Some(0) {
            fields_bytes.pop();
        }
        (type_bytes, fields_bytes)
    } else {
        (rest.to_vec(), Vec::new())
    };

    let (declaration, decode_error) = match decode_tinfo_decl(&type_bytes, &fields_bytes) {
        Ok(decl) => (Some(decl), None),
        Err(err) => (None, Some(err)),
    };

    Some(MdTypeParts {
        userti,
        type_bytes,
        fields_bytes,
        declaration,
        decode_error,
    })
}

fn parse_frame_desc(data: &[u8]) -> Option<FrameDesc> {
    let mut parser = FrameParser { data, offset: 0 };

    let frsize = parser.read_ea64()?;
    let argsize = parser.read_ea64()?;
    let frregs = parser.read_dw()?;
    let n = parser.read_dd()?;

    // Sanity check to avoid OOM on malformed payloads
    if n > 10000 {
        return None;
    }

    let mut members = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mem = parser.read_frame_mem()?;
        members.push(mem);
    }

    Some(FrameDesc {
        frsize,
        argsize,
        frregs,
        members,
    })
}

fn parse_insn_cmts(data: &[u8]) -> Option<Vec<InsnCmt>> {
    let mut offset = 0;

    // unpack initial chunk number
    let (mut fchunk_nr, consumed) = unpack_dd(&data[offset..]);
    if consumed == 0 {
        return None;
    }
    offset += consumed;

    let mut fchunk_off = 0;
    let mut first_in_fchunk = true;
    let mut cmts = Vec::new();

    while offset < data.len() {
        let (delta, consumed) = unpack_dd(&data[offset..]);
        if consumed == 0 {
            break;
        }
        offset += consumed;

        if !first_in_fchunk && delta == 0 {
            // switch to new fchunk
            let (nr, consumed) = unpack_dd(&data[offset..]);
            if consumed == 0 {
                break;
            }
            offset += consumed;
            fchunk_nr = nr;
            fchunk_off = 0;
            first_in_fchunk = true;
            continue;
        }

        fchunk_off += delta;

        // read string (var bytes)
        let (val, consumed) = unpack_var_bytes_capped(&data[offset..], 65536).ok()?;
        offset += consumed;

        let cmt = String::from_utf8_lossy(val).into_owned();
        cmts.push(InsnCmt {
            fchunk_nr,
            fchunk_off,
            cmt: cmt.trim_end_matches('\0').to_string(),
        });

        first_in_fchunk = false;
    }

    Some(cmts)
}

struct FrameParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> FrameParser<'a> {
    fn read_db(&mut self) -> Option<u8> {
        let b = self.data.get(self.offset).copied()?;
        self.offset += 1;
        Some(b)
    }

    fn read_dw(&mut self) -> Option<u16> {
        let (v, consumed) = unpack_dw(&self.data[self.offset..]);
        if consumed == 0 {
            return None;
        }
        self.offset += consumed;
        Some(v)
    }

    fn read_dd(&mut self) -> Option<u32> {
        let (v, consumed) = unpack_dd(&self.data[self.offset..]);
        if consumed == 0 {
            return None;
        }
        self.offset += consumed;
        Some(v)
    }

    fn read_dq(&mut self) -> Option<u64> {
        let (v, consumed) = unpack_dq(&self.data[self.offset..]);
        if consumed == 0 {
            return None;
        }
        self.offset += consumed;
        Some(v)
    }

    fn read_ea64(&mut self) -> Option<u64> {
        let (v, consumed) = unpack_ea64(&self.data[self.offset..]);
        if consumed == 0 {
            return None;
        }
        self.offset += consumed;
        Some(v)
    }

    fn read_cstr_bytes(&mut self) -> Option<Vec<u8>> {
        let start = self.offset;
        let mut end = start;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        if end >= self.data.len() {
            return None; // No null terminator
        }
        let s = self.data[start..end].to_vec();
        self.offset = end + 1;
        Some(s)
    }

    fn read_str(&mut self) -> Option<String> {
        Some(String::from_utf8_lossy(&self.read_cstr_bytes()?).into_owned())
    }

    fn read_tinfo(&mut self) -> Option<SerializedTinfo> {
        let type_bytes = self.read_cstr_bytes()?;
        let fields_bytes = self.read_cstr_bytes()?;
        let (declaration, decode_error) = match decode_tinfo_decl(&type_bytes, &fields_bytes) {
            Ok(decl) => (Some(decl), None),
            Err(err) => (None, Some(err)),
        };
        Some(SerializedTinfo {
            type_bytes,
            fields_bytes,
            declaration,
            decode_error,
        })
    }

    fn skip_oprepr(&mut self) -> Option<Vec<u8>> {
        let start_offset = self.offset;
        let flags = self.read_db()?;
        if (flags & 0x0F) == 0x05 {
            // consume 7 varints
            for _ in 0..7 {
                self.read_dd()?; // read_dd skips the bytes correctly for any dd
            }
        }
        Some(self.data[start_offset..self.offset].to_vec())
    }

    fn read_frame_mem(&mut self) -> Option<FrameMem> {
        let greedy_bits = self.read_db()?;
        let mut mem = FrameMem::default();

        if (greedy_bits & (1 << 0)) != 0 {
            mem.name = Some(self.read_str()?);
        }
        if (greedy_bits & (1 << 1)) != 0 {
            mem.tinfo = Some(self.read_tinfo()?);
        }
        if (greedy_bits & (1 << 2)) != 0 {
            mem.cmt = Some(self.read_str()?);
        }
        if (greedy_bits & (1 << 3)) != 0 {
            mem.rptcmt = Some(self.read_str()?);
        }
        if (greedy_bits & (1 << 4)) != 0 {
            mem.offset = Some(self.read_ea64()?);
        }
        if (greedy_bits & (1 << 5)) != 0 {
            mem.info = Some(self.skip_oprepr()?);
        }
        if (greedy_bits & (1 << 6)) != 0 {
            mem.nbytes = Some(self.read_ea64()?); // safe_unpack_asize
        }

        Some(mem)
    }
}

pub fn parse_metadata(data: &[u8]) -> FunctionMetadata {
    MetadataParser::parse(data)
}
