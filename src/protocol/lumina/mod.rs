//! IDA Pro Lumina protocol implementation.
//!
//! This module implements the Lumina protocol used by IDA Pro for function metadata exchange.
//! It supports:
//! - Protocol parsing (server-side)
//! - Response building (server-side)
//! - Client-side helpers for upstream forwarding
//! - Function metadata parsing (metadata payloads)

mod builder;
pub mod metadata;
mod parser;
pub(crate) mod type_decoder;
mod types;
mod wire;

pub use crate::common::error::LuminaError;
pub use builder::*;
pub use metadata::{
    parse_metadata, FrameDesc, FrameMem, FunctionMetadata, InsnCmt, MdKey, MdTypeParts,
    MetadataParser,
};
pub use parser::*;
pub use types::*;
pub use wire::*;
