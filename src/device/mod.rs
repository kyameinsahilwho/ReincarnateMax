//! Device engine: physical drives, volumes, shadow copies and image files, all opened read-only.
//! `source.rs` (trait, windows, tolerant reads) is the orchestrator's; the rest is the device agent's.

pub mod image;
pub mod imaging;
pub mod list;
pub mod smart;
pub mod source;
pub mod win;
