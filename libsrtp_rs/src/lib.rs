// Rust-facing interfaces
pub mod sha1;

// C-facing interfaces

#[no_mangle]
pub extern "C" fn rust_noop() {}

mod sha1_c;
pub use sha1_c::*;
