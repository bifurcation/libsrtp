// Rust-facing interfaces
pub mod replay;
pub mod sha1;
pub mod srtp;

#[cfg(test)]
mod ut_sim;

// C-facing interfaces
mod c;
pub use c::sha1::*;
