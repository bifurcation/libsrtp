// Rust-facing interfaces
pub mod aes;
pub mod aes_icm;
pub mod crypto_kernel;
pub mod crypto_test;
pub mod hmac;
pub mod null_auth;
pub mod replay;
pub mod sha1;
pub mod srtp;

// C-facing interfaces
mod c;
