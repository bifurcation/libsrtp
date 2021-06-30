// Rust-facing interfaces
pub mod aes_gcm;
pub mod aes_icm;
pub mod crypto_kernel;
pub mod crypto_test;
pub mod hmac;
pub mod kdf;
pub mod key_limit;
pub mod null_auth;
pub mod null_cipher;
pub mod policy;
pub mod replay;
mod rtp_header;
pub mod srtp;

// C-facing interfaces
mod c;
