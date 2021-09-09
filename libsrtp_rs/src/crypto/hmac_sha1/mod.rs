// Define all implementations
mod openssl;
mod rust_crypto;

// Export the crypto that was actually built
#[cfg(feature = "rust-crypto")]
pub use self::rust_crypto::*;

#[cfg(feature = "openssl-crypto")]
pub use self::openssl::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self_test, AuthType, AuthTypeID};
    use crate::srtp::Error;

    #[test]
    fn test_hmac() -> Result<(), Error> {
        let auth_type = HmacSha1 {};
        assert_eq!(auth_type.id(), AuthTypeID::HmacSha1);

        let tests_passed = self_test::auth(&auth_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
