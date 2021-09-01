use crate::crypto_kernel::{Auth, AuthType, AuthTypeID, Reset};
use crate::srtp::Error;

#[derive(Clone)]
struct Context;

impl Reset for Context {
    fn reset(&mut self) {}
}

impl Auth for Context {
    fn tag_size(&self) -> usize {
        0
    }

    fn prefix_size(&self) -> usize {
        0
    }

    fn start(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn update(&mut self, _update: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn compute(&mut self, tag: &mut [u8]) -> Result<(), Error> {
        if tag.len() > 0 {
            Err(Error::AuthFail)
        } else {
            Ok(())
        }
    }
}

pub struct NullAuth;

impl AuthType for NullAuth {
    fn id(&self) -> AuthTypeID {
        AuthTypeID::Null
    }

    fn create(&self, key: &[u8], tag_size: usize) -> Result<Box<dyn Auth>, Error> {
        if key.len() > 0 || tag_size > 0 {
            return Err(Error::BadParam);
        }

        Ok(Box::new(Context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_null_auth() -> Result<(), Error> {
        let auth_type = NullAuth {};
        assert_eq!(auth_type.id(), AuthTypeID::Null);

        let tests_passed = crypto_test::auth(&auth_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
