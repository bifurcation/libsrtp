use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::srtp::Error;

struct Context;

impl Auth for Context {
    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() > 0 {
            Err(Error::BadParam)
        } else {
            Ok(())
        }
    }

    fn start(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn update(&mut self, _update: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn compute(&mut self, _message: &[u8], tag: &mut [u8]) -> Result<(), Error> {
        if tag.len() > 0 {
            Err(Error::BadParam)
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

    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Auth>, Error> {
        if key_len > 0 || out_len > 0 {
            return Err(Error::BadParam);
        }

        Ok(Box::new(Context {}))
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
