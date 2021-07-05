use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::srtp::Error;
use std::any::Any;

#[derive(Clone)]
struct Context;

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

    fn compute(&mut self, _message: &[u8], tag: &mut [u8]) -> Result<(), Error> {
        if tag.len() > 0 {
            Err(Error::AuthFail)
        } else {
            Ok(())
        }
    }

    fn clone_inner(&self) -> Box<dyn Auth> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equals(&self, other: &Box<dyn Auth>) -> bool {
        other.as_any().is::<Context>()
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
