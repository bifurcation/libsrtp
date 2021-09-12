use super::*;

#[derive(Clone)]
struct Context;

impl Reset for Context {
    fn reset(&mut self) {}
}

impl Auth for Context {
    fn tag_size(&self) -> usize {
        0
    }

    fn compute(&mut self, _inputs: &[&[u8]], _tag: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }

    fn constant_time_eq(&self, tag_a: &[u8], tag_b: &[u8]) -> bool {
        tag_a.is_empty() && tag_b.is_empty()
    }
}

pub struct NullAuth;

impl AuthType for NullAuth {
    fn id(&self) -> AuthTypeID {
        AuthTypeID::Null
    }

    fn create(&self, _key: &[u8], _tag_size: usize) -> Result<Box<dyn Auth>, Error> {
        Ok(Box::new(Context))
    }

    fn clone(&self) -> Box<dyn AuthType> {
        Box::new(NullAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::self_test;

    #[test]
    fn test_null_auth() -> Result<(), Error> {
        let auth_type = NullAuth {};
        assert_eq!(auth_type.id(), AuthTypeID::Null);

        let tests_passed = self_test::auth(&auth_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
