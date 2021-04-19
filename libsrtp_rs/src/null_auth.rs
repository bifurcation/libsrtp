use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::srtp::Error;

struct Null;

impl Auth for Null {
    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() > 0 {
            Err(Error::BadParam)
        } else {
            Ok(())
        }
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

pub struct NativeNull;

impl AuthType for NativeNull {
    fn id(&self) -> AuthTypeID {
        AuthTypeID::Null
    }

    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Auth>, Error> {
        if key_len > 0 || out_len > 0 {
            return Err(Error::BadParam);
        }

        Ok(Box::new(Null {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null() -> Result<(), Error> {
        let key: [u8; 0] = [];
        let data: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65]; // "Hi There"
        let expected_tag: [u8; 0] = [];
        let mut actual_tag: [u8; 0] = [];

        // Instantiate and check ID
        let auth_type = NativeNull {};
        let mut auth = auth_type.create(key.len(), actual_tag.len())?;
        assert_eq!(auth_type.id(), AuthTypeID::Null);

        // One step
        auth.init(&key)?;
        auth.compute(&data, &mut actual_tag)?;
        assert_eq!(actual_tag, expected_tag);

        // Two step
        auth.init(&key)?;
        auth.update(&data)?;
        auth.compute(&[], &mut actual_tag)?;
        assert_eq!(actual_tag, expected_tag);
        Ok(())
    }
}
