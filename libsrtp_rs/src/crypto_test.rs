use crate::crypto_kernel::{AuthType, AuthTypeID, CipherDirection, CipherType, CipherTypeID};
use crate::srtp::Error;

//
// Cipher Tests
//
struct CipherTest {
    id: CipherTypeID,
    key: &'static [u8],
    nonce: &'static [u8],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
}

impl CipherTest {
    fn run(&self, cipher_type: &dyn CipherType) -> Result<(), Error> {
        let mut cipher = cipher_type.create(self.key.len(), 0)?;

        // TODO(RLB) AEAD additions below

        // Encrypt
        cipher.init(&self.key)?;
        cipher.set_iv(&self.nonce, CipherDirection::Encrypt)?;

        let mut encrypt_vec = vec![0u8; self.ciphertext.len()];
        let encrypt_buffer = encrypt_vec.as_mut_slice();
        encrypt_buffer.copy_from_slice(self.plaintext);
        let mut encrypt_len = self.plaintext.len();
        let encrypt_len = cipher.encrypt(encrypt_buffer, encrypt_buffer.len())?;
        if encrypt_len != self.ciphertext.len() {
            return Err(Error::AlgoFail);
        }
        if encrypt_buffer != self.ciphertext {
            return Err(Error::AlgoFail);
        }

        // Decrypt
        cipher.init(&self.key)?;
        cipher.set_iv(&self.nonce, CipherDirection::Decrypt)?;

        let mut decrypt_vec = vec![0u8; self.ciphertext.len()];
        let decrypt_buffer = decrypt_vec.as_mut_slice();
        decrypt_buffer.copy_from_slice(self.ciphertext);
        let decrypt_len = cipher.decrypt(decrypt_buffer, decrypt_buffer.len())?;
        if decrypt_len != self.plaintext.len() {
            return Err(Error::AlgoFail);
        }
        if decrypt_buffer != self.plaintext {
            return Err(Error::AlgoFail);
        }

        Ok(())
    }
}

const CIPHER_TEST_DATA: [CipherTest; 3] = [
    CipherTest {
        id: CipherTypeID::Null,
        key: &[],
        nonce: &[],
        plaintext: &[1, 2, 3, 4],
        ciphertext: &[1, 2, 3, 4],
    },
    CipherTest {
        id: CipherTypeID::AesIcm128,
        key: &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
            0xfc, 0xfd,
        ],
        nonce: &[0; 16],
        plaintext: &[0; 32],
        ciphertext: &[
            0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80, 0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b,
            0x4e, 0xb4, 0xd2, 0x35, 0x13, 0x16, 0x2b, 0x02, 0xd0, 0xf7, 0x2a, 0x43, 0xa2, 0xfe,
            0x4a, 0x5f, 0x97, 0xab,
        ],
    },
    CipherTest {
        id: CipherTypeID::AesIcm256,
        key: &[
            0x57, 0xf8, 0x2f, 0xe3, 0x61, 0x3f, 0xd1, 0x70, 0xa8, 0x5e, 0xc9, 0x3c, 0x40, 0xb1,
            0xf0, 0x92, 0x2e, 0xc4, 0xcb, 0x0d, 0xc0, 0x25, 0xb5, 0x82, 0x72, 0x14, 0x7c, 0xc4,
            0x38, 0x94, 0x4a, 0x98, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
            0xfa, 0xfb, 0xfc, 0xfd,
        ],
        nonce: &[0; 16],
        plaintext: &[0; 32],
        ciphertext: &[
            0x92, 0xbd, 0xd2, 0x8a, 0x93, 0xc3, 0xf5, 0x25, 0x11, 0xc6, 0x77, 0xd0, 0x8b, 0x55,
            0x15, 0xa4, 0x9d, 0xa7, 0x1b, 0x23, 0x78, 0xa8, 0x54, 0xf6, 0x70, 0x50, 0x75, 0x6d,
            0xed, 0x16, 0x5b, 0xac,
        ],
    },
];

pub fn cipher(cipher_type: &dyn CipherType) -> Result<usize, Error> {
    let mut tests_passed: usize = 0;
    for test in &CIPHER_TEST_DATA {
        if test.id != cipher_type.id() {
            continue;
        }

        test.run(cipher_type)?;
        tests_passed += 1;
    }

    Ok(tests_passed)
}

//
// Auth Tests
//
const fn tag_size(id: AuthTypeID) -> usize {
    match id {
        AuthTypeID::Null => 0,
        AuthTypeID::HmacSha1 => 20,
    }
}

struct AuthTest {
    id: AuthTypeID,
    key: &'static [u8],
    data: &'static [u8],
    tag: &'static [u8],
}

impl AuthTest {
    fn run(&self, auth_type: &dyn AuthType) -> Result<(), Error> {
        let mut auth = auth_type.create(self.key.len(), self.tag.len())?;
        let mut computed_tag = vec![0u8; tag_size(self.id)];

        // One step
        auth.init(&self.key)?;
        auth.compute(&self.data, computed_tag.as_mut_slice())?;
        if computed_tag.as_slice() != self.tag {
            return Err(Error::AlgoFail);
        }

        // Two step
        auth.init(&self.key)?;
        auth.update(&self.data)?;
        auth.compute(&[], computed_tag.as_mut_slice())?;
        if computed_tag.as_slice() != self.tag {
            return Err(Error::AlgoFail);
        }

        Ok(())
    }
}

const AUTH_TEST_DATA: [AuthTest; 2] = [
    AuthTest {
        id: AuthTypeID::Null,
        key: &[],
        data: &[0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65],
        tag: &[],
    },
    AuthTest {
        id: AuthTypeID::HmacSha1,
        key: &[0x0b; 20],
        data: &[0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65],
        tag: &[
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ],
    },
];

pub fn auth(auth_type: &dyn AuthType) -> Result<usize, Error> {
    let mut tests_passed: usize = 0;
    for test in &AUTH_TEST_DATA {
        if test.id != auth_type.id() {
            continue;
        }

        test.run(auth_type)?;
        tests_passed += 1;
    }

    Ok(tests_passed)
}
