use crate::crypto::{
    AuthType, AuthTypeID, CipherType, CipherTypeID, ExtensionCipherType, ExtensionCipherTypeID,
};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use hex_literal::hex;
use std::ops::Range;

//
// Extension Cipher Tests
//
struct ExtensionCipherTest {
    id: ExtensionCipherTypeID,
    key: &'static [u8],
    salt: &'static [u8],
    ssrc: u32,
    index: ExtendedSequenceNumber,
    ranges: &'static [Range<usize>],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
}

impl ExtensionCipherTest {
    fn run(&self, xtn_cipher_type: &dyn ExtensionCipherType) -> Result<(), Error> {
        let mut cipher = xtn_cipher_type.xtn_create(self.key, self.salt)?;
        cipher.init(self.ssrc, self.index)?;

        let mut enc_vec = vec![0u8; self.plaintext.len()];
        let enc_buffer = enc_vec.as_mut_slice();
        enc_buffer.copy_from_slice(self.plaintext);
        for r in self.ranges {
            cipher.xor_key(&mut enc_buffer[r.clone()], r.clone())?;
        }
        if enc_buffer != self.ciphertext {
            return Err(Error::AlgoFail);
        }

        Ok(())
    }
}

const XTN_CIPHER_TEST_DATA: &'static [ExtensionCipherTest] = &[
    ExtensionCipherTest {
        id: ExtensionCipherTypeID::Null,
        key: &[],
        salt: &[],
        ssrc: 0,
        index: 0,
        ranges: &[2..5, 7..10, 12..13],
        plaintext: &hex!("000102030405060708090a0b0c"),
        ciphertext: &hex!("000102030405060708090a0b0c"),
    },
    ExtensionCipherTest {
        id: ExtensionCipherTypeID::AesIcm128,
        key: &hex!("2b7e151628aed2a6abf7158809cf4f3c"),
        salt: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd"),
        ssrc: 0,
        index: 0,
        ranges: &[2..5, 7..10, 12..13],
        plaintext: &[0; 13],
        ciphertext: &hex!("0000ad0935000080e1660000d9"),
    },
    ExtensionCipherTest {
        id: ExtensionCipherTypeID::AesIcm192,
        key: &hex!("eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7"),
        salt: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd"),
        ssrc: 0,
        index: 0,
        ranges: &[2..5, 7..10, 12..13],
        plaintext: &[0; 13],
        ciphertext: &hex!("00006cba4600008dc1b5000080"),
    },
    ExtensionCipherTest {
        id: ExtensionCipherTypeID::AesIcm256,
        key: &hex!("57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98"),
        salt: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd"),
        ssrc: 0,
        index: 0,
        ranges: &[2..5, 7..10, 12..13],
        plaintext: &[0; 13],
        ciphertext: &hex!("0000d28a9300002511c600008b"),
    },
];

pub fn xtn_cipher(xtn_cipher_type: &dyn ExtensionCipherType) -> Result<usize, Error> {
    let mut tests_passed: usize = 0;
    for test in XTN_CIPHER_TEST_DATA {
        if test.id != xtn_cipher_type.xtn_id() {
            continue;
        }

        test.run(xtn_cipher_type)?;
        tests_passed += 1;
    }

    Ok(tests_passed)
}

//
// Cipher Tests
//
struct CipherTest {
    id: CipherTypeID,
    key: &'static [u8],
    salt: &'static [u8],
    nonce: &'static [u8],
    aad: &'static [u8],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
}

impl CipherTest {
    fn run(&self, cipher_type: &dyn CipherType) -> Result<(), Error> {
        let mut cipher = cipher_type.create(self.key, self.salt)?;

        let pt_size = self.plaintext.len();
        let ct_size = self.ciphertext.len();

        // Encrypt
        let mut enc_vec = vec![0u8; ct_size];
        let enc_buffer = enc_vec.as_mut_slice();
        enc_buffer[..pt_size].copy_from_slice(self.plaintext);

        cipher.reset();
        let enc_len = cipher.encrypt(self.nonce, &[self.aad], enc_buffer, pt_size)?;
        if enc_len != ct_size {
            return Err(Error::AlgoFail);
        }
        if enc_buffer != self.ciphertext {
            return Err(Error::AlgoFail);
        }

        // Decrypt
        let mut dec_vec = vec![0u8; ct_size];
        let dec_buffer = dec_vec.as_mut_slice();
        dec_buffer.copy_from_slice(self.ciphertext);

        cipher.reset();
        let dec_len = cipher.decrypt(self.nonce, &[self.aad], dec_buffer)?;
        if dec_len != pt_size {
            return Err(Error::AlgoFail);
        }
        if &dec_buffer[..pt_size] != self.plaintext {
            return Err(Error::AlgoFail);
        }

        Ok(())
    }
}

const CIPHER_TEST_DATA: &'static [CipherTest] = &[
    CipherTest {
        id: CipherTypeID::Null,
        key: &[],
        salt: &[],
        nonce: &[],
        aad: &[],
        plaintext: &hex!("01020304"),
        ciphertext: &hex!("01020304"),
    },
    CipherTest {
        id: CipherTypeID::AesIcm128,
        key: &hex!("2b7e151628aed2a6abf7158809cf4f3c"),
        salt: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd"),
        nonce: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000"),
        aad: &[],
        plaintext: &[0; 32],
        ciphertext: &hex!("e03ead0935c95e80e166b16dd92b4eb4d23513162b02d0f72a43a2fe4a5f97ab"),
    },
    CipherTest {
        id: CipherTypeID::AesIcm192,
        key: &hex!("eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7"),
        salt: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd"),
        nonce: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000"),
        aad: &[],
        plaintext: &[0; 32],
        ciphertext: &hex!("35096cba4610028dc1b57503804ce37c5de986291dcce161d5165ec4568f5c9a"),
    },
    CipherTest {
        id: CipherTypeID::AesIcm256,
        key: &hex!("57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98"),
        salt: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd"),
        nonce: &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000"),
        aad: &[],
        plaintext: &[0; 32],
        ciphertext: &hex!("92bdd28a93c3f52511c677d08b5515a49da71b2378a854f67050756ded165bac"),
    },
    CipherTest {
        id: CipherTypeID::AesGcm128,
        key: &hex!("feffe9928665731c6d6a8f9467308308"),
        salt: &hex!("0102030405060708090a0b0c"),
        nonce: &hex!("cafebabefacedbaddecaf888"),
        aad: &hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        plaintext: &hex!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d
             8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657
             ba637b39"
        ),
        ciphertext: &hex!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e23
             29aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac97
             3d58e0915bc94fbc3221a5db94fae95ae7121a47"
        ),
    },
    CipherTest {
        id: CipherTypeID::AesGcm256,
        key: &hex!("feffe9928665731ca55909c55466931caff5269a21d514b26d6a8f9467308308"),
        salt: &hex!("0102030405060708090a0b0c"),
        nonce: &hex!("cafebabefacedbaddecaf888"),
        aad: &hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        plaintext: &hex!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d
             8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657
             ba637b39"
        ),
        ciphertext: &hex!(
            "0b11cfaf684dae46c790b88eb76a762a9482caab3e39d7861bc793ed
             757f235adafdd3e20e8087a96dd7e26a7d5fb480efefc52912d1aa10
             09c986c145bc03e6e1ac0a9f81cb8e5b4665631d"
        ),
    },
];

pub fn cipher(cipher_type: &dyn CipherType) -> Result<usize, Error> {
    let mut tests_passed: usize = 0;
    for test in CIPHER_TEST_DATA {
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
        let mut auth = auth_type.create(self.key, self.tag.len())?;
        let mut tag = vec![0u8; tag_size(self.id)];

        auth.compute(&[&self.data], tag.as_mut_slice())?;
        if tag.as_slice() != self.tag {
            return Err(Error::AlgoFail);
        }

        Ok(())
    }
}

const AUTH_TEST_DATA: &'static [AuthTest] = &[
    AuthTest {
        id: AuthTypeID::Null,
        key: &[],
        data: &hex!("4869205468657265"),
        tag: &[],
    },
    AuthTest {
        id: AuthTypeID::HmacSha1,
        key: &[0x0b; 20],
        data: &hex!("4869205468657265"),
        tag: &hex!("b617318655057264e28bc0b6fb378c8ef146be00"),
    },
];

pub fn auth(auth_type: &dyn AuthType) -> Result<usize, Error> {
    let mut tests_passed: usize = 0;
    for test in AUTH_TEST_DATA {
        if test.id != auth_type.id() {
            continue;
        }

        test.run(auth_type)?;
        tests_passed += 1;
    }

    Ok(tests_passed)
}
