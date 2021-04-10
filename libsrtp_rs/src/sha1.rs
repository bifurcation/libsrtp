use std::convert::TryFrom;
use std::os::raw::c_int;

fn s1(x: u32) -> u32 {
    x.rotate_left(1)
}
fn s5(x: u32) -> u32 {
    x.rotate_left(5)
}
fn s30(x: u32) -> u32 {
    x.rotate_left(30)
}

fn f0(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

fn f1(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn f2(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

fn f3(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

const K0: u32 = 0x5A827999; // Kt for 0  <= t <= 19
const K1: u32 = 0x6ED9EBA1; // Kt for 20 <= t <= 39
const K2: u32 = 0x8F1BBCDC; // Kt for 40 <= t <= 59
const K3: u32 = 0xCA62C1D6; // Kt for 60 <= t <= 79

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Context {
    pub h: [u32; 5],             // state vector
    pub m: [u8; 64],             // message buffer
    pub octets_in_buffer: c_int, // octets of message in buffer
    pub num_bits_in_msg: u32,    // total number of bits in message
}

impl Context {
    pub fn new() -> Self {
        Self {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            m: [0; 64],
            octets_in_buffer: 0,
            num_bits_in_msg: 0,
        }
    }

    fn octets_in_buffer_usize(&self) -> usize {
        usize::try_from(self.octets_in_buffer).unwrap()
    }

    fn fill_buffer(&mut self, msg: &[u8]) -> usize {
        let octets_in_buffer = self.octets_in_buffer_usize();
        let remaining = self.m.len() - octets_in_buffer;
        let to_read = if msg.len() < remaining {
            msg.len()
        } else {
            remaining
        };

        let start = octets_in_buffer;
        let end = start + to_read;
        self.m[start..end].clone_from_slice(&msg[..to_read]);
        self.octets_in_buffer += c_int::try_from(to_read).unwrap();
        self.num_bits_in_msg += u32::try_from(8 * to_read).unwrap();
        to_read
    }

    fn core(&mut self) {
        let mut w: [u32; 80] = [0; 80];
        for i in 0..16 {
            let array = <[u8; 4]>::try_from(&self.m[(4 * i)..(4 * (i + 1))]).unwrap();
            w[i] = u32::from_be_bytes(array);
        }
        for i in 16..80 {
            w[i] = s1(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for t in 0..20 {
            let temp = s5(a)
                .wrapping_add(f0(b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K0);
            e = d;
            d = c;
            c = s30(b);
            b = a;
            a = temp;
        }
        for t in 20..40 {
            let temp = s5(a)
                .wrapping_add(f1(b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K1);
            e = d;
            d = c;
            c = s30(b);
            b = a;
            a = temp;
        }
        for t in 40..60 {
            let temp = s5(a)
                .wrapping_add(f2(b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K2);
            e = d;
            d = c;
            c = s30(b);
            b = a;
            a = temp;
        }
        for t in 60..80 {
            let temp = s5(a)
                .wrapping_add(f3(b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K3);
            e = d;
            d = c;
            c = s30(b);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);

        self.m = [0; 64];
        self.octets_in_buffer = 0;
    }

    pub fn update(&mut self, msg: &[u8]) {
        let mut start: usize = 0;
        while start < msg.len() {
            let read = self.fill_buffer(&msg[start..]);
            if self.octets_in_buffer_usize() == self.m.len() {
                self.core();
            }

            start += read;
        }
    }

    pub fn finalize(&mut self, output: &mut [u8]) {
        // Write a final one bit
        let final_msg_bits = self.num_bits_in_msg;
        self.update(&[0x80u8]);

        // Write the length
        if self.octets_in_buffer > 56 {
            self.core();
        }

        self.m[60] = (final_msg_bits >> 24) as u8;
        self.m[61] = (final_msg_bits >> 16) as u8;
        self.m[62] = (final_msg_bits >> 8) as u8;
        self.m[63] = (final_msg_bits >> 0) as u8;
        self.core();

        // Copy the cached hash value to the output
        output[0..4].copy_from_slice(&self.h[0].to_be_bytes());
        output[4..8].copy_from_slice(&self.h[1].to_be_bytes());
        output[8..12].copy_from_slice(&self.h[2].to_be_bytes());
        output[12..16].copy_from_slice(&self.h[3].to_be_bytes());
        output[16..20].copy_from_slice(&self.h[4].to_be_bytes());

        self.reset();
    }

    pub fn reset(&mut self) {
        self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        self.m = [0; 64];
        self.octets_in_buffer = 0;
        self.num_bits_in_msg = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() -> Result<(), hex::FromHexError> {
        struct TestCase {
            input: &'static str,
            output: &'static str,
        }

        let test_cases: [TestCase; 65] = [
            TestCase {
                input: "",
                output: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            },
            TestCase {
                input: "a8",
                output: "99f2aa95e36f95c2acb0eaf23998f030638f3f15",
            },
            TestCase {
                input: "3000",
                output: "f944dcd635f9801f7ac90a407fbc479964dec024",
            },
            TestCase {
                input: "42749e",
                output: "a444319e9b6cc1e8464c511ec0969c37d6bb2619",
            },
            TestCase {
                input: "9fc3fe08",
                output: "16a0ff84fcc156fd5d3ca3a744f20a232d172253",
            },
            TestCase {
                input: "b5c1c6f1af",
                output: "fec9deebfcdedaf66dda525e1be43597a73a1f93",
            },
            TestCase {
                input: "e47571e5022e",
                output: "8ce051181f0ed5e9d0c498f6bc4caf448d20deb5",
            },
            TestCase {
                input: "3e1b28839fb758",
                output: "67da53837d89e03bf652ef09c369a3415937cfd3",
            },
            TestCase {
                input: "a81350cbb224cb90",
                output: "305e4ff9888ad855a78573cddf4c5640cce7e946",
            },
            TestCase {
                input: "c243d167923dec3ce1",
                output: "5902b77b3265f023f9bbc396ba1a93fa3509bde7",
            },
            TestCase {
                input: "50ac18c59d6a37a29bf4",
                output: "fcade5f5d156bf6f9af97bdfa9c19bccfb4ff6ab",
            },
            TestCase {
                input: "98e2b611ad3b1cccf634f6",
                output: "1d20fbe00533c10e3cbd6b27088a5de0c632c4b5",
            },
            TestCase {
                input: "73fe9afb68e1e8712e5d4eec",
                output: "7e1b7e0f7a8f3455a9c03e9580fd63ae205a2d93",
            },
            TestCase {
                input: "9e701ed7d412a9226a2a130e66",
                output: "706f0677146307b20bb0e8d6311e329966884d13",
            },
            TestCase {
                input: "6d3ee90413b0a7cbf69e5e6144ca",
                output: "a7241a703aaf0d53fe142f86bf2e849251fa8dff",
            },
            TestCase {
                input: "fae24d56514efcb530fd4802f5e71f",
                output: "400f53546916d33ad01a5e6df66822dfbdc4e9e6",
            },
            TestCase {
                input: "c5a22dd6eda3fe2bdc4ddb3ce6b35fd1",
                output: "fac8ab93c1ae6c16f0311872b984f729dc928ccd",
            },
            TestCase {
                input: "d98cded2adabf08fda356445c781802d95",
                output: "fba6d750c18da58f6e2aab10112b9a5ef3301b3b",
            },
            TestCase {
                input: "bcc6d7087a84f00103ccb32e5f5487a751a2",
                output: "29d27c2d44c205c8107f0351b05753ac708226b6",
            },
            TestCase {
                input: "36ecacb1055434190dbbc556c48bafcb0feb0d",
                output: "b971bfc1ebd6f359e8d74cb7ecfe7f898d0ba845",
            },
            TestCase {
                input: "5ff9edb69e8f6bbd498eb4537580b7fba7ad31d0",
                output: "96d08c430094b9fcc164ad2fb6f72d0a24268f68",
            },
            TestCase {
                input: "c95b441d8270822a46a798fae5defcf7b26abace36",
                output: "a287ea752a593d5209e287881a09c49fa3f0beb1",
            },
            TestCase {
                input: "83104c1d8a55b28f906f1b72cb53f68cbb097b44f860",
                output: "a06c713779cbd88519ed4a585ac0cb8a5e9d612b",
            },
            TestCase {
                input: "755175528d55c39c56493d697b790f099a5ce741f7754b",
                output: "bff7d52c13a3688132a1d407b1ab40f5b5ace298",
            },
            TestCase {
                input: "088fc38128bbdb9fd7d65228b3184b3faac6c8715f07272f",
                output: "c7566b91d7b6f56bdfcaa9781a7b6841aacb17e9",
            },
            TestCase {
                input: "a4a586eb9245a6c87e3adf1009ac8a49f46c07e14185016895",
                output: "ffa30c0b5c550ea4b1e34f8a60ec9295a1e06ac1",
            },
            TestCase {
                input: "8e7c555270c006092c2a3189e2a526b873e2e269f0fb28245256",
                output: "29e66ed23e914351e872aa761df6e4f1a07f4b81",
            },
            TestCase {
                input: "a5f3bfa6bb0ba3b59f6b9cbdef8a558ec565e8aa3121f405e7f2f0",
                output: "b28cf5e5b806a01491d41f69bd9248765c5dc292",
            },
            TestCase {
                input: "589054f0d2bd3c2c85b466bfd8ce18e6ec3e0b87d944cd093ba36469",
                output: "60224fb72c46069652cd78bcd08029ef64da62f3",
            },
            TestCase {
                input: "a0abb12083b5bbc78128601bf1cbdbc0fdf4b862b24d899953d8da0ff3",
                output: "b72c4a86f72608f24c05f3b9088ef92fba431df7",
            },
            TestCase {
                input: "82143f4cea6fadbf998e128a8811dc75301cf1db4f079501ea568da68eeb",
                output: "73779ad5d6b71b9b8328ef7220ff12eb167076ac",
            },
            TestCase {
                input: "9f1231dd6df1ff7bc0b0d4f989d048672683ce35d956d2f57913046267e6f3",
                output: "a09671d4452d7cf50015c914a1e31973d20cc1a0",
            },
            TestCase {
                input: "041c512b5eed791f80d3282f3a28df263bb1df95e1239a7650e5670fc2187919",
                output: "e88cdcd233d99184a6fd260b8fca1b7f7687aee0",
            },
            TestCase {
                input: "17e81f6ae8c2e5579d69dafa6e070e7111461552d314b691e7a3e7a4feb3fae418",
                output: "010def22850deb1168d525e8c84c28116cb8a269",
            },
            TestCase {
                input: "d15976b23a1d712ad28fad04d805f572026b54dd64961fda94d5355a0cc98620cf77",
                output: "aeaa40ba1717ed5439b1e6ea901b294ba500f9ad",
            },
            TestCase {
                input: "09fce4d434f6bd32a44e04b848ff50ec9f642a8a85b37a264dc73f130f22838443328f",
                output: "c6433791238795e34f080a5f1f1723f065463ca0",
            },
            TestCase {
                input: "f17af27d776ec82a257d8d46d2b46b639462c56984cc1be9c1222eadb8b26594a25c709d",
                output: "e21e22b89c1bb944a32932e6b2a2f20d491982c3",
            },
            TestCase {
                input: "b13ce635d6f8758143ffb114f2f601cb20b6276951416a2f94fbf4ad081779d79f4f195b22",
                output: "575323a9661f5d28387964d2ba6ab92c17d05a8a",
            },
            TestCase {
                input: "5498793f60916ff1c918dde572cdea76da8629ba4ead6d065de3dfb48de94d234cc1c5002910",
                output: "feb44494af72f245bfe68e86c4d7986d57c11db7",
            },
            TestCase {
                input: "498a1e0b39fa49582ae688cd715c86fbaf8a81b8b11b4d1594c49c902d197c8ba8a621fd6e3be5",
                output: "cff2290b3648ba2831b98dde436a72f9ebf51eee",
            },
            TestCase {
                input: "3a36ae71521f9af628b3e34dcb0d4513f84c78ee49f10416a98857150b8b15cb5c83afb4b570376e",
                output: "9b4efe9d27b965905b0c3dab67b8d7c9ebacd56c",
            },
            TestCase {
                input: "dcc76b40ae0ea3ba253e92ac50fcde791662c5b6c948538cffc2d95e9de99cac34dfca38910db2678f",
                output: "afedb0ff156205bcd831cbdbda43db8b0588c113",
            },
            TestCase {
                input: "5b5ec6ec4fd3ad9c4906f65c747fd4233c11a1736b6b228b92e90cddabb0c7c2fcf9716d3fad261dff33",
                output: "8deb1e858f88293a5e5e4d521a34b2a4efa70fc4",
            },
            TestCase {
                input: "df48a37b29b1d6de4e94717d60cdb4293fcf170bba388bddf7a9035a15d433f20fd697c3e4c8b8c5f590ab",
                output: "95cbdac0f74afa69cebd0e5c7defbc6faf0cbeaf",
            },
            TestCase {
                input: "1f179b3b82250a65e1b0aee949e218e2f45c7a8dbfd6ba08de05c55acfc226b48c68d7f7057e5675cd96fcfc",
                output: "f0307bcb92842e5ae0cd4f4f14f3df7f877fbef2",
            },
            TestCase {
                input: "ee3d72da3a44d971578972a8e6780ce64941267e0f7d0179b214fa97855e1790e888e09fbe3a70412176cb3b54",
                output: "7b13bb0dbf14964bd63b133ac85e22100542ef55",
            },
            TestCase {
                input: "d4d4c7843d312b30f610b3682254c8be96d5f6684503f8fbfbcd15774fc1b084d3741afb8d24aaa8ab9c104f7258",
                output: "c314d2b6cf439be678d2a74e890d96cfac1c02ed",
            },
            TestCase {
                input: "32c094944f5936a190a0877fb9178a7bf60ceae36fd530671c5b38c5dbd5e6a6c0d615c2ac8ad04b213cc589541cf6",
                output: "4d0be361e410b47a9d67d8ce0bb6a8e01c53c078",
            },
            TestCase {
                input: "e5d3180c14bf27a5409fa12b104a8fd7e9639609bfde6ee82bbf9648be2546d29688a65e2e3f3da47a45ac14343c9c02",
                output: "e5353431ffae097f675cbf498869f6fbb6e1c9f2",
            },
            TestCase {
                input: "e7b6e4b69f724327e41e1188a37f4fe38b1dba19cbf5a7311d6e32f1038e97ab506ee05aebebc1eed09fc0e357109818b9",
                output: "b8720a7068a085c018ab18961de2765aa6cd9ac4",
            },
            TestCase {
                input: "bc880cb83b8ac68ef2fedc2da95e7677ce2aa18b0e2d8b322701f67af7d5e7a0d96e9e33326ccb7747cfff0852b961bfd475",
                output: "b0732181568543ba85f2b6da602b4b065d9931aa",
            },
            TestCase {
                input: "235ea9c2ba7af25400f2e98a47a291b0bccdaad63faa2475721fda5510cc7dad814bce8dabb611790a6abe56030b798b75c944",
                output: "9c22674cf3222c3ba921672694aafee4ce67b96b",
            },
            TestCase {
                input: "07e3e29fed63104b8410f323b975fd9fba53f636af8c4e68a53fb202ca35dd9ee07cb169ec5186292e44c27e5696a967f5e67709",
                output: "d128335f4cecca9066cdae08958ce656ff0b4cfc",
            },
            TestCase {
                input: "65d2a1dd60a517eb27bfbf530cf6a5458f9d5f4730058bd9814379547f34241822bf67e6335a6d8b5ed06abf8841884c636a25733f",
                output: "0b67c57ac578de88a2ae055caeaec8bb9b0085a0",
            },
            TestCase {
                input: "dcc86b3bd461615bab739d8daafac231c0f462e819ad29f9f14058f3ab5b75941d4241ea2f17ebb8a458831b37a9b16dead4a76a9b0e",
                output: "c766f912a89d4ccda88e0cce6a713ef5f178b596",
            },
            TestCase {
                input: "4627d54f0568dc126b62a8c35fb46a9ac5024400f2995e51635636e1afc4373dbb848eb32df23914230560b82477e9c3572647a7f2bb92",
                output: "9aa3925a9dcb177b15ccff9b78e70cf344858779",
            },
            TestCase {
                input: "ba531affd4381168ef24d8b275a84d9254c7f5cc55fded53aa8024b2c5c5c8aa7146fe1d1b83d62b70467e9a2e2cb67b3361830adbab28d7",
                output: "4811fa30042fc076acf37c8e2274d025307e5943",
            },
            TestCase {
                input: "8764dcbcf89dcf4282eb644e3d568bdccb4b13508bfa7bfe0ffc05efd1390be22109969262992d377691eb4f77f3d59ea8466a74abf57b2ef4",
                output: "6743018450c9730761ee2b130df9b91c1e118150",
            },
            TestCase {
                input: "497d9df9ddb554f3d17870b1a31986c1be277bc44feff713544217a9f579623d18b5ffae306c25a45521d2759a72c0459b58957255ab592f3be4",
                output: "71ad4a19d37d92a5e6ef3694ddbeb5aa61ada645",
            },
            TestCase {
                input: "72c3c2e065aefa8d9f7a65229e818176eef05da83f835107ba90ec2e95472e73e538f783b416c04654ba8909f26a12db6e5c4e376b7615e4a25819",
                output: "a7d9dc68dacefb7d6116186048cb355cc548e11d",
            },
            TestCase {
                input: "7cc9894454d0055ab5069a33984e2f712bef7e3124960d33559f5f3b81906bb66fe64da13c153ca7f5cabc89667314c32c01036d12ecaf5f9a78de98",
                output: "142e429f0522ba5abf5131fa81df82d355b96909",
            },
            TestCase {
                input: "74e8404d5a453c5f4d306f2cfa338ca65501c840ddab3fb82117933483afd6913c56aaf8a0a0a6b2a342fc3d9dc7599f4a850dfa15d06c61966d74ea59",
                output: "ef72db70dcbcab991e9637976c6faf00d22caae9",
            },
            TestCase {
                input: "46fe5ed326c8fe376fcc92dc9e2714e2240d3253b105adfbb256ff7a19bc40975c604ad7c0071c4fd78a7cb64786e1bece548fa4833c04065fe593f6fb10",
                output: "f220a7457f4588d639dc21407c942e9843f8e26b",
            },
            TestCase {
                input: "836dfa2524d621cf07c3d2908835de859e549d35030433c796b81272fd8bc0348e8ddbc7705a5ad1fdf2155b6bc48884ac0cd376925f069a37849c089c8645",
                output: "ddd2117b6e309c233ede85f962a0c2fc215e5c69",
            },
            TestCase {
                input: "7e3a4c325cb9c52b88387f93d01ae86d42098f5efa7f9457388b5e74b6d28b2438d42d8b64703324d4aa25ab6aad153ae30cd2b2af4d5e5c00a8a2d0220c6116",
                output: "a3054427cdb13f164a610b348702724c808a0dcc",
            },
        ];

        let mut actual_output: [u8; 20] = [0; 20];
        for tc in &test_cases {
            let input = hex::decode(tc.input)?;
            let expected_output = hex::decode(tc.output)?;

            let mut ctx = Context::new();
            ctx.update(&input);
            ctx.finalize(&mut actual_output);

            println!("{} ?= {}", hex::encode(actual_output), tc.output);
            assert_eq!(expected_output, actual_output);
        }

        Ok(())
    }
}
