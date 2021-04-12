#![cfg(test)]

use rand::seq::SliceRandom;

const UT_BUFFER_SIZE: usize = 160;

pub struct UnreliableTransport {
    index: u32,
    buffer: [u32; UT_BUFFER_SIZE],
}

impl UnreliableTransport {
    pub fn new() -> Self {
        let mut ut = Self {
            index: (UT_BUFFER_SIZE - 1) as u32,
            buffer: [0; UT_BUFFER_SIZE],
        };

        for i in 0..UT_BUFFER_SIZE {
            ut.buffer[i] = i as u32;
        }

        ut.shuffle();
        ut
    }

    fn shuffle(&mut self) {
        let mut rng = rand::thread_rng();
        self.buffer.shuffle(&mut rng);
    }

    pub fn next(&mut self) -> u32 {
        let tmp = self.buffer[0];
        self.buffer[0] = self.index;
        self.index += 1;
        self.shuffle();
        tmp
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_unreliable_transport() {
        let mut ut = UnreliableTransport::new();
        for i in 0..1000 {
            let irecvd = ut.next();
            let idiff = (i as i32) - (irecvd as i32);
            println!("{:?}\t{:?}\t{:?}", i, irecvd, idiff);
        }
    }
}
