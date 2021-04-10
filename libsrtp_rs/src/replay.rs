use crate::Error;

struct Bitmask {
    storage: u128,
}

impl Bitmask {
    const BITS: u32 = 128;

    fn new() -> Self {
        Self { storage: 0 }
    }

    fn get(&self, bit: u32) -> bool {
        return (self.storage >> bit) & 1 == 1;
    }

    fn set(&mut self, bit: u32) {
        self.storage |= 1u128 << bit;
    }

    fn shift(&mut self, bits: u32) {
        self.storage >>= bits;
    }
}

#[repr(C)]
pub struct ReplayDB {
    window_start: u32,
    bitmask: Bitmask,
}

impl ReplayDB {
    pub fn new() -> Self {
        return Self {
            window_start: 0,
            bitmask: Bitmask::new(),
        };
    }

    pub fn check(&self, index: u32) -> Result<(), Error> {
        // if the index appears after (or at very end of) the window, its good
        if index >= self.window_start + Bitmask::BITS {
            return Ok(());
        }

        // if the index appears before the window, its bad
        if index < self.window_start {
            return Err(Error::replay_old);
        }

        // otherwise, the index appears within the window, so check the bitmask
        if self.bitmask.get(index - self.window_start) {
            return Err(Error::replay_fail);
        }

        // otherwise, the index is okay
        return Ok(());
    }

    pub fn add(&mut self, index: u32) -> Result<(), Error> {
        if index < self.window_start {
            return Err(Error::replay_fail);
        }

        let delta = index - self.window_start;
        if delta < Bitmask::BITS {
            // if the index is within the window, set the appropriate bit
            self.bitmask.set(delta);
            return Ok(());
        }

        // shift the window forward by delta bits
        let delta = delta - Bitmask::BITS - 1;
        self.bitmask.shift(delta);
        self.bitmask.set(Bitmask::BITS - 1);
        self.window_start += delta;
        return Ok(());
    }

    pub fn increment(&mut self) -> Result<(), Error> {
        if self.window_start >= 0x7fffffff {
            return Err(Error::key_expired);
        }

        self.window_start += 1;
        return Ok(());
    }
}

// TODO(RLB) ExtendedReplayDB
// TODO(RLB) ReplayDB test
// TODO(RLB) ExtendedReplayDB test
