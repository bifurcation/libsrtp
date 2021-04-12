use crate::srtp::Error;

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
            return Err(Error::ReplayOld);
        }

        // otherwise, the index appears within the window, so check the bitmask
        if self.bitmask.get(index - self.window_start) {
            return Err(Error::ReplayFail);
        }

        // otherwise, the index is okay
        return Ok(());
    }

    pub fn add(&mut self, index: u32) -> Result<(), Error> {
        if index < self.window_start {
            return Err(Error::ReplayFail);
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
            return Err(Error::KeyExpired);
        }

        self.window_start += 1;
        return Ok(());
    }

    pub fn get_value(&self) -> u32 {
        self.window_start
    }
}

// TODO(RLB) ExtendedReplayDB

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ut_sim::UnreliableTransport;
    use rand::{thread_rng, Rng};

    const NUM_TRIALS: u32 = 1 << 16;

    fn rdb_check_add(rdb: &mut ReplayDB, i: u32) {
        match rdb.check(i) {
            Ok(_) => {}
            Err(_) => panic!("Expected success"),
        }

        rdb.add(i).unwrap()
    }

    fn rdb_check_add_unordered(rdb: &mut ReplayDB, i: u32) {
        match rdb.check(i) {
            Ok(_) => {}
            Err(Error::ReplayOld) => return,
            Err(_) => panic!("Unexpected error type"),
        }

        rdb.add(i).unwrap()
    }

    fn rdb_check_expect_failure(rdb: &mut ReplayDB, i: u32) {
        match rdb.check(i) {
            Ok(_) => panic!("Expected failure"),
            Err(Error::ReplayOld) => {}
            Err(Error::ReplayFail) => {}
            Err(_) => panic!("Unexpected error type"),
        }
    }

    #[test]
    fn test_sequential_insertion() {
        let mut rdb = ReplayDB::new();
        for i in 0..NUM_TRIALS {
            rdb_check_add(&mut rdb, i);
            rdb_check_expect_failure(&mut rdb, i);
        }
    }

    #[test]
    fn test_non_sequential_insertion() {
        let mut rdb = ReplayDB::new();
        let mut ut = UnreliableTransport::new();
        for _ in 0..NUM_TRIALS {
            let ircvd = ut.next();
            rdb_check_add_unordered(&mut rdb, ircvd);
            rdb_check_expect_failure(&mut rdb, ircvd);
        }
    }

    #[test]
    fn test_large_gaps() {
        let mut rdb = ReplayDB::new();
        let gap_bound: u32 = 10;

        let mut ircvd: u32 = 0;
        let mut rng = thread_rng();
        for _ in 0..NUM_TRIALS {
            ircvd += rng.gen_range(0..gap_bound);
            rdb_check_add(&mut rdb, ircvd);
            rdb_check_expect_failure(&mut rdb, ircvd);
        }
    }

    #[test]
    fn test_large_offset() {
        let mut rdb = ReplayDB::new();
        for i in 0..NUM_TRIALS {
            rdb_check_add(&mut rdb, i + 513);
            rdb_check_expect_failure(&mut rdb, 513);
        }
    }

    #[test]
    fn test_key_expired() {
        let mut rdb = ReplayDB::new();

        rdb.window_start = 0x7ffffffe;
        rdb.increment().unwrap();
        assert_eq!(rdb.get_value(), 0x7fffffff);

        match rdb.increment() {
            Err(Error::KeyExpired) => {}
            _ => panic!("Allowed use of expired key"),
        }
        assert_eq!(rdb.get_value(), 0x7fffffff);
    }

    // TODO(RLB) ReplayDB benchmarking
    // TODO(RLB) ExtendedReplayDB test
}
