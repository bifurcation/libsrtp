use crate::srtp::Error;
use std::convert::TryFrom;

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
        if bits >= Bitmask::BITS {
            self.storage = 0;
            return;
        }

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

        // shift the window to fit the index
        let new_window_start = index - Bitmask::BITS + 1;
        self.bitmask.shift(new_window_start - self.window_start);
        self.bitmask.set(Bitmask::BITS - 1);
        self.window_start = new_window_start;
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

pub type SequenceNumber = u16;
pub type RolloverCounter = u32;
pub type ExtendedSequenceNumber = u64;

const SEQ_NUM_MEDIAN: i32 = 1 << 15;
const SEQ_NUM_MAX: i32 = 1 << 16;

pub trait ExtSeqNum {
    fn from_roc_seq(roc: RolloverCounter, seq: SequenceNumber) -> Self;
    fn roc(&self) -> RolloverCounter;
    fn seq(&self) -> SequenceNumber;
    fn set_roc(&mut self, roc: RolloverCounter);
    fn set_seq(&mut self, seq: SequenceNumber);
    fn estimate(&self, seq: SequenceNumber) -> (ExtendedSequenceNumber, i32);
}

impl ExtSeqNum for ExtendedSequenceNumber {
    fn from_roc_seq(roc: RolloverCounter, seq: SequenceNumber) -> Self {
        let roc_as_ext = ExtendedSequenceNumber::try_from(roc).unwrap();
        let seq_as_ext = ExtendedSequenceNumber::try_from(seq).unwrap();
        (roc_as_ext << 16) | seq_as_ext
    }

    fn roc(&self) -> RolloverCounter {
        RolloverCounter::try_from((self >> 16) & 0xffffffff).unwrap()
    }

    fn seq(&self) -> SequenceNumber {
        SequenceNumber::try_from(self & 0xffff).unwrap()
    }

    fn set_roc(&mut self, roc: RolloverCounter) {
        let roc_as_ext = ExtendedSequenceNumber::try_from(roc).unwrap();
        *self = (*self & 0x000000000000ffff) | (roc_as_ext << 16);
    }

    fn set_seq(&mut self, seq: SequenceNumber) {
        let seq_as_ext = ExtendedSequenceNumber::try_from(seq).unwrap();
        *self = (*self & 0xffffffffffff0000) | seq_as_ext;
    }

    fn estimate(&self, seq: SequenceNumber) -> (ExtendedSequenceNumber, i32) {
        let local_roc = self.roc();
        let local_seq = self.seq() as i32;

        let guess_roc: RolloverCounter;
        let mut difference: i32 = seq as i32;
        if local_seq < SEQ_NUM_MEDIAN {
            if ((seq as i32) > SEQ_NUM_MEDIAN + local_seq) && (local_roc > 0) {
                guess_roc = local_roc - 1;
                difference -= local_seq + SEQ_NUM_MAX;
            } else {
                guess_roc = local_roc;
                difference -= local_seq;
            }
        } else {
            if (seq as i32) < local_seq - SEQ_NUM_MEDIAN {
                guess_roc = local_roc + 1;
                difference -= local_seq - SEQ_NUM_MAX;
            } else {
                guess_roc = local_roc;
                difference -= local_seq;
            }
        }

        (
            ExtendedSequenceNumber::from_roc_seq(guess_roc, seq),
            difference,
        )
    }
}

#[repr(C)]
struct BitVector {
    bit_length: usize,
    words: Box<[u64]>,
}

impl BitVector {
    const BITS_PER_BYTE: usize = 8;
    const BYTES_PER_WORD: usize = 8;
    const BITS_PER_WORD: usize = Self::BITS_PER_BYTE * Self::BYTES_PER_WORD;

    fn new(window_bits: usize) -> Result<Self, Error> {
        if window_bits == 0 {
            return Err(Error::BadParam);
        }

        let window_bytes = window_bits / Self::BITS_PER_BYTE;
        let extra_word: usize = if window_bytes % Self::BYTES_PER_WORD != 0 {
            1
        } else {
            0
        };
        let word_size: usize = (window_bytes / Self::BYTES_PER_WORD) + extra_word;

        println!("allocating {} words", word_size);
        Ok(Self {
            bit_length: window_bits,
            words: vec![0u64; word_size].into_boxed_slice(),
        })
    }

    fn bit_length(&self) -> usize {
        self.bit_length
    }

    fn get(&self, bit: usize) -> bool {
        assert!(bit < self.bit_length);
        (self.words[bit / Self::BITS_PER_WORD] >> (bit % Self::BITS_PER_WORD)) & 1 == 1
    }

    fn set(&mut self, bit: usize) {
        assert!(bit < self.bit_length);
        self.words[bit / Self::BITS_PER_WORD] |= 1 << (bit % Self::BITS_PER_WORD);
    }

    fn shift(&mut self, shift: usize) {
        if shift > self.bit_length {
            for w in self.words.iter_mut() {
                *w = 0;
            }
            return;
        }

        let base_index = shift / Self::BITS_PER_WORD;
        let bit_index = shift % Self::BITS_PER_WORD;
        let word_length = self.words.len();

        if bit_index == 0 {
            for i in 0..(word_length - base_index) {
                self.words[i] = self.words[i + base_index];
            }
        } else {
            for i in 0..(word_length - base_index - 1) {
                self.words[i] = (self.words[i + base_index] >> bit_index)
                    ^ (self.words[i + base_index + 1] << (Self::BITS_PER_WORD - bit_index));
            }
            self.words[word_length - base_index - 1] = self.words[word_length - 1] >> bit_index;
        }

        for i in (word_length - base_index)..word_length {
            self.words[i] = 0;
        }
    }
}

#[repr(C)]
pub struct ExtendedReplayDB {
    index: ExtendedSequenceNumber,
    bitmask: BitVector,
}

impl ExtendedReplayDB {
    pub fn new(window_bits: usize) -> Result<Self, Error> {
        if window_bits != 0 && (window_bits < 64 || window_bits >= 0x8000) {
            return Err(Error::BadParam);
        }

        let mut actual_window_bits = 128;
        if window_bits != 0 {
            actual_window_bits = window_bits;
        }

        Ok(Self {
            index: 0,
            bitmask: BitVector::new(actual_window_bits)?,
        })
    }

    pub fn check(&self, delta: i32) -> Result<(), Error> {
        // TODO(RLB): Unify this logic with what's in ReplayDB

        // If delta is positive, it's good
        if delta > 0 {
            return Ok(());
        }

        // If the delta is below the window, it's old
        let window_pos: i32 = (self.bitmask.bit_length() as i32 - 1) + delta;
        if window_pos < 0 {
            return Err(Error::ReplayOld);
        }

        // If the delta is in the window and its bit is set, it's a replay
        let window_pos = usize::try_from(window_pos).unwrap();
        if self.bitmask.get(window_pos) {
            return Err(Error::ReplayFail);
        }

        // Otherwise, it's good
        Ok(())
    }

    pub fn add(&mut self, delta: i32) -> Result<(), Error> {
        if delta > 0 {
            self.index += ExtendedSequenceNumber::try_from(delta).unwrap();
            self.bitmask.shift(delta as usize);
            self.bitmask.set(self.bitmask.bit_length() - 1);
            return Ok(());
        }

        let window_pos: i32 = (self.bitmask.bit_length() as i32 - 1) + delta;
        if window_pos < 0 {
            return Err(Error::ReplayOld);
        }

        self.bitmask.set(window_pos as usize);
        Ok(())
    }

    pub fn estimate(&self, seq: SequenceNumber) -> (ExtendedSequenceNumber, i32) {
        self.index.estimate(seq)
    }

    pub fn packet_index(&self) -> ExtendedSequenceNumber {
        self.index
    }

    pub fn window_size(&self) -> usize {
        self.bitmask.bit_length()
    }

    pub fn roc(&self) -> RolloverCounter {
        self.index.roc()
    }

    pub fn set_roc(&mut self, roc: RolloverCounter) -> Result<(), Error> {
        if roc < self.index.roc() {
            return Err(Error::ReplayOld);
        }

        self.index.set_roc(roc);
        Ok(())
    }

    pub fn set_roc_seq(&mut self, roc: RolloverCounter, seq: SequenceNumber) -> Result<(), Error> {
        self.set_roc(roc)?;
        self.index.set_seq(seq);
        Ok(())
    }
}

#[cfg(test)]
mod rdb_tests {
    use super::*;
    use rand::seq::SliceRandom;
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
            Err(err) => panic!("Unexpected error {:?}", err),
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

        const TRIALS: usize = NUM_TRIALS as usize;
        let mut range: [u32; TRIALS] = [0; TRIALS];
        for i in 0..TRIALS {
            range[i] = i as u32;
        }

        let mut rng = rand::thread_rng();
        range.shuffle(&mut rng);

        for ircvd in range.iter() {
            rdb_check_add_unordered(&mut rdb, *ircvd);
            rdb_check_expect_failure(&mut rdb, *ircvd);
        }
    }

    #[test]
    fn test_large_gaps() {
        let mut rdb = ReplayDB::new();
        let gap_bound: u32 = 10;

        let mut ircvd: u32 = 0;
        let mut rng = thread_rng();
        for _ in 0..NUM_TRIALS {
            ircvd += rng.gen_range(1..gap_bound);
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
}

#[cfg(test)]
mod rdbx_tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};

    const WINDOW_SIZE: usize = 1024;
    const NUM_TRIALS: usize = 1 << 18;

    fn rdbx_check_add(rdbx: &mut ExtendedReplayDB, i: SequenceNumber) {
        let (_, delta) = rdbx.estimate(i);
        match rdbx.check(delta) {
            Ok(_) => {}
            Err(err) => panic!("Expected success: {:?}", err),
        }

        rdbx.add(delta).unwrap()
    }

    fn rdbx_check_add_unordered(rdbx: &mut ExtendedReplayDB, i: SequenceNumber) {
        let (_, delta) = rdbx.estimate(i);
        match rdbx.check(delta) {
            Ok(_) => {}
            Err(Error::ReplayOld) => return,
            Err(err) => panic!("Unexpected error {:?}", err),
        }

        rdbx.add(delta).unwrap()
    }

    fn rdbx_check_expect_failure(rdbx: &mut ExtendedReplayDB, i: SequenceNumber) {
        let (_, delta) = rdbx.estimate(i);
        match rdbx.check(delta) {
            Ok(_) => panic!("Expected failure"),
            Err(Error::ReplayOld) => {}
            Err(Error::ReplayFail) => {}
            Err(err) => panic!("Unexpected error type: {:?}", err),
        }
    }

    #[test]
    fn test_sequential_insertion() {
        let mut rdbx = ExtendedReplayDB::new(WINDOW_SIZE).unwrap();
        let mut i: SequenceNumber = 0;
        for _ in 0..NUM_TRIALS {
            i = i.wrapping_add(1);
            rdbx_check_add(&mut rdbx, i);
            rdbx_check_expect_failure(&mut rdbx, i);
        }
    }

    #[test]
    fn test_non_sequential_insertion() {
        let mut rdbx = ExtendedReplayDB::new(WINDOW_SIZE).unwrap();

        // Don't repeat sequence numbers on this pure random test
        const NUM_TRIALS: usize = 1 << 16;

        let mut range: [SequenceNumber; NUM_TRIALS] = [0; NUM_TRIALS];
        for i in 0..NUM_TRIALS {
            range[i] = i as SequenceNumber;
        }

        let mut rng = rand::thread_rng();
        range.shuffle(&mut rng);

        for ircvd in range.iter() {
            rdbx_check_add_unordered(&mut rdbx, *ircvd);
            rdbx_check_expect_failure(&mut rdbx, *ircvd);
        }
    }

    #[test]
    fn test_large_gaps() {
        let mut rdbx = ExtendedReplayDB::new(WINDOW_SIZE).unwrap();
        let gap_bound: SequenceNumber = 10;

        let mut ircvd: SequenceNumber = 0;
        let mut rng = thread_rng();
        for _ in 0..NUM_TRIALS {
            ircvd = ircvd.wrapping_add(rng.gen_range(1..gap_bound));
            rdbx_check_add(&mut rdbx, ircvd);
            rdbx_check_expect_failure(&mut rdbx, ircvd);
        }
    }

    // TODO(RLB) Benchmark rdbx
}
