use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum KeyEvent {
    Normal = 0,
    SoftLimit = 1,
    HardLimit = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyState {
    Normal = 0,
    PastSoftLimit = 1,
    Expired = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KeyLimitContext {
    pub num_left: ExtendedSequenceNumber,
    pub state: KeyState,
}

const SOFT_LIMIT: ExtendedSequenceNumber = 0x10000;

impl KeyLimitContext {
    pub fn new() -> Self {
        KeyLimitContext {
            num_left: ExtendedSequenceNumber::MAX,
            state: KeyState::Normal,
        }
    }

    pub fn set(&mut self, s: ExtendedSequenceNumber) -> Result<(), Error> {
        if s < SOFT_LIMIT {
            return Err(Error::BadParam);
        }

        self.num_left = s;
        self.state = KeyState::Normal;
        Ok(())
    }

    pub fn check(&self) -> Result<(), Error> {
        match self.state {
            KeyState::Expired => Err(Error::KeyExpired),
            _ => Ok(()),
        }
    }

    pub fn update(&mut self) -> KeyEvent {
        if self.num_left == 0 || self.state == KeyState::Expired {
            return KeyEvent::HardLimit;
        }

        self.num_left -= 1;
        if self.num_left >= SOFT_LIMIT {
            return KeyEvent::Normal;
        }

        if self.num_left > 0 {
            self.state = KeyState::PastSoftLimit;
            return KeyEvent::SoftLimit;
        }

        self.state = KeyState::Expired;
        KeyEvent::HardLimit
    }
}
