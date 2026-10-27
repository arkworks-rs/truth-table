//! How a string ORDER BY key is proved: on its base column's committed rank
//! (TruthTable++ Rank-Based String Sort Check, §7.3, PIOP 13), or on its
//! characters (String Sort Check, §7.2, PIOP 11). Both read data the owner
//! committed; no front-end option selects the lexicographic mode, so only
//! tests use it. The mode is a process-wide verifier policy; a proof records
//! the prover's, and the verifier rejects a proof whose mode is not its own.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StringOrder {
    #[default]
    Rank,
    Lexicographic,
}

impl StringOrder {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Rank => 0,
            Self::Lexicographic => 1,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Rank),
            1 => Some(Self::Lexicographic),
            _ => None,
        }
    }
}

static MODE: AtomicU8 = AtomicU8::new(0);

pub fn string_order() -> StringOrder {
    StringOrder::from_byte(MODE.load(Ordering::Relaxed)).expect("a valid string order")
}

/// Every proof and verification of the process afterwards uses `order`, so
/// a test binary sets it once, before its first query.
#[cfg(feature = "test-utils")]
pub fn set_string_order(order: StringOrder) {
    MODE.store(order.to_byte(), Ordering::Relaxed);
}
