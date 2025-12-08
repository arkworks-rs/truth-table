use crate::irs::payloads::PayloadStructure;
use arithmetic::table_oracle::TrackedTableOracle;
pub type TrackedPayload<B> = PayloadStructure<TrackedTableOracle<B>>;
pub type VirtualizedPayload<B> = PayloadStructure<TrackedTableOracle<B>>;
