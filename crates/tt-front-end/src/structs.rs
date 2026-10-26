use std::io::Cursor;

use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    prover::structs::proof::SNARKProof,
    setup::structs::{SNARKPk, SNARKVk},
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid,
};
use derivative::Derivative;
use proof_planner::data_dependent_lp_optimizer::OptimizationHints;
use tracing::debug;
use tt_core::{
    errors::TTResult, irs::string_order::StringOrder, prover::passes::tracking::FingerprintOpenings,
};
use zstd::stream::{decode_all as zstd_decode_all, encode_all as zstd_encode_all};

pub use ark_piop::types::artifact::{Artifact, SizeBreakdown};

/// Zstd level of a serialized `TTProof`. Level 1 favors low prover-side
/// latency and still shrinks the proof bytes well.
const TTPROOF_ZSTD_LEVEL: i32 = 1;

/// The full truth-table proof that is sent from the prover to the verifier
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct TTProof<B: SnarkBackend> {
    /// Also called the cryptographic proof.
    snark_proof: SNARKProof<B>,
    /// The prover's data-dependent choices, which the verifier replays to
    /// arrive at the same proof plan.
    optimization_hints: OptimizationHints,
    /// The prover's string order, which the verifier requires to be its own.
    string_order: StringOrder,
    /// The Merkle multiproofs opening, against the table oracles' roots, the
    /// fingerprint bins whose commitments this proof carries.
    fingerprint_openings: FingerprintOpenings,
}

pub struct TTPk<B: SnarkBackend> {
    snark_pk: SNARKPk<B>,
}

pub struct TTVk<B: SnarkBackend> {
    snark_vk: SNARKVk<B>,
}

impl<B: SnarkBackend> TTProof<B> {
    pub fn new(
        snark_proof: SNARKProof<B>,
        optimization_hints: OptimizationHints,
        string_order: StringOrder,
        fingerprint_openings: FingerprintOpenings,
    ) -> TTResult<Self> {
        Ok(Self {
            snark_proof,
            optimization_hints,
            string_order,
            fingerprint_openings,
        })
    }

    /// Discards the optimization hints and the fingerprint openings.
    pub fn snark_proof(self) -> SNARKProof<B> {
        self.snark_proof
    }

    pub fn as_snark_proof(&self) -> &SNARKProof<B> {
        &self.snark_proof
    }
    /// Discards the fingerprint openings.
    pub fn into_parts(self) -> (SNARKProof<B>, OptimizationHints) {
        (self.snark_proof, self.optimization_hints)
    }

    pub fn optimization_hints(&self) -> &OptimizationHints {
        &self.optimization_hints
    }

    pub fn string_order(&self) -> StringOrder {
        self.string_order
    }

    /// The multiproofs of the fingerprint bins this proof opens.
    pub fn fingerprint_openings(&self) -> &FingerprintOpenings {
        &self.fingerprint_openings
    }
}

impl<B> Artifact for TTVk<B>
where
    B: SnarkBackend,
{
    fn to_bytes(&self) -> SnarkResult<Vec<u8>> {
        let mut buffer = Vec::new();
        self.snark_vk.serialize_uncompressed(&mut buffer)?;
        Ok(buffer)
    }

    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(Self {
            snark_vk: SNARKVk::<B>::deserialize_uncompressed_unchecked(&mut cursor)?,
        })
    }
}

impl<B> Artifact for TTPk<B>
where
    B: SnarkBackend,
    SNARKPk<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> SnarkResult<Vec<u8>> {
        let mut buffer = Vec::new();
        self.snark_pk.serialize_uncompressed(&mut buffer)?;
        Ok(buffer)
    }

    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(Self {
            snark_pk: SNARKPk::<B>::deserialize_uncompressed_unchecked(&mut cursor)?,
        })
    }
}

impl<B> Artifact for TTProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalSerialize + CanonicalDeserialize,
{
    /// The canonical proof bytes, zstd-compressed.
    fn to_bytes(&self) -> SnarkResult<Vec<u8>> {
        let mut raw_bytes = Vec::new();
        self.serialize_compressed(&mut raw_bytes)?;
        zstd_encode_all(Cursor::new(raw_bytes), TTPROOF_ZSTD_LEVEL).map_err(Into::into)
    }

    /// Accepts zstd-compressed or raw canonical bytes.
    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self> {
        if let Ok(decoded) = zstd_decode_all(Cursor::new(bytes)) {
            let mut cursor = Cursor::new(decoded.as_slice());
            return match Self::deserialize_compressed_unchecked(&mut cursor) {
                Ok(proof) => Ok(proof),
                Err(_) => {
                    let mut fallback_cursor = Cursor::new(decoded.as_slice());
                    Ok(Self::deserialize_uncompressed_unchecked(
                        &mut fallback_cursor,
                    )?)
                }
            };
        }

        let mut cursor = Cursor::new(bytes);
        match Self::deserialize_compressed_unchecked(&mut cursor) {
            Ok(proof) => Ok(proof),
            Err(_) => {
                let mut fallback_cursor = Cursor::new(bytes);
                Ok(Self::deserialize_uncompressed_unchecked(
                    &mut fallback_cursor,
                )?)
            }
        }
    }

    /// The length prefix (8 bytes), the hint payload, the string order (one
    /// byte), the SNARK proof and the fingerprint openings.
    fn size_breakdown(&self) -> Option<SizeBreakdown> {
        let optimization_hints = optimization_hints_payload_bytes(&self.optimization_hints)
            .map(|bytes| bytes.len())
            .ok()?;
        let snark_proof = self.snark_proof.size_breakdown()?;
        let openings = self.fingerprint_openings.serialized_size(Compress::Yes);

        Some(SizeBreakdown::node(
            8 + optimization_hints + 1 + snark_proof.size + openings,
            [
                (
                    "optimization_hints",
                    SizeBreakdown::leaf(optimization_hints),
                ),
                ("string_order", SizeBreakdown::leaf(1)),
                ("snark_proof", snark_proof),
                ("fingerprint_openings", SizeBreakdown::leaf(openings)),
            ],
        ))
    }
}

impl<B> TTVk<B>
where
    B: SnarkBackend,
{
    pub fn into_inner(self) -> SNARKVk<B> {
        self.snark_vk
    }

    pub fn as_inner(&self) -> &SNARKVk<B> {
        &self.snark_vk
    }
}

impl<B> TTPk<B>
where
    B: SnarkBackend,
{
    pub fn into_inner(self) -> SNARKPk<B> {
        self.snark_pk
    }

    pub fn as_inner(&self) -> &SNARKPk<B> {
        &self.snark_pk
    }
}

/// The framed hint payload of a serialized `TTProof`: a `TTH1` prefix, then
/// the bincode bytes; empty for empty hints. Deserialization ignores a payload
/// without the prefix.
fn optimization_hints_payload_bytes(
    optimization_hints: &OptimizationHints,
) -> Result<Vec<u8>, SerializationError> {
    if optimization_hints.is_empty() {
        return Ok(Vec::new());
    }
    let payload = bincode::serialize(optimization_hints).map_err(|err| {
        debug!(
            ?err,
            "TTProof serialize: failed to serialize optimization hints"
        );
        SerializationError::InvalidData
    })?;
    let mut bytes = Vec::with_capacity(b"TTH1".len() + payload.len());
    bytes.extend_from_slice(b"TTH1");
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

impl<B> Valid for TTProof<B>
where
    B: SnarkBackend,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

/// The serialized layout is:
/// 1. little-endian payload length for optimization hints
/// 2. framed optimization-hint payload bytes
/// 3. the string order, one byte
/// 4. canonical SNARK proof bytes
/// 5. the fingerprint multiproofs
impl<B> CanonicalSerialize for TTProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalSerialize,
{
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        let plan_bytes = optimization_hints_payload_bytes(&self.optimization_hints)?;
        let plan_len = plan_bytes.len() as u64;
        debug!(
            plan_len,
            "TTProof serialize: optimization-hint artifact byte length"
        );
        writer.write_all(&plan_len.to_le_bytes())?;
        writer.write_all(&plan_bytes)?;
        writer.write_all(&[self.string_order.to_byte()])?;
        self.snark_proof
            .serialize_with_mode(&mut writer, compress)?;
        self.fingerprint_openings
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let plan_len = optimization_hints_payload_bytes(&self.optimization_hints)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        8 + plan_len
            + 1
            + self.snark_proof.serialized_size(compress)
            + self.fingerprint_openings.serialized_size(compress)
    }
}

impl<B> CanonicalDeserialize for TTProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalDeserialize,
{
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let mut len_bytes = [0u8; 8];
        reader.read_exact(&mut len_bytes)?;
        let plan_len = u64::from_le_bytes(len_bytes) as usize;
        let mut plan_bytes = vec![0u8; plan_len];
        if plan_len > 0 {
            reader.read_exact(&mut plan_bytes)?;
        }
        let optimization_hints = if plan_len == 0 {
            OptimizationHints::default()
        } else if plan_bytes.starts_with(b"TTH1") {
            bincode::deserialize::<OptimizationHints>(&plan_bytes[b"TTH1".len()..])
                .map_err(|_| SerializationError::InvalidData)?
        } else {
            // A payload without the prefix is not a hint payload (old proofs
            // stored IR bytes in this slot) and is ignored.
            OptimizationHints::default()
        };
        let mut order_byte = [0u8; 1];
        reader.read_exact(&mut order_byte)?;
        let string_order =
            StringOrder::from_byte(order_byte[0]).ok_or(SerializationError::InvalidData)?;
        let snark_proof = SNARKProof::<B>::deserialize_with_mode(&mut reader, compress, _validate)?;
        let fingerprint_openings =
            FingerprintOpenings::deserialize_with_mode(&mut reader, compress, _validate)?;
        Ok(Self {
            snark_proof,
            optimization_hints,
            string_order,
            fingerprint_openings,
        })
    }
}
