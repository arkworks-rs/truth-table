use std::{io::Cursor, path::Path};

use ark_piop::{
    prover::structs::proof::SNARKProof,
    setup::structs::{SNARKPk, SNARKVk},
    SnarkBackend,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid,
};
use tracing::{debug, instrument};
use tt_core::errors::TTResult;
use tt_core::irs::{
    codec::{deserialize_empty_ir, serialize_empty_ir},
    shared_ir::EmptyIr,
};

pub struct TTProof<B: SnarkBackend> {
    snark_proof: SNARKProof<B>,
    optimized_ir: EmptyIr<B>,
}

impl<B: SnarkBackend> Clone for TTProof<B>
where
    SNARKProof<B>: Clone,
    EmptyIr<B>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            snark_proof: self.snark_proof.clone(),
            optimized_ir: self.optimized_ir.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PCSSubproofSizeBreakdown {
    pub opening_proof: usize,
    pub commitments: usize,
    pub query_map: usize,
    pub total: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct SnarkProofSizeBreakdown {
    pub sc_subproof: usize,
    pub mv_pcs_subproof: usize,
    pub mv_pcs_subproof_parts: PCSSubproofSizeBreakdown,
    pub uv_pcs_subproof: usize,
    pub uv_pcs_subproof_parts: PCSSubproofSizeBreakdown,
    pub miscellaneous_field_elements: usize,
    pub total: usize,
}

impl<B: SnarkBackend> TTProof<B> {
    pub fn new(snark_proof: SNARKProof<B>, optimized_ir: EmptyIr<B>) -> Self {
        Self {
            snark_proof,
            optimized_ir,
        }
    }

    pub fn into_inner(self) -> SNARKProof<B> {
        self.snark_proof
    }

    pub fn into_parts(self) -> (SNARKProof<B>, EmptyIr<B>) {
        (self.snark_proof, self.optimized_ir)
    }

    pub fn as_inner(&self) -> &SNARKProof<B> {
        &self.snark_proof
    }

    pub fn optimized_ir(&self) -> &EmptyIr<B> {
        &self.optimized_ir
    }

    pub fn optimized_ir_serialized_size_bytes(&self) -> TTResult<usize> {
        Ok(serialize_empty_ir(&self.optimized_ir)?.len())
    }

    pub fn snark_proof_serialized_size_bytes(&self) -> usize
    where
        SNARKProof<B>: CanonicalSerialize,
    {
        self.snark_proof.serialized_size(Compress::Yes)
    }

    pub fn snark_proof_size_breakdown_bytes(&self) -> SnarkProofSizeBreakdown
    where
        SNARKProof<B>: CanonicalSerialize,
    {
        let sc_subproof = self.snark_proof.sc_subproof.serialized_size(Compress::Yes);

        let mv_opening_proof = self
            .snark_proof
            .mv_pcs_subproof
            .opening_proof
            .serialized_size(Compress::Yes);
        let mv_commitments = self
            .snark_proof
            .mv_pcs_subproof
            .comitments
            .serialized_size(Compress::Yes);
        let mv_query_map = self
            .snark_proof
            .mv_pcs_subproof
            .query_map
            .serialized_size(Compress::Yes);
        let mv_pcs_subproof = self
            .snark_proof
            .mv_pcs_subproof
            .serialized_size(Compress::Yes);

        let uv_opening_proof = self
            .snark_proof
            .uv_pcs_subproof
            .opening_proof
            .serialized_size(Compress::Yes);
        let uv_commitments = self
            .snark_proof
            .uv_pcs_subproof
            .comitments
            .serialized_size(Compress::Yes);
        let uv_query_map = self
            .snark_proof
            .uv_pcs_subproof
            .query_map
            .serialized_size(Compress::Yes);
        let uv_pcs_subproof = self
            .snark_proof
            .uv_pcs_subproof
            .serialized_size(Compress::Yes);

        let miscellaneous_field_elements = self
            .snark_proof
            .miscellaneous_field_elements
            .serialized_size(Compress::Yes);
        let total = self.snark_proof.serialized_size(Compress::Yes);

        SnarkProofSizeBreakdown {
            sc_subproof,
            mv_pcs_subproof,
            mv_pcs_subproof_parts: PCSSubproofSizeBreakdown {
                opening_proof: mv_opening_proof,
                commitments: mv_commitments,
                query_map: mv_query_map,
                total: mv_pcs_subproof,
            },
            uv_pcs_subproof,
            uv_pcs_subproof_parts: PCSSubproofSizeBreakdown {
                opening_proof: uv_opening_proof,
                commitments: uv_commitments,
                query_map: uv_query_map,
                total: uv_pcs_subproof,
            },
            miscellaneous_field_elements,
            total,
        }
    }
}

pub struct TTPk<B: SnarkBackend> {
    snark_pk: SNARKPk<B>,
}

pub struct TTVk<B: SnarkBackend> {
    snark_vk: SNARKVk<B>,
}

pub trait Artifact: Sized {
    fn to_bytes(&self) -> TTResult<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> TTResult<Self>;

    #[instrument(level = "debug")]
    fn load(path: &Path) -> TTResult<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    #[instrument(level = "debug", skip(self))]
    fn save(&self, path: &Path) -> TTResult<()> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

impl<B> Artifact for TTVk<B>
where
    B: SnarkBackend,
{
    fn to_bytes(&self) -> TTResult<Vec<u8>> {
        canonical_to_vec_uncompressed(&self.snark_vk)
    }

    fn from_bytes(bytes: &[u8]) -> TTResult<Self> {
        Ok(Self {
            snark_vk: canonical_from_slice_uncompressed(bytes)?,
        })
    }
}

impl<B> Artifact for TTPk<B>
where
    B: SnarkBackend,
    SNARKPk<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> TTResult<Vec<u8>> {
        canonical_to_vec_uncompressed(&self.snark_pk)
    }

    fn from_bytes(bytes: &[u8]) -> TTResult<Self> {
        Ok(Self {
            snark_pk: canonical_from_slice_uncompressed(bytes)?,
        })
    }
}

impl<B> Artifact for TTProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> TTResult<Vec<u8>> {
        canonical_to_vec_compressed(self)
    }

    fn from_bytes(bytes: &[u8]) -> TTResult<Self> {
        match canonical_from_slice_compressed(bytes) {
            Ok(proof) => Ok(proof),
            Err(_) => canonical_from_slice_uncompressed(bytes),
        }
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

fn canonical_to_vec_uncompressed<T: CanonicalSerialize>(value: &T) -> TTResult<Vec<u8>> {
    let mut buffer = Vec::new();
    value.serialize_uncompressed(&mut buffer)?;
    Ok(buffer)
}

#[instrument(level = "debug", skip_all)]
fn canonical_from_slice_uncompressed<T: CanonicalDeserialize>(bytes: &[u8]) -> TTResult<T> {
    let mut cursor = Cursor::new(bytes);
    Ok(T::deserialize_uncompressed_unchecked(&mut cursor)?)
}

fn canonical_to_vec_compressed<T: CanonicalSerialize>(value: &T) -> TTResult<Vec<u8>> {
    let mut buffer = Vec::new();
    value.serialize_compressed(&mut buffer)?;
    Ok(buffer)
}

#[instrument(level = "debug", skip_all)]
fn canonical_from_slice_compressed<T: CanonicalDeserialize>(bytes: &[u8]) -> TTResult<T> {
    let mut cursor = Cursor::new(bytes);
    Ok(T::deserialize_compressed_unchecked(&mut cursor)?)
}

impl<B> Valid for TTProof<B>
where
    B: SnarkBackend,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

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
        let ir_bytes = serialize_empty_ir(&self.optimized_ir).map_err(|err| {
            debug!(?err, "TTProof serialize: failed to serialize IR");
            SerializationError::InvalidData
        })?;
        let ir_len = ir_bytes.len() as u64;
        debug!(ir_len, "TTProof serialize: IR byte length");
        writer.write_all(&ir_len.to_le_bytes())?;
        writer.write_all(&ir_bytes)?;
        self.snark_proof
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let ir_len = serialize_empty_ir(&self.optimized_ir)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        8 + ir_len + self.snark_proof.serialized_size(compress)
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
        let ir_len = u64::from_le_bytes(len_bytes) as usize;
        let mut ir_bytes = vec![0u8; ir_len];
        if ir_len > 0 {
            reader.read_exact(&mut ir_bytes)?;
        }
        let optimized_ir =
            deserialize_empty_ir::<B>(&ir_bytes).map_err(|_| SerializationError::InvalidData)?;
        let snark_proof = SNARKProof::<B>::deserialize_with_mode(reader, compress, _validate)?;
        Ok(Self {
            snark_proof,
            optimized_ir,
        })
    }
}
