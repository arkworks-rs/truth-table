use std::{
    io::{Cursor, Read, Write},
    path::Path,
};

use ark_piop::{
    prover::structs::proof::SNARKProof,
    setup::structs::{SNARKPk, SNARKVk},
    SnarkBackend,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid};
use datafusion_expr::LogicalPlan;
use tracing::{debug, instrument};
use tt_core::errors::TTResult;
use tt_core::irs::{
    nodes::{Node, PlanNode},
    shared_ir::EmptyIr,
    tree::Tree,
};

pub struct TTProof<B: SnarkBackend> {
    snark_proof: SNARKProof<B>,
    optimized_ir: EmptyIr<B>,
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
        canonical_to_vec(&self.snark_vk)
    }

    fn from_bytes(bytes: &[u8]) -> TTResult<Self> {
        Ok(Self {
            snark_vk: canonical_from_slice(bytes)?,
        })
    }
}

impl<B> Artifact for TTPk<B>
where
    B: SnarkBackend,
    SNARKPk<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> TTResult<Vec<u8>> {
        canonical_to_vec(&self.snark_pk)
    }

    fn from_bytes(bytes: &[u8]) -> TTResult<Self> {
        Ok(Self {
            snark_pk: canonical_from_slice(bytes)?,
        })
    }
}

impl<B> Artifact for TTProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> TTResult<Vec<u8>> {
        canonical_to_vec(self)
    }

    fn from_bytes(bytes: &[u8]) -> TTResult<Self> {
        canonical_from_slice(bytes)
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

fn canonical_to_vec<T: CanonicalSerialize>(value: &T) -> TTResult<Vec<u8>> {
    let mut buffer = Vec::new();
    value.serialize_uncompressed(&mut buffer)?;
    Ok(buffer)
}

#[instrument(level = "debug", skip_all)]
fn canonical_from_slice<T: CanonicalDeserialize>(bytes: &[u8]) -> TTResult<T> {
    let mut cursor = Cursor::new(bytes);
    Ok(T::deserialize_uncompressed_unchecked(&mut cursor)?)
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
        let plan = optimized_ir_to_logical_plan(&self.optimized_ir).map_err(|err| {
            debug!(?err, "TTProof serialize: failed to build logical plan");
            SerializationError::InvalidData
        })?;
        let plan_bytes =
            crate::logical_plan_codec::serialize_logical_plan(&plan).map_err(|err| {
                debug!(?err, "TTProof serialize: failed to serialize logical plan");
                SerializationError::InvalidData
            })?;
        let ir_len = plan_bytes.len() as u64;
        debug!(ir_len, "TTProof serialize: logical plan byte length");
        writer.write_all(&ir_len.to_le_bytes())?;
        writer.write_all(&plan_bytes)?;
        self.snark_proof.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let plan_len = optimized_ir_to_logical_plan(&self.optimized_ir)
            .ok()
            .and_then(|plan| crate::logical_plan_codec::serialize_logical_plan(&plan).ok())
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        8 + plan_len + self.snark_proof.serialized_size(compress)
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
        let plan = crate::logical_plan_codec::deserialize_logical_plan(&ir_bytes)
            .map_err(|_| SerializationError::InvalidData)?;
        let optimized_ir = EmptyIr::<B>::new_empty(Tree::from_logical_plan(&plan));
        let snark_proof = SNARKProof::<B>::deserialize_with_mode(reader, compress, _validate)?;
        Ok(Self {
            snark_proof,
            optimized_ir,
        })
    }
}

fn optimized_ir_to_logical_plan<B: SnarkBackend>(ir: &EmptyIr<B>) -> TTResult<LogicalPlan> {
    let root = ir.tree().root();
    match root.as_ref() {
        Node::Plan(PlanNode::LpBased(node)) => Ok(node.lp()),
        _ => Err(tt_core::errors::TTError::Serialization(
            ark_serialize::SerializationError::InvalidData,
        )),
    }
}
