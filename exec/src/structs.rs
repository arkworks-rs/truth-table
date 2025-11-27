use std::{io::Cursor, path::Path};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    setup::structs::{SNARKPk, SNARKVk},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tracing::instrument;
use truthtable_core::errors::TTResult;

pub struct TTPk<B:SnarkBackend> {
    snark_pk: SNARKPk<B>,
}

pub struct TTVk<B:SnarkBackend> {
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
B:SnarkBackend
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
B:SnarkBackend
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

impl<B> TTVk<B>
where
B:SnarkBackend
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
B:SnarkBackend
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
