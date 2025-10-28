use std::{io::Cursor, path::Path};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    setup::structs::{SNARKPk, SNARKVk},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use truthtable_core::errors::TTResult;

pub struct TTPk<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> {
    snark_pk: SNARKPk<F, MvPCS, UvPCS>,
}

pub struct TTVk<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> {
    snark_vk: SNARKVk<F, MvPCS, UvPCS>,
}

pub trait Artifact: Sized {
    fn to_bytes(&self) -> TTResult<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> TTResult<Self>;

    fn load(path: &Path) -> TTResult<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    fn save(&self, path: &Path) -> TTResult<()> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> Artifact for TTVk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
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

impl<F, MvPCS, UvPCS> Artifact for TTPk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    SNARKPk<F, MvPCS, UvPCS>: CanonicalSerialize + CanonicalDeserialize,
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

impl<F, MvPCS, UvPCS> TTVk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn into_inner(self) -> SNARKVk<F, MvPCS, UvPCS> {
        self.snark_vk
    }

    pub fn as_inner(&self) -> &SNARKVk<F, MvPCS, UvPCS> {
        &self.snark_vk
    }
}

impl<F, MvPCS, UvPCS> TTPk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn into_inner(self) -> SNARKPk<F, MvPCS, UvPCS> {
        self.snark_pk
    }

    pub fn as_inner(&self) -> &SNARKPk<F, MvPCS, UvPCS> {
        &self.snark_pk
    }
}

fn canonical_to_vec<T: CanonicalSerialize>(value: &T) -> TTResult<Vec<u8>> {
    let mut buffer = Vec::new();
    value.serialize_uncompressed(&mut buffer)?;
    Ok(buffer)
}

fn canonical_from_slice<T: CanonicalDeserialize>(bytes: &[u8]) -> TTResult<T> {
    let mut cursor = Cursor::new(bytes);
    Ok(T::deserialize_uncompressed(&mut cursor)?)
}
