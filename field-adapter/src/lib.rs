// use ark_ff::Field;



// pub trait FieldAdapter<F:Fliod> {
//     fn from_u64(u: u64) -> Self;
//     fn to_u64(&self) -> u64;
// }

// impl FieldAdapter for Fr {
//     fn from_u64(u: u64) -> Self {
//         Fr::from(u)
//     }

//     fn to_u64(&self) -> u64 {
//         self.into_repr().as_ref()[0] as u64
//     }
// }