//! The truth-table intermediate representation (IR).
//!
//! An IR is a tree of [`nodes::Node`]s paired with a map from node to payload.
//! A node is a plan node (a logical-plan operator or expression carried over
//! from DataFusion) or a gadget node (a low-level argument attached during
//! gadget planning). Each pass maps the payloads of one stage to the next.

pub mod codec;
pub mod ir;
pub mod nodes;
pub mod payloads;
pub mod shared_ir;
pub mod supported;
pub mod tree;
