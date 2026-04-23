//! The truth-table intermediate representation (IR).
//!
//! The IR is a tree of [`nodes::Node`]s — either plan nodes (logical-plan
//! operators and expressions carried over from DataFusion) or gadget nodes
//! (the low-level arguments attached during gadget planning) — paired with a
//! payload map that is transformed by each pass in turn. `Ir<B, Payload>`
//! (from [`ir`]) is the in-memory shape; [`shared_ir`] provides the type
//! aliases for each stage of the pipeline (`EmptyIr`, `OutputPlannedIr`,
//! `GadgetPlannedIr`, …).
//!
//! - [`tree`] — the node-arena [`tree::Tree`] used by all IR stages.
//! - [`ir`] — [`ir::Ir`] and the [`ir::LocalPass`] trait every pass implements.
//! - [`nodes`] — concrete plan / expression / gadget node types.
//! - [`payloads`] — [`payloads::PayloadStructure`], the per-node payload
//!   envelope, plus the [`payloads::EmptyPayload`] used by the initial IR.
//! - [`shared_ir`] — type aliases naming each pipeline stage.
//! - [`codec`] — serde codecs that turn DataFusion logical plans / expressions
//!   into IR nodes and back.

pub mod codec;
pub mod ir;
pub mod nodes;
pub mod payloads;
pub mod shared_ir;
pub mod tree;
