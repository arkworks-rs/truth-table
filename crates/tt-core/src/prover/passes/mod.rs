//! The prover's passes over the IR, from logical plans to the arithmetized,
//! tracked tables the gadgets prove over.

pub mod arithmetization;
pub mod commitment;
pub mod gadget_initialization;
pub mod gadget_planning;
pub mod honest_prover;
pub mod materialization;
pub mod output_planning;
pub mod proving;
pub mod tracking;
pub mod virtualization;
