//! Prover passes for truth-table Intermediate Representations (IRs).
//!
//! This module contains transformation passes that operate on the prover's IRs, facilitating the progression from  dataframes (or logical plans) all the way to the arithmetized and tracked representations suitable for feeding to a SNARK prover.

pub mod arithmetization;
pub mod materialization;
pub mod gadget_initialization;
pub mod proving;
pub mod tracking;
pub mod virtualization;
