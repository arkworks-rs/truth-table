//! Prover passes for truth-table Intermediate Representations (IRs).
//!
//! This module contains transformation passes that operate on the prover's IRs, facilitating the progression from  dataframes (or logical plans) all the way to the arithmetized and tracked representations suitable for feeding to a SNARK prover.

pub mod gadget_initialization;
pub mod gadget_planning;
pub mod output_planning;
pub mod tracking;
pub mod verify;
pub mod virtualization;
