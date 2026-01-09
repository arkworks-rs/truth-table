use arithmetic::{ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::functions_window::expr_fn::{first_value, lead};
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, ExprFunctionExt, SortExpr, col, expr_fn::when, lit};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
#[cfg(test)]
mod tests;
pub const TABLE_LABEL: &str = "__input__";
pub const ROTATED_INPUT_LABEL: &str = "__rotated_input__";
pub const TIE_INDICATOR_LABEL: &str = "__tie_indicator__";
pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

fn populate_rotated(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
) {
    let rotated_df =
        rotate(input_hint.data_frame().clone()).expect("sort rotate planning should succeed");
    let should_materialize = rotated_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), !is_system_column(field.name())))
        .collect();
    let rotated_hint = crate::irs::nodes::hints::HintDF::new(rotated_df, should_materialize);
    gadget_payload.insert(ROTATED_INPUT_LABEL.to_string(), rotated_hint);
}

fn populate_tie_indicator(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
) {
    let tie_df = tie_indicator(input_hint.data_frame().clone(), Vec::new())
        .expect("sort tie indicator planning should succeed");
    let should_materialize = tie_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), !is_system_column(field.name())))
        .collect();
    let tie_hint = crate::irs::nodes::hints::HintDF::new(tie_df, should_materialize);
    gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
}

fn rotate(df: DataFrame) -> DataFusionResult<DataFrame> {
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    if !has_row_id {
        return Err(DataFusionError::Plan(format!(
            "rotate requires {} column for deterministic ordering",
            ROW_ID_COL_NAME
        )));
    }

    let ordered = df.sort(vec![col(ROW_ID_COL_NAME).sort(true, true)])?;
    let mut rotated_cols = Vec::new();
    let order_by = vec![col(ROW_ID_COL_NAME).sort(true, true)];

    for field in ordered.schema().fields() {
        let name = field.name();
        if name == ROW_ID_COL_NAME {
            continue;
        }
        let lead_expr = lead(col(name), Some(1), None)
            .order_by(order_by.clone())
            .build()?;
        let first_expr = first_value(col(name)).order_by(order_by.clone()).build()?;
        let rotated_expr = when(lead_expr.clone().is_null(), first_expr)
            .otherwise(lead_expr)?
            .alias(name.to_string());
        rotated_cols.push(rotated_expr);
    }

    ordered.select(rotated_cols)
}

/// Builds a boolean tie-indicator table:
/// `tie_k` is true on row i iff rows i and i+1 match on columns [0..k-1].
pub fn tie_indicator(df: DataFrame, order_by: Vec<SortExpr>) -> DataFusionResult<DataFrame> {
    let schema = df.schema();
    let has_row_id = schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        order_by
    };
    if order_by.is_empty() {
        return Err(DataFusionError::Plan(
            "tie_indicator requires ordering or __row_id__ column".to_string(),
        ));
    }

    let data_cols: Vec<String> = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        .filter(|name| name != ROW_ID_COL_NAME)
        .collect();
    if data_cols.len() < 2 {
        return df.select(Vec::<Expr>::new());
    }

    let ordered = df.sort(order_by.clone())?;

    let mut prefix = lit(true);
    let mut out = Vec::with_capacity(data_cols.len() - 1);

    for (idx, col_name) in data_cols.iter().enumerate().take(data_cols.len() - 1) {
        let next_val = lead(col(col_name), Some(1), None)
            .order_by(order_by.clone())
            .build()?;
        let eq = col(col_name).eq(next_val);
        let eq_non_null = when(eq.clone().is_null(), lit(false)).otherwise(eq)?;
        prefix = prefix.and(eq_non_null);
        out.push(prefix.clone().alias(format!("tie_{}", idx + 1)));
    }

    ordered.select(out)
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Sort".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input_hint = match gadget_payload.get(TABLE_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        populate_rotated(&mut gadget_payload, &input_hint);
        populate_tie_indicator(&mut gadget_payload, &input_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        if payload.get(TABLE_LABEL).is_some() && payload.get(ROTATED_INPUT_LABEL).is_none() {
            panic!("Expected rotated input payload for Sort gadget");
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        if payload.get(TABLE_LABEL).is_some() && payload.get(ROTATED_INPUT_LABEL).is_none() {
            panic!("Expected rotated input payload for Sort gadget");
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}
