use std::{any::Any, collections::HashSet, sync::Arc};

use ark_piop::SnarkBackend;
use datafusion_common::{Column, TableReference};
use datafusion_expr::{Expr, LogicalPlan};
use tt_core::irs::nodes::hints::column_constraint_metadata;
use tt_core::irs::{
    nodes::{IsNode, Node, PlanNode, gadget::lps::join as gadget_join},
    shared_ir::InitialIr,
    tree::Tree,
};

use super::ProofPlanOptimizerRule;

pub struct SimplifyOneToManyJoins;

impl<B: SnarkBackend> ProofPlanOptimizerRule<B> for SimplifyOneToManyJoins {
    fn name(&self) -> &'static str {
        "SimplifyOneToManyJoins"
    }

    fn optimize(&self, ir: InitialIr<B>) -> InitialIr<B> {
        // Annotate join gadget modes (ONE_TO_MANY / MANY_TO_ONE / ONE_TO_ONE)
        // before materialization so expensive MANY_TO_MANY utility gadgets can be skipped.
        annotate_join_modes(ir.tree().root());
        // Rebuild the tree arena from the (now possibly mode-switched) root.
        // This drops hidden join-utility gadget subtrees from traversal.
        let rebuilt = Tree::new_from_root(ir.tree().root().clone());
        InitialIr::new_empty(rebuilt)
    }
}

fn annotate_join_modes<B: SnarkBackend>(node: &Arc<Node<B>>) {
    for child in node.children() {
        annotate_join_modes(&child);
    }

    let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref() else {
        return;
    };
    let LogicalPlan::Join(join) = lp_node.lp() else {
        return;
    };

    let mode = compute_join_mode_from_lp_node(node, &join);
    for child in node.children() {
        let Node::Gadget(gadget) = child.as_ref() else {
            continue;
        };
        let any = gadget.as_ref() as &dyn Any;
        if let Some(join_gadget) = any.downcast_ref::<gadget_join::GadgetNode<B>>() {
            join_gadget.set_join_mode(mode);
        }
    }
}

fn compute_join_mode_from_lp_node<B: SnarkBackend>(
    join_node: &Arc<Node<B>>,
    join: &datafusion_expr::Join,
) -> gadget_join::JoinMode {
    let children = join_node.children();
    if children.len() < 2 {
        return gadget_join::JoinMode::MANY_TO_MANY;
    }

    let left_fields = match children[0].as_ref() {
        Node::Plan(plan) => fields_with_metadata(&plan.output()),
        Node::Gadget(_) => return gadget_join::JoinMode::MANY_TO_MANY,
    };
    let right_fields = match children[1].as_ref() {
        Node::Plan(plan) => fields_with_metadata(&plan.output()),
        Node::Gadget(_) => return gadget_join::JoinMode::MANY_TO_MANY,
    };
    // Fallback table sets used when qualifier metadata is missing.
    let left_tables = collect_tables(&children[0]);
    let right_tables = collect_tables(&children[1]);

    let mut left_is_pk = true;
    let mut right_is_pk = true;
    let mut left_is_fk_to_right = true;
    let mut right_is_fk_to_left = true;

    for (left_expr, right_expr) in &join.on {
        let Some(left_col) = expr_to_column(left_expr) else {
            return gadget_join::JoinMode::MANY_TO_MANY;
        };
        let Some(right_col) = expr_to_column(right_expr) else {
            return gadget_join::JoinMode::MANY_TO_MANY;
        };

        let left_field = find_field_in_fields(&left_fields, &left_col);
        let right_field = find_field_in_fields(&right_fields, &right_col);
        let (Some(left_field), Some(right_field)) = (left_field, right_field) else {
            return gadget_join::JoinMode::MANY_TO_MANY;
        };

        let left_md = left_field.metadata();
        let right_md = right_field.metadata();

        // Resolve table names from (highest to lowest confidence):
        // 1) relation on expression, 2) field qualifier metadata, 3) column-name prefix inference,
        // 4) single-table side fallback.
        let left_table = table_name_from_column(&left_col)
            .or_else(|| {
                left_md
                    .get("tt.qualifier")
                    .map(|q| table_name_from_qualifier(q.as_str()))
            })
            .or_else(|| infer_table_from_column_name(left_col.name.as_str(), &left_tables))
            .or_else(|| single_table_name(&left_tables));
        let right_table = table_name_from_column(&right_col)
            .or_else(|| {
                right_md
                    .get("tt.qualifier")
                    .map(|q| table_name_from_qualifier(q.as_str()))
            })
            .or_else(|| infer_table_from_column_name(right_col.name.as_str(), &right_tables))
            .or_else(|| single_table_name(&right_tables));

        let left_meta = left_table
            .as_deref()
            .and_then(|tbl| column_constraint_metadata(tbl, left_col.name.as_str()));
        let right_meta = right_table
            .as_deref()
            .and_then(|tbl| column_constraint_metadata(tbl, right_col.name.as_str()));

        let left_pk = left_meta
            .as_ref()
            .map(|m| m.is_pk)
            .unwrap_or_else(|| left_md.get("tt.pk").map(|v| v == "true").unwrap_or(false));
        let right_pk = right_meta
            .as_ref()
            .map(|m| m.is_pk)
            .unwrap_or_else(|| right_md.get("tt.pk").map(|v| v == "true").unwrap_or(false));
        left_is_pk &= left_pk;
        right_is_pk &= right_pk;

        let left_fk_to_right = left_meta
            .as_ref()
            .and_then(|m| m.fk_ref_table.as_ref().map(|t| (t, &m.fk_ref_columns)))
            .map(|(ref_table, ref_cols)| {
                right_table
                    .as_deref()
                    .map(|t| table_name_from_qualifier(ref_table) == t)
                    .unwrap_or(true)
                    && ref_cols
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(right_col.name.as_str()))
            })
            .unwrap_or_else(|| {
                fk_matches(left_md, right_table.as_deref(), right_col.name.as_str())
            });
        let right_fk_to_left = right_meta
            .as_ref()
            .and_then(|m| m.fk_ref_table.as_ref().map(|t| (t, &m.fk_ref_columns)))
            .map(|(ref_table, ref_cols)| {
                left_table
                    .as_deref()
                    .map(|t| table_name_from_qualifier(ref_table) == t)
                    .unwrap_or(true)
                    && ref_cols
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(left_col.name.as_str()))
            })
            .unwrap_or_else(|| fk_matches(right_md, left_table.as_deref(), left_col.name.as_str()));

        left_is_fk_to_right &= left_fk_to_right;
        right_is_fk_to_left &= right_fk_to_left;
    }

    if left_is_pk && right_is_pk {
        gadget_join::JoinMode::ONE_TO_ONE
    } else if left_is_pk && right_is_fk_to_left {
        gadget_join::JoinMode::ONE_TO_MANY
    } else if right_is_pk && left_is_fk_to_right {
        gadget_join::JoinMode::MANY_TO_ONE
    } else {
        gadget_join::JoinMode::MANY_TO_MANY
    }
}

fn collect_tables<B: SnarkBackend>(node: &Arc<Node<B>>) -> HashSet<String> {
    let mut out = HashSet::new();
    collect_tables_rec(node, &mut out);
    out
}

fn collect_tables_rec<B: SnarkBackend>(node: &Arc<Node<B>>, out: &mut HashSet<String>) {
    if let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref() {
        if let LogicalPlan::TableScan(ts) = lp_node.lp() {
            out.insert(table_name_from_qualifier(
                ts.table_name.to_string().as_str(),
            ));
        }
    }
    for child in node.children() {
        collect_tables_rec(&child, out);
    }
}

fn single_table_name(tables: &HashSet<String>) -> Option<String> {
    if tables.len() == 1 {
        tables.iter().next().cloned()
    } else {
        None
    }
}

fn infer_table_from_column_name(col_name: &str, candidates: &HashSet<String>) -> Option<String> {
    let prefix = col_name
        .split('_')
        .next()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if prefix.is_empty() {
        return None;
    }

    let by_exact = candidates
        .iter()
        .filter(|t| t.as_str() == prefix.as_str())
        .cloned()
        .collect::<Vec<_>>();
    if by_exact.len() == 1 {
        return by_exact.into_iter().next();
    }

    let by_initial = candidates
        .iter()
        .filter(|t| t.chars().next().map(|c| c.to_string()) == Some(prefix.clone()))
        .cloned()
        .collect::<Vec<_>>();
    if by_initial.len() == 1 {
        return by_initial.into_iter().next();
    }
    None
}

fn expr_to_column(expr: &Expr) -> Option<Column> {
    match expr {
        Expr::Column(col) => Some(col.clone()),
        Expr::Alias(alias) => expr_to_column(&alias.expr),
        Expr::Cast(cast) => expr_to_column(&cast.expr),
        Expr::TryCast(cast) => expr_to_column(&cast.expr),
        _ => None,
    }
}

fn fields_with_metadata(
    hint: &tt_core::irs::nodes::hints::HintDF,
) -> Vec<(
    Option<TableReference>,
    datafusion::arrow::datatypes::FieldRef,
)> {
    let qualifiers: Vec<Option<TableReference>> = hint
        .data_frame()
        .schema()
        .iter()
        .map(|(qualifier, _)| qualifier.cloned())
        .collect();
    let fields: Vec<datafusion::arrow::datatypes::FieldRef> = hint
        .field_materialization_iter()
        .map(|(field, _)| field.clone())
        .collect();
    qualifiers.into_iter().zip(fields).collect()
}

fn find_field_in_fields(
    fields: &[(
        Option<TableReference>,
        datafusion::arrow::datatypes::FieldRef,
    )],
    col: &Column,
) -> Option<datafusion::arrow::datatypes::FieldRef> {
    let target_table = col.relation.as_ref().map(table_name_from_relation);
    let mut by_name = Vec::new();

    for (qualifier, field) in fields {
        if field.name().as_str() != col.name.as_str() {
            continue;
        }
        if let Some(target_table) = target_table.as_deref() {
            if qualifier_matches_field(target_table, qualifier.as_ref(), field) {
                return Some(field.clone());
            }
        }
        by_name.push(field.clone());
    }

    if by_name.len() == 1 {
        return by_name.into_iter().next();
    }
    None
}

fn qualifier_matches_field(
    target_table: &str,
    qualifier: Option<&TableReference>,
    field: &datafusion::arrow::datatypes::FieldRef,
) -> bool {
    if let Some(q) = qualifier {
        if table_name_from_qualifier(&q.to_string()) == target_table {
            return true;
        }
    }
    if let Some(q_md) = field.metadata().get("tt.qualifier") {
        if table_name_from_qualifier(q_md) == target_table {
            return true;
        }
    }
    false
}

fn fk_matches(
    metadata: &std::collections::HashMap<String, String>,
    expected_ref_table: Option<&str>,
    expected_ref_col: &str,
) -> bool {
    let Some(ref_table) = metadata.get("tt.fk.ref_table") else {
        return false;
    };
    if let Some(expected_ref_table) = expected_ref_table {
        if table_name_from_qualifier(ref_table) != expected_ref_table {
            return false;
        }
    }

    let Some(ref_cols_raw) = metadata.get("tt.fk.ref_columns") else {
        return false;
    };
    let ref_cols = parse_simple_json_string_array(ref_cols_raw);
    ref_cols
        .iter()
        .any(|col| col.eq_ignore_ascii_case(expected_ref_col))
}

fn parse_simple_json_string_array(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return Vec::new();
    }
    let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
    if inner.trim().is_empty() {
        return Vec::new();
    }
    inner
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn table_name_from_column(col: &Column) -> Option<String> {
    col.relation.as_ref().map(table_name_from_relation)
}

fn table_name_from_relation(relation: &TableReference) -> String {
    table_name_from_qualifier(&relation.to_string())
}

fn table_name_from_qualifier(qualifier: &str) -> String {
    qualifier
        .rsplit('.')
        .next()
        .unwrap_or(qualifier)
        .trim_matches('"')
        .trim_matches('`')
        .to_lowercase()
}
