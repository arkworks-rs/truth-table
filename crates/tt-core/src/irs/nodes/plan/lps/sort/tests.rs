//! ORDER BY must bind Sortcheck to the materialized output's key columns.

use std::{any::Any, collections::HashMap, sync::Arc};

use arithmetic::{ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, prover::ArgProver,
    test_utils::prelude_with_vars, types::TrackerID,
};
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};
use datafusion_common::{Column, DFSchema, TableReference};
use datafusion_expr::{
    Expr, LogicalPlan, Sort, col, expr::Sort as SortExpr, logical_plan::EmptyRelation,
};
use indexmap::IndexMap;

use super::gadget::OUTPUT_SORT_EXPRS;
use crate::{
    irs::{
        ir::Ir,
        nodes::{IsNode, Node, NodeId, PlanNode, ProverNodeOps, plan::exprs::column},
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn test_df() -> datafusion::prelude::DataFrame {
    let schema = Arc::new(Schema::new(vec![
        Field::new("a", DataType::Int64, false),
        Field::new("b", DataType::Int64, false),
        Field::new(arithmetic::ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(vec![2, 1, 1, 2])) as ArrayRef,
            Arc::new(Int64Array::from(vec![1, 3, 2, 4])) as ArrayRef,
            Arc::new(BooleanArray::from(vec![true; 4])) as ArrayRef,
        ],
    )
    .unwrap();
    SessionContext::new().read_batch(batch).unwrap()
}

fn test_df_qualifier() -> String {
    let df = test_df();
    df.schema()
        .iter()
        .find(|(_, field)| field.name() == "a")
        .and_then(|(qualifier, _)| qualifier.map(ToString::to_string))
        .expect("read_batch should qualify its fields")
}

fn tracked_table(prover: &mut ArgProver<B>, a: [u64; 4], b: [u64; 4]) -> TrackedTable<B> {
    // Production hint materialization preserves DataFusion's relation
    // qualifier in metadata, so the hand-built tracked table models the
    // identity obtained from the fixture rather than hard-coding it.
    let qualifier = HashMap::from([("tt.qualifier".to_string(), test_df_qualifier())]);
    let a_field =
        Arc::new(Field::new("a", DataType::Int64, false).with_metadata(qualifier.clone()));
    let b_field = Arc::new(Field::new("b", DataType::Int64, false).with_metadata(qualifier));
    let a_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            2,
            a.into_iter().map(F::from).collect(),
        ))
        .unwrap();
    let b_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            2,
            b.into_iter().map(F::from).collect(),
        ))
        .unwrap();
    let active_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(2, vec![F::from(1u64); 4]))
        .unwrap();
    let mut polys = IndexMap::new();
    polys.insert(a_field.clone(), a_poly);
    polys.insert(b_field.clone(), b_poly);
    polys.insert(ACTIVATOR_FIELD.clone(), active_poly);
    TrackedTable::new(
        Some(Schema::new(vec![a_field, b_field, ACTIVATOR_FIELD.clone()])),
        polys,
        2,
    )
}

fn data_id(table: &TrackedTable<B>, name: &str) -> TrackerID {
    table
        .tracked_polys_iter()
        .find(|(field, _)| field.name() == name)
        .unwrap_or_else(|| panic!("missing tracked column {name}"))
        .1
        .id()
}

fn sole_data_id(table: &TrackedTable<B>) -> TrackerID {
    let indices = table.data_tracked_polys_indices();
    assert_eq!(indices.len(), 1, "expected one expression data column");
    table
        .tracked_col_by_ind(indices[0])
        .data_tracked_poly()
        .id()
}

fn sole_oracle_id(table: &TrackedTableOracle<B>) -> TrackerID {
    let indices = table.data_tracked_oracles_indices();
    assert_eq!(indices.len(), 1, "expected one output-key oracle");
    table
        .tracked_col_oracle_by_ind(indices[0])
        .data_tracked_oracle()
        .id()
}

fn active_id(table: &TrackedTable<B>) -> TrackerID {
    table
        .activator_tracked_poly()
        .expect("expected an output activator")
        .id()
}

fn active_oracle_id(table: &TrackedTableOracle<B>) -> TrackerID {
    table
        .activator_tracked_poly()
        .expect("expected an output activator oracle")
        .id()
}

fn qualified_id_table(prover: &mut ArgProver<B>) -> (TrackedTable<B>, TrackerID, TrackerID) {
    let qualified_field = |relation: &str| {
        Arc::new(
            Field::new("id", DataType::Int64, false).with_metadata(HashMap::from([(
                "tt.qualifier".to_string(),
                relation.to_string(),
            )])),
        )
    };
    let left_field = qualified_field("l");
    let right_field = qualified_field("r");
    let left = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            2,
            [10u64, 20, 30, 40].into_iter().map(F::from).collect(),
        ))
        .unwrap();
    let right = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            2,
            [1u64, 2, 3, 4].into_iter().map(F::from).collect(),
        ))
        .unwrap();
    let active = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            2,
            [1u64, 1, 1, 0].into_iter().map(F::from).collect(),
        ))
        .unwrap();
    let left_id = left.id();
    let right_id = right.id();
    let mut polys = IndexMap::new();
    polys.insert(left_field.clone(), left);
    polys.insert(right_field.clone(), right);
    polys.insert(ACTIVATOR_FIELD.clone(), active);
    (
        TrackedTable::new(
            Some(Schema::new(vec![
                left_field,
                right_field,
                ACTIVATOR_FIELD.clone(),
            ])),
            polys,
            2,
        ),
        left_id,
        right_id,
    )
}

fn qualified_id_sort(key: SortExpr) -> Sort {
    let schema = DFSchema::new_with_metadata(
        vec![
            (
                Some(TableReference::bare("l")),
                Arc::new(Field::new("id", DataType::Int64, false)),
            ),
            (
                Some(TableReference::bare("r")),
                Arc::new(Field::new("id", DataType::Int64, false)),
            ),
        ],
        HashMap::new(),
    )
    .unwrap();
    Sort {
        expr: vec![key],
        input: Arc::new(LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema: Arc::new(schema),
        })),
        fetch: None,
    }
}

fn add_expr_witnesses(node: &Arc<Node<B>>, ir: &mut VirtualizedIr<B>) {
    for child in node.children() {
        if matches!(child.as_ref(), Node::Plan(PlanNode::ExprBased(_))) {
            add_expr_witnesses(&child, ir);
        }
    }
    ProverNodeOps::add_virtual_witness(node.as_ref(), node.id(), ir).unwrap();
}

fn prepared_sort_ir(
    sort_keys: Vec<Expr>,
    input_a: [u64; 4],
    input_b: [u64; 4],
    output_a: [u64; 4],
    output_b: [u64; 4],
) -> (Arc<Node<B>>, VirtualizedIr<B>, ArgProver<B>) {
    let sorted = test_df()
        .sort(
            sort_keys
                .iter()
                .cloned()
                .map(|expr| expr.sort(true, false))
                .collect(),
        )
        .unwrap();
    let tree = Tree::<B>::from_logical_plan(sorted.logical_plan());
    let root = tree.root().clone();
    let children = root.children();
    let expression_count = sort_keys.len();
    let (mut prover, _verifier) = prelude_with_vars::<B>(8).unwrap();
    let input = tracked_table(&mut prover, input_a, input_b);
    let output = tracked_table(&mut prover, output_a, output_b);
    let mut ir = Ir::new_empty(tree);
    ir.set_payload_for_node(root.id(), Some(PayloadStructure::PlanPayload(output)));
    // Expression children remain scoped to this input for acyclic planning.
    // They are auxiliary only: Sortcheck is wired from the root output below.
    ir.set_payload_for_node(children[0].id(), Some(PayloadStructure::PlanPayload(input)));

    for expr in &children[1..=expression_count] {
        add_expr_witnesses(expr, &mut ir);
    }
    (root, ir, prover)
}

fn assert_column_scopes(node: &Node<B>, expected_scope_id: NodeId) -> usize {
    let mut count = 0;
    if let Node::Plan(PlanNode::ExprBased(expr)) = node
        && let Some(column) = (expr.as_ref() as &dyn Any).downcast_ref::<column::ExprNode<B>>()
    {
        assert_eq!(column.scope.len(), 1);
        assert_eq!(column.scope[0].upgrade().unwrap().id(), expected_scope_id);
        count += 1;
    }
    for child in node.children() {
        count += assert_column_scopes(child.as_ref(), expected_scope_id);
    }
    count
}

#[test]
fn expression_children_remain_input_scoped_for_planning() {
    let keys: Vec<Expr> = vec![col("a"), col("b")];
    let df = test_df();
    let sorted = df
        .sort(vec![
            keys[0].clone().sort(true, false),
            keys[1].clone().sort(false, false),
        ])
        .unwrap();
    let tree = Tree::<B>::from_logical_plan(sorted.logical_plan());
    let root = tree.root();
    let children = root.children();
    // Child zero is the input plan; the following expression children remain
    // input-scoped so the plan graph is acyclic. They do not supply the keys
    // checked by Sortcheck.
    let checked: usize = children[1..=keys.len()]
        .iter()
        .map(|expr| assert_column_scopes(expr.as_ref(), children[0].id()))
        .sum();
    assert_eq!(checked, 2, "both planning expressions must use input rows");
}

#[test]
fn sortcheck_uses_exact_output_tracker_ids_for_multicolumn_keys() {
    let keys = vec![col("a"), col("b")];
    let key_count = keys.len();
    let (root, mut ir, mut prover) = prepared_sort_ir(
        keys,
        [40, 30, 20, 10],
        [400, 300, 200, 100],
        [1, 1, 2, 2],
        [2, 3, 1, 4],
    );
    let children = root.children();
    let input = match ir.payload_for_node(&children[0].id()) {
        Some(PayloadStructure::PlanPayload(table)) => table,
        _ => panic!("missing ORDER BY input payload"),
    };
    let output = match ir.payload_for_node(&root.id()) {
        Some(PayloadStructure::PlanPayload(table)) => table,
        _ => panic!("missing ORDER BY output payload"),
    };
    let input_a_id = data_id(input, "a");
    let input_b_id = data_id(input, "b");
    let output_a_id = data_id(output, "a");
    let output_b_id = data_id(output, "b");

    // Planning expression children use the input commitments. Keeping these
    // IDs distinct from the output commitments makes the regression test
    // detect accidental rewiring back to an independently evaluated helper.
    for (expr, expected_id) in children[1..=key_count].iter().zip([input_a_id, input_b_id]) {
        let expr_table = match ir.payload_for_node(&expr.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => panic!("missing direct sort-expression payload"),
        };
        assert_eq!(sole_data_id(expr_table), expected_id);
    }
    assert_ne!(input_a_id, output_a_id);
    assert_ne!(input_b_id, output_b_id);

    ProverNodeOps::initialize_gadgets(root.as_ref(), root.id(), &mut prover, &mut ir).unwrap();

    let order_gadget = children.last().unwrap();
    let sort_keys = match ir.payload_for_node(&order_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(payload)) => &payload[OUTPUT_SORT_EXPRS],
        _ => panic!("missing ORDER BY gadget payload"),
    };
    let sort_key_indices = sort_keys.data_tracked_polys_indices();
    assert_eq!(sort_key_indices.len(), key_count);
    for (expected_id, sort_key_idx) in [output_a_id, output_b_id].into_iter().zip(sort_key_indices)
    {
        assert_eq!(
            sort_keys
                .tracked_col_by_ind(sort_key_idx)
                .data_tracked_poly()
                .id(),
            expected_id,
            "Sortcheck must consume the exact materialized output commitment"
        );
    }
}

#[test]
fn computed_sort_keys_are_rejected_fail_closed() {
    for unsupported_key in [col("a") + col("b"), col("a") / col("b")] {
        let sorted = test_df()
            .sort(vec![unsupported_key.clone().sort(true, false)])
            .unwrap();
        let tree = Tree::<B>::from_logical_plan(sorted.logical_plan());
        let root = tree.root().clone();
        let mut ir = Ir::new_empty(tree);

        let err = ProverNodeOps::add_virtual_witness(root.as_ref(), root.id(), &mut ir)
            .expect_err("unproved computed ORDER BY keys must fail closed");
        match err {
            ark_piop::errors::SnarkError::Artifact(message) => {
                assert!(message.contains("unsupported ORDER BY key"));
                assert!(message.contains("only direct column keys"));
            }
            other => panic!("unexpected ORDER BY validation error: {other:?}"),
        }
        assert_eq!(
            root.children().len(),
            2,
            "an invalid key must not be lowered into an expression witness"
        );
    }
}

#[test]
fn output_key_resolution_never_discards_or_invents_a_qualifier() {
    let schema = DFSchema::new_with_metadata(
        vec![
            (
                Some(TableReference::bare("l")),
                Arc::new(Field::new("id", DataType::Int64, false)),
            ),
            (
                Some(TableReference::bare("r")),
                Arc::new(Field::new("id", DataType::Int64, false)),
            ),
        ],
        HashMap::new(),
    )
    .unwrap();
    let right = SortExpr::new(Expr::Column(Column::new(Some("r"), "id")), true, false);
    let missing = SortExpr::new(Expr::Column(Column::new(Some("x"), "id")), true, false);
    let ambiguous = SortExpr::new(Expr::Column(Column::new_unqualified("id")), true, false);
    let requested = vec![right, missing, ambiguous];

    let resolved = super::output::resolve_sort_exprs(&schema, &requested);

    assert_eq!(resolved, requested);
}

#[test]
fn tracked_output_key_selection_honors_qualifiers_on_both_sides() {
    let (mut prover, mut verifier) = prelude_with_vars::<B>(8).unwrap();
    let (output, left_id, right_id) = qualified_id_table(&mut prover);
    let right_key = SortExpr::new(Expr::Column(Column::new(Some("r"), "id")), true, false);

    let right_sort = qualified_id_sort(right_key.clone());
    let prover_keys = super::build_output_sort_keys_prover(&output, &right_sort)
        .expect("the exact qualified output key should resolve");
    assert_eq!(sole_data_id(&prover_keys), right_id);
    assert_ne!(sole_data_id(&prover_keys), left_id);
    assert_eq!(
        active_id(&prover_keys),
        active_id(&output),
        "Sortcheck must reuse the exact output activator"
    );

    let missing_key = SortExpr::new(
        Expr::Column(Column::new(Some("missing"), "id")),
        true,
        false,
    );
    let missing_error =
        super::build_output_sort_keys_prover(&output, &qualified_id_sort(missing_key))
            .expect_err("a missing qualifier must not fall back to another relation");
    assert!(
        missing_error
            .to_string()
            .contains("does not resolve uniquely")
    );

    let ambiguous_key = SortExpr::new(Expr::Column(Column::new_unqualified("id")), true, false);
    let ambiguous_error =
        super::build_output_sort_keys_prover(&output, &qualified_id_sort(ambiguous_key))
            .expect_err("an ambiguous unqualified key must not pick the first relation");
    assert!(
        ambiguous_error
            .to_string()
            .contains("does not resolve uniquely")
    );

    // Mirror the exact successful selection on the verifier. The proof only
    // needs to carry the commitments created above; no gadget claims are
    // required to test the tracked-oracle wiring itself.
    let proof = prover.build_proof().unwrap();
    verifier.set_proof(proof);
    let output_oracle = TrackedTableOracle::from_tracked_table(output, &mut verifier).unwrap();
    let verifier_keys =
        super::build_output_sort_keys_verifier(&output_oracle, &right_sort).unwrap();
    assert_eq!(sole_oracle_id(&verifier_keys), right_id);
    assert_ne!(sole_oracle_id(&verifier_keys), left_id);
    assert_eq!(
        active_oracle_id(&verifier_keys),
        active_oracle_id(&output_oracle),
        "the verifier must reuse the exact output activator oracle"
    );
}

#[test]
fn tracked_output_key_schema_must_match_the_validated_logical_key() {
    let sorted = test_df().sort(vec![col("a").sort(true, false)]).unwrap();
    let LogicalPlan::Sort(sort) = sorted.logical_plan() else {
        panic!("expected Sort plan");
    };
    let qualifier = HashMap::from([("tt.qualifier".to_string(), test_df_qualifier())]);

    for (actual_type, nullable, expected_message) in [
        (DataType::Int64, true, "is nullable"),
        (DataType::UInt64, false, "expected `Int64`"),
    ] {
        let (mut prover, _verifier) = prelude_with_vars::<B>(8).unwrap();
        let key = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                2,
                [1u64, 2, 3, 4].into_iter().map(F::from).collect(),
            ))
            .unwrap();
        let active = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(2, vec![F::from(1u64); 4]))
            .unwrap();
        let key_field =
            Arc::new(Field::new("a", actual_type, nullable).with_metadata(qualifier.clone()));
        let mut polys = IndexMap::new();
        polys.insert(key_field.clone(), key);
        polys.insert(ACTIVATOR_FIELD.clone(), active);
        let malformed = TrackedTable::new(
            Some(Schema::new(vec![key_field, ACTIVATOR_FIELD.clone()])),
            polys,
            2,
        );

        let error = super::build_output_sort_keys_prover(&malformed, sort)
            .expect_err("tracked output schema must match the validated Sort schema");
        assert!(
            error.to_string().contains(expected_message),
            "expected `{expected_message}` in `{error}`"
        );
    }
}

#[test]
fn tracked_output_activator_must_be_boolean() {
    let sorted = test_df().sort(vec![col("a").sort(true, false)]).unwrap();
    let LogicalPlan::Sort(sort) = sorted.logical_plan() else {
        panic!("expected Sort plan");
    };
    let qualifier = HashMap::from([("tt.qualifier".to_string(), test_df_qualifier())]);
    let (mut prover, _verifier) = prelude_with_vars::<B>(8).unwrap();
    let key = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            2,
            [1u64, 2, 3, 4].into_iter().map(F::from).collect(),
        ))
        .unwrap();
    let active = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(2, vec![F::from(1u64); 4]))
        .unwrap();
    let key_field = Arc::new(Field::new("a", DataType::Int64, false).with_metadata(qualifier));
    let malformed_active = Arc::new(Field::new(
        arithmetic::ACTIVATOR_COL_NAME,
        DataType::Int64,
        false,
    ));
    let mut polys = IndexMap::new();
    polys.insert(key_field.clone(), key);
    polys.insert(malformed_active.clone(), active);
    let malformed = TrackedTable::new(
        Some(Schema::new(vec![key_field, malformed_active])),
        polys,
        2,
    );

    let error = super::build_output_sort_keys_prover(&malformed, sort)
        .expect_err("the output activator schema is part of the soundness boundary");
    assert!(error.to_string().contains("must be Boolean"));
}

#[test]
fn missing_lp_input_or_output_payload_is_rejected() {
    for missing_output in [false, true] {
        let (root, mut ir, mut prover) = prepared_sort_ir(
            vec![col("a")],
            [4, 3, 2, 1],
            [0, 0, 0, 0],
            [1, 2, 3, 4],
            [0, 0, 0, 0],
        );
        let missing_id = if missing_output {
            root.id()
        } else {
            root.children()[0].id()
        };
        ir.set_payload_for_node(missing_id, None);

        let error =
            ProverNodeOps::initialize_gadgets(root.as_ref(), root.id(), &mut prover, &mut ir)
                .expect_err("ORDER BY must fail closed when a row table is missing");
        assert!(matches!(error, ark_piop::errors::SnarkError::Artifact(_)));
        assert!(error.to_string().contains("ORDER BY"));
        assert!(error.to_string().contains("missing"));
    }
}

#[test]
fn production_wiring_overwrites_a_sorted_helper_with_the_actual_unsorted_output_key() {
    let (root, mut ir, mut prover) = prepared_sort_ir(
        vec![col("a")],
        [1, 2, 3, 4],
        [0, 0, 0, 0],
        [2, 1, 3, 4],
        [0, 0, 0, 0],
    );
    let root_children = root.children();
    let order_gadget = root_children.last().unwrap();
    let sort_gadget = order_gadget.children()[0].clone();

    let sorted_helper = tracked_table(&mut prover, [1, 2, 3, 4], [0, 0, 0, 0]);
    let helper_id = data_id(&sorted_helper, "a");
    let mut helper_payload = IndexMap::new();
    helper_payload.insert(OUTPUT_SORT_EXPRS.to_string(), sorted_helper);
    ir.set_payload_for_node(
        order_gadget.id(),
        Some(PayloadStructure::GadgetPayload(helper_payload)),
    );

    // First the Sort LP must replace any pre-existing helper payload with a
    // table selected directly from the materialized Sort output.
    ProverNodeOps::initialize_gadgets(root.as_ref(), root.id(), &mut prover, &mut ir).unwrap();
    // Then the ORDER gadget passes that exact table to ContiguousSort.
    ProverNodeOps::initialize_gadgets(
        order_gadget.as_ref(),
        order_gadget.id(),
        &mut prover,
        &mut ir,
    )
    .unwrap();

    let output_id = match ir.payload_for_node(&root.id()) {
        Some(PayloadStructure::PlanPayload(table)) => data_id(table, "a"),
        _ => panic!("missing ORDER BY output payload"),
    };
    let checked_id = match ir.payload_for_node(&sort_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(payload)) => payload
            [crate::irs::nodes::utils::contig_sort::TABLE_LABEL]
            .tracked_col_by_ind(0)
            .data_tracked_poly()
            .id(),
        _ => panic!("missing Sortcheck payload"),
    };
    assert_ne!(
        helper_id, output_id,
        "test setup needs distinct commitments"
    );
    assert_eq!(
        checked_id, output_id,
        "an independently sorted helper must not replace the actual output key"
    );
}
