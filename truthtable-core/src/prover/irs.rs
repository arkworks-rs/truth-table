use ark_piop::SnarkBackend;

use crate::{
    irs::ir::Ir,
    prover::payloads::{
        ArithPayload, HintDFPayload, EmptyPayload, MemTablePayload, TrackedPayload,
    },
};

pub type InitialIr<B> = Ir<B, EmptyPayload>;
pub type PlannedIr<B> = Ir<B, HintDFPayload>;
pub type ExecutedIr<B> = Ir<B, MemTablePayload>;
pub type ArithmetizedIr<B> = Ir<B, ArithPayload<<B as SnarkBackend>::F>>;
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::irs::tree::Tree;
    use crate::prover::passes::planning::PlanningPass;
    use ark_piop::DefaultSnarkBackend;
    use datafusion::{
        arrow::{
            array::{ArrayRef, Int32Array},
            datatypes::{DataType, Field, Schema},
            record_batch::RecordBatch,
        },
        prelude::SessionContext,
    };
    use indexmap::IndexMap;
    use std::sync::Arc;

    fn dummy_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("first_column", DataType::Int32, false),
            Field::new("second_column", DataType::Int32, false),
            Field::new("third_column", DataType::Int32, false),
        ]))
    }

    fn register_dummy_table(ctx: &SessionContext) {
        let schema = dummy_schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef,
                Arc::new(Int32Array::from(vec![10, 20, 30])) as ArrayRef,
                Arc::new(Int32Array::from(vec![100, 200, 300])) as ArrayRef,
            ],
        )
        .unwrap();
        ctx.register_batch("dummy_table", batch).unwrap();
    }

    fn queries() -> Vec<&'static str> {
        vec![
            "SELECT first_column, second_column FROM dummy_table ",
            "SELECT first_column, second_column FROM dummy_table where third_column > 150",
        ]
    }
    #[tokio::test]
    async fn builds_initial_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);

        for query in queries() {
            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let payloads = tree
                .arena()
                .keys()
                .map(|id| (id.clone(), EmptyPayload))
                .collect::<IndexMap<_, _>>();

            let ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new(tree, payloads);
            println!("Query: {query}");
            println!("{}", ir.display_graphviz(true));
            assert!(!ir.tree().arena().is_empty());
        }
    }

    #[tokio::test]
    async fn builds_planned_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);
        let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();

        for query in queries() {
            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let payloads = tree
                .arena()
                .keys()
                .map(|id| (id.clone(), EmptyPayload))
                .collect::<IndexMap<_, _>>();

            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new(tree, payloads);
            let planned_ir = initial_ir.apply_local_pass_sequential(&planning_pass);

            println!("Planned Query: {query}");
            println!("{}", planned_ir.display_graphviz(true));
            assert!(!planned_ir.tree().arena().is_empty());
            assert_eq!(planned_ir.payloads().len(), planned_ir.tree().arena().len());
        }
    }
}
