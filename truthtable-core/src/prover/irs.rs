use ark_piop::SnarkBackend;

use crate::{
    irs::ir::Ir,
    prover::payloads::{
        ArithPayload, DataFramePayload, EmptyPayload, MemTablePayload, TrackedPayload,
    },
};

pub type InitialIr<B> = Ir<B, EmptyPayload>;
pub type PlannedIr<B> = Ir<B, DataFramePayload>;
pub type ExecutedIr<B> = Ir<B, MemTablePayload>;
pub type ArithmetizedIr<B> = Ir<B, ArithPayload<<B as SnarkBackend>::F>>;
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::irs::tree::Tree;
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
    #[tokio::test]
    async fn builds_initial_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int32,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef],
        )
        .unwrap();
        ctx.register_batch("dummy_table", batch).unwrap();

        let df = ctx.sql("SELECT value FROM dummy_table").await.unwrap();
        let lp = df.into_unoptimized_plan();

        let tree = Tree::from_logical_plan(&lp);
        let arena = tree.arena();
        let payloads = arena
            .keys()
            .map(|id| (id.clone(), EmptyPayload))
            .collect::<IndexMap<_, _>>();

        let ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new(tree, payloads);
        println!("{}", ir.display_graphviz(true));
        assert!(ir.tree().arena().len() >= 2);
    }
}
