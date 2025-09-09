use super::{nodes::*, ProofPlan};

impl ProofPlan {
    /// Render this ProofPlan as a Graphviz DOT string, similar to
    /// DataFusion's `LogicalPlan::display_graphviz()`.
    pub fn display_graphviz(&self) -> String {
        fn escape_label(s: &str) -> String {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        }

        fn kind(node: &ProofPlan) -> &'static str {
            match node.root {
                ProofPlanNode::Projection(_) => "Projection",
                ProofPlanNode::Filter(_) => "Filter",
                ProofPlanNode::Aggregate(_) => "Aggregate",
                ProofPlanNode::Sort(_) => "Sort",
                ProofPlanNode::Join(_) => "Join",
                ProofPlanNode::Repartition(_) => "Repartition",
                ProofPlanNode::Window(_) => "Window",
                ProofPlanNode::Limit(_) => "Limit",
                ProofPlanNode::TableScan(_) => "TableScan",
                ProofPlanNode::Union(_) => "Union",
                ProofPlanNode::Subquery(_) => "Subquery",
                ProofPlanNode::SubqueryAlias(_) => "SubqueryAlias",
                ProofPlanNode::Distinct(_) => "Distinct",
                ProofPlanNode::Values(_) => "Values",
                ProofPlanNode::Explain(_) => "Explain",
                ProofPlanNode::Analyze(_) => "Analyze",
                ProofPlanNode::Extension(_) => "Extension",
                ProofPlanNode::Other(_) => "Other",
            }
        }

        fn label_for(node: &ProofPlan) -> String {
            let meta = match &node.root {
                ProofPlanNode::Projection(ProjectionNode { expr, .. }) => {
                    format!(" exprs: {}", expr.len())
                },
                ProofPlanNode::Filter(FilterNode { predicate, .. }) => {
                    format!(" predicate: {}", predicate)
                },
                ProofPlanNode::Aggregate(AggregateNode {
                    group_expr,
                    aggr_expr,
                    ..
                }) => {
                    format!(" groups: {}, aggrs: {}", group_expr.len(), aggr_expr.len())
                },
                ProofPlanNode::Sort(SortNode {
                    sort_expr, fetch, ..
                }) => {
                    format!(" keys: {}, fetch: {:?}", sort_expr.len(), fetch)
                },
                ProofPlanNode::Join(JoinNode { join_type, on, .. }) => {
                    format!(" {:?} on {}", join_type, on.len())
                },
                ProofPlanNode::Window(WindowNode { window_expr, .. }) => {
                    format!(" windows: {}", window_expr.len())
                },
                ProofPlanNode::Limit(LimitNode { skip, fetch, .. }) => {
                    let s = skip
                        .as_ref()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "-".into());
                    let f = fetch
                        .as_ref()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "-".into());
                    format!(" skip: {}, fetch: {}", s, f)
                },
                ProofPlanNode::SubqueryAlias(SubqueryAliasNode { alias, .. }) => {
                    format!(" alias: {}", alias)
                },
                _ => String::new(),
            };
            format!("ProofPlan::{}{}", kind(node), meta)
        }

        fn build_graph(
            node: &ProofPlan,
            next_id: &mut usize,
            nodes: &mut Vec<(usize, String)>,
            edges: &mut Vec<(usize, usize)>,
        ) -> usize {
            let my_id = *next_id;
            *next_id += 1;

            let lbl = escape_label(&label_for(node));
            nodes.push((my_id, lbl));

            match &node.root {
                ProofPlanNode::Projection(ProjectionNode { input, .. })
                | ProofPlanNode::Filter(FilterNode { input, .. })
                | ProofPlanNode::Aggregate(AggregateNode { input, .. })
                | ProofPlanNode::Sort(SortNode { input, .. })
                | ProofPlanNode::Repartition(RepartitionNode { input, .. })
                | ProofPlanNode::Window(WindowNode { input, .. })
                | ProofPlanNode::Limit(LimitNode { input, .. })
                | ProofPlanNode::Subquery(SubqueryNode { input, .. })
                | ProofPlanNode::SubqueryAlias(SubqueryAliasNode { input, .. })
                | ProofPlanNode::Distinct(DistinctNode { input, .. })
                | ProofPlanNode::Explain(ExplainNode { input, .. })
                | ProofPlanNode::Analyze(AnalyzeNode { input, .. }) => {
                    let cid = build_graph(input, next_id, nodes, edges);
                    edges.push((my_id, cid));
                },
                ProofPlanNode::Join(JoinNode { left, right, .. }) => {
                    let l = build_graph(left, next_id, nodes, edges);
                    edges.push((my_id, l));
                    let r = build_graph(right, next_id, nodes, edges);
                    edges.push((my_id, r));
                },
                ProofPlanNode::Union(UnionNode { inputs, .. })
                | ProofPlanNode::Extension(ExtensionNode { inputs, .. })
                | ProofPlanNode::Other(OtherNode { inputs, .. }) => {
                    for ch in inputs {
                        let cid = build_graph(ch, next_id, nodes, edges);
                        edges.push((my_id, cid));
                    }
                },
                ProofPlanNode::TableScan(_) | ProofPlanNode::Values(_) => {},
            }

            my_id
        }

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut next_id = 0usize;
        let _root_id = build_graph(self, &mut next_id, &mut nodes, &mut edges);

        let mut dot = String::new();
        dot.push_str("digraph LogicalPlan {\n");
        dot.push_str("  node [shape=box];\n");
        for (id, label) in nodes {
            dot.push_str(&format!("  n{} [label=\"{}\"];\n", id, label));
        }
        for (src, dst) in edges {
            dot.push_str(&format!("  n{} -> n{};\n", src, dst));
        }
        dot.push_str("}\n");
        dot
    }
}
