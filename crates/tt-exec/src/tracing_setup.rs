/// Initializes tracing with tree, span-timing and event layers. With
/// `emit_jsonl_stats` the JSONL statistics layer is added and the
/// `bench_stats` target is kept out of the other three.
pub fn init_cli_tracing(emit_jsonl_stats: bool) {
    if emit_jsonl_stats {
        ark_piop::test_utils::init_subscriber_with(|| {
            use tracing_subscriber::filter::filter_fn;
            use tracing_subscriber::fmt::format::FmtSpan;
            use tracing_subscriber::prelude::*;

            let filter = ark_piop::test_utils::build_env_filter();

            let tree_layer = tracing_tree::HierarchicalLayer::default()
                .with_targets(false)
                .with_timer(tracing_tree::time::Uptime::default())
                .with_deferred_spans(true)
                .with_writer(std::io::stdout)
                .with_filter(filter_fn(|metadata| {
                    metadata.is_span() && metadata.target() != "bench_stats"
                }));

            let span_timing_layer = tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_timer(tracing_subscriber::fmt::time::Uptime::default())
                .with_target(false)
                .with_filter(filter_fn(|metadata| {
                    metadata.is_span() && metadata.target() != "bench_stats"
                }));

            let event_layer = tracing_subscriber::fmt::layer()
                .with_timer(tracing_subscriber::fmt::time::Uptime::default())
                .with_target(false)
                .with_filter(filter_fn(|metadata| {
                    metadata.is_event() && metadata.target() != "bench_stats"
                }));

            let registry = tracing_subscriber::registry()
                .with(filter)
                .with(tree_layer)
                .with(span_timing_layer)
                .with(event_layer);

            match crate::stats_jsonl::BenchStatsJsonlLayer::new_default() {
                Ok(stats_layer) => {
                    let _ = registry.with(stats_layer).try_init();
                }
                Err(err) => {
                    eprintln!("failed to initialize jsonl stats layer: {}", err);
                    let _ = registry.try_init();
                }
            }
        });
    } else {
        ark_piop::test_utils::init_subscriber();
    }
}

pub fn init_test_tracing(emit_jsonl_stats: bool) {
    init_cli_tracing(emit_jsonl_stats);
}
