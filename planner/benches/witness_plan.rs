#![allow(unused)]

use std::{path::PathBuf, sync::Arc};

use datafusion::prelude::{ParquetReadOptions, SessionContext};
use planner::{
    ra_proof_plan::{logical_to_proof_plan, ProofPlan},
    witness_plan::{proof_to_witness_plan, WitnessNode},
};

fn resolve_parquet(file_name: &str) -> PathBuf {
    if let Ok(p) = std::env::var("IMDB_PARQUET_PATH") {
        let pb = PathBuf::from(&p);
        let candidate = if pb.is_dir() {
            pb.join(file_name)
        } else {
            pb.clone()
        };
        if candidate.exists() {
            return candidate;
        }
    }
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = base.join("..").join("parquets").join(file_name);
    if candidate.exists() {
        return candidate;
    }
    panic!(
        "Could not resolve parquet. Set IMDB_PARQUET_PATH or place {} at {:?}",
        file_name, candidate
    );
}

#[divan::bench]
fn witness_sequential(bencher: divan::Bencher) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    bencher.bench_local(|| {
        rt.block_on(async {
            let _wtree = build_tree().await;
            divan::black_box(())
        })
    });
}

#[divan::bench]
fn witness_parallel(bencher: divan::Bencher) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    bencher.bench_local(|| {
        rt.block_on(async {
            let _wtree = build_tree().await;
            divan::black_box(())
        })
    });
}

#[cfg(unix)]
fn get_max_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    unsafe {
        libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr());
        let usage = usage.assume_init();
        let mut v = usage.ru_maxrss as u64;
        #[cfg(target_os = "macos")]
        {
            // macOS returns bytes
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Linux returns kilobytes
            v *= 1024;
        }
        v
    }
}

#[cfg(not(unix))]
fn get_max_rss_bytes() -> u64 {
    0
}

fn run_child_rss(mode: &str) -> u64 {
    let exe = std::env::current_exe().expect("current_exe");
    let out = std::process::Command::new(exe)
        .env("WP_RSS_BENCH", mode)
        .output()
        .expect("spawn child");
    assert!(out.status.success(), "child process failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("RSS_BYTES:") {
            if let Ok(v) = rest.trim().parse::<u64>() {
                return v;
            }
        }
    }
    0
}

#[divan::bench]
fn witness_sequential_rss(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let bytes = run_child_rss("seq");
        divan::black_box(bytes)
    });
}

#[divan::bench]
fn witness_parallel_rss(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let bytes = run_child_rss("par");
        divan::black_box(bytes)
    });
}

fn main() {
    if let Ok(mode) = std::env::var("WP_RSS_BENCH") {
        let _ = mode;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let _wtree = build_tree().await;
            let rss = get_max_rss_bytes();
            println!("RSS_BYTES:{}", rss);
        });
        return;
    }
    divan::main()
}

// Shared async helper to build the witness tree with fresh context and plan.
async fn build_tree() -> WitnessNode {
    // Fresh context and plan per iteration to avoid table name clashes
    let ctx = SessionContext::new();
    let parquet_path = resolve_parquet("title-sanitized.parquet");
    ctx.register_parquet(
        "titles",
        parquet_path.to_str().unwrap(),
        ParquetReadOptions::default(),
    )
    .await
    .unwrap();

    let sql = r#"SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000"#;
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();
    let proof_plan = logical_to_proof_plan(&ctx, &logical);

    proof_to_witness_plan(&ctx, Arc::clone(&proof_plan))
        .await
        .unwrap()
}
