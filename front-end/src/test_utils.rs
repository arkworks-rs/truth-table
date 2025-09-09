use std::path::PathBuf;

pub(crate) fn imdb_parquet_path() -> PathBuf {
    // 1) Explicit override via env var
    if let Ok(p) = std::env::var("IMDB_PARQUET_PATH") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return pb;
        }
    }

    // 2) Try current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("imdb_parquet/title-sanitized.parquet");
        if candidate.exists() {
            return candidate;
        }
    }

    // 3) Walk up from the crate directory and try common relative paths
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut tried = Vec::new();
    for anc in crate_dir.ancestors() {
        let c1 = anc.join("imdb_parquet/title-sanitized.parquet");
        if c1.exists() {
            return c1;
        }
        tried.push(c1);

        let c2 = anc.join("sql-toolbox-bench/imdb_parquet/title-sanitized.parquet");
        if c2.exists() {
            return c2;
        }
        tried.push(c2);
    }

    // If nothing matched, panic with useful message listing where we looked
    let mut msg = String::from("Could not find 'title-sanitized.parquet'. Tried:\n");
    for t in tried {
        msg.push_str("  - ");
        msg.push_str(&t.display().to_string());
        msg.push('\n');
    }
    panic!("{}", msg);
}
