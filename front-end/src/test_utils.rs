use std::path::PathBuf;

use datafusion::{arrow::array::RecordBatch, scalar::ScalarValue};
use std::collections::HashMap;

pub(crate) fn imdb_parquet_path(file_name: &str) -> PathBuf {
    // 1) Explicit override via env var
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

    // 2) Try current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("parquets").join(file_name);
        if candidate.exists() {
            return candidate;
        }
    }

    // 3) Walk up from the crate directory and try common relative paths
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut tried = Vec::new();
    for anc in crate_dir.ancestors() {
        let c1 = anc.join("parquets").join(file_name);
        if c1.exists() {
            return c1;
        }
        tried.push(c1);
    }

    // If nothing matched, panic with useful message listing where we looked
    let mut msg = format!("Could not find '{}'. Tried:\n", file_name);
    for t in tried {
        msg.push_str("  - ");
        msg.push_str(&t.display().to_string());
        msg.push('\n');
    }
    panic!("{}", msg);
}

/// Order-insensitive equality using row hashing (multiset semantics).
///
/// Builds maps of row->count for both sides and compares counts. This avoids
/// sorting and is robust to batch boundaries and row order. Schemas (field
/// names and types) must match exactly and rows are compared positionally by
/// column order.
pub fn are_batches_equal(left: &[RecordBatch], right: &[RecordBatch]) -> bool {
    // Quick checks
    let total_rows = |v: &[RecordBatch]| v.iter().map(|b| b.num_rows()).sum::<usize>();
    if total_rows(left) != total_rows(right) {
        return false;
    }
    if left.is_empty() && right.is_empty() {
        return true;
    }

    // Schema equality (names + types) — use the first non-empty batch schema on
    // each side
    let lschema = left
        .iter()
        .find(|b| b.num_columns() > 0)
        .map(|b| b.schema());
    let rschema = right
        .iter()
        .find(|b| b.num_columns() > 0)
        .map(|b| b.schema());
    match (lschema, rschema) {
        (Some(l), Some(r)) => {
            if l.fields().len() != r.fields().len() {
                return false;
            }
            for (lf, rf) in l.fields().iter().zip(r.fields().iter()) {
                if lf.name() != rf.name() || lf.data_type() != rf.data_type() {
                    return false;
                }
            }
        },
        // If both are entirely empty (no batches or no columns), they are equal
        (None, None) => return true,
        _ => return false,
    }

    // Build multiset of row keys for left, then decrement with right
    let mut counts: HashMap<String, i64> = HashMap::new();
    for b in left {
        let cols = b.columns();
        for row in 0..b.num_rows() {
            let mut key_parts = Vec::with_capacity(cols.len());
            for col in cols {
                // Normalize via ScalarValue -> String
                let sv =
                    ScalarValue::try_from_array(col.as_ref(), row).unwrap_or(ScalarValue::Null);
                key_parts.push(sv.to_string());
            }
            let key = key_parts.join("\u{1F}"); // unit separator to reduce collision chance
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    for b in right {
        let cols = b.columns();
        for row in 0..b.num_rows() {
            let mut key_parts = Vec::with_capacity(cols.len());
            for col in cols {
                let sv =
                    ScalarValue::try_from_array(col.as_ref(), row).unwrap_or(ScalarValue::Null);
                key_parts.push(sv.to_string());
            }
            let key = key_parts.join("\u{1F}");
            *counts.entry(key).or_insert(0) -= 1;
        }
    }
    counts.values().all(|&c| c == 0)
}

/// Equality on the "effective" rows only.
///
/// If both sides expose an `activator` Boolean column, filters to rows with
/// `activator=true` on each side before comparing via `are_batches_equal`.
/// If either side does not have an `activator` column, compares all rows via
/// `are_batches_equal`.
pub fn are_effective_batches_equal(left: &[RecordBatch], right: &[RecordBatch]) -> bool {
    let has_activator = |v: &[RecordBatch]| -> bool {
        v.iter()
            .find(|b| b.num_columns() > 0)
            .map_or(false, |b| b.schema().index_of("activator").is_ok())
    };

    let left_has = has_activator(left);
    let right_has = has_activator(right);

    if left_has && right_has {
        use datafusion::arrow::{array::BooleanArray, compute::filter as arrow_filter};
        let filter_true = |batches: &[RecordBatch]| -> Vec<RecordBatch> {
            let mut out = Vec::with_capacity(batches.len());
            for b in batches {
                let idx = match b.schema().index_of("activator") {
                    Ok(i) => i,
                    Err(_) => {
                        out.push(b.clone());
                        continue;
                    }
                };
                let mask = b
                    .column(idx)
                    .as_any()
                    .downcast_ref::<BooleanArray>()
                    .expect("'activator' must be Boolean");
                let mut cols = Vec::with_capacity(b.num_columns());
                for col in b.columns() {
                    let filtered = arrow_filter(col.as_ref(), mask).expect("filter should succeed");
                    cols.push(filtered);
                }
                let fb = RecordBatch::try_new(b.schema(), cols).expect("batch rebuild after filter");
                out.push(fb);
            }
            out
        };

        let lf = filter_true(left);
        let rf = filter_true(right);
        are_batches_equal(&lf, &rf)
    } else {
        are_batches_equal(left, right)
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::prelude::{ParquetReadOptions, SessionContext};

    async fn query(ctx: &SessionContext, sql: &str) -> Vec<RecordBatch> {
        ctx.sql(sql).await.unwrap().collect().await.unwrap()
    }

    #[tokio::test]
    async fn unordered_hash_equal_cases() {
        let ctx = SessionContext::new();
        let parquet_path = imdb_parquet_path("title-sanitized.parquet");
        assert!(
            parquet_path.exists(),
            "Missing Parquet at {:?}",
            parquet_path
        );
        ctx.register_parquet(
            "titles",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .unwrap();

        // Identical queries
        let q1 = "SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000";
        let q2 = "SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000";

        let b1 = query(&ctx, q1).await;
        let b2 = query(&ctx, q2).await;
        assert!(are_batches_equal(&b1, &b2));

        // Equivalent queries with different output order
        let q3 = "SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000 ORDER BY TITLE ASC";
        let q4 = "SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000 ORDER BY TITLE DESC";
        let b3 = query(&ctx, q3).await;
        let b4 = query(&ctx, q4).await;
        assert!(are_batches_equal(&b3, &b4));
    }

    #[tokio::test]
    async fn unordered_hash_not_equal_case() {
        let ctx = SessionContext::new();
        let parquet_path = imdb_parquet_path("title-sanitized.parquet");
        assert!(
            parquet_path.exists(),
            "Missing Parquet at {:?}",
            parquet_path
        );
        ctx.register_parquet(
            "titles",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .unwrap();

        // Different predicate -> different row set
        let q1 = "SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000";
        let qdiff = "SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 1999";
        let b1 = query(&ctx, q1).await;
        let bdiff = query(&ctx, qdiff).await;
        assert!(!are_batches_equal(&b1, &bdiff));
    }
}
