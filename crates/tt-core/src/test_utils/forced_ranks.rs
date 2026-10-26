//! `(table, column)` rank columns added to every tree's
//! [`Tree::required_rank_columns`](crate::irs::tree::Tree::required_rank_columns),
//! so a test can load ranks at table scans that no node reads. The set is
//! global to the process, so every test of a binary that forces ranks must
//! force the same set.

use std::collections::BTreeSet;
use std::sync::Mutex;

static FORCED: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());

pub fn force_rank_columns<'a>(columns: impl IntoIterator<Item = &'a (&'a str, &'a str)>) {
    *FORCED.lock().expect("lock poisoned") = columns
        .into_iter()
        .map(|(table, column)| (table.to_string(), column.to_string()))
        .collect();
}

pub(crate) fn forced_rank_columns() -> BTreeSet<(String, String)> {
    FORCED.lock().expect("lock poisoned").clone()
}
