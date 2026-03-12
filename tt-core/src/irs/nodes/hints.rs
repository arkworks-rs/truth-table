use arithmetic::ROW_ID_COL_NAME;
use ark_std::fmt::Display;
use datafusion::{
    arrow::{
        datatypes::{Field, FieldRef, Schema},
        record_batch::RecordBatch,
    },
    prelude::{DataFrame, SessionContext},
};
use datafusion_common::{Column, Result as DataFusionResult, TableReference};
use datafusion_expr::{Expr, LogicalPlan, SortExpr, col, expr::Alias, expr_fn::try_cast};
use indexmap::IndexMap;
use serde::Deserialize;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};

#[derive(Clone, Debug)]
pub struct HintDF {
    data_fram: DataFrame,
    should_materialize: IndexMap<FieldRef, bool>,
}
impl Display for HintDF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (materialized, virtualized): (Vec<_>, Vec<_>) =
            self.should_materialize.iter().partition(|(_, mat)| **mat);

        let materialized_cols: Vec<String> = materialized
            .into_iter()
            .map(|(field, _)| field.name().to_string())
            .collect();
        let virtual_cols: Vec<String> = virtualized
            .into_iter()
            .map(|(field, _)| field.name().to_string())
            .collect();

        writeln!(f, "HintDF with {} columns", self.should_materialize.len())?;
        writeln!(f, "Materialized: ({})", materialized_cols.join(","))?;
        write!(f, "Virtual: ({})", virtual_cols.join(","))
    }
}

impl HintDF {
    pub fn new(data_fram: DataFrame, should_materialize: IndexMap<FieldRef, bool>) -> Self {
        let (data_fram, should_materialize) = normalize_hint_df(data_fram, should_materialize);
        Self {
            data_fram,
            should_materialize,
        }
    }

    pub fn new_materialized(plan: DataFrame) -> Self {
        Self::new_with_mat_flag(plan, true)
    }

    pub fn new_virtual(plan: DataFrame) -> Self {
        Self::new_with_mat_flag(plan, false)
    }

    fn new_with_mat_flag(data_fram: DataFrame, materialized: bool) -> Self {
        let should_materialize = data_fram
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), materialized))
            .collect();
        let (data_fram, should_materialize) = normalize_hint_df(data_fram, should_materialize);
        Self {
            data_fram,
            should_materialize,
        }
    }

    // Use only when `data_fram` and `should_materialize` are already aligned and normalized.
    pub(crate) fn new_assume_normalized(
        data_fram: DataFrame,
        should_materialize: IndexMap<FieldRef, bool>,
    ) -> Self {
        Self {
            data_fram,
            should_materialize,
        }
    }

    pub fn data_frame(&self) -> &DataFrame {
        &self.data_fram
    }

    pub fn should_materialize(&self, field: &FieldRef) -> Option<&bool> {
        self.should_materialize.get(field)
    }

    pub fn as_virtual_view(&self) -> Self {
        let should_materialize = self
            .data_fram
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), false))
            .collect();
        Self::new_assume_normalized(self.data_fram.clone(), should_materialize)
    }

    pub fn field_materialization_iter(&self) -> impl Iterator<Item = (&FieldRef, &bool)> {
        self.should_materialize.iter()
    }

    pub fn project_materialized(&self) -> Option<LogicalPlan> {
        todo!()
        // let schema = self.plan.schema();
        // let projection_exprs: Vec<Expr> = schema
        //     .iter()
        //     .filter(|&(_qualifier, field)| {
        //         self.should_materialize.get(field).copied().unwrap_or(false)
        //     })
        //     .map(|(qualifier, field)| Expr::from((qualifier, field)))
        //     .collect();

        // if projection_exprs.len() == schema.fields().len() {
        //     return Some(self.plan.clone());
        // }

        // if projection_exprs.is_empty() {
        //     return None;
        // }

        // LogicalPlanBuilder::from(self.plan.clone())
        //     .project(projection_exprs)
        //     .expect("failed to build projection for materialized columns")
        //     .build()
        //     .ok()
    }
}

pub fn sort_by_row_id_if_present(df: DataFrame) -> DataFusionResult<DataFrame> {
    let row_id_sort_exprs: Vec<SortExpr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true))
        })
        .collect();
    if row_id_sort_exprs.is_empty() {
        return Ok(df);
    }
    df.sort(row_id_sort_exprs)
}

pub fn schema_only_df(fields: Vec<Field>) -> DataFrame {
    static SCHEMA_ONLY_CTX: OnceLock<SessionContext> = OnceLock::new();
    let ctx = scoped_schema_only_ctx()
        .unwrap_or_else(|| SCHEMA_ONLY_CTX.get_or_init(SessionContext::new).clone());
    ctx.read_batch(RecordBatch::new_empty(Arc::new(Schema::new(fields))))
        .expect("schema-only dataframe construction should succeed")
}

thread_local! {
    static SCHEMA_ONLY_CTX_SCOPE: RefCell<Option<SessionContext>> = const { RefCell::new(None) };
}

pub(crate) fn begin_schema_only_ctx_scope() {
    SCHEMA_ONLY_CTX_SCOPE.with(|cell| {
        *cell.borrow_mut() = Some(SessionContext::new());
    });
}

pub(crate) fn end_schema_only_ctx_scope() {
    SCHEMA_ONLY_CTX_SCOPE.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

pub(crate) fn scoped_schema_only_ctx() -> Option<SessionContext> {
    SCHEMA_ONLY_CTX_SCOPE.with(|cell| cell.borrow().clone())
}

pub fn append_row_id_expr_if_present(df: &DataFrame, exprs: &mut Vec<Expr>) {
    let row_id_exprs: Vec<Expr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(
                qualifier.cloned(),
                ROW_ID_COL_NAME,
            )))
        })
        .collect();
    if row_id_exprs.is_empty() {
        return;
    }
    let mut qualified: Vec<Expr> = row_id_exprs
        .iter()
        .filter(|&expr| matches!(expr, Expr::Column(col) if col.relation.is_some()))
        .cloned()
        .collect();
    let row_expr = if !qualified.is_empty() {
        qualified.remove(0)
    } else if row_id_exprs.len() == 1 {
        row_id_exprs[0].clone()
    } else {
        return;
    };

    let row_col = match &row_expr {
        Expr::Column(col) => col,
        _ => return,
    };
    let already_present = exprs.iter().any(|expr| match expr {
        Expr::Column(col) => col.name == row_col.name && col.relation == row_col.relation,
        _ => false,
    });
    if already_present {
        return;
    }
    let insert_pos = exprs.iter().position(|expr| match expr {
        Expr::Column(col) => col.name == arithmetic::ACTIVATOR_COL_NAME,
        _ => false,
    });
    if let Some(pos) = insert_pos {
        exprs.insert(pos, row_expr);
        return;
    }
    exprs.push(row_expr);
}

pub fn append_activator_exprs_if_present(df: &DataFrame, exprs: &mut Vec<Expr>) {
    let activator_exprs: Vec<Expr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != arithmetic::ACTIVATOR_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(
                qualifier.cloned(),
                arithmetic::ACTIVATOR_COL_NAME,
            )))
        })
        .collect();
    if activator_exprs.is_empty() {
        return;
    }
    let mut to_insert = Vec::new();
    for activator_expr in activator_exprs {
        let activator_col = match &activator_expr {
            Expr::Column(col) => col,
            _ => continue,
        };
        let already_present = exprs.iter().any(|expr| match expr {
            Expr::Column(col) => {
                col.name == activator_col.name && col.relation == activator_col.relation
            }
            _ => false,
        });
        if !already_present {
            to_insert.push(activator_expr);
        }
    }
    if to_insert.is_empty() {
        return;
    }
    exprs.extend(to_insert);
}

pub fn strip_row_id_from_hint(hint: &HintDF) -> HintDF {
    let df = hint.data_frame().clone();
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    if !has_row_id {
        return hint.clone();
    }

    // Row-id is only for deterministic ordering, so drop it before storing payloads.
    let projected: Vec<Expr> = df
        .schema()
        .fields()
        .iter()
        .filter_map(|field| (field.name() != ROW_ID_COL_NAME).then_some(col(field.name())))
        .collect();
    let projected_df = df
        .select(projected)
        .expect("row-id projection should succeed");

    let mut by_name: HashMap<&str, bool> = HashMap::new();
    for (field, materialized) in hint.field_materialization_iter() {
        by_name.entry(field.name()).or_insert(*materialized);
    }

    let mut should_materialize = IndexMap::new();
    for field in projected_df.schema().fields() {
        let materialized = by_name.get(field.name().as_str()).copied().unwrap_or(true);
        should_materialize.insert(field.clone(), materialized);
    }

    HintDF::new(projected_df, should_materialize)
}

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";
const CONSTRAINTS_FILE_NAME: &str = "constraints.json";
const PK_METADATA_KEY: &str = "tt.pk";
const FK_REF_TABLE_METADATA_KEY: &str = "tt.fk.ref_table";
const FK_REF_COLUMNS_METADATA_KEY: &str = "tt.fk.ref_columns";

static CONSTRAINTS_BY_TABLE: OnceLock<RwLock<BTreeMap<String, TableConstraint>>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct ConstraintManifest {
    tables: Vec<TableConstraintSpec>,
}

#[derive(Debug, Deserialize)]
struct TableConstraintSpec {
    table: String,
    #[serde(default)]
    primary_key: Vec<String>,
    #[serde(default)]
    foreign_keys: Vec<ForeignKeySpec>,
}

#[derive(Debug, Deserialize)]
struct ForeignKeySpec {
    columns: Vec<String>,
    ref_table: String,
    ref_columns: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct TableConstraint {
    primary_key_cols: BTreeSet<String>,
    foreign_key_by_col: BTreeMap<String, ForeignKeyColConstraint>,
}

#[derive(Clone, Debug)]
struct ForeignKeyColConstraint {
    ref_table: String,
    ref_columns: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ColumnConstraintMetadata {
    pub is_pk: bool,
    pub fk_ref_table: Option<String>,
    pub fk_ref_columns: Vec<String>,
}

pub fn column_constraint_metadata(
    table_name: &str,
    column_name: &str,
) -> Option<ColumnConstraintMetadata> {
    let lock = CONSTRAINTS_BY_TABLE.get()?;
    let guard = lock.read().ok()?;
    let table_key = table_name_from_qualifier(table_name);
    let table = guard.get(&table_key)?;
    let column_key = column_name.to_lowercase();

    let is_pk = table.primary_key_cols.contains(&column_key);
    let (fk_ref_table, fk_ref_columns) = table
        .foreign_key_by_col
        .get(&column_key)
        .map(|fk| (Some(fk.ref_table.clone()), fk.ref_columns.clone()))
        .unwrap_or((None, Vec::new()));

    Some(ColumnConstraintMetadata {
        is_pk,
        fk_ref_table,
        fk_ref_columns,
    })
}

pub fn configure_constraint_metadata_from_parquet_paths(parquet_paths: &[PathBuf]) {
    let mut merged = BTreeMap::new();
    for parquet_path in parquet_paths {
        let Some(dir) = parquet_path.parent() else {
            continue;
        };
        merge_constraints_from_dir(dir, &mut merged);
    }
    let lock = CONSTRAINTS_BY_TABLE.get_or_init(|| RwLock::new(BTreeMap::new()));
    if let Ok(mut guard) = lock.write() {
        *guard = merged;
    }
}

fn field_with_qualifier_metadata(field: &FieldRef, qualifier: Option<&TableReference>) -> FieldRef {
    let mut updated = field.as_ref().clone();
    if updated.name() == arithmetic::ACTIVATOR_COL_NAME
        || updated.name() == arithmetic::ROW_ID_COL_NAME
    {
        return Arc::new(updated);
    }
    if let Some(qualifier) = qualifier {
        let mut metadata = updated.metadata().clone();
        let qualifier_str = qualifier.to_string();
        metadata.insert(QUALIFIER_METADATA_KEY.to_string(), qualifier_str.clone());
        apply_constraint_metadata(
            &mut metadata,
            &table_name_from_qualifier(&qualifier_str),
            updated.name(),
        );
        updated = updated.with_metadata(metadata);
    }
    Arc::new(updated)
}

fn merge_constraints_from_dir(dir: &Path, out: &mut BTreeMap<String, TableConstraint>) {
    let path = dir.join(CONSTRAINTS_FILE_NAME);
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(manifest) = serde_json::from_str::<ConstraintManifest>(&raw) else {
        return;
    };

    for table in manifest.tables {
        let key = table.table.to_lowercase();
        let mut constraint = TableConstraint {
            primary_key_cols: table
                .primary_key
                .into_iter()
                .map(|c| c.to_lowercase())
                .collect(),
            foreign_key_by_col: BTreeMap::new(),
        };

        for fk in table.foreign_keys {
            if fk.columns.is_empty() {
                continue;
            }
            for (idx, src_col) in fk.columns.iter().enumerate() {
                let ref_col = fk
                    .ref_columns
                    .get(idx)
                    .cloned()
                    .or_else(|| fk.ref_columns.first().cloned())
                    .into_iter()
                    .collect::<Vec<_>>();
                constraint.foreign_key_by_col.insert(
                    src_col.to_lowercase(),
                    ForeignKeyColConstraint {
                        ref_table: fk.ref_table.clone(),
                        ref_columns: ref_col,
                    },
                );
            }
        }

        out.insert(key, constraint);
    }
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

fn apply_constraint_metadata(
    metadata: &mut HashMap<String, String>,
    table_name: &str,
    column_name: &str,
) {
    let Some(lock) = CONSTRAINTS_BY_TABLE.get() else {
        return;
    };
    let Ok(guard) = lock.read() else {
        return;
    };
    let Some(table) = guard.get(table_name) else {
        return;
    };
    let column_key = column_name.to_lowercase();

    if table.primary_key_cols.contains(&column_key) {
        metadata.insert(PK_METADATA_KEY.to_string(), "true".to_string());
    }
    if let Some(fk) = table.foreign_key_by_col.get(&column_key) {
        metadata.insert(FK_REF_TABLE_METADATA_KEY.to_string(), fk.ref_table.clone());
        if let Ok(serialized) = serde_json::to_string(&fk.ref_columns) {
            metadata.insert(FK_REF_COLUMNS_METADATA_KEY.to_string(), serialized);
        }
    }
}

fn normalize_hint_df(
    data_fram: DataFrame,
    should_materialize: IndexMap<FieldRef, bool>,
) -> (DataFrame, IndexMap<FieldRef, bool>) {
    let schema = data_fram.schema();
    let original_fields: Vec<FieldRef> = schema.fields().iter().cloned().collect();
    let projection: Vec<Expr> = schema
        .iter()
        .map(|(qualifier, field)| {
            let col_expr = if let Some(qualifier) = qualifier {
                Expr::Column(Column::new(Some(qualifier.clone()), field.name()))
            } else {
                Expr::Column(Column::new_unqualified(field.name()))
            };
            let cast_expr = try_cast(col_expr, field.data_type().clone());
            Expr::Alias(Alias::new(cast_expr, qualifier.cloned(), field.name()))
        })
        .collect();

    let already_normalized = match data_fram.logical_plan() {
        // A normalized HintDF is exactly the projection we build above.
        // If it already matches, avoid re-projecting/casting.
        LogicalPlan::Projection(proj) => proj.expr == projection,
        _ => false,
    };

    let normalized_df = if already_normalized {
        data_fram
    } else {
        data_fram
            .select(projection)
            .expect("hint dataframe normalization should succeed")
    };

    let mut normalized_should_materialize = IndexMap::new();
    for (idx, (qualifier, field)) in normalized_df.schema().iter().enumerate() {
        let original_field = &original_fields[idx];
        let should = should_materialize
            .get(original_field)
            .copied()
            .unwrap_or(true);
        let qualified_field = field_with_qualifier_metadata(field, qualifier);
        normalized_should_materialize.insert(qualified_field, should);
    }

    (normalized_df, normalized_should_materialize)
}
