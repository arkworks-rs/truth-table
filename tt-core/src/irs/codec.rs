use std::{any::Any, sync::Arc};

use ark_piop::SnarkBackend;
use ark_serialize::SerializationError;
use datafusion::arrow::array::types::{IntervalDayTime, IntervalMonthDayNano};
use datafusion::arrow::datatypes::{DataType, Field, Schema, i256};
use datafusion::datasource::{empty::EmptyTable, provider_as_source};
use datafusion::execution::FunctionRegistry;
use datafusion::prelude::SessionContext;
use datafusion_common::{
    Column, DFSchemaRef, JoinConstraint, JoinType, ScalarValue, TableReference,
};
use datafusion_expr::expr::{
    AggregateFunction, Alias, Between, BinaryExpr, Case, Cast, InList, InSubquery, ScalarFunction,
    Sort as SortExpr,
};
use datafusion_expr::logical_plan::builder::build_join_schema;
use datafusion_expr::logical_plan::{
    Aggregate, Filter, Join, Limit, Projection, Sort, Subquery, SubqueryAlias, TableScan,
};
use datafusion_expr::{Expr, LogicalPlan, Operator};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::errors::{TTError, TTResult};
use crate::irs::nodes::gadget::lps::join as gadget_join;
use crate::irs::nodes::plan::{rematerialize, result_check};
use crate::irs::nodes::{IsNode, Node, PlanNode};
use crate::irs::shared_ir::EmptyIr;
use crate::irs::tree::Tree;

#[derive(Serialize, Deserialize)]
enum LogicalPlanRepr {
    TableScan {
        table_name: String,
        schema: SchemaRepr,
        projection: Option<Vec<usize>>,
        filters: Vec<ExprRepr>,
        fetch: Option<usize>,
    },
    Projection {
        expr: Vec<ExprRepr>,
        input: Box<LogicalPlanRepr>,
    },
    Filter {
        predicate: ExprRepr,
        input: Box<LogicalPlanRepr>,
        having: bool,
    },
    Aggregate {
        group_expr: Vec<ExprRepr>,
        aggr_expr: Vec<ExprRepr>,
        input: Box<LogicalPlanRepr>,
    },
    Sort {
        expr: Vec<SortRepr>,
        input: Box<LogicalPlanRepr>,
        fetch: Option<usize>,
    },
    Join {
        left: Box<LogicalPlanRepr>,
        right: Box<LogicalPlanRepr>,
        on: Vec<(ExprRepr, ExprRepr)>,
        filter: Option<ExprRepr>,
        join_type: JoinTypeRepr,
        join_constraint: JoinConstraintRepr,
        null_equals_null: bool,
    },
    SubqueryAlias {
        input: Box<LogicalPlanRepr>,
        alias: String,
    },
    Limit {
        input: Box<LogicalPlanRepr>,
        skip: Option<ExprRepr>,
        fetch: Option<ExprRepr>,
    },
    ExtensionRematerialize {
        input: Box<LogicalPlanRepr>,
    },
    ExtensionResultCheck {
        input: Box<LogicalPlanRepr>,
    },
}

#[derive(Serialize, Deserialize)]
struct ColumnRepr {
    relation: Option<String>,
    name: String,
}

impl SchemaRepr {
    fn from_schema(schema: &Schema) -> TTResult<Self> {
        Ok(SchemaRepr {
            fields: schema
                .fields()
                .iter()
                .map(|field| FieldRepr::from_field(field))
                .collect::<TTResult<_>>()?,
            metadata: schema
                .metadata()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    fn to_schema(&self) -> TTResult<Schema> {
        let fields = self
            .fields
            .iter()
            .map(|field| field.to_field())
            .collect::<TTResult<Vec<_>>>()?;
        let metadata = self.metadata.iter().cloned().collect();
        Ok(Schema::new_with_metadata(fields, metadata))
    }
}

impl FieldRepr {
    fn from_field(field: &Field) -> TTResult<Self> {
        Ok(FieldRepr {
            name: field.name().to_string(),
            data_type: DataTypeRepr::from_data_type(field.data_type())?,
            nullable: field.is_nullable(),
            metadata: field
                .metadata()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    fn to_field(&self) -> TTResult<Field> {
        let data_type = self.data_type.to_data_type()?;
        let mut field = Field::new(self.name.clone(), data_type, self.nullable);
        if !self.metadata.is_empty() {
            let metadata = self.metadata.iter().cloned().collect();
            field = field.with_metadata(metadata);
        }
        Ok(field)
    }
}

impl DataTypeRepr {
    fn from_data_type(data_type: &DataType) -> TTResult<Self> {
        use datafusion::arrow::datatypes::TimeUnit;

        Ok(match data_type {
            DataType::Null => DataTypeRepr::Null,
            DataType::Boolean => DataTypeRepr::Boolean,
            DataType::Int8 => DataTypeRepr::Int8,
            DataType::Int16 => DataTypeRepr::Int16,
            DataType::Int32 => DataTypeRepr::Int32,
            DataType::Int64 => DataTypeRepr::Int64,
            DataType::UInt8 => DataTypeRepr::UInt8,
            DataType::UInt16 => DataTypeRepr::UInt16,
            DataType::UInt32 => DataTypeRepr::UInt32,
            DataType::UInt64 => DataTypeRepr::UInt64,
            DataType::Float32 => DataTypeRepr::Float32,
            DataType::Float64 => DataTypeRepr::Float64,
            DataType::Decimal128(precision, scale) => DataTypeRepr::Decimal128 {
                precision: *precision,
                scale: *scale,
            },
            DataType::Decimal256(precision, scale) => DataTypeRepr::Decimal256 {
                precision: *precision,
                scale: *scale,
            },
            DataType::Utf8 => DataTypeRepr::Utf8,
            DataType::Utf8View => DataTypeRepr::Utf8View,
            DataType::LargeUtf8 => DataTypeRepr::LargeUtf8,
            DataType::Binary => DataTypeRepr::Binary,
            DataType::LargeBinary => DataTypeRepr::LargeBinary,
            DataType::FixedSizeBinary(size) => DataTypeRepr::FixedSizeBinary(*size),
            DataType::Date32 => DataTypeRepr::Date32,
            DataType::Date64 => DataTypeRepr::Date64,
            DataType::Time32(TimeUnit::Second) => DataTypeRepr::Time32Second,
            DataType::Time32(TimeUnit::Millisecond) => DataTypeRepr::Time32Millisecond,
            DataType::Time64(TimeUnit::Microsecond) => DataTypeRepr::Time64Microsecond,
            DataType::Time64(TimeUnit::Nanosecond) => DataTypeRepr::Time64Nanosecond,
            DataType::Timestamp(unit, tz) => DataTypeRepr::Timestamp {
                unit: format!("{unit:?}"),
                timezone: tz.as_ref().map(|v| v.to_string()),
            },
            DataType::Duration(unit) => DataTypeRepr::Duration {
                unit: format!("{unit:?}"),
            },
            DataType::Interval(unit) => DataTypeRepr::Interval {
                unit: format!("{unit:?}"),
            },
            DataType::List(field) => DataTypeRepr::List(Box::new(FieldRepr::from_field(field)?)),
            DataType::LargeList(field) => {
                DataTypeRepr::LargeList(Box::new(FieldRepr::from_field(field)?))
            }
            DataType::FixedSizeList(field, size) => {
                DataTypeRepr::FixedSizeList(Box::new(FieldRepr::from_field(field)?), *size)
            }
            DataType::Struct(fields) => DataTypeRepr::Struct(
                fields
                    .iter()
                    .map(|field| FieldRepr::from_field(field.as_ref()))
                    .collect::<TTResult<_>>()?,
            ),
            other => {
                debug!(?other, "TTProof serialize: unsupported DataType");
                return serialization_error();
            }
        })
    }

    fn to_data_type(&self) -> TTResult<DataType> {
        use datafusion::arrow::datatypes::{IntervalUnit, TimeUnit};

        Ok(match self {
            DataTypeRepr::Null => DataType::Null,
            DataTypeRepr::Boolean => DataType::Boolean,
            DataTypeRepr::Int8 => DataType::Int8,
            DataTypeRepr::Int16 => DataType::Int16,
            DataTypeRepr::Int32 => DataType::Int32,
            DataTypeRepr::Int64 => DataType::Int64,
            DataTypeRepr::UInt8 => DataType::UInt8,
            DataTypeRepr::UInt16 => DataType::UInt16,
            DataTypeRepr::UInt32 => DataType::UInt32,
            DataTypeRepr::UInt64 => DataType::UInt64,
            DataTypeRepr::Float32 => DataType::Float32,
            DataTypeRepr::Float64 => DataType::Float64,
            DataTypeRepr::Decimal128 { precision, scale } => {
                DataType::Decimal128(*precision, *scale)
            }
            DataTypeRepr::Decimal256 { precision, scale } => {
                DataType::Decimal256(*precision, *scale)
            }
            DataTypeRepr::Utf8 => DataType::Utf8,
            DataTypeRepr::Utf8View => DataType::Utf8View,
            DataTypeRepr::LargeUtf8 => DataType::LargeUtf8,
            DataTypeRepr::Binary => DataType::Binary,
            DataTypeRepr::LargeBinary => DataType::LargeBinary,
            DataTypeRepr::FixedSizeBinary(size) => DataType::FixedSizeBinary(*size),
            DataTypeRepr::Date32 => DataType::Date32,
            DataTypeRepr::Date64 => DataType::Date64,
            DataTypeRepr::Time32Second => DataType::Time32(TimeUnit::Second),
            DataTypeRepr::Time32Millisecond => DataType::Time32(TimeUnit::Millisecond),
            DataTypeRepr::Time64Microsecond => DataType::Time64(TimeUnit::Microsecond),
            DataTypeRepr::Time64Nanosecond => DataType::Time64(TimeUnit::Nanosecond),
            DataTypeRepr::Timestamp { unit, timezone } => {
                let unit = match unit.as_str() {
                    "Second" => TimeUnit::Second,
                    "Millisecond" => TimeUnit::Millisecond,
                    "Microsecond" => TimeUnit::Microsecond,
                    "Nanosecond" => TimeUnit::Nanosecond,
                    _ => return serialization_error(),
                };
                DataType::Timestamp(unit, timezone.as_ref().map(|tz| tz.as_str().into()))
            }
            DataTypeRepr::Duration { unit } => {
                let unit = match unit.as_str() {
                    "Second" => TimeUnit::Second,
                    "Millisecond" => TimeUnit::Millisecond,
                    "Microsecond" => TimeUnit::Microsecond,
                    "Nanosecond" => TimeUnit::Nanosecond,
                    _ => return serialization_error(),
                };
                DataType::Duration(unit)
            }
            DataTypeRepr::Interval { unit } => {
                let unit = match unit.as_str() {
                    "YearMonth" => IntervalUnit::YearMonth,
                    "DayTime" => IntervalUnit::DayTime,
                    "MonthDayNano" => IntervalUnit::MonthDayNano,
                    _ => return serialization_error(),
                };
                DataType::Interval(unit)
            }
            DataTypeRepr::List(field) => DataType::List(Arc::new(field.to_field()?)),
            DataTypeRepr::LargeList(field) => DataType::LargeList(Arc::new(field.to_field()?)),
            DataTypeRepr::FixedSizeList(field, size) => {
                DataType::FixedSizeList(Arc::new(field.to_field()?), *size)
            }
            DataTypeRepr::Struct(fields) => DataType::Struct(
                fields
                    .iter()
                    .map(|field| field.to_field())
                    .collect::<TTResult<Vec<_>>>()?
                    .into(),
            ),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SchemaRepr {
    fields: Vec<FieldRepr>,
    metadata: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
struct FieldRepr {
    name: String,
    data_type: DataTypeRepr,
    nullable: bool,
    metadata: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
enum DataTypeRepr {
    Null,
    Boolean,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float32,
    Float64,
    Decimal128 {
        precision: u8,
        scale: i8,
    },
    Decimal256 {
        precision: u8,
        scale: i8,
    },
    Utf8,
    Utf8View,
    LargeUtf8,
    Binary,
    LargeBinary,
    FixedSizeBinary(i32),
    Date32,
    Date64,
    Time32Second,
    Time32Millisecond,
    Time64Microsecond,
    Time64Nanosecond,
    Timestamp {
        unit: String,
        timezone: Option<String>,
    },
    Duration {
        unit: String,
    },
    Interval {
        unit: String,
    },
    List(Box<FieldRepr>),
    LargeList(Box<FieldRepr>),
    FixedSizeList(Box<FieldRepr>, i32),
    Struct(Vec<FieldRepr>),
}

#[derive(Serialize, Deserialize)]
struct SortRepr {
    expr: ExprRepr,
    asc: bool,
    nulls_first: bool,
}

#[derive(Serialize, Deserialize)]
struct SubqueryRepr {
    subquery: Box<LogicalPlanRepr>,
    outer_ref_columns: Vec<ExprRepr>,
}

#[derive(Serialize, Deserialize)]
enum ExprRepr {
    Column(ColumnRepr),
    Literal(ScalarValueRepr),
    BinaryExpr {
        left: Box<ExprRepr>,
        op: OperatorRepr,
        right: Box<ExprRepr>,
    },
    Cast {
        expr: Box<ExprRepr>,
        data_type: DataTypeRepr,
    },
    Alias {
        expr: Box<ExprRepr>,
        relation: Option<String>,
        name: String,
    },
    AggregateFunction {
        func: String,
        args: Vec<ExprRepr>,
        distinct: bool,
        filter: Option<Box<ExprRepr>>,
        order_by: Option<Vec<SortRepr>>,
    },
    Between {
        expr: Box<ExprRepr>,
        negated: bool,
        low: Box<ExprRepr>,
        high: Box<ExprRepr>,
    },
    InList {
        expr: Box<ExprRepr>,
        list: Vec<ExprRepr>,
        negated: bool,
    },
    ScalarFunction {
        func: String,
        args: Vec<ExprRepr>,
    },
    InSubquery {
        expr: Box<ExprRepr>,
        subquery: SubqueryRepr,
        negated: bool,
    },
    Case {
        expr: Option<Box<ExprRepr>>,
        when_then: Vec<(ExprRepr, ExprRepr)>,
        else_expr: Option<Box<ExprRepr>>,
    },
}

#[derive(Serialize, Deserialize)]
enum ScalarValueRepr {
    Null,
    Boolean(Option<bool>),
    Float32(Option<f32>),
    Float64(Option<f64>),
    Decimal128(Option<i128>, u8, i8),
    Decimal256(Option<String>, u8, i8),
    Int8(Option<i8>),
    Int16(Option<i16>),
    Int32(Option<i32>),
    Int64(Option<i64>),
    UInt8(Option<u8>),
    UInt16(Option<u16>),
    UInt32(Option<u32>),
    UInt64(Option<u64>),
    Utf8(Option<String>),
    Utf8View(Option<String>),
    LargeUtf8(Option<String>),
    Binary(Option<Vec<u8>>),
    BinaryView(Option<Vec<u8>>),
    FixedSizeBinary(i32, Option<Vec<u8>>),
    LargeBinary(Option<Vec<u8>>),
    Date32(Option<i32>),
    Date64(Option<i64>),
    Time32Second(Option<i32>),
    Time32Millisecond(Option<i32>),
    Time64Microsecond(Option<i64>),
    Time64Nanosecond(Option<i64>),
    TimestampSecond(Option<i64>, Option<String>),
    TimestampMillisecond(Option<i64>, Option<String>),
    TimestampMicrosecond(Option<i64>, Option<String>),
    TimestampNanosecond(Option<i64>, Option<String>),
    IntervalYearMonth(Option<i32>),
    IntervalDayTime(Option<(i32, i32)>),
    IntervalMonthDayNano(Option<(i32, i32, i64)>),
    DurationSecond(Option<i64>),
    DurationMillisecond(Option<i64>),
    DurationMicrosecond(Option<i64>),
    DurationNanosecond(Option<i64>),
}

#[derive(Serialize, Deserialize)]
enum OperatorRepr {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    And,
    Or,
    IsDistinctFrom,
    IsNotDistinctFrom,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    BitwiseShiftRight,
    BitwiseShiftLeft,
    RegexMatch,
    RegexIMatch,
    RegexNotMatch,
    RegexNotIMatch,
    LikeMatch,
    ILikeMatch,
    NotLikeMatch,
    NotILikeMatch,
    StringConcat,
    AtArrow,
    ArrowAt,
}

#[derive(Serialize, Deserialize)]
enum JoinTypeRepr {
    Inner,
    Left,
    Right,
    Full,
    LeftSemi,
    RightSemi,
    LeftAnti,
    RightAnti,
    LeftMark,
}

#[derive(Serialize, Deserialize)]
enum JoinConstraintRepr {
    On,
    Using,
}

#[derive(Serialize, Deserialize)]
enum JoinModeRepr {
    OneToMany,
    ManyToOne,
    OneToOne,
    ManyToMany,
}

impl JoinModeRepr {
    fn from_join_mode(mode: gadget_join::JoinMode) -> Self {
        match mode {
            gadget_join::JoinMode::ONE_TO_MANY => JoinModeRepr::OneToMany,
            gadget_join::JoinMode::MANY_TO_ONE => JoinModeRepr::ManyToOne,
            gadget_join::JoinMode::ONE_TO_ONE => JoinModeRepr::OneToOne,
            gadget_join::JoinMode::MANY_TO_MANY => JoinModeRepr::ManyToMany,
        }
    }

    fn to_join_mode(&self) -> gadget_join::JoinMode {
        match self {
            JoinModeRepr::OneToMany => gadget_join::JoinMode::ONE_TO_MANY,
            JoinModeRepr::ManyToOne => gadget_join::JoinMode::MANY_TO_ONE,
            JoinModeRepr::OneToOne => gadget_join::JoinMode::ONE_TO_ONE,
            JoinModeRepr::ManyToMany => gadget_join::JoinMode::MANY_TO_MANY,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TreeRepr {
    plan: LogicalPlanRepr,
    // Keep join gadget mode stable across proof serialization so verifier and prover
    // use the same join gadget shape.
    #[serde(default)]
    join_modes: Vec<JoinModeRepr>,
}

fn serialization_error<T>() -> TTResult<T> {
    Err(TTError::Serialization(SerializationError::InvalidData))
}

impl LogicalPlanRepr {
    fn from_plan(plan: &LogicalPlan) -> TTResult<Self> {
        Ok(match plan {
            LogicalPlan::TableScan(ts) => LogicalPlanRepr::TableScan {
                table_name: ts.table_name.to_string(),
                schema: SchemaRepr::from_schema(ts.source.schema().as_ref())?,
                projection: ts.projection.clone(),
                filters: ts
                    .filters
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
                fetch: ts.fetch,
            },
            LogicalPlan::Projection(proj) => LogicalPlanRepr::Projection {
                expr: proj
                    .expr
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
                input: Box::new(LogicalPlanRepr::from_plan(proj.input.as_ref())?),
            },
            LogicalPlan::Filter(filter) => LogicalPlanRepr::Filter {
                predicate: ExprRepr::from_expr(&filter.predicate)?,
                input: Box::new(LogicalPlanRepr::from_plan(filter.input.as_ref())?),
                having: filter.having,
            },
            LogicalPlan::Aggregate(agg) => LogicalPlanRepr::Aggregate {
                group_expr: agg
                    .group_expr
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
                aggr_expr: agg
                    .aggr_expr
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
                input: Box::new(LogicalPlanRepr::from_plan(agg.input.as_ref())?),
            },
            LogicalPlan::Sort(sort) => LogicalPlanRepr::Sort {
                expr: sort
                    .expr
                    .iter()
                    .map(SortRepr::from_sort)
                    .collect::<TTResult<_>>()?,
                input: Box::new(LogicalPlanRepr::from_plan(sort.input.as_ref())?),
                fetch: sort.fetch,
            },
            LogicalPlan::Join(join) => LogicalPlanRepr::Join {
                left: Box::new(LogicalPlanRepr::from_plan(join.left.as_ref())?),
                right: Box::new(LogicalPlanRepr::from_plan(join.right.as_ref())?),
                on: join
                    .on
                    .iter()
                    .map(|(l, r)| Ok((ExprRepr::from_expr(l)?, ExprRepr::from_expr(r)?)))
                    .collect::<TTResult<_>>()?,
                filter: match join.filter.as_ref() {
                    Some(filter) => Some(ExprRepr::from_expr(filter)?),
                    None => None,
                },
                join_type: JoinTypeRepr::from_join_type(join.join_type),
                join_constraint: JoinConstraintRepr::from_constraint(join.join_constraint),
                null_equals_null: join.null_equals_null,
            },
            LogicalPlan::SubqueryAlias(alias) => LogicalPlanRepr::SubqueryAlias {
                input: Box::new(LogicalPlanRepr::from_plan(alias.input.as_ref())?),
                alias: alias.alias.to_string(),
            },
            LogicalPlan::Limit(limit) => LogicalPlanRepr::Limit {
                input: Box::new(LogicalPlanRepr::from_plan(limit.input.as_ref())?),
                skip: match limit.skip.as_deref() {
                    Some(expr) => Some(ExprRepr::from_expr(expr)?),
                    None => None,
                },
                fetch: match limit.fetch.as_deref() {
                    Some(expr) => Some(ExprRepr::from_expr(expr)?),
                    None => None,
                },
            },
            LogicalPlan::Extension(extension) => {
                if let Some(remat) = extension
                    .node
                    .as_any()
                    .downcast_ref::<rematerialize::RematerializeLogicalNode>()
                {
                    LogicalPlanRepr::ExtensionRematerialize {
                        input: Box::new(LogicalPlanRepr::from_plan(remat.input())?),
                    }
                } else if let Some(result_check) = extension
                    .node
                    .as_any()
                    .downcast_ref::<result_check::ResultCheckLogicalNode>(
                ) {
                    LogicalPlanRepr::ExtensionResultCheck {
                        input: Box::new(LogicalPlanRepr::from_plan(result_check.input())?),
                    }
                } else {
                    debug!(?plan, "TTProof serialize: unsupported Extension node");
                    return serialization_error();
                }
            }
            _ => {
                debug!(?plan, "TTProof serialize: unsupported LogicalPlan variant");
                return serialization_error();
            }
        })
    }

    fn to_plan(&self, ctx: &SessionContext) -> TTResult<LogicalPlan> {
        match self {
            LogicalPlanRepr::TableScan {
                table_name,
                schema,
                projection,
                filters,
                fetch,
            } => {
                let schema_ref = Arc::new(schema.to_schema()?);
                let table = EmptyTable::new(schema_ref);
                let source = provider_as_source(Arc::new(table));
                let filters = filters
                    .iter()
                    .map(|expr| expr.to_expr(ctx))
                    .collect::<TTResult<Vec<_>>>()?;
                let scan = TableScan::try_new(
                    table_name.clone(),
                    source,
                    projection.clone(),
                    filters,
                    *fetch,
                )?;
                Ok(LogicalPlan::TableScan(scan))
            }
            LogicalPlanRepr::Projection { expr, input } => {
                let input_plan = Arc::new(input.to_plan(ctx)?);
                let exprs = expr
                    .iter()
                    .map(|expr| expr.to_expr(ctx))
                    .collect::<TTResult<Vec<_>>>()?;
                let proj = Projection::try_new(exprs, input_plan)?;
                Ok(LogicalPlan::Projection(proj))
            }
            LogicalPlanRepr::Filter {
                predicate,
                input,
                having,
            } => {
                let input_plan = Arc::new(input.to_plan(ctx)?);
                let predicate = predicate.to_expr(ctx)?;
                let filter = if *having {
                    Filter::try_new_with_having(predicate, input_plan)?
                } else {
                    Filter::try_new(predicate, input_plan)?
                };
                Ok(LogicalPlan::Filter(filter))
            }
            LogicalPlanRepr::Aggregate {
                group_expr,
                aggr_expr,
                input,
            } => {
                let input_plan = Arc::new(input.to_plan(ctx)?);
                let group_expr = group_expr
                    .iter()
                    .map(|expr| expr.to_expr(ctx))
                    .collect::<TTResult<Vec<_>>>()?;
                let aggr_expr = aggr_expr
                    .iter()
                    .map(|expr| expr.to_expr(ctx))
                    .collect::<TTResult<Vec<_>>>()?;
                let agg = Aggregate::try_new(input_plan, group_expr, aggr_expr)?;
                Ok(LogicalPlan::Aggregate(agg))
            }
            LogicalPlanRepr::Sort { expr, input, fetch } => {
                let input_plan = Arc::new(input.to_plan(ctx)?);
                let expr = expr
                    .iter()
                    .map(|sort| sort.to_sort(ctx))
                    .collect::<TTResult<Vec<_>>>()?;
                Ok(LogicalPlan::Sort(Sort {
                    expr,
                    input: input_plan,
                    fetch: *fetch,
                }))
            }
            LogicalPlanRepr::Join {
                left,
                right,
                on,
                filter,
                join_type,
                join_constraint,
                null_equals_null,
            } => {
                let left_plan = Arc::new(left.to_plan(ctx)?);
                let right_plan = Arc::new(right.to_plan(ctx)?);
                let on = on
                    .iter()
                    .map(|(l, r)| Ok((l.to_expr(ctx)?, r.to_expr(ctx)?)))
                    .collect::<TTResult<Vec<_>>>()?;
                let join_type = join_type.to_join_type();
                let schema = DFSchemaRef::new(build_join_schema(
                    left_plan.schema(),
                    right_plan.schema(),
                    &join_type,
                )?);
                let join = Join {
                    left: left_plan,
                    right: right_plan,
                    on,
                    filter: match filter.as_ref() {
                        Some(expr) => Some(expr.to_expr(ctx)?),
                        None => None,
                    },
                    join_type,
                    join_constraint: join_constraint.to_join_constraint(),
                    schema,
                    null_equals_null: *null_equals_null,
                };
                Ok(LogicalPlan::Join(join))
            }
            LogicalPlanRepr::SubqueryAlias { input, alias } => {
                let input_plan = Arc::new(input.to_plan(ctx)?);
                let alias = TableReference::from(alias.clone());
                let alias = SubqueryAlias::try_new(input_plan, alias)?;
                Ok(LogicalPlan::SubqueryAlias(alias))
            }
            LogicalPlanRepr::Limit { input, skip, fetch } => {
                let input_plan = Arc::new(input.to_plan(ctx)?);
                let skip = match skip {
                    Some(expr) => Some(Box::new(expr.to_expr(ctx)?)),
                    None => None,
                };
                let fetch = match fetch {
                    Some(expr) => Some(Box::new(expr.to_expr(ctx)?)),
                    None => None,
                };
                Ok(LogicalPlan::Limit(Limit {
                    skip,
                    fetch,
                    input: input_plan,
                }))
            }
            LogicalPlanRepr::ExtensionRematerialize { input } => {
                let input_plan = input.to_plan(ctx)?;
                Ok(rematerialize::wrap_logical_plan(input_plan))
            }
            LogicalPlanRepr::ExtensionResultCheck { input } => {
                let input_plan = input.to_plan(ctx)?;
                Ok(result_check::wrap_logical_plan(input_plan))
            }
        }
    }
}

impl ColumnRepr {
    fn from_column(column: &Column) -> Self {
        ColumnRepr {
            relation: column.relation.as_ref().map(|r| r.to_string()),
            name: column.name.clone(),
        }
    }

    fn to_column(&self) -> Column {
        Column::new(
            self.relation
                .as_ref()
                .map(|r| TableReference::from(r.clone())),
            self.name.clone(),
        )
    }
}

impl SortRepr {
    fn from_sort(sort: &SortExpr) -> TTResult<Self> {
        Ok(SortRepr {
            expr: ExprRepr::from_expr(&sort.expr)?,
            asc: sort.asc,
            nulls_first: sort.nulls_first,
        })
    }

    fn to_sort(&self, ctx: &SessionContext) -> TTResult<SortExpr> {
        Ok(SortExpr::new(
            self.expr.to_expr(ctx)?,
            self.asc,
            self.nulls_first,
        ))
    }
}

impl SubqueryRepr {
    fn from_subquery(subquery: &Subquery) -> TTResult<Self> {
        Ok(SubqueryRepr {
            subquery: Box::new(LogicalPlanRepr::from_plan(subquery.subquery.as_ref())?),
            outer_ref_columns: subquery
                .outer_ref_columns
                .iter()
                .map(ExprRepr::from_expr)
                .collect::<TTResult<_>>()?,
        })
    }

    fn to_subquery(&self, ctx: &SessionContext) -> TTResult<Subquery> {
        Ok(Subquery {
            subquery: Arc::new(self.subquery.to_plan(ctx)?),
            outer_ref_columns: self
                .outer_ref_columns
                .iter()
                .map(|expr| expr.to_expr(ctx))
                .collect::<TTResult<Vec<_>>>()?,
        })
    }
}

impl ExprRepr {
    fn from_expr(expr: &Expr) -> TTResult<Self> {
        Ok(match expr {
            Expr::Column(column) => ExprRepr::Column(ColumnRepr::from_column(column)),
            Expr::Literal(value) => ExprRepr::Literal(ScalarValueRepr::from_value(value)?),
            Expr::BinaryExpr(binary) => ExprRepr::BinaryExpr {
                left: Box::new(ExprRepr::from_expr(binary.left.as_ref())?),
                op: OperatorRepr::from_operator(binary.op),
                right: Box::new(ExprRepr::from_expr(binary.right.as_ref())?),
            },
            Expr::Cast(cast) => ExprRepr::Cast {
                expr: Box::new(ExprRepr::from_expr(cast.expr.as_ref())?),
                data_type: DataTypeRepr::from_data_type(&cast.data_type)?,
            },
            Expr::Alias(alias) => ExprRepr::Alias {
                expr: Box::new(ExprRepr::from_expr(alias.expr.as_ref())?),
                relation: alias.relation.as_ref().map(|r| r.to_string()),
                name: alias.name.clone(),
            },
            Expr::AggregateFunction(agg) => ExprRepr::AggregateFunction {
                func: agg.func.name().to_string(),
                args: agg
                    .params
                    .args
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
                distinct: agg.params.distinct,
                filter: match agg.params.filter.as_ref() {
                    Some(expr) => Some(Box::new(ExprRepr::from_expr(expr.as_ref())?)),
                    None => None,
                },
                order_by: match agg.params.order_by.as_ref() {
                    Some(order_by) => Some(
                        order_by
                            .iter()
                            .map(SortRepr::from_sort)
                            .collect::<TTResult<_>>()?,
                    ),
                    None => None,
                },
            },
            Expr::Between(between) => ExprRepr::Between {
                expr: Box::new(ExprRepr::from_expr(between.expr.as_ref())?),
                negated: between.negated,
                low: Box::new(ExprRepr::from_expr(between.low.as_ref())?),
                high: Box::new(ExprRepr::from_expr(between.high.as_ref())?),
            },
            Expr::InList(list) => ExprRepr::InList {
                expr: Box::new(ExprRepr::from_expr(list.expr.as_ref())?),
                list: list
                    .list
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
                negated: list.negated,
            },
            Expr::ScalarFunction(func) => ExprRepr::ScalarFunction {
                func: func.func.name().to_string(),
                args: func
                    .args
                    .iter()
                    .map(ExprRepr::from_expr)
                    .collect::<TTResult<_>>()?,
            },
            Expr::InSubquery(subquery) => ExprRepr::InSubquery {
                expr: Box::new(ExprRepr::from_expr(subquery.expr.as_ref())?),
                subquery: SubqueryRepr::from_subquery(&subquery.subquery)?,
                negated: subquery.negated,
            },
            Expr::Case(case) => ExprRepr::Case {
                expr: match case.expr.as_ref() {
                    Some(expr) => Some(Box::new(ExprRepr::from_expr(expr.as_ref())?)),
                    None => None,
                },
                when_then: case
                    .when_then_expr
                    .iter()
                    .map(|(when_expr, then_expr)| {
                        Ok((
                            ExprRepr::from_expr(when_expr.as_ref())?,
                            ExprRepr::from_expr(then_expr.as_ref())?,
                        ))
                    })
                    .collect::<TTResult<_>>()?,
                else_expr: match case.else_expr.as_ref() {
                    Some(expr) => Some(Box::new(ExprRepr::from_expr(expr.as_ref())?)),
                    None => None,
                },
            },
            _ => {
                debug!(?expr, "TTProof serialize: unsupported Expr variant");
                return serialization_error();
            }
        })
    }

    fn to_expr(&self, ctx: &SessionContext) -> TTResult<Expr> {
        Ok(match self {
            ExprRepr::Column(column) => Expr::Column(column.to_column()),
            ExprRepr::Literal(value) => Expr::Literal(value.to_value()?),
            ExprRepr::BinaryExpr { left, op, right } => Expr::BinaryExpr(BinaryExpr::new(
                Box::new(left.to_expr(ctx)?),
                op.to_operator(),
                Box::new(right.to_expr(ctx)?),
            )),
            ExprRepr::Cast { expr, data_type } => Expr::Cast(Cast::new(
                Box::new(expr.to_expr(ctx)?),
                data_type.to_data_type()?,
            )),
            ExprRepr::Alias {
                expr,
                relation,
                name,
            } => Expr::Alias(Alias::new(
                expr.to_expr(ctx)?,
                relation
                    .as_ref()
                    .map(|rel| TableReference::from(rel.clone())),
                name.clone(),
            )),
            ExprRepr::AggregateFunction {
                func,
                args,
                distinct,
                filter,
                order_by,
            } => {
                let udf = ctx.udaf(func)?;
                let args = args
                    .iter()
                    .map(|expr| expr.to_expr(ctx))
                    .collect::<TTResult<Vec<_>>>()?;
                let filter = match filter {
                    Some(expr) => Some(Box::new(expr.to_expr(ctx)?)),
                    None => None,
                };
                let order_by = match order_by {
                    Some(order_by) => Some(
                        order_by
                            .iter()
                            .map(|sort| sort.to_sort(ctx))
                            .collect::<TTResult<Vec<_>>>()?,
                    ),
                    None => None,
                };
                Expr::AggregateFunction(AggregateFunction::new_udf(
                    udf, args, *distinct, filter, order_by, None,
                ))
            }
            ExprRepr::Between {
                expr,
                negated,
                low,
                high,
            } => Expr::Between(Between::new(
                Box::new(expr.to_expr(ctx)?),
                *negated,
                Box::new(low.to_expr(ctx)?),
                Box::new(high.to_expr(ctx)?),
            )),
            ExprRepr::InList {
                expr,
                list,
                negated,
            } => Expr::InList(InList::new(
                Box::new(expr.to_expr(ctx)?),
                list.iter()
                    .map(|expr| expr.to_expr(ctx))
                    .collect::<TTResult<Vec<_>>>()?,
                *negated,
            )),
            ExprRepr::ScalarFunction { func, args } => {
                let udf = ctx.udf(func)?;
                Expr::ScalarFunction(ScalarFunction::new_udf(
                    udf,
                    args.iter()
                        .map(|expr| expr.to_expr(ctx))
                        .collect::<TTResult<Vec<_>>>()?,
                ))
            }
            ExprRepr::InSubquery {
                expr,
                subquery,
                negated,
            } => {
                let subquery = subquery.to_subquery(ctx)?;
                Expr::InSubquery(InSubquery::new(
                    Box::new(expr.to_expr(ctx)?),
                    subquery,
                    *negated,
                ))
            }
            ExprRepr::Case {
                expr,
                when_then,
                else_expr,
            } => {
                let expr = match expr {
                    Some(expr) => Some(Box::new(expr.to_expr(ctx)?)),
                    None => None,
                };
                let when_then = when_then
                    .iter()
                    .map(|(when_expr, then_expr)| {
                        Ok((
                            Box::new(when_expr.to_expr(ctx)?),
                            Box::new(then_expr.to_expr(ctx)?),
                        ))
                    })
                    .collect::<TTResult<Vec<_>>>()?;
                let else_expr = match else_expr {
                    Some(expr) => Some(Box::new(expr.to_expr(ctx)?)),
                    None => None,
                };
                Expr::Case(Case::new(expr, when_then, else_expr))
            }
        })
    }
}

impl ScalarValueRepr {
    fn from_value(value: &ScalarValue) -> TTResult<Self> {
        Ok(match value {
            ScalarValue::Null => ScalarValueRepr::Null,
            ScalarValue::Boolean(value) => ScalarValueRepr::Boolean(*value),
            ScalarValue::Float32(value) => ScalarValueRepr::Float32(*value),
            ScalarValue::Float64(value) => ScalarValueRepr::Float64(*value),
            ScalarValue::Decimal128(value, precision, scale) => {
                ScalarValueRepr::Decimal128(*value, *precision, *scale)
            }
            ScalarValue::Decimal256(value, precision, scale) => {
                ScalarValueRepr::Decimal256(value.map(|v| v.to_string()), *precision, *scale)
            }
            ScalarValue::Int8(value) => ScalarValueRepr::Int8(*value),
            ScalarValue::Int16(value) => ScalarValueRepr::Int16(*value),
            ScalarValue::Int32(value) => ScalarValueRepr::Int32(*value),
            ScalarValue::Int64(value) => ScalarValueRepr::Int64(*value),
            ScalarValue::UInt8(value) => ScalarValueRepr::UInt8(*value),
            ScalarValue::UInt16(value) => ScalarValueRepr::UInt16(*value),
            ScalarValue::UInt32(value) => ScalarValueRepr::UInt32(*value),
            ScalarValue::UInt64(value) => ScalarValueRepr::UInt64(*value),
            ScalarValue::Utf8(value) => ScalarValueRepr::Utf8(value.clone()),
            ScalarValue::Utf8View(value) => ScalarValueRepr::Utf8View(value.clone()),
            ScalarValue::LargeUtf8(value) => ScalarValueRepr::LargeUtf8(value.clone()),
            ScalarValue::Binary(value) => ScalarValueRepr::Binary(value.clone()),
            ScalarValue::BinaryView(value) => ScalarValueRepr::BinaryView(value.clone()),
            ScalarValue::FixedSizeBinary(size, value) => {
                ScalarValueRepr::FixedSizeBinary(*size, value.clone())
            }
            ScalarValue::LargeBinary(value) => ScalarValueRepr::LargeBinary(value.clone()),
            ScalarValue::Date32(value) => ScalarValueRepr::Date32(*value),
            ScalarValue::Date64(value) => ScalarValueRepr::Date64(*value),
            ScalarValue::Time32Second(value) => ScalarValueRepr::Time32Second(*value),
            ScalarValue::Time32Millisecond(value) => ScalarValueRepr::Time32Millisecond(*value),
            ScalarValue::Time64Microsecond(value) => ScalarValueRepr::Time64Microsecond(*value),
            ScalarValue::Time64Nanosecond(value) => ScalarValueRepr::Time64Nanosecond(*value),
            ScalarValue::TimestampSecond(value, tz) => {
                ScalarValueRepr::TimestampSecond(*value, tz.as_ref().map(|v| v.to_string()))
            }
            ScalarValue::TimestampMillisecond(value, tz) => {
                ScalarValueRepr::TimestampMillisecond(*value, tz.as_ref().map(|v| v.to_string()))
            }
            ScalarValue::TimestampMicrosecond(value, tz) => {
                ScalarValueRepr::TimestampMicrosecond(*value, tz.as_ref().map(|v| v.to_string()))
            }
            ScalarValue::TimestampNanosecond(value, tz) => {
                ScalarValueRepr::TimestampNanosecond(*value, tz.as_ref().map(|v| v.to_string()))
            }
            ScalarValue::IntervalYearMonth(value) => ScalarValueRepr::IntervalYearMonth(*value),
            ScalarValue::IntervalDayTime(value) => {
                ScalarValueRepr::IntervalDayTime(value.map(|v| (v.days, v.milliseconds)))
            }
            ScalarValue::IntervalMonthDayNano(value) => ScalarValueRepr::IntervalMonthDayNano(
                value.map(|v| (v.months, v.days, v.nanoseconds)),
            ),
            ScalarValue::DurationSecond(value) => ScalarValueRepr::DurationSecond(*value),
            ScalarValue::DurationMillisecond(value) => ScalarValueRepr::DurationMillisecond(*value),
            ScalarValue::DurationMicrosecond(value) => ScalarValueRepr::DurationMicrosecond(*value),
            ScalarValue::DurationNanosecond(value) => ScalarValueRepr::DurationNanosecond(*value),
            _ => {
                debug!(?value, "TTProof serialize: unsupported ScalarValue variant");
                return serialization_error();
            }
        })
    }

    fn to_value(&self) -> TTResult<ScalarValue> {
        Ok(match self {
            ScalarValueRepr::Null => ScalarValue::Null,
            ScalarValueRepr::Boolean(value) => ScalarValue::Boolean(*value),
            ScalarValueRepr::Float32(value) => ScalarValue::Float32(*value),
            ScalarValueRepr::Float64(value) => ScalarValue::Float64(*value),
            ScalarValueRepr::Decimal128(value, precision, scale) => {
                ScalarValue::Decimal128(*value, *precision, *scale)
            }
            ScalarValueRepr::Decimal256(value, precision, scale) => {
                let parsed =
                    match value {
                        Some(value) => Some(value.parse::<i256>().map_err(|_| {
                            TTError::Serialization(SerializationError::InvalidData)
                        })?),
                        None => None,
                    };
                ScalarValue::Decimal256(parsed, *precision, *scale)
            }
            ScalarValueRepr::Int8(value) => ScalarValue::Int8(*value),
            ScalarValueRepr::Int16(value) => ScalarValue::Int16(*value),
            ScalarValueRepr::Int32(value) => ScalarValue::Int32(*value),
            ScalarValueRepr::Int64(value) => ScalarValue::Int64(*value),
            ScalarValueRepr::UInt8(value) => ScalarValue::UInt8(*value),
            ScalarValueRepr::UInt16(value) => ScalarValue::UInt16(*value),
            ScalarValueRepr::UInt32(value) => ScalarValue::UInt32(*value),
            ScalarValueRepr::UInt64(value) => ScalarValue::UInt64(*value),
            ScalarValueRepr::Utf8(value) => ScalarValue::Utf8(value.clone()),
            ScalarValueRepr::Utf8View(value) => ScalarValue::Utf8View(value.clone()),
            ScalarValueRepr::LargeUtf8(value) => ScalarValue::LargeUtf8(value.clone()),
            ScalarValueRepr::Binary(value) => ScalarValue::Binary(value.clone()),
            ScalarValueRepr::BinaryView(value) => ScalarValue::BinaryView(value.clone()),
            ScalarValueRepr::FixedSizeBinary(size, value) => {
                ScalarValue::FixedSizeBinary(*size, value.clone())
            }
            ScalarValueRepr::LargeBinary(value) => ScalarValue::LargeBinary(value.clone()),
            ScalarValueRepr::Date32(value) => ScalarValue::Date32(*value),
            ScalarValueRepr::Date64(value) => ScalarValue::Date64(*value),
            ScalarValueRepr::Time32Second(value) => ScalarValue::Time32Second(*value),
            ScalarValueRepr::Time32Millisecond(value) => ScalarValue::Time32Millisecond(*value),
            ScalarValueRepr::Time64Microsecond(value) => ScalarValue::Time64Microsecond(*value),
            ScalarValueRepr::Time64Nanosecond(value) => ScalarValue::Time64Nanosecond(*value),
            ScalarValueRepr::TimestampSecond(value, tz) => {
                ScalarValue::TimestampSecond(*value, tz.as_ref().map(|v| v.as_str().into()))
            }
            ScalarValueRepr::TimestampMillisecond(value, tz) => {
                ScalarValue::TimestampMillisecond(*value, tz.as_ref().map(|v| v.as_str().into()))
            }
            ScalarValueRepr::TimestampMicrosecond(value, tz) => {
                ScalarValue::TimestampMicrosecond(*value, tz.as_ref().map(|v| v.as_str().into()))
            }
            ScalarValueRepr::TimestampNanosecond(value, tz) => {
                ScalarValue::TimestampNanosecond(*value, tz.as_ref().map(|v| v.as_str().into()))
            }
            ScalarValueRepr::IntervalYearMonth(value) => ScalarValue::IntervalYearMonth(*value),
            ScalarValueRepr::IntervalDayTime(value) => ScalarValue::IntervalDayTime(
                value.map(|(days, milliseconds)| IntervalDayTime { days, milliseconds }),
            ),
            ScalarValueRepr::IntervalMonthDayNano(value) => {
                ScalarValue::IntervalMonthDayNano(value.map(|(months, days, nanoseconds)| {
                    IntervalMonthDayNano {
                        months,
                        days,
                        nanoseconds,
                    }
                }))
            }
            ScalarValueRepr::DurationSecond(value) => ScalarValue::DurationSecond(*value),
            ScalarValueRepr::DurationMillisecond(value) => ScalarValue::DurationMillisecond(*value),
            ScalarValueRepr::DurationMicrosecond(value) => ScalarValue::DurationMicrosecond(*value),
            ScalarValueRepr::DurationNanosecond(value) => ScalarValue::DurationNanosecond(*value),
        })
    }
}

impl OperatorRepr {
    fn from_operator(op: Operator) -> Self {
        match op {
            Operator::Eq => OperatorRepr::Eq,
            Operator::NotEq => OperatorRepr::NotEq,
            Operator::Lt => OperatorRepr::Lt,
            Operator::LtEq => OperatorRepr::LtEq,
            Operator::Gt => OperatorRepr::Gt,
            Operator::GtEq => OperatorRepr::GtEq,
            Operator::Plus => OperatorRepr::Plus,
            Operator::Minus => OperatorRepr::Minus,
            Operator::Multiply => OperatorRepr::Multiply,
            Operator::Divide => OperatorRepr::Divide,
            Operator::Modulo => OperatorRepr::Modulo,
            Operator::And => OperatorRepr::And,
            Operator::Or => OperatorRepr::Or,
            Operator::IsDistinctFrom => OperatorRepr::IsDistinctFrom,
            Operator::IsNotDistinctFrom => OperatorRepr::IsNotDistinctFrom,
            Operator::BitwiseAnd => OperatorRepr::BitwiseAnd,
            Operator::BitwiseOr => OperatorRepr::BitwiseOr,
            Operator::BitwiseXor => OperatorRepr::BitwiseXor,
            Operator::BitwiseShiftRight => OperatorRepr::BitwiseShiftRight,
            Operator::BitwiseShiftLeft => OperatorRepr::BitwiseShiftLeft,
            Operator::RegexMatch => OperatorRepr::RegexMatch,
            Operator::RegexIMatch => OperatorRepr::RegexIMatch,
            Operator::RegexNotMatch => OperatorRepr::RegexNotMatch,
            Operator::RegexNotIMatch => OperatorRepr::RegexNotIMatch,
            Operator::LikeMatch => OperatorRepr::LikeMatch,
            Operator::ILikeMatch => OperatorRepr::ILikeMatch,
            Operator::NotLikeMatch => OperatorRepr::NotLikeMatch,
            Operator::NotILikeMatch => OperatorRepr::NotILikeMatch,
            Operator::StringConcat => OperatorRepr::StringConcat,
            Operator::AtArrow => OperatorRepr::AtArrow,
            Operator::ArrowAt => OperatorRepr::ArrowAt,
        }
    }

    fn to_operator(&self) -> Operator {
        match self {
            OperatorRepr::Eq => Operator::Eq,
            OperatorRepr::NotEq => Operator::NotEq,
            OperatorRepr::Lt => Operator::Lt,
            OperatorRepr::LtEq => Operator::LtEq,
            OperatorRepr::Gt => Operator::Gt,
            OperatorRepr::GtEq => Operator::GtEq,
            OperatorRepr::Plus => Operator::Plus,
            OperatorRepr::Minus => Operator::Minus,
            OperatorRepr::Multiply => Operator::Multiply,
            OperatorRepr::Divide => Operator::Divide,
            OperatorRepr::Modulo => Operator::Modulo,
            OperatorRepr::And => Operator::And,
            OperatorRepr::Or => Operator::Or,
            OperatorRepr::IsDistinctFrom => Operator::IsDistinctFrom,
            OperatorRepr::IsNotDistinctFrom => Operator::IsNotDistinctFrom,
            OperatorRepr::BitwiseAnd => Operator::BitwiseAnd,
            OperatorRepr::BitwiseOr => Operator::BitwiseOr,
            OperatorRepr::BitwiseXor => Operator::BitwiseXor,
            OperatorRepr::BitwiseShiftRight => Operator::BitwiseShiftRight,
            OperatorRepr::BitwiseShiftLeft => Operator::BitwiseShiftLeft,
            OperatorRepr::RegexMatch => Operator::RegexMatch,
            OperatorRepr::RegexIMatch => Operator::RegexIMatch,
            OperatorRepr::RegexNotMatch => Operator::RegexNotMatch,
            OperatorRepr::RegexNotIMatch => Operator::RegexNotIMatch,
            OperatorRepr::LikeMatch => Operator::LikeMatch,
            OperatorRepr::ILikeMatch => Operator::ILikeMatch,
            OperatorRepr::NotLikeMatch => Operator::NotLikeMatch,
            OperatorRepr::NotILikeMatch => Operator::NotILikeMatch,
            OperatorRepr::StringConcat => Operator::StringConcat,
            OperatorRepr::AtArrow => Operator::AtArrow,
            OperatorRepr::ArrowAt => Operator::ArrowAt,
        }
    }
}

impl JoinTypeRepr {
    fn from_join_type(join_type: JoinType) -> Self {
        match join_type {
            JoinType::Inner => JoinTypeRepr::Inner,
            JoinType::Left => JoinTypeRepr::Left,
            JoinType::Right => JoinTypeRepr::Right,
            JoinType::Full => JoinTypeRepr::Full,
            JoinType::LeftSemi => JoinTypeRepr::LeftSemi,
            JoinType::RightSemi => JoinTypeRepr::RightSemi,
            JoinType::LeftAnti => JoinTypeRepr::LeftAnti,
            JoinType::RightAnti => JoinTypeRepr::RightAnti,
            JoinType::LeftMark => JoinTypeRepr::LeftMark,
        }
    }

    fn to_join_type(&self) -> JoinType {
        match self {
            JoinTypeRepr::Inner => JoinType::Inner,
            JoinTypeRepr::Left => JoinType::Left,
            JoinTypeRepr::Right => JoinType::Right,
            JoinTypeRepr::Full => JoinType::Full,
            JoinTypeRepr::LeftSemi => JoinType::LeftSemi,
            JoinTypeRepr::RightSemi => JoinType::RightSemi,
            JoinTypeRepr::LeftAnti => JoinType::LeftAnti,
            JoinTypeRepr::RightAnti => JoinType::RightAnti,
            JoinTypeRepr::LeftMark => JoinType::LeftMark,
        }
    }
}

impl JoinConstraintRepr {
    fn from_constraint(constraint: JoinConstraint) -> Self {
        match constraint {
            JoinConstraint::On => JoinConstraintRepr::On,
            JoinConstraint::Using => JoinConstraintRepr::Using,
        }
    }

    fn to_join_constraint(&self) -> JoinConstraint {
        match self {
            JoinConstraintRepr::On => JoinConstraint::On,
            JoinConstraintRepr::Using => JoinConstraint::Using,
        }
    }
}

pub fn serialize_tree<B: SnarkBackend>(tree: &Tree<B>) -> TTResult<Vec<u8>> {
    let root = tree.root();
    let plan = match root.as_ref() {
        Node::Plan(PlanNode::LpBased(node)) => node.lp(),
        _ => {
            debug!("TTProof serialize: non-LP root node");
            return serialization_error();
        }
    };
    let mut join_modes = Vec::new();
    collect_join_modes(root, &mut join_modes);
    let repr = TreeRepr {
        plan: LogicalPlanRepr::from_plan(&plan)?,
        join_modes,
    };
    bincode::serialize(&repr).map_err(|_| TTError::Serialization(SerializationError::InvalidData))
}

pub fn deserialize_tree<B: SnarkBackend>(bytes: &[u8]) -> TTResult<Tree<B>> {
    // Backward compatibility: try bincode first (current), then JSON (legacy).
    let repr: TreeRepr = match bincode::deserialize(bytes) {
        Ok(repr) => repr,
        Err(_) => serde_json::from_slice(bytes)
            .map_err(|_| TTError::Serialization(SerializationError::InvalidData))?,
    };
    let ctx = SessionContext::new();
    let plan = repr.plan.to_plan(&ctx)?;
    let tree = Tree::from_logical_plan(&plan);
    if !repr.join_modes.is_empty() {
        apply_join_modes(tree.root(), &repr.join_modes, &mut 0usize);
        Ok(Tree::new_from_root(tree.root().clone()))
    } else {
        Ok(tree)
    }
}

pub fn serialize_empty_ir<B: SnarkBackend>(ir: &EmptyIr<B>) -> TTResult<Vec<u8>> {
    serialize_tree(ir.tree())
}

pub fn deserialize_empty_ir<B: SnarkBackend>(bytes: &[u8]) -> TTResult<EmptyIr<B>> {
    let tree = deserialize_tree::<B>(bytes)?;
    Ok(EmptyIr::<B>::new_empty(tree))
}

fn collect_join_modes<B: SnarkBackend>(node: &Arc<Node<B>>, out: &mut Vec<JoinModeRepr>) {
    if let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref()
        && matches!(lp_node.lp(), LogicalPlan::Join(_)) {
            let mode = node
                .children()
                .iter()
                .find_map(|child| {
                    let Node::Gadget(gadget) = child.as_ref() else {
                        return None;
                    };
                    let any = gadget.as_ref() as &dyn Any;
                    any.downcast_ref::<gadget_join::GadgetNode<B>>()
                        .map(|join_gadget| join_gadget.join_mode())
                })
                .unwrap_or(gadget_join::JoinMode::MANY_TO_MANY);
            out.push(JoinModeRepr::from_join_mode(mode));
        }

    for child in node.children() {
        collect_join_modes(&child, out);
    }
}

fn apply_join_modes<B: SnarkBackend>(node: &Arc<Node<B>>, modes: &[JoinModeRepr], idx: &mut usize) {
    if let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref()
        && matches!(lp_node.lp(), LogicalPlan::Join(_)) {
            if let Some(mode) = modes.get(*idx) {
                for child in node.children() {
                    let Node::Gadget(gadget) = child.as_ref() else {
                        continue;
                    };
                    let any = gadget.as_ref() as &dyn Any;
                    if let Some(join_gadget) = any.downcast_ref::<gadget_join::GadgetNode<B>>() {
                        join_gadget.set_join_mode(mode.to_join_mode());
                    }
                }
            }
            *idx += 1;
        }

    for child in node.children() {
        apply_join_modes(&child, modes, idx);
    }
}
