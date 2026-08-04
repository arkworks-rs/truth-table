from __future__ import annotations

import json
import math
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

import streamlit as st
import streamlit.components.v1 as components


DEFAULT_JSONL_PATH = Path(__file__).resolve().parent / "raw" / "bench_stats.jsonl"
# Where the sumcheck-degree default lives. Newer ark-piop exposes it as a
# `SharedArgConfig::default()` field in `types/mod.rs`; older versions had a
# top-level `SUMCHECK_TERM_DEGREE_LIMIT` const in `lib.rs`. We try both.
ARK_PIOP_TYPES_PATH = Path(__file__).resolve().parents[2] / "ark-piop" / "src" / "types" / "mod.rs"
ARK_PIOP_LIB_PATH = Path(__file__).resolve().parents[2] / "ark-piop" / "src" / "lib.rs"


# Canonical order the TT prover emits plan / IR stages in, from
# `crates/tt-front-end/src/prover.rs`. Any stage not in this list is
# appended at the end in alphabetical order — safe default if the
# pipeline grows a new stage the dashboard hasn't been taught yet.
PIPELINE_STAGE_ORDER = (
    "initial_logical_plan",
    "analyzed_logical_plan",
    "structural_optimized_logical_plan",
    "data_dependent_optimized_logical_plan",
    "initial_ir",
    "optimized_initial_ir",
    "output_planned_ir",
    "gadget_planned_ir",
    "materialized_ir",
    "arithmetized_ir",
    "committed_ir",
    "tracked_ir",
    "virtualized_ir",
    "gadget_ready_ir",
)


def order_plan_stages(names: Any) -> list[str]:
    """Sort plan-stage names by pipeline order; unknown names go last A→Z."""
    index_of = {name: i for i, name in enumerate(PIPELINE_STAGE_ORDER)}
    unknown_start = len(PIPELINE_STAGE_ORDER)
    return sorted(
        names,
        key=lambda name: (index_of.get(name, unknown_start), name),
    )


def parse_scalar(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: parse_scalar(inner_value) for key, inner_value in value.items()}
    if isinstance(value, list):
        return [parse_scalar(item) for item in value]
    if isinstance(value, str):
        try:
            return parse_scalar(json.loads(value))
        except json.JSONDecodeError:
            return value
    return value


def load_jsonl(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    file_path = Path(path)
    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            parsed = {key: parse_scalar(value) for key, value in raw.items()}
            records.append(parsed)
    return records


def sumcheck_term_degree_limit_label() -> str:
    import re

    # Newer ark-piop: field default in `SharedArgConfig::default()` impl.
    #   sumcheck_term_degree_limit: 6,
    try:
        source = ARK_PIOP_TYPES_PATH.read_text(encoding="utf-8")
    except OSError:
        source = ""
    match = re.search(r"sumcheck_term_degree_limit\s*:\s*([0-9]+)", source)
    if match:
        return match.group(1)

    # Legacy ark-piop: top-level const in lib.rs.
    #   pub const SUMCHECK_TERM_DEGREE_LIMIT: usize = 6;
    try:
        legacy = ARK_PIOP_LIB_PATH.read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    for line in legacy.splitlines():
        if "SUMCHECK_TERM_DEGREE_LIMIT" not in line or "=" not in line:
            continue
        value = line.split("=", 1)[1].strip().rstrip(";")
        if value:
            return value
    return "unknown"


def bytes_to_kib_label(value: Any) -> str:
    try:
        return f"{float(value) / 1024.0:.2f} KiB"
    except (TypeError, ValueError):
        return "n/a"


def to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def render_pie_svg(
    rows: list[dict[str, Any]],
    *,
    value_key: str = "seconds",
    value_label: str = "s",
    center_format: str = ".3f",
    legend_format: str = ".4f",
) -> str:
    rows = sorted(rows, key=lambda row: row[value_key], reverse=True)
    total = sum(row[value_key] for row in rows)
    if total <= 0:
        return ""

    colors = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
    ]
    cx = 110
    cy = 110
    r = 90
    start_angle = -math.pi / 2
    slices: list[str] = []
    legend: list[str] = []

    for idx, row in enumerate(rows):
        value = row[value_key]
        fraction = value / total
        end_angle = start_angle + fraction * 2 * math.pi
        x1 = cx + r * math.cos(start_angle)
        y1 = cy + r * math.sin(start_angle)
        x2 = cx + r * math.cos(end_angle)
        y2 = cy + r * math.sin(end_angle)
        large_arc = 1 if fraction > 0.5 else 0
        color = colors[idx % len(colors)]
        path = (
            f"M {cx} {cy} "
            f"L {x1:.3f} {y1:.3f} "
            f"A {r} {r} 0 {large_arc} 1 {x2:.3f} {y2:.3f} Z"
        )
        slices.append(f'<path d="{path}" fill="{color}"></path>')
        legend_y = 24 + idx * 22
        legend.append(
            f'<rect x="240" y="{legend_y - 10}" width="12" height="12" fill="{color}"></rect>'
            f'<text x="260" y="{legend_y}" font-size="12" fill="#222">'
            f'{escape(row["pass"])}: {format(value, legend_format)}{value_label}'
            f"</text>"
        )
        start_angle = end_angle

    donut_hole = f'<circle cx="{cx}" cy="{cy}" r="42" fill="white"></circle>'
    center_label = (
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="14" fill="#222">Total</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="16" font-weight="bold" fill="#222">{format(total, center_format)}{value_label}</text>'
    )
    return (
        '<svg viewBox="0 0 520 240" width="100%" height="240" xmlns="http://www.w3.org/2000/svg">'
        + "".join(slices)
        + donut_hole
        + center_label
        + "".join(legend)
        + "</svg>"
    )


def render_zoomable_graphviz(dot: str) -> None:
    html = f"""
    <div id="graphviz-root" style="width:100%;height:780px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;background:white;"></div>
    <script src="https://cdn.jsdelivr.net/npm/viz.js@2.1.2/viz.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/viz.js@2.1.2/full.render.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/panzoom@9.4.3/dist/panzoom.min.js"></script>
    <script>
      const dot = {json.dumps(dot)};
      const root = document.getElementById("graphviz-root");
      const viz = new Viz();
      viz.renderSVGElement(dot).then((svg) => {{
        svg.setAttribute("width", "100%");
        svg.setAttribute("height", "100%");
        svg.style.cursor = "grab";
        root.innerHTML = "";
        root.appendChild(svg);
        const panzoomInstance = window.panzoom(svg, {{
          maxZoom: 20,
          minZoom: 0.1,
          bounds: false,
          boundsPadding: 0.2,
        }});
        root.addEventListener("wheel", panzoomInstance.zoomWithWheel);
      }}).catch((err) => {{
        root.innerHTML = "<pre style='padding:16px;white-space:pre-wrap;'>" + String(err) + "</pre>";
      }});
    </script>
    """
    components.html(html, height=820, scrolling=False)


def render_grouped_bar_svg(title: str, stages: list[dict[str, Any]]) -> str:
    if not stages:
        return ""
    series = ["non-zero-checks", "zero-checks", "sum-checks"]
    colors = {
        "non-zero-checks": "#1f77b4",
        "zero-checks": "#ff7f0e",
        "sum-checks": "#2ca02c",
    }
    max_value = max(
        max((to_float(stage.get(series_name, 0)) or 0.0) for series_name in series)
        for stage in stages
    )
    max_value = max(max_value, 1.0)
    chart_left = 55
    chart_top = 25
    chart_width = 620
    chart_height = 220
    group_width = chart_width / max(len(stages), 1)
    bar_width = min(28.0, group_width / 4.5)
    bar_gap = bar_width * 0.35
    group_inner_width = 3 * bar_width + 2 * bar_gap

    parts = [
        '<svg viewBox="0 0 760 320" width="100%" height="320" xmlns="http://www.w3.org/2000/svg">',
        f'<text x="{chart_left}" y="18" font-size="16" font-weight="bold" fill="#222">{escape(title)}</text>',
        f'<line x1="{chart_left}" y1="{chart_top}" x2="{chart_left}" y2="{chart_top + chart_height}" stroke="#555" />',
        f'<line x1="{chart_left}" y1="{chart_top + chart_height}" x2="{chart_left + chart_width}" y2="{chart_top + chart_height}" stroke="#555" />',
    ]

    for tick_idx in range(5):
        value = max_value * (4 - tick_idx) / 4
        y = chart_top + chart_height * tick_idx / 4
        parts.append(f'<line x1="{chart_left}" y1="{y:.2f}" x2="{chart_left + chart_width}" y2="{y:.2f}" stroke="#e5e7eb" />')
        parts.append(f'<text x="{chart_left - 8}" y="{y + 4:.2f}" text-anchor="end" font-size="11" fill="#555">{value:.0f}</text>')

    for idx, stage in enumerate(stages):
        group_x = chart_left + idx * group_width + (group_width - group_inner_width) / 2
        for series_idx, series_name in enumerate(series):
            value = to_float(stage.get(series_name, 0)) or 0.0
            bar_height = (value / max_value) * chart_height
            x = group_x + series_idx * (bar_width + bar_gap)
            y = chart_top + chart_height - bar_height
            parts.append(
                f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_height:.2f}" fill="{colors[series_name]}"></rect>'
            )
        parts.append(
            f'<text x="{group_x + group_inner_width / 2:.2f}" y="{chart_top + chart_height + 18}" '
            f'text-anchor="middle" font-size="11" fill="#222">{escape(str(stage["stage"]))}</text>'
        )

    legend_y = chart_top + chart_height + 46
    legend_x = chart_left
    for idx, series_name in enumerate(series):
        x = legend_x + idx * 170
        parts.append(f'<rect x="{x}" y="{legend_y - 10}" width="12" height="12" fill="{colors[series_name]}"></rect>')
        parts.append(f'<text x="{x + 18}" y="{legend_y}" font-size="12" fill="#222">{escape(series_name)}</text>')

    parts.append("</svg>")
    return "".join(parts)


def render_histogram_svg(title: str, histogram: dict[str, int]) -> str:
    if not histogram:
        return ""
    items = sorted(((int(k), v) for k, v in histogram.items()), key=lambda item: item[0])
    max_count = max(v for _, v in items)
    max_count = max(max_count, 1)
    chart_left = 45
    chart_top = 20
    chart_width = 260
    chart_height = 150
    bar_gap = 6
    bar_width = max(12.0, (chart_width - bar_gap * (len(items) - 1)) / max(len(items), 1))
    parts = [
        '<svg viewBox="0 0 330 220" width="100%" height="220" xmlns="http://www.w3.org/2000/svg">',
        f'<text x="{chart_left}" y="14" font-size="13" font-weight="bold" fill="#222">{escape(title)}</text>',
        f'<line x1="{chart_left}" y1="{chart_top}" x2="{chart_left}" y2="{chart_top + chart_height}" stroke="#555" />',
        f'<line x1="{chart_left}" y1="{chart_top + chart_height}" x2="{chart_left + chart_width}" y2="{chart_top + chart_height}" stroke="#555" />',
    ]
    for idx, (degree, count) in enumerate(items):
        x = chart_left + idx * (bar_width + bar_gap)
        bar_height = (count / max_count) * chart_height
        y = chart_top + chart_height - bar_height
        parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_height:.2f}" fill="#4f46e5"></rect>')
        parts.append(f'<text x="{x + bar_width / 2:.2f}" y="{chart_top + chart_height + 16}" text-anchor="middle" font-size="10" fill="#222">{degree}</text>')
    parts.append(f'<text x="{chart_left - 8}" y="{chart_top + 4}" text-anchor="end" font-size="11" fill="#555">{max_count}</text>')
    parts.append(f'<text x="{chart_left + chart_width / 2}" y="{chart_top + chart_height + 34}" text-anchor="middle" font-size="11" fill="#555">degree</text>')
    parts.append("</svg>")
    return "".join(parts)


def metric_rows(stage: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for metric_name in ["non-zero-checks", "zero-checks", "sum-checks"]:
        metric = stage.get(metric_name, {}) if isinstance(stage, dict) else {}
        rows.append(
            {
                "check type": metric_name,
                "count": metric.get("count"),
                "degree distribution": metric.get("degree_distribution"),
            }
        )
    return rows


def degree_histogram_data(degrees: Any) -> dict[str, int]:
    if not isinstance(degrees, list):
        return {}
    counts = Counter(str(value) for value in degrees)
    return dict(sorted(counts.items(), key=lambda item: int(item[0])))


def stage_count_row(stage_name: str, stage: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": stage_name,
        "non-zero-checks": to_float(((stage or {}).get("non-zero-checks") or {}).get("count")) or 0.0,
        "zero-checks": to_float(((stage or {}).get("zero-checks") or {}).get("count")) or 0.0,
        "sum-checks": to_float(((stage or {}).get("sum-checks") or {}).get("count")) or 0.0,
    }


def render_stage_histograms(title: str, stage: dict[str, Any]) -> None:
    st.markdown(f"##### {title}")
    cols = st.columns(3)
    for idx, metric_name in enumerate(["non-zero-checks", "zero-checks", "sum-checks"]):
        metric = stage.get(metric_name, {}) if isinstance(stage, dict) else {}
        histogram = degree_histogram_data(metric.get("degree_distribution"))
        with cols[idx]:
            if histogram:
                st.markdown(render_histogram_svg(metric_name, histogram), unsafe_allow_html=True)
            else:
                st.info(f"No {metric_name} degrees.")


def render_claims_section(claims: dict[str, Any], sc_buckets: Any = None) -> None:
    st.subheader("Claims")
    before = claims.get("before-degree-reduction", {})
    after = claims.get("after-degree-reduction", {})
    target_degree = sumcheck_term_degree_limit_label()

    st.markdown(f"#### Before Degree Reduction ( Target Degree = {target_degree} )")
    before_rows = [
        stage_count_row("initial", before.get("initial", {})),
        stage_count_row("after-nozero-batching", before.get("after-nozero-batching", {})),
        stage_count_row("after-zero-batching", before.get("after-zero-batching", {})),
        stage_count_row("after-sum-batching", before.get("after-sum-batching", {})),
    ]
    st.markdown(
        render_grouped_bar_svg("Before Degree Reduction Claim Counts", before_rows),
        unsafe_allow_html=True,
    )
    render_stage_histograms("Initial", before.get("initial", {}))
    render_stage_histograms("After NonzeroChecker", before.get("after-nozero-batching", {}))
    render_stage_histograms("After ZeroChecker", before.get("after-zero-batching", {}))
    render_stage_histograms("After SumChecker", before.get("after-sum-batching", {}))

    st.markdown(f"#### After Degree Reduction ( Target Degree = {target_degree} )")
    after_rows = [
        stage_count_row("initial", after.get("initial", {})),
        stage_count_row("after-zero-batching", after.get("after-zero-batching", {})),
        stage_count_row("after-sum-batching", after.get("after-sum-batching", {})),
    ]
    st.markdown(
        render_grouped_bar_svg("After Degree Reduction Claim Counts", after_rows),
        unsafe_allow_html=True,
    )
    render_stage_histograms("Initial", after.get("initial", {}))
    render_stage_histograms("After ZeroChecker", after.get("after-zero-batching", {}))
    render_stage_histograms("After SumChecker", after.get("after-sum-batching", {}))

    render_per_bucket_claim_counts(sc_buckets)

    render_lookup_claims_section(claims.get("lookups"))


def _bucket_claims_to_aggregate_shape(bucket_claims: Any) -> dict[str, Any]:
    """Reshape a per-bucket claims blob (snake_case, `non_zero_checks` etc.)
    into the same hyphenated shape the aggregate Claims section renders, so
    we can reuse `stage_count_row`, `render_grouped_bar_svg`, and
    `render_stage_histograms` unchanged.
    """
    def stage(s: Any) -> dict[str, Any]:
        if not isinstance(s, dict):
            return {}
        return {
            "non-zero-checks": {
                "count": (s.get("non_zero_checks") or {}).get("count"),
                "degree_distribution": (s.get("non_zero_checks") or {}).get("degree_distribution"),
            },
            "zero-checks": {
                "count": (s.get("zero_checks") or {}).get("count"),
                "degree_distribution": (s.get("zero_checks") or {}).get("degree_distribution"),
            },
            "sum-checks": {
                "count": (s.get("sum_checks") or {}).get("count"),
                "degree_distribution": (s.get("sum_checks") or {}).get("degree_distribution"),
            },
        }

    if not isinstance(bucket_claims, dict):
        return {"before-degree-reduction": {}, "after-degree-reduction": {}}
    before = bucket_claims.get("before_degree_reduction") or {}
    after = bucket_claims.get("after_degree_reduction") or {}
    return {
        "before-degree-reduction": {
            "initial": stage(before.get("initial")),
            "after-nozero-batching": stage(before.get("after_nozero_batching")),
            "after-zero-batching": stage(before.get("after_zero_batching")),
            "after-sum-batching": stage(before.get("after_sum_batching")),
        },
        "after-degree-reduction": {
            "initial": stage(after.get("initial")),
            "after-zero-batching": stage(after.get("after_zero_batching")),
            "after-sum-batching": stage(after.get("after_sum_batching")),
        },
    }


def render_per_bucket_claim_counts(sc_buckets: Any) -> None:
    """Full per-bucket claim breakdown — same structure as the aggregate
    section above (Before/After Degree Reduction, per-stage grouped bars,
    per-stage degree histograms), one collapsible group per bucket.
    """
    if not isinstance(sc_buckets, dict):
        return
    buckets = sc_buckets.get("buckets") or []
    if not isinstance(buckets, list) or not buckets:
        return

    target_degree = sumcheck_term_degree_limit_label()
    st.markdown("#### Per-Bucket Claims")

    for b in buckets:
        if not isinstance(b, dict):
            continue
        shaped = _bucket_claims_to_aggregate_shape(b.get("claims"))
        before = shaped["before-degree-reduction"]
        after = shaped["after-degree-reduction"]

        header = (
            f"Bucket {b.get('index')} — target_nv={b.get('target_nv')}, "
            f"included_nvs={b.get('included_nvs')}, {b.get('n_claims_total')} claims"
        )
        with st.expander(header, expanded=True):
            st.markdown(f"##### Before Degree Reduction ( Target Degree = {target_degree} )")
            before_rows = [
                stage_count_row("initial", before.get("initial", {})),
                stage_count_row("after-nozero-batching", before.get("after-nozero-batching", {})),
                stage_count_row("after-zero-batching", before.get("after-zero-batching", {})),
                stage_count_row("after-sum-batching", before.get("after-sum-batching", {})),
            ]
            st.markdown(
                render_grouped_bar_svg("Before Degree Reduction Claim Counts", before_rows),
                unsafe_allow_html=True,
            )
            render_stage_histograms("Initial", before.get("initial", {}))
            render_stage_histograms("After NonzeroChecker", before.get("after-nozero-batching", {}))
            render_stage_histograms("After ZeroChecker", before.get("after-zero-batching", {}))
            render_stage_histograms("After SumChecker", before.get("after-sum-batching", {}))

            st.markdown(f"##### After Degree Reduction ( Target Degree = {target_degree} )")
            after_rows = [
                stage_count_row("initial", after.get("initial", {})),
                stage_count_row("after-zero-batching", after.get("after-zero-batching", {})),
                stage_count_row("after-sum-batching", after.get("after-sum-batching", {})),
            ]
            st.markdown(
                render_grouped_bar_svg("After Degree Reduction Claim Counts", after_rows),
                unsafe_allow_html=True,
            )
            render_stage_histograms("Initial", after.get("initial", {}))
            render_stage_histograms("After ZeroChecker", after.get("after-zero-batching", {}))
            render_stage_histograms("After SumChecker", after.get("after-sum-batching", {}))


def render_lookup_claims_section(lookups: Any) -> None:
    if not isinstance(lookups, dict):
        return

    def _to_int(val: Any) -> int | None:
        if val is None:
            return None
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    count = _to_int(lookups.get("count"))
    supersets_count = _to_int(lookups.get("supersets_count"))

    raw = lookups.get("subset_counts_per_superset")
    subset_counts: list[int] = []
    if isinstance(raw, list):
        subset_counts = [int(x) for x in raw if _to_int(x) is not None]
    elif isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                subset_counts = [int(x) for x in parsed if _to_int(x) is not None]
        except (json.JSONDecodeError, ValueError):
            subset_counts = []

    if (count or 0) == 0 and not subset_counts:
        return

    st.markdown("#### Lookup Claims")
    col1, col2 = st.columns(2)
    col1.metric("Total lookup claims", str(count) if count is not None else "n/a")
    col2.metric(
        "Distinct supersets",
        str(supersets_count) if supersets_count is not None else "n/a",
    )

    if subset_counts:
        # Group: how many supersets share each subset count?
        # E.g. {50: 2, 20: 1, 10: 1, 3: 1, 1: 54}
        grouped = Counter(subset_counts)
        rows = [
            {"# supersets": num_supersets, "# subsets per superset": subset_count}
            for subset_count, num_supersets in sorted(
                grouped.items(), key=lambda kv: (-kv[0],)
            )
        ]
        st.markdown(
            "Each row says *N supersets each have M subset polynomials looked up "
            "into them*."
        )
        st.table(rows)


def render_results_section(results: dict[str, Any]) -> None:
    st.subheader("Results")
    col1, col2 = st.columns(2)
    col1.metric("Rows Count", str(results.get("Rows Count", "n/a")))
    col2.metric("Size", bytes_to_kib_label(results.get("Size")))
    schema = results.get("Schema")
    if schema:
        st.markdown("#### Schema")
        st.code(str(schema), language="text")
    else:
        st.info("No result schema found for this run.")

    # Inline preview (first N rows, embedded in the JSONL by the bench).
    # We convert to a pandas DataFrame explicitly rather than passing the
    # list of dicts directly — st.dataframe's internal Arrow inference has
    # been fragile across pyarrow / streamlit / pandas version combos.
    preview = results.get("preview_rows")
    if preview:
        st.markdown("#### Preview")
        preview_rows: list[Any] | None = None
        if isinstance(preview, str):
            try:
                parsed = json.loads(preview)
                if isinstance(parsed, list):
                    preview_rows = parsed
            except json.JSONDecodeError:
                st.warning("Preview rows field is not valid JSON.")
        elif isinstance(preview, list):
            preview_rows = preview
        if preview_rows is not None:
            if preview_rows:
                try:
                    import pandas as pd  # local import: pandas is heavy

                    preview_df = pd.DataFrame(preview_rows)
                    st.dataframe(preview_df, hide_index=True, use_container_width=True)
                    total = results.get("Rows Count")
                    if isinstance(total, int) and total > len(preview_rows):
                        st.caption(
                            f"Showing first {len(preview_rows)} of {total} rows. "
                            f"Full result available below."
                        )
                except Exception as exc:
                    st.error(f"Preview render failed: {exc}")
                    st.code(json.dumps(preview_rows[:5], indent=2), language="json")
            else:
                st.info("Result set is empty.")

    # Full result — lazy-loaded only when the user clicks the button so we
    # don't re-read the parquet on every rerun (Streamlit re-executes the
    # whole script per interaction; expander bodies run even when collapsed).
    parquet_path = results.get("parquet_path")
    if parquet_path:
        st.markdown("#### Full Result")
        path = Path(str(parquet_path))
        if not path.exists():
            st.caption(f"No parquet at `{path}`.")
        else:
            st.caption(f"Sidecar: `{path}`")
            if st.button("Load full result from parquet"):
                try:
                    import pandas as pd  # local import: pandas is heavy

                    df = pd.read_parquet(path)
                    st.caption(f"{len(df):,} rows × {len(df.columns)} cols")
                    st.dataframe(df, hide_index=True, use_container_width=True)
                except Exception as exc:
                    st.error(f"Failed to read parquet: {exc}")


def render_proof_size_section(proof_size: dict[str, Any]) -> None:
    st.subheader("Proof Size")
    full = proof_size.get("full", {})
    crypto = proof_size.get("crypto", {})
    non_crypto = proof_size.get("non_crypto", {})
    crypto_breakdown = crypto.get("breakdown", {})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Full", bytes_to_kib_label(full.get("size")))
    col2.metric("Full Compressed", bytes_to_kib_label(full.get("compressed size")))
    col3.metric("Crypto", bytes_to_kib_label(crypto.get("size")))
    col4.metric("Non-Crypto", bytes_to_kib_label(non_crypto.get("size")))

    if isinstance(crypto_breakdown, dict) and crypto_breakdown:
        crypto_rows = []
        for key, value in crypto_breakdown.items():
            if isinstance(value, dict):
                size_value = to_float(value.get("size"))
                if size_value is not None:
                    crypto_rows.append({"pass": key, "seconds": size_value})
            else:
                size_value = to_float(value)
                if size_value is not None:
                    crypto_rows.append({"pass": key, "seconds": size_value})

        mv_rows = []
        mv_pcs = crypto_breakdown.get("mv_pcs_subproof", {})
        if isinstance(mv_pcs, dict):
            mv_breakdown = mv_pcs.get("breakdown", {})
            if isinstance(mv_breakdown, dict):
                for key, value in mv_breakdown.items():
                    if isinstance(value, dict):
                        size_value = to_float(value.get("size"))
                    else:
                        size_value = to_float(value)
                    if size_value is not None:
                        mv_rows.append({"pass": key, "seconds": size_value})

        uv_rows = []
        uv_pcs = crypto_breakdown.get("uv_pcs_subproof", {})
        if isinstance(uv_pcs, dict):
            uv_breakdown = uv_pcs.get("breakdown", {})
            if isinstance(uv_breakdown, dict):
                for key, value in uv_breakdown.items():
                    if isinstance(value, dict):
                        size_value = to_float(value.get("size"))
                    else:
                        size_value = to_float(value)
                    if size_value is not None:
                        uv_rows.append({"pass": key, "seconds": size_value})

        if crypto_rows:
            st.markdown("#### Crypto Breakdown")
            st.markdown(
                render_pie_svg(
                    crypto_rows,
                    value_key="seconds",
                    value_label=" B",
                    center_format=".0f",
                    legend_format=".0f",
                ),
                unsafe_allow_html=True,
            )
        breakdown_cols = st.columns(2)
        with breakdown_cols[0]:
            if mv_rows:
                st.markdown("#### MV PCS Breakdown")
                st.markdown(
                    render_pie_svg(
                        mv_rows,
                        value_key="seconds",
                        value_label=" B",
                        center_format=".0f",
                        legend_format=".0f",
                    ),
                    unsafe_allow_html=True,
                )
        with breakdown_cols[1]:
            if uv_rows:
                st.markdown("#### UV PCS Breakdown")
                st.markdown(
                    render_pie_svg(
                        uv_rows,
                        value_key="seconds",
                        value_label=" B",
                        center_format=".0f",
                        legend_format=".0f",
                    ),
                    unsafe_allow_html=True,
                )


def render_overview_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for record in records:
        proof_size = record.get("proof_size", {})
        full = proof_size.get("full", {})
        crypto = proof_size.get("crypto", {})
        non_crypto = proof_size.get("non_crypto", {})
        rows.append(
            {
                "timestamp": record.get("timestamp"),
                "query": record.get("query"),
                "full bytes": full.get("size"),
                "full compressed bytes": full.get("compressed size"),
                "crypto bytes": crypto.get("size"),
                "non-crypto bytes": non_crypto.get("size"),
            }
        )
    return rows


def timing_rows_from_prover(prover_time: Any) -> list[dict[str, Any]]:
    if not isinstance(prover_time, dict):
        return []
    return [
        {
            "component": key.removeprefix("prover_time_").removesuffix("_s"),
            "seconds": seconds,
        }
        for key, value in sorted(prover_time.items())
        if (seconds := to_float(value)) is not None
    ]


def timing_rows_from_piop(piop: Any) -> list[dict[str, Any]]:
    if not isinstance(piop, dict):
        seconds = to_float(piop)
        return [{"component": "piop", "seconds": seconds}] if seconds is not None else []

    breakdown = piop.get("breakdown", {})
    if not isinstance(breakdown, dict):
        seconds = to_float(piop.get("time"))
        return [{"component": "piop", "seconds": seconds}] if seconds is not None else []

    return [
        {"component": label, "seconds": seconds}
        for label, value in breakdown.items()
        if (seconds := to_float(value)) is not None
    ]


def render_prover_timing_section(record: dict[str, Any]) -> None:
    st.subheader("Prover Timing")
    prover = record.get("prover", {})
    prover_time = prover.get("time", {}) if isinstance(prover, dict) else {}
    snark_prover = record.get("snark prover", {})

    pass_rows = timing_rows_from_prover(prover_time)
    piop_rows = timing_rows_from_piop(snark_prover.get("piop") if isinstance(snark_prover, dict) else None)
    mv_pcs_time = to_float(snark_prover.get("mv pcs")) if isinstance(snark_prover, dict) else None
    uv_pcs_time = to_float(snark_prover.get("uv pcs")) if isinstance(snark_prover, dict) else None

    summary_rows = []
    if pass_rows:
        summary_rows.append({"pass": "passes", "seconds": sum(row["seconds"] for row in pass_rows)})
    if piop_rows:
        summary_rows.append({"pass": "piop", "seconds": sum(row["seconds"] for row in piop_rows)})
    if mv_pcs_time is not None:
        summary_rows.append({"pass": "mv pcs", "seconds": mv_pcs_time})
    if uv_pcs_time is not None:
        summary_rows.append({"pass": "uv pcs", "seconds": uv_pcs_time})

    if summary_rows:
        st.markdown("#### Proving Time Share")
        st.markdown(render_pie_svg(summary_rows), unsafe_allow_html=True)
        detail_cols = st.columns(2)
        with detail_cols[0]:
            st.markdown("#### Passes Breakdown")
            if pass_rows:
                st.markdown(
                    render_pie_svg([{"pass": row["component"], "seconds": row["seconds"]} for row in pass_rows]),
                    unsafe_allow_html=True,
                )
            else:
                st.info("No pass timing data.")
        with detail_cols[1]:
            st.markdown("#### piop Breakdown")
            if piop_rows:
                st.markdown(
                    render_pie_svg([{"pass": row["component"], "seconds": row["seconds"]} for row in piop_rows]),
                    unsafe_allow_html=True,
                )
            else:
                st.info("No piop timing data.")
    else:
        st.info("No numeric prover timing data found for this run.")

    render_per_bucket_timing(record.get("sc_buckets"))


def render_per_bucket_timing(sc_buckets: Any) -> None:
    """One timing-breakdown pie per sumcheck bucket. Buckets with all-zero
    timings are dropped rather than rendering an empty pie.
    """
    if not isinstance(sc_buckets, dict):
        return
    buckets = sc_buckets.get("buckets") or []
    if not isinstance(buckets, list) or not buckets:
        return

    timing_keys = [
        ("nozero batching", "nozerocheck_batching_time_s"),
        ("1st batch zerocheck", "first_batch_zerocheck_time_s"),
        ("1st zerocheck→sumcheck", "first_zerocheck_to_sumcheck_time_s"),
        ("1st batch sumcheck", "first_batch_sumcheck_time_s"),
        ("reduce sumcheck", "reduce_sumcheck_time_s"),
        ("2nd batch zerocheck", "second_batch_zerocheck_time_s"),
        ("2nd zerocheck→sumcheck", "second_zerocheck_to_sumcheck_time_s"),
        ("sumcheck", "sumcheck_time_s"),
    ]

    st.markdown("#### Per-Bucket piop Breakdown")
    if len(buckets) <= 2:
        cols = st.columns(max(len(buckets), 1))
    else:
        cols = st.columns(2)
    for idx, b in enumerate(buckets):
        if not isinstance(b, dict):
            continue
        timing = b.get("timing", {}) if isinstance(b.get("timing"), dict) else {}
        pie_rows: list[dict[str, Any]] = []
        for label, key in timing_keys:
            seconds = to_float(timing.get(key))
            if seconds is not None and seconds > 0:
                pie_rows.append({"pass": label, "seconds": seconds})
        target = b.get("target_nv")
        n_claims = b.get("n_claims_total")
        header = f"Bucket {b.get('index')} — target_nv={target}, {n_claims} claims"
        with cols[idx % len(cols)]:
            st.markdown(f"##### {header}")
            if pie_rows:
                st.markdown(render_pie_svg(pie_rows), unsafe_allow_html=True)
            else:
                st.info("All timings were zero.")


def render_buckets_section(record: dict[str, Any]) -> None:
    """Summary table of the sumcheck bucket plan.

    Per-bucket timing lives in the Prover Timing tab and per-bucket claim
    counts live in the Claims tab, so this tab just shows the picker's
    plan and the topline numbers per bucket. Absent for older JSONL runs
    that predate per-bucket emission.
    """
    st.subheader("Sumcheck Buckets")
    sc_buckets = record.get("sc_buckets")
    if not isinstance(sc_buckets, dict):
        st.info("No per-bucket sumcheck stats in this record (older JSONL).")
        return
    buckets = sc_buckets.get("buckets") or []
    if not isinstance(buckets, list) or not buckets:
        st.info("Bucket list is empty.")
        return

    count = sc_buckets.get("count", len(buckets))
    st.markdown(f"**Plan:** {count} bucket(s).")

    summary_rows: list[dict[str, Any]] = []
    for b in buckets:
        if not isinstance(b, dict):
            continue
        included = b.get("included_nvs")
        included_str = ",".join(str(x) for x in included) if isinstance(included, list) else str(included)
        timing = b.get("timing", {}) if isinstance(b.get("timing"), dict) else {}
        summary_rows.append({
            "idx": b.get("index"),
            "target_nv": b.get("target_nv"),
            "included_nvs": included_str,
            "zerocheck claims": b.get("n_zerocheck_claims"),
            "sumcheck claims": b.get("n_sumcheck_claims"),
            "nozerocheck claims": b.get("n_nozerocheck_claims"),
            "total claims": b.get("n_claims_total"),
            "total time (s)": timing.get("total_time_s"),
            "sumcheck time (s)": timing.get("sumcheck_time_s"),
            "reduce sumcheck (s)": timing.get("reduce_sumcheck_time_s"),
            "nozero batch (s)": timing.get("nozerocheck_batching_time_s"),
        })
    st.markdown("#### Summary")
    st.dataframe(summary_rows, use_container_width=True, hide_index=True)


def render_memory_section(record: dict[str, Any]) -> None:
    """RSS-over-time curve for the bench_query span.

    Samples come from the tt-exec subscriber's background sampler thread
    (10 ms interval on Linux; no-op elsewhere). x-axis is elapsed ms from
    the first sample; y-axis is RSS in MiB. Vertical dashed markers show
    per-bucket sumcheck boundaries so it's easy to attribute a memory
    spike to a specific bucket.
    """
    st.subheader("Memory")
    memory = record.get("memory")
    if not isinstance(memory, dict):
        st.info("No memory samples in this record (older JSONL or non-Linux).")
        return
    samples = memory.get("samples")
    if not isinstance(samples, list) or not samples:
        st.info("Memory sample list is empty.")
        return

    # Samples arrive as [[wall_ms, rss_bytes], ...]. Convert to elapsed ms
    # from the first sample, so different runs can be compared on a common
    # 0-based axis regardless of when they ran.
    typed: list[tuple[int, int]] = []
    for item in samples:
        if not isinstance(item, list) or len(item) != 2:
            continue
        try:
            t = int(item[0])
            r = int(item[1])
        except (TypeError, ValueError):
            continue
        typed.append((t, r))
    if not typed:
        st.info("Memory samples were unparseable.")
        return
    t0 = typed[0][0]
    points = [(t - t0, r) for t, r in typed]
    peak = max(r for _, r in points)
    duration_ms = points[-1][0]

    col1, col2, col3 = st.columns(3)
    col1.metric("Peak RSS", f"{peak / (1024 * 1024):.1f} MiB")
    col2.metric("Samples", str(memory.get("sample_count", len(points))))
    col3.metric("Sample interval", f"{memory.get('sample_interval_ms', '?')} ms")

    # Collect bucket boundaries (wall-clock ms → elapsed ms) so we can
    # overlay dashed lines at bucket transitions.
    sc_buckets = record.get("sc_buckets")
    bucket_markers: list[tuple[int, str]] = []
    if isinstance(sc_buckets, dict):
        for b in sc_buckets.get("buckets") or []:
            if not isinstance(b, dict):
                continue
            wall_start = b.get("wall_start_ms")
            try:
                x = int(wall_start) - t0
            except (TypeError, ValueError):
                continue
            if 0 <= x <= duration_ms:
                bucket_markers.append((x, f"b{b.get('index')} nv={b.get('target_nv')}"))

    st.markdown(render_line_chart_svg(points, peak, duration_ms, bucket_markers), unsafe_allow_html=True)

    with st.expander("Raw samples", expanded=False):
        st.markdown(
            f"First sample at wall_clock_ms = {t0}, "
            f"{len(points)} samples over {duration_ms} ms."
        )
        st.dataframe(
            [{"elapsed_ms": x, "rss_mib": f"{r / (1024 * 1024):.2f}"} for x, r in points],
            use_container_width=True,
            hide_index=True,
        )


def render_line_chart_svg(
    points: list[tuple[int, int]],
    peak_bytes: int,
    duration_ms: int,
    markers: list[tuple[int, str]],
) -> str:
    """Inline SVG line chart. RSS in MiB on Y, elapsed ms on X. Vertical
    dashed lines at each marker with a small text label at the top."""
    if not points or duration_ms <= 0 or peak_bytes <= 0:
        return ""
    chart_left = 60
    chart_right_pad = 20
    chart_top = 20
    chart_height = 260
    chart_width = 900
    inner_w = chart_width - chart_left - chart_right_pad

    x_of = lambda t: chart_left + (t / duration_ms) * inner_w if duration_ms > 0 else chart_left
    y_of = lambda r: chart_top + chart_height - (r / peak_bytes) * chart_height

    # Build polyline points.
    poly = " ".join(f"{x_of(t):.2f},{y_of(r):.2f}" for t, r in points)

    parts = [
        f'<svg viewBox="0 0 {chart_width} {chart_top + chart_height + 60}" '
        f'width="100%" height="{chart_top + chart_height + 60}" '
        f'xmlns="http://www.w3.org/2000/svg">',
        f'<text x="{chart_left}" y="14" font-size="14" font-weight="bold" fill="#222">'
        f'RSS over time — peak {peak_bytes / (1024 * 1024):.1f} MiB</text>',
        # Axes
        f'<line x1="{chart_left}" y1="{chart_top}" x2="{chart_left}" '
        f'y2="{chart_top + chart_height}" stroke="#555" />',
        f'<line x1="{chart_left}" y1="{chart_top + chart_height}" '
        f'x2="{chart_left + inner_w}" y2="{chart_top + chart_height}" stroke="#555" />',
    ]

    # Y ticks (5 rows, MiB labels).
    for tick_idx in range(5):
        frac = (4 - tick_idx) / 4
        value_bytes = peak_bytes * frac
        y = chart_top + chart_height * tick_idx / 4
        parts.append(
            f'<line x1="{chart_left}" y1="{y:.2f}" '
            f'x2="{chart_left + inner_w}" y2="{y:.2f}" stroke="#e5e7eb" />'
        )
        parts.append(
            f'<text x="{chart_left - 8}" y="{y + 4:.2f}" text-anchor="end" '
            f'font-size="11" fill="#555">{value_bytes / (1024 * 1024):.0f} MiB</text>'
        )

    # X ticks (5 columns, ms labels).
    for tick_idx in range(6):
        frac = tick_idx / 5
        value_ms = duration_ms * frac
        x = chart_left + inner_w * frac
        parts.append(
            f'<text x="{x:.2f}" y="{chart_top + chart_height + 16}" '
            f'text-anchor="middle" font-size="11" fill="#555">{value_ms:.0f} ms</text>'
        )

    # Bucket boundary markers — vertical dashed lines with labels alternating
    # top/bottom to avoid overlap.
    marker_colors = ["#e11d48", "#7c3aed", "#0891b2", "#ca8a04", "#059669"]
    for idx, (x_ms, label) in enumerate(markers):
        x = x_of(x_ms)
        color = marker_colors[idx % len(marker_colors)]
        parts.append(
            f'<line x1="{x:.2f}" y1="{chart_top}" x2="{x:.2f}" '
            f'y2="{chart_top + chart_height}" stroke="{color}" '
            f'stroke-width="1.5" stroke-dasharray="4,3" />'
        )
        # Alternate label y so overlapping markers stay readable.
        label_y = chart_top - 6 if idx % 2 == 0 else chart_top + chart_height + 34
        parts.append(
            f'<text x="{x:.2f}" y="{label_y:.2f}" text-anchor="middle" '
            f'font-size="10" fill="{color}">{escape(label)}</text>'
        )

    # The line itself last, so it draws on top of gridlines.
    parts.append(
        f'<polyline points="{poly}" fill="none" stroke="#2563eb" stroke-width="1.5" />'
    )
    parts.append("</svg>")
    return "".join(parts)


def render_plans_section(record: dict[str, Any]) -> None:
    st.subheader("Plans")
    plans = record.get("plans", {})
    if not isinstance(plans, dict) or not plans:
        st.info("No plan graphviz data found for this run.")
        return

    stage_names = order_plan_stages(plans.keys())
    selected_stage = st.selectbox(
        "Plan Stage",
        stage_names,
        format_func=lambda name: name.replace("_", " "),
    )
    dot = plans.get(selected_stage)
    if not isinstance(dot, str) or not dot.strip():
        st.info("Selected plan is empty.")
        return
    render_zoomable_graphviz(dot)


def collect_mem_samples_by_query(records: list[dict[str, Any]]) -> dict[str, list[tuple[int, int]]]:
    """Group streaming `mem_sample` records by query. Used as an OOM
    fallback — the sampler thread flushes each sample to disk as its
    own record, so even if the bench_query span never closes (because
    the process got SIGKILL'd) we can still reconstruct the RSS curve
    for the killed query.
    """
    by_query: dict[str, list[tuple[int, int]]] = {}
    for r in records:
        if r.get("kind") != "mem_sample":
            continue
        q = r.get("query")
        if not isinstance(q, str):
            continue
        try:
            wall_ms = int(r.get("wall_ms"))
            rss = int(r.get("rss_bytes"))
        except (TypeError, ValueError):
            continue
        by_query.setdefault(q, []).append((wall_ms, rss))
    # Sort each series so the dashboard sees them in wall-clock order.
    for series in by_query.values():
        series.sort(key=lambda p: p[0])
    return by_query


def synthesize_oom_record(query: str, samples: list[tuple[int, int]]) -> dict[str, Any]:
    """Build a minimal bench_query-shaped record for a query that only
    has streaming mem_samples on disk (i.e. it OOM'd before the span
    closed). Everything downstream (tabs) will show "no data" for
    non-memory sections — which is exactly what happened.
    """
    peak = max((r for _, r in samples), default=0)
    return {
        "kind": "bench_query",
        "query": query,
        "timestamp": "(oom — reconstructed from mem_samples)",
        "timestamp_utc": "",
        "memory": {
            "peak_rss_bytes": peak,
            "sample_count": len(samples),
            "sample_interval_ms": 10,
            "samples": [[t, r] for t, r in samples],
        },
        "_oom_reconstructed": True,
    }


def main() -> None:
    st.set_page_config(page_title="TT Bench Dashboard", layout="wide")
    st.title("TT Bench Dashboard")

    st.sidebar.header("Data")
    path = st.sidebar.text_input("JSONL path", str(DEFAULT_JSONL_PATH))

    records = load_jsonl(path)
    if not records:
        st.warning(f"No JSONL records found at {path}")
        return

    bench_records = [record for record in records if record.get("kind") == "bench_query"]

    # OOM fallback: if a query only shows up as streaming mem_sample
    # records with no matching bench_query record, synthesize a minimal
    # record so it appears in the Query selector and its Memory tab
    # renders. Any query that DOES have a bench_query record keeps its
    # real one (streaming samples are already embedded there).
    mem_by_query = collect_mem_samples_by_query(records)
    completed_queries = {r.get("query") for r in bench_records}
    for q, samples in mem_by_query.items():
        if q not in completed_queries and samples:
            bench_records.append(synthesize_oom_record(q, samples))

    if not bench_records:
        st.warning("No bench_query records found in the JSONL file.")
        return

    query_options = sorted({record.get("query", "") for record in bench_records})
    selected_query = st.sidebar.selectbox("Query", query_options)
    filtered_records = [record for record in bench_records if record.get("query") == selected_query]
    filtered_records.sort(key=lambda record: record.get("timestamp", ""), reverse=True)

    timestamp_options = [record.get("timestamp", "") for record in filtered_records]
    selected_timestamp = st.sidebar.selectbox("Run", timestamp_options)
    record = next(r for r in filtered_records if r.get("timestamp") == selected_timestamp)
    if record.get("_oom_reconstructed"):
        st.sidebar.warning("This run OOM'd — only memory samples survived.")

    (
        overview_tab,
        results_tab,
        proof_size_tab,
        claims_tab,
        prover_timing_tab,
        buckets_tab,
        memory_tab,
        plans_tab,
        extra_tab,
    ) = st.tabs(
        [
            "Overview",
            "Results",
            "Proof Size",
            "Claims",
            "Prover Timing",
            "Buckets",
            "Memory",
            "Plans",
            "Extra",
        ]
    )

    with overview_tab:
        st.subheader("Runs")
        st.dataframe(render_overview_rows(filtered_records), use_container_width=True, hide_index=True)

    with results_tab:
        results = record.get("results")
        if isinstance(results, dict):
            render_results_section(results)
        else:
            st.info("No results metadata found for this run.")

    with proof_size_tab:
        render_proof_size_section(record.get("proof_size", {}))

    with claims_tab:
        claims = record.get("claims")
        if isinstance(claims, dict):
            render_claims_section(claims, record.get("sc_buckets"))
        else:
            st.info("No claims metadata found for this run.")

    with prover_timing_tab:
        render_prover_timing_section(record)

    with buckets_tab:
        render_buckets_section(record)

    with memory_tab:
        render_memory_section(record)

    with plans_tab:
        render_plans_section(record)

    with extra_tab:
        st.subheader("Extra")
        extra = record.get("extra", {})
        if isinstance(extra, dict) and extra:
            st.json(extra, expanded=False)
        else:
            st.info("No extra metadata found for this run.")


if __name__ == "__main__":
    main()
