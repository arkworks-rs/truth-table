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


def render_claims_section(claims: dict[str, Any]) -> None:
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

    render_lookup_claims_section(claims.get("lookups"))


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


def render_plans_section(record: dict[str, Any]) -> None:
    st.subheader("Plans")
    plans = record.get("plans", {})
    if not isinstance(plans, dict) or not plans:
        st.info("No plan graphviz data found for this run.")
        return

    stage_names = list(plans.keys())
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

    overview_tab, results_tab, proof_size_tab, claims_tab, prover_timing_tab, plans_tab, extra_tab = st.tabs(
        ["Overview", "Results", "Proof Size", "Claims", "Prover Timing", "Plans", "Extra"]
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
            render_claims_section(claims)
        else:
            st.info("No claims metadata found for this run.")

    with prover_timing_tab:
        render_prover_timing_section(record)

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
