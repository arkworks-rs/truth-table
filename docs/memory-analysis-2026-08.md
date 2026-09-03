# Bench-scale memory analysis (LIKE infix lineitem, 2026-08-09)

## Setup

Workload: `SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'`
at bench scale (2^24 rows, `TT_SUMCHECK_STREAM_K` unset → auto-streaming
enabled).

Memsnap captured with `TT_MEMSNAP=1` at
`after_compile_uv_pcs_subproof` (i.e. the tracker's state right after
the last compile step, when persistent Vec<F> holdings are largest).

## Tracker persistent state — final phase

```
Total polys:            117
Total bytes:            16.51 GiB
```

| MLE storage kind | count | bytes    | avg poly size |
|------------------|------:|---------:|--------------:|
| **field**        | **52** | **15.85 GiB** | **312 MiB** |
| u32              | 11    | 0.26 GiB | 24 MiB |
| u64              | 2     | 0.25 GiB | 128 MiB |
| u8               | 15    | 0.13 GiB | 9 MiB |
| bit              | 25    | 0.02 GiB | 0.7 MiB |
| rle              | 8     | negligible | — |
| lazy_inv         | 2     | negligible | — |
| const            | 2     | negligible | — |

Top-10 individual polys are all **`field` @ nv=24** (512 MiB each,
5.12 GiB total). The remaining ~42 `field` polys average ~260 MiB
apiece — presumably at nv=22-23 (activator sub-polys, intermediates,
smaller side segments).

## What this tells us

**Field storage is the whole remaining budget.** All other kinds
together sum to 0.66 GiB. Every memory optimization landed this
session (add_scalar virtualization, RLE window activator, U32-back
shift poly, lazy phat backing, auto-streaming) attacks either
transient burst OR non-Field storage. The persistent Field storage
survives all of them because `Field` IS the natural storage — there's
nothing more compact to migrate to within the current MLE type.

## Attack surface for further reduction

Ranked by expected impact:

### (1) Better encoding of arrow → MLE for currently-Field columns

`encoding::encode_arrow_array_to_field` picks the smallest MLE
storage that faithfully represents each source column. Anything with
negative values, decimals, floats, or field-native hashes falls back
to `MLEStorage::Field`. Levers:

  - **Add `MLEStorage::U16`**: currently `UInt16Array` inputs promote
    to `U32` (see `EncodedBacking::U16s` path); adding `U16` storage
    at the MLE layer would halve those polys. Modest win — the
    `u32`-bucket total is 0.26 GiB, so upper-bound saving is 0.13
    GiB.
  - **Packed-decimal storage**: `Decimal128` columns arithmetize
    straight to `Field` today (254-bit scalar per value). A packed
    16-byte-per-value storage (half the field-element size) would
    save ~50% on the decimal columns. lineitem has 4 decimal
    columns (`l_quantity`, `l_extendedprice`, `l_discount`,
    `l_tax`) — each at nv=24 = 512 MiB × 4 = 2 GiB, so upper-bound
    saving is ~1 GiB.
  - **Signed-int-with-negatives via absolute + sign bit**: currently
    negative int64 → `Field` (via `MODULUS - abs(v)`). A `SignedU64`
    variant carrying `(magnitude: u64, sign: Bit)` per value would
    be 9 bytes vs 32. Applies to signed integer columns of lineitem
    (`l_orderkey`, `l_partkey`, `l_suppkey`, `l_linenumber` if any
    entries are negative — usually not, but the encoder can't prove
    it at ingest without scanning). Upper-bound saving: maybe 1-2 GiB
    depending on how many columns get pushed.

Combined ceiling for (1): ~2-3 GiB reduction, at nontrivial
implementation cost (each new variant means wiring through all match
arms — `inner_num_vars`, `lift`, `heap_bytes`, `detect_redundancy`,
`is_constant`, `check`, `digest`, `serialize`, plus pst13 commit,
snapshot, and the streaming sumcheck read path — same shape as the
`LazyInverseShifted` work from ark-piop@69e81ef).

### (2) Streaming-aware commit for Field polys

Currently `MLEStorage::Field` MLEs go through `pst13::commit` as
a full `Vec<F>` MSM. For polys that will only be evaluated at a
handful of points (typical for sumcheck-verifier-side eval claims),
we could defer materialization by wrapping them in a lazy
"compute-on-demand" storage variant.

This would attack the **transient** burst during commit rather than
the persistent state, so it's orthogonal to the persistent budget
here. It's the same shape as the auto-streaming work but applied to
the PCS commit path instead of the sumcheck loop.

### (3) Column pruning at the query planner level

`SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'`
only truly needs 2 lineitem columns (`l_returnflag` for projection,
`l_comment` for the predicate). DataFusion's projection pushdown
_should_ prune to just those before TableScan runs — check
`table_scan/mod.rs::projected_schema`. If pruning is working
correctly, the 52 `field` polys are all from the 2 needed columns
(primary + side segments) plus per-query derived polys. If it's
NOT working, most polys are wasted.

Quick check: for lineitem's 2 string columns loaded, each contributes
1 primary + up to 5 side segments = up to 12 base polys per query.
Observing 52 field polys means ~40 are computed/derived (LIKE-gadget
intermediates, sumcheck aggregation temporaries, zerocheck-to-sumcheck
eq_x_r polys). Reducing those requires per-gadget optimization,
same class of work as `phat B` from this session.

## Recommendation

If the goal is to bring bench-scale peak RSS below the current 65 GiB
by another 30-50%, the highest-leverage single attack is **(1)
packed-decimal storage + signed-int-with-negatives storage** —
combined potential ~2-3 GiB off the persistent 15.85 GiB Field
bucket. This lifts the compression-based ceiling that everything
else lives under.

If the goal is to bring bench-scale below ~50 GiB, that requires
both (1) and (2) — attacking both persistent AND transient sides —
plus revisiting per-gadget compute-poly reuse.

Neither of these was implemented in the 2026-08 session; both are
scoped and left for follow-up.
