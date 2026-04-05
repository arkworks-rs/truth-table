#!/usr/bin/env python3
"""
preprocess.py

This script mirrors the preprocessing in `tpch-data`:

1. Expands Date32/Date64/Timestamp columns by appending derived fields:
   - Date32: <name>_year, <name>_month, <name>_day
   - Date64/Timestamp: <name>_year, <name>_month, <name>_day, <name>_time
2. Adds a stable Int64 row id column (ROW_ID_COL_NAME).
3. Adds a boolean activator column (ACTIVATOR_COL_NAME):
   - True for original rows.
4. Pads to the next power of two by duplicating the last row:
   - Appended rows get activator=False.

If the number of rows is already a power of two, no padding is done.
----------------------------------------------------------------------
USAGE:
    python preprocess.py input.parquet
        # Overwrites input file by default

    python preprocess.py input.parquet -o output.parquet
        # Writes the result to output.parquet instead

OPTIONS:
    --activator-name NAME
        Change the name of the activator column (default: ACTIVATOR_COL_NAME)
    --row-id-name NAME
        Change the name of the row id column (default: ROW_ID_COL_NAME)

----------------------------------------------------------------------
VIRTUAL ENVIRONMENT SETUP:

1. Create a virtual environment:
       python3 -m venv venv

2. Activate it:
       source venv/bin/activate        # On Linux/Mac
       venv\\Scripts\\activate         # On Windows (PowerShell)

3. Install dependencies:
       pip install -r requirements.txt

   The requirements.txt should contain:
       pyarrow>=14.0.0

4. Run the script:
       python preprocess.py input.parquet -o output.parquet

5. Deactivate the environment when done:
       deactivate
----------------------------------------------------------------------
"""

import argparse
try:
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency: pyarrow. Install with: pip install -r tt-scripts/requirements.txt"
    ) from exc

ACTIVATOR_COL_NAME = "__activator__"
ROW_ID_COL_NAME = "__row_id__"


def next_power_of_two(n: int) -> int:
    if n <= 1:
        return max(1, n)
    return 1 << (n - 1).bit_length()


def read_parquet_to_table(path: str) -> pa.Table:
    return pq.read_table(path)


def write_table_to_parquet(table: pa.Table, path: str) -> None:
    pq.write_table(table, path)


def _ensure_int32(array: pa.Array) -> pa.Array:
    return pc.cast(array, pa.int32())


def expand_table(table: pa.Table) -> pa.Table:
    fields = []
    columns = []

    for field, column in zip(table.schema, table.columns):
        name = field.name
        columns.append(column)
        fields.append(field)

        if pa.types.is_date32(field.type):
            year = _ensure_int32(pc.year(column))
            month = _ensure_int32(pc.month(column))
            day = _ensure_int32(pc.day(column))
            fields.extend(
                [
                    pa.field(f"{name}_year", pa.int32(), field.nullable),
                    pa.field(f"{name}_month", pa.int32(), field.nullable),
                    pa.field(f"{name}_day", pa.int32(), field.nullable),
                ]
            )
            columns.extend([year, month, day])
        elif pa.types.is_date64(field.type):
            ts = pc.cast(column, pa.timestamp("ms"))
            year = _ensure_int32(pc.year(ts))
            month = _ensure_int32(pc.month(ts))
            day = _ensure_int32(pc.day(ts))
            time = _ensure_int32(
                pc.add(
                    pc.add(pc.multiply(pc.hour(ts), 3600), pc.multiply(pc.minute(ts), 60)),
                    pc.second(ts),
                )
            )
            fields.extend(
                [
                    pa.field(f"{name}_year", pa.int32(), field.nullable),
                    pa.field(f"{name}_month", pa.int32(), field.nullable),
                    pa.field(f"{name}_day", pa.int32(), field.nullable),
                    pa.field(f"{name}_time", pa.int32(), field.nullable),
                ]
            )
            columns.extend([year, month, day, time])
        elif pa.types.is_timestamp(field.type):
            ts = column
            year = _ensure_int32(pc.year(ts))
            month = _ensure_int32(pc.month(ts))
            day = _ensure_int32(pc.day(ts))
            time = _ensure_int32(
                pc.add(
                    pc.add(pc.multiply(pc.hour(ts), 3600), pc.multiply(pc.minute(ts), 60)),
                    pc.second(ts),
                )
            )
            fields.extend(
                [
                    pa.field(f"{name}_year", pa.int32(), field.nullable),
                    pa.field(f"{name}_month", pa.int32(), field.nullable),
                    pa.field(f"{name}_day", pa.int32(), field.nullable),
                    pa.field(f"{name}_time", pa.int32(), field.nullable),
                ]
            )
            columns.extend([year, month, day, time])

    return pa.Table.from_arrays(columns, schema=pa.schema(fields))


def add_row_id_and_activator(table: pa.Table, row_id_col: str, activator_col: str) -> pa.Table:
    n = table.num_rows
    row_id = pa.array(range(n), type=pa.int64())
    activator = pa.array([True] * n, type=pa.bool_())
    return table.append_column(row_id_col, row_id).append_column(activator_col, activator)


def pad_to_power_of_two(table: pa.Table, row_id_col: str, activator_col: str) -> pa.Table:
    n0 = table.num_rows
    if n0 == 0:
        return table

    target = next_power_of_two(n0)
    pad = target - n0
    if pad <= 0:
        return table

    last_idx = n0 - 1
    pad_columns = []
    for col in table.columns:
        arr = col.combine_chunks()
        one = arr.slice(last_idx, 1)
        repeated = pa.concat_arrays([one] * pad)
        pad_columns.append(repeated)

    next_row_id = n0
    pad_row_id = pa.array(range(next_row_id, next_row_id + pad), type=pa.int64())
    pad_activator = pa.array([False] * pad, type=pa.bool_())
    pad_columns[-2] = pad_row_id
    pad_columns[-1] = pad_activator

    out_columns = []
    for orig, pad_arr in zip(table.columns, pad_columns):
        orig_arr = orig.combine_chunks()
        out_columns.append(pa.concat_arrays([orig_arr, pad_arr]))
    return pa.Table.from_arrays(out_columns, schema=table.schema)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Expand date/time columns, add row id + activator, and pad by duplicating the "
            "last row until the row count is a power of two."
        )
    )
    parser.add_argument("input", help="Path to input Parquet file")
    parser.add_argument(
        "-o",
        "--output",
        help="Path to output Parquet file (default: overwrite input)",
        default=None,
    )
    parser.add_argument(
        "--activator-name",
        default=ACTIVATOR_COL_NAME,
        help="Name of the activator column (default: __activator__)",
    )
    parser.add_argument(
        "--row-id-name",
        default=ROW_ID_COL_NAME,
        help="Name of the row id column (default: __row_id__)",
    )
    args = parser.parse_args()

    in_path = args.input
    out_path = args.output or in_path
    activator_col = args.activator_name
    row_id_col = args.row_id_name

    # 1) Read
    table = read_parquet_to_table(in_path)
    original_rows = table.num_rows

    # 2) Expand date/time columns
    table = expand_table(table)

    # 3) Add row id and activator
    table = add_row_id_and_activator(table, row_id_col, activator_col)

    # 4) Pad to power of two by duplicating last row
    table = pad_to_power_of_two(table, row_id_col, activator_col)

    # Write
    write_table_to_parquet(table, out_path)

    print(
        f"Input rows: {original_rows} | Final (power of 2): {table.num_rows} | "
        f"Appended: {table.num_rows - original_rows} | Output: {out_path}"
    )


if __name__ == "__main__":
    main()
