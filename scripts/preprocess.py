#!/usr/bin/env python3
"""
sanitize_and_pad_parquet.py

This script processes a Parquet file in three steps:

1. Removes any rows that contain NULL values in any column.
2. Adds a boolean column called ACTIVATOR_COL_NAME:
   - Sets activator=True for all remaining (original) rows.
3. Pads the table so that the total number of rows is a power of two:
   - Duplicates the last row as many times as needed.
   - Sets activator=False for all duplicated rows.

If the number of rows is already a power of two, no padding is done.
If all rows are removed by the null filter, the script raises an error.

----------------------------------------------------------------------
USAGE:
    python sanitize_and_pad_parquet.py input.parquet
        # Overwrites input file by default

    python sanitize_and_pad_parquet.py input.parquet -o output.parquet
        # Writes the result to output.parquet instead

OPTIONS:
    --activator-name NAME
        Change the name of the activator column (default: ACTIVATOR_COL_NAME)

----------------------------------------------------------------------
VIRTUAL ENVIRONMENT SETUP:

1. Create a virtual environment:
       python3 -m venv venv

2. Activate it:
       source venv/bin/activate        # On Linux/Mac
       venv\Scripts\activate           # On Windows (PowerShell)

3. Install dependencies:
       pip install -r requirements.txt

   The requirements.txt should contain:
       pandas>=2.0.0
       pyarrow>=14.0.0
       numpy>=1.24.0

4. Run the script:
       python sanitize_and_pad_parquet.py input.parquet -o output.parquet

5. Deactivate the environment when done:
       deactivate
----------------------------------------------------------------------
"""

import argparse
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


def next_power_of_two(n: int) -> int:
    if n <= 1:
        return max(1, n)
    return 1 << (n - 1).bit_length()


def read_parquet_to_pandas(path: str) -> pd.DataFrame:
    table = pq.read_table(path)
    return table.to_pandas(types_mapper=pd.ArrowDtype)


def write_pandas_to_parquet(df: pd.DataFrame, path: str) -> None:
    table_out = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(table_out, path)


def sanitize_drop_null_rows(df: pd.DataFrame) -> pd.DataFrame:
    # Drop any row that contains at least one null
    return df.dropna(how="any").reset_index(drop=True)


def pad_by_duplicating_last_row(df: pd.DataFrame, activator_col: str) -> pd.DataFrame:
    n0 = len(df)
    if n0 == 0:
        raise ValueError(
            "After removing rows with nulls, no rows remain; cannot duplicate last row."
        )

    # Ensure activator exists and is True for all current rows
    df[activator_col] = True

    target = next_power_of_two(n0)
    pad = target - n0
    if pad <= 0:
        # already a power of two; nothing to append
        out = df
    else:
        last_row = df.iloc[-1:].copy()
        pad_df = pd.concat([last_row] * pad, ignore_index=True)
        pad_df[activator_col] = False
        out = pd.concat([df, pad_df], ignore_index=True)

    # Defensive: ensure no nulls (shouldn’t happen since we only duplicated)
    if out.isna().any().any():
        raise RuntimeError("Unexpected nulls found after padding.")

    out[activator_col] = out[activator_col].astype(bool)
    return out


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Remove rows containing nulls, add 'activator' column, "
            "and pad by duplicating the last row until row count is a power of two."
        )
    )
    parser.add_argument("input", help="Path to input Parquet file")
    parser.add_argument(
        "-o", "--output",
        help="Path to output Parquet file (default: overwrite input)",
        default=None,
    )
    parser.add_argument(
        "--activator-name",
        default=ACTIVATOR_COL_NAME,
        help="Name of the activator column (default: activator)",
    )
    args = parser.parse_args()

    in_path = args.input
    out_path = args.output or in_path
    activator_col = args.activator_name

    # 1) Read
    df = read_parquet_to_pandas(in_path)
    original_rows = len(df)

    # 2) Remove any rows with nulls
    df = sanitize_drop_null_rows(df)
    kept_rows = len(df)

    # 3 & 4) Add activator=True to current rows and pad by duplicating last row
    df2 = pad_by_duplicating_last_row(df, activator_col)
    final_rows = len(df2)

    # Write
    write_pandas_to_parquet(df2, out_path)

    print(
        f"Input rows: {original_rows} | After null-filter: {kept_rows} | "
        f"Final (power of 2): {final_rows} | Appended: {final_rows - kept_rows} | Output: {out_path}"
    )


if __name__ == "__main__":
    main()