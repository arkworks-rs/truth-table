import duckdb

# Paths
input_path = "title-sanitized.parquet"
output_path = "sanitized.parquet"

# Open DuckDB
con = duckdb.connect()

# Load Parquet to get column names
df = con.execute(f"SELECT * FROM read_parquet('{input_path}') LIMIT 1").fetchdf()
column_names = df.columns

# Build WHERE clause: col1 IS NOT NULL AND col2 IS NOT NULL AND ...
where_clause = " AND ".join([f"{col} IS NOT NULL" for col in column_names])

# Full SQL query
query = f"""
    SELECT *
    FROM read_parquet('{input_path}')
    WHERE {where_clause}
"""

# Run query and save result to Parquet
con.execute(f"COPY ({query}) TO '{output_path}' (FORMAT 'parquet')")