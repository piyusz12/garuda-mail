"""
Phase 5 output: per-session JSON records + ML feature matrix
(Phase 5, Section 48-49, 64).

Always keep both: the human-readable record (for explainability, Section
61) and the numeric matrix (for Phase 6). Never store only the vector.
"""

import json
import os
from typing import Any, Dict, List, Optional

try:
    from .schema import FEATURE_SCHEMA_VERSION, feature_names, write_schema
except (ImportError, ValueError):
    from schema import FEATURE_SCHEMA_VERSION, feature_names, write_schema


def session_record(session_id: str, features: Dict[str, Any]) -> dict:
    """Section 48: human-readable per-session feature record."""
    return {
        "session_id": session_id,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "features": features,
    }


def write_session_record(path: str, session_id: str, features: Dict[str, Any]) -> None:
    with open(path, "w") as f:
        json.dump(session_record(session_id, features), f, indent=2, default=_json_safe)


def _json_safe(value: Any) -> Any:
    import math
    if isinstance(value, float) and math.isnan(value):
        return None
    raise TypeError(f"Object of type {type(value)} is not JSON serializable")


def build_feature_matrix(
    rows: List[Dict[str, Any]],
    session_ids: List[str],
    columns: Optional[List[str]] = None,
):
    """
    Builds a pandas DataFrame with one row per session and a stable column
    order (Section 2, 39). Requires pandas; imported lazily so the rest of
    the package works without a hard pandas dependency.
    """
    import pandas as pd

    cols = columns if columns is not None else feature_names()
    data: Dict[str, Any] = {"session_id": session_ids}
    for col in cols:
        data[col] = [row.get(col) for row in rows]
    df = pd.DataFrame(data)
    return df


def write_feature_matrix_parquet(df: Any, path: str) -> None:
    df.to_parquet(path, index=False)


def export_dataset(
    rows: List[Dict[str, Any]],
    session_ids: List[str],
    output_dir: str,
    matrix_filename: str = "feature_matrix_v1.parquet",
    schema_filename: str = "feature_schema_v1.json",
    write_per_session_json: bool = True,
) -> Dict[str, str]:
    """
    Section 64's full Phase 5 output bundle:
      output/
        features/FLOW-XXXXX.json      (per session, optional)
        feature_matrix_v1.parquet
        feature_schema_v1.json
    Returns a dict of the paths written.
    """
    os.makedirs(output_dir, exist_ok=True)
    written: Dict[str, str] = {}

    if write_per_session_json:
        for sid, row in zip(session_ids, rows):
            path = os.path.join(output_dir, f"{sid}.json")
            write_session_record(path, sid, row)

    matrix_path = os.path.join(output_dir, matrix_filename)
    df = build_feature_matrix(rows, session_ids)
    write_feature_matrix_parquet(df, matrix_path)
    written["matrix"] = matrix_path

    schema_path = os.path.join(output_dir, schema_filename)
    write_schema(schema_path)
    written["schema"] = schema_path

    return written
