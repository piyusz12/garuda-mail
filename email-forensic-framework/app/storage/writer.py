"""
app/storage/writer.py

Writes one ProtocolAnalysis per session to output/analysis/<session_id>.json,
the contract Phase 3 reads from.
"""

from __future__ import annotations

import json
from pathlib import Path


def write_analysis(analysis, output_dir: str = "output/analysis") -> Path:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{analysis.session_id}.json"
    path.write_text(json.dumps(analysis.to_dict(), indent=2))
    return path
