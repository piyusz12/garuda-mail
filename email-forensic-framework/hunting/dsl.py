"""
Phase 23 - Hunt Query Language (HQL) Parser and AST.
Parses domain-specific threat hunting syntax.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import re

@dataclass
class HuntQueryCondition:
    field: str
    operator: str  # =, !=, IN, NOT IN, <, >, <=, >=, CONTAINS, IS
    value: Any

@dataclass
class HuntQueryAST:
    hunt_name: str
    source_entity: str
    conditions: List[HuntQueryCondition] = field(default_factory=list)
    within_window: Optional[str] = None  # e.g., "7d", "90d", "24h"
    after_event: Optional[str] = None    # e.g., "remediation_event"
    historical_conditions: List[HuntQueryCondition] = field(default_factory=list)
    raw_query: str = ""


class HQLParser:
    """Parses HQL query strings into executable AST objects."""

    @classmethod
    def parse(cls, query_str: str) -> HuntQueryAST:
        raw = query_str.strip()
        # Normalization
        tokens = raw.split()
        if not tokens or tokens[0].upper() != "HUNT":
            raise ValueError("Query must begin with HUNT keyword")

        hunt_name = tokens[1]
        
        # Find FROM
        upper_tokens = [t.upper() for t in tokens]
        if "FROM" not in upper_tokens:
            raise ValueError("Query missing FROM clause")
        from_idx = upper_tokens.index("FROM")
        source_entity = tokens[from_idx + 1].lower()

        # Extract WHERE clause, WITHIN clause, AFTER clause
        ast = HuntQueryAST(hunt_name=hunt_name, source_entity=source_entity, raw_query=raw)

        # Parse WITHIN if present
        within_match = re.search(r"\bWITHIN\s+([0-9]+[smhd])\b", raw, re.IGNORECASE)
        if within_match:
            ast.within_window = within_match.group(1).lower()

        # Parse AFTER if present
        after_match = re.search(r"\bAFTER\s+([A-Za-z0-9_-]+)\b", raw, re.IGNORECASE)
        if after_match:
            ast.after_event = after_match.group(1)

        # Parse WHERE section
        if "WHERE" in upper_tokens:
            where_idx = upper_tokens.index("WHERE")
            # Slice up to WITHIN or AFTER if they appear later
            end_idx = len(tokens)
            for kw in ("WITHIN", "AFTER"):
                if kw in upper_tokens and upper_tokens.index(kw) > where_idx:
                    end_idx = min(end_idx, upper_tokens.index(kw))

            where_tokens = tokens[where_idx + 1:end_idx]
            where_text = " ".join(where_tokens)
            
            # Split conditions on AND
            cond_parts = re.split(r"\bAND\b", where_text, flags=re.IGNORECASE)
            for part in cond_parts:
                cond = cls._parse_single_condition(part.strip())
                if cond:
                    if "asset.history." in cond.field.lower() or "history." in cond.field.lower():
                        ast.historical_conditions.append(cond)
                    else:
                        ast.conditions.append(cond)

        return ast

    @classmethod
    def _parse_single_condition(cls, cond_text: str) -> Optional[HuntQueryCondition]:
        cond_text = cond_text.strip()
        if not cond_text:
            return None

        # Check IN / NOT IN
        in_match = re.match(r"^([\w\.]+)\s+(NOT\s+IN|IN)\s+\[(.*)\]$", cond_text, re.IGNORECASE)
        if in_match:
            field = in_match.group(1)
            op = in_match.group(2).upper()
            raw_vals = in_match.group(3)
            vals = [v.strip().strip("'\"") for v in raw_vals.split(",") if v.strip()]
            return HuntQueryCondition(field=field, operator=op, value=vals)

        # Check standard operators: =, !=, <=, >=, <, >
        op_match = re.match(r"^([\w\.]+)\s*(=|!=|<=|>=|<|>)\s*(.+)$", cond_text)
        if op_match:
            field = op_match.group(1)
            op = op_match.group(2)
            raw_val = op_match.group(3).strip().strip("'\"")
            
            # Parse booleans and numbers if applicable
            val: Any = raw_val
            if raw_val.lower() == "true": val = True
            elif raw_val.lower() == "false": val = False
            else:
                try:
                    if "." in raw_val:
                        val = float(raw_val)
                    else:
                        val = int(raw_val)
                except ValueError:
                    val = raw_val

            return HuntQueryCondition(field=field, operator=op, value=val)

        return None
