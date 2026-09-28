"""
Phase 23 - Detection Rule Evaluator
Evaluates SIGNATURE, THRESHOLD, ANOMALY, STATISTICAL, BEHAVIORAL, GRAPH, and ML rule logic.
"""
from typing import Dict, Any, List, Tuple
import re

class DetectionEvaluator:
    """Evaluates various rule types against telemetry events or aggregated state."""

    @classmethod
    def evaluate(cls, rule_type: str, logic: Dict[str, Any], event_data: Dict[str, Any], context: Dict[str, Any] = None) -> Tuple[bool, List[str]]:
        """
        Returns (is_match, explanations).
        """
        context = context or {}
        rule_type = rule_type.upper()

        if rule_type == "SIGNATURE":
            return cls._eval_signature(logic, event_data)
        elif rule_type == "THRESHOLD":
            return cls._eval_threshold(logic, event_data, context)
        elif rule_type in ("ANOMALY", "STATISTICAL"):
            return cls._eval_statistical(logic, event_data, context)
        elif rule_type in ("BEHAVIORAL", "GRAPH"):
            return cls._eval_behavioral(logic, event_data, context)
        elif rule_type == "ML":
            return cls._eval_ml(logic, event_data, context)
        else:
            return cls._eval_signature(logic, event_data)

    @classmethod
    def _eval_signature(cls, logic: Dict[str, Any], data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        conditions = logic.get("conditions", [])
        if not conditions and "field" in logic:
            conditions = [logic]

        explanations = []
        for cond in conditions:
            field = cond.get("field")
            op = cond.get("op", "=").upper()
            expected = cond.get("value")
            actual = data.get(field)

            matched = False
            if op in ("=", "=="):
                matched = str(actual).lower() == str(expected).lower()
            elif op == "!=":
                matched = str(actual).lower() != str(expected).lower()
            elif op == "IN":
                expected_list = [str(x).lower() for x in (expected if isinstance(expected, list) else [expected])]
                matched = str(actual).lower() in expected_list
            elif op == "NOT IN":
                expected_list = [str(x).lower() for x in (expected if isinstance(expected, list) else [expected])]
                matched = str(actual).lower() not in expected_list
            elif op == "CONTAINS":
                matched = str(expected).lower() in str(actual).lower()
            elif op == "REGEX":
                matched = bool(re.search(str(expected), str(actual or "")))
            elif op in (">", ">=", "<", "<="):
                try:
                    act_num = float(actual or 0)
                    exp_num = float(expected or 0)
                    if op == ">": matched = act_num > exp_num
                    elif op == ">=": matched = act_num >= exp_num
                    elif op == "<": matched = act_num < exp_num
                    elif op == "<=": matched = act_num <= exp_num
                except (ValueError, TypeError):
                    matched = False

            if not matched:
                return False, []
            explanations.append(f"Condition '{field} {op} {expected}' satisfied (observed: '{actual}').")

        return True, explanations

    @classmethod
    def _eval_threshold(cls, logic: Dict[str, Any], data: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        field = logic.get("metric_field", "session_count")
        threshold = logic.get("threshold", 10)
        op = logic.get("op", ">")
        
        actual_val = context.get(field, data.get(field, 0))
        matched = False
        if op == ">": matched = actual_val > threshold
        elif op == ">=": matched = actual_val >= threshold
        elif op == "<": matched = actual_val < threshold
        elif op == "<=": matched = actual_val <= threshold
        elif op in ("=", "=="): matched = actual_val == threshold

        if matched:
            return True, [f"Metric '{field}' value {actual_val} exceeded threshold condition '{op} {threshold}'."]
        return False, []

    @classmethod
    def _eval_statistical(cls, logic: Dict[str, Any], data: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        rarity_field = logic.get("rarity_field", "ja4_rarity")
        rarity_threshold = logic.get("max_rarity", 0.05)
        observed_rarity = context.get(rarity_field, data.get(rarity_field, 1.0))

        if observed_rarity < rarity_threshold:
            return True, [
                f"Statistical rarity for '{rarity_field}' is {observed_rarity:.4f}, below threshold {rarity_threshold:.4f}."
            ]
        return False, []

    @classmethod
    def _eval_behavioral(cls, logic: Dict[str, Any], data: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        peer_deviation_threshold = logic.get("peer_deviation_threshold", 2.0)
        z_score = context.get("peer_z_score", data.get("peer_z_score", 0.0))
        
        if abs(z_score) >= peer_deviation_threshold:
            return True, [
                f"Asset exhibited significant behavioral deviation from peer group (Z-Score: {z_score:.2f} >= {peer_deviation_threshold})."
            ]
        return False, []

    @classmethod
    def _eval_ml(cls, logic: Dict[str, Any], data: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        min_score = logic.get("min_anomaly_score", 0.85)
        model_score = context.get("ml_anomaly_score", data.get("ml_anomaly_score", 0.0))
        
        if model_score >= min_score:
            return True, [
                f"AI/ML Anomaly Model triggered with inference score {model_score:.3f} >= threshold {min_score:.3f}."
            ]
        return False, []
