import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

# --- POLICY CONFIGURATIONS ---
RISK_POLICY = {
    "name": "enterprise-default",
    "version": "1.2",
    "weights": {
        "deterministic": 0.50,
        "ai": 0.25,
        "asset": 0.15,
        "exploitability": 0.10
    },
    "ranges": {
        "CRITICAL": {"min": 90, "max": 100},
        "HIGH": {"min": 70, "max": 89},
        "MEDIUM": {"min": 40, "max": 69},
        "LOW": {"min": 0, "max": 39}
    }
}

SEVERITY_MAP = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.0
}

# --- DATA MODELS ---

@dataclass
class AssetContext:
    asset_id: str
    role: str
    exposure: str  # e.g., "INTERNET", "INTERNAL"
    criticality: float  # 0.0 to 1.0
    environment: str

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    observed: str
    evidence_confidence: float = 1.0

@dataclass
class RiskContext:
    session_id: str
    protocol: str
    tls_version: str
    deterministic_findings: List[Finding]
    ai_score: float
    ai_model_agreement: float
    ai_top_features: List[str]
    asset: AssetContext
    data_quality: float = 1.0
    cvss_context: float = 0.0  # Normalized 0.0 to 1.0
    threat_intel_match: bool = False

class FindingCorrelator:
    """
    Identifies relationships between isolated findings to apply risk modifiers.
    For example: STARTTLS failure + Plaintext Auth = Downgrade Attack.
    """
    def __init__(self):
        self.correlation_rules = [
            {
                "id": "STARTTLS-DOWNGRADE-01",
                "condition": lambda ctx, finding_ids: "STARTTLS_FAILURE" in finding_ids and "PLAINTEXT_AUTH" in finding_ids,
                "modifier": +15.0,
                "description": "STARTTLS failure followed by plaintext authentication"
            },
            {
                "id": "AI-CRYPTO-01",
                "condition": lambda ctx, finding_ids: ctx.ai_score > 0.85 and any("DEPRECATED_TLS" in f for f in finding_ids),
                "modifier": +5.0,
                "description": "High AI behavioral anomaly combined with deprecated cryptography"
            },
            {
                "id": "EXTERNAL-EXPOSURE-01",
                "condition": lambda ctx, finding_ids: ctx.asset.exposure == "INTERNET" and ctx.cvss_context > 0.7,
                "modifier": +10.0,
                "description": "Highly exploitable condition on an internet-facing asset"
            }
        ]

    def evaluate(self, context: RiskContext) -> Dict[str, Any]:
        finding_ids = [f.rule_id for f in context.deterministic_findings]
        correlations = []
        total_modifier = 0.0

        for rule in self.correlation_rules:
            if rule["condition"](context, finding_ids):
                correlations.append(rule["id"])
                total_modifier += rule["modifier"]
                
        return {
            "applied_correlations": correlations,
            "total_modifier": total_modifier
        }

class RiskScoringEngine:
    """
    Computes the Cryptographic Risk Score (CRS) based on weighted evidence.
    """
    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy
        self.weights = policy["weights"]

    def _calculate_deterministic_component(self, findings: List[Finding]) -> float:
        if not findings:
            return 0.0
        # Base deterministic score on the highest severity finding + a small bump for multiplicity
        severities = [SEVERITY_MAP.get(f.severity, 0.0) for f in findings]
        max_sev = max(severities)
        multiplicity_bump = min(0.2, (len(findings) - 1) * 0.05)
        return min(1.0, max_sev + multiplicity_bump)

    def _calculate_exploitability(self, context: RiskContext) -> float:
        # Fuse CVSS, threat intelligence, and exposure
        base = context.cvss_context
        if context.threat_intel_match:
            base += 0.2
        if context.asset.exposure == "INTERNET":
            base += 0.1
        return min(1.0, base)

    def calculate_crs(self, context: RiskContext, correlator: FindingCorrelator) -> Dict[str, Any]:
        # 1. Base Components
        d_score = self._calculate_deterministic_component(context.deterministic_findings)
        a_score = context.ai_score
        c_score = context.asset.criticality
        e_score = self._calculate_exploitability(context)

        # 2. Apply Weights
        base_risk = (
            (d_score * self.weights["deterministic"]) +
            (a_score * self.weights["ai"]) +
            (c_score * self.weights["asset"]) +
            (e_score * self.weights["exploitability"])
        ) * 100.0  # Scale to 0-100

        # 3. Apply Correlations
        correlation_results = correlator.evaluate(context)
        modified_risk = base_risk + correlation_results["total_modifier"]
        
        # Cap at 100
        final_crs = min(100.0, max(0.0, modified_risk))

        # 4. Determine Category
        category = "UNKNOWN"
        for cat, bounds in self.policy["ranges"].items():
            if bounds["min"] <= final_crs <= bounds["max"]:
                category = cat
                break

        # 5. Build Explanation Drivers
        drivers = [f.observed for f in context.deterministic_findings]
        if a_score > 0.8:
            drivers.append(f"High behavioral anomaly ({', '.join(context.ai_top_features)})")
        if context.asset.exposure == "INTERNET":
            drivers.append(f"Internet-facing {context.asset.role}")

        return {
            "score": round(final_crs, 1),
            "category": category,
            "components": {
                "deterministic": round(d_score, 3),
                "ai": round(a_score, 3),
                "asset_criticality": round(c_score, 3),
                "exploitability": round(e_score, 3)
            },
            "correlations": correlation_results["applied_correlations"],
            "primary_drivers": drivers,
            "confidence": round(context.data_quality * min(1.0, context.ai_model_agreement + 0.5), 2)
        }

class EnterpriseAggregator:
    """
    Rolls up individual session risk scores into an enterprise posture view.
    """
    @staticmethod
    def aggregate(session_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        affected_assets = set()
        total_sessions = len(session_results)
        ai_anomalies = 0
        
        for res in session_results:
            distribution[res["risk"]["category"]] += 1
            affected_assets.add(res["asset"]["asset_id"])
            if res["ai"]["combined_anomaly"] > 0.85:
                ai_anomalies += 1

        return {
            "total_sessions": total_sessions,
            "risk_distribution": distribution,
            "assets_affected": len(affected_assets),
            "high_ai_anomalies": ai_anomalies,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

def run_risk_fusion(context: RiskContext) -> Dict[str, Any]:
    """
    Main entry point for Phase 7: evaluates a single session and outputs the structured Risk JSON.
    """
    correlator = FindingCorrelator()
    engine = RiskScoringEngine(policy=RISK_POLICY)
    
    risk_assessment = engine.calculate_crs(context, correlator)
    
    return {
        "session_id": context.session_id,
        "risk": {
            "score": risk_assessment["score"],
            "category": risk_assessment["category"],
            "confidence": risk_assessment["confidence"]
        },
        "components": risk_assessment["components"],
        "correlations": risk_assessment["correlations"],
        "primary_findings": [f.rule_id for f in context.deterministic_findings],
        "ai": {
            "combined_anomaly": context.ai_score,
            "model_agreement": context.ai_model_agreement
        },
        "asset": asdict(context.asset),
        "explanation": {
            "primary_drivers": risk_assessment["primary_drivers"]
        },
        "provenance": {
            "risk_policy": f"{RISK_POLICY['name']}-v{RISK_POLICY['version']}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    }

if __name__ == "__main__":
    # Mocking Phase 4 and Phase 6 data for a highly vulnerable session
    mock_asset = AssetContext(
        asset_id="smtp.enterprise.com",
        role="MTA",
        exposure="INTERNET",
        criticality=0.95,
        environment="PRODUCTION"
    )
    
    mock_context = RiskContext(
        session_id="FLOW-00124",
        protocol="SMTP",
        tls_version="TLS 1.1",
        deterministic_findings=[
            Finding("STARTTLS_FAILURE", "PROTOCOL", "HIGH", "STARTTLS explicitly failed"),
            Finding("PLAINTEXT_AUTH", "AUTH", "CRITICAL", "Plaintext authentication observed over unencrypted channel"),
            Finding("DEPRECATED_TLS_1_1", "TLS", "HIGH", "TLS 1.1 negotiated")
        ],
        ai_score=0.88,
        ai_model_agreement=0.91,
        ai_top_features=["IAT variance", "JA4 rarity", "Packet size distribution"],
        asset=mock_asset,
        data_quality=0.98,
        cvss_context=0.80, # E.g., known vulnerability on this MTA version
        threat_intel_match=False
    )
    
    # Run the fusion pipeline
    session_result = run_risk_fusion(mock_context)
    
    # Print the resulting JSON
    print("--- SESSION RISK RESULT ---")
    print(json.dumps(session_result, indent=2))
    
    # Mock an enterprise roll-up
    print("\n--- ENTERPRISE POSTURE ---")
    posture = EnterpriseAggregator.aggregate([session_result])
    print(json.dumps(posture, indent=2))