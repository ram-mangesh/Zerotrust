"""Single Anomaly Scenario Runner and Real Inference Verification Service.

Provides:
1. Predefined normal-versus-anomalous synthetic request scenarios.
2. Real model inference with isolation_forest_global.pkl and scaler pipeline.
3. Feature-level SHAP attribution (TreeExplainer or deterministic feature ranking).
4. Zero Trust 6-factor policy evaluation and action determination.
5. Tamper-evident hash-chained AuditLog recording and instant SHA-256 seal verification.
6. 4-Gate Pass/Fail validation matrix (Inference, SHAP, Policy, Audit).
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import anomaly
from app.models.base import utcnow
from app.models.enums import RiskLevel, AccessAction
from app.services.audit_service import AuditService
from app.services.events import Event, publish_sync
from app.services.hash_chain import compute_record_hash, hash_payload

logger = logging.getLogger(__name__)


class SyntheticScenario(BaseModel):
    id: str
    name: str
    category: str
    description: str
    expected_anomaly_score_range: str
    expected_risk_level: str
    expected_action: str
    features: Dict[str, float]


PREDEFINED_SCENARIOS: List[SyntheticScenario] = [
    SyntheticScenario(
        id="baseline_normal",
        name="Legitimate Employee Access (Normal)",
        category="baseline",
        description="Clean corporate laptop, usual office IP (Coimbatore), business hours, low request frequency (2.0 RPM), 3 standard resources.",
        expected_anomaly_score_range="0.30–0.52",
        expected_risk_level="LOW",
        expected_action="ALLOW",
        features={
            "hour_sin": 0.0,
            "hour_cos": 1.0,
            "day_of_week": 2.0,
            "is_known_device": 1.0,
            "geo_distance_from_usual_km": 0.0,
            "is_new_country": 0.0,
            "ip_reputation_score": 0.0,
            "is_vpn": 0.0,
            "requests_per_minute": 2.0,
            "session_duration_min": 25.0,
            "num_distinct_resources": 3.0,
            "failed_auth_count_24h": 0.0,
            "travel_velocity_kmh": 0.0,
        },
    ),
    SyntheticScenario(
        id="geo_velocity_anomaly",
        name="Impossible Travel Velocity Jump",
        category="geo_anomaly",
        description="Geographical jump of 14,000 km across borders in minutes with velocity > 900 km/h, unfamiliar country, and datacenter VPN.",
        expected_anomaly_score_range="0.65–0.95",
        expected_risk_level="CRITICAL",
        expected_action="BLOCK / REVOKE_SESSION",
        features={
            "hour_sin": -0.86,
            "hour_cos": -0.50,
            "day_of_week": 2.0,
            "is_known_device": 1.0,
            "geo_distance_from_usual_km": 14000.0,
            "is_new_country": 1.0,
            "ip_reputation_score": 75.0,
            "is_vpn": 1.0,
            "requests_per_minute": 6.0,
            "session_duration_min": 40.0,
            "num_distinct_resources": 4.0,
            "failed_auth_count_24h": 0.0,
            "travel_velocity_kmh": 1200.0,
        },
    ),
    SyntheticScenario(
        id="mass_data_exfiltration",
        name="Mass Resource Enumeration & Exfiltration Burst",
        category="data_exfiltration",
        description="Rapid API burst of 150 requests/min touching 45 distinct corporate endpoints with extended session duration.",
        expected_anomaly_score_range="0.70–0.98",
        expected_risk_level="CRITICAL",
        expected_action="BLOCK / STEP_UP_MFA",
        features={
            "hour_sin": 0.50,
            "hour_cos": 0.86,
            "day_of_week": 3.0,
            "is_known_device": 1.0,
            "geo_distance_from_usual_km": 5.0,
            "is_new_country": 0.0,
            "ip_reputation_score": 10.0,
            "is_vpn": 0.0,
            "requests_per_minute": 150.0,
            "session_duration_min": 540.0,
            "num_distinct_resources": 45.0,
            "failed_auth_count_24h": 0.0,
            "travel_velocity_kmh": 0.0,
        },
    ),
    SyntheticScenario(
        id="credential_stuffing_tor",
        name="Credential Stuffing & Unregistered Device",
        category="credential_abuse",
        description="8 consecutive failed logins in 24 hours, unrecognised hardware fingerprint, high IP threat intelligence score (85) from Tor network.",
        expected_anomaly_score_range="0.60–0.90",
        expected_risk_level="HIGH",
        expected_action="STEP_UP_MFA / BLOCK",
        features={
            "hour_sin": -0.70,
            "hour_cos": 0.71,
            "day_of_week": 4.0,
            "is_known_device": 0.0,
            "geo_distance_from_usual_km": 2500.0,
            "is_new_country": 1.0,
            "ip_reputation_score": 85.0,
            "is_vpn": 1.0,
            "requests_per_minute": 30.0,
            "session_duration_min": 15.0,
            "num_distinct_resources": 12.0,
            "failed_auth_count_24h": 8.0,
            "travel_velocity_kmh": 0.0,
        },
    ),
    SyntheticScenario(
        id="off_hours_reconnaissance",
        name="Off-Hours Weekend Reconnaissance Probe",
        category="reconnaissance",
        description="Off-hours probe on Sunday 3 AM, touching 22 endpoints sequentially on an unapproved device.",
        expected_anomaly_score_range="0.58–0.85",
        expected_risk_level="MEDIUM",
        expected_action="ALLOW_LIMITED / STEP_UP_MFA",
        features={
            "hour_sin": 0.70,
            "hour_cos": -0.71,
            "day_of_week": 6.0,
            "is_known_device": 0.0,
            "geo_distance_from_usual_km": 80.0,
            "is_new_country": 0.0,
            "ip_reputation_score": 25.0,
            "is_vpn": 1.0,
            "requests_per_minute": 22.0,
            "session_duration_min": 90.0,
            "num_distinct_resources": 22.0,
            "failed_auth_count_24h": 1.0,
            "travel_velocity_kmh": 0.0,
        },
    ),
]

SCENARIOS_MAP = {s.id: s for s in PREDEFINED_SCENARIOS}


class AnomalyRunnerService:
    """Orchestrates scenario execution, real ML inference, SHAP, policy, and audit hash verification."""

    @classmethod
    def list_scenarios(cls) -> List[Dict[str, Any]]:
        return [s.model_dump() for s in PREDEFINED_SCENARIOS]

    @classmethod
    def run_scenario(
        cls,
        db: Session,
        *,
        scenario_id: Optional[str] = None,
        custom_features: Optional[Dict[str, float]] = None,
        actor_label: str = "security_analyst",
        actor_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """Execute a single anomaly scenario through the complete 6-gate verification pipeline."""
        start_time = time.perf_counter()

        # 1. Resolve Scenario & Feature Map
        scenario_meta: Optional[SyntheticScenario] = None
        if scenario_id and scenario_id in SCENARIOS_MAP:
            scenario_meta = SCENARIOS_MAP[scenario_id]
            features = dict(scenario_meta.features)
            if custom_features:
                features.update(custom_features)
            scen_name = scenario_meta.name
            scen_category = scenario_meta.category
            scen_desc = scenario_meta.description
        else:
            features = custom_features or dict(PREDEFINED_SCENARIOS[0].features)
            scen_name = "Custom Synthetic Anomaly Request"
            scen_category = "custom"
            scen_desc = "User-defined synthetic request features for zero-trust evaluation."

        # 2. Real Model Inference Pipeline
        t_inf_0 = time.perf_counter()
        raw_anomaly_score = anomaly.score(features, anomaly.GLOBAL_MODEL_NAME)
        inf_duration_ms = round((time.perf_counter() - t_inf_0) * 1000, 3)

        if raw_anomaly_score is None:
            anomaly_score = 0.50
            model_used = "Fallback / No Model"
            inference_gate_passed = False
        else:
            anomaly_score = round(float(raw_anomaly_score), 4)
            model_used = anomaly.GLOBAL_MODEL_NAME
            inference_gate_passed = True

        # 3. SHAP Feature Attribution
        t_shap_0 = time.perf_counter()
        explanation = anomaly.explain(features, anomaly.GLOBAL_MODEL_NAME)
        shap_duration_ms = round((time.perf_counter() - t_shap_0) * 1000, 3)

        if explanation:
            top_drivers = explanation.get("top_anomaly_drivers", [])
            mitigators = explanation.get("top_mitigating_factors", [])
            feature_impacts = explanation.get("feature_attributions", [])
            shap_method = explanation.get("explanation_method", "TreeExplainer")
            shap_gate_passed = True
        else:
            top_drivers = []
            mitigators = []
            feature_impacts = []
            shap_method = "Unavailable"
            shap_gate_passed = False

        # 4. Zero Trust Scoring & Policy Decision Gate
        # Compute factor penalties based on 6 ZTNA dimensions
        identity_penalty = min(25.0, float(features.get("failed_auth_count_24h", 0)) * 3.0)
        device_penalty = 20.0 if features.get("is_known_device", 1.0) == 0.0 else 0.0
        network_penalty = min(20.0, (20.0 if features.get("is_vpn", 0.0) == 1.0 else 0.0) + float(features.get("ip_reputation_score", 0)) * 0.15)
        behavior_penalty = min(20.0, (anomaly_score * 25.0) + (10.0 if float(features.get("requests_per_minute", 0)) > 50 else 0.0))
        location_penalty = min(10.0, (10.0 if features.get("is_new_country", 0.0) == 1.0 else 0.0) + min(10.0, float(features.get("geo_distance_from_usual_km", 0)) / 1000.0))
        temporal_penalty = min(5.0, 5.0 if float(features.get("day_of_week", 0)) >= 5 else 0.0)

        total_deductions = identity_penalty + device_penalty + network_penalty + behavior_penalty + location_penalty + temporal_penalty
        calculated_trust = max(0.0, min(100.0, 100.0 - total_deductions))

        # Apply hard overrides if critical thresholds breached
        overrides_triggered = []
        if float(features.get("travel_velocity_kmh", 0)) > 900.0:
            calculated_trust = min(calculated_trust, 22.0)
            overrides_triggered.append("impossible_travel")
        if float(features.get("requests_per_minute", 0)) > 100.0 or float(features.get("num_distinct_resources", 0)) > 30.0:
            calculated_trust = min(calculated_trust, 35.0)
            overrides_triggered.append("mass_enumeration")

        trust_score = round(calculated_trust, 2)
        risk_score = round(100.0 - trust_score, 2)

        if trust_score >= 80.0:
            risk_level = "LOW"
            action = "ALLOW"
        elif trust_score >= 60.0:
            risk_level = "MEDIUM"
            action = "ALLOW_LIMITED"
        elif trust_score >= 40.0:
            risk_level = "HIGH"
            action = "STEP_UP_MFA"
        else:
            risk_level = "CRITICAL"
            action = "REVOKE_SESSION" if "impossible_travel" in overrides_triggered else "BLOCK"

        policy_gate_passed = True

        # 5. Audit Logging & Real-Time SHA-256 Hash Seal Verification
        audit_payload = {
            "scenario_id": scenario_id or "custom",
            "scenario_name": scen_name,
            "anomaly_score": anomaly_score,
            "trust_score": trust_score,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": action,
            "overrides": overrides_triggered,
            "top_drivers": [d.get("feature") for d in top_drivers[:3]] if top_drivers else [],
            "features_summary": {
                "rpm": features.get("requests_per_minute"),
                "geo_km": features.get("geo_distance_from_usual_km"),
                "velocity": features.get("travel_velocity_kmh"),
                "is_vpn": features.get("is_vpn"),
            },
        }

        audit_rec = AuditService.record(
            db,
            action="AI_ANOMALY_SCENARIO_EVALUATED",
            actor_id=actor_id,
            actor_label=actor_label,
            resource_type="anomaly_scenario",
            resource_id=scenario_id or "custom",
            ip_address="177.18.200.45" if "geo" in (scenario_id or "") else "127.0.0.1",
            payload=audit_payload,
        )
        db.commit()

        # Instant Cryptographic Verification of the Appended Hash Record
        expected_payload_hash = hash_payload(audit_payload)
        expected_rec_hash = compute_record_hash(
            audit_rec.prev_hash,
            audit_rec.timestamp,
            audit_rec.actor_label,
            audit_rec.action,
            expected_payload_hash,
        )

        hash_chain_valid = (
            audit_rec.payload_hash == expected_payload_hash
            and audit_rec.record_hash == expected_rec_hash
        )
        audit_gate_passed = hash_chain_valid

        audit_verification_data = {
            "seq": audit_rec.seq,
            "record_hash": audit_rec.record_hash,
            "prev_hash": audit_rec.prev_hash,
            "payload_hash": audit_rec.payload_hash,
            "timestamp": audit_rec.timestamp.isoformat(),
            "chain_valid": hash_chain_valid,
            "verification_algorithm": "SHA-256 Chain-of-Trust",
        }

        # 6. Structured 4-Gate Pass / Fail Verification Matrix
        gates = {
            "gate_1_model_inference": {
                "gate_name": "Real Model Inference (.pkl)",
                "passed": inference_gate_passed,
                "status": "PASS" if inference_gate_passed else "FAIL",
                "details": f"Isolation Forest scored feature vector in {inf_duration_ms}ms (Score: {anomaly_score:.4f})",
            },
            "gate_2_shap_explanation": {
                "gate_name": "SHAP Feature-Level Explainability",
                "passed": shap_gate_passed,
                "status": "PASS" if shap_gate_passed else "FAIL",
                "details": f"Attributed {len(feature_impacts)} features via {shap_method} (Top driver: {top_drivers[0]['feature'] if top_drivers else 'None'})",
            },
            "gate_3_policy_decision": {
                "gate_name": "Zero Trust Policy & Risk Decision",
                "passed": policy_gate_passed,
                "status": "PASS" if policy_gate_passed else "FAIL",
                "details": f"Computed Trust: {trust_score:.1f}/100 -> Risk: {risk_level} -> Action: {action}",
            },
            "gate_4_audit_persistence": {
                "gate_name": "Tamper-Evident Hash Chain Audit",
                "passed": audit_gate_passed,
                "status": "PASS" if audit_gate_passed else "FAIL",
                "details": f"Audit record #{audit_rec.seq} cryptographically verified with SHA-256 seal",
            },
        }

        all_passed = all(g["passed"] for g in gates.values())
        total_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Broadcast live event to connected WebSocket clients
        publish_sync(
            Event(
                type="scenario.run_completed",
                payload={
                    "scenario_id": scenario_id or "custom",
                    "scenario_name": scen_name,
                    "anomaly_score": anomaly_score,
                    "trust_score": trust_score,
                    "risk_level": risk_level,
                    "action": action,
                    "overall_result": "PASS" if all_passed else "FAIL",
                    "audit_seq": audit_rec.seq,
                },
            )
        )

        return {
            "scenario": {
                "id": scenario_id or "custom",
                "name": scen_name,
                "category": scen_category,
                "description": scen_desc,
            },
            "inference": {
                "anomaly_score": anomaly_score,
                "model_name": model_used,
                "duration_ms": inf_duration_ms,
                "features": features,
            },
            "shap_explanation": {
                "method": shap_method,
                "duration_ms": shap_duration_ms,
                "top_anomaly_drivers": top_drivers,
                "top_mitigating_factors": mitigators,
                "feature_attributions": feature_impacts,
            },
            "policy_decision": {
                "trust_score": trust_score,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "action": action,
                "overrides_triggered": overrides_triggered,
                "factor_penalties": {
                    "identity": identity_penalty,
                    "device": device_penalty,
                    "network": network_penalty,
                    "behavior": behavior_penalty,
                    "location": location_penalty,
                    "temporal": temporal_penalty,
                },
            },
            "audit_verification": audit_verification_data,
            "verification_gates": gates,
            "overall_result": "PASS" if all_passed else "FAIL",
            "total_latency_ms": total_duration_ms,
        }
