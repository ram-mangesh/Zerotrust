"""Attack Simulator Service: multi-vector attack scenarios and progressive escalation."""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import (
    ContextBundle,
    GeoLocation,
    IPReputation,
    NetworkContext,
    NetworkIntel,
    TemporalContext,
)
from app.models.alert import Alert
from app.models.base import as_aware, utcnow
from app.models.device import Device
from app.models.enums import (
    AccessAction,
    AlertSeverity,
    AlertStatus,
    DeviceStatus,
    RiskLevel,
    ScoreTrigger,
    SessionStatus,
)
from app.models.session import UserSession
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.events import Event, publish_sync
from app.services.trust_service import TrustService

logger = logging.getLogger(__name__)


@dataclass
class ScenarioInfo:
    id: str
    name: str
    description: str
    category: str
    expected_score_range: str
    expected_action: str
    severity: str
    steps_count: int


SCENARIOS: dict[str, ScenarioInfo] = {
    "normal": ScenarioInfo(
        id="normal",
        name="Legitimate User Activity",
        description="Normal business hours, known approved device, residential network, usual location.",
        category="baseline",
        expected_score_range="85–100",
        expected_action="ALLOW",
        severity="INFO",
        steps_count=1,
    ),
    "country_change": ScenarioInfo(
        id="country_change",
        name="Impossible Travel (Country Jump)",
        description="Consecutive logins from distant geolocations (Coimbatore → São Paulo) in minutes at >900 km/h.",
        category="geo_anomaly",
        expected_score_range="20–35",
        expected_action="BLOCK / REVOKE_SESSION",
        severity="CRITICAL",
        steps_count=2,
    ),
    "rapid_export": ScenarioInfo(
        id="rapid_export",
        name="Rapid Data Exfiltration (Mass Enumeration)",
        description="Insider threat: touching 25+ sensitive resources rapidly, exceeding baseline volume.",
        category="data_exfiltration",
        expected_score_range="30–45",
        expected_action="BLOCK / STEP_UP_MFA",
        severity="HIGH",
        steps_count=2,
    ),
    "stolen_token": ScenarioInfo(
        id="stolen_token",
        name="Stolen Session Token / Hijack",
        description="Valid session token presented from an unrecognised device with mismatched ECDSA key.",
        category="credential_abuse",
        expected_score_range="20–30",
        expected_action="REVOKE_SESSION",
        severity="CRITICAL",
        steps_count=2,
    ),
    "full_attack": ScenarioInfo(
        id="full_attack",
        name="Full Attack Progressive Escalation",
        description="5-step attack cycle: off-hours login → unapproved device → permission probing → policy denials → exfiltration.",
        category="apt_simulation",
        expected_score_range="15–25",
        expected_action="REVOKE_SESSION",
        severity="CRITICAL",
        steps_count=5,
    ),
}


class SimulatorService:
    @staticmethod
    def list_scenarios() -> list[dict[str, Any]]:
        """Return catalog of all available attack simulation scenarios."""
        return [asdict(s) for s in SCENARIOS.values()]

    @classmethod
    def run_scenario(
        cls,
        db: Session,
        scenario_id: str,
        *,
        user_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Execute a simulated scenario against an active or synthetic target session."""
        if scenario_id not in SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario_id}'")

        # Resolve or pick target user and session
        user = None
        if user_id:
            user = db.get(User, user_id)
        if not user:
            user = db.execute(select(User).where(User.username != "admin")).scalars().first()
        if not user:
            user = db.execute(select(User)).scalars().first()
        if not user:
            raise ValueError("No user found in database for simulation")

        session = None
        if session_id:
            session = db.get(UserSession, session_id)
        if not session:
            session = db.execute(
                select(UserSession).where(
                    UserSession.user_id == user.id,
                    UserSession.status == SessionStatus.ACTIVE,
                )
            ).scalars().first()

        now = utcnow()
        if not session:
            # Create a live session for the simulation
            session = UserSession(
                user_id=user.id,
                status=SessionStatus.ACTIVE,
                ip_address="117.192.1.20",
                country="IN",
                city="Coimbatore",
                started_at=now,
                last_seen_at=now,
                expires_at=now + timedelta(days=7),
                current_trust_score=95.0,
            )
            db.add(session)
            db.flush()

        device = db.get(Device, session.device_id) if session.device_id else None

        initial_score = session.current_trust_score
        timeline: list[dict[str, Any]] = []
        alerts_generated: list[str] = []

        # ── SCENARIO 1: NORMAL ACTIVITY ─────────────────────────────────────
        if scenario_id == "normal":
            bundle = ContextBundle(
                request_id=uuid.uuid4().hex[:12],
                method="GET",
                path="/api/resources/public-docs",
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                network=NetworkContext(
                    ip_address="117.192.1.20",
                    geo=GeoLocation(
                        ip="117.192.1.20", country="IN", city="Coimbatore",
                        latitude=11.0, longitude=76.9, resolved=True, provider="test",
                    ),
                    intel=NetworkIntel(asn="AS9829", is_vpn=False, is_proxy=False),
                    reputation=IPReputation(ip="117.192.1.20", provider="test"),
                ),
                temporal=TemporalContext(
                    at=now, local_time=now, hour_of_day=11, day_of_week=2,
                    is_weekend=False, is_business_hours=True,
                ),
            )
            assessment, score_row = TrustService.evaluate(
                db, user=user, session=session, bundle=bundle, trigger=ScoreTrigger.ACCESS_REQUEST, device=device
            )
            timeline.append({
                "step": 1,
                "title": "Normal Request",
                "score": assessment.score,
                "risk_level": assessment.risk_level.value,
                "action": assessment.action.value,
                "detail": "Verified device, home location (Coimbatore), business hours.",
            })

        # ── SCENARIO 2: COUNTRY CHANGE / IMPOSSIBLE TRAVEL ──────────────────
        elif scenario_id == "country_change":
            # Step 1: Create an earlier session in Coimbatore 2 minutes ago
            prior_session = UserSession(
                user_id=user.id,
                status=SessionStatus.LOGGED_OUT,
                ip_address="117.192.1.20",
                country="IN",
                city="Coimbatore",
                latitude=11.0168,
                longitude=76.9558,
                started_at=now - timedelta(minutes=2),
                last_seen_at=now - timedelta(minutes=2),
                expires_at=now + timedelta(days=1),
                current_trust_score=95.0,
            )
            db.add(prior_session)
            db.flush()

            timeline.append({
                "step": 1,
                "title": "Normal Login in Coimbatore",
                "score": 92.0,
                "risk_level": "LOW",
                "action": "ALLOW",
                "detail": "User authenticated from usual home office 2 minutes ago.",
            })

            # Step 2: Instantaneous jump to São Paulo, Brazil
            abroad_bundle = ContextBundle(
                request_id=uuid.uuid4().hex[:12],
                method="GET",
                path="/api/auth/me",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                network=NetworkContext(
                    ip_address="177.18.200.45",
                    geo=GeoLocation(
                        ip="177.18.200.45", country="BR", city="São Paulo",
                        latitude=-23.55, longitude=-46.63, resolved=True, provider="test",
                    ),
                    intel=NetworkIntel(asn="AS28573", is_vpn=True, is_proxy=True, is_datacenter=True),
                    reputation=IPReputation(ip="177.18.200.45", abuse_confidence=85, provider="test"),
                ),
                temporal=TemporalContext(
                    at=now, local_time=now, hour_of_day=3, day_of_week=2,
                    is_weekend=False, is_business_hours=False,
                ),
            )
            assessment, score_row = TrustService.evaluate(
                db, user=user, session=session, bundle=abroad_bundle, trigger=ScoreTrigger.ACCESS_REQUEST, device=None
            )

            # Generate Impossible Travel Alert
            alert = Alert(
                user_id=user.id,
                session_id=session.id,
                severity=AlertSeverity.CRITICAL,
                status=AlertStatus.OPEN,
                category="impossible_travel",
                title=f"Impossible Travel: {user.username} (Coimbatore → São Paulo)",
                description="Consecutive access events across 14,000 km in under 2 minutes (implied speed > 900 km/h).",
                trust_score=assessment.score,
                evidence={"origin": "Coimbatore, IN", "destination": "São Paulo, BR", "velocity_kmh": 420000},
            )
            db.add(alert)
            alerts_generated.append(alert.title)

            timeline.append({
                "step": 2,
                "title": "Impossible Travel (São Paulo Jump)",
                "score": assessment.score,
                "risk_level": assessment.risk_level.value,
                "action": assessment.action.value,
                "detail": "Location override applied: distance > 14,000 km, velocity > 900 km/h.",
            })

        # ── SCENARIO 3: RAPID EXPORT / MASS ENUMERATION ─────────────────────
        elif scenario_id == "rapid_export":
            timeline.append({
                "step": 1,
                "title": "Baseline Active Session",
                "score": 90.0,
                "risk_level": "LOW",
                "action": "ALLOW",
                "detail": "Approved laptop on clean residential connection.",
            })

            session.request_count = 140
            session.distinct_resource_count = 28
            db.flush()

            burst_bundle = ContextBundle(
                request_id=uuid.uuid4().hex[:12],
                method="GET",
                path="/api/resources/payroll-db/export",
                user_agent="Mozilla/5.0",
                network=NetworkContext(
                    ip_address="117.192.1.20",
                    geo=GeoLocation(ip="117.192.1.20", country="IN", city="Coimbatore", resolved=True, provider="test"),
                    intel=NetworkIntel(asn="AS9829"),
                    reputation=IPReputation(ip="117.192.1.20", provider="test"),
                ),
                temporal=TemporalContext(at=now, local_time=now, hour_of_day=14, day_of_week=2, is_weekend=False, is_business_hours=True),
            )
            assessment, score_row = TrustService.evaluate(
                db, user=user, session=session, bundle=burst_bundle, trigger=ScoreTrigger.ACCESS_REQUEST, device=device
            )

            alert = Alert(
                user_id=user.id,
                session_id=session.id,
                severity=AlertSeverity.HIGH,
                status=AlertStatus.OPEN,
                category="mass_enumeration",
                title=f"Mass Resource Enumeration by {user.username}",
                description="Touched 28 distinct resources in under 1 minute (baseline is 3).",
                trust_score=assessment.score,
                evidence={"distinct_resources": 28, "requests_per_minute": 140.0},
            )
            db.add(alert)
            alerts_generated.append(alert.title)

            timeline.append({
                "step": 2,
                "title": "Mass Enumeration & Export Spike",
                "score": assessment.score,
                "risk_level": assessment.risk_level.value,
                "action": assessment.action.value,
                "detail": "Touched 28 resources (7x baseline) -> mass_enumeration override clamped score.",
            })

        # ── SCENARIO 4: STOLEN TOKEN / SESSION HIJACK ───────────────────────
        elif scenario_id == "stolen_token":
            timeline.append({
                "step": 1,
                "title": "Session Created on Valid Device",
                "score": 90.0,
                "risk_level": "LOW",
                "action": "ALLOW",
                "detail": "Authenticated with valid ECDSA key.",
            })

            # Session token presented from unknown foreign IP with mismatched public key
            hijack_bundle = ContextBundle(
                request_id=uuid.uuid4().hex[:12],
                method="GET",
                path="/api/resources/source-repo",
                user_agent="Python-urllib/3.11",
                network=NetworkContext(
                    ip_address="45.154.255.80",
                    geo=GeoLocation(ip="45.154.255.80", country="RU", city="Moscow", resolved=True, provider="test"),
                    intel=NetworkIntel(asn="AS44050", is_vpn=True, is_datacenter=True),
                    reputation=IPReputation(ip="45.154.255.80", abuse_confidence=92, provider="test"),
                ),
                temporal=TemporalContext(at=now, local_time=now, hour_of_day=3, day_of_week=6, is_weekend=True, is_business_hours=False),
            )
            assessment, score_row = TrustService.evaluate(
                db, user=user, session=session, bundle=hijack_bundle, trigger=ScoreTrigger.ACCESS_REQUEST, device=None
            )

            session.status = SessionStatus.REVOKED
            session.revoked_reason = "Simulated Attack: Token theft & device key mismatch"
            session.ended_at = now

            alert = Alert(
                user_id=user.id,
                session_id=session.id,
                severity=AlertSeverity.CRITICAL,
                status=AlertStatus.OPEN,
                category="session_hijack",
                title=f"Token Hijack & Device Key Mismatch on {user.username}",
                description="Session token presented from Moscow IP (AS44050) without registered ECDSA device key.",
                trust_score=assessment.score,
                evidence={"source_ip": "45.154.255.80", "country": "RU", "action": "SESSION_REVOKED"},
            )
            db.add(alert)
            alerts_generated.append(alert.title)

            timeline.append({
                "step": 2,
                "title": "Stolen Token Presented from Foreign IP",
                "score": assessment.score,
                "risk_level": "CRITICAL",
                "action": "REVOKE_SESSION",
                "detail": "Mismatched device key + datacenter IP -> Session terminated immediately.",
            })

        # ── SCENARIO 5: FULL PROGRESSIVE 5-STEP ATTACK ──────────────────────
        elif scenario_id == "full_attack":
            steps_data = [
                (1, "Off-Hours Login (02:30 AM)", 75.0, "MEDIUM", "ALLOW_LIMITED", "Signed in 7.5 hours outside typical window."),
                (2, "Unapproved Device Fingerprint", 60.0, "MEDIUM", "ALLOW_LIMITED", "New unrecognised browser hardware fingerprint."),
                (3, "High Request Burst & API Rate Spike", 48.0, "HIGH", "STEP_UP_MFA", "API calls jumped to 45 RPM (9x baseline)."),
                (4, "Policy Probing on Restricted Resources", 35.0, "CRITICAL", "BLOCK", "5 consecutive policy denials on Payroll DB."),
                (5, "Data Exfiltration & Session Termination", 18.0, "CRITICAL", "REVOKE_SESSION", "Mass data export detected. Session revoked."),
            ]
            for step_num, title, score_val, r_level, act, detail_msg in steps_data:
                timeline.append({
                    "step": step_num,
                    "title": title,
                    "score": score_val,
                    "risk_level": r_level,
                    "action": act,
                    "detail": detail_msg,
                })

            assessment = None
            session.current_trust_score = 18.0
            session.current_risk_level = RiskLevel.CRITICAL
            session.status = SessionStatus.REVOKED
            session.revoked_reason = "Full attack multi-stage escalation"
            session.ended_at = now

            alert = Alert(
                user_id=user.id,
                session_id=session.id,
                severity=AlertSeverity.CRITICAL,
                status=AlertStatus.OPEN,
                category="full_attack_escalation",
                title=f"Multi-Stage Attack Chain Terminated on {user.username}",
                description="Progressive escalation across 5 attack vectors culminated in session revocation.",
                trust_score=18.0,
                evidence={"steps_completed": 5, "final_action": "REVOKE_SESSION"},
            )
            db.add(alert)
            alerts_generated.append(alert.title)

        final_score = timeline[-1]["score"]
        final_risk = timeline[-1]["risk_level"]
        final_action = timeline[-1]["action"]

        # Broadcast live simulation event over WebSocket
        publish_sync(
            Event(
                type="simulation.attack_completed",
                payload={
                    "scenario_id": scenario_id,
                    "scenario_name": SCENARIOS[scenario_id].name,
                    "user": user.username,
                    "session_id": str(session.id),
                    "initial_score": initial_score,
                    "final_score": final_score,
                    "risk_level": final_risk,
                    "action": final_action,
                    "alerts_generated": alerts_generated,
                    "steps": timeline,
                },
            )
        )

        AuditService.record(
            db,
            action="ATTACK_SIMULATION_EXECUTED",
            actor_id=user.id,
            actor_label=user.username,
            resource_type="simulation",
            resource_id=scenario_id,
            ip_address=session.ip_address,
            payload={
                "scenario": scenario_id,
                "initial_score": initial_score,
                "final_score": final_score,
                "risk_level": final_risk,
                "action": final_action,
            },
        )
        db.commit()

        return {
            "scenario_id": scenario_id,
            "scenario_name": SCENARIOS[scenario_id].name,
            "target_user": user.username,
            "session_id": str(session.id),
            "initial_score": initial_score,
            "final_score": final_score,
            "risk_level": final_risk,
            "action": final_action,
            "alerts_generated": alerts_generated,
            "timeline": timeline,
            "status": "completed",
        }
