"""LLM Incident Narrator and Behavioral Baseline Synthesizer (Groq / Llama-3.3-70B).

Provides:
  1. AI Behavioral Baseline Synthesis: Generates role/department-aware expected activity baselines.
  2. LLM Incident Narration: Generates plain-English security investigation reports for SOC analysts.
  3. Deterministic Offline Fallback: Full offline support when GROQ_API_KEY is unset or unreachable.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.alert import Alert

logger = logging.getLogger(__name__)


class LLMService:
    @classmethod
    async def call_groq(
        cls,
        prompt: str,
        system_prompt: str = "You are a senior cybersecurity incident response analyst and Zero Trust engine.",
        max_tokens: int = 400,
        temperature: float = 0.2,
    ) -> str | None:
        """Call an OpenAI-compatible chat-completions API."""
        api_key = settings.llm_api_key or settings.groq_api_key
        if not settings.llm_enabled and not api_key:
            return None

        url = f"{settings.llm_base_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": settings.llm_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        return choices[0]["message"]["content"].strip()
        except Exception as exc:
            logger.warning("LLM call failed (%s); using deterministic fallback", exc)
        return None

    @classmethod
    async def synthesize_baseline(
        cls,
        role: str,
        department: str = "Engineering",
        permissions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Synthesize an initial behavioral profile baseline for a new user role/department."""
        perms_str = ", ".join(permissions or ["resources:read"])
        prompt = (
            f"Generate a behavioral baseline profile for an enterprise Zero Trust employee.\n"
            f"Role: {role}\nDepartment: {department}\nPermissions: {perms_str}\n\n"
            f"Respond ONLY with a valid JSON object matching this schema:\n"
            f"{{\n"
            f'  "expected_hours_start": <int 0-23>,\n'
            f'  "expected_hours_end": <int 0-23>,\n'
            f'  "avg_requests_per_minute": <float 1.0-20.0>,\n'
            f'  "avg_session_minutes": <float 15.0-120.0>,\n'
            f'  "avg_distinct_resources": <float 1.0-10.0>,\n'
            f'  "typical_resources": [<list of string slugs, e.g. "public-docs", "hr-portal"]>,\n'
            f'  "allowed_countries": ["IN"]\n'
            f"}}"
        )

        raw = await cls.call_groq(prompt, max_tokens=300)
        if raw:
            try:
                # Clean code blocks if present
                clean = raw.strip()
                if clean.startswith("```"):
                    clean = clean.split("```")[1]
                    if clean.startswith("json"):
                        clean = clean[4:]
                    clean = clean.strip()
                parsed = json.loads(clean)
                if "expected_hours_start" in parsed and "avg_requests_per_minute" in parsed:
                    parsed["synthesized_by"] = "Groq/Llama-3.3-70B"
                    return parsed
            except Exception as exc:
                logger.debug("Failed to parse LLM JSON: %s", exc)

        # Deterministic fallback baseline
        return cls._fallback_baseline(role, department)

    @classmethod
    def _fallback_baseline(cls, role: str, department: str) -> dict[str, Any]:
        """Role-tailored deterministic baseline profile."""
        role_lower = role.lower()
        dept_lower = department.lower()

        if "admin" in role_lower:
            start_h, end_h = 8, 20
            rpm = 8.0
            distinct_res = 6.0
            typical = ["public-docs", "hr-portal", "source-repo", "admin-console"]
        elif "finance" in dept_lower or "hr" in dept_lower:
            start_h, end_h = 9, 18
            rpm = 4.0
            distinct_res = 4.0
            typical = ["public-docs", "hr-portal", "finance-reports", "payroll-db"]
        elif "contractor" in role_lower:
            start_h, end_h = 9, 17
            rpm = 2.0
            distinct_res = 2.0
            typical = ["public-docs"]
        else:
            # Standard Employee
            start_h, end_h = 9, 19
            rpm = 3.5
            distinct_res = 3.0
            typical = ["public-docs", "hr-portal", "source-repo"]

        return {
            "expected_hours_start": start_h,
            "expected_hours_end": end_h,
            "avg_requests_per_minute": rpm,
            "avg_session_minutes": 45.0,
            "avg_distinct_resources": distinct_res,
            "typical_resources": typical,
            "allowed_countries": ["IN"],
            "synthesized_by": "Rule-Based Synthesizer (Offline Fallback)",
        }

    @classmethod
    async def narrate_incident(
        cls,
        *,
        username: str,
        user_id: str,
        risk_score: float,
        risk_level: str,
        action: str,
        factors: list[dict[str, Any]] | None = None,
        overrides: list[str] | None = None,
        threat_details: dict[str, Any] | None = None,
    ) -> str:
        """Generate a concise plain-English SOC incident investigation narrative."""
        factors_summary = []
        for f in factors or []:
            if f.get("points_deducted", 0) >= 0.5:
                factors_summary.append(f"- {f.get('factor')}: -{f.get('points_deducted')} pts ({f.get('reason')})")

        prompt = (
            f"Write a concise, professional security incident investigation report (<120 words) for SOC analysts.\n"
            f"User: {username} (ID: {user_id})\n"
            f"Final Trust Score: {risk_score:.1f}/100 | Risk Level: {risk_level} | Enforcement Action: {action}\n"
            f"Hard Overrides Triggered: {', '.join(overrides or ['None'])}\n"
            f"Factor Deductions:\n"
            + ("\n".join(factors_summary) if factors_summary else "None")
            + f"\nThreat Context: {json.dumps(threat_details or {})}\n\n"
            f"Explain clearly: (1) what anomalous activity occurred, (2) the root cause triggers, and (3) the Zero Trust containment action applied. Be direct and analytical."
        )

        narrative = await cls.call_groq(prompt, max_tokens=250)
        if narrative:
            return narrative.strip()

        # Deterministic fallback incident narrative
        return cls._fallback_narrative(
            username=username,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            overrides=overrides,
            threat_details=threat_details,
        )

    @classmethod
    def _fallback_narrative(
        cls,
        *,
        username: str,
        risk_score: float,
        risk_level: str,
        action: str,
        overrides: list[str] | None = None,
        threat_details: dict[str, Any] | None = None,
    ) -> str:
        """Deterministic rule-based incident report."""
        reasons = []
        if overrides:
            for o in overrides:
                if o == "impossible_travel":
                    reasons.append("geographical impossible travel across two distant locations in minutes")
                elif o == "session_hijack":
                    reasons.append("session token presented with mismatched hardware-bound ECDSA public key")
                elif o == "mass_enumeration":
                    reasons.append("abnormal mass resource access exceeding baseline by >5x")
                elif o == "account_lockout":
                    reasons.append("multiple consecutive authentication and MFA failures")
                else:
                    reasons.append(f"critical security override '{o}'")

        if threat_details and "summary" in threat_details:
            reasons.append(str(threat_details["summary"]))

        cause_str = "; ".join(reasons) if reasons else f"composite multi-factor risk degradation to {risk_score:.1f}/100"

        return (
            f"Security Incident Alert for user '{username}': The Zero Trust policy engine evaluated this session "
            f"at Trust Score {risk_score:.1f}/100 ({risk_level} risk). The primary root cause was {cause_str}. "
            f"In accordance with adaptive least-privilege policy, the gateway immediately enforced {action} "
            f"to protect internal resources and prevent lateral movement."
        )
