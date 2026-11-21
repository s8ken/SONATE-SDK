"""
SONATE Platform Client — Python SDK for the SONATE REST API

Provides typed access to:
  - Detection (resonance scoring)
  - Policy evaluation
  - Truth debt analysis
  - Trust pipeline (end-to-end)

Usage:
    from sonate.client import SonateClient

    client = SonateClient(base_url="https://api.yseeku.com/v1", api_key="sk-...")
    result = client.detect("Hello, I am an AI assistant.")
    print(result.trust_protocol)
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ─── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Result from the SONATE detection endpoint."""
    R_m: float = 0.5
    trust_protocol: str = "PARTIAL"
    alert_level: str = "YELLOW"
    ethical_alignment: float = 3.0
    resonance_quality: str = "STRONG"
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TruthDebtResult:
    """Result from truth debt analysis."""
    debt_score: float = 0.0
    claims: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyResult:
    """Result from policy evaluation."""
    final_action: str = "allow"
    policies_evaluated: int = 0
    policies_matched: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    """Full end-to-end pipeline result."""
    agent_id: str = ""
    action: str = "allow"
    detection: Optional[DetectionResult] = None
    truth_debt: Optional[TruthDebtResult] = None
    policy: Optional[PolicyResult] = None
    alerts_created: int = 0
    duration_ms: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)


# ─── Client ───────────────────────────────────────────────────────────────────

class SonateClient:
    """
    Python SDK client for the SONATE platform REST API.

    Uses only stdlib (urllib) — zero extra dependencies beyond the core SDK.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3000/api/v1",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # ─── HTTP Helpers ──────────────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "sonate-python-sdk/1.0.0",
        }
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            raise SonateAPIError(e.code, error_body) from e
        except urllib.error.URLError as e:
            raise SonateConnectionError(str(e.reason)) from e

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", path, body)

    def _get(self, path: str) -> Dict[str, Any]:
        return self._request("GET", path)

    # ─── Detection ─────────────────────────────────────────────────────

    def detect(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Run SONATE detection on the given content.

        Args:
            content: Text to analyze
            metadata: Optional metadata dict

        Returns:
            DetectionResult with resonance metrics
        """
        resp = self._post("/detect", {
            "content": content,
            "metadata": metadata or {},
        })
        return DetectionResult(
            R_m=resp.get("R_m", 0.5),
            trust_protocol=resp.get("trust_protocol", "PARTIAL"),
            alert_level=resp.get("alertLevel", "YELLOW"),
            ethical_alignment=resp.get("ethical_alignment", 3.0),
            resonance_quality=resp.get("resonance_quality", "STRONG"),
            raw=resp,
        )

    # ─── Truth Debt ────────────────────────────────────────────────────

    def analyze_truth_debt(self, content: str) -> TruthDebtResult:
        """
        Analyze content for truth debt (unverifiable claims).

        Args:
            content: Text to analyze

        Returns:
            TruthDebtResult with debt score and flagged claims
        """
        resp = self._post("/truth-debt", {"content": content})
        return TruthDebtResult(
            debt_score=resp.get("debtScore", 0.0),
            claims=resp.get("claims", []),
            raw=resp,
        )

    # ─── Policy ────────────────────────────────────────────────────────

    def evaluate_policy(
        self,
        agent_id: str,
        trust_score: float,
        truth_debt_score: float = 0.0,
        extra: Optional[Dict[str, Any]] = None,
    ) -> PolicyResult:
        """
        Evaluate governance policies against a context.

        Args:
            agent_id: Agent identifier
            trust_score: Current trust score (0-10)
            truth_debt_score: Truth debt score (0-1)
            extra: Additional context fields

        Returns:
            PolicyResult with final action
        """
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "trust_score": trust_score,
            "truth_debt_score": truth_debt_score,
        }
        if extra:
            body.update(extra)

        resp = self._post("/policy/evaluate", body)
        return PolicyResult(
            final_action=resp.get("finalAction", "allow"),
            policies_evaluated=resp.get("policiesEvaluated", 0),
            policies_matched=resp.get("policiesMatched", 0),
            raw=resp,
        )

    # ─── Full Pipeline ─────────────────────────────────────────────────

    def evaluate(
        self,
        agent_id: str,
        content: str,
        session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """
        Run the full trust pipeline: detect → truth debt → policy → alert.

        Args:
            agent_id: Agent identifier
            content: Text to evaluate
            session_id: Optional session ID
            tenant_id: Optional tenant ID
            metadata: Optional metadata

        Returns:
            PipelineResult with all sub-results
        """
        body: Dict[str, Any] = {
            "agentId": agent_id,
            "content": content,
        }
        if session_id:
            body["sessionId"] = session_id
        if tenant_id:
            body["tenantId"] = tenant_id
        if metadata:
            body["metadata"] = metadata

        resp = self._post("/pipeline/evaluate", body)

        detection = None
        if "detection" in resp:
            d = resp["detection"]
            detection = DetectionResult(
                R_m=d.get("R_m", 0.5),
                trust_protocol=d.get("trust_protocol", "PARTIAL"),
                alert_level=d.get("alertLevel", "YELLOW"),
                raw=d,
            )

        truth_debt = None
        if "truthDebt" in resp:
            td = resp["truthDebt"]
            truth_debt = TruthDebtResult(
                debt_score=td.get("debtScore", 0.0),
                claims=td.get("claims", []),
                raw=td,
            )

        policy = None
        if "policy" in resp:
            p = resp["policy"]
            policy = PolicyResult(
                final_action=p.get("finalAction", "allow"),
                policies_evaluated=p.get("policiesEvaluated", 0),
                policies_matched=p.get("policiesMatched", 0),
                raw=p,
            )

        return PipelineResult(
            agent_id=resp.get("agentId", agent_id),
            action=resp.get("action", "allow"),
            detection=detection,
            truth_debt=truth_debt,
            policy=policy,
            alerts_created=resp.get("alertsCreated", 0),
            duration_ms=resp.get("durationMs", 0.0),
            raw=resp,
        )

    # ─── Health Check ──────────────────────────────────────────────────

    def health(self) -> Dict[str, Any]:
        """Check platform health."""
        return self._get("/health")


# ─── Exceptions ────────────────────────────────────────────────────────────────

class SonateAPIError(Exception):
    """Raised when the SONATE API returns an error status."""
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        super().__init__(f"SONATE API error {status_code}: {body}")


class SonateConnectionError(Exception):
    """Raised when we cannot connect to the SONATE API."""
    pass
