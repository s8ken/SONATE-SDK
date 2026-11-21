"""
Tests for sonate.client — Python SDK REST API client

Uses a mock HTTP server (http.server) to verify request/response handling.
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict

import pytest

from sonate.client import (
    SonateClient,
    DetectionResult,
    TruthDebtResult,
    PolicyResult,
    PipelineResult,
    SonateAPIError,
    SonateConnectionError,
)


# ─── Mock Server ───────────────────────────────────────────────────────────────

class MockHandler(BaseHTTPRequestHandler):
    """Simple mock handler that returns canned JSON responses."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress server logs during tests

    def do_GET(self) -> None:
        if self.path == "/api/v1/health":
            self._respond(200, {"status": "ok", "version": "2.0.0"})
        elif self.path == "/api/v1/error":
            self._respond(500, {"error": "not found"})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        if self.path == "/api/v1/detect":
            self._respond(200, {
                "R_m": 0.82,
                "trust_protocol": "PASS",
                "alertLevel": "GREEN",
                "ethical_alignment": 4.0,
                "resonance_quality": "ADVANCED",
            })
        elif self.path == "/api/v1/truth-debt":
            self._respond(200, {
                "debtScore": 0.35,
                "claims": [{"claim": "fully tested", "category": "unqualified-absolute", "severity": "medium"}],
            })
        elif self.path == "/api/v1/policy/evaluate":
            self._respond(200, {
                "finalAction": "warn",
                "policiesEvaluated": 3,
                "policiesMatched": 1,
            })
        elif self.path == "/api/v1/pipeline/evaluate":
            self._respond(200, {
                "agentId": body.get("agentId", "unknown"),
                "action": "allow",
                "detection": {"R_m": 0.75, "trust_protocol": "PASS"},
                "truthDebt": {"debtScore": 0.2, "claims": []},
                "policy": {"finalAction": "allow", "policiesEvaluated": 2, "policiesMatched": 0},
                "alertsCreated": 0,
                "durationMs": 12.5,
            })
        elif self.path == "/api/v1/error":
            self._respond(500, {"error": "internal server error"})
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, status: int, body: Dict[str, Any]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))


@pytest.fixture(scope="module")
def mock_server():
    """Start a mock HTTP server on a random port."""
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/api/v1"
    server.shutdown()


@pytest.fixture
def client(mock_server: str) -> SonateClient:
    return SonateClient(base_url=mock_server, api_key="test-key", timeout=5.0)


# ─── Tests ─────────────────────────────────────────────────────────────────────

class TestSonateClient:
    def test_health(self, client: SonateClient) -> None:
        result = client.health()
        assert result["status"] == "ok"

    def test_detect(self, client: SonateClient) -> None:
        result = client.detect("Hello, I am an AI assistant")
        assert isinstance(result, DetectionResult)
        assert result.R_m == 0.82
        assert result.trust_protocol == "PASS"
        assert result.alert_level == "GREEN"

    def test_truth_debt(self, client: SonateClient) -> None:
        result = client.analyze_truth_debt("We are fully tested and compliant")
        assert isinstance(result, TruthDebtResult)
        assert result.debt_score == 0.35
        assert len(result.claims) == 1

    def test_policy_evaluate(self, client: SonateClient) -> None:
        result = client.evaluate_policy("agent-1", trust_score=7.5, truth_debt_score=0.3)
        assert isinstance(result, PolicyResult)
        assert result.final_action == "warn"
        assert result.policies_evaluated == 3

    def test_pipeline_evaluate(self, client: SonateClient) -> None:
        result = client.evaluate(
            agent_id="agent-pipeline",
            content="Test content",
            session_id="s1",
            tenant_id="t1",
        )
        assert isinstance(result, PipelineResult)
        assert result.agent_id == "agent-pipeline"
        assert result.action == "allow"
        assert result.detection is not None
        assert result.detection.R_m == 0.75
        assert result.truth_debt is not None
        assert result.truth_debt.debt_score == 0.2
        assert result.policy is not None
        assert result.policy.final_action == "allow"
        assert result.duration_ms == 12.5

    def test_api_error(self, mock_server: str) -> None:
        # Point client at the error endpoint
        client = SonateClient(base_url=mock_server)
        with pytest.raises(SonateAPIError) as exc_info:
            client._get("/error")
        assert exc_info.value.status_code == 500

    def test_connection_error(self) -> None:
        client = SonateClient(base_url="http://127.0.0.1:1", timeout=1.0)
        with pytest.raises(SonateConnectionError):
            client.health()

    def test_api_key_header(self, mock_server: str) -> None:
        """Ensure Authorization header is set."""
        client = SonateClient(base_url=mock_server, api_key="sk-test-123")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer sk-test-123"

    def test_no_api_key(self, mock_server: str) -> None:
        """No Authorization header when api_key is None."""
        client = SonateClient(base_url=mock_server)
        headers = client._headers()
        assert "Authorization" not in headers
