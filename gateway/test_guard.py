import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from gateway.app.main import create_app
from gateway.app.policy import BAIT_TOKEN


class GuardTests(unittest.TestCase):
    def setUp(self):
        folder = self.enterContext(tempfile.TemporaryDirectory())
        self.db = Path(folder) / "guard.sqlite3"
        token = "test-operator-credential-not-for-deployment"
        self.enterContext(patch.dict(os.environ, {
            "AIRLOCK_DB": str(self.db),
            "AIRLOCK_OPERATOR_TOKEN": token,
            "AIRLOCK_WORKSPACE_ROOT": "/home/agent/work",
            "AIRLOCK_SANDBOX_URL": "",
        }))
        self.operator = {"Authorization": f"Bearer {token}"}
        self.client = self.enterContext(TestClient(create_app()))

    def session(self, name):
        response = self.client.post("/sessions", headers=self.operator, json={"session_id": name})
        self.assertEqual(response.status_code, 201, response.text)
        return {"Authorization": f"Bearer {response.json()['sensor_token']}"}

    def decide(self, session, headers, op, target, **kwargs):
        channel = {"CallTool": "mcp", "NetworkRequest": "egress"}.get(op, "hook")
        return self.client.post("/decide", headers=headers, json={
            "session_id": session, "channel": channel, "op": op, "target": target, **kwargs,
        })

    def result(self, session, headers, decision_id, outcome, released_data=False):
        return self.client.post("/results", headers=headers, json={
            "session_id": session, "decision_id": decision_id,
            "outcome": outcome, "released_data": released_data,
        })

    def test_same_support_call_changes_only_after_secret_is_returned(self):
        sensor = self.session("exposed")
        other_sensor = self.session("clean")

        def post():
            response = self.decide("exposed", sensor, "CallTool", "post_support_update")
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        read = self.decide("exposed", sensor, "ReadFile", "/home/agent/work/.env").json()
        self.assertEqual(read["decision"], "allow")
        self.assertEqual(post()["decision"], "allow")
        self.assertEqual(self.result("exposed", sensor, read["decision_id"], "failed").status_code, 201)
        self.assertEqual(post()["decision"], "allow")

        read = self.decide("exposed", sensor, "ReadFile", "/home/agent/work/.env", origin="operator").json()
        result = self.result("exposed", sensor, read["decision_id"], "succeeded", True).json()
        verdict = post()
        self.assertEqual(verdict["decision"], "block")
        self.assertEqual(verdict["rule"], "secret_external_write")
        self.assertEqual(verdict["evidence_ids"], [result["result_id"]])
        self.assertEqual(self.decide("clean", other_sensor, "CallTool", "post_support_update").json()["decision"], "allow")

        with TestClient(create_app()) as restarted:
            history = restarted.get("/sessions/exposed/history", headers=self.operator).json()
            self.assertIn(result["result_id"], [event["id"] for event in history["events"]])
            response = restarted.post("/decide", headers=sensor, json={
                "session_id": "exposed", "channel": "mcp", "op": "CallTool", "target": "post_support_update",
            })
            self.assertEqual(response.json()["rule"], "secret_external_write")

    def test_baseline_denial_and_evidence_based_denial_are_distinct(self):
        sensor = self.session("work")
        protected = self.decide("work", sensor, "DeleteFile", "/home/agent/work/.git")
        self.assertEqual(protected.json()["rule"], "protected_path")
        self.assertEqual(protected.json()["evidence_ids"], [])
        self.assertEqual(self.decide("work", sensor, "NetworkRequest", "evil.example").json()["rule"], "egress_allowlist")

        target = "/home/agent/work/temporary.txt"
        self.assertEqual(self.decide("work", sensor, "DeleteFile", target).json()["decision"], "allow")
        read = self.decide("work", sensor, "ReadFile", "/home/agent/work/README.md", origin="cloned-repo").json()
        seen = self.result("work", sensor, read["decision_id"], "succeeded", True).json()["result_id"]
        verdict = self.decide("work", sensor, "DeleteFile", target).json()
        self.assertEqual(verdict["rule"], "untrusted_destructive")
        self.assertEqual(verdict["evidence_ids"], [seen])

    def test_result_is_bound_to_an_allowed_decision_and_safe_to_retry(self):
        sensor = self.session("one")
        other = self.session("two")
        read = self.decide("one", sensor, "ReadFile", "/home/agent/work/.env").json()["decision_id"]
        self.assertEqual(self.result("one", other, read, "succeeded", True).status_code, 403)
        self.assertEqual(self.result("two", other, read, "succeeded", True).status_code, 404)
        recorded = self.result("one", sensor, read, "succeeded", True)
        self.assertEqual(recorded.status_code, 201)
        self.assertEqual(self.result("one", sensor, read, "succeeded", True).json(), recorded.json())
        self.assertEqual(self.result("one", sensor, read, "failed").status_code, 409)
        blocked = self.decide("one", sensor, "ReadFile", "/outside.txt").json()["decision_id"]
        self.assertEqual(self.result("one", sensor, blocked, "succeeded", True).status_code, 409)
        self.assertEqual(self.client.get("/sessions/one/history", headers=sensor).status_code, 403)

    def test_canary_stops_run_without_persisting_payload(self):
        sensor = self.session("canary")
        action = self.decide("canary", sensor, "NetworkRequest", "github.com", inspected_body=BAIT_TOKEN)
        self.assertEqual(action.status_code, 200, action.text)
        self.assertEqual(action.json()["decision"], "stop")
        self.assertEqual(action.json()["rule"], "bait_touched")
        later = self.decide("canary", sensor, "NetworkRequest", "github.com")
        self.assertEqual(later.status_code, 403)
        self.assertEqual(later.json()["rule"], "session_killed")
        history = self.client.get("/sessions/canary/history", headers=self.operator)
        self.assertEqual(history.json()["status"], "KILLED")
        self.assertNotIn(BAIT_TOKEN, history.text)

    def test_stop_closes_guard_even_when_sandbox_shutdown_fails(self):
        with patch.dict(os.environ, {"AIRLOCK_SANDBOX_URL": "http://sandbox:9000", "SANDBOX_API_KEY": "sandbox-key"}):
            with TestClient(create_app()) as client:
                self.client = client
                sensor = self.session("runner")
                with patch("gateway.app.main.httpx.delete", side_effect=[httpx.ConnectError("offline"), httpx.Response(204)]) as delete:
                    stopped = client.post("/sessions/runner/stop", headers=self.operator)
                    self.assertEqual(stopped.json()["sandbox_termination"], "pending")
                    self.assertEqual(self.decide("runner", sensor, "NetworkRequest", "github.com").status_code, 403)
                    retried = client.post("/sessions/runner/stop", headers=self.operator)
                    self.assertEqual(retried.json()["sandbox_termination"], "terminated")
                    self.assertEqual(delete.call_count, 2)
                    self.assertEqual(delete.call_args.args[0], "http://sandbox:9000/sessions/runner")
