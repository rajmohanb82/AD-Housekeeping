import json
import tempfile
import unittest
from pathlib import Path

from ad_housekeeping.directory import LabDirectory
from ad_housekeeping.policy import assess_password
from ad_housekeeping.scanner import build_alerts, scan
from ad_housekeeping.web import create_app


PASSWORD = "Orchid-harbor-7-silver"


class LabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state.json"
        self.lab = LabDirectory(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_categories_and_score(self):
        result = scan(self.lab.snapshot())
        ids = {alert["id"] for alert in result["alerts"]}
        self.assertIn("priv-arjun-domain-admins", ids)
        self.assertIn("audit-log-cleared", ids)
        self.assertIn("krbtgt-age", ids)
        self.assertIn("repl-fab-dc04", ids)
        self.assertIn("lockout-priya.nair", ids)
        self.assertNotIn("sarah.chen", " ".join(ids))
        categories = {alert["category"] for alert in result["alerts"]}
        self.assertIn("Replication", categories)
        self.assertIn("Account lockout", categories)
        self.assertGreaterEqual(result["summary"]["score"], 0)
        self.assertLessEqual(result["summary"]["score"], 100)
        self.assertEqual(result["summary"]["band"], "Action required")
        informational = [event for event in self.lab.snapshot()["events"] if event["event_id"] == 4624 and event["account"] == "sarah.chen"]
        self.assertTrue(informational)
        self.assertFalse(informational[0]["actionable"])

    def test_helpdesk_unlocks_priya_and_cannot_reset_admin(self):
        self.lab.unlock("helpdesk", "priya.nair", "Cleared the mapped drive on WKS-1042")
        state = self.lab.snapshot()
        priya = next(user for user in state["users"] if user["sam"] == "priya.nair")
        self.assertFalse(priya["locked"])
        self.assertTrue(any(event["event_id"] == 4767 and event["account"] == "priya.nair" for event in state["events"]))
        live = {alert["id"] for alert in build_alerts(state)}
        self.assertNotIn("lockout-priya.nair", live)
        self.assertIn("lockout-priya.nair", {alert["id"] for alert in state["published_alerts"]})
        with self.assertRaises(Exception) as raised:
            self.lab.reset_password("helpdesk", "helena.voss", PASSWORD, PASSWORD, True, "Should be refused")
        self.assertIn("Tier-0", str(raised.exception))
        denied = self.lab.snapshot()["audit"][0]
        self.assertEqual(denied["result"], "Denied")
        self.assertNotIn(PASSWORD, json.dumps(denied))

    def test_tier0_removes_intern_and_password_is_not_stored(self):
        self.lab.remove_domain_admin("tier0", "arjun.patel", "No change ticket for the add")
        state = self.lab.snapshot()
        arjun = next(user for user in state["users"] if user["sam"] == "arjun.patel")
        self.assertNotIn("Domain Admins", arjun["groups"])
        self.lab.reset_password("tier0", "liam.wright", PASSWORD, PASSWORD, True, "Expired password, caller verified")
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, raw)
        liam = next(user for user in self.lab.snapshot()["users"] if user["sam"] == "liam.wright")
        self.assertEqual(liam["password_age_days"], 0)
        self.assertFalse(liam["password_expired"])
        self.assertTrue(liam["must_change"])

    def test_password_rules_and_krbtgt(self):
        user = next(user for user in self.lab.snapshot()["users"] if user["sam"] == "liam.wright")
        self.assertTrue(assess_password("short", "short", user))
        self.assertTrue(assess_password("LiamWright123456!", "LiamWright123456!", user))
        self.assertEqual(assess_password(PASSWORD, PASSWORD, user), [])
        with self.assertRaises(Exception) as raised:
            self.lab.reset_password("tier0", "krbtgt", PASSWORD, PASSWORD, False, "Do not allow this")
        self.assertIn("twice", str(raised.exception).lower())

    def test_republish_clears_resolved_alert(self):
        self.lab.unlock("helpdesk", "priya.nair", "Caller confirmed on the phone")
        result = self.lab.publish("helpdesk")
        ids = {alert["id"] for alert in result["alerts"]}
        self.assertNotIn("lockout-priya.nair", ids)
        self.assertGreater(result["summary"]["score"], self.lab.snapshot()["scans"][1]["score"])


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state.json"
        self.app = create_app(self.path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess["csrf"] = "token"
            sess["role"] = "helpdesk"

    def tearDown(self):
        self.tmp.cleanup()

    def test_pages_render(self):
        for path in ["/", "/scan", "/alerts", "/events", "/infrastructure", "/accounts", "/guidance", "/deploy", "/health", "/setup", "/servers", "/hardening", "/reports"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
        self.assertIn(b"Directory Keep", self.client.get("/").data)
        self.assertIn(b"fabrikam.corp", self.client.get("/infrastructure").data)
        priya = self.client.get("/accounts/priya.nair")
        self.assertIn(b"Unlock account", priya.data)
        helena = self.client.get("/accounts/helena.voss")
        self.assertNotIn(b"Reset password</button>", helena.data)
        self.assertIn(b"Tier-0", helena.data)

    def test_denied_reset_flashes(self):
        response = self.client.post(
            "/accounts/helena.voss/reset",
            data={
                "csrf_token": "token",
                "password": PASSWORD,
                "confirm": PASSWORD,
                "must_change": "yes",
                "reason": "Trying from helpdesk",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Helpdesk can reset standard", response.data)
        self.assertNotIn(PASSWORD.encode(), self.path.read_bytes())

    def test_wizard_keeps_password_out_of_the_lab_file(self):
        response = self.client.post(
            "/setup",
            data={
                "csrf_token": "token",
                "mode": "lab",
                "host": "172.16.10.11",
                "domain": "fabrikam.corp",
                "port": "389",
                "username": "james.okonkwo",
                "password": PASSWORD,
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Authenticated to the Fabrikam lab", response.data)
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, raw)
        self.assertIn("james.okonkwo", raw)
        blocked = self.client.post("/scan", data={"csrf_token": "token"}, headers={"X-Requested-With": "fetch"})
        self.assertEqual(blocked.status_code, 200)

    def test_scan_requires_sign_in_and_pdf_has_no_secret(self):
        blocked = self.client.post("/scan", data={"csrf_token": "token"})
        self.assertEqual(blocked.status_code, 302)
        self.assertIn("/setup", blocked.headers["Location"])
        pdf = self.client.get("/reports/housekeeping.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b"%PDF"))
        self.assertNotIn(PASSWORD.encode(), pdf.data)


if __name__ == "__main__":
    unittest.main()
