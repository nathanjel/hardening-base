"""hooks/sms-supervoip against a local stand-in for supervoip's REST API."""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

HOOK = os.path.join(REPO, "hooks", "sms-supervoip")
TEXT = "agent FAIL k8s: secret-looking text 1234"


class Api(http.server.BaseHTTPRequestHandler):
    calls = []
    post_status, post_answer = 201, {"queuedMessages": [{"id": 1}]}

    def log_message(self, *a):
        pass

    def answer(self, code, data):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/ld+json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        Api.calls.append(("GET", self.path, self.headers.get("Authorization"), None))
        lists = {"/api/countries": [{"@id": "/api/countries/1", "prefix": "1"},
                                    {"@id": "/api/countries/40", "prefix": "4"},
                                    {"@id": "/api/countries/96", "prefix": "48"}],
                 "/api/sms_senders": [{"@id": "/api/sms_senders/7", "name": "Acme"}],
                 "/api/voip_numbers": [{"@id": "/api/voip_numbers/3", "phoneNumber": "48221234567"}]}
        if self.path in lists:
            self.answer(200, {"hydra:member": lists[self.path]})
        else:
            self.answer(404, {"detail": "no such thing"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Api.calls.append(("POST", self.path, self.headers.get("Authorization"), body))
        self.answer(Api.post_status, Api.post_answer)


class SupervoipHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Api.calls, Api.post_status, Api.post_answer = [], 201, {"queuedMessages": [{"id": 1}]}
        self.token = os.path.join(tempfile.mkdtemp(), "token")
        with open(self.token, "w") as f:
            f.write("\ntok123\n")

    def hook(self, *args, text=TEXT, to="+48600000000", sender="Acme"):
        argv = [sys.executable, "-IB", HOOK, "--token-file", self.token, "--api", self.url]
        argv += (["--to", to] if to else []) + (["--sender", sender] if sender else []) + list(args)
        return subprocess.run(argv, input=text, capture_output=True, text=True, timeout=30)

    def posts(self):
        return [c for c in Api.calls if c[0] == "POST"]

    def test_a_named_sender_and_the_country_from_the_prefix(self):
        r = self.hook()
        self.assertEqual(r.returncode, 0, r.stderr)
        (_, path, auth, body), = self.posts()
        self.assertEqual(path, "/api/sms_messages")
        self.assertEqual(auth, "Bearer tok123")
        self.assertEqual(body, {"recipients": ["+48600000000"], "text": TEXT, "sender": "smsSender",
                                "smsSender": "/api/sms_senders/7", "country": "/api/countries/96"})
        self.assertNotIn("secret-looking", r.stdout + r.stderr)

    def test_kinds_and_iris(self):
        self.assertEqual(self.hook(sender="SMS").returncode, 0)
        self.assertEqual(self.hook(sender="/api/voip_numbers/3", to="+1 555-0100").returncode, 0)
        a, b = (p[3] for p in self.posts())
        self.assertEqual((a["sender"], "smsSender" in a), ("SMS", False))
        self.assertEqual((b["sender"], b["voipNumber"], b["country"], b["recipients"]),
                         ("voipNumber", "/api/voip_numbers/3", "/api/countries/1", ["+15550100"]))

    def test_accepted_but_not_sent_is_a_failure(self):
        Api.post_answer = {"queuedMessages": []}
        r = self.hook()
        self.assertEqual(r.returncode, 1)
        self.assertIn("not sent", r.stderr)

    def test_an_api_error_names_the_status_never_the_text(self):
        Api.post_status, Api.post_answer = 401, {"detail": "Invalid JWT"}
        r = self.hook()
        self.assertEqual(r.returncode, 1)
        self.assertIn("401", r.stderr)
        self.assertIn("Invalid JWT", r.stderr)
        self.assertNotIn("secret-looking", r.stderr)

    def test_an_unknown_sender_name_sends_nothing(self):
        r = self.hook(sender="Nope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no SMS sender named 'Nope'", r.stderr)
        self.assertEqual(self.posts(), [])

    def test_bad_input_sends_nothing(self):
        self.assertEqual(self.hook(to="600123123").returncode, 2)
        self.assertEqual(self.hook(text="  \n").returncode, 2)
        os.unlink(self.token)
        r = self.hook()
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot read the token", r.stderr)
        self.assertEqual(Api.calls, [])

    def test_unreachable(self):
        r = subprocess.run([sys.executable, "-IB", HOOK, "--token-file", self.token, "--api", "http://127.0.0.1:9",
                            "--to", "+48600000000", "--sender", "SMS", "--country", "/api/countries/96"],
                           input=TEXT, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertIn("unreachable", r.stderr)

    def test_list_senders(self):
        r = self.hook("--list-senders", to=None, sender=None, text="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Acme", r.stdout)
        self.assertIn("/api/sms_senders/7", r.stdout)
        self.assertIn("/api/voip_numbers/3", r.stdout)


if __name__ == "__main__":
    unittest.main()
