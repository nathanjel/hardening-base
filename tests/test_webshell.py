"""The web shell daemon over real sockets: who is served, logins and their limits, sessions, the
WebSocket terminal (cat on a pty instead of tmux), the public window, size limits, the pins."""
import asyncio
import base64
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import pwd
import warnings

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402,F401  (puts lib/ on sys.path)
from hbkit import otp, webshell as ws  # noqa: E402

PASSWORD = "correct horse battery staple"
HOST = "shell.test"
TUNNEL, INGRESS = "127.0.0.0/29", "127.0.0.9"
ME = pwd.getpwuid(os.getuid()).pw_name


class Server:
    """The daemon on 127.0.0.1:<free port>: 127.0.0.0/29 plays the tunnel, 127.0.0.9 the ingress pod."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.secret = otp.new_secret()
        ws.STATE_DIR, ws.AUTH = self.dir, os.path.join(self.dir, "auth.json")
        with open(ws.AUTH, "w") as f:
            json.dump({"password": otp.scrypt_hash(PASSWORD), "secret": self.secret}, f)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        files, pages, bad = ws.load_assets()
        assert not bad, bad
        self.shell = ws.Shell(ws.Settings(f"127.0.0.1:{self.port}", TUNNEL, HOST, [f"{INGRESS}/32"]), files, pages)
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        assert self.ready.wait(5)
        self.step = int(time.time() // otp.STEP) - 1        # codes for the previous, current and next step work

    def run(self):
        self.loop = asyncio.new_event_loop()
        self.loop.run_until_complete(self.main())

    async def main(self):
        self.stop = asyncio.Event()
        await self.shell.serve(self.stop, self.ready)

    def close(self):
        self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(5)

    def code(self):
        """A code the daemon hasn't seen yet (each works once)."""
        c = otp.hotp(otp.b32key(self.secret), self.step)
        self.step += 1
        return c

    # a plain HTTP/1.1 client

    def request(self, method, path, headers=None, body=b"", src="127.0.0.1", host=None, raw=None):
        """(status, headers, body), or None when the daemon closed without answering."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5, source_address=(src, 0))
        h = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        if body:
            h["Content-Length"] = str(len(body))
        s.sendall(raw if raw is not None else
                  (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
                   + "\r\n").encode() + body)
        data = b""
        try:
            while chunk := s.recv(65536):
                data += chunk
        except ConnectionResetError:
            pass
        s.close()
        if not data:
            return None
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        hdrs = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            hdrs.setdefault(k.lower(), []).append(v.strip())
        return int(lines[0].split()[1]), hdrs, rest

    def origin(self, ingress=False):
        return {"Origin": f"https://{HOST}" if ingress else f"http://127.0.0.1:{self.port}"}

    def login(self, password=PASSWORD, code=None, src="127.0.0.1", ingress=False, extra=None):
        body = urllib.parse.urlencode({"password": password, "code": code or self.code()}).encode()
        h = {**self.origin(ingress), "Content-Type": "application/x-www-form-urlencoded", **(extra or {})}
        return self.request("POST", "/login", h, body, src=src, host=HOST if ingress else None)

    # a WebSocket client

    def ws_open(self, cookie, origin=True, src="127.0.0.1", ingress=False, extra=None):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5, source_address=(src, 0))
        key = base64.b64encode(os.urandom(16)).decode()
        h = {"Host": HOST if ingress else f"127.0.0.1:{self.port}", "Upgrade": "websocket", "Connection": "Upgrade",
             "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key, "Cookie": cookie,
             **(self.origin(ingress) if origin else {}), **(extra or {})}
        s.sendall(("GET /ws HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1)
            if not chunk:
                break
            head += chunk
        return s, int(head.split()[1]) if head else None

    @staticmethod
    def ws_send(s, op, payload, mask=True):
        n = len(payload)
        b2 = (0x80 if mask else 0)
        head = struct.pack("!BB", 0x80 | op, b2 | n) if n < 126 else (
            struct.pack("!BBH", 0x80 | op, b2 | 126, n) if n < 65536 else struct.pack("!BBQ", 0x80 | op, b2 | 127, n))
        if mask:
            key = os.urandom(4)
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
            head += key
        s.sendall(head + payload)

    @staticmethod
    def ws_recv(s):
        def exact(n):
            buf = b""
            while len(buf) < n:
                chunk = s.recv(n - len(buf))
                if not chunk:
                    raise EOFError
                buf += chunk
            return buf
        b1, b2 = exact(2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", exact(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", exact(8))[0]
        return b1 & 0x0F, exact(n)


def cookie_of(resp):
    return resp[1]["set-cookie"][0].split(";")[0]


class WebShellTest(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", DeprecationWarning)    # fork() from the test's server thread
        warnings.simplefilter("ignore", ResourceWarning)
        self.saved = {n: getattr(ws, n) for n in ("STATE_DIR", "AUTH", "TERMINAL", "FAIL_DELAY", "SESSION_IDLE", "log")}
        self.logs = []
        ws.TERMINAL, ws.FAIL_DELAY, ws.log = ("/bin/cat",), 0, self.logs.append
        self.srv = Server()

    def tearDown(self):
        self.srv.close()
        for n, v in self.saved.items():
            setattr(ws, n, v)

    def test_login_page_and_its_headers(self):
        status, h, body = self.srv.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b'action="/login"', body)
        self.assertIn("script-src 'self'", h["content-security-policy"][0])
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"][0])
        self.assertEqual(h["x-frame-options"], ["DENY"])
        # Browsers send "Origin: null" on form POSTs from a no-referrer page, and the login would be refused.
        self.assertIn(h["referrer-policy"][0], ("same-origin", "strict-origin", "strict-origin-when-cross-origin"))
        self.assertNotIn("strict-transport-security", h)        # plain HTTP inside the tunnel

    def test_who_is_dropped(self):
        self.assertIsNone(self.srv.request("GET", "/", host="evil.example"))      # DNS rebinding
        self.assertIsNone(self.srv.request("GET", "/", src=INGRESS, host=HOST,     # no public window
                                           headers={"X-Forwarded-Proto": "https"}))
        self.assertIsNone(self.srv.request("GET", "/", src="127.0.0.20"))        # neither tunnel nor ingress

    def test_login_terminal_logout(self):
        s = self.srv
        self.assertEqual(s.request("POST", "/login", {"Content-Type": "application/x-www-form-urlencoded"},
                                   b"password=x&code=123456")[0], 403)          # no Origin
        bad = s.login(password="wrong password here", code="000000")
        self.assertEqual((bad[0], bad[1]["location"]), (303, ["/?m=bad"]))
        code = s.code()
        ok = s.login(code=code)
        self.assertEqual((ok[0], ok[1]["location"]), (303, ["/"]))
        attrs = ok[1]["set-cookie"][0]
        self.assertTrue(attrs.startswith("hbws="))
        for a in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(a, attrs)
        self.assertNotIn("Secure", attrs)
        self.assertEqual(s.login(code=code)[1]["location"], ["/?m=bad"])          # a code works once
        cookie = cookie_of(ok)
        self.assertIn(b'id="term"', s.request("GET", "/", {"Cookie": cookie})[2])
        self.assertEqual(s.ws_open(cookie, origin=False)[1], 403)
        self.assertEqual(s.ws_open("hbws=forged")[1], 403)
        sock, status = s.ws_open(cookie)
        self.assertEqual(status, 101)
        s.ws_send(sock, 1, b'r{"c":100,"r":30}')
        s.ws_send(sock, 1, b"ihello from the test\n")
        got = b""
        while b"hello from the test" not in got:
            op, data = s.ws_recv(sock)
            self.assertEqual(op, 2)
            got += data
        out = s.request("POST", "/logout", {**s.origin(), "Cookie": cookie, "Content-Length": "0"})
        self.assertEqual(out[1]["location"], ["/?m=out"])
        while True:                                     # logging out closes the terminal with 4001
            op, data = s.ws_recv(sock)
            if op == 8:
                self.assertEqual(struct.unpack("!H", data[:2])[0], 4001)
                break
        self.assertIn(b'action="/login"', s.request("GET", "/", {"Cookie": cookie})[2])
        sock.close()
        logged = "\n".join(self.logs)                       # who and from where, never what
        self.assertIn("login: 127.0.0.1 via wg", logged)
        for secret in (PASSWORD, "wrong password here", code, "hello from the test"):
            self.assertNotIn(secret, logged)

    def test_failures_slow_down_then_lock(self):
        s = self.srv
        for _ in range(ws.IP_FAILS):
            self.assertEqual(s.login(password="nope nope nope", code="000000")[1]["location"], ["/?m=bad"])
        self.assertEqual(s.login()[1]["location"], ["/?m=slow"])                  # even the right one
        for src in ("127.0.0.2", "127.0.0.3", "127.0.0.4"):
            for _ in range(ws.IP_FAILS):
                s.login(password="nope nope nope", code="000000", src=src)
        self.assertTrue(os.path.exists(os.path.join(s.dir, "lock")))
        self.assertEqual(s.login(src="127.0.0.5")[1]["location"], ["/?m=locked"])
        os.remove(os.path.join(s.dir, "lock"))                                    # hb webshell unlock
        self.assertEqual(s.login(src="127.0.0.5")[1]["location"], ["/"])

    def test_public_window(self):
        s = self.srv
        h = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.5"}
        with open(os.path.join(s.dir, "public"), "w") as f:
            json.dump({"until": time.time() + 60}, f)
        status, hdrs, _ = s.request("GET", "/", h, src=INGRESS, host=HOST)
        self.assertEqual(status, 200)
        self.assertIn("strict-transport-security", hdrs)
        self.assertIsNone(s.request("GET", "/", {"X-Forwarded-Proto": "http"}, src=INGRESS, host=HOST))
        self.assertEqual(s.request("GET", "/", h, src=INGRESS, host=HOST + ":443")[0], 200)   # the port spelled out
        self.assertIsNone(s.request("GET", "/", h, src=INGRESS, host=HOST + ":8443"))
        self.assertIsNone(s.request("GET", "/", h, src=INGRESS))                  # tunnel Host via the ingress
        ok = s.login(src=INGRESS, ingress=True, extra=h)
        attrs = ok[1]["set-cookie"][0]
        self.assertTrue(attrs.startswith("__Host-hbws="))
        self.assertIn("Secure", attrs)
        self.assertEqual(s.shell.last_login["client"], "203.0.113.5")            # X-Forwarded-For, from the ingress
        # traefik marks WebSocket upgrades X-Forwarded-Proto: wss (the first phone login met a 502 here)
        sock, status = s.ws_open(cookie_of(ok), src=INGRESS, ingress=True,
                                 extra={"X-Forwarded-Proto": "wss", "X-Forwarded-For": "203.0.113.5"})
        self.assertEqual(status, 101)
        sock.close()
        self.assertIsNone(s.ws_open(cookie_of(ok), src=INGRESS, ingress=True, extra={"X-Forwarded-Proto": "ws"})[1])
        tunnel_cookie = cookie_of(ok).replace("__Host-hbws", "hbws")
        self.assertIn(b'action="/login"', s.request("GET", "/", {"Cookie": tunnel_cookie})[2])
        with open(os.path.join(s.dir, "public"), "w") as f:
            json.dump({"until": time.time() - 1}, f)
        self.assertIsNone(s.request("GET", "/", h, src=INGRESS, host=HOST))      # the window has passed

    def test_limits(self):
        s = self.srv
        self.assertIsNone(s.request("GET", "/", raw=b"GET / HTTP/1.1\r\nX-Big: " + b"a" * 9000 + b"\r\n\r\n"))
        self.assertEqual(s.request("POST", "/login", {**s.origin(), "Content-Length": "5000"})[0], 413)
        self.assertEqual(s.request("GET", "/", raw=b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n")[0], 400)
        cookie = cookie_of(s.login())
        sock, _ = s.ws_open(cookie)
        s.ws_send(sock, 1, b"ihi", mask=False)                                    # browsers must mask
        op, data = s.ws_recv(sock)
        while op != 8:
            op, data = s.ws_recv(sock)
        self.assertEqual(struct.unpack("!H", data[:2])[0], 1002)
        sock, _ = s.ws_open(cookie)
        s.ws_send(sock, 1, b"i" + b"x" * (ws.MAX_FRAME + 1))
        op, data = s.ws_recv(sock)
        while op != 8:
            op, data = s.ws_recv(sock)
        self.assertEqual(struct.unpack("!H", data[:2])[0], 1009)
        for _ in range(50):                                 # the two closed above finish their cleanup
            if not s.shell.terminals:
                break
            time.sleep(0.1)
        socks = [s.ws_open(cookie) for _ in range(ws.MAX_TERMINALS)]
        self.assertEqual([st for _, st in socks], [101] * ws.MAX_TERMINALS)
        extra, status = s.ws_open(cookie)
        self.assertEqual(status, 503)
        for sock, _ in socks + [(extra, None)]:
            sock.close()

    def test_idle_session_ends(self):
        ws.SESSION_IDLE = 1
        cookie = cookie_of(self.srv.login())
        time.sleep(1.5)
        self.assertIn(b'action="/login"', self.srv.request("GET", "/", {"Cookie": cookie})[2])


class AdminTest(unittest.TestCase):
    """hb-webshell (root's side): the unit it writes, the objects \`open\` applies, durations."""

    def setUp(self):
        from tools import load_tool
        self.tool = load_tool("webshell")
        self.s = {"user": ME, "port": 7681, "host": "shell.example.org", "iface": "wg0", "addr": "10.77.0.1",
                  "net": "10.77.0.0/24", "ingress_from": ["10.1.0.0/16"], "class": "public", "ns": "default",
                  "issuer": "letsencrypt", "middlewares": "default-redirect-https@kubernetescrd", "max_hours": 12}

    def exec_args(self, unit):
        line = [l for l in unit.splitlines() if l.startswith("ExecStart=")][0]
        return line.split()[2:]                       # after the program and "serve"

    def test_unit(self):
        unit = self.tool.unit_wanted(self.s)
        for want in (f"User={ME}\n", "LoadCredential=auth:/etc/hb/webshell.json\n", "StateDirectory=hb-webshell\n",
                     "KillMode=process\n", "After=network-online.target wg-quick@wg0.service\n"):
            self.assertIn(want, unit)
        settings, why = ws.parse_args(self.exec_args(unit))  # the daemon reads back what root wrote
        self.assertIsNone(why)
        self.assertEqual((settings.wg_host, str(settings.wg_net), settings.host, [str(n) for n in settings.ingress_nets]),
                         ("10.77.0.1:7681", "10.77.0.0/24", "shell.example.org", ["10.1.0.0/16"]))
        tunnel_only = ws.parse_args(self.exec_args(self.tool.unit_wanted({**self.s, "host": ""})))[0]
        self.assertEqual((tunnel_only.host, tunnel_only.ingress_nets), ("", []))
        self.assertIsNotNone(ws.parse_args(["--listen", "10.77.0.1:7681", "--bogus", "x"])[1])

    def test_manifests(self):
        keep, ing = self.tool.manifests(self.s)
        svc, eps, cert = keep
        self.assertNotIn("selector", svc["spec"])                                  # the EndpointSlice says where
        self.assertEqual(eps["metadata"]["labels"]["kubernetes.io/service-name"], svc["metadata"]["name"])
        self.assertEqual(eps["endpoints"][0]["addresses"], ["10.77.0.1"])
        self.assertEqual(eps["ports"][0]["name"], svc["spec"]["ports"][0]["name"])
        self.assertEqual(cert["spec"]["dnsNames"], ["shell.example.org"])
        self.assertEqual(ing["spec"]["tls"][0]["secretName"], cert["spec"]["secretName"])
        self.assertEqual(ing["spec"]["rules"][0]["host"], "shell.example.org")
        self.assertEqual(ing["spec"]["ingressClassName"], "public")
        self.assertEqual(ing["metadata"]["annotations"],
                         {"traefik.ingress.kubernetes.io/router.middlewares": "default-redirect-https@kubernetescrd"})

    def test_code_change_is_noticed(self):
        self.assertTrue(self.tool.code_changed_since(0))
        self.assertFalse(self.tool.code_changed_since(time.time() + 60))

    def test_durations(self):
        p = self.tool.parse_duration
        self.assertEqual((p("2h", 12), p("30m", 12), p("12h", 12)), (7200, 1800, 43200))
        for bad in ("13h", "0m", "2d", "", "h", "-1h"):
            self.assertIsNone(p(bad, 12), bad)


class PinTest(unittest.TestCase):
    def test_vendored_files_match_their_pins(self):
        self.assertEqual(ws.load_assets()[2], [])
        d = tempfile.mkdtemp()
        shutil.copytree(ws.WEB, d, dirs_exist_ok=True)
        with open(os.path.join(d, "vendor", "xterm", "xterm.js"), "a") as f:
            f.write("\n// changed\n")
        self.assertEqual(ws.load_assets(d)[2], ["vendor/xterm/xterm.js"])


if __name__ == "__main__":
    unittest.main()
