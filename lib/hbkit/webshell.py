"""hb's web shell daemon: a login page, then your shell (in tmux) in the browser.

It runs as the shell's user from hb-webshell.service and listens on the
WireGuard address only. It reads no config: root's hb-webshell writes the
settings into the unit's command line, and systemd hands it the password hash
and code secret as a credential (LoadCredential), so they stay root-only on disk. Connections from the
tunnel's network are served. Connections from webshell.ingress_from (the
ingress pod) are served only while `hb webshell open` has a window open, only
for webshell.host, and only as HTTPS (X-Forwarded-Proto). Anything else is
dropped without a word.

Guards: a password (scrypt) and a 6-digit code from the web shell's own
authenticator entry. 5 failed logins per address in 15 minutes; after 20 in an
hour, logins stop for everyone until `hb webshell unlock`. Sessions: a random
token in an HttpOnly, SameSite=Strict cookie (__Host- and Secure over HTTPS),
12 hours at most and 30 idle minutes. Every POST and the WebSocket must carry
this site's Origin. No inline script, no framing. The request head, the body,
WebSocket frames and the time to send them are all bounded; at most 3
terminals. Logs say who logged in or failed, from where; terminal content is
never logged.

Standard library only. The browser side is vendored xterm.js, pinned by sha256.
"""
import asyncio
import base64
import collections
import fcntl
import hashlib
import html
import ipaddress
import json
import os
import pty
import pwd
import re
import secrets
import signal
import socket
import struct
import sys
import termios
import time
import urllib.parse

from hbkit import otp, util

WEB = os.path.join(util.HB_ROOT, "web")
AUTH = os.environ.get("HB_WEBSHELL_AUTH") or os.path.join(os.environ.get("CREDENTIALS_DIRECTORY", "/nonexistent"), "auth")
STATE_DIR = os.environ.get("HB_WEBSHELL_STATE", "/var/lib/hb-webshell")

MAX_HEAD = 8192              # request line plus headers
MAX_HEADERS = 64
MAX_BODY = 2048              # the login form
HEAD_TIMEOUT = BODY_TIMEOUT = 10
MAX_CONNECTIONS = 32
MAX_FRAME = 64 * 1024        # one WebSocket message from the browser
MAX_TERMINALS = 3
SESSION_MAX, SESSION_IDLE = 12 * 3600, 30 * 60
IP_FAILS, IP_WINDOW = 5, 15 * 60
ALL_FAILS, ALL_WINDOW = 20, 3600
PING_EVERY, PONG_WAIT = 30, 75
FAIL_DELAY = 1               # seconds before answering a failed login
TERMINAL = ("tmux", "new-session", "-A", "-s", "web")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
IP_FREEBIND = 15             # bind the tunnel address even before wg0 is up

PINNED = {
    "vendor/xterm/xterm.js": "14903579ff54664cd72f8e8699e6961a6272c21863ec1c3b118cdc8af5d4a972",
    "vendor/xterm/xterm.css": "854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6",
    "vendor/xterm/addon-fit.js": "ba3ea256ce0620a0992a197d6c9baea64823fc93d8da07a9e366ca9943c18527",
}
STATIC = {
    "/static/xterm.js": ("vendor/xterm/xterm.js", "text/javascript"),
    "/static/xterm.css": ("vendor/xterm/xterm.css", "text/css"),
    "/static/addon-fit.js": ("vendor/xterm/addon-fit.js", "text/javascript"),
    "/static/term.js": ("term.js", "text/javascript"),
    "/static/style.css": ("style.css", "text/css"),
}
# Inline styles are allowed because xterm.js writes its own <style> elements; scripts are 'self' only.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; "
       "img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
MESSAGES = {
    "bad": "Wrong password or code.",
    "slow": "Too many attempts from your address. Try again in 15 minutes.",
    "locked": "Logins are locked after too many failed attempts. On the server: hb webshell unlock",
    "off": "Not set up yet. On the server: hb webshell apply",
    "out": "Logged out.",
}
# Not no-referrer: with it, browsers send "Origin: null" on the page's own form POSTs, which the
# Origin check rightly refuses. same-origin keeps the real Origin there and tells other sites nothing.
REFERRER = "same-origin"
REASONS = {101: "Switching Protocols", 200: "OK", 303: "See Other", 400: "Bad Request", 403: "Forbidden",
           404: "Not Found", 405: "Method Not Allowed", 413: "Content Too Large", 503: "Service Unavailable"}
SINGLE = {"host", "content-length", "content-type", "origin", "cookie", "upgrade", "sec-websocket-key",
          "sec-websocket-version", "x-forwarded-for", "x-forwarded-proto"}


def log(text):
    print(text, file=sys.stderr, flush=True)


def state_path(name):
    return os.path.join(STATE_DIR, name)


def locked():
    return os.path.exists(state_path("lock"))


def public_until():
    data = util.read_json(state_path("public"), {})
    try:
        return float(data.get("until", 0))
    except (AttributeError, TypeError, ValueError):
        return 0.0


def load_assets(web=WEB):
    """({path: (bytes, content type)}, {page: html}, [pinned files whose sha256 differs])."""
    files, bad = {}, []
    for path, (name, ctype) in STATIC.items():
        with open(os.path.join(web, name), "rb") as f:
            data = f.read()
        if name in PINNED and hashlib.sha256(data).hexdigest() != PINNED[name]:
            bad.append(name)
        files[path] = (data, ctype + "; charset=utf-8")
    pages = {}
    for page in ("login", "term"):
        with open(os.path.join(web, page + ".html"), encoding="utf-8") as f:
            pages[page] = f.read()
    return files, pages, bad


class Settings:
    def __init__(self, listen, tunnel, host="", ingress_from=()):
        addr, _, port = listen.rpartition(":")
        self.addr, self.port = str(ipaddress.IPv4Address(addr)), int(port)
        self.wg_net = ipaddress.ip_network(tunnel, strict=False)
        self.ingress_nets = [ipaddress.ip_network(n, strict=False) for n in ingress_from]
        self.host = host.lower()
        self.wg_host = f"{self.addr}:{self.port}"
        self.title = socket.gethostname().split(".")[0]
        pw = pwd.getpwuid(os.getuid())
        self.user, self.home, self.shell = pw.pw_name, pw.pw_dir, pw.pw_shell or "/bin/bash"

    def origin(self, via):
        return f"https://{self.host}" if via == "ingress" else f"http://{self.wg_host}"


# --- HTTP -----------------------------------------------------------------------------

class HttpError(Exception):
    def __init__(self, status):
        super().__init__(status)
        self.status = status


class Request:
    def __init__(self, method, path, query, headers, body):
        self.method, self.path, self.query, self.headers, self.body = method, path, query, headers, body
        self.via = self.client = None


async def read_request(reader):
    """The next request, or None when the client sent nothing usable in time."""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
        return None
    if len(head) > MAX_HEAD:
        raise HttpError(400)
    lines = head[:-4].decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise HttpError(400)
    method, target = parts[0], parts[1]
    if method not in ("GET", "POST"):
        raise HttpError(405)
    if not target.startswith("/") or len(target) > 1024:
        raise HttpError(400)
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        name = name.lower()
        if not sep or not name or not re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]+", name) or len(headers) >= MAX_HEADERS:
            raise HttpError(400)
        if name in headers:
            if name in SINGLE:
                raise HttpError(400)
            headers[name] += ", " + value.strip()
        else:
            headers[name] = value.strip()
    if "transfer-encoding" in headers:
        raise HttpError(400)
    body = b""
    if method == "POST":
        n = headers.get("content-length", "")
        if not n.isdigit():
            raise HttpError(400)
        if int(n) > MAX_BODY:
            raise HttpError(413)
        try:
            body = await asyncio.wait_for(reader.readexactly(int(n)), BODY_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
    path, _, query = target.partition("?")
    return Request(method, path, query, headers, body)


def response(status, body=b"", ctype="text/plain; charset=utf-8", extra=(), secure=False, cache="no-store"):
    lines = [f"HTTP/1.1 {status} {REASONS[status]}", f"Content-Type: {ctype}", f"Content-Length: {len(body)}",
             "Connection: close", f"Content-Security-Policy: {CSP}", "X-Frame-Options: DENY",
             "X-Content-Type-Options: nosniff", f"Referrer-Policy: {REFERRER}", f"Cache-Control: {cache}",
             "Cross-Origin-Opener-Policy: same-origin", "Cross-Origin-Resource-Policy: same-origin"]
    if secure:
        lines.append("Strict-Transport-Security: max-age=31536000")
    lines += list(extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


# --- WebSocket ------------------------------------------------------------------------

class WsClose(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def ws_frame(op, payload=b""):
    n, b1 = len(payload), 0x80 | op
    if n < 126:
        head = struct.pack("!BB", b1, n)
    elif n < 65536:
        head = struct.pack("!BBH", b1, 126, n)
    else:
        head = struct.pack("!BBQ", b1, 127, n)
    return head + payload


def unmask(data, mask):
    n = len(data)
    if not n:
        return data
    m = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "little") ^ int.from_bytes(m, "little")).to_bytes(n, "little")


class WsReader:
    """Messages from the browser: (opcode, payload). Control frames come back as they arrive,
    even in the middle of a fragmented message."""

    def __init__(self, reader):
        self.reader, self.op, self.parts, self.size = reader, None, [], 0

    async def read(self):
        while True:
            b1, b2 = await self.reader.readexactly(2)
            fin, op, n = b1 & 0x80, b1 & 0x0F, b2 & 0x7F
            if b1 & 0x70 or not b2 & 0x80:            # no extensions; browsers must mask
                raise WsClose(1002)
            if n == 126:
                n = struct.unpack("!H", await self.reader.readexactly(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", await self.reader.readexactly(8))[0]
            if op >= 8:
                if not fin or n > 125:
                    raise WsClose(1002)
            elif self.size + n > MAX_FRAME:
                raise WsClose(1009)
            mask = await self.reader.readexactly(4)
            data = unmask(await self.reader.readexactly(n), mask)
            if op >= 8:
                return op, data
            if op == 0:
                if self.op is None:
                    raise WsClose(1002)
            elif self.op is not None or op not in (1, 2):
                raise WsClose(1002)
            else:
                self.op = op
            self.parts.append(data)
            self.size += n
            if fin:
                msg = (self.op, b"".join(self.parts))
                self.op, self.parts, self.size = None, [], 0
                return msg


def ws_accept(key):
    try:
        if len(base64.b64decode(key, validate=True)) != 16:
            return None
    except ValueError:
        return None
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


# --- the terminal -----------------------------------------------------------------------

def spawn(s):
    """A tmux client on a new pty, attached to (or creating) session "web". Returns (pid, master fd)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(s.home)
            env = {"HOME": s.home, "USER": s.user, "LOGNAME": s.user, "SHELL": s.shell,
                   "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin",
                   "TERM": "xterm-256color", "COLORTERM": "truecolor",
                   "LANG": os.environ.get("LANG", "C.UTF-8")}
            os.execvpe(TERMINAL[0], list(TERMINAL), env)
        finally:
            os._exit(127)
    return pid, fd


class Terminal:
    def __init__(self, shell, session, reader, writer):
        self.shell, self.session, self.reader, self.writer = shell, session, reader, writer
        self.queue, self.paused, self.code, self.pong = asyncio.Queue(), False, 1000, time.monotonic()
        self.done = asyncio.Event()

    def kick(self, code):
        self.code = code
        self.done.set()

    async def run(self):
        loop = asyncio.get_running_loop()
        pid, fd = spawn(self.shell.s)
        os.set_blocking(fd, False)
        self.fd = fd

        def readable():
            try:
                data = os.read(fd, 65536)
            except OSError:                      # EIO: the tmux client has gone
                data = b""
            if not data:
                loop.remove_reader(fd)
                self.queue.put_nowait(None)
                return
            self.queue.put_nowait(data)
            if self.queue.qsize() >= 16:         # the browser is slow: stop reading until it catches up
                loop.remove_reader(fd)
                self.paused = True

        self.readable = readable
        loop.add_reader(fd, readable)
        tasks = [asyncio.create_task(c) for c in (self.pump_out(), self.pump_in(), self.pinger(), self.done.wait())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            loop.remove_reader(fd)
            os.close(fd)                         # the tmux client gets SIGHUP; the session lives on
            try:
                self.writer.write(ws_frame(8, struct.pack("!H", self.code)))
                await asyncio.wait_for(self.writer.drain(), 5)
            except (ConnectionError, asyncio.TimeoutError):
                pass
            await reap(pid)

    async def pump_out(self):
        loop = asyncio.get_running_loop()
        while True:
            data = await self.queue.get()
            if data is None:
                return
            self.writer.write(ws_frame(2, data))
            await asyncio.wait_for(self.writer.drain(), 60)
            if self.paused and self.queue.qsize() < 4:
                self.paused = False
                loop.add_reader(self.fd, self.readable)

    async def pump_in(self):
        ws = WsReader(self.reader)
        try:
            while True:
                op, data = await ws.read()
                if op == 8:
                    self.code = 1000
                    return
                if op == 9:
                    self.writer.write(ws_frame(10, data))
                    continue
                if op == 10:
                    self.pong = time.monotonic()
                    continue
                if op != 1:
                    continue
                if not self.shell.touch(self.session):
                    self.code = 4001                    # logged out or expired: the page goes back to the login
                    return
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    self.code = 1007
                    return
                if text[:1] == "i":
                    await pty_write(self.fd, text[1:].encode("utf-8"))
                elif text[:1] == "r":
                    resize(self.fd, text[1:])
        except WsClose as e:
            self.code = e.code
        except (asyncio.IncompleteReadError, ConnectionError):
            pass

    async def pinger(self):
        while True:
            await asyncio.sleep(PING_EVERY)
            if time.monotonic() - self.pong > PONG_WAIT:
                self.code = 1001
                return
            self.writer.write(ws_frame(9))


async def pty_write(fd, data):
    while data:
        try:
            data = data[os.write(fd, data):]
        except BlockingIOError:
            await asyncio.sleep(0.01)


def resize(fd, text):
    try:
        size = json.loads(text)
        cols, rows = int(size["c"]), int(size["r"])
    except (ValueError, TypeError, KeyError):
        return
    if 1 <= cols <= 1000 and 1 <= rows <= 1000:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


async def reap(pid):
    for _ in range(30):
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if done:
            return
        await asyncio.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    except (ProcessLookupError, ChildProcessError):
        pass


# --- the server -------------------------------------------------------------------------

class Shell:
    def __init__(self, settings, files, pages):
        self.s, self.files, self.pages = settings, files, pages
        self.sessions = {}                 # sha256 of the cookie token -> {created, seen, via, client}
        self.terminals = set()
        self.fails = {}                    # client address -> times of failed logins
        self.all_fails = collections.deque()
        self.was_locked = locked()
        self.conns = 0
        self.last_step = int(util.read_json(state_path("state.json"), {}).get("last_step", 0))
        self.last_login = None
        self.activity = 0.0

    # who is asking

    def peer_allowed(self, peer):
        ip = ipaddress.ip_address(peer)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip in self.s.wg_net:
            return "wg", ip
        if self.s.host and any(ip in n for n in self.s.ingress_nets) and time.time() < public_until():
            return "ingress", ip
        return None, ip

    def classify(self, req, via, ip):
        """Fill in req.via and req.client; False when the request must be dropped."""
        host = req.headers.get("host", "").lower()
        if via == "wg":
            if host != self.s.wg_host:
                log(f"dropped: {ip} asked for Host {host[:80]!r} over the tunnel")
                return False
            req.client = str(ip)
        else:
            # traefik says "wss" rather than "https" on WebSocket upgrades; some clients name port 443
            proto = req.headers.get("x-forwarded-proto", "")
            if host.endswith(":443"):
                host = host[:-4]
            if host != self.s.host or proto not in ("https", "wss"):
                log(f"dropped: ingress request for Host {host[:80]!r}, X-Forwarded-Proto {proto[:10]!r}")
                return False
            last = req.headers.get("x-forwarded-for", "").split(",")[-1].strip()
            try:
                req.client = str(ipaddress.ip_address(last))
            except ValueError:
                req.client = str(ip)
        req.via = via
        return True

    def same_origin(self, req):
        return req.headers.get("origin") == self.s.origin(req.via)

    # sessions

    def cookie_name(self, via):
        return "__Host-hbws" if via == "ingress" else "hbws"

    def session_of(self, req):
        want = self.cookie_name(req.via)
        for part in req.headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == want and 0 < len(value) <= 64:
                key = hashlib.sha256(value.encode()).hexdigest()
                if key in self.sessions and self.sessions[key]["via"] == req.via and self.touch(key):
                    return key
        return None

    def touch(self, key):
        """Mark a session used now; False when it has ended."""
        s, now = self.sessions.get(key), time.time()
        if not s or now - s["created"] > SESSION_MAX or now - s["seen"] > SESSION_IDLE:
            self.sessions.pop(key, None)
            return False
        s["seen"] = now
        if now - self.activity > 60:
            self.activity = now
            try:
                util.write_atomic(state_path("activity"), f"{int(now)}\n", mode=0o644)
            except OSError:
                pass
        return True

    def end_sessions(self, which):
        for key in [k for k, s in self.sessions.items() if which(s)]:
            del self.sessions[key]
        for t in list(self.terminals):
            if t.session not in self.sessions:
                t.kick(4001)

    # failed logins

    def too_many(self, client):
        q, now = self.fails.get(client), time.time()
        while q and now - q[0] > IP_WINDOW:
            q.popleft()
        return bool(q) and len(q) >= IP_FAILS

    def failed(self, client):
        now = time.time()
        if len(self.fails) > 10000:
            self.fails.clear()
        self.fails.setdefault(client, collections.deque()).append(now)
        self.all_fails.append(now)
        while self.all_fails and now - self.all_fails[0] > ALL_WINDOW:
            self.all_fails.popleft()
        if len(self.all_fails) >= ALL_FAILS and not locked():
            util.write_json(state_path("lock"), {"since": int(now), "failures": len(self.all_fails)}, mode=0o644)
            self.was_locked = True
            log(f"locked: {len(self.all_fails)} failed logins in the last hour; hb webshell unlock reopens")

    def check_unlocked(self):
        if self.was_locked and not locked():
            self.was_locked = False
            self.all_fails.clear()
            self.fails.clear()
            log("unlocked")

    # pages

    def page(self, name, req, message=""):
        text = (self.pages[name].replace("{{TITLE}}", html.escape(self.s.title))
                .replace("{{MESSAGE}}", html.escape(message)))
        return response(200, text.encode(), "text/html; charset=utf-8", secure=req.via == "ingress")

    def redirect(self, req, where, cookie=None):
        extra = [f"Location: {where}"]
        if cookie is not None:
            name = self.cookie_name(req.via)
            attrs = "Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if req.via == "ingress" else "")
            extra.append(f"Set-Cookie: {name}={cookie}; {attrs}; Max-Age={SESSION_MAX if cookie else 0}")
        return response(303, extra=extra, secure=req.via == "ingress")

    async def login(self, req):
        if not self.same_origin(req) or not req.headers.get("content-type", "").startswith(
                "application/x-www-form-urlencoded"):
            return response(403, b"forbidden")
        self.check_unlocked()
        if locked():
            return self.redirect(req, "/?m=locked")
        if self.too_many(req.client):
            return self.redirect(req, "/?m=slow")
        auth = util.read_json(AUTH, {})
        if not isinstance(auth, dict) or not auth.get("password") or not auth.get("secret"):
            return self.redirect(req, "/?m=off")
        try:
            form = urllib.parse.parse_qs(req.body.decode("utf-8"), max_num_fields=4)
        except (UnicodeDecodeError, ValueError):
            return response(400, b"bad request")
        password = form.get("password", [""])[0][:256]
        code = form.get("code", [""])[0].strip()
        # About 50 ms, inline: no worker thread, so pty.fork() happens in a single-threaded process.
        good_pw = otp.scrypt_matches(password, auth["password"])
        step = otp.match_totp(auth["secret"], code, self.last_step, time.time()) \
            if re.fullmatch(r"\d{6}", code) else None
        if not (good_pw and step is not None):
            self.failed(req.client)
            log(f"login failed: {req.client} via {req.via}")
            await asyncio.sleep(FAIL_DELAY)
            return self.redirect(req, "/?m=bad")
        self.last_step = step
        util.write_json(state_path("state.json"), {"last_step": step})
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {
            "created": now, "seen": now, "via": req.via, "client": req.client}
        self.fails.pop(req.client, None)
        self.last_login = {"at": int(now), "client": req.client, "via": req.via}
        log(f"login: {req.client} via {req.via}")
        self.write_status()
        return self.redirect(req, "/", cookie=token)

    def logout(self, req):
        if not self.same_origin(req):
            return response(403, b"forbidden")
        key = self.session_of(req)
        if key:
            mine = self.sessions[key]
            self.end_sessions(lambda s: s is mine)
            self.write_status()
        return self.redirect(req, "/?m=out", cookie="")

    async def route(self, req):
        if req.method == "GET" and req.path in self.files:
            data, ctype = self.files[req.path]
            return response(200, data, ctype, secure=req.via == "ingress", cache="no-cache")
        if req.path == "/" and req.method == "GET":
            if self.session_of(req):
                return self.page("term", req)
            m = urllib.parse.parse_qs(req.query).get("m", [""])[0]
            return self.page("login", req, MESSAGES.get(m, ""))
        if req.path == "/login" and req.method == "POST":
            return await self.login(req)
        if req.path == "/logout" and req.method == "POST":
            return self.logout(req)
        return response(404, b"not found")

    async def websocket(self, req, reader, writer):
        h = req.headers
        accept = ws_accept(h.get("sec-websocket-key", ""))
        if (h.get("upgrade", "").lower() != "websocket" or "upgrade" not in h.get("connection", "").lower()
                or h.get("sec-websocket-version") != "13" or not accept):
            log(f"websocket refused: {req.client} via {req.via}, not a valid upgrade")
            writer.write(response(400, b"bad request"))
            return
        session = self.session_of(req) if self.same_origin(req) else None
        if not session:
            why = "no valid session" if self.same_origin(req) else "Origin " + repr(h.get("origin", "")[:80])
            log(f"websocket refused: {req.client} via {req.via}, {why}")
            writer.write(response(403, b"forbidden"))
            return
        if len(self.terminals) >= MAX_TERMINALS:
            log(f"websocket refused: {req.client} via {req.via}, {MAX_TERMINALS} terminals already open")
            writer.write(response(503, b"too many terminals"))
            return
        writer.write((f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        await writer.drain()
        term = Terminal(self, session, reader, writer)
        self.terminals.add(term)
        self.write_status()
        try:
            await term.run()
        finally:
            self.terminals.discard(term)
            self.write_status()

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        via, ip = self.peer_allowed(peer[0]) if peer else (None, None)
        if via is None or self.conns >= MAX_CONNECTIONS:
            writer.close()
            return
        self.conns += 1
        try:
            req = await read_request(reader)
            if req is None or not self.classify(req, via, ip):
                return
            if req.path == "/ws" and req.method == "GET":
                await self.websocket(req, reader, writer)
            else:
                writer.write(await self.route(req))
            await asyncio.wait_for(writer.drain(), 30)
        except HttpError as e:
            writer.write(response(e.status, REASONS[e.status].encode()))
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            self.conns -= 1
            writer.close()

    # housekeeping

    def write_status(self):
        try:
            util.write_json(state_path("status.json"), {
                "terminals": len(self.terminals), "sessions": len(self.sessions), "last_login": self.last_login,
                "pid": os.getpid()}, mode=0o644)
        except OSError:
            pass

    async def housekeeping(self):
        while True:
            await asyncio.sleep(15)
            now, before = time.time(), len(self.sessions)
            self.end_sessions(lambda s: now - s["created"] > SESSION_MAX or now - s["seen"] > SESSION_IDLE)
            if now >= public_until():           # the public window closed: so do its sessions
                self.end_sessions(lambda s: s["via"] == "ingress")
            self.check_unlocked()
            if len(self.sessions) != before:
                self.write_status()

    async def serve(self, stop=None, ready=None):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, 1)
        sock.bind((self.s.addr, self.s.port))
        sock.listen(64)
        sock.setblocking(False)
        server = await asyncio.start_server(self.handle, sock=sock, limit=MAX_HEAD)
        log(f"listening on {self.s.wg_host}" + (f"; {self.s.host} through the ingress while opened" if self.s.host else ""))
        self.write_status()
        if stop is None:
            stop = asyncio.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, stop.set)
        if ready is not None:
            ready.set()
        house = asyncio.create_task(self.housekeeping())
        await stop.wait()
        house.cancel()
        server.close()
        for t in list(self.terminals):
            t.kick(1001)
        await asyncio.sleep(0.5)


def parse_args(argv):
    """(Settings, None) from `--listen ADDR:PORT --tunnel NET [--host NAME --ingress-from NET...]`,
    or (None, why not)."""
    opts = {"--listen": "", "--tunnel": "", "--host": "", "--ingress-from": []}
    args = list(argv)
    while args:
        name = args.pop(0)
        if name not in opts or not args:
            return None, f"unknown or incomplete option {name!r}"
        if isinstance(opts[name], list):
            opts[name].append(args.pop(0))
        else:
            opts[name] = args.pop(0)
    try:
        return Settings(opts["--listen"], opts["--tunnel"], opts["--host"], opts["--ingress-from"]), None
    except ValueError as e:
        return None, str(e)


def main(argv):
    settings, why = parse_args(argv)
    if settings is None:
        log(f"bad settings: {why}")
        return 2
    files, pages, bad = load_assets()
    if bad:
        log("refusing to start: sha256 differs from the pin for " + ", ".join(bad))
        return 2
    if not os.access(AUTH, os.R_OK):
        log(f"refusing to start: can't read {AUTH} (hb webshell apply sets the password and code)")
        return 2
    asyncio.run(Shell(settings, files, pages).serve())
    return 0
