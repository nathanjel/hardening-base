"""Time-based one-time codes (RFC 4226 / 6238) and scrypt hashes, shared by hb-totp and the web shell.

Codes: HMAC-SHA1, 6 digits, 30-second steps, one step of clock drift either way.
"""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import subprocess
import time
import urllib.parse

STEP, DIGITS, DRIFT = 30, 6, 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


def hotp(key, counter, digits=DIGITS):
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def b32key(secret):
    s = secret.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def match_totp(secret, code, last_step, now):
    """The time step code belongs to, if it is within the drift and newer than last_step."""
    key, cur = b32key(secret), int(now // STEP)
    for step in range(cur - DRIFT, cur + DRIFT + 1):
        if step > last_step and hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(issuer, account, secret):
    return ("otpauth://totp/" + urllib.parse.quote(f"{issuer}:{account}") + "?"
            + urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                      "digits": DIGITS, "period": STEP}))


def show_qr(uri):
    try:
        p = subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2"], input=uri, text=True,
                           capture_output=True, timeout=10)
        if p.returncode == 0:
            print(p.stdout)
            return
    except (OSError, subprocess.TimeoutExpired):
        pass
    print("(no QR code: qrencode isn't installed; `sudo dnf install qrencode` shows one)\n")


def enrol(issuer, account):
    """Show a new secret for an authenticator app and ask for one code from it, at the terminal.

    Returns (secret, step of the code typed), or (None, None) when no code matched."""
    secret = new_secret()
    print("In your authenticator app, add an account by scanning this, or by typing the key.\n")
    show_qr(otpauth_uri(issuer, account, secret))
    print(f"    account  {issuer}:{account}")
    print(f"    key      {' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))}")
    print("    type     time-based, 6 digits, 30 seconds\n")
    for _ in range(3):
        try:
            code = input("The code the app shows now: ").strip().replace(" ", "")
        except EOFError:
            break
        step = match_totp(secret, code, 0, time.time()) if re.fullmatch(r"\d{6}", code) else None
        if step is not None:
            return secret, step
        print("that doesn't match; check the phone's clock and try the next code")
    return None, None


def _scrypt(text, salt, n, r, p):
    return hashlib.scrypt(text.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=32)


def scrypt_hash(text):
    salt = secrets.token_bytes(16)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${_scrypt(text, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P).hex()}"


def scrypt_matches(text, stored):
    try:
        kind, n, r, p, salt, want = stored.split("$")
        if kind != "scrypt":
            return False
        got = _scrypt(text, bytes.fromhex(salt), int(n), int(r), int(p)).hex()
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(got, want)
