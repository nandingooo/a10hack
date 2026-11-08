"""Settings and request guards shared by the gateway and sign-in.

Local mode (the default) keeps the original single-operator demo: loopback only and
anyone who can open the page can run agents.

Public mode (TRUSTAGENT_PUBLIC=1) is for a server reachable from the internet:
  * anyone can watch the shared run, but only operators can start, stop or add agents;
  * operators sign in with the access code or with an allowlisted OAuth identity;
  * runs have a cooldown and a daily cap, sign-in attempts are rate limited per IP;
  * cookies are Secure when TRUSTAGENT_ORIGIN is https.
"""
import os
import secrets
import sys
import threading
import time
from urllib.parse import urlsplit


def _flag(name, default="0"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        sys.exit(f"{name} must be a whole number.")


PUBLIC = _flag("TRUSTAGENT_PUBLIC")
BIND = os.getenv("AIRLOCK_BIND", "0.0.0.0" if PUBLIC else "127.0.0.1")
PORT = _int("PORT", 8787)
ORIGIN = os.getenv("TRUSTAGENT_ORIGIN", f"http://127.0.0.1:{PORT}").rstrip("/")
HTTPS = ORIGIN.startswith("https://")
# Only trust X-Forwarded-For when a reverse proxy you control sits in front of the gateway.
TRUST_PROXY = _flag("TRUSTAGENT_TRUST_PROXY")

# Run limits. Local mode keeps the original behaviour (no cooldown, no cap).
RUN_COOLDOWN = _int("TRUSTAGENT_RUN_COOLDOWN", 60 if PUBLIC else 0)
MAX_RUNS_PER_DAY = _int("TRUSTAGENT_MAX_RUNS_PER_DAY", 50 if PUBLIC else 0)
MAX_EXTRA_AGENTS = _int("TRUSTAGENT_MAX_EXTRA_AGENTS", 4 if PUBLIC else 12)

# A fixed code lets a server keep the same code across restarts. Locally a fresh one is printed.
ACCESS_CODE = os.getenv("TRUSTAGENT_ACCESS_CODE") or secrets.token_urlsafe(12)
if os.getenv("TRUSTAGENT_ACCESS_CODE") and len(ACCESS_CODE) < 12:
    sys.exit("TRUSTAGENT_ACCESS_CODE must be at least 12 characters.")

# OAuth identities allowed to operate, e.g. "github:octocat,google:me@example.com,aws:me@example.com".
OPERATORS = {item.strip().lower() for item in os.getenv("TRUSTAGENT_OPERATORS", "").split(",") if item.strip()}


def role_for(identity):
    """Role for a signed-in identity such as "github:octocat". The access code is always an operator."""
    if identity == "code" or not PUBLIC:
        return "operator"
    return "operator" if identity.lower() in OPERATORS else "viewer"


def client_ip(handler):
    if TRUST_PROXY:
        forwarded = handler.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()  # the address your proxy saw
    return handler.client_address[0]


def same_origin(handler):
    """Browsers send Origin on every POST. A request from another site is refused even though the
    custom X-Airlock-Demo header already forces a CORS preflight that this server never approves."""
    origin = handler.headers.get("Origin")
    if not origin:
        return True  # non-browser clients (curl) still need the custom header
    allowed = {urlsplit(ORIGIN).netloc, handler.headers.get("Host", "")}
    return urlsplit(origin).netloc in allowed


class RateLimiter:
    """Fixed-window counter per key. Old windows are dropped as new keys arrive."""

    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self.hits = {}
        self.guard = threading.Lock()

    def allow(self, key):
        now = time.time()
        with self.guard:
            if len(self.hits) > 10000:
                self.hits = {k: v for k, v in self.hits.items() if v[0] > now}
            reset, count = self.hits.get(key, (0, 0))
            if reset <= now:
                reset, count = now + self.window, 0
            if count >= self.limit:
                return False
            self.hits[key] = (reset, count + 1)
            return True


# Wrong access codes: 10 tries per IP every 15 minutes.
code_attempts = RateLimiter(10, 900)
# Starting OAuth or AWS device flows makes outbound calls: 20 per IP per 10 minutes.
auth_flows = RateLimiter(20, 600)
# Mutating API calls (start, stop, add agent): 30 per IP per minute.
api_writes = RateLimiter(30, 60)


def security_headers(handler):
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "same-origin")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Cross-Origin-Opener-Policy", "same-origin")
    handler.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    handler.send_header(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    )
    if HTTPS:
        handler.send_header("Strict-Transport-Security", "max-age=31536000")


def describe():
    lines = [f"TrustAgent: {ORIGIN if PUBLIC else f'http://localhost:{PORT}'}  (listening on {BIND}:{PORT})"]
    if PUBLIC:
        lines.append(f"Public mode: viewers watch, operators run. Cooldown {RUN_COOLDOWN}s, "
                     f"{MAX_RUNS_PER_DAY or 'unlimited'} runs per day.")
        if ORIGIN.startswith("http://127.0.0.1"):
            lines.append("Warning: set TRUSTAGENT_ORIGIN to the public address people use (needed for OAuth and cookies).")
        if not HTTPS:
            lines.append("Warning: TRUSTAGENT_ORIGIN is not https, so the session cookie and access code travel unencrypted.")
    return lines
