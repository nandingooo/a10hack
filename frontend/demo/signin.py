"""Profile sign-in for the TrustAgent gateway.

Providers: workspace access code (always), Google and GitHub OAuth (when client credentials are
configured), and AWS Builder ID through the OAuth device-code flow (no configuration needed).

Every session carries an identity ("code", "github:<login>", "google:<email>", "aws:<email>") and
a role. In public mode only the access code and identities listed in TRUSTAGENT_OPERATORS are
operators; everyone else who signs in is a viewer. Network calls never run while the lock is held."""
import base64
import json
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie, CookieError
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, parse_qs
from urllib.request import Request, urlopen

import security

SESSION_SECONDS = 28800
MAX_SESSIONS = 5000
MAX_PENDING = 2000
code = security.ACCESS_CODE
sessions = {}  # token -> (display name, expiry, identity, role)
pending = {}   # nonce -> (provider, expiry[, device flow info])
guard = threading.Lock()
# name -> (authorize URL, token URL, profile URL, scope, display field, identity field)
providers = {
    "github": ("https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token",
               "https://api.github.com/user", "read:user", "login", "login"),
    "google": ("https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
               "https://openidconnect.googleapis.com/v1/userinfo", "openid email profile", "name", "email"),
}
# AWS Builder ID is served by the IAM Identity Center OIDC service in us-east-1.
AWS_OIDC = "https://oidc.us-east-1.amazonaws.com"
AWS_START_URL = "https://view.awsapps.com/start"
aws_client = {}
COOKIE_FLAGS = "HttpOnly; SameSite=Lax; Path=/" + ("; Secure" if security.HTTPS else "")


def credentials(name):
    return [os.getenv("TRUSTAGENT_" + name.upper() + "_" + key) for key in ("CLIENT_ID", "CLIENT_SECRET")]


def aws_enabled():
    return os.getenv("TRUSTAGENT_AWS_BUILDER_ID", "1") != "0"


def cookie(handler, key):
    jar = SimpleCookie()
    try:
        jar.load(handler.headers.get("Cookie", ""))
    except CookieError:
        return ""
    return jar[key].value if key in jar else ""


def current_user(handler):
    """(name, identity, role) for the request's session, or None."""
    token = cookie(handler, "ta_session")
    with guard:
        entry = sessions.get(token)
    if not entry or entry[1] <= time.time():
        return None
    return entry[0], entry[2], entry[3]


def can_operate(handler):
    if not security.PUBLIC:
        return True
    user = current_user(handler)
    return bool(user) and user[2] == "operator"


def response(handler, data=None, status=200, cookies=(), location=None):
    body = json.dumps(data if data is not None else {}).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    for name, value, age in cookies:
        handler.send_header("Set-Cookie", f"{name}={value}; {COOKIE_FLAGS}; Max-Age={age}")
    if location:
        handler.send_header("Location", location)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def profile(name, role):
    return {"name": name, "role": role, "canRun": role == "operator" or not security.PUBLIC}


def login(handler, name, identity, redirect=False):
    token = secrets.token_urlsafe(32)
    role = security.role_for(identity)
    with guard:
        if len(sessions) >= MAX_SESSIONS:  # drop the oldest sessions rather than grow without bound
            for key in sorted(sessions, key=lambda k: sessions[k][1])[:len(sessions) - MAX_SESSIONS + 1]:
                sessions.pop(key, None)
        sessions[token] = (str(name)[:80], time.time() + SESSION_SECONDS, identity, role)
    response(handler, profile(str(name)[:80], role), 303 if redirect else 200,
             [("ta_session", token, SESSION_SECONDS), ("ta_flow", "", 0)], "/#account" if redirect else None)


def add_pending(nonce, entry):
    with guard:
        if len(pending) >= MAX_PENDING:
            return False
        pending[nonce] = entry
        return True


def aws_call(path, body):
    """POST JSON to the AWS OIDC service. Returns (status, data, normalized error type)."""
    req = Request(AWS_OIDC + path, json.dumps(body).encode(),
                  {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "TrustAgent"})
    try:
        with urlopen(req, timeout=10) as res:
            return res.status, json.load(res), ""
    except HTTPError as err:
        try:
            data = json.load(err)
        except ValueError:
            data = {}
        kind = err.headers.get("x-amzn-ErrorType") or data.get("error") or data.get("__type") or ""
        kind = kind.split(":")[0].split("#")[-1].replace("_", "").lower()
        return err.code, data, kind[:-9] if kind.endswith("exception") else kind


def aws_registration():
    with guard:
        if aws_client.get("expires", 0) > time.time() + 300:
            return dict(aws_client)
    status, data, _ = aws_call("/client/register", {"clientName": "TrustAgent", "clientType": "public"})
    if status != 200 or "clientId" not in data:
        raise OSError("AWS client registration failed")
    with guard:
        aws_client.update(id=data["clientId"], secret=data["clientSecret"],
                          expires=float(data.get("clientSecretExpiresAt") or time.time() + 3600))
        return dict(aws_client)


def aws_identity(tokens):
    """(display name, identity) from the ID token when AWS returns one. The token arrived directly
    from AWS over TLS in answer to our own request, so its claims are decoded, not re-verified."""
    try:
        payload = tokens["idToken"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (KeyError, IndexError, ValueError, AttributeError):
        claims = {}
    email = claims.get("email") or ""
    subject = claims.get("sub") or ""
    name = claims.get("name") or email or claims.get("preferred_username") or "AWS Builder ID user"
    return name, "aws:" + (email or subject or "unknown")


def aws_start(handler, now):
    try:
        client = aws_registration()
        status, data, _ = aws_call("/device_authorization", {"clientId": client["id"], "clientSecret": client["secret"], "startUrl": AWS_START_URL})
        link = data.get("verificationUriComplete") or data.get("verificationUri") or ""
        if status != 200 or not data.get("deviceCode") or not link.startswith("https://"):
            raise OSError("AWS device authorization failed")
    except (OSError, ValueError, KeyError):
        return response(handler, {"error": "AWS sign-in could not be reached from the gateway host."}, 502)
    interval = max(int(data.get("interval") or 5), 1)
    lifetime = min(int(data.get("expiresIn") or 600), 900)
    nonce = secrets.token_urlsafe(32)
    if not add_pending(nonce, ("aws", now + lifetime, {"device": data["deviceCode"], "interval": interval, "next": now + interval})):
        return response(handler, {"error": "Too many sign-ins in progress. Try again in a few minutes."}, 503)
    return response(handler, {"userCode": data.get("userCode", ""), "verificationUri": link, "interval": interval, "expiresIn": lifetime},
                    cookies=[("ta_flow", nonce, lifetime)])


def aws_poll(handler, now):
    nonce = cookie(handler, "ta_flow")
    with guard:
        flow = pending.get(nonce)
        if not flow or flow[0] != "aws":
            return response(handler, {"error": "expired"}, 410)
        info = flow[2]
        if now < info["next"]:
            return response(handler, {"status": "pending"}, 202)
        info["next"] = now + info["interval"]
        client = dict(aws_client)
    try:
        status, data, kind = aws_call("/token", {"clientId": client["id"], "clientSecret": client["secret"],
                                                 "grantType": "urn:ietf:params:oauth:grant-type:device_code", "deviceCode": info["device"]})
    except (OSError, ValueError, KeyError):
        return response(handler, {"status": "pending"}, 202)
    if status == 200 and data.get("accessToken"):
        with guard:
            pending.pop(nonce, None)
        return login(handler, *aws_identity(data))
    if kind in ("authorizationpending", "slowdown"):
        if kind == "slowdown":
            with guard:
                info["interval"] += 5
        return response(handler, {"status": "pending"}, 202)
    with guard:
        pending.pop(nonce, None)
    return response(handler, {"error": "expired" if kind == "expiredtoken" else "denied"}, 403, [("ta_flow", "", 0)])


def read_body(handler, limit):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return None
    return handler.rfile.read(length) if 0 < length <= limit else None


def handle(handler):
    url = urlsplit(handler.path)
    path = url.path
    token = cookie(handler, "ta_session")
    now = time.time()
    ip = security.client_ip(handler)
    with guard:
        for store in (sessions, pending):
            for key, value in list(store.items()):
                if value[1] <= now:
                    store.pop(key, None)
    if handler.command == "POST":
        if handler.headers.get("X-Airlock-Demo") != "1" or not security.same_origin(handler):
            return response(handler, {"error": "Cross-site request refused."}, 403)
        if path == "/auth/logout":
            with guard:
                sessions.pop(token, None)
            return response(handler, profile(None, None), cookies=[("ta_session", "", 0)])
        if path == "/auth/local":
            if not security.code_attempts.allow(ip):
                return response(handler, {"error": "Too many attempts. Wait 15 minutes and try again."}, 429)
            supplied = read_body(handler, 256) or b""
            if secrets.compare_digest(supplied.strip(), code.encode()):
                return login(handler, "Workspace operator", "code")
            return response(handler, {"error": "That code did not match."}, 401)
        if path in ("/auth/aws/start", "/auth/aws/poll") and aws_enabled():
            if path == "/auth/aws/start":
                if not security.auth_flows.allow(ip):
                    return response(handler, {"error": "Too many sign-in attempts. Try again in a few minutes."}, 429)
                return aws_start(handler, now)
            return aws_poll(handler, now)
    elif path == "/auth/me":
        user = current_user(handler)
        available = [n for n in providers if all(credentials(n))] + (["aws"] if aws_enabled() else [])
        data = profile(user[0], user[2]) if user else profile(None, None)
        data.update(providers=available, public=security.PUBLIC)
        return response(handler, data)
    elif path.startswith(("/auth/start/", "/auth/callback/")):
        name = path.split("/")[-1]
        if name not in providers or not all(credentials(name)):
            return response(handler, {}, 404)
        authorize, exchange, profile_url, scope, field, id_field = providers[name]
        client, secret = credentials(name)
        callback = security.ORIGIN + "/auth/callback/" + name
        if path.startswith("/auth/start/"):
            if not security.auth_flows.allow(ip):
                return response(handler, {}, 303, location="/#signin-error")
            nonce = secrets.token_urlsafe(32)
            if not add_pending(nonce, (name, now + 600)):
                return response(handler, {}, 303, location="/#signin-error")
            params = dict(client_id=client, redirect_uri=callback, scope=scope, response_type="code", state=nonce)
            if name == "google":
                params["prompt"] = "select_account"
            return response(handler, {}, 303, [("ta_flow", nonce, 600)], authorize + "?" + urlencode(params))
        query = parse_qs(url.query)
        nonce = query.get("state", [""])[0]
        with guard:
            matched = bool(nonce) and nonce == cookie(handler, "ta_flow") and pending.pop(nonce, (None,))[0] == name
        if not matched:
            return response(handler, {}, 303, location="/#signin-error")
        try:
            params = dict(client_id=client, client_secret=secret, redirect_uri=callback,
                          grant_type="authorization_code", code=query["code"][0])
            req = Request(exchange, urlencode(params).encode(), {"Accept": "application/json"})
            with urlopen(req, timeout=10) as res:
                access = json.load(res)["access_token"]
            with urlopen(Request(profile_url, headers={"Authorization": "Bearer " + access, "User-Agent": "TrustAgent"}), timeout=10) as res:
                user = json.load(res)
            if name == "google" and user.get("email_verified") is False:
                raise ValueError("unverified email")
            ident = str(user.get(id_field) or user.get("sub") or user.get("id") or "")
            if not ident:
                raise ValueError("no identity")
            return login(handler, user.get(field) or ident, name + ":" + ident, True)
        except (ValueError, KeyError, OSError):
            return response(handler, {}, 303, location="/#signin-error")
    response(handler, {}, 404)
