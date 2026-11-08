"""Optional profile sign-in for the shared localhost demo.

Providers: workspace code (always), Google and GitHub OAuth (when client credentials are
configured), and AWS Builder ID through the OAuth device-code flow (no configuration needed).
Network calls never run while the session lock is held."""
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

origin = os.getenv("TRUSTAGENT_ORIGIN", "http://127.0.0.1:8787")
code = secrets.token_urlsafe(12)
sessions = {}
pending = {}
guard = threading.Lock()
providers = {
    "github": ("https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "https://api.github.com/user", "read:user", "login"),
    "google": ("https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo", "openid profile", "name"),
}
# AWS Builder ID is served by the IAM Identity Center OIDC service in us-east-1.
AWS_OIDC = "https://oidc.us-east-1.amazonaws.com"
AWS_START_URL = "https://view.awsapps.com/start"
aws_client = {}


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


def response(handler, data=None, status=200, cookies=(), location=None):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    for name, value, age in cookies:
        handler.send_header("Set-Cookie", f"{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={age}")
    if location:
        handler.send_header("Location", location)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def login(handler, name, redirect=False):
    token = secrets.token_urlsafe(32)
    with guard:
        sessions[token] = (name, time.time() + 28800)
    response(handler, {"name": name}, 303 if redirect else 200,
             [("ta_session", token, 28800), ("ta_flow", "", 0)], "/#account" if redirect else None)


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
    status, data, _ = aws_call("/client/register", {"clientName": "TrustAgent local demo", "clientType": "public"})
    if status != 200 or "clientId" not in data:
        raise OSError("AWS client registration failed")
    with guard:
        aws_client.update(id=data["clientId"], secret=data["clientSecret"],
                          expires=float(data.get("clientSecretExpiresAt") or time.time() + 3600))
        return dict(aws_client)


def aws_name(tokens):
    """Display name from the ID token when AWS returns one. The token arrived directly from
    AWS over TLS, so its claims are only decoded here, for display."""
    try:
        payload = tokens["idToken"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return claims.get("name") or claims.get("email") or claims.get("preferred_username") or "AWS Builder ID user"
    except (KeyError, IndexError, ValueError, AttributeError):
        return "AWS Builder ID user"


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
    with guard:
        pending[nonce] = ("aws", now + lifetime, {"device": data["deviceCode"], "interval": interval, "next": now + interval})
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
        return login(handler, aws_name(data))
    if kind in ("authorizationpending", "slowdown"):
        if kind == "slowdown":
            with guard:
                info["interval"] += 5
        return response(handler, {"status": "pending"}, 202)
    with guard:
        pending.pop(nonce, None)
    return response(handler, {"error": "expired" if kind == "expiredtoken" else "denied"}, 403, [("ta_flow", "", 0)])


def handle(handler):
    url = urlsplit(handler.path)
    path = url.path
    token = cookie(handler, "ta_session")
    now = time.time()
    with guard:
        for store in (sessions, pending):
            for key, value in list(store.items()):
                if value[1] <= now:
                    store.pop(key, None)
    if handler.command == "POST":
        if handler.headers.get("X-Airlock-Demo") != "1":
            return response(handler, {}, 403)
        if path == "/auth/logout":
            with guard:
                sessions.pop(token, None)
            return response(handler, {}, cookies=[("ta_session", "", 0)])
        if path == "/auth/local":
            length = int(handler.headers.get("Content-Length", "0"))
            supplied = handler.rfile.read(length) if 0 < length <= 256 else b""
            if secrets.compare_digest(supplied, code.encode()):
                return login(handler, "Local operator")
            return response(handler, {}, 401)
        if path == "/auth/aws/start" and aws_enabled():
            return aws_start(handler, now)
        if path == "/auth/aws/poll" and aws_enabled():
            return aws_poll(handler, now)
    elif path == "/auth/me":
        with guard:
            name = sessions.get(token, (None,))[0]
        available = [n for n in providers if all(credentials(n))] + (["aws"] if aws_enabled() else [])
        return response(handler, {"name": name, "providers": available})
    elif path.startswith(("/auth/start/", "/auth/callback/")):
        name = path.split("/")[-1]
        if name not in providers or not all(credentials(name)):
            return response(handler, {}, 404)
        authorize, exchange, profile, scope, field = providers[name]
        client, secret = credentials(name)
        callback = origin + "/auth/callback/" + name
        if path.startswith("/auth/start/"):
            nonce = secrets.token_urlsafe(32)
            with guard:
                pending[nonce] = (name, now + 600)
            params = dict(client_id=client, redirect_uri=callback, scope=scope, response_type="code", state=nonce)
            if name == "google":
                params["prompt"] = "select_account"
            return response(handler, {}, 303, [("ta_flow", nonce, 600)], authorize + "?" + urlencode(params))
        query = parse_qs(url.query)
        nonce = query.get("state", [""])[0]
        with guard:
            matched = bool(nonce) and nonce == cookie(handler, "ta_flow") and pending.pop(nonce, (None,))[0] == name
        if not matched:
            return response(handler, {}, 403)
        try:
            params = dict(client_id=client, client_secret=secret, redirect_uri=callback,
                          grant_type="authorization_code", code=query["code"][0])
            req = Request(exchange, urlencode(params).encode(), {"Accept": "application/json"})
            with urlopen(req, timeout=10) as res:
                access = json.load(res)["access_token"]
            with urlopen(Request(profile, headers={"Authorization": "Bearer " + access, "User-Agent": "TrustAgent"}), timeout=10) as res:
                user = json.load(res)
            return login(handler, user.get(field) or name.title() + " user", True)
        except (ValueError, KeyError, OSError):
            return response(handler, {}, 303, location="/#signin-error")
    response(handler, {}, 404)
