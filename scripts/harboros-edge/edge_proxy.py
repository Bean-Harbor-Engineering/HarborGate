#!/usr/bin/env python3
"""HarborOS demo transport: authenticated middleware user -> existing Beacon API.

No business state or alternate Knowledge protocol lives here. Nginx sends only
/api/harbor-beacon/* to this loopback adapter. The browser supplies a fresh
60-second single-use auth.generate_token token; the Gate service bearer stays
in this process environment. Production integration belongs in HarborGate.
"""
import asyncio
from dataclasses import dataclass
import os
import re
from pathlib import Path

from aiohttp import ClientError, ClientSession, ClientTimeout, UnixConnector, WSMsgType, web
from yarl import URL

PREFIX = "/api/harbor-beacon"
MAX_BODY = 32 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
SESSION_KEY = web.AppKey("session", ClientSession)
AUTH_SESSION_KEY = web.AppKey("middleware_session", ClientSession)
SEGMENT = r"[^/]+"
# Explicit current WebUI route shapes; no arbitrary URL or destination proxy.
ROUTES = {
    "GET": [
        r"state", r"gateway/status", r"inference/healthz", r"hardware/readiness", r"rag/readiness",
        r"knowledge/(settings|retrieval-settings|conversation-settings|conversations|preview)",
        rf"knowledge/conversations/{SEGMENT}", r"knowledge/index/status", r"files/browse",
        r"models/(endpoints|capabilities|runtimes|policies|local-catalog|local-downloads)",
        r"admin/notification-targets", r"audit/(records|summary)", r"routing/status",
        r"harboros/(status|im-capability-map)", r"harboros/apps/home-assistant/status",
        r"home-assistant/(status|entities|services)", r"automation/(reviews|rules)",
        rf"automation/rules/{SEGMENT}", r"evt/(readiness|preflight/latest|evidence-bundle)",
        r"family/(timeline|timeline/digest|memory/events|memory/stats)", r"home-guardian/activity",
        r"cameras/(recording-settings|recordings/status|recordings/timeline)",
        rf"cameras/{SEGMENT}/live/status", rf"devices/{SEGMENT}/evidence", r"share-links",
        r"vision/(events|vlm/status)",
    ],
    "POST": [
        r"knowledge/(search|index/run)", r"models/(endpoints|local-downloads)",
        rf"models/endpoints/{SEGMENT}/test", rf"models/runtimes/{SEGMENT}/install",
        rf"models/capabilities/{SEGMENT}/selection", rf"models/local-downloads/{SEGMENT}/cancel",
        r"inference/v1/(vision/chat/completions|audio/transcriptions|audio/speech)",
        r"admin/notification-targets/default", r"evt/preflight", r"automation/reviews",
        rf"automation/reviews/{SEGMENT}/(enable|pause|discard|evaluate-latest)",
        r"home-assistant/(test|sync)", r"harboros/apps/home-assistant/(install-plan|install)",
        r"discovery/scan", r"devices/(manual|default-camera)", r"defaults",
        rf"devices/{SEGMENT}/(credentials|rtsp-check|validation/run)",
        rf"cameras/{SEGMENT}/(recordings/start|recordings/stop|live/start|live/stop|share-link|snapshot)",
        rf"share-links/{SEGMENT}/revoke", rf"family/memory/events/{SEGMENT}/feedback",
        rf"vision/events/{SEGMENT}/vlm-enrich",
    ],
    "PUT": [r"knowledge/settings", r"models/(store|policies)", r"home-assistant/config", r"cameras/recording-settings"],
    "PATCH": [r"knowledge/conversation-settings", rf"models/endpoints/{SEGMENT}", rf"devices/{SEGMENT}"],
    "DELETE": [rf"knowledge/conversations/{SEGMENT}", rf"admin/notification-targets/{SEGMENT}", rf"devices/{SEGMENT}"],
}


@dataclass(frozen=True)
class Config:
    service_token: str
    workspace_id: str
    beacon_url: str = "http://127.0.0.1:4174"
    middleware_url: str = "http://127.0.0.1:6000/websocket"
    middleware_socket: str | None = None

    def __post_init__(self):
        if (not self.service_token or len(self.service_token) > 4096 or any(c.isspace() for c in self.service_token)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.workspace_id)):
            raise ValueError("Gate service token and active workspace are required")
        for endpoint in (self.beacon_url, self.middleware_url):
            parsed = URL(endpoint)
            if parsed.scheme != "http" or parsed.host != "127.0.0.1" or parsed.user or parsed.query or parsed.fragment:
                raise ValueError("Upstreams must be HTTP loopback endpoints")


def allowed(method, path):
    if not path.startswith(PREFIX + "/") or any(ord(char) < 32 for char in path):
        return False
    tail = path[len(PREFIX) + 1:]
    # Reject decoded traversal or delimiter escapes before constructing an upstream URL.
    if "\\" in tail or "%" in tail or any(part in ("", ".", "..") for part in tail.split("/")):
        return False
    return any(re.fullmatch(pattern, tail) for pattern in ROUTES.get(method, []))


async def rpc(ws, request_id, method, params):
    await ws.send_json({"msg": "method", "id": request_id, "method": method, "params": params})
    for _ in range(128):
        message = await ws.receive(timeout=10)
        if message.type != WSMsgType.TEXT:
            raise web.HTTPServiceUnavailable(text="Middleware authentication unavailable")
        payload = message.json()
        if payload.get("msg") == "ping":
            await ws.send_json({"msg": "pong"})
        elif payload.get("id") == request_id:
            if payload.get("error"):
                if payload["error"].get("error") == 16:
                    raise web.HTTPServiceUnavailable(text="Middleware authentication is busy", headers={"Retry-After": "1"})
                raise web.HTTPUnauthorized(text="Invalid user session token")
            return payload.get("result")
    raise web.HTTPServiceUnavailable(text="Middleware authentication unavailable")


async def authenticate(session, config, token):
    """Validate the user token with middleware, never trust browser identity headers."""
    try:
        async with asyncio.timeout(12):
            async with session.ws_connect(config.middleware_url, max_msg_size=1024 * 1024) as ws:
                await ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
                connected = await ws.receive_json(timeout=5)
                if connected.get("msg") != "connected":
                    raise web.HTTPServiceUnavailable(text="Middleware authentication unavailable")
                result = await rpc(ws, "authenticate", "auth.login_ex", [{
                    "mechanism": "TOKEN_PLAIN", "token": token,
                    "login_options": {"user_info": True, "reconnect_token": False},
                }])
                if not isinstance(result, dict) or result.get("response_type") != "SUCCESS":
                    raise web.HTTPUnauthorized(text="Invalid or expired user session token")
                # End the short-lived PAM session before admitting more page requests.
                # The identity below comes only from successful TOKEN_PLAIN user_info,
                # never from the Unix socket's initial OS-authenticated principal.
                await rpc(ws, "logout", "auth.logout", [])
                user = result.get("user_info") or {}
                uid = user.get("pw_uid")
                roles = user.get("privilege", {}).get("roles", [])
                if isinstance(roles, dict):
                    roles = roles.get("$set", [])
                if type(uid) is not int or uid < 0 or uid > 2**64 - 1:
                    raise web.HTTPForbidden(text="A real middleware user is required")
                if not isinstance(roles, list) or "FULL_ADMIN" not in roles:
                    raise web.HTTPForbidden(text="FULL_ADMIN role is required")
                return uid
    except (ClientError, asyncio.TimeoutError, ValueError, TypeError, KeyError):
        raise web.HTTPServiceUnavailable(text="Middleware authentication unavailable") from None


def create_app(config, authenticate_user=authenticate):
    app = web.Application(client_max_size=MAX_BODY)
    authentication_slots = asyncio.Semaphore(2)

    async def sessions(application):
        application[SESSION_KEY] = ClientSession(timeout=ClientTimeout(total=180, connect=5), auto_decompress=False)
        if config.middleware_socket:
            application[AUTH_SESSION_KEY] = ClientSession(
                connector=UnixConnector(path=config.middleware_socket),
                timeout=ClientTimeout(total=15, connect=5), auto_decompress=False,
            )
        else:
            # Test-injected TCP middleware servers keep the exact same token protocol.
            application[AUTH_SESSION_KEY] = application[SESSION_KEY]
        yield
        if application[AUTH_SESSION_KEY] is not application[SESSION_KEY]:
            await application[AUTH_SESSION_KEY].close()
        await application[SESSION_KEY].close()

    app.cleanup_ctx.append(sessions)

    async def proxy(request):
        if not allowed(request.method, request.path):
            raise web.HTTPNotFound(text="Unknown Harbor Assistant route")
        auth = request.headers.get("Authorization", "")
        if not re.fullmatch(r"Bearer [A-Za-z0-9_.~+/=-]{1,4096}", auth):
            raise web.HTTPUnauthorized(text="A user session token is required")
        session = request.app[SESSION_KEY]
        try:
            async with asyncio.timeout(30):
                async with authentication_slots:
                    uid = await authenticate_user(request.app[AUTH_SESSION_KEY], config, auth[7:])
        except asyncio.TimeoutError:
            raise web.HTTPServiceUnavailable(text="Middleware authentication is busy") from None
        body = await request.read()
        headers = {
            "Authorization": "Bearer " + config.service_token,
            "X-Harbor-Principal-Source": "harboros",
            "X-Harbor-Principal-Id": f"harboros:uid:{uid}",
            "X-Harbor-Principal-Roles": "FULL_ADMIN",
            "X-Harbor-Workspace-Id": config.workspace_id,
            "Accept-Encoding": "identity",
        }
        for header in ("Content-Type", "Accept", "Range", "If-None-Match"):
            if header in request.headers:
                headers[header] = request.headers[header]
        # Header identities, cookies, caller Authorization and arbitrary proxy headers are never forwarded.
        target = URL(config.beacon_url + "/api" + request.path[len(PREFIX):]).with_query(request.query_string)
        try:
            async with session.request(request.method, target, data=body, headers=headers, allow_redirects=False) as response:
                chunks = []
                size = 0
                async for chunk in response.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        raise web.HTTPBadGateway(text="Beacon response exceeds demo transport limit")
                    chunks.append(chunk)
                response_headers = {name: response.headers[name] for name in (
                    "Content-Type", "Content-Range", "Accept-Ranges", "ETag", "Cache-Control", "Content-Encoding",
                ) if name in response.headers}
                response_headers["Cache-Control"] = "no-store"
                return web.Response(status=response.status, body=b"".join(chunks), headers=response_headers)
        except (ClientError, asyncio.TimeoutError):
            raise web.HTTPBadGateway(text="Beacon endpoint unavailable") from None

    app.router.add_route("*", "/{path:.*}", proxy)
    return app


def service_token_from_env(environ=os.environ):
    """A configured credential file takes precedence and fails closed if unreadable."""
    token_file = environ.get("HARBOR_GATE_TO_BEACON_TOKEN_FILE", "").strip()
    if token_file:
        credential = Path(token_file)
        if credential.stat().st_size > 4096:
            raise ValueError("Gate credential file exceeds 4096 bytes")
        return credential.read_text(encoding="utf-8").strip()
    return environ.get("HARBOR_GATE_TO_BEACON_TOKEN", "").strip()


if __name__ == "__main__":
    config = Config(
        service_token=service_token_from_env(),
        workspace_id=os.environ.get("HARBOR_EDGE_WORKSPACE_ID", ""),
        middleware_socket=os.environ.get("HARBOR_EDGE_MIDDLEWARE_SOCKET", "/run/middleware/middlewared.sock"),
    )
    web.run_app(create_app(config), host="127.0.0.1", port=4176, access_log=None)
