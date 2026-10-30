"""Transport tests exercise a real fake middleware WS and a fake Beacon HTTP server."""
import unittest
import asyncio
import os
from io import BytesIO
from pathlib import Path
import tempfile

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import edge_proxy


class EdgeProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.beacon_requests = []
        self.auth_tokens = []
        self.logout_count = 0
        self.active_authentications = 0
        self.maximum_authentications = 0

        async def middleware(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            async for msg in ws:
                data = msg.json()
                if data.get("msg") == "connect":
                    await ws.send_json({"msg": "connected", "session": "test-session"})
                elif data.get("method") == "auth.logout":
                    self.logout_count += 1
                    self.active_authentications -= 1
                    await ws.send_json({"msg": "result", "id": data["id"], "result": True})
                elif data.get("method") == "auth.login_ex":
                    auth = data["params"][0]
                    self.auth_tokens.append(auth["token"])
                    if auth["token"] == "busy-user-token":
                        await ws.send_json({"msg": "result", "id": data["id"],
                                            "error": {"error": 16, "reason": "Rate Limit Exceeded"}})
                        continue
                    self.assertEqual(auth["mechanism"], "TOKEN_PLAIN")
                    self.assertFalse(auth["login_options"]["reconnect_token"])
                    if auth["token"] == "valid-user-token":
                        self.active_authentications += 1
                        self.maximum_authentications = max(self.maximum_authentications, self.active_authentications)
                        result = {"response_type": "SUCCESS", "user_info": {
                            "pw_uid": 950, "privilege": {"roles": {"$set": ["FULL_ADMIN"]}},
                        }}
                    elif auth["token"] == "readonly-user-token":
                        self.active_authentications += 1
                        result = {"response_type": "SUCCESS", "user_info": {
                            "pw_uid": 1001, "privilege": {"roles": ["READONLY_ADMIN"]},
                        }}
                    else:
                        result = {"response_type": "AUTH_ERR"}
                    await ws.send_json({"msg": "result", "id": data["id"], "result": result})
            return ws

        async def beacon(request):
            self.beacon_requests.append((request.method, request.path_qs, dict(request.headers), await request.read()))
            if request.path.endswith("/audio/speech"):
                return web.Response(body=b"RIFFdemo-wave", content_type="audio/wav")
            return web.json_response({"conversation_id": "conversation-1", "citations": [{"source_path": "demo.md"}]})

        middleware_app = web.Application()
        middleware_app.router.add_get("/websocket", middleware)
        beacon_app = web.Application()
        beacon_app.router.add_route("*", "/{path:.*}", beacon)
        self.middleware_handler = middleware
        self.middleware_server = TestServer(middleware_app)
        self.beacon_server = TestServer(beacon_app)
        await self.middleware_server.start_server()
        await self.beacon_server.start_server()
        config = edge_proxy.Config(
            "server-only-gate-token", "workspace-demo",
            str(self.beacon_server.make_url("")).rstrip("/"),
            str(self.middleware_server.make_url("/websocket")),
        )
        self.client = TestClient(TestServer(edge_proxy.create_app(config)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.middleware_server.close()
        await self.beacon_server.close()

    async def test_real_authenticated_user_headers_replace_forged_browser_headers(self):
        response = await self.client.post("/api/harbor-beacon/knowledge/search?limit=3", json={"query": "demo"}, headers={
            "Authorization": "Bearer valid-user-token",
            "X-Harbor-Principal-Id": "harboros:uid:0",
            "X-Harbor-Workspace-Id": "attacker-workspace",
            "X-Harbor-User-Id": "attacker", "Cookie": "session=attacker",
        })
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["conversation_id"], "conversation-1")
        method, path, headers, body = self.beacon_requests[0]
        self.assertEqual((method, path), ("POST", "/api/knowledge/search?limit=3"))
        self.assertEqual(headers["Authorization"], "Bearer server-only-gate-token")
        self.assertEqual(headers["X-Harbor-Principal-Id"], "harboros:uid:950")
        self.assertEqual(headers["X-Harbor-Principal-Source"], "harboros")
        self.assertEqual(headers["X-Harbor-Principal-Roles"], "FULL_ADMIN")
        self.assertEqual(headers["X-Harbor-Workspace-Id"], "workspace-demo")
        self.assertNotIn("X-Harbor-User-Id", headers)
        self.assertNotIn("Cookie", headers)
        self.assertEqual(self.logout_count, 1)
        self.assertIn(b'"query": "demo"', body)

    async def test_rejects_missing_invalid_and_non_admin_sessions_without_forwarding(self):
        for token, expected in ((None, 401), ("invalid-token", 401), ("readonly-user-token", 403)):
            headers = {"Authorization": "Bearer " + token} if token else {}
            response = await self.client.get("/api/harbor-beacon/knowledge/conversations", headers=headers)
            self.assertEqual(response.status, expected)
            await response.read()
        self.assertEqual(self.beacon_requests, [])

    async def test_unknown_route_or_method_does_not_authenticate_or_forward(self):
        for method, path in (("GET", "/api/harbor-beacon/evil"), ("DELETE", "/api/harbor-beacon/models/runtimes")):
            response = await self.client.request(method, path, headers={"Authorization": "Bearer valid-user-token"})
            self.assertEqual(response.status, 404)
            await response.read()
        self.assertEqual(self.auth_tokens, [])
        self.assertEqual(self.beacon_requests, [])

    async def test_multimodal_content_passes_through_without_json_rewriting(self):
        body = b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="demo.wav"\r\n\r\nRIFF\r\n--boundary--'
        response = await self.client.post("/api/harbor-beacon/inference/v1/audio/transcriptions", data=body, headers={
            "Authorization": "Bearer valid-user-token", "Content-Type": "multipart/form-data; boundary=boundary",
        })
        self.assertEqual(response.status, 200)
        await response.read()
        self.assertEqual(self.beacon_requests[0][3], body)
        self.assertEqual(self.beacon_requests[0][2]["Content-Type"], "multipart/form-data; boundary=boundary")
        speech = await self.client.post("/api/harbor-beacon/inference/v1/audio/speech", json={"input": "hello"}, headers={
            "Authorization": "Bearer valid-user-token",
        })
        self.assertEqual(await speech.read(), b"RIFFdemo-wave")
        self.assertEqual(speech.headers["Content-Type"], "audio/wav")

    async def test_body_limit_prevents_forwarding(self):
        original = edge_proxy.MAX_BODY
        try:
            # Application's configured limit is immutable after startup; validate actual 32MiB limit.
            response = await self.client.post("/api/harbor-beacon/knowledge/search", data=BytesIO(b"x" * (original + 1)), headers={
                "Authorization": "Bearer valid-user-token",
            })
            self.assertEqual(response.status, 413)
            await response.read()
            self.assertEqual(self.beacon_requests, [])
        finally:
            edge_proxy.MAX_BODY = original

    async def test_middleware_busy_is_service_unavailable_without_identity_fallback(self):
        response = await self.client.get("/api/harbor-beacon/models/endpoints", headers={
            "Authorization": "Bearer busy-user-token",
        })
        self.assertEqual(response.status, 503)
        self.assertEqual(response.headers["Retry-After"], "1")
        self.assertEqual(await response.text(), "Middleware authentication is busy")
        self.assertEqual(self.beacon_requests, [])

    @unittest.skipIf(os.name == "nt", "NAS Unix socket transport runs on Linux")
    async def test_unix_transport_authenticates_every_request_and_bounds_page_fanout(self):
        with tempfile.TemporaryDirectory(prefix="edge-unix-") as directory:
            socket_path = str(Path(directory) / "middleware.sock")
            middleware_app = web.Application()
            middleware_app.router.add_get("/websocket", self.middleware_handler)
            runner = web.AppRunner(middleware_app)
            await runner.setup()
            site = web.UnixSite(runner, socket_path)
            await site.start()
            config = edge_proxy.Config("server-only-gate-token", "workspace-demo",
                                       str(self.beacon_server.make_url("")).rstrip("/"),
                                       middleware_socket=socket_path)
            client = TestClient(TestServer(edge_proxy.create_app(config)))
            await client.start_server()
            try:
                async def get():
                    response = await client.get("/api/harbor-beacon/models/endpoints", headers={
                        "Authorization": "Bearer valid-user-token",
                    })
                    await response.read()
                    return response.status
                self.assertEqual(await asyncio.gather(*(get() for _ in range(30))), [200] * 30)
                self.assertEqual(len(self.auth_tokens), 30)
                self.assertEqual(self.logout_count, 30)
                self.assertLessEqual(self.maximum_authentications, 2)
                invalid = await client.get("/api/harbor-beacon/models/endpoints", headers={
                    "Authorization": "Bearer invalid-token",
                })
                self.assertEqual(invalid.status, 401)
                await invalid.read()
                self.assertEqual(len(self.beacon_requests), 30)
            finally:
                await client.close()
                await runner.cleanup()

    def test_allowlist_rejects_ambiguous_paths_and_external_destinations(self):
        for path in ("/api/harbor-beacon/knowledge/../state", "/api/harbor-beacon/knowledge/%2e%2e/state",
                     "/api/harbor-beacon/knowledge//search", "/api/harbor-beacon/knowledge/search\\evil"):
            self.assertFalse(edge_proxy.allowed("POST", path))
        with self.assertRaises(ValueError):
            edge_proxy.Config("secret", "workspace", "http://example.com")


class CredentialFileTests(unittest.TestCase):
    def test_file_precedes_environment_and_missing_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "gate-token"
            credential.write_text("file-secret\n", encoding="utf-8")
            environment = {"HARBOR_GATE_TO_BEACON_TOKEN_FILE": str(credential), "HARBOR_GATE_TO_BEACON_TOKEN": "env-secret"}
            self.assertEqual(edge_proxy.service_token_from_env(environment), "file-secret")
            credential.unlink()
            with self.assertRaises(FileNotFoundError):
                edge_proxy.service_token_from_env(environment)
        self.assertEqual(edge_proxy.service_token_from_env({"HARBOR_GATE_TO_BEACON_TOKEN": "env-secret"}), "env-secret")


if __name__ == "__main__":
    unittest.main()
