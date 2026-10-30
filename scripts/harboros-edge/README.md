# HarborOS WebUI session edge

Temporary deployment transport for the HarborNAS WebUI demo. Business requests and
responses remain the existing HarborBeacon protocol. This code belongs to Gate,
which owns authentication and transport, and does not implement Knowledge state.

The existing WebUI WebSocket session calls `auth.generate_token(60, {}, false,
true)` for each HTTP request. A separate single-use token avoids consuming the
WebUI reconnect token chain. The functional WebUI interceptor sends the user token
as an Authorization bearer to `/api/harbor-beacon/`. The edge authenticates it using
middleware `auth.login_ex` (`TOKEN_PLAIN`, no reconnect token), derives the actual
Unix UID and `FULL_ADMIN` role from server-returned `user_info`, and replaces the
user bearer and all identity headers with the server's Gate credential and
`harboros:uid:<uid>` identity. Browser identity hints are never trusted.

Listen: `127.0.0.1:4176`; upstream Beacon: `127.0.0.1:4174`; middleware: `127.0.0.1:6000/websocket`.
Nginx must preserve the `/api/harbor-beacon/` URI when proxying to port 4176. The
adapter maps that prefix to `/api/` and forwards bodies unchanged (including
multipart audio). Every allowlisted route requires a real admin user token.
Unknown paths/methods are rejected. Request bodies are capped at 20 MiB and
responses at 32 MiB. No response or token cache is used; authentication failures
never fall back to anonymous access.

Install `edge_proxy.py` at
`/var/lib/harborbeacon-agent-ci/deployment/edge_proxy.py` and the supplied unit at
`/etc/systemd/system/harbor-gate-webui-edge.service`. The host needs Python 3.11+
and aiohttp (both already present on the demo host). The root-only environment
file `/etc/default/harbor-gate-webui-edge` must contain:

```text
HARBOR_GATE_TO_BEACON_TOKEN_FILE=/absolute/path/to/root-only-bare-token-file
HARBOR_EDGE_WORKSPACE_ID=<actual-active-Beacon-workspace-id>
```

The credential file contains only the Gate token. It takes precedence over the
optional `HARBOR_GATE_TO_BEACON_TOKEN` environment value. Missing/unreadable files
fail startup. Use the same real Gate-to-Beacon credential configured on Beacon;
never place it in frontend code, browser storage, or URLs. After nginx validation,
run `systemctl daemon-reload` and `systemctl enable --now harbor-gate-webui-edge`.
Rollback restores nginx's previous target, disables this unit, and restores the
previous WebUI dist together; the new WebUI user bearer must not be sent straight
to Beacon as a service credential.

Direct `<img>`, `<video>`, or `<a>` URLs cannot carry the interceptor's bearer.
Load protected previews through HttpClient as blobs before displaying/opening
them. Do not put user or service tokens in query strings.

Run the integration tests with:

```sh
python3 -m unittest discover -s scripts/harboros-edge -p test_edge_proxy.py -v
```
