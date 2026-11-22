# NAS edge verification — October 30, 2026

Changes: transport `67a9f09`; native Debian hook integration `ffb2120`.
The WebUI per-request user-token interceptor is committed separately as
`HarborNAS-webui` `49b5a275b5`.

| Check | Observed result |
|---|---|
| Windows Python 3.12, `python -m unittest discover -s scripts/harboros-edge -p 'test_edge_*.py' -q` | 12 tests passed |
| Target 192.168.3.209 Python 3.13/aiohttp 3.12.14, same test discovery in `/var/tmp/harbor-demo/edge-package-tests` | 12 tests passed in 0.119 seconds |
| Target `bash -n postinst prerm` for the native package hooks | Exit 0 |
| Read-only `beacon_context(MainPID)` against the target's actual running Beacon process | Active workspace `home-1`, Gate credential configured; no credential content printed |
| Frontend dedicated interceptor Jest suite | 8 tests passed, including retry token renewal, rejection without anonymous fallback, and no external-origin credential attachment |
| Focused frontend ESLint | Exit 0; existing baseline-browser-mapping freshness notice only |

The Python integration tests use real local HTTP and WebSocket test servers.
They verify middleware TOKEN_PLAIN authentication, real returned UID/FULL_ADMIN
role projection, replacement of forged browser identity headers, rejection of
missing/invalid/non-admin credentials, strict route/method allowlisting,
multipart audio and binary audio pass-through, request size limits, and token
file precedence with failure on a missing configured file.

The native bootstrap tests verify systemd credential precedence, discovery of
the actual Beacon admin-state path, active workspace selection, no guessed
workspace when state is missing/inactive, and writing a private edge copy without
modifying the original Gate credential. The actual target context probe exercises
this discovery against the existing service while leaving services unchanged.

Package integration is present in the existing release workflow and maintainer
scripts: edge scripts and unit are staged in the Debian artifact, Python/aiohttp
are declared dependencies, and the edge is enabled only for a NAS middleware
installation. The native unit retries missing Beacon state every five seconds.
Native N2 does not enable this middleware adapter.

This validation did not install/upgrade a Debian package or restart the live
edge service. The release CI workflow and an end-to-end package transaction have
not been executed here. The parent deployment owns the final live edge/Beacon
HTTP smoke, WebUI browser acceptance, reboot, and rollback verification.

## Live page fanout regression and correction

On October 30, 2026 the initial TCP implementation reproduced the actual Chrome
failure: thirty fresh single-use user tokens sent in parallel returned nineteen
200 responses and eleven 401 responses. Authorization was present in every
request. A direct middleware probe identified the underlying error as errno 16,
`[EBUSY] Rate Limit Exceeded`, from the shared loopback-IP login budget.

After switching the production adapter to the native middleware Unix socket,
adding explicit child logout, and bounding authentication concurrency to two:

- Linux target: fourteen transport/bootstrap tests passed, including an actual
  UnixSite test with thirty concurrent requests, invalid-token rejection, and a
  busy-error regression.
- Windows: thirteen tests passed; the UnixSite test was skipped on Windows.
- Temporary edge 4186 against the real Beacon: thirty fresh tokens produced
  thirty 200 responses; an invalid token remained 401.
- Live HTTPS nginx to edge 4176: thirty fresh tokens produced thirty 200
  responses. The real authenticated user UID was 950. Invalid token and replay
  of an already consumed token both remained 401.

Only `harbor-gate-webui-edge` was restarted, at `2026-10-30T07:44:19Z`. No Beacon,
nginx, middleware, or model runtime restart was performed for this correction.
Current release script:
`/var/lib/harborbeacon-agent-ci/releases/20261030T071534Z/deployment/edge_proxy.py`.
Private rollback copy in the same directory:
`edge_proxy.before-unix-auth-20261030T074419Z.py` (mode 0600).

```text
old sha256 7cf799fabe6953ef827aab42761c13c2fd764326604a5652008bc5187b5ee55f
new sha256 610e8f298c31e7343bea573dc5bacbb0ce33fac6ae804455489554b08ab0a4e9
```

Safe request/deployment evidence is saved in the HarborNAS WebUI repository at
`plans/harboros-demo-209-evidence/edge-auth-20261030T074419Z.json`. It records
request paths, statuses, Authorization-presence booleans, user UID, hashes, and
backup paths. It contains no token values, captured headers, environment bodies,
or state responses. Actual Chrome acceptance is run by the parent browser task.
