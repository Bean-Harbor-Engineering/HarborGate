# Feishu processing acknowledgement — 2026-11-01

Implemented in Gate `ace1192`, using the existing Feishu text-message adapter and
Beacon v2.0 turn contract. No new business protocol, work queue or daemon is added.

## User-visible behavior

A nontrivial Feishu text request or a message with an attachment receives the
best-effort transport notice `收到，正在处理…`. The notice is attempted before the
per-chat business lock, platform audio download and Beacon request. A queued
request can therefore be acknowledged while an earlier business turn is running.
Short greetings and connectivity probes do not receive this extra notice. The
notice acknowledges receipt; it does not mean Beacon completed the task.

Each send attempt is bounded to one second. This is a local waiting limit, not a
guarantee that the mobile client displays a message within one second. Platform
latency, token refresh, connectivity and a concurrent transport notice can affect
visibility. A failed or timed-out acknowledgement does not block the business
request. If processing fails, Gate makes one bounded attempt to send
`本次处理暂未完成，请稍后重试。`; failure of the platform itself can prevent that
message too. Existing final results and partial-media retry remain independent.

## Identity and persistence

The existing delivery ledger reserves a separate `processing_ack_…` key derived
from platform, chat and original message identity before sending. The failure
notice uses its own namespace. A concurrent retry, completed replay or restart
does not produce another notice attempt for the same identity. Feishu also
receives the adapter's existing stable UUID, distinct from the business result.

Reservation before sending prevents duplicate attempts after an uncertain
provider response. It deliberately does not guarantee eventual acknowledgement
delivery if the process stops between reservation and sending. No processing
notice overwrites business completion, conversation history, continuation or
`previous_delivery` image receipts. The notice lock is shared per chat in a
separate namespace; it is not retained as a new lock for every message.

## Verification

Clean committed-source Linux build at `.78`, source `ace1192`:

- Library tests: 43 passed.
- `feishu_processing_ack`: 5 passed. Checks acknowledgement before slow business
  and audio download, queued requests, concurrent replay and restart, provider
  failure, bounded acknowledgement timeout, and one visible business-failure
  notice.
- Existing `feishu_voice_transport`: 5 passed, 2 ignored because they require real
  ffmpeg/libopus. The duplicate-delivery test still requires exactly two business
  results, separately accounting for one voice acknowledgement.
- Release build: passed.

No real IM messages were sent by these tests. A read-only target check at
`2026-11-01T05:24:56Z` found the Gate unit enabled/active, executable under
`feishu-voice-customer-closeout-20261101-b23a585-ace1192`, authenticated gateway
status HTTP 200, and Feishu configured/connected in websocket mode. These facts
confirm deployment and transport connectivity; actual phone acknowledgement
visibility and perceived latency remain pending user validation.

Evidence: `E:/HarborDemoCloseout/20261101/feishu-ack-voice-isolation/` contains the
clean build context, deployment manifest and `ack-postdeploy-readonly.json`.
No credential, auth state or media capability URL is included in that status file.
