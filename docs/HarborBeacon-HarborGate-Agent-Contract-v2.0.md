# HarborBeacon HarborGate Agent Contract v2.0

## Status

This is the active HarborBeacon <-> HarborGate contract.

It supersedes `HarborBeacon-HarborGate-Agent-Contract-v1.5.md` for current
implementation, tests, runbooks, and release gates. The v1.5 document remains
historical reference only.

The v2.0 upgrade is intentionally breaking. There is no in-process v1.5/v2.0
dual stack. Rollback means rolling both HarborBeacon and HarborGate back to the
previous approved artifacts.

## Purpose

v2.0 makes the conversation turn model explicit so HarborBeacon no longer
depends on hidden coupling between `source.session_id`, `args.resume_token`, and
HarborGate session metadata.

HarborBeacon owns business interpretation and state:

- planner and router behavior
- conversation continuity
- active dialogue frames
- approvals, artifacts, and audit
- tool execution and business errors

HarborGate owns IM transport:

- adapters, route registry, and platform credentials
- inbound normalization
- outbound platform delivery
- delivery retry and provider failure mapping
- redacted gateway status

## Product Boundary Scope

This v2.0 contract only freezes the HarborBeacon <-> HarborGate IM/channel
service-to-service seam. It does not assign the wider product boundaries:

- HarborCloud owns account, entitlement, Hub identity, WebRTC signaling, and
  cloud metadata.
- HarborLink owns Hub-side outbound MQTT, command acknowledgements, and local
  Home Assistant/camera bridge execution.
- harbor-dock owns Android/Paper UI state and user intent.
- HarborNAS-webui owns HarborOS WebUI presentation and same-origin operation
  surfaces.

HarborGate may normalize assistant turns from channel clients, but it must not
become the backend for HarborCloud entitlement, HarborLink MQTT, HarborDock
remote home/camera control, or WebUI display truth.

## Hard Boundary Rules

- Repos communicate only through HTTP/JSON.
- Repos must not import each other's runtime code.
- Repos must not share `.harborbeacon/*.json` or other runtime state files.
- HarborGate must not own business semantics, approvals, artifacts, or audit.
- HarborBeacon must not own platform credentials or direct IM delivery.
- HarborBeacon must treat `transport.route_key` as opaque routing metadata.
- HarborGate may cache only opaque `conversation.handle` and `continuation`
  values returned by HarborBeacon.
- HarborGate must not own HarborCloud entitlement, HarborLink MQTT command/ack,
  HarborDock UI intent, or HarborNAS WebUI display state.
- Group chat remains out of scope for this upgrade.

## Versioning

All service-to-service calls on the v2.0 seam must carry:

```text
X-Contract-Version: 2.0
```

Requests with any other active contract version must be rejected with the shared
non-200 error envelope and `CONTRACT_VERSION_MISMATCH`.

## Interface 1: Inbound Turn

### Endpoint

`POST /api/web/turns`

`POST /api/turns` remains a deprecated compatibility alias for the HarborBeacon
single-port cutover window.

This endpoint replaces HarborGate use of `POST /api/tasks`.

### Request Shape

```json
{
  "turn": {
    "turn_id": "turn_01JABC",
    "trace_id": "trace_01JABC",
    "occurred_at": "2026-04-26T10:00:00Z",
    "retry_of": null
  },
  "actor": {
    "user_id": "ou_xxx",
    "workspace_id": "home-1",
    "account_id": null
  },
  "conversation": {
    "handle": "conv_01JABC",
    "channel": "weixin",
    "surface": "harborgate",
    "thread_id": "chat_xxx",
    "chat_type": "p2p"
  },
  "transport": {
    "route_key": "gw_route_01JABC",
    "message_id": "om_xxx",
    "capabilities": {
      "text": true,
      "image": true,
      "file": true,
      "video": true
    },
    "metadata": {}
  },
  "input": {
    "text": "非常好",
    "parts": []
  },
  "continuation": {
    "token": "cont_01JABC",
    "frame_id": "frame_01JABC",
    "reply_to_turn_id": "turn_01JAAA",
    "expires_at": "2026-04-26T10:05:00Z"
  },
  "autonomy": {
    "level": "supervised"
  }
}
```

### Request Rules

- `turn.turn_id` is the inbound idempotency anchor.
- `turn.trace_id` is the cross-repo observability anchor.
- `conversation.handle` is Beacon-owned and opaque to HarborGate.
- If HarborGate does not yet have a handle, it sends `null` or omits the field;
  HarborBeacon returns the canonical handle.
- `conversation.thread_id` is transport-origin identity only.
- `transport.route_key` is HarborGate-owned and opaque to HarborBeacon.
- `transport.message_id` is the platform message identity when available.
- `input.parts` carries opaque attachments and non-text parts.
- `continuation` is optional and opaque to HarborGate.
- `args.resume_token` is not part of v2.0.
- `source.session_id` is not part of v2.0 business identity.

## Response Shape

```json
{
  "turn": {
    "turn_id": "turn_01JABC",
    "trace_id": "trace_01JABC",
    "status": "completed"
  },
  "conversation": {
    "handle": "conv_01JABC"
  },
  "active_frame": {
    "frame_id": "frame_01JABC",
    "kind": "camera.clip_confirmation",
    "state": "awaiting_user_choice",
    "expected_reply": ["yes", "no", "playback"],
    "continuation_token": "cont_01JABC",
    "expires_at": "2026-04-26T10:05:00Z"
  },
  "reply": {
    "kind": "frame_prompt",
    "text": "已录制短视频。是否看完整回放？回复：要 / 不要"
  },
  "artifacts": [],
  "delivery_hints": [],
  "observability": {
    "route_key": "gw_route_01JABC",
    "message_id": "om_xxx",
    "frame_id": "frame_01JABC",
    "artifact_count": 0
  },
  "error": null
}
```

### Response Rules

- `reply.text` is the primary user-visible text.
- `reply.kind` must be one of `tool_result`, `conversation`, `boundary`,
  `repair`, `cancel`, `clarify`, or `frame_prompt`.
- `active_frame` is present only when Beacon wants the next turn interpreted in
  a known dialogue frame.
- HarborGate must store `conversation.handle` and `active_frame.continuation_token`
  opaquely and return them on the next turn.
- HarborGate must not interpret `active_frame.kind` for business routing.
- `delivery_hints` are platform-neutral instructions for delivery formatting.

## Conversation Acts

When no tool action is selected, HarborBeacon still returns a valid conversation
act instead of falling back to unsupported.

Supported act kinds:

- `conversation_continue`
- `conversation_boundary`
- `conversation_repair`
- `conversation_cancel`
- `clarify_continue`

Unsupported fallback is reserved for parser or backend failures, not normal user
input.

## Interface 2: Notification Delivery

### Endpoint

`POST /api/notifications/deliveries`

This endpoint remains hosted by HarborGate, but v2.0 callers must use the v2.0
version header and v2 response/error rules.

### Request Shape

```json
{
  "notification": {
    "notification_id": "notif_01JABC",
    "trace_id": "trace_01JABC",
    "event_type": "task.completed"
  },
  "conversation": {
    "handle": "conv_01JABC"
  },
  "destination": {
    "route_key": "gw_route_01JABC"
  },
  "reply": {
    "kind": "tool_result",
    "text": "回放已准备好。"
  },
  "artifacts": [],
  "delivery_hints": [
    {
      "kind": "native_video",
      "artifact_id": "artifact_clip_1",
      "fallback": "file"
    }
  ],
  "delivery": {
    "mode": "send",
    "idempotency_key": "idem_01JABC",
    "reply_to_message_id": null,
    "update_message_id": null
  }
}
```

### Delivery Rules

- HarborGate owns native platform formatting and fallback.
- HarborBeacon supplies platform-neutral `delivery_hints` only.
- `native_video` may fall back to file when platform video delivery fails.
- Native delivery metadata such as `native_attachment_kind` and
  `native_attachment_fallback` remains Gate-side observability, not Beacon
  contract truth.
- Request-rejection failures use non-200 shared error envelope.
- Accepted delivery failures use HTTP 200 with the delivery response envelope.

### Member Rule/Plan email authorization extension (2026-10-08)

This additive development extension keeps the existing IM v2.0 contract and service authentication. A `rule.reminder` or `plan.reminder` sent through `feishu_mail` carries its original opaque `conversation.handle` permit. Gate preserves it in the delivery fingerprint/item plan and calls Native's private `POST /api/im/peer/delivery-authorization` before preparation, after preparation and on retry/recovery, with the existing contract header. Missing permits and withdrawn membership, binding, preferences, source or original dispatch attempt deny sending.

Email transport uses `destination.platform: "feishu_mail"`, the actual verified address in `destination.id` and `destination.recipient.recipient_id`, and an empty `destination.route_key`. Empty identity/address alternatives do not hide a nonempty recipient. The authorization body uses `platform: "feishu_mail"` and `delivery.route_key: "member-email"`; this is a Native authorization identifier, not a Gate transport route. `delivery.recipient` is the exact actual address, with original permit/text and no attachments or source references. The provider request's single To address must equal this authorized address; CC/BCC and recipient replacement are rejected using the actual mail recipient builder.

`member.email_verification` mails remain independent of business reminder authorization. Legacy queued Native reminders with `reminder-im-` IDs still require a permit even if their pre-fix item metadata omitted it. This patch has compilation/static evidence only; regression specifications are not executed, and live delivery/retry/revocation behavior is unaccepted.

## Error Envelope

Non-200 request rejections use:

```json
{
  "ok": false,
  "error": {
    "code": "SERVICE_AUTH_FAILED|CONTRACT_VERSION_MISMATCH|VALIDATION_ERROR|IDEMPOTENCY_CONFLICT|ROUTE_NOT_FOUND|ROUTE_EXPIRED|INFRASTRUCTURE_ERROR",
    "message": "human-readable summary"
  },
  "trace_id": "trace_01JABC"
}
```

Business failures after a turn is accepted stay in the v2 turn response with
`turn.status=failed`.

## Idempotency

- Retrying the same inbound IM event must reuse `turn.turn_id`.
- A conflicting replay of the same `turn.turn_id` must return
  `IDEMPOTENCY_CONFLICT`.
- A new user message must use a new `turn.turn_id`, even when continuing an
  active frame.
- Notification retries must reuse `delivery.idempotency_key`.
- Conflicting notification replay must return `IDEMPOTENCY_CONFLICT`.

## Observability

Both repos should log these fields when available:

- `turn.turn_id`
- `turn.trace_id`
- `conversation.handle`
- `transport.route_key`
- `transport.message_id`
- `active_frame.frame_id`
- `notification.notification_id`
- `delivery.idempotency_key`
- `provider_message_id`
- `contract_version`

## Release Gate

v2.0 is release-ready only when:

- HarborGate sends no active `/api/tasks` requests.
- Active service-to-service calls use `X-Contract-Version: 2.0`.
- No active request builder emits `args.resume_token`.
- HarborBeacon does not treat transport session identity as business truth.
- Gate stores continuation values opaquely and does not route on business
  frame semantics.
- Weixin private DM matrix passes capability, conversation, clarification,
  cancel, record, and playback cases.
- Direct IM delivery and raw platform credential ownership remain outside
  HarborBeacon.
- HarborCloud entitlement, HarborLink MQTT, HarborDock remote home/camera
  control, and WebUI display state remain outside this IM contract.
