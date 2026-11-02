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

## Hard Boundary Rules

- Repos communicate only through HTTP/JSON.
- Repos must not import each other's runtime code.
- Repos must not share `.harborbeacon/*.json` or other runtime state files.
- HarborGate must not own business semantics, approvals, artifacts, or audit.
- HarborBeacon must not own platform credentials or direct IM delivery.
- HarborBeacon must treat `transport.route_key` as opaque routing metadata.
- HarborGate may cache only opaque `conversation.handle` and `continuation`
  values returned by HarborBeacon.
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

## Feishu voice/media transport extension (2026-10-31)

This remains contract v2.0. No additional conversation protocol is introduced.

- Feishu advertises `transport.capabilities.audio=true`; Weixin does not. The
  existing text/image/file capabilities retain their meanings.
- An audio `input.parts` item uses the existing attachment descriptor fields:
  `attachment_id`, `type=audio`, `name`, `mime_type`, `size_bytes`, `download`,
  and `metadata.duration_ms`. Gate downloads the platform resource itself.
- `download` uses `mode=proxy`, `method=GET`, `url`, a single-file opaque bearer
  capability in `headers.Authorization`, `auth.type=bearer`, `expires_at`, and
  `max_size_bytes=33554432`. The Gate endpoint is `/api/media/{attachment_id}`.
  Capabilities expire after ten minutes and cannot read another attachment.
  Platform credentials must never appear in this descriptor. Inbound voice is
  normalized by Gate to mono 16 kHz PCM WAV with measured duration. Pending
  delivery replays its original turn to refresh expired speech capabilities;
  Beacon reuses the cached business answer and generated speech.
- Beacon-generated speech uses `kind=audio`, stable `artifact_id`,
  `mime_type=audio/wav`, `url`, and `metadata.download` with the same download
  descriptor fields. Gate fetches only the configured loopback Beacon origin
  and `/api/web/media/` prefix, with redirects disabled.
- A `native_audio` hint refers to that audio artifact; its fallback is text.
  Gate converts speech to Opus, uploads it, and sends a native Feishu audio
  message. An original photo requested as a file uses `kind=file` and a
  `native_file` hint, preserving file bytes rather than using image compression.
- Feishu delivery order is text/card, at most three ordered images, an optional
  original file, then optional audio. Per-part provider receipts are Gate-owned
  delivery state. A partial send is explicitly reported and retries skip parts
  already sent; the same platform message must not create a new business turn.
- Incoming websocket events are acknowledged before business processing.
  Platform HTTP operations and audio conversion are bounded to twenty seconds;
  Gate waits at most two hundred seconds for Beacon's business response.

## Model-selection cards extension (2026-11-02)

This is an additive v2.0 extension; the service header remains `2.0`.

- `transport.capabilities.interactive_card` is optional and defaults to false.
- Beacon may return `delivery_hints` with `kind=native_card`, `fallback=text`, and
  `metadata.card={schema_version:1,title,subtitle,rows:[{text}],actions:[{label,value}]}`.
- The card descriptor is platform-neutral. Gate renders it; Gate must not interpret
  capability, model or runtime selection semantics. Existing `reply.text` remains the text fallback.
- Feishu callbacks carry `input.parts` entries with `type=card_action`, a stable
  `attachment_id` anchored to the platform event, and
  `metadata={provider:"feishu",source_message_id,value}`. The opaque `value` carries
  Beacon-issued `chooser_id`/`option_id` and an action identifier. It carries no
  endpoint URL, local file path, credential or trusted principal.
- Gate preserves the verified operator identity and source conversation, checks its
  sender policy and persisted source-card receipt, and promptly acknowledges the
  event before asynchronous business processing. Normal turn card delivery uses
  the same transport ledger and retry semantics as other messages.
- Beacon owns the ten-minute chooser, actor/workspace/conversation/configuration
  binding, authorization, deterministic selection, replay protection and audit.
  Only an existing bound administrator may modify global model settings.
- The card and WebUI use the same capability-selection service and persistent state.
  Result cards are sent as new replies; this extension does not require message editing.
- Cards without interactive-card capability degrade to useful text; unsupported
  clients must not be told that a model was switched.

The explicitly approved 2026-11-02 Demo may use a server-owned, expiring
actor/route/workspace permission grant instead of an identity binding. The original
grant was due to expire at 2026-11-02T23:59:59+08:00; on 2026-11-02 the user explicitly extended
the same grant through November 11 inclusive, with the current cutoff at
**2026-11-11T23:59:59+08:00**. The actor, route, workspace and permission scope remain
unchanged. Gate still verifies the callback source and private operator; Beacon
still owns all business checks and global selection state. This exception does not
change platform roles or the ten-minute chooser expiry. Any further extension
requires explicit user authorization.
