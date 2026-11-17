# Feishu inbound image transport

For the 2026-11-20 demo, Gate delivers JPEG/PNG image messages to Beacon using
the existing v2.0 short-lived attachment proxy. Gate does not interpret, save to
the photo library, or index pictures. Beacon owns those user-visible actions.

## Provider setup and boundaries

Use the existing bound private-chat bot and credentials. The app must receive
`im.message.receive_v1` and have permission to retrieve resources belonging to
the received message (`im:resource`, shown as message resource access in the
provider console). Verify the published app version and permitted user scope
on the demo tenant before the live rehearsal. Local mock tests cannot prove
tenant permissions or mobile-client format conversion.

Gate calls `/open-apis/im/v1/messages/{message_id}/resources/{image_key}?type=image`
with its tenant token. HTTP requests retain the configured bounded timeout
(`FEISHU_TIMEOUT_SECONDS`, default 20 seconds) and never follow redirects.
Provider HTTP failures, JSON error documents, empty content, and downloads
over 32 MiB are rejected. The stream is size-limited even without Content-Length.
No platform token or provider error body is forwarded to Beacon.

A rejected new image still creates a v2 turn after sender authorization. The
attachment contains only its stable `attachment_id`, `type=image`, and
`metadata.media_error` (`image_invalid`, `image_too_large`,
`image_dimensions_exceeded`, `image_download_failed`, or
`image_storage_unavailable`). There is no usable download descriptor or fabricated
MIME/hash. Beacon clears the previous image context before displaying this error,
so a follow-up cannot accidentally describe an older photo. Gate persists the
prepared failure for duplicate/restart replay; retrying the upload requires a new
user message. A provider failure never creates a successful media-cache entry.

Only decodable JPEG and PNG are accepted. HEIC, WebP, GIF and corrupt files
must be re-sent as JPEG/PNG. Limits are 64 million pixels, 16384 pixels per edge,
and 512 MiB of decoder allocation. Gate preserves original downloaded bytes,
including EXIF, and reports their actual MIME, size, SHA-256 and encoded dimensions.
The mobile app may transform a photo before uploading it; the checksum identifies
the received Feishu resource, not necessarily the phone's camera-roll original.

## v2.0 descriptor example

```json
{
  "attachment_id": "att_opaque_stable_id",
  "type": "image",
  "name": "image.jpg",
  "mime_type": "image/jpeg",
  "size_bytes": 123456,
  "download": {
    "mode": "proxy",
    "method": "GET",
    "url": "http://127.0.0.1:8787/api/media/att_opaque_stable_id",
    "headers": {"Authorization": "Bearer <single-file-capability>"},
    "auth": {"type": "bearer"},
    "expires_at": "<RFC3339, ten minutes after preparation>",
    "max_size_bytes": 33554432
  },
  "metadata": {
    "sha256": "<64 lowercase hex characters, original bytes>",
    "width": 4032,
    "height": 3024,
    "provider": "feishu",
    "source_message_id": "om_example"
  }
}
```

Beacon should fetch and checksum the original during the first turn. The
capability does not authorize other files and returns `MEDIA_NOT_AVAILABLE`
after expiry or with missing/wrong authorization. Replayed events reuse the
same descriptor and turn; expiry must not create a new business action.

## Local verification

```text
cargo test --lib --test feishu_voice_transport --test feishu_image_transport
cargo test --test rust_only_guard
git diff --check
```

The image tests use local HTTP providers only: JPEG/PNG byte preservation,
v2 headers and descriptors, concurrent duplicate events, restart, expired
capabilities, actual media endpoint authorization, sender allowlist, malformed
formats, resource denial, redirects, declared/chunked oversize and timeout.
They also cover a valid photo followed by a rejected replacement, ensuring that
the failure reaches Beacon once, with no download or credentials, across
concurrent duplicate events and restart.
Live phone upload, image understanding, follow-up, authorized save and search
must still be accepted end to end on the demo device by the integration owner.
