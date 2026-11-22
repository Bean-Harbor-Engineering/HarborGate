# Feishu inbound file transport

Gate accepts a Feishu `file` message through the existing v2.0 `input.parts`
attachment shape. It downloads the message-bound resource with `type=file`,
caches the original bytes, and supplies `type=file`, a display filename, MIME
hint, actual byte count, SHA-256, provider, and source message ID. Gate does not
parse documents or decide which formats Beacon can understand. The current
Beacon demo accepts PDF documents up to 16 MiB; Gate's transport limit remains
32 MiB. A MIME hint or `.pdf` filename is not proof of a valid PDF.

The configured sender/chat policy runs before downloading. Provider credentials
stay inside Gate. Resource downloads reject redirects, JSON provider error
documents, empty bodies, and declared or streamed bodies over 32 MiB. Missing
Content-Type defaults to `application/octet-stream`. Names are sanitized display
basenames and never become storage paths. Cached bytes are accessed only by
safe attachment IDs and ten-minute, single-file bearer capabilities on the
existing loopback `/api/media/{attachment_id}` endpoint.

A failed new file still reaches Beacon after sender authorization with only
`attachment_id`, `type=file`, and `metadata.media_error`. Codes are `file_empty`,
`file_too_large`, `file_download_failed`, and `file_storage_unavailable`. Such a
part has no download, fabricated hash, MIME, provider credential, or error body.
Beacon must clear the previous document context before returning the error.
Duplicate events and restart replay reuse the same prepared part and turn;
expired capabilities are not silently renewed. A new upload creates a new turn.

Run the local mock-only checks with:

```text
cargo test --locked --lib --test feishu_file_transport --test feishu_image_transport --test feishu_voice_transport --test rust_only_guard
```

These checks cover original bytes and hash, MIME fallback, display names,
capability scope and expiry, authorization before network access, stable retry,
backward-compatible audio/image cache entries, provider denial, redirects,
timeouts, and declared/chunked oversize. They do not establish live provider
permissions or successful PDF parsing. Those require the deployed Beacon and a
user-uploaded test document in the verified bot conversation.
