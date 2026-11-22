# Feishu voice transport for the HarborOS demo

Gate owns platform resource download, native image/audio/file delivery and
receipts. Beacon owns ASR, retrieval, conversation state and TTS. This feature
uses the existing v2.0 HTTP turn seam. Weixin voice is not enabled by this change.

Configure existing Feishu app credentials and receive permissions through the
existing setup portal. Use websocket receive and enable live send only for the
bound private chat demo. Group chat is outside the demo scope.

Runtime environment:

```text
IM_AGENT_STATE_DIR=/var/lib/harboros-im-gate
IM_AGENT_DATA_DIR=/var/lib/harboros-im-gate/sessions
HARBOR_BEACON_MEDIA_ORIGIN=http://127.0.0.1:4174
HARBORGATE_FFMPEG_BIN=/var/lib/harboros-im-gate/runtime/media-tools/bin/ffmpeg
```

`HARBOR_FFMPEG_BIN` remains a compatible fallback. ffmpeg needs libopus. The
existing `FEISHU_TIMEOUT_SECONDS` defaults to 20 and is now actually applied to
HTTP requests. The Beacon request deadline is 200 seconds. Downloaded inbound
voice is decoded to mono 16 kHz PCM WAV for ASR, capped at 32 MiB, and served by a single-file capability for ten minutes,
and expired entries are removed on subsequent cache writes.

Persistent state includes prepared inbound messages, completed-turn delivery
results and per-part receipts. A duplicate platform message reuses its original
business identity and does not resend successful parts. The ordered image
sequence stays stable during a partial-send retry. Original files are uploaded
with Feishu's file API so their content remains unchanged.

Local verification (mock provider only; no real messages are sent):

```text
cargo test --lib
cargo test --test feishu_voice_transport
cargo test --test feishu_voice_transport native_audio_is_converted_and_sent_after_at_most_three_images -- --ignored
```

The last test uses real ffmpeg plus a local mock provider to verify WAV-to-Opus
conversion and text → three images → audio order. Set `HARBORGATE_TEST_FFMPEG`
when ffmpeg is not on PATH. A passing mock does not replace receiving and playing
native audio in the real Feishu mobile client.

For TrueNAS, deploy a persistent release binary and media tools using the
existing service/drop-in approach. Do not install with dpkg for this demo.
Back up binary and service pointers, configuration and Gate state before a
switch. Keep Feishu credentials in the existing private configuration and out of
source control or evidence output.
