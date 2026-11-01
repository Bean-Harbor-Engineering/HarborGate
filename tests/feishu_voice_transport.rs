use axum::{
    body::Bytes,
    extract::State,
    routing::{get, post},
    Json, Router,
};
use harborgate::adapters::{feishu::FeishuAdapter, PlatformAdapter};
use harborgate::config::AppConfig;
use harborgate::gateway::GatewayService;
use harborgate::models::OutboundMessage;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[derive(Default)]
struct Mock {
    messages: Mutex<Vec<Value>>,
    turns: Mutex<Vec<Value>>,
    origin: Mutex<String>,
    files: Mutex<Vec<Vec<u8>>>,
    fail_image_once: AtomicBool,
}

async fn mock_message(State(state): State<Arc<Mock>>, Json(body): Json<Value>) -> Json<Value> {
    state.messages.lock().unwrap().push(body.clone());
    if body["msg_type"] == "image" && state.fail_image_once.swap(false, Ordering::SeqCst) {
        return Json(json!({"code":1,"msg":"controlled image failure"}));
    }
    Json(
        json!({"code":0,"data":{"message_id":format!("mock_{}",state.messages.lock().unwrap().len())}}),
    )
}
async fn mock_file(State(state): State<Arc<Mock>>, body: Bytes) -> Json<Value> {
    state.files.lock().unwrap().push(body.to_vec());
    Json(json!({"code":0,"data":{"file_key":"file_mock"}}))
}
async fn mock_image() -> Json<Value> {
    Json(json!({"code":0,"data":{"image_key":"image_mock"}}))
}
async fn mock_token() -> Json<Value> {
    Json(json!({"code":0,"tenant_access_token":"mock_platform_secret","expire":7200}))
}
async fn mock_turn(State(state): State<Arc<Mock>>, Json(body): Json<Value>) -> Json<Value> {
    if let Some(part) = body.pointer("/input/parts/0") {
        assert_eq!(part["type"], "audio");
        let auth = part
            .pointer("/download/headers/Authorization")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(!auth.contains("mock_platform_secret"));
        let bytes = reqwest::Client::new()
            .get(part["download"]["url"].as_str().unwrap())
            .header("Authorization", auth)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), short_wav().as_slice());
        assert_eq!(part["mime_type"], "audio/wav");
        assert_eq!(part["metadata"]["duration_ms"], 100);
    }
    let first = !state
        .turns
        .lock()
        .unwrap()
        .iter()
        .any(|old| old["turn"]["turn_id"] == body["turn"]["turn_id"]);
    state.turns.lock().unwrap().push(body.clone());
    if body["input"]["text"] == "retry expired audio" {
        let origin = state.origin.lock().unwrap().clone();
        let expires = chrono::Utc::now() + chrono::Duration::minutes(if first { -1 } else { 10 });
        return Json(
            json!({"turn":{"turn_id":body["turn"]["turn_id"],"trace_id":body["turn"]["trace_id"],"status":"completed"},
            "conversation":{"handle":"conv_mock"},"reply":{"kind":"conversation","text":"cached answer"},
            "artifacts":[{"kind":"audio","artifact_id":"cached_speech","mime_type":"audio/wav","url":format!("{origin}/api/web/media/cached_speech"),
                "metadata":{"duration_ms":100,"download":{"url":format!("{origin}/api/web/media/cached_speech"),"method":"GET","headers":{"Authorization":"Bearer short-cap"},"expires_at":expires.to_rfc3339()}}}],
            "delivery_hints":[{"kind":"native_audio","artifact_id":"cached_speech","fallback":"text"}]}),
        );
    }
    Json(
        json!({"turn":{"turn_id":body["turn"]["turn_id"],"trace_id":body["turn"]["trace_id"],"status":"completed"},
        "conversation":{"handle":"conv_mock"},"reply":{"kind":"conversation","text":"Mock retrieval result"},"artifacts":[],"delivery_hints":[]}),
    )
}
async fn cached_media(
    State(gateway): State<Arc<GatewayService>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl axum::response::IntoResponse, harborgate::error::GatewayError> {
    let (mime, bytes) = gateway.read_media(
        &id,
        headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    )?;
    Ok(([("content-type", mime)], bytes))
}
async fn mock_audio() -> ([(&'static str, &'static str); 1], Vec<u8>) {
    ([("content-type", "audio/opus")], short_wav())
}

async fn provider(state: Arc<Mock>) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/web/turns", post(mock_turn))
        .route(
            "/open-apis/auth/v3/tenant_access_token/internal",
            post(mock_token),
        )
        .route("/open-apis/im/v1/messages", post(mock_message))
        .route("/open-apis/im/v1/images", post(mock_image))
        .route("/open-apis/im/v1/files", post(mock_file))
        .route(
            "/open-apis/im/v1/messages/{message}/resources/{key}",
            get(mock_audio),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    *state.origin.lock().unwrap() = origin.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (origin, task)
}

fn config(root: &std::path::Path, origin: &str) -> AppConfig {
    let mut config = AppConfig::from_env();
    config.data_dir = root.join("sessions");
    config.state_dir = root.join("state");
    config.harborbeacon_base_url.clear();
    config.feishu.base_url = origin.into();
    config.feishu.auth_base_url = origin.into();
    config.feishu.app_id = "mock_app".into();
    config.feishu.app_secret = "mock_secret".into();
    config.feishu.enable_live_send = true;
    config.feishu.allowed_users.clear();
    config.feishu.verification_token.clear();
    config
}
fn event(kind: &str, message: &str, content: Value) -> Value {
    json!({"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},
        "message":{"chat_id":"oc_chat","chat_type":"p2p","message_id":message,"message_type":kind,"content":content.to_string()}}})
}
fn outbound(attachments: Vec<Value>, turn: &str) -> OutboundMessage {
    OutboundMessage {
        platform: "feishu".into(),
        chat_id: "oc_chat".into(),
        text: "Found results".into(),
        attachments,
        timestamp: harborgate::models::utc_now_iso(),
        metadata: serde_json::from_value(json!({"turn_id":turn})).unwrap(),
    }
}

#[tokio::test]
async fn audio_normalization_download_and_duplicate_text_use_real_transport() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (origin, task) = provider(state.clone()).await;
    let mut config = config(temp.path(), &origin);
    let adapter = FeishuAdapter::new(config.feishu.clone());
    let normalized = adapter
        .normalize_inbound(event(
            "audio",
            "om_audio",
            json!({"file_key":"file_voice","duration":1234}),
        ))
        .unwrap();
    assert!(normalized.text.is_empty());
    assert_eq!(normalized.attachments[0]["duration_ms"], 1234);
    assert!(adapter
        .normalize_inbound(event("audio", "om_empty", json!({})))
        .is_err());
    let (mime, bytes) = adapter
        .download_audio("om_audio", "file_voice")
        .await
        .unwrap();
    assert_eq!(mime, "audio/opus");
    assert_eq!(bytes, short_wav());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.port = listener.local_addr().unwrap().port();
    config.harborbeacon_base_url = origin.clone();
    let gateway = Arc::new(GatewayService::from_config(&config).unwrap());
    let router = Router::new()
        .route("/api/media/{id}", get(cached_media))
        .with_state(gateway.clone());
    let media_task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let voice = event(
        "audio",
        "om_voice_once",
        json!({"file_key":"voice_key","duration":1234}),
    );
    let (a, b) = tokio::join!(
        gateway.handle_inbound("feishu", voice.clone()),
        gateway.handle_inbound("feishu", voice)
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(
        state.turns.lock().unwrap().len(),
        1,
        "voice replay must not transcribe/submit twice"
    );
    let payload = event("text", "om_once", json!({"text":"hello"}));
    gateway
        .handle_inbound("feishu", payload.clone())
        .await
        .unwrap();
    gateway.handle_inbound("feishu", payload).await.unwrap();
    let messages = state.messages.lock().unwrap().clone();
    let ack_count = messages.iter().filter(|message| {
        serde_json::from_str::<Value>(message["content"].as_str().unwrap_or("{}"))
            .ok().is_some_and(|body| body["text"] == "收到，正在处理…")
    }).count();
    assert_eq!(ack_count, 1, "the voice message has one transport acknowledgement");
    assert_eq!(messages.len() - ack_count, 2,
        "each unique voice/text business result must still send exactly once");
    let restarted = GatewayService::from_config(&config).unwrap();
    restarted
        .handle_inbound("feishu", event("text", "om_once", json!({"text":"hello"})))
        .await
        .unwrap();
    assert_eq!(
        state.messages.lock().unwrap().len(),
        3,
        "restart must retain both acknowledgement and completed-message dedupe"
    );
    assert_eq!(
        state.turns.lock().unwrap()[1]["conversation"]["handle"],
        "conv_mock"
    );
    media_task.abort();
    task.abort();
}

#[tokio::test]
async fn partial_retry_skips_caption_and_original_file_bytes_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    state.fail_image_once.store(true, Ordering::SeqCst);
    let (origin, task) = provider(state.clone()).await;
    let cfg = config(temp.path(), &origin);
    let adapter = FeishuAdapter::with_media(
        cfg.feishu,
        temp.path().join("out"),
        "ffmpeg".into(),
        "http://127.0.0.1:4174".into(),
    );
    let image = temp.path().join("original.jpg");
    let original = b"\0ORIGINAL-JPEG-\xff";
    std::fs::write(&image, original).unwrap();
    let reply = outbound(
        vec![json!({"kind":"image","path":image,"mime_type":"image/jpeg"})],
        "turn_partial",
    );
    let first = adapter.send_outbound(reply.clone()).await.unwrap();
    assert_eq!(first["partial"], true);
    let second = adapter.send_outbound(reply).await.unwrap();
    assert_eq!(second["sent"], true);
    let messages = state.messages.lock().unwrap().clone();
    assert_eq!(
        messages.iter().filter(|m| m["msg_type"] == "image").count(),
        2
    );
    assert_eq!(
        messages
            .iter()
            .filter(|m| m["msg_type"] == "text"
                && m["content"].as_str().unwrap().contains("Found results"))
            .count(),
        1
    );
    assert_eq!(
        messages
            .iter()
            .filter(|m| m["msg_type"] == "image")
            .map(|m| m["uuid"].clone())
            .collect::<Vec<_>>()[0],
        messages
            .iter()
            .filter(|m| m["msg_type"] == "image")
            .map(|m| m["uuid"].clone())
            .collect::<Vec<_>>()[1]
    );
    adapter
        .send_outbound(outbound(
            vec![json!({"kind":"file","path":image,"mime_type":"image/jpeg"})],
            "turn_original",
        ))
        .await
        .unwrap();
    let files = state.files.lock().unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0]
        .windows(original.len())
        .any(|window| window == original));
    assert_eq!(
        state.messages.lock().unwrap().last().unwrap()["msg_type"],
        "file",
        "image MIME must not reclassify requested original as image"
    );
    task.abort();
}

fn short_wav() -> Vec<u8> {
    let data = vec![0u8; 3200];
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36u32 + data.len() as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&16000u32.to_le_bytes());
    wav.extend_from_slice(&32000u32.to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
    wav.extend_from_slice(&data);
    wav
}

#[tokio::test]
#[ignore = "requires a real ffmpeg with libopus; run explicitly on the demo build/runtime host"]
async fn native_audio_is_converted_and_sent_after_at_most_three_images() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (origin, task) = provider(state.clone()).await;
    let wav = short_wav();
    let app = Router::new().route(
        "/api/web/media/voice_one",
        get(move |headers: axum::http::HeaderMap| {
            let bytes = wav.clone();
            async move {
                assert_eq!(headers.get("Authorization").unwrap(), "Bearer shortcap");
                ([("content-type", "audio/wav")], bytes)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let beacon = format!("http://{}", listener.local_addr().unwrap());
    let media_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let cfg = config(temp.path(), &origin);
    let ffmpeg = std::env::var("HARBORGATE_TEST_FFMPEG").unwrap_or_else(|_| "ffmpeg".into());
    let adapter = FeishuAdapter::with_media(
        cfg.feishu,
        temp.path().join("out"),
        ffmpeg.into(),
        beacon.clone(),
    );
    let image = temp.path().join("image.jpg");
    std::fs::write(&image, b"image").unwrap();
    let mut attachments = vec![
        json!({"kind":"audio","artifact_id":"voice_one","mime_type":"audio/wav","url":format!("{beacon}/api/web/media/voice_one"),
        "metadata":{"duration_ms":100,"download":{"url":format!("{beacon}/api/web/media/voice_one"),"method":"GET",
            "headers":{"Authorization":"Bearer shortcap"},"expires_at":(chrono::Utc::now()+chrono::Duration::minutes(10)).to_rfc3339(),"max_size_bytes":33554432}}}),
    ];
    for _ in 0..4 {
        attachments.push(json!({"kind":"image","path":image,"mime_type":"image/jpeg"}));
    }
    let result = adapter
        .send_outbound(outbound(attachments, "turn_audio"))
        .await
        .unwrap();
    assert_eq!(result["sent"], true);
    assert_eq!(result["metadata"]["native_audio_reply"], true);
    let kinds = state
        .messages
        .lock()
        .unwrap()
        .iter()
        .map(|m| m["msg_type"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(kinds, vec!["text", "image", "image", "image", "audio"]);
    let files = state.files.lock().unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].windows(8).any(|b| b == b"OpusHead"));
    assert!(!files[0].windows(4).any(|b| b == b"RIFF"));
    task.abort();
    media_task.abort();
}

#[tokio::test]
async fn restart_pending_audio_replays_identical_turn_to_refresh_expired_capability() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (origin, task) = provider(state.clone()).await;
    let mut cfg = config(temp.path(), &origin);
    cfg.harborbeacon_base_url = origin.clone();
    let gateway = GatewayService::from_config(&cfg).unwrap();
    let request = event("text", "om_expired", json!({"text":"retry expired audio"}));
    let initial = gateway
        .handle_inbound("feishu", request.clone())
        .await
        .unwrap();
    assert_eq!(initial["partial"], true);
    drop(gateway);
    let restarted = GatewayService::from_config(&cfg).unwrap();
    // Provider deliberately has no media route. The renewed descriptor reaches HTTP,
    // then remains partial; no caption is resent and the business request is unchanged.
    let retried = restarted.handle_inbound("feishu", request).await.unwrap();
    assert_eq!(retried["partial"], true);
    let turns = state.turns.lock().unwrap();
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0], turns[1]);
    assert_eq!(
        state
            .messages
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["content"].as_str().unwrap().contains("cached answer"))
            .count(),
        1
    );
    let records: Value =
        serde_json::from_slice(&std::fs::read(cfg.data_dir.join("_inbound.json")).unwrap())
            .unwrap();
    let record = records.as_object().unwrap().values().next().unwrap();
    assert!(record["prepared"].is_object() && record["session_metadata"].is_object());
    let expiry = record["outbound"]["attachments"][0]["metadata"]["download"]["expires_at"]
        .as_str()
        .unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(expiry).unwrap() > chrono::Utc::now());
    task.abort();
}

#[tokio::test]
#[ignore = "requires a real ffmpeg with libopus; run explicitly on the demo build/runtime host"]
async fn inbound_opus_is_normalized_to_mono_16k_pcm_wav() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.wav");
    let opus = temp.path().join("source.opus");
    std::fs::write(&source, short_wav()).unwrap();
    let ffmpeg = std::env::var("HARBORGATE_TEST_FFMPEG").unwrap_or_else(|_| "ffmpeg".into());
    harborgate::media::convert_to_opus(std::path::Path::new(&ffmpeg), &source, &opus)
        .await
        .unwrap();
    let encoded = std::fs::read(&opus).unwrap();
    assert!(encoded.windows(8).any(|b| b == b"OpusHead"));
    let (wav, duration) = harborgate::media::normalize_inbound_audio(
        std::path::Path::new(&ffmpeg),
        temp.path(),
        &encoded,
    )
    .await
    .unwrap();
    assert_eq!(harborgate::media::pcm_wav_duration_ms(&wav), Some(duration));
    assert!(duration >= 90 && duration <= 110);
    assert!(wav.starts_with(b"RIFF"));
}

#[tokio::test]
async fn preview_delivery_does_not_consume_a_message_before_live_send_is_enabled() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (origin, task) = provider(state.clone()).await;
    let mut cfg = config(temp.path(), &origin);
    cfg.feishu.enable_live_send = false;
    let payload = event("text", "om_before_live", json!({"text":"hello"}));
    let preview = GatewayService::from_config(&cfg)
        .unwrap()
        .handle_inbound("feishu", payload.clone())
        .await
        .unwrap();
    assert_eq!(preview["sent"], false);
    assert!(state.messages.lock().unwrap().is_empty());
    cfg.feishu.enable_live_send = true;
    let actual = GatewayService::from_config(&cfg)
        .unwrap()
        .handle_inbound("feishu", payload)
        .await
        .unwrap();
    assert_eq!(actual["sent"], true);
    assert_eq!(state.messages.lock().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn notification_http_reports_partial_and_retry_only_sends_missing_part() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (origin, task) = provider(state.clone()).await;
    let mut cfg = config(temp.path(), &origin);
    cfg.service_token = "mock_internal_token".into();
    cfg.contract_version = "2.0".into();
    let gateway = Arc::new(GatewayService::from_config(&cfg).unwrap());
    gateway
        .handle_inbound(
            "feishu",
            event("text", "om_notify_route", json!({"text":"register route"})),
        )
        .await
        .unwrap();
    state.messages.lock().unwrap().clear();
    state.fail_image_once.store(true, Ordering::SeqCst);
    let routes: Value =
        serde_json::from_slice(&std::fs::read(cfg.data_dir.join("_routes.json")).unwrap()).unwrap();
    let route = routes.as_object().unwrap().keys().next().unwrap();
    let image = temp.path().join("notification.jpg");
    std::fs::write(&image, b"mock image").unwrap();
    let payload = json!({"notification":{"notification_id":"notif_ready","trace_id":"trace_ready","event_type":"demo.ready"},
        "conversation":{"handle":"conv_opaque"},"destination":{"route_key":route},"reply":{"kind":"tool_result","text":"Ready notification"},
        "artifacts":[{"kind":"image","artifact_id":"photo_1","mime_type":"image/jpeg","path":image}],
        "delivery_hints":[{"kind":"native_image","metadata":{"max_items":3}}],
        "delivery":{"mode":"send","idempotency_key":"idem_ready","reply_to_message_id":null,"update_message_id":null}});
    let appstate = harborgate::server::AppState {
        config: cfg.clone(),
        gateway: gateway.clone(),
        setup: Arc::new(harborgate::setup::SetupPortalService::new(cfg, gateway)),
        feishu_websocket_started: Arc::new(AtomicBool::new(false)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!(
        "http://{}/api/notifications/deliveries",
        listener.local_addr().unwrap()
    );
    let api_task = tokio::spawn(async move {
        axum::serve(listener, harborgate::server::router(appstate))
            .await
            .unwrap();
    });
    let http = reqwest::Client::new();
    let first: Value = http
        .post(&api)
        .header("X-Contract-Version", "2.0")
        .bearer_auth("mock_internal_token")
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["ok"], false);
    assert_eq!(first["sent"], false);
    assert_eq!(first["partial"], true);
    assert_eq!(first["status"], "partial");
    assert_eq!(first["retryable"], true);
    let second: Value = http
        .post(&api)
        .header("X-Contract-Version", "2.0")
        .bearer_auth("mock_internal_token")
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second["ok"], true);
    assert_eq!(second["sent"], true);
    assert_eq!(second["partial"], false);
    assert_eq!(second["delivery_receipts"][0]["artifact_id"], "photo_1");
    let count = state.messages.lock().unwrap().len();
    let replay: Value = http
        .post(&api)
        .header("X-Contract-Version", "2.0")
        .bearer_auth("mock_internal_token")
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay, second);
    assert_eq!(state.messages.lock().unwrap().len(), count);
    let messages = state.messages.lock().unwrap();
    assert_eq!(
        messages
            .iter()
            .filter(|m| m["content"]
                .as_str()
                .unwrap()
                .contains("Ready notification"))
            .count(),
        1
    );
    assert_eq!(
        messages.iter().filter(|m| m["msg_type"] == "image").count(),
        2
    );
    task.abort();
    api_task.abort();
}
