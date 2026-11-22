use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    routing::{get, post},
    Json, Router,
};
use harborgate::{
    adapters::{feishu::FeishuAdapter, PlatformAdapter},
    config::AppConfig,
    gateway::GatewayService,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Cursor,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

struct Mock {
    bytes: Vec<u8>,
    resource_requests: AtomicUsize,
    turns: Mutex<Vec<Value>>,
    notices: Mutex<Vec<Value>>,
    fail_turns: AtomicUsize,
    response_mode: &'static str,
}

fn picture(format: image::ImageFormat) -> Vec<u8> {
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(3, 2, image::Rgb([12, 87, 204])))
        .write_to(&mut encoded, format)
        .unwrap();
    encoded.into_inner()
}

async fn resource(
    State(state): State<Arc<Mock>>,
    Path((message, key)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    assert_eq!(headers["authorization"], "Bearer provider-secret");
    assert_eq!(query["type"], "image");
    assert!(message.starts_with("om_"));
    assert_eq!(key, "image-key");
    state.resource_requests.fetch_add(1, Ordering::SeqCst);
    let builder = Response::builder();
    if message == "om_first" {
        return builder
            .header("content-type", "image/png")
            .body(Body::from(picture(image::ImageFormat::Png)))
            .unwrap();
    }
    match state.response_mode {
        "forbidden" => builder
            .status(403)
            .body(Body::from("provider-secret denied"))
            .unwrap(),
        "json" => builder
            .header("content-type", "application/json")
            .body(Body::from(r#"{"code":999,"msg":"provider-secret denied"}"#))
            .unwrap(),
        "redirect" => builder
            .status(302)
            .header("location", "/must-not-follow")
            .body(Body::empty())
            .unwrap(),
        "oversize" => builder
            .header(
                "content-length",
                (harborgate::media::MAX_MEDIA_BYTES + 1).to_string(),
            )
            .body(Body::from(vec![0; harborgate::media::MAX_MEDIA_BYTES + 1]))
            .unwrap(),
        "chunked_oversize" => builder
            .body(Body::from_stream(futures_util::stream::iter([
                Ok::<_, std::io::Error>(bytes::Bytes::from(vec![
                    0;
                    harborgate::media::MAX_MEDIA_BYTES
                ])),
                Ok(bytes::Bytes::from_static(&[1])),
            ])))
            .unwrap(),
        "timeout" => {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            builder.body(Body::from(state.bytes.clone())).unwrap()
        }
        // Deliberately incorrect MIME: descriptor must reflect the image bytes.
        _ => builder
            .header("content-type", "application/octet-stream")
            .body(Body::from(state.bytes.clone()))
            .unwrap(),
    }
}

async fn turn(
    State(state): State<Arc<Mock>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["x-contract-version"], "2.0");
    assert!(!body.to_string().contains("provider-secret"));
    assert!(!body.to_string().contains("image-key"));
    state.turns.lock().unwrap().push(body.clone());
    if state
        .fail_turns
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"controlled Beacon outage"})),
        );
    }
    let failed_image = body
        .pointer("/input/parts/0/metadata/media_error")
        .is_some();
    (
        StatusCode::OK,
        Json(json!({
            "turn":{"turn_id":body["turn"]["turn_id"],"trace_id":body["turn"]["trace_id"],"status":if failed_image { "failed" } else { "completed" }},
            "conversation":{"handle":"conv_image"},
            "reply":{"kind":"conversation","text":if failed_image { "请重新发送有效的 JPEG 或 PNG" } else { "Image received" }},"artifacts":[],"delivery_hints":[]
        })),
    )
}

async fn provider(state: Arc<Mock>) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/open-apis/auth/v3/tenant_access_token/internal",
            post(|| async {
                Json(json!({"code":0,"tenant_access_token":"provider-secret","expire":7200}))
            }),
        )
        .route(
            "/open-apis/im/v1/messages/{message}/resources/{key}",
            get(resource),
        )
        .route(
            "/must-not-follow",
            get(|| async {
                panic!("provider redirect was followed");
                #[allow(unreachable_code)]
                ""
            }),
        )
        .route(
            "/open-apis/im/v1/messages",
            post(
                |State(state): State<Arc<Mock>>, Json(body): Json<Value>| async move {
                    state.notices.lock().unwrap().push(body);
                    Json(json!({"code":0,"data":{"message_id":"om_reply"}}))
                },
            ),
        )
        .route("/api/web/turns", post(turn))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (origin, task)
}

fn config(root: &std::path::Path, origin: &str) -> AppConfig {
    let mut cfg = AppConfig::from_env();
    cfg.data_dir = root.join("sessions");
    cfg.state_dir = root.join("state");
    cfg.harborbeacon_base_url = origin.into();
    cfg.feishu.base_url = origin.into();
    cfg.feishu.auth_base_url = origin.into();
    cfg.feishu.app_id = "mock_app".into();
    cfg.feishu.app_secret = "mock_app_secret".into();
    cfg.feishu.enable_live_send = true;
    cfg.feishu.allowed_users.clear();
    cfg.feishu.verification_token.clear();
    cfg
}

fn event(message: &str, key: &str) -> Value {
    json!({"header":{"event_type":"im.message.receive_v1"},"event":{
        "sender":{"sender_id":{"open_id":"ou_user"}},
        "message":{"chat_id":"oc_chat","chat_type":"p2p","message_id":message,"message_type":"image",
            "content":json!({"image_key":key}).to_string()}}})
}

#[tokio::test]
async fn jpeg_and_png_reach_v2_with_original_bytes_and_stable_capability_after_restart() {
    for (format, mime) in [
        (image::ImageFormat::Jpeg, "image/jpeg"),
        (image::ImageFormat::Png, "image/png"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state = Arc::new(Mock {
            bytes: picture(format),
            resource_requests: AtomicUsize::new(0),
            turns: Mutex::new(vec![]),
            notices: Mutex::new(vec![]),
            fail_turns: AtomicUsize::new(0),
            response_mode: "image",
        });
        let (origin, provider_task) = provider(state.clone()).await;
        let mut cfg = config(temp.path(), &origin);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.port = listener.local_addr().unwrap().port();
        let gateway = Arc::new(GatewayService::from_config(&cfg).unwrap());
        let app_state = harborgate::server::AppState {
            config: cfg.clone(),
            gateway: gateway.clone(),
            setup: Arc::new(harborgate::setup::SetupPortalService::new(
                cfg.clone(),
                gateway.clone(),
            )),
            feishu_websocket_started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let media_task = tokio::spawn(async move {
            axum::serve(listener, harborgate::server::router(app_state))
                .await
                .unwrap();
        });
        let request = event("om_image", "image-key");
        let (first, duplicate) = tokio::join!(
            gateway.handle_inbound("feishu", request.clone()),
            gateway.handle_inbound("feishu", request.clone())
        );
        assert!(first.unwrap()["sent"].as_bool().unwrap());
        assert!(duplicate.unwrap()["sent"].as_bool().unwrap());
        let bodies = state.turns.lock().unwrap().clone();
        assert_eq!(bodies.len(), 1);
        assert_eq!(state.resource_requests.load(Ordering::SeqCst), 1);
        assert_eq!(bodies[0]["input"]["text"], "");
        let part = &bodies[0]["input"]["parts"][0];
        assert_eq!(part["type"], "image");
        assert_eq!(part["mime_type"], mime);
        assert_eq!(part["size_bytes"], state.bytes.len());
        assert_eq!(
            part["metadata"]["sha256"],
            format!("{:x}", Sha256::digest(&state.bytes))
        );
        assert_eq!(part["metadata"]["width"], 3);
        assert_eq!(part["metadata"]["height"], 2);
        assert_eq!(part["metadata"]["source_message_id"], "om_image");
        let http = reqwest::Client::new();
        let url = part["download"]["url"].as_str().unwrap();
        assert_eq!(
            http.get(url).send().await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let authorization = part["download"]["headers"]["Authorization"]
            .as_str()
            .unwrap();
        let fetched = http
            .get(url)
            .header("Authorization", authorization)
            .send()
            .await
            .unwrap();
        assert_eq!(fetched.headers()["content-type"], mime);
        assert_eq!(fetched.headers()["cache-control"], "no-store");
        assert_eq!(fetched.bytes().await.unwrap().as_ref(), state.bytes);
        let restarted = GatewayService::from_config(&cfg).unwrap();
        restarted.handle_inbound("feishu", request).await.unwrap();
        assert_eq!(state.resource_requests.load(Ordering::SeqCst), 1);
        assert_eq!(state.turns.lock().unwrap().len(), 1);
        assert_eq!(
            restarted
                .read_media(part["attachment_id"].as_str().unwrap(), authorization)
                .unwrap()
                .1,
            state.bytes
        );
        media_task.abort();
        provider_task.abort();
    }
}

#[tokio::test]
async fn pending_image_retry_keeps_identical_turn_and_does_not_renew_expired_capability() {
    let temp = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock {
        bytes: picture(image::ImageFormat::Png),
        resource_requests: AtomicUsize::new(0),
        turns: Mutex::new(vec![]),
        notices: Mutex::new(vec![]),
        fail_turns: AtomicUsize::new(1),
        response_mode: "image",
    });
    let (origin, task) = provider(state.clone()).await;
    let cfg = config(temp.path(), &origin);
    let request = event("om_retry", "image-key");
    assert!(GatewayService::from_config(&cfg)
        .unwrap()
        .handle_inbound("feishu", request.clone())
        .await
        .is_err());
    let first = state.turns.lock().unwrap()[0].clone();
    let part = &first["input"]["parts"][0];
    let id = part["attachment_id"].as_str().unwrap();
    let manifest = cfg
        .state_dir
        .join("media-inbound")
        .join(format!("{id}.json"));
    let mut entry: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    entry["expires_at"] = json!((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339());
    std::fs::write(&manifest, serde_json::to_vec(&entry).unwrap()).unwrap();
    let restarted = GatewayService::from_config(&cfg).unwrap();
    assert!(restarted
        .read_media(
            id,
            part["download"]["headers"]["Authorization"]
                .as_str()
                .unwrap()
        )
        .is_err());
    restarted.handle_inbound("feishu", request).await.unwrap();
    assert_eq!(state.turns.lock().unwrap()[1], first);
    assert_eq!(state.resource_requests.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn provider_denial_error_documents_redirects_size_and_timeout_are_rejected_without_secrets() {
    for mode in [
        "forbidden",
        "json",
        "redirect",
        "oversize",
        "chunked_oversize",
        "timeout",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state = Arc::new(Mock {
            bytes: picture(image::ImageFormat::Png),
            resource_requests: AtomicUsize::new(0),
            turns: Mutex::new(vec![]),
            notices: Mutex::new(vec![]),
            fail_turns: AtomicUsize::new(0),
            response_mode: mode,
        });
        let (origin, task) = provider(state.clone()).await;
        let mut cfg = config(temp.path(), &origin);
        cfg.feishu.timeout_seconds = 1;
        let adapter = FeishuAdapter::new(cfg.feishu);
        let error = adapter
            .download_image("om_denied", "image-key")
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("provider-secret"));
        if mode.contains("oversize") {
            assert!(error.message.contains("32 MiB"), "{error}");
        }
        assert_eq!(state.resource_requests.load(Ordering::SeqCst), 1);
        task.abort();
    }
}

#[tokio::test]
async fn unsupported_or_corrupt_image_reaches_beacon_only_as_failure_after_sender_policy() {
    for bytes in [
        b"GIF89a-not-supported".to_vec(),
        b"\x89PNG\r\n\x1a\ntruncated".to_vec(),
        vec![],
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state = Arc::new(Mock {
            bytes,
            resource_requests: AtomicUsize::new(0),
            turns: Mutex::new(vec![]),
            notices: Mutex::new(vec![]),
            fail_turns: AtomicUsize::new(0),
            response_mode: "image",
        });
        let (origin, task) = provider(state.clone()).await;
        let mut cfg = config(temp.path(), &origin);
        cfg.feishu.allowed_users = vec!["ou_other".into()];
        assert!(GatewayService::from_config(&cfg)
            .unwrap()
            .handle_inbound("feishu", event("om_policy", "image-key"))
            .await
            .is_err());
        assert_eq!(state.resource_requests.load(Ordering::SeqCst), 0);
        cfg.feishu.allowed_users.clear();
        let gateway = GatewayService::from_config(&cfg).unwrap();
        gateway
            .handle_inbound("feishu", event("om_invalid", "image-key"))
            .await
            .unwrap();
        let turns = state.turns.lock().unwrap().clone();
        assert_eq!(turns.len(), 1);
        let part = &turns[0]["input"]["parts"][0];
        assert_eq!(part["type"], "image");
        assert_eq!(part["metadata"]["media_error"], "image_invalid");
        assert_eq!(part.as_object().unwrap().len(), 3);
        assert!(state
            .notices
            .lock()
            .unwrap()
            .iter()
            .any(|message| message["content"].as_str().unwrap_or("").contains("JPEG")));
        assert!(FeishuAdapter::new(cfg.feishu.clone())
            .normalize_inbound(event("om_bad", ""))
            .is_err());
        assert!(FeishuAdapter::new(cfg.feishu)
            .normalize_inbound(event("", "image-key"))
            .is_err());
        task.abort();
    }
}

#[tokio::test]
async fn rejected_new_photo_invalidates_the_old_image_via_one_stable_failed_turn() {
    for mode in [
        "image",
        "forbidden",
        "json",
        "redirect",
        "timeout",
        "oversize",
        "chunked_oversize",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state = Arc::new(Mock {
            bytes: b"not-an-image-provider-secret".to_vec(),
            resource_requests: AtomicUsize::new(0),
            turns: Mutex::new(vec![]),
            notices: Mutex::new(vec![]),
            fail_turns: AtomicUsize::new(0),
            response_mode: mode,
        });
        let (origin, task) = provider(state.clone()).await;
        let mut cfg = config(temp.path(), &origin);
        cfg.feishu.timeout_seconds = 1;
        let gateway = GatewayService::from_config(&cfg).unwrap();
        gateway
            .handle_inbound("feishu", event("om_first", "image-key"))
            .await
            .unwrap();
        let second = event("om_replacement", "image-key");
        let (first, duplicate) = tokio::join!(
            gateway.handle_inbound("feishu", second.clone()),
            gateway.handle_inbound("feishu", second.clone())
        );
        assert!(first.is_ok() && duplicate.is_ok());
        let restarted = GatewayService::from_config(&cfg).unwrap();
        restarted.handle_inbound("feishu", second).await.unwrap();
        assert_eq!(state.resource_requests.load(Ordering::SeqCst), 2, "{mode}");
        let turns = state.turns.lock().unwrap();
        assert_eq!(
            turns.len(),
            2,
            "{mode}: repeated failed photo cannot execute another turn"
        );
        assert!(turns[0]["input"]["parts"][0]["download"].is_object());
        let failed = &turns[1]["input"]["parts"][0];
        assert_eq!(failed["type"], "image");
        assert_eq!(failed.as_object().unwrap().len(), 3);
        assert_eq!(failed["metadata"].as_object().unwrap().len(), 1);
        let expected = match mode {
            "image" => "image_invalid",
            "oversize" | "chunked_oversize" => "image_too_large",
            _ => "image_download_failed",
        };
        assert_eq!(failed["metadata"]["media_error"], expected);
        assert_ne!(turns[0]["turn"]["turn_id"], turns[1]["turn"]["turn_id"]);
        let attachment_id = failed["attachment_id"].as_str().unwrap();
        assert!(!cfg
            .state_dir
            .join("media-inbound")
            .join(format!("{attachment_id}.json"))
            .exists());
        assert!(restarted.read_media(attachment_id, "Bearer any").is_err());
        task.abort();
    }
}
