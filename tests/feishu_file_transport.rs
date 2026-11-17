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
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const FILE: &[u8] = b"%PDF-1.4\nopaque-document-bytes\n%%EOF\n";

struct Mock {
    resources: AtomicUsize,
    turns: Mutex<Vec<Value>>,
    fail_turns: AtomicUsize,
    mode: &'static str,
}

impl Mock {
    fn new(mode: &'static str) -> Arc<Self> {
        Arc::new(Self {
            resources: AtomicUsize::new(0),
            turns: Mutex::new(vec![]),
            fail_turns: AtomicUsize::new(0),
            mode,
        })
    }
}

async fn resource(
    State(state): State<Arc<Mock>>,
    Path((message, key)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    assert_eq!(headers["authorization"], "Bearer provider-secret");
    assert_eq!(query["type"], "file");
    assert_eq!(key, "file-key");
    state.resources.fetch_add(1, Ordering::SeqCst);
    let builder = Response::builder();
    if message == "om_first" {
        return builder
            .header("content-type", "application/pdf")
            .body(Body::from(FILE))
            .unwrap();
    }
    match state.mode {
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
        "empty" => builder.body(Body::empty()).unwrap(),
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
            builder.body(Body::from(FILE)).unwrap()
        }
        // Deliberately opaque invalid PDF: parsing and format validation belong to Beacon.
        "opaque" => builder
            .header("content-type", "application/pdf")
            .body(Body::from("not-a-pdf"))
            .unwrap(),
        "pdf" => builder
            .header("content-type", "application/pdf")
            .body(Body::from(FILE))
            .unwrap(),
        _ => builder.body(Body::from(FILE)).unwrap(),
    }
}

async fn turn(
    State(state): State<Arc<Mock>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["x-contract-version"], "2.0");
    assert!(!body.to_string().contains("provider-secret"));
    assert!(!body.to_string().contains("file-key"));
    state.turns.lock().unwrap().push(body.clone());
    if state
        .fail_turns
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"controlled outage"})),
        );
    }
    let failed = body
        .pointer("/input/parts/0/metadata/media_error")
        .is_some();
    (
        StatusCode::OK,
        Json(json!({
            "turn":{"turn_id":body["turn"]["turn_id"],"trace_id":body["turn"]["trace_id"],"status":if failed {"failed"} else {"completed"}},
            "conversation":{"handle":"conv_document"},
            "reply":{"kind":"conversation","text":if failed {"请重新发送文档"} else {"Document received"}},
            "artifacts":[],"delivery_hints":[]
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
            post(|| async { Json(json!({"code":0,"data":{"message_id":"om_reply"}})) }),
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
    cfg.port = 8787;
    cfg.harborbeacon_base_url = origin.into();
    cfg.harborbeacon_turn_endpoint = "/api/web/turns".into();
    cfg.feishu.base_url = origin.into();
    cfg.feishu.auth_base_url = origin.into();
    cfg.feishu.app_id = "cli_test".into();
    cfg.feishu.app_secret = "test-secret".into();
    cfg.feishu.enable_live_send = true;
    cfg.feishu.allowed_users.clear();
    cfg.feishu.verification_token.clear();
    cfg
}

fn event(message: &str, key: &str) -> Value {
    json!({"header":{"event_type":"im.message.receive_v1"},"event":{
        "sender":{"sender_id":{"open_id":"ou_user"}},
        "message":{"chat_id":"oc_chat","chat_type":"p2p","message_id":message,"message_type":"file",
            "content":json!({"file_key":key,"file_name":"../folder\\客户资料.pdf\r\n"}).to_string()}}})
}

#[tokio::test]
async fn files_reach_v2_as_original_bytes_and_stable_scoped_capabilities_after_restart() {
    for (mode, mime, expected) in [
        ("pdf", "application/pdf", FILE),
        ("missing_mime", "application/octet-stream", FILE),
        ("opaque", "application/pdf", b"not-a-pdf".as_slice()),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state = Mock::new(mode);
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
        let request = event("om_document", "file-key");
        let (first, duplicate) = tokio::join!(
            gateway.handle_inbound("feishu", request.clone()),
            gateway.handle_inbound("feishu", request.clone())
        );
        assert_eq!(first.unwrap()["sent"], true);
        assert_eq!(duplicate.unwrap()["sent"], true);
        let bodies = state.turns.lock().unwrap().clone();
        assert_eq!(bodies.len(), 1);
        assert_eq!(state.resources.load(Ordering::SeqCst), 1);
        assert_eq!(bodies[0]["input"]["text"], "");
        let part = &bodies[0]["input"]["parts"][0];
        assert_eq!(part["type"], "file");
        assert_eq!(part["name"], "客户资料.pdf");
        assert_eq!(part["mime_type"], mime);
        assert_eq!(part["size_bytes"], expected.len());
        assert_eq!(
            part["metadata"]["sha256"],
            format!("{:x}", Sha256::digest(expected))
        );
        assert_eq!(part["metadata"]["source_message_id"], "om_document");
        assert_eq!(part["metadata"]["provider"], "feishu");
        assert!(part["metadata"].get("duration_ms").is_none());
        let http = reqwest::Client::new();
        let url = part["download"]["url"].as_str().unwrap();
        assert_eq!(
            http.get(url).send().await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            http.get(url)
                .bearer_auth("wrong")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let auth = part["download"]["headers"]["Authorization"]
            .as_str()
            .unwrap();
        let fetched = http
            .get(url)
            .header("Authorization", auth)
            .send()
            .await
            .unwrap();
        assert_eq!(fetched.headers()["content-type"], mime);
        assert_eq!(fetched.headers()["cache-control"], "no-store");
        assert_eq!(fetched.bytes().await.unwrap().as_ref(), expected);
        let restarted = GatewayService::from_config(&cfg).unwrap();
        restarted.handle_inbound("feishu", request).await.unwrap();
        assert_eq!(state.resources.load(Ordering::SeqCst), 1);
        assert_eq!(state.turns.lock().unwrap().len(), 1);
        assert_eq!(
            restarted
                .read_media(part["attachment_id"].as_str().unwrap(), auth)
                .unwrap()
                .1,
            expected
        );
        assert!(restarted.read_media("att_other", auth).is_err());
        assert!(restarted.read_media("../document", auth).is_err());
        media_task.abort();
        provider_task.abort();
    }
}

#[tokio::test]
async fn file_sender_policy_and_malformed_resource_identity_prevent_downloads() {
    let temp = tempfile::tempdir().unwrap();
    let state = Mock::new("pdf");
    let (origin, task) = provider(state.clone()).await;
    let mut cfg = config(temp.path(), &origin);
    cfg.feishu.allowed_users = vec!["ou_other".into()];
    assert!(GatewayService::from_config(&cfg)
        .unwrap()
        .handle_inbound("feishu", event("om_denied", "file-key"))
        .await
        .is_err());
    cfg.feishu.allowed_users.clear();
    let gateway = GatewayService::from_config(&cfg).unwrap();
    for request in [event("om_invalid", ""), event("", "file-key")] {
        assert!(gateway
            .handle_inbound("feishu", request.clone())
            .await
            .is_err());
        assert!(FeishuAdapter::new(cfg.feishu.clone())
            .normalize_inbound(request)
            .is_err());
    }
    assert_eq!(state.resources.load(Ordering::SeqCst), 0);
    assert!(state.turns.lock().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn failed_new_file_reaches_beacon_without_download_or_secrets_once_across_retries() {
    for mode in [
        "forbidden",
        "json",
        "redirect",
        "empty",
        "oversize",
        "chunked_oversize",
        "timeout",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state = Mock::new(mode);
        let (origin, task) = provider(state.clone()).await;
        let mut cfg = config(temp.path(), &origin);
        cfg.feishu.timeout_seconds = 1;
        let gateway = GatewayService::from_config(&cfg).unwrap();
        gateway
            .handle_inbound("feishu", event("om_first", "file-key"))
            .await
            .unwrap();
        let replacement = event("om_replacement", "file-key");
        let (first, duplicate) = tokio::join!(
            gateway.handle_inbound("feishu", replacement.clone()),
            gateway.handle_inbound("feishu", replacement.clone())
        );
        assert!(first.is_ok() && duplicate.is_ok(), "{mode}");
        let restarted = GatewayService::from_config(&cfg).unwrap();
        restarted
            .handle_inbound("feishu", replacement)
            .await
            .unwrap();
        assert_eq!(state.resources.load(Ordering::SeqCst), 2, "{mode}");
        let bodies = state.turns.lock().unwrap();
        assert_eq!(bodies.len(), 2, "{mode}");
        assert!(bodies[0]["input"]["parts"][0]["download"].is_object());
        let failed = &bodies[1]["input"]["parts"][0];
        assert_eq!(failed["type"], "file");
        assert_eq!(failed.as_object().unwrap().len(), 3);
        assert_eq!(failed["metadata"].as_object().unwrap().len(), 1);
        assert_eq!(
            failed["metadata"]["media_error"],
            match mode {
                "empty" => "file_empty",
                "oversize" | "chunked_oversize" => "file_too_large",
                _ => "file_download_failed",
            }
        );
        assert_ne!(bodies[0]["turn"]["turn_id"], bodies[1]["turn"]["turn_id"]);
        let id = failed["attachment_id"].as_str().unwrap();
        assert!(!cfg
            .state_dir
            .join("media-inbound")
            .join(format!("{id}.json"))
            .exists());
        assert!(restarted.read_media(id, "Bearer anything").is_err());
        task.abort();
    }
}

#[tokio::test]
async fn pending_file_retry_preserves_turn_and_expired_capability() {
    let temp = tempfile::tempdir().unwrap();
    let state = Mock::new("pdf");
    state.fail_turns.store(1, Ordering::SeqCst);
    let (origin, task) = provider(state.clone()).await;
    let cfg = config(temp.path(), &origin);
    let request = event("om_retry", "file-key");
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
    std::fs::write(manifest, serde_json::to_vec(&entry).unwrap()).unwrap();
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
    assert_eq!(state.resources.load(Ordering::SeqCst), 1);
    task.abort();
}
