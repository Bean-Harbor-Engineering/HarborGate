use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use harborgate::{config::AppConfig, gateway::GatewayService};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};

const ACK: &str = "收到，正在处理…";
const FAILED: &str = "本次处理暂未完成，请稍后重试。";

struct Mock {
    started: Instant,
    messages: Mutex<Vec<(u128, Value)>>,
    turns: Mutex<Vec<Value>>,
    changed: Notify,
    release: Semaphore,
    ack_fails: AtomicBool,
    business_fails: AtomicBool,
    delay_ack: AtomicBool,
    audio_downloads: Mutex<Vec<u128>>,
}
impl Default for Mock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            messages: Mutex::new(Vec::new()),
            turns: Mutex::new(Vec::new()),
            changed: Notify::new(),
            release: Semaphore::new(0),
            ack_fails: AtomicBool::new(false),
            business_fails: AtomicBool::new(false),
            delay_ack: AtomicBool::new(false),
            audio_downloads: Mutex::new(Vec::new()),
        }
    }
}
fn message_text(body: &Value) -> String {
    serde_json::from_str::<Value>(body["content"].as_str().unwrap_or("{}"))
        .ok()
        .and_then(|body| body["text"].as_str().map(str::to_string))
        .unwrap_or_default()
}
async fn message(State(state): State<Arc<Mock>>, Json(body): Json<Value>) -> Json<Value> {
    let fail = message_text(&body) == ACK && state.ack_fails.load(Ordering::SeqCst);
    let (count, is_ack) = {
        let mut messages = state.messages.lock().unwrap();
        let is_ack = message_text(&body) == ACK;
        messages.push((state.started.elapsed().as_millis(), body));
        (messages.len(), is_ack)
    };
    state.changed.notify_waiters();
    if state.delay_ack.load(Ordering::SeqCst) && is_ack {
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    Json(if fail {
        json!({"code":1,"msg":"controlled ack failure"})
    } else {
        json!({"code":0,"data":{"message_id":format!("mock_{count}")}})
    })
}
async fn audio_resource(State(state): State<Arc<Mock>>) -> (StatusCode, &'static str) {
    state
        .audio_downloads
        .lock()
        .unwrap()
        .push(state.started.elapsed().as_millis());
    (
        StatusCode::GATEWAY_TIMEOUT,
        "controlled audio download timeout",
    )
}
async fn token() -> Json<Value> {
    Json(json!({"code":0,"tenant_access_token":"mock-token","expire":7200}))
}
async fn turn(
    State(state): State<Arc<Mock>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state.turns.lock().unwrap().push(body.clone());
    state.changed.notify_waiters();
    state.release.acquire().await.unwrap().forget();
    if state.business_fails.load(Ordering::SeqCst) {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({"error":{"code":"TIMEOUT","message":"controlled timeout"}})),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({"turn":{"turn_id":body["turn"]["turn_id"],"trace_id":body["turn"]["trace_id"],"status":"completed"},"conversation":{"handle":"conv_mock"},"reply":{"kind":"tool_result","text":"Actual completed result"},"artifacts":[],"delivery_hints":[]}),
        ),
    )
}
async fn setup(
    root: &std::path::Path,
    state: Arc<Mock>,
) -> (AppConfig, Arc<GatewayService>, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/web/turns", post(turn))
        .route(
            "/open-apis/auth/v3/tenant_access_token/internal",
            post(token),
        )
        .route("/open-apis/im/v1/messages", post(message))
        .route(
            "/open-apis/im/v1/messages/{message}/resources/{key}",
            axum::routing::get(audio_resource),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let worker = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut config = AppConfig::from_env();
    config.data_dir = root.join("sessions");
    config.state_dir = root.join("state");
    config.harborbeacon_base_url = origin.clone();
    config.harborbeacon_token = "mock-beacon-token-for-formal-transport".into();
    config.harborbeacon_token = "mock-beacon-token-for-formal-transport".into();
    config.feishu.base_url = origin.clone();
    config.feishu.auth_base_url = origin;
    config.feishu.app_id = "mock-app".into();
    config.feishu.app_secret = "mock-secret".into();
    config.feishu.enable_live_send = true;
    config.feishu.verification_token.clear();
    config.feishu.allowed_users.clear();
    let gateway = Arc::new(GatewayService::from_config(&config).unwrap());
    (config, gateway, worker)
}
fn event(id: &str, text: &str) -> Value {
    json!({"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"mock-user"}},"message":{"chat_id":"mock-chat","chat_type":"p2p","message_id":id,"message_type":"text","content":json!({"text":text}).to_string()}}})
}
async fn wait_for(_state: &Mock, condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_millis(900), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await
        }
    })
    .await
    .expect("Transport acknowledgement must precede slow processing");
}
#[tokio::test]
async fn processing_ack_precedes_business_and_replay_restart_do_not_duplicate_it() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (config, gateway, worker) = setup(root.path(), state.clone()).await;
    let payload = event("slow-1", "请找几张海边的照片");
    let task = {
        let gateway = gateway.clone();
        let payload = payload.clone();
        tokio::spawn(async move { gateway.handle_inbound("feishu", payload).await })
    };
    wait_for(&state, || {
        state
            .messages
            .lock()
            .unwrap()
            .iter()
            .any(|(_, body)| message_text(body) == ACK)
    })
    .await;
    assert!(!task.is_finished());
    let ack = state.messages.lock().unwrap()[0].clone();
    assert!(ack.0 < 900);
    assert!(ack.1["uuid"].as_str().is_some());
    let concurrent_retry = {
        let gateway = gateway.clone();
        let payload = payload.clone();
        tokio::spawn(async move { gateway.handle_inbound("feishu", payload).await })
    };
    state.release.add_permits(1);
    assert!(task.await.unwrap().unwrap()["sent"].as_bool().unwrap());
    concurrent_retry.await.unwrap().unwrap();
    gateway
        .handle_inbound("feishu", payload.clone())
        .await
        .unwrap();
    drop(gateway);
    GatewayService::from_config(&config)
        .unwrap()
        .handle_inbound("feishu", payload)
        .await
        .unwrap();
    let messages = state.messages.lock().unwrap();
    assert_eq!(
        messages
            .iter()
            .filter(|(_, m)| message_text(m) == ACK)
            .count(),
        1
    );
    assert_eq!(
        messages
            .iter()
            .filter(|(_, m)| message_text(m) == "Actual completed result")
            .count(),
        1
    );
    assert_ne!(messages[0].1["uuid"], messages[1].1["uuid"]);
    assert_eq!(state.turns.lock().unwrap().len(), 1);
    worker.abort();
}
#[tokio::test]
async fn a_queued_request_ack_does_not_wait_for_the_previous_business_turn() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (_, gateway, worker) = setup(root.path(), state.clone()).await;
    let first = {
        let gateway = gateway.clone();
        tokio::spawn(async move {
            gateway
                .handle_inbound("feishu", event("queued-1", "查找备份恢复文档"))
                .await
        })
    };
    wait_for(&state, || state.turns.lock().unwrap().len() == 1).await;
    let second = {
        let gateway = gateway.clone();
        tokio::spawn(async move {
            gateway
                .handle_inbound("feishu", event("queued-2", "帮我找有狗的照片"))
                .await
        })
    };
    wait_for(&state, || {
        state
            .messages
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m)| message_text(m) == ACK)
            .count()
            == 2
    })
    .await;
    assert_eq!(state.turns.lock().unwrap().len(), 1);
    state.release.add_permits(2);
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    worker.abort();
}
#[tokio::test]
async fn ack_failure_does_not_block_the_real_result_and_business_timeout_is_visible_once() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    state.ack_fails.store(true, Ordering::SeqCst);
    state.release.add_permits(1);
    let (_, gateway, worker) = setup(root.path(), state.clone()).await;
    assert!(gateway
        .handle_inbound("feishu", event("ack-fail", "根据资料回答并附上原文"))
        .await
        .unwrap()["sent"]
        .as_bool()
        .unwrap());
    assert_eq!(state.turns.lock().unwrap().len(), 1);
    state.ack_fails.store(false, Ordering::SeqCst);
    state.business_fails.store(true, Ordering::SeqCst);
    state.release.add_permits(1);
    let payload = event("business-timeout", "帮我查找资料");
    assert!(gateway
        .handle_inbound("feishu", payload.clone())
        .await
        .is_err());
    state.release.add_permits(1);
    assert!(gateway.handle_inbound("feishu", payload).await.is_err());
    let messages = state.messages.lock().unwrap();
    assert_eq!(
        messages
            .iter()
            .filter(|(_, m)| message_text(m) == FAILED)
            .count(),
        1
    );
    assert_eq!(
        messages
            .iter()
            .filter(|(_, m)| message_text(m) == "Actual completed result")
            .count(),
        1
    );
    worker.abort();
}

#[tokio::test]
async fn acknowledgement_timeout_is_bounded_and_does_not_block_business() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    state.delay_ack.store(true, Ordering::SeqCst);
    state.release.add_permits(1);
    let (_, gateway, worker) = setup(root.path(), state.clone()).await;
    let started = Instant::now();
    let payload = event("slow-ack", "请查找设备文档");
    assert_eq!(
        gateway
            .handle_inbound("feishu", payload.clone())
            .await
            .unwrap()["sent"],
        true
    );
    assert!(started.elapsed() < Duration::from_millis(1400));
    gateway.handle_inbound("feishu", payload).await.unwrap();
    assert_eq!(state.turns.lock().unwrap().len(), 1);
    assert_eq!(
        state
            .messages
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, body)| message_text(body) == ACK)
            .count(),
        1
    );
    worker.abort();
}

#[tokio::test]
async fn voice_is_acknowledged_before_platform_audio_download_starts() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(Mock::default());
    let (_, gateway, worker) = setup(root.path(), state.clone()).await;
    let mut payload = event("audio-ack", "");
    payload["event"]["message"]["message_type"] = json!("audio");
    payload["event"]["message"]["content"] = json!({"file_key":"mock-audio","duration":3000})
        .to_string()
        .into();
    assert!(gateway.handle_inbound("feishu", payload).await.is_err());
    let messages = state.messages.lock().unwrap();
    assert_eq!(message_text(&messages[0].1), ACK);
    assert!(messages[0].0 < 900);
    assert!(messages[0].0 <= state.audio_downloads.lock().unwrap()[0]);
    assert_eq!(message_text(&messages[1].1), FAILED);
    assert!(state.turns.lock().unwrap().is_empty());
    worker.abort();
}
