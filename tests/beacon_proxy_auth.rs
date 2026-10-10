use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::{Json, Router};
use harborgate::config::AppConfig;
use harborgate::device_session::DeviceSessionStore;
use harborgate::gateway::GatewayService;
use harborgate::harboros_auth::{HarborOsAuthFailure, HarborOsAuthenticator, HarborOsPrincipal};
use harborgate::server::{router, AppState};
use harborgate::setup::SetupPortalService;
use serde_json::json;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Clone)]
struct FakeAuthenticator {
    result: Result<HarborOsPrincipal, HarborOsAuthFailure>,
    tokens: Arc<Mutex<Vec<String>>>,
}

impl FakeAuthenticator {
    fn successful() -> Self {
        Self::new(Ok(HarborOsPrincipal {
            source: "harboros".to_string(),
            principal_id: "harboros:uid:42".to_string(),
            roles: vec!["FULL_ADMIN".to_string(), "SYSTEM_READ".to_string()],
            camera_scope: None,
        }))
    }

    fn new(result: Result<HarborOsPrincipal, HarborOsAuthFailure>) -> Self {
        Self {
            result,
            tokens: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn tokens(&self) -> Vec<String> {
        self.tokens.lock().await.clone()
    }
}

#[async_trait]
impl HarborOsAuthenticator for FakeAuthenticator {
    async fn authenticate(&self, token: &str) -> Result<HarborOsPrincipal, HarborOsAuthFailure> {
        self.tokens.lock().await.push(token.to_string());
        self.result.clone()
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Bytes,
}

async fn capture_request(
    State(captured): State<Arc<Mutex<Vec<CapturedRequest>>>>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let is_supported_control_request = matches!(&method, &Method::GET | &Method::PUT)
        && (uri.path().ends_with("/cat-detection/control")
            || uri.path().ends_with("/package-detection/control")
            || uri.path().ends_with("/package-detection/event-config"));
    captured.lock().await.push(CapturedRequest {
        method,
        path_and_query: uri.to_string(),
        headers,
        body,
    });
    if uri.path() == "/api/knowledge/preview" {
        let mut response =
            (StatusCode::PARTIAL_CONTENT, Bytes::from_static(b"clip")).into_response();
        response
            .headers_mut()
            .insert("content-type", "video/mp4".parse().unwrap());
        response
            .headers_mut()
            .insert("accept-ranges", "bytes".parse().unwrap());
        response
            .headers_mut()
            .insert("content-range", "bytes 10-13/100".parse().unwrap());
        response
            .headers_mut()
            .insert("content-length", "4".parse().unwrap());
        response
            .headers_mut()
            .insert("etag", "\"preview-v1\"".parse().unwrap());
        response.headers_mut().insert(
            "last-modified",
            "Sat, 02 Aug 2026 00:00:00 GMT".parse().unwrap(),
        );
        return response;
    }
    if is_supported_control_request {
        return (
            StatusCode::ACCEPTED,
            [("content-type", "application/json")],
            Bytes::from_static(br#"{"state":"accepted"}"#),
        )
            .into_response();
    }
    Json(json!({"ok": true})).into_response()
}

async fn mock_beacon() -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(capture_request))
        .with_state(captured.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), captured)
}

fn test_state(
    beacon_url: &str,
    beacon_web_api_token: &str,
    authenticator: Arc<dyn HarborOsAuthenticator>,
) -> (AppState, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = temp_dir.path().join("sessions");
    config.state_dir = temp_dir.path().join("state");
    config.harborbeacon_base_url = beacon_url.to_string();
    config.harborbeacon_token = "legacy-task-secret".to_string();
    config.harborbeacon_web_api_token = beacon_web_api_token.to_string();
    config.harbor_workspace_id = "home-1".to_string();
    config.enable_feishu_websocket = false;
    config.enable_weixin_runtime = false;
    let gateway = Arc::new(GatewayService::from_config(&config).unwrap());
    let state = AppState {
        config: config.clone(),
        setup: Arc::new(SetupPortalService::new(config.clone(), gateway.clone())),
        gateway,
        feishu_websocket_started: Arc::new(AtomicBool::new(false)),
        harboros_authenticator: authenticator,
        device_sessions: Arc::new(DeviceSessionStore::new(
            config.device_session_state_dir.clone(),
        )),
    };
    (state, temp_dir)
}

async fn response_body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn generic_message_routes_cannot_bypass_the_signed_whatsapp_webhook() {
    let (state, _directory) = test_state(
        "http://127.0.0.1:1",
        "fixture-token",
        Arc::new(FakeAuthenticator::successful()),
    );
    let app = router(state);
    for path in ["/messages/whatsapp", "/api/harbor-gate/messages/whatsapp"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"phone_number_id":"15555550100", "message":{"from":"15555550101",
                "id":"forged-proof", "timestamp":chrono::Utc::now().timestamp().to_string(),
                "text":{"body":format!("NAVI navi-a.{}", "a".repeat(64))}}})
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response_body(response)
            .await
            .contains("WHATSAPP_SIGNED_WEBHOOK_REQUIRED"));
    }
}

#[tokio::test]
async fn whatsapp_media_pull_requires_beacon_service_auth() {
    let (mut state, _directory) = test_state(
        "http://127.0.0.1:1",
        "fixture-token",
        Arc::new(FakeAuthenticator::successful()),
    );
    state.config.contract_version = "2.0".into();
    state.config.service_token = "beacon-to-gate-media-fixture-token-123456".into();
    let app = router(state);
    for path in [
        "/api/im/whatsapp/media/wa_image_aaaaaaaaaaaaaaaaaaaaaaaa",
        "/api/harbor-gate/api/im/whatsapp/media/wa_image_aaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("X-Contract-Version", "2.0")
            .header("X-Harbor-Route-Key", "gw_route_fixture")
            .header("X-Harbor-Hub-Id", "local")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response_body(response)
            .await
            .contains("SERVICE_AUTH_FAILED"));
    }
}

#[tokio::test]
async fn protected_prefixed_search_replaces_all_client_identity() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let request_body = r#"{"query":"front door"}"#;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/harbor-gate/api/beacon/knowledge/search?user_id=spoof&open_id=spoof&workspace_id=evil&limit=4")
        .header("content-type", "application/json")
        .header("authorization", "Bearer browser-controlled")
        .header("x-harboros-auth-token", "one-time-secret")
        .header("x-harbor-user-id", "spoof")
        .header("x-harbor-open-id", "spoof")
        .header("x-harboros-user", "spoof")
        .header("x-harbor-os-user", "spoof")
        .header("x-harbor-principal-source", "client")
        .header("x-harbor-principal-id", "client:spoof")
        .header("x-harbor-principal-roles", "SUPERUSER")
        .header("x-harbor-workspace-id", "evil")
        .body(Body::from(request_body))
        .unwrap();

    let response = router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-harbor-beacon-proxy-prefix")
            .unwrap(),
        "/api/harbor-gate/api/beacon"
    );
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.method, Method::POST);
    assert_eq!(upstream.path_and_query, "/api/knowledge/search?limit=4");
    assert_eq!(upstream.body, request_body);
    assert_eq!(
        upstream.headers.get("authorization").unwrap(),
        "Bearer beacon-service-secret"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-principal-source").unwrap(),
        "harboros"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-principal-id").unwrap(),
        "harboros:uid:42"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-principal-roles").unwrap(),
        "FULL_ADMIN,SYSTEM_READ"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-workspace-id").unwrap(),
        "home-1"
    );
    for name in [
        "x-harboros-auth-token",
        "x-harbor-user-id",
        "x-harbor-open-id",
        "x-harboros-user",
        "x-harbor-os-user",
    ] {
        assert!(upstream.headers.get(name).is_none(), "forwarded {name}");
    }
    drop(requests);
    assert_eq!(authenticator.tokens().await, vec!["one-time-secret"]);
}

#[tokio::test]
async fn every_proxy_alias_requires_authentication_for_conversation_json() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for path in [
        "/api/beacon/knowledge/conversations",
        "/api/harbor-gate/api/beacon/knowledge/conversations",
        "/api/harbor-assistant/knowledge/conversations",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }

    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn dlna_proxy_requires_authenticated_principal_on_every_alias() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for prefix in [
        "/api/beacon",
        "/api/harbor-gate/api/beacon",
        "/api/harbor-assistant",
    ] {
        for (method, suffix) in [
            (Method::GET, "/dlna/status"),
            (Method::GET, "/dlna/devices"),
            (Method::GET, "/dlna/catalog"),
            (Method::POST, "/dlna/grants"),
            (Method::POST, "/dlna/sessions"),
            (Method::POST, "/dlna/commands"),
            (Method::DELETE, "/dlna/catalog/object-1"),
        ] {
            let path = format!("{prefix}{suffix}");
            let request = Request::builder()
                .method(method.clone())
                .uri(&path)
                .header("content-type", "application/json")
                .header("authorization", "Bearer browser-controlled")
                .header("x-harbor-principal-id", "attacker")
                .body(Body::from("{}"))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
    }
    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/beacon/dlna/commands")
        .header("content-type", "application/json")
        .header("x-harboros-auth-token", "one-time-secret")
        .header("x-harbor-principal-id", "attacker")
        .header("x-harbor-workspace-id", "evil-home")
        .body(Body::from("{}"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.path_and_query, "/api/dlna/commands");
    assert_eq!(
        upstream.headers.get("x-harbor-principal-id").unwrap(),
        "harboros:uid:42"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-workspace-id").unwrap(),
        "home-1"
    );
    assert_eq!(
        upstream.headers.get("authorization").unwrap(),
        "Bearer beacon-service-secret"
    );
    assert!(upstream.headers.get("x-harboros-auth-token").is_none());
    assert_eq!(authenticator.tokens().await, vec!["one-time-secret"]);
}

#[tokio::test]
async fn observation_is_open_while_detection_job_control_requires_authentication() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for (method, path, expected_status) in [
        (
            Method::GET,
            "/api/beacon/cameras/camera-252/cat-detection/observation?stream_profile=sub",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/api/harbor-assistant/cameras/camera-252/cat-detection/observation?stream_profile=sub",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/api/harbor-gate/api/beacon/cameras/camera-252/cat-detection/observation?stream_profile=sub",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/api/beacon/vision/detection-jobs",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::PATCH,
            "/api/beacon/vision/detection-jobs/job-1/results/latest",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::GET,
            "/api/harbor-assistant/vision/detection-jobs",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::PATCH,
            "/api/harbor-assistant/vision/detection-jobs/job-1/results/latest",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::GET,
            "/api/harbor-gate/api/beacon/vision/detection-jobs",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::PATCH,
            "/api/harbor-gate/api/beacon/vision/detection-jobs/job-1/results/latest",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::POST,
            "/api/harbor-gate/api/beacon/vision/detection-jobs",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::GET,
            "/api/harbor-gate/api/beacon/vision/detection-jobs/job-1",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::POST,
            "/api/harbor-gate/api/beacon/vision/detection-jobs/job-1/renew",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::DELETE,
            "/api/harbor-gate/api/beacon/vision/detection-jobs/job-1",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status, "{path}");
    }

    assert_eq!(captured.lock().await.len(), 3);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn cat_detection_control_requires_harboros_principal_and_preserves_upstream_response() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let request_body = br#"{"enabled":true,"mode":"balanced"}"#;

    let control_paths = [
        "/api/beacon/cameras/camera%2F252/cat-detection/control",
        "/api/harbor-assistant/cameras/camera%2F252/cat-detection/control",
        "/api/harbor-gate/api/beacon/cameras/camera%2F252/cat-detection/control",
    ];

    for path in control_paths {
        for method in [Method::GET, Method::PUT] {
            let request = Request::builder()
                .method(method.clone())
                .uri(path)
                .header("content-type", "application/json")
                .header(
                    "x-harboros-auth-token",
                    format!("control-token-{method}-{path}"),
                )
                .body(if method == Method::PUT {
                    Body::from(Bytes::from_static(request_body))
                } else {
                    Body::empty()
                })
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED, "{method} {path}");
            assert_eq!(
                response_body(response).await,
                r#"{"state":"accepted"}"#,
                "{method} {path}"
            );
        }
    }

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 6);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(
            request.path_and_query,
            "/api/cameras/camera%2F252/cat-detection/control"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-id").unwrap(),
            "harboros:uid:42"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-roles").unwrap(),
            "FULL_ADMIN,SYSTEM_READ"
        );
        if index % 2 == 1 {
            assert_eq!(request.body, Bytes::from_static(request_body));
        } else {
            assert!(request.body.is_empty());
        }
    }
    drop(requests);
    assert_eq!(authenticator.tokens().await.len(), 6);
}

#[tokio::test]
async fn cat_detection_control_allows_anonymous_lan_get_and_put_without_session() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for method in [Method::GET, Method::PUT] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri("/api/beacon/cameras/camera-252/cat-detection/control")
                    .header("content-type", "application/json")
                    .body(if method == Method::PUT {
                        Body::from(r#"{"enabled":true,"stream_profile":"sub"}"#)
                    } else {
                        Body::empty()
                    })
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{method}");
        assert_eq!(response_body(response).await, r#"{"state":"accepted"}"#);
    }

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(
            request.headers.get("x-harbor-principal-source").unwrap(),
            "harbornavi-lan"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-id").unwrap(),
            "harbornavi-lan:anonymous"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-roles").unwrap(),
            "CAMERA_CONTROL"
        );
        assert_eq!(
            request.headers.get("x-harbor-camera-scope").unwrap(),
            "camera-252"
        );
    }
    drop(requests);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn package_detection_control_requires_harboros_principal_and_preserves_upstream_response() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for method in [Method::GET, Method::PUT] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri("/api/harbor-gate/api/beacon/cameras/camera-252/package-detection/control")
                    .header("content-type", "application/json")
                    .header("x-harboros-auth-token", format!("package-token-{method}"))
                    .body(if method == Method::PUT {
                        Body::from(r#"{"enabled":true,"stream_profile":"sub"}"#)
                    } else {
                        Body::empty()
                    })
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{method}");
    }

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(
            request.path_and_query,
            "/api/cameras/camera-252/package-detection/control"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-id").unwrap(),
            "harboros:uid:42"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-roles").unwrap(),
            "FULL_ADMIN,SYSTEM_READ"
        );
    }
    drop(requests);
    assert_eq!(authenticator.tokens().await.len(), 2);
}

#[tokio::test]
async fn package_event_config_requires_harboros_principal_and_preserves_body() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let body = r#"{"enabled":true,"zone":{"left":0.2,"top":0.2,"right":0.8,"bottom":0.8}}"#;
    let response = router(state)
        .oneshot(
            Request::put(
                "/api/harbor-gate/api/beacon/cameras/camera-252/package-detection/event-config",
            )
            .header("content-type", "application/json")
            .header("x-harboros-auth-token", "package-event-config-token")
            .body(Body::from(body))
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path_and_query,
        "/api/cameras/camera-252/package-detection/event-config"
    );
    assert_eq!(requests[0].body, Bytes::from(body));
    assert_eq!(
        requests[0].headers.get("x-harbor-principal-id").unwrap(),
        "harboros:uid:42"
    );
    assert!(requests[0].headers.get("x-harbor-camera-scope").is_none());
    drop(requests);
    assert_eq!(authenticator.tokens().await, ["package-event-config-token"]);
}

#[tokio::test]
async fn person_preview_forwards_body_and_camera_scoped_lan_principal() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator),
    );
    let body = r#"{"image_base64":"/9j/test","frame_id":42}"#;
    let response = router(state).oneshot(Request::post(
        "/api/harbor-gate/api/beacon/cameras/cam-rtsp-192-168-3-252/person-detection/preview")
        .header("content-type", "application/json").body(Body::from(body)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, Bytes::from(body));
    assert_eq!(
        requests[0]
            .headers
            .get("x-harbor-principal-source")
            .unwrap(),
        "harbornavi-lan"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-principal-roles").unwrap(),
        "CAMERA_CONTROL"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-camera-scope").unwrap(),
        "cam-rtsp-192-168-3-252"
    );
}

#[tokio::test]
async fn package_detection_control_allows_anonymous_lan_get_and_put_without_session() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for method in [Method::GET, Method::PUT] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri("/api/beacon/cameras/camera-252/package-detection/control")
                    .header("content-type", "application/json")
                    .body(if method == Method::PUT {
                        Body::from(r#"{"enabled":true,"stream_profile":"sub"}"#)
                    } else {
                        Body::empty()
                    })
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{method}");
    }

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(
            request.headers.get("x-harbor-principal-source").unwrap(),
            "harbornavi-lan"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-roles").unwrap(),
            "CAMERA_CONTROL"
        );
        assert_eq!(
            request.headers.get("x-harbor-camera-scope").unwrap(),
            "camera-252"
        );
    }
    drop(requests);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn malformed_package_detection_control_paths_are_rejected_before_proxying() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for facade in [
        "/api/beacon",
        "/api/harbor-assistant",
        "/api/harbor-gate/api/beacon",
    ] {
        for suffix in [
            "/cameras%2Fcamera-252/package-detection/control",
            "/cameras/../package-detection/control",
            "/cameras/camera%5C252/package-detection/control",
            "/cameras%252Fcamera-252/package-detection/control",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::put(format!("{facade}{suffix}"))
                        .header("x-harboros-auth-token", "must-not-be-consumed")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn cat_detection_control_does_not_downgrade_failed_harboros_authentication() {
    let (beacon_url, observer_captured) = mock_beacon().await;
    let observer = FakeAuthenticator::new(Err(HarborOsAuthFailure::FullAdminRequired));
    let (observer_state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(observer.clone()),
    );
    let observer_response = router(observer_state)
        .oneshot(
            Request::get("/api/beacon/cameras/camera-252/cat-detection/control")
                .header("x-harboros-auth-token", "observation-only-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(observer_response.status(), StatusCode::FORBIDDEN);
    assert!(observer_captured.lock().await.is_empty());
    assert_eq!(observer.tokens().await, vec!["observation-only-token"]);
}

#[tokio::test]
async fn malformed_or_unsupported_cat_detection_control_paths_remain_unprivileged() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);

    for (method, path) in [
        (
            Method::GET,
            "/api/beacon/cameras/camera-252/cat-detection/control/extra",
        ),
        (
            Method::POST,
            "/api/beacon/cameras/camera-252/cat-detection/control",
        ),
        (
            Method::DELETE,
            "/api/harbor-assistant/cameras/camera-252/cat-detection/control",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("x-harboros-auth-token", "unused-control-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }

    assert_eq!(captured.lock().await.len(), 3);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn malformed_control_canonicalization_is_rejected_before_authentication_or_proxying() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let invalid_control_suffixes = [
        "//cameras/camera-252/cat-detection/control",
        "/cameras%2Fcamera-252/cat-detection/control",
        "/cameras/camera-252/cat-detection%2Fcontrol",
        "/cameras/./cat-detection/control",
        "/cameras/../cat-detection/control",
        "/cameras/%2E/cat-detection/control",
        "/cameras/%2E%2E/cat-detection/control",
        "/cameras/camera%5C252/cat-detection/control",
        "/cameras/camera\\252/cat-detection/control",
    ];

    for facade in [
        "/api/beacon",
        "/api/harbor-assistant",
        "/api/harbor-gate/api/beacon",
    ] {
        for suffix in invalid_control_suffixes {
            let path = format!("{facade}{suffix}");
            let response = app
                .clone()
                .oneshot(
                    Request::put(&path)
                        .header("x-harboros-auth-token", "must-not-be-consumed")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );
        }
    }

    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn double_encoded_control_candidates_are_rejected_before_authentication_or_proxying() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let invalid_control_suffixes = [
        "/cameras%252Fcamera-252/cat-detection/control",
        "/cameras/camera-252/cat-detection%252Fcontrol",
        "/cameras%252F%252E%252Fcat-detection%252Fcontrol",
        "/cameras%252Fcamera%255C252%252Fcat-detection%252Fcontrol",
    ];

    for facade in [
        "/api/beacon",
        "/api/harbor-assistant",
        "/api/harbor-gate/api/beacon",
    ] {
        for suffix in invalid_control_suffixes {
            let path = format!("{facade}{suffix}");
            let response = app
                .clone()
                .oneshot(
                    Request::put(&path)
                        .header("x-harboros-auth-token", "must-not-be-consumed")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );
        }
    }

    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn control_paths_with_prefixed_canonicalization_are_rejected_before_authentication_or_proxying(
) {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let invalid_control_suffixes = [
        "/ignored/../cameras/camera-252/cat-detection/control",
        "/ignored/%2E%2E/cameras/camera-252/cat-detection/control",
        "/ignored/%252E%252E/cameras/camera-252/cat-detection/control",
        "/ignored\\..\\cameras\\camera-252\\cat-detection\\control",
        "/ignored%5C..%5Ccameras%5Ccamera-252%5Ccat-detection%5Ccontrol",
    ];

    for facade in [
        "/api/beacon",
        "/api/harbor-assistant",
        "/api/harbor-gate/api/beacon",
    ] {
        for method in [Method::GET, Method::PUT] {
            for suffix in invalid_control_suffixes {
                let path = format!("{facade}{suffix}");
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(&path)
                            .header("x-harboros-auth-token", "must-not-be-consumed")
                            .body(Body::from("{}"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                assert_eq!(
                    response.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{method} {path}"
                );
            }
        }
    }

    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn ordinary_percent_encoded_paths_keep_axum_decoded_proxy_semantics() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let facades = [
        "/api/beacon",
        "/api/harbor-assistant",
        "/api/harbor-gate/api/beacon",
    ];

    for facade in facades {
        for target in ["cat", "package"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!(
                        "{facade}/cameras/camera%2D252/{target}-detection/observation"
                    ))
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    for facade in facades {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("{facade}/vision/detection%2Djobs/job%2D1"))
                    .header("x-harboros-auth-token", format!("token-{facade}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 9);
    for (index, request) in requests.iter().take(6).enumerate() {
        let target = if index % 2 == 0 { "cat" } else { "package" };
        assert_eq!(
            request.path_and_query,
            format!("/api/cameras/camera-252/{target}-detection/observation")
        );
        assert_eq!(
            request.headers.get("x-harbor-camera-scope").unwrap(),
            "camera-252"
        );
    }
    for request in requests.iter().skip(6) {
        assert_eq!(request.path_and_query, "/api/vision/detection-jobs/job-1");
        assert_eq!(
            request.headers.get("x-harbor-principal-id").unwrap(),
            "harboros:uid:42"
        );
    }
    drop(requests);
    assert_eq!(authenticator.tokens().await.len(), 3);
}

#[tokio::test]
async fn canonical_control_keeps_single_decoded_camera_ids_and_replaces_client_identity() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let camera_ids = ["camera%25fleet", "camera%252F252"];
    let facades = [
        "/api/beacon",
        "/api/harbor-assistant",
        "/api/harbor-gate/api/beacon",
    ];
    let mut expected_requests = Vec::new();

    for camera_id in camera_ids {
        for facade in facades {
            for method in [Method::GET, Method::PUT] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(format!(
                                "{facade}/cameras/{camera_id}/cat-detection/control"
                            ))
                            .header("content-type", "application/json")
                            .header("authorization", "Bearer browser-controlled")
                            .header(
                                "x-harboros-auth-token",
                                format!("token-{camera_id}-{facade}-{method}"),
                            )
                            .header("x-harbor-principal-source", "client")
                            .header("x-harbor-principal-id", "client:spoof")
                            .header("x-harbor-principal-roles", "SUPERUSER")
                            .header("x-harbor-workspace-id", "evil")
                            .body(Body::from("{}"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                assert_eq!(
                    response.headers().get("content-type").unwrap(),
                    "application/json"
                );
                expected_requests.push((
                    method,
                    format!("/api/cameras/{camera_id}/cat-detection/control"),
                ));
            }
        }
    }

    let requests = captured.lock().await;
    assert_eq!(requests.len(), expected_requests.len());
    for (request, (method, target_path)) in requests.iter().zip(expected_requests) {
        assert_eq!(request.method, method);
        assert_eq!(request.path_and_query, target_path);
        assert_eq!(
            request.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            "Bearer beacon-service-secret"
        );
        assert!(request.headers.get("x-harboros-auth-token").is_none());
        assert_eq!(
            request.headers.get("x-harbor-principal-source").unwrap(),
            "harboros"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-id").unwrap(),
            "harboros:uid:42"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-roles").unwrap(),
            "FULL_ADMIN,SYSTEM_READ"
        );
        assert_eq!(
            request.headers.get("x-harbor-workspace-id").unwrap(),
            "home-1"
        );
    }
    drop(requests);
    assert_eq!(authenticator.tokens().await.len(), 12);
}

#[tokio::test]
async fn authenticated_detection_job_request_replaces_spoofed_principal() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let request =
        Request::patch("/api/harbor-gate/api/beacon/vision/detection-jobs/job-1/results/latest")
            .header("content-type", "application/json")
            .header("authorization", "Bearer browser-controlled")
            .header("x-harboros-auth-token", "one-time-detection-token")
            .header("x-harbor-principal-source", "client")
            .header("x-harbor-principal-id", "client:spoof")
            .header("x-harbor-principal-roles", "SUPERUSER")
            .header("x-harbor-workspace-id", "evil")
            .body(Body::from(r#"{"device_id":"camera-252"}"#))
            .unwrap();

    let response = router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(
        upstream.path_and_query,
        "/api/vision/detection-jobs/job-1/results/latest"
    );
    assert_eq!(
        upstream.headers.get("authorization").unwrap(),
        "Bearer beacon-service-secret"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-principal-id").unwrap(),
        "harboros:uid:42"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-principal-roles").unwrap(),
        "FULL_ADMIN,SYSTEM_READ"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-workspace-id").unwrap(),
        "home-1"
    );
    assert!(upstream.headers.get("x-harboros-auth-token").is_none());
    drop(requests);
    assert_eq!(
        authenticator.tokens().await,
        vec!["one-time-detection-token"]
    );
}

#[tokio::test]
async fn authenticated_observation_replaces_spoofed_principal_and_discards_one_time_token() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let request = Request::get(
        "/api/beacon/cameras/camera-252/package-detection/observation?stream_profile=sub",
    )
    .header("authorization", "Bearer browser-controlled")
    .header("x-harboros-auth-token", "one-time-observation-token")
    .header("x-harbor-principal-source", "client")
    .header("x-harbor-principal-id", "client:spoof")
    .header("x-harbor-principal-roles", "SUPERUSER")
    .header("x-harbor-workspace-id", "evil")
    .body(Body::empty())
    .unwrap();

    let response = router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(
        upstream.path_and_query,
        "/api/cameras/camera-252/package-detection/observation?stream_profile=sub"
    );
    assert_eq!(
        upstream.headers.get("authorization").unwrap(),
        "Bearer beacon-service-secret"
    );
    assert_eq!(
        upstream.headers.get("x-harbor-principal-id").unwrap(),
        "harboros:uid:42"
    );
    assert!(upstream.headers.get("x-harboros-auth-token").is_none());
    drop(requests);
    assert_eq!(
        authenticator.tokens().await,
        vec!["one-time-observation-token"]
    );
}

#[tokio::test]
async fn anonymous_observation_uses_camera_scoped_lan_principal_and_keeps_mutations_protected() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let app = router(state);
    let observation = Request::get(
        "/api/beacon/cameras/camera-252/package-detection/observation?stream_profile=sub",
    )
    .header("authorization", "Bearer browser-controlled")
    .header("x-harbor-principal-source", "client")
    .header("x-harbor-principal-id", "client:spoof")
    .header("x-harbor-principal-roles", "FULL_ADMIN")
    .header("x-harbor-camera-scope", "camera-999")
    .body(Body::empty())
    .unwrap();

    assert_eq!(
        app.clone().oneshot(observation).await.unwrap().status(),
        StatusCode::OK
    );
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("x-harbor-principal-source")
            .unwrap(),
        "harbornavi-lan"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-principal-id").unwrap(),
        "harbornavi-lan:anonymous"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-principal-roles").unwrap(),
        "CAMERA_VIEW"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-camera-scope").unwrap(),
        "camera-252"
    );
    drop(requests);

    let mutation = Request::post("/api/beacon/vision/detection-jobs")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        app.oneshot(mutation).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(captured.lock().await.len(), 1);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn device_session_cookie_does_not_limit_anonymous_lan_cat_detection_control() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let device_sessions = state.device_sessions.clone();
    let pairing = state
        .device_sessions
        .issue_pairing("camera-252", 300)
        .unwrap();
    let app = router(state);

    let exchange = Request::post("/api/harbor-gate/api/device-session/exchange")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"pairing_code": &pairing.code}).to_string(),
        ))
        .unwrap();
    let exchange_response = app.clone().oneshot(exchange).await.unwrap();
    assert_eq!(exchange_response.status(), StatusCode::OK);
    let cookie = exchange_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("harbornavi_device_session="));
    assert!(exchange_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("HttpOnly; SameSite=Strict"));
    assert_eq!(
        exchange_response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let status = Request::get("/api/harbor-gate/api/device-session")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let status_response = app.clone().oneshot(status).await.unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    assert_eq!(
        status_response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let replay_exchange = Request::post("/api/harbor-gate/api/device-session/exchange")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"pairing_code": &pairing.code}).to_string(),
        ))
        .unwrap();
    let replay_response = app.clone().oneshot(replay_exchange).await.unwrap();
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        replay_response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let observation =
        Request::get("/api/beacon/cameras/camera-252/cat-detection/observation?stream_profile=sub")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
    assert_eq!(
        app.clone().oneshot(observation).await.unwrap().status(),
        StatusCode::OK
    );
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("x-harbor-principal-source")
            .unwrap(),
        "harbornavi-lan"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-principal-roles").unwrap(),
        "CAMERA_VIEW"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-camera-scope").unwrap(),
        "camera-252"
    );
    assert_eq!(
        requests[0].headers.get("x-harbor-principal-id").unwrap(),
        "harbornavi-lan:anonymous"
    );
    drop(requests);

    let wrong_camera =
        Request::get("/api/beacon/cameras/camera-999/cat-detection/observation?stream_profile=sub")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
    assert_eq!(
        app.clone().oneshot(wrong_camera).await.unwrap().status(),
        StatusCode::OK
    );

    let detection_jobs = Request::get("/api/beacon/vision/detection-jobs")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(detection_jobs).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let get_control =
        Request::get("/api/harbor-gate/api/beacon/cameras/camera-252/cat-detection/control")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
    assert_eq!(
        app.clone().oneshot(get_control).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    let put_control =
        Request::put("/api/harbor-gate/api/beacon/cameras/camera-252/cat-detection/control")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .body(Body::from(r#"{"enabled":true,"stream_profile":"sub"}"#))
            .unwrap();
    assert_eq!(
        app.clone().oneshot(put_control).await.unwrap().status(),
        StatusCode::ACCEPTED
    );

    for method in [Method::GET, Method::PUT] {
        let wrong_camera = Request::builder()
            .method(method)
            .uri("/api/harbor-gate/api/beacon/cameras/camera-999/cat-detection/control")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(wrong_camera).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
    }

    let anonymous_control =
        Request::get("/api/harbor-gate/api/beacon/cameras/camera-252/cat-detection/control")
            .body(Body::empty())
            .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(anonymous_control)
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );

    let session_token = cookie.split_once('=').expect("device session cookie").1;
    device_sessions.revoke(session_token).unwrap();
    let revoked_control =
        Request::get("/api/harbor-gate/api/beacon/cameras/camera-252/cat-detection/control")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
    assert_eq!(
        app.oneshot(revoked_control).await.unwrap().status(),
        StatusCode::ACCEPTED
    );

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 8);
    for request in &requests[2..] {
        assert_eq!(
            request.headers.get("x-harbor-principal-source").unwrap(),
            "harbornavi-lan"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-id").unwrap(),
            "harbornavi-lan:anonymous"
        );
        assert_eq!(
            request.headers.get("x-harbor-principal-roles").unwrap(),
            "CAMERA_CONTROL"
        );
        let expected_camera = if request.path_and_query.contains("camera-999") {
            "camera-999"
        } else {
            "camera-252"
        };
        assert_eq!(
            request.headers.get("x-harbor-camera-scope").unwrap(),
            expected_camera
        );
    }
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn authentication_failures_have_stable_statuses_and_redact_tokens() {
    let (beacon_url, captured) = mock_beacon().await;
    let cases = [
        (
            HarborOsAuthFailure::InvalidToken,
            StatusCode::UNAUTHORIZED,
            "HARBOROS_AUTH_FAILED",
        ),
        (
            HarborOsAuthFailure::AccessDenied,
            StatusCode::FORBIDDEN,
            "HARBOROS_ACCESS_DENIED",
        ),
        (
            HarborOsAuthFailure::WebUiAccessRequired,
            StatusCode::FORBIDDEN,
            "HARBOROS_WEBUI_ACCESS_REQUIRED",
        ),
        (
            HarborOsAuthFailure::FullAdminRequired,
            StatusCode::FORBIDDEN,
            "HARBOROS_FULL_ADMIN_REQUIRED",
        ),
        (
            HarborOsAuthFailure::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "HARBOROS_AUTH_UNAVAILABLE",
        ),
    ];

    for (failure, expected_status, expected_code) in cases {
        let authenticator = FakeAuthenticator::new(Err(failure));
        let (state, _temp_dir) = test_state(
            &beacon_url,
            "beacon-service-secret",
            Arc::new(authenticator),
        );
        let token = format!("secret-token-{expected_code}");
        let request = Request::post("/api/beacon/knowledge/search")
            .header("x-harboros-auth-token", &token)
            .body(Body::from("{}"))
            .unwrap();

        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected_status);
        let body = response_body(response).await;
        assert!(body.contains(expected_code));
        assert!(!body.contains(&token));
    }

    assert!(captured.lock().await.is_empty());
}

#[tokio::test]
async fn ordinary_beacon_routes_strip_identity_without_harboros_login() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let request = Request::get("/api/beacon/state?user_id=spoof&refresh=1")
        .header("authorization", "Bearer browser-controlled")
        .header("x-harbor-principal-id", "client:spoof")
        .header("x-harbor-workspace-id", "evil")
        .body(Body::empty())
        .unwrap();

    let response = router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.path_and_query, "/api/state?refresh=1");
    assert_eq!(
        upstream.headers.get("authorization").unwrap(),
        "Bearer beacon-service-secret"
    );
    assert!(upstream.headers.get("x-harbor-principal-id").is_none());
    assert!(upstream.headers.get("x-harbor-workspace-id").is_none());
    drop(requests);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn media_preview_preserves_range_semantics_without_forwarding_identity() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(
        &beacon_url,
        "beacon-service-secret",
        Arc::new(authenticator.clone()),
    );
    let request = Request::get("/api/beacon/knowledge/preview?user_id=spoof&file=clip")
        .header("range", "bytes=10-13")
        .header("if-range", "\"client-preview-v1\"")
        .header("authorization", "Bearer browser-controlled")
        .header("x-harboros-auth-token", "unused-one-time-secret")
        .header("x-harbor-principal-id", "client:spoof")
        .header("x-harbor-workspace-id", "evil")
        .body(Body::empty())
        .unwrap();

    let response = router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    for (name, expected) in [
        ("accept-ranges", "bytes"),
        ("content-range", "bytes 10-13/100"),
        ("content-length", "4"),
        ("etag", "\"preview-v1\""),
        ("last-modified", "Sat, 02 Aug 2026 00:00:00 GMT"),
    ] {
        assert_eq!(response.headers().get(name).unwrap(), expected, "{name}");
    }
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        Bytes::from_static(b"clip")
    );

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.path_and_query, "/api/knowledge/preview?file=clip");
    assert_eq!(upstream.headers.get("range").unwrap(), "bytes=10-13");
    assert_eq!(
        upstream.headers.get("if-range").unwrap(),
        "\"client-preview-v1\""
    );
    assert_eq!(
        upstream.headers.get("authorization").unwrap(),
        "Bearer beacon-service-secret"
    );
    for name in [
        "x-harboros-auth-token",
        "x-harbor-principal-id",
        "x-harbor-workspace-id",
    ] {
        assert!(upstream.headers.get(name).is_none(), "forwarded {name}");
    }
    drop(requests);
    assert!(authenticator.tokens().await.is_empty());
}

#[tokio::test]
async fn legacy_task_token_cannot_replace_missing_web_api_token() {
    let (beacon_url, captured) = mock_beacon().await;
    let authenticator = FakeAuthenticator::successful();
    let (state, _temp_dir) = test_state(&beacon_url, "", Arc::new(authenticator.clone()));
    assert_eq!(state.config.harborbeacon_token, "legacy-task-secret");
    assert!(state.config.harborbeacon_web_api_token.is_empty());
    let request = Request::post("/api/beacon/knowledge/search")
        .header("authorization", "Bearer browser-controlled")
        .header("x-harboros-auth-token", "one-time-secret")
        .body(Body::from("{}"))
        .unwrap();

    let response = router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_body(response).await;
    assert!(body.contains("HARBORBEACON_SERVICE_AUTH_UNAVAILABLE"));
    assert!(!body.contains("one-time-secret"));
    assert!(!body.contains("browser-controlled"));
    assert!(captured.lock().await.is_empty());
    assert!(authenticator.tokens().await.is_empty());
}
