use crate::config::AppConfig;
use crate::device_session::{DeviceSessionError, DeviceSessionStore, ExchangedDeviceSession};
use crate::error::GatewayError;
use crate::gateway::GatewayService;
use crate::harboros_auth::{
    HarborOsAuthFailure, HarborOsAuthenticator, HarborOsPrincipal, MiddlewareHarborOsAuthenticator,
};
use crate::runtime::{
    maybe_start_feishu_websocket_runtime, maybe_start_weixin_poll_runtime,
    start_delivery_recovery_runtime,
};
use crate::setup::SetupPortalService;
use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{
    header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, SET_COOKIE},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

const HARBOR_GATE_PUBLIC_PREFIX: &str = "/api/harbor-gate";
const GATEWAY_TURN_CONTRACT_VERSION: &str = "3.0";
const LEGACY_GATEWAY_TURN_CONTRACT_VERSION: &str = "2.0";
const HARBOROS_AUTH_TOKEN_HEADER: &str = "X-HarborOS-Auth-Token";
const DEVICE_SESSION_COOKIE: &str = "harbornavi_device_session";
const DEVICE_SESSION_TTL_SECONDS: u64 = 12 * 60 * 60;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub gateway: Arc<GatewayService>,
    pub setup: Arc<SetupPortalService>,
    pub feishu_websocket_started: Arc<AtomicBool>,
    pub harboros_authenticator: Arc<dyn HarborOsAuthenticator>,
    pub device_sessions: Arc<DeviceSessionStore>,
}

pub async fn serve(config: AppConfig) -> anyhow::Result<()> {
    validate_required_service_auth(&config)?;
    config.validate_runtime_profile()?;
    let gateway = Arc::new(GatewayService::from_config(&config)?);
    let feishu_websocket_started = Arc::new(AtomicBool::new(false));
    maybe_start_configured_feishu_runtime(
        gateway.clone(),
        config.feishu.clone(),
        config.enable_feishu_websocket,
        feishu_websocket_started.clone(),
    );
    maybe_start_weixin_poll_runtime(gateway.clone(), config.enable_weixin_runtime);
    start_delivery_recovery_runtime(gateway.clone());
    start_whatsapp_inbox(gateway.clone());
    let state = AppState {
        config: config.clone(),
        setup: Arc::new(SetupPortalService::new(config.clone(), gateway.clone())),
        gateway,
        feishu_websocket_started,
        harboros_authenticator: Arc::new(MiddlewareHarborOsAuthenticator::default()),
        device_sessions: Arc::new(DeviceSessionStore::new(
            config.device_session_state_dir.clone(),
        )),
    };
    let app = router(state);
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("HarborGate Rust listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    let feishu_path = state.config.feishu.webhook_path.clone();
    Router::new()
        .route("/health", get(health))
        .route("/", get(root))
        .route("/api/setup/status", get(setup_status))
        .route("/api/gateway/status", get(gateway_status))
        .route("/api/gateway/turns", post(gateway_turn))
        .route("/api/harbor-gate", get(root))
        .route("/api/harbor-gate/", get(root))
        .route(
            "/api/harbor-gate/api/setup/status",
            get(prefixed_setup_status),
        )
        .route("/api/harbor-gate/api/gateway/status", get(gateway_status))
        .route("/api/harbor-gate/api/gateway/turns", post(gateway_turn))
        .route(
            "/api/harbor-gate/api/device-session",
            get(device_session_status),
        )
        .route(
            "/api/harbor-gate/api/device-session/exchange",
            post(device_session_exchange),
        )
        .route(
            "/api/harbor-gate/api/device-session/logout",
            post(device_session_logout),
        )
        .route("/api/harbor-assistant", any(harbor_assistant_proxy_root))
        .route("/api/harbor-assistant/{*path}", any(harbor_assistant_proxy))
        .route("/api/beacon", any(beacon_proxy_root))
        .route("/api/beacon/{*path}", any(beacon_proxy))
        .route(
            "/api/harbor-gate/api/beacon",
            any(prefixed_beacon_proxy_root),
        )
        .route(
            "/api/harbor-gate/api/beacon/{*path}",
            any(prefixed_beacon_proxy),
        )
        .route(
            "/api/harbor-gate/api/notifications/deliveries",
            post(notification_delivery),
        )
        .route("/api/notifications/deliveries", post(notification_delivery))
        .route(
            "/api/im/whatsapp/media/{attachment_id}",
            get(whatsapp_media),
        )
        .route(
            "/api/harbor-gate/api/im/whatsapp/media/{attachment_id}",
            get(whatsapp_media),
        )
        .route("/api/harbor-gate/setup", get(prefixed_feishu_setup_page))
        .route(
            "/api/harbor-gate/setup/feishu",
            get(prefixed_feishu_setup_page),
        )
        .route("/api/harbor-gate/setup/qr", get(prefixed_feishu_qr_page))
        .route(
            "/api/harbor-gate/setup/feishu/qr",
            get(prefixed_feishu_qr_page),
        )
        .route("/api/harbor-gate/setup/qr.svg", get(prefixed_feishu_qr_svg))
        .route(
            "/api/harbor-gate/setup/feishu/qr.svg",
            get(prefixed_feishu_qr_svg),
        )
        .route(
            "/api/harbor-gate/setup/weixin",
            get(prefixed_weixin_setup_page),
        )
        .route(
            "/api/harbor-gate/setup/weixin/qr",
            get(prefixed_weixin_setup_page),
        )
        .route("/api/harbor-gate/setup/weixin/qr.svg", get(weixin_qr_svg))
        .route("/api/harbor-gate/admin/im", get(prefixed_admin_im))
        .route(
            "/api/harbor-gate/admin/im/feishu",
            get(prefixed_feishu_setup_page),
        )
        .route(
            "/api/harbor-gate/admin/im/weixin",
            get(prefixed_weixin_setup_page),
        )
        .route(
            "/api/harbor-gate/api/setup/feishu/configure",
            post(configure_feishu),
        )
        .route(
            "/api/harbor-gate/api/setup/weixin/login/start",
            post(prefixed_weixin_login_start),
        )
        .route(
            "/api/harbor-gate/api/setup/weixin/login/status",
            get(prefixed_weixin_login_status),
        )
        .route(
            "/api/harbor-gate/api/setup/weixin/unbind",
            post(prefixed_weixin_unbind),
        )
        .route("/setup", get(feishu_setup_page))
        .route("/setup/feishu", get(feishu_setup_page))
        .route("/setup/qr", get(feishu_qr_page))
        .route("/setup/feishu/qr", get(feishu_qr_page))
        .route("/setup/qr.svg", get(feishu_qr_svg))
        .route("/setup/feishu/qr.svg", get(feishu_qr_svg))
        .route("/setup/weixin", get(weixin_setup_page))
        .route("/setup/weixin/qr", get(weixin_setup_page))
        .route("/setup/weixin/qr.svg", get(weixin_qr_svg))
        .route("/admin/im", get(admin_im))
        .route("/admin/im/feishu", get(feishu_setup_page))
        .route("/admin/im/weixin", get(weixin_setup_page))
        .route("/api/setup/feishu/configure", post(configure_feishu))
        .route("/api/setup/weixin/login/start", post(weixin_login_start))
        .route("/api/setup/weixin/login/status", get(weixin_login_status))
        .route("/api/setup/weixin/unbind", post(weixin_unbind))
        .route("/api/harbor-gate/messages/{platform}", post(message))
        .route("/messages/{platform}", post(message))
        .route(&feishu_path, post(feishu_webhook))
        .route(
            "/whatsapp/webhook",
            get(whatsapp_verify).post(whatsapp_webhook),
        )
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "runtime": "rust",
        "runtime_supervisor": {
            "runtime": "rust",
            "status": "running",
            "adapters": state.gateway.status()["adapters"].clone(),
        }
    }))
}

async fn root() -> impl IntoResponse {
    Json(json!({
        "name": "harborgate",
        "runtime": "rust",
        "message": "Rust HarborGate is active for IM setup, Feishu, Weixin, webhook, delivery, and runtime supervision."
    }))
}

async fn setup_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    Json(state.setup.status_payload(host_header(&headers)))
}

async fn prefixed_setup_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Json(
        state
            .setup
            .status_payload_with_prefix(host_header(&headers), HARBOR_GATE_PUBLIC_PREFIX),
    )
}

async fn gateway_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    require_service_contract(&state.config, &headers)?;
    require_service_auth(&state.config, &headers)?;
    Ok(Json(
        state.setup.gateway_status_payload(host_header(&headers)),
    ))
}

async fn notification_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, GatewayError> {
    require_service_contract(&state.config, &headers)?;
    require_service_auth(&state.config, &headers)?;
    Ok(Json(
        state.gateway.handle_notification_delivery(payload).await?,
    ))
}

async fn gateway_turn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<impl IntoResponse, GatewayError> {
    let contract_version = require_gateway_turn_contract(&headers)?;
    require_service_auth(&state.config, &headers)?;
    Ok((
        gateway_turn_response_headers(contract_version),
        Json(state.gateway.handle_gateway_turn(payload).await?),
    ))
}

fn gateway_turn_response_headers(contract_version: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Contract-Version",
        contract_version.parse().expect("negotiated header"),
    );
    headers
}

fn require_gateway_turn_contract(headers: &HeaderMap) -> Result<&'static str, GatewayError> {
    let Some(received) = headers
        .get("X-Contract-Version")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(GATEWAY_TURN_CONTRACT_VERSION);
    };
    if received != GATEWAY_TURN_CONTRACT_VERSION && received != LEGACY_GATEWAY_TURN_CONTRACT_VERSION
    {
        return Err(GatewayError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CONTRACT_VERSION_MISMATCH",
            format!("X-Contract-Version must be {GATEWAY_TURN_CONTRACT_VERSION}"),
        ));
    }
    Ok(if received == LEGACY_GATEWAY_TURN_CONTRACT_VERSION {
        LEGACY_GATEWAY_TURN_CONTRACT_VERSION
    } else {
        GATEWAY_TURN_CONTRACT_VERSION
    })
}

async fn beacon_proxy_root(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    proxy_beacon_request(
        state,
        method,
        headers,
        beacon_proxy_target_path("", uri.query()),
        "/api/beacon",
        body,
    )
    .await
}

async fn beacon_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    proxy_beacon_request(
        state,
        method,
        headers,
        beacon_proxy_target_path_from_original_uri(uri.path(), &path, "/api/beacon", uri.query())?,
        "/api/beacon",
        body,
    )
    .await
}

#[derive(Debug, serde::Deserialize)]
struct DeviceSessionExchangeRequest {
    pairing_code: String,
}

async fn device_session_exchange(
    State(state): State<AppState>,
    Json(payload): Json<DeviceSessionExchangeRequest>,
) -> axum::response::Response {
    let response = state
        .device_sessions
        .exchange(&payload.pairing_code, DEVICE_SESSION_TTL_SECONDS)
        .map(device_session_response)
        .unwrap_or_else(|error| device_session_gateway_error(error).into_response());
    no_store_response(response)
}

async fn device_session_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let response = match device_session_cookie(&headers) {
        Some(token) => match state.device_sessions.current(token) {
            Ok(principal) => Json(json!({
                "authenticated": true,
                "camera_id": principal.camera_id,
                "expires_at_epoch_seconds": principal.expires_at_epoch_seconds,
            }))
            .into_response(),
            Err(error) => device_session_gateway_error(error).into_response(),
        },
        None => device_session_gateway_error(DeviceSessionError::InvalidSession).into_response(),
    };
    no_store_response(response)
}

async fn device_session_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(token) = device_session_cookie(&headers) {
        match state.device_sessions.revoke(token) {
            Ok(()) | Err(DeviceSessionError::InvalidSession) => {}
            Err(error) => {
                return no_store_response(device_session_gateway_error(error).into_response())
            }
        }
    }
    let mut response = Json(json!({"authenticated": false})).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "harbornavi_device_session=; Path=/api/harbor-gate/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    no_store_response(response)
}

fn no_store_response(mut response: axum::response::Response) -> axum::response::Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn device_session_response(exchanged: ExchangedDeviceSession) -> axum::response::Response {
    let mut response = Json(json!({
        "authenticated": true,
        "camera_id": exchanged.principal.camera_id,
        "expires_at_epoch_seconds": exchanged.principal.expires_at_epoch_seconds,
    }))
    .into_response();
    let cookie = format!(
        "{DEVICE_SESSION_COOKIE}={}; Path=/api/harbor-gate/; HttpOnly; SameSite=Strict; Max-Age={DEVICE_SESSION_TTL_SECONDS}",
        exchanged.token
    );
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("device session cookie"),
    );
    response
}

async fn prefixed_beacon_proxy_root(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    proxy_beacon_request(
        state,
        method,
        headers,
        beacon_proxy_target_path("", uri.query()),
        "/api/harbor-gate/api/beacon",
        body,
    )
    .await
}

async fn prefixed_beacon_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    proxy_beacon_request(
        state,
        method,
        headers,
        beacon_proxy_target_path_from_original_uri(
            uri.path(),
            &path,
            "/api/harbor-gate/api/beacon",
            uri.query(),
        )?,
        "/api/harbor-gate/api/beacon",
        body,
    )
    .await
}

async fn harbor_assistant_proxy_root(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    proxy_beacon_request(
        state,
        method,
        headers,
        harbor_assistant_proxy_target_path("", uri.query()),
        "/api/harbor-assistant",
        body,
    )
    .await
}

async fn harbor_assistant_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    proxy_beacon_request(
        state,
        method,
        headers,
        beacon_proxy_target_path_from_original_uri(
            uri.path(),
            &path,
            "/api/harbor-assistant",
            uri.query(),
        )?,
        "/api/harbor-assistant",
        body,
    )
    .await
}

async fn proxy_beacon_request(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    target_path: String,
    proxy_prefix: &'static str,
    body: Bytes,
) -> Result<axum::response::Response, GatewayError> {
    let base_url = state
        .config
        .harborbeacon_base_url
        .trim()
        .trim_end_matches('/');
    if base_url.is_empty() {
        return Err(GatewayError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "HARBORBEACON_DISABLED",
            "HarborBeacon admin proxy is not configured",
        ));
    }
    let harborbeacon_web_api_token = state.config.harborbeacon_web_api_token.trim();
    if harborbeacon_web_api_token.is_empty() {
        return Err(GatewayError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "HARBORBEACON_SERVICE_AUTH_UNAVAILABLE",
            "HarborBeacon proxy service token is not configured",
        ));
    }
    let principal = if requires_harboros_principal(&method, &target_path) {
        Some(authenticate_proxy_principal(&state, &method, &target_path, &headers).await?)
    } else {
        None
    };
    let url = format!("{base_url}{target_path}");
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).map_err(|err| {
            GatewayError::validation(format!("unsupported proxy method {}: {err}", method))
        })?;
    let request = Client::new()
        .request(reqwest_method, url)
        .headers(beacon_upstream_headers(
            &headers,
            harborbeacon_web_api_token,
            principal.as_ref(),
            &state.config.harbor_workspace_id,
        )?)
        .body(body.to_vec());
    let response = request.send().await.map_err(|err| {
        GatewayError::infrastructure(format!("Could not reach HarborBeacon admin API: {err}"))
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(|err| {
        GatewayError::infrastructure(format!("HarborBeacon returned invalid HTTP status: {err}"))
    })?;
    let upstream_headers = response.headers().clone();
    let body = response.bytes().await.map_err(|err| {
        GatewayError::infrastructure(format!(
            "Could not read HarborBeacon admin API response: {err}"
        ))
    })?;
    let mut result = (status, body).into_response();
    copy_response_header(&upstream_headers, result.headers_mut(), "content-type");
    copy_response_header(&upstream_headers, result.headers_mut(), "cache-control");
    copy_response_header(&upstream_headers, result.headers_mut(), "accept-ranges");
    copy_response_header(&upstream_headers, result.headers_mut(), "content-range");
    copy_response_header(&upstream_headers, result.headers_mut(), "content-length");
    copy_response_header(&upstream_headers, result.headers_mut(), "etag");
    copy_response_header(&upstream_headers, result.headers_mut(), "last-modified");
    copy_response_header(
        &upstream_headers,
        result.headers_mut(),
        "x-contract-version",
    );
    if let Ok(header_value) = "beacon".parse() {
        result
            .headers_mut()
            .insert("X-Harbor-Gateway-Proxy", header_value);
    }
    let proxy_prefix_header = match proxy_prefix {
        "/api/harbor-assistant" => "X-Harbor-Assistant-Proxy-Prefix",
        _ => "X-Harbor-Beacon-Proxy-Prefix",
    };
    if let Ok(header_value) = proxy_prefix.parse() {
        result
            .headers_mut()
            .insert(proxy_prefix_header, header_value);
    }
    Ok(result)
}

async fn message(
    State(state): State<AppState>,
    Path(platform): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, GatewayError> {
    if platform == "whatsapp" {
        return Err(GatewayError::new(
            StatusCode::FORBIDDEN,
            "WHATSAPP_SIGNED_WEBHOOK_REQUIRED",
            "WhatsApp messages must arrive through the signed provider webhook",
        ));
    }
    Ok(Json(
        state.gateway.handle_inbound(&platform, payload).await?,
    ))
}

async fn feishu_setup_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    Html(state.setup.build_feishu_setup_page(host_header(&headers)))
}

async fn prefixed_feishu_setup_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Html(
        state
            .setup
            .build_feishu_setup_page_with_prefix(host_header(&headers), HARBOR_GATE_PUBLIC_PREFIX),
    )
}

async fn feishu_qr_page(State(state): State<AppState>) -> impl IntoResponse {
    Html(state.setup.build_qr_page())
}

async fn prefixed_feishu_qr_page(State(state): State<AppState>) -> impl IntoResponse {
    Html(
        state
            .setup
            .build_qr_page_with_prefix(HARBOR_GATE_PUBLIC_PREFIX),
    )
}

async fn feishu_qr_svg(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        state.setup.build_feishu_qr_svg(host_header(&headers)),
    )
}

async fn prefixed_feishu_qr_svg(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        state
            .setup
            .build_feishu_qr_svg_with_prefix(host_header(&headers), HARBOR_GATE_PUBLIC_PREFIX),
    )
}

async fn weixin_setup_page(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Html(
        state
            .setup
            .build_weixin_setup_page(host_header(&headers), query_flag(&query, "unbound")),
    )
}

async fn prefixed_weixin_setup_page(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Html(state.setup.build_weixin_setup_page_with_prefix(
        host_header(&headers),
        query_flag(&query, "unbound"),
        HARBOR_GATE_PUBLIC_PREFIX,
    ))
}

async fn weixin_qr_svg(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        state.setup.build_weixin_qr_svg(),
    )
}

async fn admin_im(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let platform = query
        .get("platform")
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| "feishu".into());
    if platform == "weixin" {
        return Html(
            state
                .setup
                .build_weixin_setup_page(host_header(&headers), query_flag(&query, "unbound")),
        );
    }
    Html(state.setup.build_feishu_setup_page(host_header(&headers)))
}

async fn prefixed_admin_im(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let platform = query
        .get("platform")
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| "feishu".into());
    if platform == "weixin" {
        return Html(state.setup.build_weixin_setup_page_with_prefix(
            host_header(&headers),
            query_flag(&query, "unbound"),
            HARBOR_GATE_PUBLIC_PREFIX,
        ));
    }
    Html(
        state
            .setup
            .build_feishu_setup_page_with_prefix(host_header(&headers), HARBOR_GATE_PUBLIC_PREFIX),
    )
}

async fn configure_feishu(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> Result<impl IntoResponse, GatewayError> {
    let (status, payload) = state.setup.configure_feishu(payload).await?;
    if status.is_success() {
        maybe_start_configured_feishu_runtime(
            state.gateway.clone(),
            state.gateway.feishu_adapter().settings(),
            state.config.enable_feishu_websocket,
            state.feishu_websocket_started.clone(),
        );
    }
    Ok((status, Json(payload)))
}

async fn weixin_login_start(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, GatewayError> {
    let (status, payload) = state.setup.start_weixin_login().await?;
    Ok((status, Json(payload)))
}

async fn weixin_login_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, GatewayError> {
    let (status, payload) = state.setup.poll_weixin_login().await?;
    Ok((status, Json(payload)))
}

async fn prefixed_weixin_login_start(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, GatewayError> {
    let (status, payload) = state
        .setup
        .start_weixin_login_with_prefix(HARBOR_GATE_PUBLIC_PREFIX)
        .await?;
    Ok((status, Json(payload)))
}

async fn prefixed_weixin_login_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, GatewayError> {
    let (status, payload) = state
        .setup
        .poll_weixin_login_with_prefix(HARBOR_GATE_PUBLIC_PREFIX)
        .await?;
    Ok((status, Json(payload)))
}

async fn weixin_unbind(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    weixin_unbind_response(state, headers, "/setup/weixin?unbound=1")
}

async fn prefixed_weixin_unbind(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    weixin_unbind_response(state, headers, "/api/harbor-gate/setup/weixin?unbound=1")
}

fn weixin_unbind_response(
    state: AppState,
    headers: HeaderMap,
    redirect_path: &'static str,
) -> axum::response::Response {
    let payload = state.setup.unbind_weixin();
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(payload)).into_response();
    }
    let accept = headers
        .get("Accept")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if accept.contains("text/html") {
        return Redirect::to(redirect_path).into_response();
    }
    Json(payload).into_response()
}

async fn feishu_webhook(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, GatewayError> {
    let adapter = state.gateway.feishu_adapter();
    if adapter.is_url_verification(&payload) {
        return Ok(Json(adapter.build_url_verification_response(&payload)?));
    }
    Ok(Json(state.gateway.handle_inbound("feishu", payload).await?))
}

async fn whatsapp_verify(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<String, GatewayError> {
    state.gateway.whatsapp_adapter().verification(
        query.get("hub.mode").map(String::as_str).unwrap_or(""),
        query
            .get("hub.verify_token")
            .map(String::as_str)
            .unwrap_or(""),
        query.get("hub.challenge").map(String::as_str).unwrap_or(""),
    )
}
async fn whatsapp_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, GatewayError> {
    let adapter = state.gateway.whatsapp_adapter();
    let messages = adapter.verified_messages(
        &body,
        headers
            .get("X-Hub-Signature-256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    )?;
    adapter.enqueue(messages)?;
    Ok(Json(json!({"accepted":true})))
}
async fn whatsapp_media(
    State(state): State<AppState>,
    Path(attachment_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    require_service_contract(&state.config, &headers)?;
    require_service_auth(&state.config, &headers)?;
    let route_key = headers
        .get("X-Harbor-Route-Key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let hub_id = headers
        .get("X-Harbor-Hub-Id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let media = tokio::time::timeout(
        std::time::Duration::from_secs(32),
        state
            .gateway
            .pull_whatsapp_media(&attachment_id, route_key, hub_id),
    )
    .await
    .map_err(|_| {
        GatewayError::new(
            StatusCode::BAD_GATEWAY,
            "WHATSAPP_MEDIA_UNAVAILABLE",
            "WhatsApp image is temporarily unavailable",
        )
    })??;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&media.mime_type)
            .map_err(|_| GatewayError::validation("Invalid media type"))?,
    );
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&media.bytes.len().to_string())
            .map_err(|_| GatewayError::validation("Invalid media length"))?,
    );
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response_headers.insert(
        "X-Content-SHA256",
        HeaderValue::from_str(&media.sha256)
            .map_err(|_| GatewayError::validation("Invalid media hash"))?,
    );
    Ok((response_headers, Bytes::from(media.bytes)).into_response())
}
fn start_whatsapp_inbox(gateway: Arc<GatewayService>) {
    let media_adapter = gateway.whatsapp_adapter();
    tokio::spawn(async move {
        loop {
            if media_adapter.prune_expired_media_references().is_err() {
                tracing::warn!("WhatsApp media reference cleanup is unavailable");
            }
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
    let binding_gateway = gateway.clone();
    tokio::spawn(async move {
        loop {
            if binding_gateway.refresh_navi_binding().await.is_err() {
                tracing::warn!("Navi binding synchronization is temporarily unavailable");
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
    tokio::spawn(async move {
        loop {
            let adapter = gateway.whatsapp_adapter();
            match adapter.claim_message() {
                Ok(Some(item)) => {
                    let result = gateway
                        .handle_inbound("whatsapp", item["payload"].clone())
                        .await;
                    let retry = result.as_ref().err().is_some_and(|error| {
                        error.status.is_server_error()
                            || error.status == StatusCode::TOO_MANY_REQUESTS
                    });
                    if adapter.finish_message(item, retry).is_err() {
                        tracing::warn!("WhatsApp inbox completion could not be saved");
                    }
                }
                Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
                Err(_) => {
                    tracing::warn!("WhatsApp inbox is unavailable");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
    });
}

fn require_service_contract(config: &AppConfig, headers: &HeaderMap) -> Result<(), GatewayError> {
    let received = headers
        .get("X-Contract-Version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if received != config.contract_version {
        return Err(GatewayError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CONTRACT_VERSION_MISMATCH",
            format!("X-Contract-Version must be {}", config.contract_version),
        ));
    }
    Ok(())
}

fn require_service_auth(config: &AppConfig, headers: &HeaderMap) -> Result<(), GatewayError> {
    if config.service_token.trim().is_empty() {
        return Err(GatewayError::new(
            StatusCode::UNAUTHORIZED,
            "SERVICE_AUTH_FAILED",
            "Service authentication is not configured",
        ));
    }
    let authorization = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    let actual = authorization.strip_prefix("Bearer ").unwrap_or("").trim();
    let current_matches = service_token_matches(actual, &config.service_token);
    let previous_matches = service_token_matches(actual, &config.service_token_previous);
    if !(current_matches | previous_matches) {
        return Err(GatewayError::new(
            StatusCode::UNAUTHORIZED,
            "SERVICE_AUTH_FAILED",
            "Missing or invalid service token",
        ));
    }
    Ok(())
}

fn validate_required_service_auth(config: &AppConfig) -> anyhow::Result<()> {
    if !valid_service_token(&config.service_token) {
        anyhow::bail!("HARBOR_BEACON_TO_GATE_TOKEN is missing or malformed");
    }
    if !config.service_token_previous.is_empty()
        && (!valid_service_token(&config.service_token_previous)
            || config.service_token_previous == config.service_token)
    {
        anyhow::bail!("HARBOR_BEACON_TO_GATE_TOKEN_PREVIOUS is malformed");
    }
    if config.harborbeacon_enabled()
        && (!valid_service_token(&config.harborbeacon_web_api_token)
            || config.harborbeacon_token != config.harborbeacon_web_api_token
            || config.harborbeacon_web_api_token == config.service_token)
    {
        anyhow::bail!("HARBOR_GATE_TO_BEACON_TOKEN is missing, malformed, or not isolated");
    }
    Ok(())
}

fn valid_service_token(token: &str) -> bool {
    token.len() >= 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn service_token_matches(actual: &str, expected: &str) -> bool {
    if actual.is_empty() || expected.is_empty() || actual.len() != expected.len() {
        return false;
    }
    constant_time_eq::constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

fn beacon_proxy_target_path(path: &str, query: Option<&str>) -> String {
    let tail = path.trim_start_matches('/');
    let base = if tail.is_empty() {
        "/api/state".to_string()
    } else {
        format!("/api/{tail}")
    };
    match sanitized_beacon_query(query) {
        Some(query) => format!("{base}?{query}"),
        None => base,
    }
}

fn beacon_proxy_target_path_from_original_uri(
    request_path: &str,
    decoded_path: &str,
    proxy_prefix: &str,
    query: Option<&str>,
) -> Result<String, GatewayError> {
    let raw_suffix = request_path
        .strip_prefix(proxy_prefix)
        .ok_or_else(|| GatewayError::validation("Beacon proxy path does not match its facade"))?;
    if let Some(target_path) = detection_control_proxy_target_path(raw_suffix, query)? {
        return Ok(target_path);
    }
    let fallback_target_path = beacon_proxy_target_path(decoded_path, query);
    if is_detection_control_target_after_url_normalization(&fallback_target_path) {
        return Err(GatewayError::validation(
            "Detection control path is not canonical",
        ));
    }
    Ok(fallback_target_path)
}

const DETECTION_CONTROL_SUFFIXES: [&str; 4] = [
    "/cat-detection/control",
    "/package-detection/control",
    "/package-detection/event-config",
    "/person-detection/preview",
];

fn detection_control_proxy_target_path(
    raw_suffix: &str,
    query: Option<&str>,
) -> Result<Option<String>, GatewayError> {
    let raw_tail_after_separator = raw_suffix.strip_prefix('/').unwrap_or(raw_suffix);
    let decoded_tail = urlencoding::decode(raw_tail_after_separator).map_err(|_| {
        GatewayError::validation("Detection control path contains invalid percent encoding")
    })?;
    let decoded_control_candidate = detection_control_suffix(&decoded_tail).is_some();
    if !decoded_control_candidate {
        let twice_decoded_control_candidate = urlencoding::decode(&decoded_tail)
            .map(|twice_decoded_tail| detection_control_suffix(&twice_decoded_tail).is_some())
            .unwrap_or(false);
        if twice_decoded_control_candidate {
            return Err(GatewayError::validation(
                "Detection control path is not canonical",
            ));
        }
        return Ok(None);
    }

    let raw_tail = raw_suffix
        .strip_prefix('/')
        .filter(|tail| !tail.starts_with('/'))
        .ok_or_else(|| GatewayError::validation("Detection control path is not canonical"))?;
    let control_suffix = detection_control_suffix(raw_tail)
        .ok_or_else(|| GatewayError::validation("Detection control path is not canonical"))?;
    let camera_id = raw_tail
        .strip_prefix("cameras/")
        .and_then(|suffix| suffix.strip_suffix(control_suffix))
        .filter(|camera_id| is_safe_detection_control_camera_id(camera_id))
        .ok_or_else(|| GatewayError::validation("Detection control path is not canonical"))?;
    Ok(Some(beacon_proxy_target_path(
        &format!("cameras/{camera_id}{control_suffix}"),
        query,
    )))
}

fn detection_control_suffix(path: &str) -> Option<&'static str> {
    let camera_path = path.trim_start_matches('/').strip_prefix("cameras/")?;
    DETECTION_CONTROL_SUFFIXES
        .iter()
        .copied()
        .find(|suffix| camera_path.strip_suffix(suffix).is_some())
}

fn is_detection_control_target_after_url_normalization(target_path: &str) -> bool {
    url::Url::parse(&format!("http://harborgate.invalid{target_path}"))
        .map(|url| is_detection_control_proxy_path(url.path()))
        .unwrap_or(false)
}

fn is_safe_detection_control_camera_id(camera_id: &str) -> bool {
    if camera_id.is_empty()
        || camera_id.contains('/')
        || camera_id.contains('\\')
        || camera_id.eq_ignore_ascii_case(".")
        || camera_id.eq_ignore_ascii_case("..")
    {
        return false;
    }
    let decoded = match urlencoding::decode(camera_id) {
        Ok(decoded) => decoded,
        Err(_) => return false,
    };
    if is_unsafe_detection_control_camera_id(&decoded) {
        return false;
    }
    true
}

fn is_unsafe_detection_control_camera_id(camera_id: &str) -> bool {
    camera_id.contains('\\')
        || camera_id.contains("//")
        || camera_id
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

fn harbor_assistant_proxy_target_path(path: &str, query: Option<&str>) -> String {
    beacon_proxy_target_path(path, query)
}

fn sanitized_beacon_query(query: Option<&str>) -> Option<String> {
    let query = query.filter(|value| !value.trim().is_empty())?;
    let pairs = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| !is_identity_query_key(key))
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return None;
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(pairs);
    Some(serializer.finish())
}

fn is_identity_query_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "user_id"
            | "open_id"
            | "harboros_user"
            | "harboros_user_id"
            | "workspace_id"
            | "principal_id"
            | "account_id"
    )
}

fn requires_harboros_principal(method: &Method, target_path: &str) -> bool {
    let path = target_path.split('?').next().unwrap_or(target_path);
    if is_dlna_proxy_path(path) {
        return true;
    }
    const DETECTION_JOBS: &str = "/api/vision/detection-jobs";
    if method == Method::POST
        && path.ends_with("/person-detection/preview")
        && is_detection_control_proxy_path(path)
    {
        return true;
    }
    if method == Method::GET && is_detection_observation_proxy_path(path) {
        return true;
    }
    if matches!(method, &Method::GET | &Method::PUT) && is_detection_control_proxy_path(path) {
        return true;
    }
    if path == DETECTION_JOBS || path.starts_with(&format!("{DETECTION_JOBS}/")) {
        return true;
    }
    match (method, path) {
        (&Method::POST, "/api/knowledge/search")
        | (&Method::GET, "/api/knowledge/conversations")
        | (&Method::PATCH, "/api/knowledge/conversation-settings") => true,
        (&Method::GET | &Method::DELETE, path) => path
            .strip_prefix("/api/knowledge/conversations/")
            .is_some_and(|conversation_id| {
                !conversation_id.is_empty() && !conversation_id.contains('/')
            }),
        _ => false,
    }
}

fn is_dlna_proxy_path(path: &str) -> bool {
    let Ok(url) = url::Url::parse(&format!("http://harborgate.invalid{path}")) else {
        return false;
    };
    let mut normalized = url.path().to_string();
    for _ in 0..4 {
        if normalized == "/api/dlna" || normalized.starts_with("/api/dlna/") {
            return true;
        }
        let Ok(decoded) = urlencoding::decode(&normalized) else {
            return false;
        };
        if decoded == normalized {
            break;
        }
        normalized = decoded.into_owned();
    }
    false
}

fn is_detection_observation_proxy_path(path: &str) -> bool {
    detection_observation_camera_id(path).is_some()
}

fn is_detection_control_proxy_path(path: &str) -> bool {
    detection_control_camera_id(path).is_some()
}

fn detection_observation_camera_id(target_path: &str) -> Option<String> {
    let path = target_path.split('?').next().unwrap_or(target_path);
    let camera_path = path.strip_prefix("/api/cameras/")?;
    [
        "/cat-detection/observation",
        "/package-detection/observation",
    ]
    .into_iter()
    .find_map(|suffix| camera_path.strip_suffix(suffix))
    .filter(|camera_id| !camera_id.is_empty() && !camera_id.contains('/'))
    .map(str::to_string)
}

fn detection_control_camera_id(target_path: &str) -> Option<String> {
    let path = target_path.split('?').next().unwrap_or(target_path);
    let camera_path = path.strip_prefix("/api/cameras/")?;
    let control_suffix = detection_control_suffix(&format!("cameras/{camera_path}"))?;
    let encoded = camera_path.strip_suffix(control_suffix)?;
    if encoded.is_empty() || encoded.contains('/') {
        return None;
    }
    let camera_id = urlencoding::decode(encoded).ok()?.into_owned();
    (!camera_id.is_empty()
        && camera_id.len() <= 128
        && !camera_id.chars().any(char::is_control)
        && !camera_id
            .chars()
            .any(|character| matches!(character, '\\' | '?' | '#')))
    .then_some(camera_id)
}

async fn authenticate_proxy_principal(
    state: &AppState,
    method: &Method,
    target_path: &str,
    headers: &HeaderMap,
) -> Result<HarborOsPrincipal, GatewayError> {
    if headers.contains_key(HARBOROS_AUTH_TOKEN_HEADER) {
        return authenticate_harboros_request(state, headers).await;
    }
    if matches!(method, &Method::GET | &Method::PUT)
        || (method == Method::POST && target_path.ends_with("/person-detection/preview"))
    {
        if let Some(camera_id) = detection_control_camera_id(target_path) {
            return Ok(HarborOsPrincipal {
                source: "harbornavi-lan".to_string(),
                principal_id: "harbornavi-lan:anonymous".to_string(),
                roles: vec!["CAMERA_CONTROL".to_string()],
                camera_scope: Some(camera_id),
            });
        }
    }
    if method != Method::GET {
        return Err(harboros_auth_gateway_error(
            HarborOsAuthFailure::InvalidToken,
        ));
    }
    let camera_id = detection_observation_camera_id(target_path)
        .ok_or_else(|| harboros_auth_gateway_error(HarborOsAuthFailure::InvalidToken))?;
    Ok(HarborOsPrincipal {
        source: "harbornavi-lan".to_string(),
        principal_id: "harbornavi-lan:anonymous".to_string(),
        roles: vec!["CAMERA_VIEW".to_string()],
        camera_scope: Some(camera_id),
    })
}

async fn authenticate_harboros_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<HarborOsPrincipal, GatewayError> {
    let token = headers
        .get(HARBOROS_AUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 8192)
        .ok_or_else(|| harboros_auth_gateway_error(HarborOsAuthFailure::InvalidToken))?;
    state
        .harboros_authenticator
        .authenticate(token)
        .await
        .map_err(harboros_auth_gateway_error)
}

fn harboros_auth_gateway_error(failure: HarborOsAuthFailure) -> GatewayError {
    match failure {
        HarborOsAuthFailure::InvalidToken => GatewayError::new(
            StatusCode::UNAUTHORIZED,
            "HARBOROS_AUTH_FAILED",
            "Missing or invalid HarborOS one-time authentication token",
        ),
        HarborOsAuthFailure::AccessDenied => GatewayError::new(
            StatusCode::FORBIDDEN,
            "HARBOROS_ACCESS_DENIED",
            "HarborOS denied access",
        ),
        HarborOsAuthFailure::WebUiAccessRequired => GatewayError::new(
            StatusCode::FORBIDDEN,
            "HARBOROS_WEBUI_ACCESS_REQUIRED",
            "HarborOS WebUI access is required",
        ),
        HarborOsAuthFailure::FullAdminRequired => GatewayError::new(
            StatusCode::FORBIDDEN,
            "HARBOROS_FULL_ADMIN_REQUIRED",
            "HarborOS FULL_ADMIN role is required",
        ),
        HarborOsAuthFailure::Unavailable => GatewayError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "HARBOROS_AUTH_UNAVAILABLE",
            "HarborOS authentication service is unavailable",
        ),
    }
}

fn device_session_gateway_error(error: DeviceSessionError) -> GatewayError {
    match error {
        DeviceSessionError::InvalidPairing => GatewayError::new(
            StatusCode::UNAUTHORIZED,
            "DEVICE_PAIRING_FAILED",
            "Pairing code is invalid or expired",
        ),
        DeviceSessionError::InvalidSession => GatewayError::new(
            StatusCode::UNAUTHORIZED,
            "DEVICE_SESSION_REQUIRED",
            "A valid HarborNavi device session is required",
        ),
        DeviceSessionError::CameraDenied => GatewayError::new(
            StatusCode::FORBIDDEN,
            "DEVICE_CAMERA_ACCESS_DENIED",
            "Device session is not authorized for this camera",
        ),
        DeviceSessionError::Unavailable(_) => GatewayError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "DEVICE_SESSION_UNAVAILABLE",
            "HarborNavi device session service is unavailable",
        ),
    }
}

fn device_session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            (name.trim() == DEVICE_SESSION_COOKIE)
                .then_some(value.trim())
                .filter(|value| !value.is_empty() && value.len() <= 256)
        })
}

fn beacon_upstream_headers(
    headers: &HeaderMap,
    harborbeacon_web_api_token: &str,
    principal: Option<&HarborOsPrincipal>,
    workspace_id: &str,
) -> Result<HeaderMap, GatewayError> {
    let mut upstream = HeaderMap::new();
    for name in [
        "content-type",
        "range",
        "if-range",
        "x-request-id",
        "x-trace-id",
    ] {
        if let Some(value) = headers.get(name) {
            upstream.insert(name, value.clone());
        }
    }
    let service_authorization =
        HeaderValue::from_str(&format!("Bearer {}", harborbeacon_web_api_token.trim())).map_err(
            |_| {
                GatewayError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "HARBORBEACON_SERVICE_AUTH_UNAVAILABLE",
                    "HarborBeacon proxy service token is invalid",
                )
            },
        )?;
    upstream.insert(AUTHORIZATION, service_authorization);

    if let Some(principal) = principal {
        insert_trusted_header(
            &mut upstream,
            "X-Harbor-Principal-Source",
            &principal.source,
        )?;
        insert_trusted_header(
            &mut upstream,
            "X-Harbor-Principal-Id",
            &principal.principal_id,
        )?;
        insert_trusted_header(
            &mut upstream,
            "X-Harbor-Principal-Roles",
            &principal.roles.join(","),
        )?;
        insert_trusted_header(&mut upstream, "X-Harbor-Workspace-Id", workspace_id.trim())?;
        if let Some(camera_scope) = principal.camera_scope.as_deref() {
            insert_trusted_header(&mut upstream, "X-Harbor-Camera-Scope", camera_scope)?;
        }
    }
    Ok(upstream)
}

fn insert_trusted_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), GatewayError> {
    let value = HeaderValue::from_str(value).map_err(|_| {
        GatewayError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "HARBOROS_AUTH_UNAVAILABLE",
            "HarborOS returned an invalid authenticated principal",
        )
    })?;
    headers.insert(name, value);
    Ok(())
}

fn copy_response_header(source: &HeaderMap, target: &mut HeaderMap, name: &'static str) {
    if let Some(value) = source.get(name) {
        target.insert(name, value.clone());
    }
}

fn host_header(headers: &HeaderMap) -> &str {
    headers
        .get("Host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

fn query_flag(query: &HashMap<String, String>, key: &str) -> bool {
    query
        .get(key)
        .map(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn maybe_start_configured_feishu_runtime(
    gateway: Arc<GatewayService>,
    config: crate::config::FeishuConfig,
    enabled: bool,
    started: Arc<AtomicBool>,
) {
    if !enabled || !config.configured() || config.connection_mode != "websocket" {
        return;
    }
    if started.swap(true, Ordering::SeqCst) {
        return;
    }
    maybe_start_feishu_websocket_runtime(gateway, config, true);
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    use super::{
        beacon_proxy_target_path, gateway_turn_response_headers,
        harbor_assistant_proxy_target_path, require_gateway_turn_contract, require_service_auth,
        require_service_contract, requires_harboros_principal, validate_required_service_auth,
    };
    use crate::config::AppConfig;

    #[test]
    fn beacon_proxy_prefix_maps_to_beacon_internal_admin_api() {
        assert_eq!(beacon_proxy_target_path("", None), "/api/state");
        assert_eq!(
            beacon_proxy_target_path("knowledge/search", None),
            "/api/knowledge/search"
        );
        assert_eq!(
            beacon_proxy_target_path(
                "devices/camera-1/evidence",
                Some("user_id=u1&open_id=ou1&limit=2")
            ),
            "/api/devices/camera-1/evidence?limit=2"
        );
        assert_eq!(
            beacon_proxy_target_path("", Some("refresh=1")),
            "/api/state?refresh=1"
        );
    }

    #[test]
    fn beacon_proxy_maps_home_assistant_paths_without_gate_semantics() {
        assert_eq!(
            beacon_proxy_target_path("home-assistant/status", None),
            "/api/home-assistant/status"
        );
        assert_eq!(
            beacon_proxy_target_path("home-assistant/config", None),
            "/api/home-assistant/config"
        );
        assert_eq!(
            beacon_proxy_target_path("home-assistant/entities", Some("domain=light")),
            "/api/home-assistant/entities?domain=light"
        );
        assert_eq!(
            beacon_proxy_target_path("harboros/apps/home-assistant/install", None),
            "/api/harboros/apps/home-assistant/install"
        );
        assert_eq!(
            beacon_proxy_target_path("automation/reviews", None),
            "/api/automation/reviews"
        );
        assert_eq!(
            beacon_proxy_target_path("automation/reviews/review-1/enable", None),
            "/api/automation/reviews/review-1/enable"
        );
        assert_eq!(
            beacon_proxy_target_path("dlna/status", None),
            "/api/dlna/status"
        );
        assert_eq!(
            beacon_proxy_target_path("dlna/commands", None),
            "/api/dlna/commands"
        );
    }

    #[test]
    fn harbor_assistant_facade_maps_to_beacon_internal_admin_api() {
        assert_eq!(harbor_assistant_proxy_target_path("", None), "/api/state");
        assert_eq!(
            harbor_assistant_proxy_target_path("", Some("refresh=1")),
            "/api/state?refresh=1"
        );
        assert_eq!(
            harbor_assistant_proxy_target_path("state", None),
            "/api/state"
        );
        assert_eq!(
            harbor_assistant_proxy_target_path("home-assistant/status", None),
            "/api/home-assistant/status"
        );
        assert_eq!(
            harbor_assistant_proxy_target_path("knowledge/search", Some("limit=10")),
            "/api/knowledge/search?limit=10"
        );
    }

    #[test]
    fn harboros_authentication_covers_dlna_even_after_path_normalization() {
        for path in [
            "/api/dlna",
            "/api/dlna/status?refresh=1",
            "/api/dlna/grants",
            "/api/dlna/sessions/revoke",
            "/api/dlna/catalog/object-1",
            "/api/%64lna/commands",
            "/api/%2564lna/commands",
            "/api/./dlna/commands",
        ] {
            assert!(
                requires_harboros_principal(&axum::http::Method::POST, path),
                "{path}"
            );
        }
        assert!(!requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/dlna-other/status",
        ));
    }

    #[test]
    fn harboros_authentication_covers_rag_and_detection_job_contracts() {
        assert!(requires_harboros_principal(
            &axum::http::Method::POST,
            "/api/knowledge/search"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/cameras/camera-252/cat-detection/observation?stream_profile=sub"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/cameras/camera-252/package-detection/observation?stream_profile=sub"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::PUT,
            "/api/cameras/camera-252/package-detection/event-config"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/knowledge/conversations"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/knowledge/conversations/conversation-1"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::DELETE,
            "/api/knowledge/conversations/conversation-1"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::PATCH,
            "/api/knowledge/conversation-settings"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::POST,
            "/api/vision/detection-jobs"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/vision/detection-jobs"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/vision/detection-jobs/job-1"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::POST,
            "/api/vision/detection-jobs/job-1/renew"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::DELETE,
            "/api/vision/detection-jobs/job-1"
        ));
        assert!(requires_harboros_principal(
            &axum::http::Method::PATCH,
            "/api/vision/detection-jobs/job-1/results/latest"
        ));
        assert!(!requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/knowledge/search/suggestions"
        ));
        assert!(!requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/devices/camera-1/evidence"
        ));
        assert!(!requires_harboros_principal(
            &axum::http::Method::POST,
            "/api/knowledge/conversations"
        ));
        assert!(!requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/knowledge/conversations/"
        ));
        assert!(!requires_harboros_principal(
            &axum::http::Method::GET,
            "/api/knowledge/conversations/conversation-1/messages"
        ));
    }

    #[test]
    fn notification_delivery_requires_v20_contract_header() {
        let mut config = AppConfig::from_env();
        config.contract_version = "2.0".to_string();
        let mut headers = HeaderMap::new();
        headers.insert("X-Contract-Version", HeaderValue::from_static("1.5"));

        let error = require_service_contract(&config, &headers)
            .expect_err("wrong contract version must be rejected");

        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "CONTRACT_VERSION_MISMATCH");
    }

    #[test]
    fn service_auth_fails_closed_when_the_shared_token_is_empty() {
        let mut config = AppConfig::from_env();
        config.service_token.clear();

        let error = require_service_auth(&config, &HeaderMap::new())
            .expect_err("an empty shared token must never disable authentication");

        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.code, "SERVICE_AUTH_FAILED");
    }

    #[test]
    fn notification_delivery_auth_accepts_current_and_previous_only() {
        let mut config = AppConfig::from_env();
        config.service_token = "beacon_to_gate_current_0123456789abcdef".to_string();
        config.service_token_previous = "beacon_to_gate_previous_0123456789abcdef".to_string();

        for token in [
            "beacon_to_gate_current_0123456789abcdef",
            "beacon_to_gate_previous_0123456789abcdef",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
            require_service_auth(&config, &headers).expect("configured rotation key");
        }

        for token in [
            "gate_to_beacon_current_0123456789abcdef",
            "wrong_token_0123456789abcdef0123456789",
            "",
        ] {
            let mut headers = HeaderMap::new();
            if !token.is_empty() {
                headers.insert(
                    "Authorization",
                    HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
                );
            }
            let error = require_service_auth(&config, &headers).expect_err("wrong auth domain");
            assert_eq!(error.status, StatusCode::UNAUTHORIZED);
            assert_eq!(error.code, "SERVICE_AUTH_FAILED");
        }
    }

    #[test]
    fn gateway_turn_accepts_optional_v30_header_and_legacy_v20() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Contract-Version", HeaderValue::from_static("3.0"));
        assert_eq!(
            require_gateway_turn_contract(&headers).expect("v3 gateway header"),
            "3.0"
        );
        assert_eq!(
            require_gateway_turn_contract(&HeaderMap::new()).expect("header remains optional"),
            "3.0"
        );
        headers.insert("X-Contract-Version", HeaderValue::from_static("2.0"));
        assert_eq!(
            require_gateway_turn_contract(&headers).expect("legacy gateway header"),
            "2.0"
        );
        assert_eq!(
            gateway_turn_response_headers("3.0")
                .get("X-Contract-Version")
                .and_then(|value| value.to_str().ok()),
            Some("3.0")
        );
        assert_eq!(
            gateway_turn_response_headers("2.0")
                .get("X-Contract-Version")
                .and_then(|value| value.to_str().ok()),
            Some("2.0")
        );
    }

    #[test]
    fn gateway_turn_rejects_unknown_contract_header() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Contract-Version", HeaderValue::from_static("1.5"));
        let error = require_gateway_turn_contract(&headers).expect_err("unknown version");
        assert_eq!(error.code, "CONTRACT_VERSION_MISMATCH");
    }

    #[test]
    fn gateway_turn_uses_configured_service_auth() {
        let mut config = AppConfig::from_env();
        config.service_token = "voice-gateway-token".to_string();
        let mut headers = HeaderMap::new();

        let error = super::require_service_auth(&config, &headers)
            .expect_err("configured gateway turn auth must reject a missing token");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);

        headers.insert(
            "Authorization",
            HeaderValue::from_static("Bearer voice-gateway-token"),
        );
        super::require_service_auth(&config, &headers).expect("matching token");
    }

    #[test]
    fn notification_delivery_auth_fails_closed_without_current_key() {
        let mut config = AppConfig::from_env();
        config.service_token.clear();
        config.service_token_previous =
            "previous_must_not_stand_alone_0123456789abcdef".to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_static("Bearer previous_must_not_stand_alone_0123456789abcdef"),
        );

        let error = require_service_auth(&config, &headers).expect_err("current key is required");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn startup_rejects_malformed_or_colliding_service_credentials() {
        let mut config = AppConfig::from_env();
        config.harborbeacon_base_url = "http://127.0.0.1:4174".to_string();
        config.harborbeacon_web_api_token = "gate_to_beacon_current_0123456789abcdef".to_string();
        config.harborbeacon_token = config.harborbeacon_web_api_token.clone();
        config.service_token = "beacon_to_gate_current_0123456789abcdef".to_string();
        config.service_token_previous = "beacon_to_gate_previous_0123456789abcdef".to_string();
        validate_required_service_auth(&config).expect("directional credentials are valid");

        for malformed in [
            "too-short",
            "contains spaces 0123456789abcdef0123456789",
            "contains.period.0123456789abcdef0123456789",
        ] {
            config.service_token = malformed.to_string();
            assert!(
                validate_required_service_auth(&config).is_err(),
                "accepted malformed current credential: {malformed}"
            );
        }

        config.service_token = "beacon_to_gate_current_0123456789abcdef".to_string();
        config.service_token_previous = "too-short".to_string();
        assert!(validate_required_service_auth(&config).is_err());

        config.service_token_previous.clear();
        config.harborbeacon_web_api_token = config.service_token.clone();
        config.harborbeacon_token = config.harborbeacon_web_api_token.clone();
        assert!(
            validate_required_service_auth(&config).is_err(),
            "accepted the same current credential in both directions"
        );

        config.harborbeacon_web_api_token = "gate_to_beacon_current_0123456789abcdef".to_string();
        config.harborbeacon_token = "different_gate_token_0123456789abcdef0123".to_string();
        assert!(
            validate_required_service_auth(&config).is_err(),
            "accepted divergent Gate-to-Beacon caller credentials"
        );
    }
}
