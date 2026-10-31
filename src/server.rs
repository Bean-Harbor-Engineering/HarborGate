use crate::config::AppConfig;
use crate::error::GatewayError;
use crate::gateway::GatewayService;
use crate::runtime::{maybe_start_feishu_websocket_runtime, maybe_start_weixin_poll_runtime};
use crate::setup::SetupPortalService;
use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{header::CONTENT_TYPE, HeaderMap, Method, StatusCode};
use axum::response::{Html, IntoResponse, Redirect};
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

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub gateway: Arc<GatewayService>,
    pub setup: Arc<SetupPortalService>,
    pub feishu_websocket_started: Arc<AtomicBool>,
}

pub async fn serve(config: AppConfig) -> anyhow::Result<()> {
    let gateway = Arc::new(GatewayService::from_config(&config)?);
    let feishu_websocket_started = Arc::new(AtomicBool::new(false));
    maybe_start_configured_feishu_runtime(
        gateway.clone(),
        config.feishu.clone(),
        config.enable_feishu_websocket,
        feishu_websocket_started.clone(),
    );
    maybe_start_weixin_poll_runtime(gateway.clone(), config.enable_weixin_runtime);
    let state = AppState {
        config: config.clone(),
        setup: Arc::new(SetupPortalService::new(config.clone(), gateway.clone())),
        gateway,
        feishu_websocket_started,
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
        .route("/api/media/{attachment_id}", get(download_media))
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
        .route("/api/harbor-assistant", any(harbor_assistant_proxy_root))
        .route("/api/harbor-assistant/{*path}", any(harbor_assistant_proxy))
        .route("/api/beacon", any(beacon_proxy_root))
        .route("/api/beacon/{*path}", any(beacon_proxy))
        .route(
            "/api/harbor-gate/api/notifications/deliveries",
            post(notification_delivery),
        )
        .route("/api/notifications/deliveries", post(notification_delivery))
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
        .with_state(state)
}

async fn download_media(State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap) -> Result<impl IntoResponse, GatewayError> {
    let authorization = headers.get("Authorization").and_then(|s| s.to_str().ok()).unwrap_or("");
    let (mime, bytes) = state.gateway.read_media(&id, authorization)?;
    Ok(([(CONTENT_TYPE, mime), (axum::http::header::CACHE_CONTROL, "no-store".into())], bytes))
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
    Json(payload): Json<Value>,
) -> Result<Json<Value>, GatewayError> {
    Ok(Json(state.gateway.handle_gateway_turn(payload).await?))
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
        beacon_proxy_target_path(&path, uri.query()),
        "/api/beacon",
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
        harbor_assistant_proxy_target_path(&path, uri.query()),
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
    let url = format!("{base_url}{target_path}");
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).map_err(|err| {
            GatewayError::validation(format!("unsupported proxy method {}: {err}", method))
        })?;
    let mut request = Client::new()
        .request(reqwest_method, url)
        .body(body.to_vec());
    request = forward_beacon_headers(request, &headers, state.config.harborbeacon_token.as_str());
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
        return Ok(());
    }
    let authorization = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if authorization != format!("Bearer {}", config.service_token) {
        return Err(GatewayError::new(
            StatusCode::UNAUTHORIZED,
            "SERVICE_AUTH_FAILED",
            "Missing or invalid service token",
        ));
    }
    Ok(())
}

fn beacon_proxy_target_path(path: &str, query: Option<&str>) -> String {
    let tail = path.trim_start_matches('/');
    let base = if tail.is_empty() {
        "/api/state".to_string()
    } else {
        format!("/api/{tail}")
    };
    match query.filter(|value| !value.trim().is_empty()) {
        Some(query) => format!("{base}?{query}"),
        None => base,
    }
}

fn harbor_assistant_proxy_target_path(path: &str, query: Option<&str>) -> String {
    beacon_proxy_target_path(path, query)
}

fn forward_beacon_headers(
    mut request: reqwest::RequestBuilder,
    headers: &HeaderMap,
    harborbeacon_token: &str,
) -> reqwest::RequestBuilder {
    for name in [
        "content-type",
        "x-request-id",
        "x-trace-id",
        "x-harbor-user-id",
        "x-harbor-open-id",
        "x-harboros-user",
        "x-harbor-os-user",
    ] {
        if let Some(value) = headers.get(name) {
            request = request.header(name, value);
        }
    }
    if harborbeacon_token.trim().is_empty() {
        if let Some(value) = headers.get("authorization") {
            request = request.header("authorization", value);
        }
    } else {
        request = request.bearer_auth(harborbeacon_token.trim().to_string());
    }
    request
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
        beacon_proxy_target_path, harbor_assistant_proxy_target_path, require_service_contract,
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
            beacon_proxy_target_path("devices/camera-1/evidence", Some("user_id=u1")),
            "/api/devices/camera-1/evidence?user_id=u1"
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
}
