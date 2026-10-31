use crate::adapters::webhook::value_array;
use crate::adapters::PlatformAdapter;
use crate::config::FeishuConfig;
use crate::error::GatewayError;
use crate::harborbeacon::stable_id;
use crate::media::{
    convert_to_opus, fetch_beacon_audio, media_client, normalize_inbound_audio,
    read_bounded_response, MAX_MEDIA_BYTES,
};
use crate::models::{utc_now_iso, InboundMessage, OutboundMessage};
use async_trait::async_trait;
use axum::http::StatusCode;
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::debug;

const FEISHU_MESSAGE_EVENT_TYPE: &str = "im.message.receive_v1";
const FEISHU_CARD_ACTION_EVENT_TYPE: &str = "card.action.trigger";
const FEISHU_IMAGE_UPLOAD_ENDPOINT: &str = "/open-apis/im/v1/images";

#[derive(Debug, Default)]
struct TokenCache {
    tenant_access_token: String,
    expires_at: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
struct TransportState {
    status: String,
    connected: bool,
    last_error: String,
    last_connected_at: String,
    last_event_at: String,
    last_send_status: String,
    last_send_provider_message_id: String,
}

pub struct FeishuAdapter {
    settings: RwLock<FeishuConfig>,
    http: Client,
    token_cache: Mutex<TokenCache>,
    transport_state: Mutex<TransportState>,
    media_root: PathBuf,
    ffmpeg: PathBuf,
    beacon_origin: String,
}

#[derive(Debug, Clone)]
struct NativeImageAttachment {
    path: PathBuf,
    mime_type: String,
    file_name: String,
}

impl FeishuAdapter {
    pub fn new(settings: FeishuConfig) -> Self {
        Self::with_media(
            settings,
            PathBuf::from("data/media-outbound"),
            PathBuf::from("ffmpeg"),
            "http://127.0.0.1:4174".into(),
        )
    }

    pub fn with_media(
        settings: FeishuConfig,
        media_root: PathBuf,
        ffmpeg: PathBuf,
        beacon_origin: String,
    ) -> Self {
        let timeout = settings.timeout_seconds;
        let status = if settings.configured() {
            format!("{}_idle", settings.connection_mode)
        } else {
            "waiting_for_credentials".to_string()
        };
        Self {
            settings: RwLock::new(settings),
            http: media_client(timeout),
            token_cache: Mutex::new(TokenCache::default()),
            media_root,
            ffmpeg,
            beacon_origin,
            transport_state: Mutex::new(TransportState {
                status,
                ..TransportState::default()
            }),
        }
    }

    pub fn configured(&self) -> bool {
        self.settings_snapshot().configured()
    }

    pub fn settings(&self) -> FeishuConfig {
        self.settings_snapshot()
    }

    pub fn apply_settings(&self, settings: FeishuConfig) {
        {
            let mut guard = self.settings.write().expect("settings lock poisoned");
            *guard = settings.clone();
        }
        self.token_cache
            .lock()
            .expect("token cache lock poisoned")
            .tenant_access_token
            .clear();
        self.update_state(|state| {
            state.status = if settings.configured() {
                format!("{}_idle", settings.connection_mode)
            } else {
                "waiting_for_credentials".to_string()
            };
            state.connected = false;
            state.last_error.clear();
        });
    }

    pub fn settings_snapshot(&self) -> FeishuConfig {
        self.settings
            .read()
            .expect("settings lock poisoned")
            .clone()
    }

    pub fn webhook_path(&self) -> String {
        self.settings_snapshot().webhook_path
    }

    pub fn is_url_verification(&self, payload: &Value) -> bool {
        payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            == "url_verification"
    }

    pub fn build_url_verification_response(&self, payload: &Value) -> Result<Value, GatewayError> {
        self.validate_callback(payload)?;
        let challenge = payload
            .get("challenge")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if challenge.is_empty() {
            return Err(GatewayError::validation(
                "Feishu url_verification payload is missing challenge",
            ));
        }
        Ok(json!({"challenge": challenge}))
    }

    pub fn mark_websocket_event(&self) {
        self.update_state(|state| {
            state.status = "connected".to_string();
            state.connected = true;
            state.last_event_at = utc_now_iso();
            state.last_error.clear();
        });
    }

    pub fn mark_websocket_connected(&self) {
        self.update_state(|state| {
            state.status = "connected".to_string();
            state.connected = true;
            state.last_connected_at = utc_now_iso();
            state.last_error.clear();
        });
    }

    pub fn mark_websocket_error(&self, message: impl Into<String>) {
        let settings = self.settings_snapshot();
        let message = redact_sensitive(&message.into(), &settings);
        self.update_state(|state| {
            state.status = "error".to_string();
            state.connected = false;
            state.last_error = message;
        });
    }

    fn validate_callback(&self, payload: &Value) -> Result<(), GatewayError> {
        let settings = self.settings_snapshot();
        let expected = settings.verification_token.trim();
        if expected.is_empty() {
            return Ok(());
        }
        let received = payload
            .get("token")
            .and_then(Value::as_str)
            .or_else(|| payload.pointer("/header/token").and_then(Value::as_str))
            .unwrap_or("")
            .trim();
        if received.is_empty() && !self.is_url_verification(payload) {
            return Ok(());
        }
        if received != expected {
            return Err(GatewayError::validation(
                "Feishu callback token validation failed",
            ));
        }
        Ok(())
    }

    fn normalize_compact_payload(&self, payload: &Value) -> Result<InboundMessage, GatewayError> {
        let object = payload
            .as_object()
            .ok_or_else(|| GatewayError::validation("Feishu payload must be a JSON object"))?;
        let chat_id = str_field(object, "chat_id").unwrap_or_default();
        let user_id = str_field(object, "user_id").unwrap_or_default();
        let text = str_field(object, "text").unwrap_or_default();
        let chat_type = str_field(object, "chat_type").unwrap_or_else(|| "p2p".to_string());
        if chat_id.is_empty() {
            return Err(GatewayError::validation(
                "Feishu payload must include chat_id",
            ));
        }
        if user_id.is_empty() {
            return Err(GatewayError::validation(
                "Feishu payload must include user_id",
            ));
        }
        if text.is_empty() {
            return Err(GatewayError::validation("Feishu payload must include text"));
        }
        self.enforce_access_policy(
            &chat_type,
            &user_id,
            object
                .get("raw_content")
                .and_then(Value::as_str)
                .unwrap_or(&text),
            &value_array(object.get("mentions")),
        )?;
        Ok(InboundMessage {
            platform: "feishu".to_string(),
            chat_id,
            user_id,
            text,
            message_id: str_field(object, "message_id").unwrap_or_default(),
            chat_type,
            route_key: str_field(object, "route_key").unwrap_or_default(),
            session_id: str_field(object, "session_id").unwrap_or_default(),
            mentions: value_array(object.get("mentions")),
            attachments: value_array(object.get("attachments")),
            metadata: object
                .get("metadata")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            timestamp: utc_now_iso(),
            raw_payload: payload.clone(),
        })
    }

    fn normalize_raw_event(&self, payload: &Value) -> Result<InboundMessage, GatewayError> {
        let event_type = payload
            .pointer("/header/event_type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if event_type == FEISHU_CARD_ACTION_EVENT_TYPE {
            return self.normalize_card_action(payload);
        }
        if event_type != FEISHU_MESSAGE_EVENT_TYPE {
            return Err(GatewayError::validation(format!(
                "Unsupported Feishu event_type: {}",
                if event_type.is_empty() {
                    "unknown"
                } else {
                    event_type
                }
            )));
        }
        let message = payload
            .pointer("/event/message")
            .and_then(Value::as_object)
            .ok_or_else(|| GatewayError::validation("Feishu event is missing message"))?;
        let sender_open_id = payload
            .pointer("/event/sender/sender_id/open_id")
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .pointer("/event/sender/sender_id/user_id")
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .trim()
            .to_string();
        let chat_id = str_field(message, "chat_id").unwrap_or_default();
        let message_id = str_field(message, "message_id").unwrap_or_default();
        let chat_type = str_field(message, "chat_type").unwrap_or_else(|| "p2p".to_string());
        let message_type = str_field(message, "message_type").unwrap_or_default();
        let content = parse_message_content(message.get("content").unwrap_or(&Value::Null));
        let mentions = value_array(message.get("mentions"));
        let (text, attachments) = match message_type.as_str() {
            "text" => (
                content
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                vec![],
            ),
            "image" => {
                let image_key = content
                    .get("image_key")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let text = "飞书图片消息".to_string();
                let attachments = if image_key.is_empty() {
                    vec![]
                } else {
                    vec![json!({
                        "kind": "image",
                        "resource_key": image_key,
                        "provider": "feishu",
                        "message_id": message_id,
                    })]
                };
                (text, attachments)
            }
            "audio" => {
                let file_key = content
                    .get("file_key")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if file_key.is_empty() || message_id.is_empty() {
                    return Err(GatewayError::validation(
                        "Feishu audio message is missing file_key or message_id",
                    ));
                }
                (
                    String::new(),
                    vec![
                        json!({"kind":"audio", "provider":"feishu", "resource_key":file_key,
                    "message_id":message_id, "duration_ms":content.get("duration").and_then(Value::as_u64).unwrap_or(0)}),
                    ],
                )
            }
            other => {
                return Err(GatewayError::validation(format!(
                    "Unsupported Feishu message_type for Rust lane: {}",
                    if other.is_empty() { "unknown" } else { other }
                )));
            }
        };
        if sender_open_id.is_empty() {
            return Err(GatewayError::validation(
                "Feishu event is missing sender open_id/user_id",
            ));
        }
        if chat_id.is_empty() {
            return Err(GatewayError::validation("Feishu event is missing chat_id"));
        }
        if text.is_empty() && attachments.is_empty() {
            return Err(GatewayError::validation("Feishu message is empty"));
        }
        self.enforce_access_policy(
            &chat_type,
            &sender_open_id,
            message.get("content").and_then(Value::as_str).unwrap_or(""),
            &mentions,
        )?;
        Ok(InboundMessage {
            platform: "feishu".to_string(),
            chat_id,
            user_id: sender_open_id,
            text,
            message_id,
            chat_type,
            route_key: String::new(),
            session_id: String::new(),
            mentions,
            attachments,
            metadata: serde_json::Map::new(),
            timestamp: utc_now_iso(),
            raw_payload: payload.clone(),
        })
    }

    fn normalize_card_action(&self, payload: &Value) -> Result<InboundMessage, GatewayError> {
        let event_id = payload
            .pointer("/header/event_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let sender_open_id = payload
            .pointer("/event/operator/operator_id/open_id")
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .pointer("/event/operator/operator_id/user_id")
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .trim()
            .to_string();
        let chat_id = payload
            .pointer("/event/context/open_chat_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let command = payload
            .pointer("/event/action/value/command")
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .pointer("/event/action/value/text")
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .trim()
            .to_string();
        if chat_id.is_empty() {
            return Err(GatewayError::validation(
                "Feishu card action is missing open_chat_id",
            ));
        }
        if sender_open_id.is_empty() {
            return Err(GatewayError::validation(
                "Feishu card action is missing operator open_id/user_id",
            ));
        }
        if command.is_empty() {
            return Err(GatewayError::validation(
                "Feishu card action is missing command",
            ));
        }
        Ok(InboundMessage {
            platform: "feishu".to_string(),
            chat_id,
            user_id: sender_open_id,
            text: command,
            message_id: event_id,
            chat_type: "p2p".to_string(),
            route_key: String::new(),
            session_id: String::new(),
            mentions: vec![],
            attachments: vec![json!({"kind": "card_action", "provider": "feishu"})],
            metadata: serde_json::Map::new(),
            timestamp: utc_now_iso(),
            raw_payload: payload.clone(),
        })
    }

    fn enforce_access_policy(
        &self,
        chat_type: &str,
        sender_open_id: &str,
        raw_content: &str,
        mentions: &[Value],
    ) -> Result<(), GatewayError> {
        let settings = self.settings_snapshot();
        if !settings.allowed_users.is_empty()
            && !settings
                .allowed_users
                .iter()
                .any(|user| user == sender_open_id)
        {
            return Err(GatewayError::validation(
                "Feishu sender is not in FEISHU_ALLOWED_USERS",
            ));
        }
        if chat_type == "p2p" {
            return Ok(());
        }
        if settings.group_policy == "disabled" {
            return Err(GatewayError::validation(
                "Feishu group messages are disabled by FEISHU_GROUP_POLICY",
            ));
        }
        if !self.message_mentions_bot(raw_content, mentions) {
            return Err(GatewayError::validation(
                "Feishu group messages must explicitly @mention the bot",
            ));
        }
        Ok(())
    }

    fn message_mentions_bot(&self, raw_content: &str, mentions: &[Value]) -> bool {
        let settings = self.settings_snapshot();
        if raw_content.contains("@_all") {
            return true;
        }
        mentions.iter().any(|mention| {
            let open_id = mention
                .pointer("/id/open_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let user_id = mention
                .pointer("/id/user_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let name = mention.get("name").and_then(Value::as_str).unwrap_or("");
            (!settings.bot_open_id.is_empty() && open_id == settings.bot_open_id)
                || (!settings.bot_user_id.is_empty() && user_id == settings.bot_user_id)
                || (!settings.bot_name.is_empty() && name == settings.bot_name)
        })
    }

    pub async fn prepare_inbound_audio(
        &self,
        bytes: &[u8],
    ) -> Result<(Vec<u8>, u64), GatewayError> {
        normalize_inbound_audio(&self.ffmpeg, &self.media_root, bytes).await
    }

    pub async fn download_audio(
        &self,
        message_id: &str,
        file_key: &str,
    ) -> Result<(String, Vec<u8>), GatewayError> {
        let token = self.get_tenant_access_token().await?;
        let settings = self.settings_snapshot();
        let url = format!(
            "{}/open-apis/im/v1/messages/{}/resources/{}?type=file",
            settings.base_url.trim_end_matches('/'),
            urlencoding::encode(message_id),
            urlencoding::encode(file_key)
        );
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| self.feishu_error("Feishu audio download did not complete"))?;
        let mime = response
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("audio/opus")
            .to_string();
        if mime.to_ascii_lowercase().contains("application/json") {
            return Err(self.feishu_error("Feishu returned an error document instead of audio"));
        }
        let bytes = read_bounded_response(response).await?;
        Ok((mime, bytes))
    }

    fn checkpoint_path(&self, outbound: &OutboundMessage, index: usize) -> Option<PathBuf> {
        let turn = outbound
            .metadata
            .get("turn_id")
            .or_else(|| outbound.metadata.get("idempotency_key"))?
            .as_str()?;
        Some(self.media_root.join("deliveries").join(format!(
            "{}.json",
            stable_id(
                "part_",
                &format!(
                    "{}|{}|{}|{}",
                    outbound.platform, outbound.chat_id, turn, index
                ),
                40
            )
        )))
    }

    fn cached_part(
        &self,
        outbound: &OutboundMessage,
        index: usize,
    ) -> Result<Option<Value>, GatewayError> {
        let Some(path) = self.checkpoint_path(outbound, index) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&std::fs::read(path)?)?))
    }

    fn save_part(
        &self,
        outbound: &OutboundMessage,
        index: usize,
        response: &Value,
    ) -> Result<(), GatewayError> {
        if let Some(path) = self.checkpoint_path(outbound, index) {
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, serde_json::to_vec(response)?)?;
        }
        Ok(())
    }

    async fn upload_file(
        &self,
        path: &Path,
        file_name: &str,
        file_type: &str,
        duration_ms: u64,
        expected_sha256: Option<&str>,
        token: &str,
    ) -> Result<String, GatewayError> {
        let meta = tokio::fs::metadata(path).await?;
        if meta.len() == 0 || meta.len() > MAX_MEDIA_BYTES as u64 {
            return Err(GatewayError::validation(
                "Feishu file must contain 1 byte to 32 MiB",
            ));
        }
        let bytes = tokio::fs::read(path).await?;
        if bytes.len() > MAX_MEDIA_BYTES {
            return Err(GatewayError::validation("Feishu file exceeds 32 MiB"));
        }
        if let Some(expected) = expected_sha256 {
            use sha2::Digest;
            if format!("{:x}", sha2::Sha256::digest(&bytes)) != expected {
                return Err(GatewayError::validation(
                    "Original file changed before delivery",
                ));
            }
        }
        let part = Part::bytes(bytes).file_name(safe_multipart_filename(file_name));
        let mut form = Form::new()
            .text("file_type", file_type.to_string())
            .text("file_name", safe_multipart_filename(file_name))
            .part("file", part);
        if file_type == "opus" {
            form = form.text("duration", duration_ms.to_string());
        }
        let settings = self.settings_snapshot();
        let response = self
            .http
            .post(format!(
                "{}/open-apis/im/v1/files",
                settings.base_url.trim_end_matches('/')
            ))
            .bearer_auth(token)
            .multipart(form)
            .send()
            .await
            .map_err(|_| self.feishu_error("Feishu file upload did not complete"))?;
        let result = self.decode_openapi_response(response).await?;
        result
            .pointer("/data/file_key")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                self.feishu_error("Feishu file upload response did not include file_key")
            })
    }

    async fn send_file(
        &self,
        outbound: &OutboundMessage,
        file_key: &str,
        audio: bool,
        token: &str,
    ) -> Result<Value, GatewayError> {
        self.send_message_body(outbound, json!({"receive_id":outbound.chat_id,
            "msg_type":if audio {"audio"} else {"file"}, "content":serde_json::to_string(&json!({"file_key":file_key})).unwrap()}), token).await
    }

    async fn get_tenant_access_token(&self) -> Result<String, GatewayError> {
        {
            let cache = self.token_cache.lock().expect("token cache lock poisoned");
            if !cache.tenant_access_token.is_empty()
                && cache
                    .expires_at
                    .is_some_and(|expires_at| Instant::now() < expires_at)
            {
                return Ok(cache.tenant_access_token.clone());
            }
        }
        let settings = self.settings_snapshot();
        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            settings.auth_base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .json(&json!({
                "app_id": settings.app_id,
                "app_secret": settings.app_secret,
            }))
            .send()
            .await
            .map_err(|err| self.feishu_error(format!("Could not reach Feishu auth API: {err}")))?;
        let payload = self.decode_openapi_response(response).await?;
        let token = payload
            .get("tenant_access_token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(self.feishu_error(
                "Feishu tenant_access_token response did not include tenant_access_token",
            ));
        }
        let expire = payload.get("expire").and_then(Value::as_i64).unwrap_or(0);
        let ttl = Duration::from_secs((expire - 60).max(60) as u64);
        let mut cache = self.token_cache.lock().expect("token cache lock poisoned");
        cache.tenant_access_token = token.clone();
        cache.expires_at = Some(Instant::now() + ttl);
        Ok(token)
    }

    async fn send_message_body(
        &self,
        outbound: &OutboundMessage,
        mut body: Value,
        token: &str,
    ) -> Result<Value, GatewayError> {
        if let Some(identity) = outbound
            .metadata
            .get("turn_id")
            .or_else(|| outbound.metadata.get("idempotency_key"))
            .and_then(Value::as_str)
        {
            let part = outbound
                .metadata
                .get("native_part_index")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            body["uuid"] = json!(stable_id(
                "im_",
                &format!(
                    "{}|{}|{}|{}",
                    outbound.platform, outbound.chat_id, identity, part
                ),
                40
            ));
        }
        let settings = self.settings_snapshot();
        let reply_to_message_id = outbound
            .metadata
            .get("reply_to_message_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let update_message_id = outbound
            .metadata
            .get("update_message_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if !update_message_id.is_empty() {
            return Err(GatewayError::validation(
                "Feishu message update is not supported in this Rust lane yet",
            ));
        }
        let endpoint = if reply_to_message_id.is_empty() {
            "/open-apis/im/v1/messages?receive_id_type=chat_id".to_string()
        } else {
            format!("/open-apis/im/v1/messages/{reply_to_message_id}/reply")
        };
        let url = format!("{}{}", settings.base_url.trim_end_matches('/'), endpoint);
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|err| self.feishu_error(format!("Could not reach Feishu API: {err}")))?;
        let payload = self.decode_openapi_response(response).await?;
        if payload
            .pointer("/data/message_id")
            .and_then(Value::as_str)
            .is_none_or(|s| s.is_empty())
        {
            return Err(self.feishu_error("Feishu send response did not include message_id"));
        }
        Ok(payload)
    }

    async fn send_text(
        &self,
        outbound: &OutboundMessage,
        token: &str,
    ) -> Result<Value, GatewayError> {
        let body = json!({
            "receive_id": outbound.chat_id,
            "msg_type": "text",
            "content": serde_json::to_string(&json!({"text": outbound.text})).unwrap(),
        });
        self.send_message_body(outbound, body, token).await
    }

    async fn send_card(
        &self,
        outbound: &OutboundMessage,
        card: Value,
        token: &str,
    ) -> Result<Value, GatewayError> {
        let body = json!({
            "receive_id": outbound.chat_id,
            "msg_type": "interactive",
            "content": serde_json::to_string(&card).unwrap(),
        });
        self.send_message_body(outbound, body, token).await
    }

    async fn upload_image_attachment(
        &self,
        attachment: &NativeImageAttachment,
        token: &str,
    ) -> Result<String, GatewayError> {
        let bytes = tokio::fs::read(&attachment.path).await.map_err(|err| {
            self.feishu_error(format!(
                "Could not read image attachment {}: {err}",
                attachment.path.display()
            ))
        })?;
        if bytes.is_empty() {
            return Err(self.feishu_error(format!(
                "Feishu image artifact is empty: {}",
                attachment.path.display()
            )));
        }
        let part = Part::bytes(bytes)
            .file_name(safe_multipart_filename(&attachment.file_name))
            .mime_str(&attachment.mime_type)
            .map_err(|err| self.feishu_error(format!("Invalid image mime type: {err}")))?;
        let form = Form::new()
            .text("image_type", "message".to_string())
            .part("image", part);
        let settings = self.settings_snapshot();
        let url = format!(
            "{}{}",
            settings.base_url.trim_end_matches('/'),
            FEISHU_IMAGE_UPLOAD_ENDPOINT
        );
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .multipart(form)
            .send()
            .await
            .map_err(|err| self.feishu_error(format!("Could not reach Feishu image API: {err}")))?;
        let payload = self.decode_openapi_response(response).await?;
        let image_key = payload
            .pointer("/data/image_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if image_key.is_empty() {
            return Err(self.feishu_error("Feishu image upload response did not include image_key"));
        }
        Ok(image_key)
    }

    async fn send_image(
        &self,
        outbound: &OutboundMessage,
        image_key: &str,
        token: &str,
    ) -> Result<Value, GatewayError> {
        let body = json!({
            "receive_id": outbound.chat_id,
            "msg_type": "image",
            "content": serde_json::to_string(&json!({"image_key": image_key})).unwrap(),
        });
        self.send_message_body(outbound, body, token).await
    }

    async fn decode_openapi_response(
        &self,
        response: reqwest::Response,
    ) -> Result<Value, GatewayError> {
        let status = response.status();
        let raw = response.text().await.map_err(|err| {
            self.feishu_error(format!("Could not read Feishu API response: {err}"))
        })?;
        if !status.is_success() {
            return Err(self.feishu_error(format!("Feishu API returned HTTP {status}: {raw}")));
        }
        let payload: Value = serde_json::from_str(&raw)
            .map_err(|err| self.feishu_error(format!("Feishu API returned invalid JSON: {err}")))?;
        if payload.get("code").and_then(Value::as_i64).unwrap_or(0) != 0 {
            return Err(self.feishu_error(format!(
                "Feishu API returned code {}: {}",
                payload.get("code").cloned().unwrap_or(Value::Null),
                payload
                    .get("msg")
                    .or_else(|| payload.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
            )));
        }
        Ok(payload)
    }

    fn feishu_error(&self, message: impl Into<String>) -> GatewayError {
        let settings = self.settings_snapshot();
        let message = redact_sensitive(&message.into(), &settings);
        GatewayError::new(StatusCode::BAD_GATEWAY, "PLATFORM_UNAVAILABLE", message)
    }

    fn protocol_payload(&self, outbound: OutboundMessage) -> Value {
        let settings = self.settings_snapshot();
        json!({
            "platform": "feishu",
            "chat_id": outbound.chat_id,
            "text": outbound.text,
            "attachments": outbound.attachments,
            "timestamp": outbound.timestamp,
            "delivery": "feishu",
            "sent": false,
            "connection_mode": settings.connection_mode,
            "domain": settings.domain,
            "metadata": outbound.metadata,
            "request": build_text_payload(&outbound.chat_id, &outbound.text),
        })
    }

    fn update_state(&self, update: impl FnOnce(&mut TransportState)) {
        let mut state = self
            .transport_state
            .lock()
            .expect("transport state lock poisoned");
        update(&mut state);
    }
}

#[async_trait]
impl PlatformAdapter for FeishuAdapter {
    fn name(&self) -> &str {
        "feishu"
    }

    fn normalize_inbound(&self, payload: Value) -> Result<InboundMessage, GatewayError> {
        self.validate_callback(&payload)?;
        if payload.get("header").is_some() && payload.get("event").is_some() {
            self.normalize_raw_event(&payload)
        } else {
            self.normalize_compact_payload(&payload)
        }
    }

    async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
        let settings = self.settings_snapshot();
        if !(settings.configured() && settings.enable_live_send) {
            return Ok(self.protocol_payload(outbound));
        }

        let token = self.get_tenant_access_token().await?;
        self.update_state(|state| {
            state.status = "sending".into();
            state.last_send_status.clear();
            state.last_error.clear();
        });
        let mut responses = Vec::new();
        let mut image_keys = Vec::new();
        let mut native_kinds = Vec::new();
        let mut native_count = 0;
        let mut delivery_receipts = Vec::new();
        let result = async {
            if let Some(cached) = self.cached_part(&outbound, 0)? { responses.push(cached); }
            else {
                let response = if let Some(card) = outbound.metadata.get("feishu_card").or_else(|| outbound.metadata.get("structured_payload")).filter(|v| v.is_object()) {
                    Some(self.send_card(&outbound, card.clone(), &token).await?)
                } else if !outbound.text.trim().is_empty() { Some(self.send_text(&outbound, &token).await?) } else { None };
                if let Some(response) = response { self.save_part(&outbound, 0, &response)?; responses.push(response); }
            }
            let ordered = ordered_native_attachments(&outbound);
            for (index, artifact) in ordered.iter().enumerate() {
                let kind = artifact.get("kind").or_else(|| artifact.get("type")).and_then(Value::as_str).unwrap_or("");
                native_kinds.push(kind.to_string()); native_count += 1;
                if let Some(cached) = self.cached_part(&outbound, index + 1)? {
                    delivery_receipts.push(json!({"artifact_id":artifact.get("artifact_id"),"kind":kind,"order":index+1,
                        "provider_message_id":cached.pointer("/data/message_id"),"status":"sent"}));
                    responses.push(cached); continue;
                }
                let mut part_outbound = outbound.clone();
                part_outbound.metadata.insert("native_part_index".into(), json!(index + 1));
                let response = match kind {
                    "image" => {
                        let attachment = native_image_attachment_from_value(artifact)?;
                        let key = self.upload_image_attachment(&attachment, &token).await?;
                        image_keys.push(key.clone()); self.send_image(&part_outbound, &key, &token).await?
                    }
                    "file" => {
                        let raw = artifact.get("path").and_then(Value::as_str).unwrap_or("");
                        let path = Path::new(raw);
                        if !path.is_file() { return Err(GatewayError::validation("Original file is unavailable")); }
                        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("original");
                        let key = self.upload_file(path, name, "stream", 0, artifact.pointer("/metadata/sha256").and_then(Value::as_str), &token).await?;
                        self.send_file(&part_outbound, &key, false, &token).await?
                    }
                    "audio" => {
                        let bytes = fetch_beacon_audio(artifact, &self.beacon_origin).await?;
                        tokio::fs::create_dir_all(&self.media_root).await?;
                        let audio_id = stable_id("audio_", &format!("{}|{}|{}", outbound.chat_id, outbound.metadata.get("turn_id").unwrap_or(&Value::Null), index), 32);
                        let input = self.media_root.join(format!("{audio_id}.wav"));
                        let output = self.media_root.join(format!("{audio_id}.opus"));
                        tokio::fs::write(&input, bytes).await?;
                        let conversion = convert_to_opus(&self.ffmpeg, &input, &output).await;
                        let _ = tokio::fs::remove_file(&input).await;
                        conversion?;
                        let duration = artifact.pointer("/metadata/duration_ms").and_then(Value::as_u64).unwrap_or(0);
                        let upload = self.upload_file(&output, "reply.opus", "opus", duration, None, &token).await;
                        let _ = tokio::fs::remove_file(&output).await;
                        self.send_file(&part_outbound, &upload?, true, &token).await?
                    }
                    _ => return Err(GatewayError::validation("Unsupported Feishu native attachment kind")),
                };
                self.save_part(&outbound, index + 1, &response)?;
                delivery_receipts.push(json!({"artifact_id":artifact.get("artifact_id"),"kind":kind,"order":index+1,
                    "provider_message_id":response.pointer("/data/message_id"),"status":"sent"}));
                responses.push(response);
            }
            Ok::<(), GatewayError>(())
        }.await;

        if let Err(error) = result {
            let message = error.message.clone();
            self.update_state(|state| {
                state.status = if state.connected {
                    "connected"
                } else {
                    "error"
                }
                .to_string();
                state.last_send_status = "failed".to_string();
                state.last_error = message;
            });
            if !responses.is_empty() {
                let mut warning = outbound.clone();
                warning.text =
                    "部分结果发送失败，已送达的文字和图片仍可使用。请重试未送达部分。".into();
                warning.attachments.clear();
                warning
                    .metadata
                    .insert("native_part_index".into(), json!(999));
                if self.cached_part(&outbound, 999)?.is_none() {
                    if let Ok(receipt) = self.send_text(&warning, &token).await {
                        self.save_part(&outbound, 999, &receipt)?;
                    }
                }
                return Ok(
                    json!({"platform":"feishu", "chat_id":outbound.chat_id, "sent":false, "partial":true,
                    "status":"partial", "turn_id":outbound.metadata.get("turn_id"), "delivery_receipts":delivery_receipts,
                    "responses":responses, "error":{"code":error.code,"message":error.message},
                    "metadata":{"native_attachment_kinds":native_kinds,"native_attachment_fallback":false}}),
                );
            }
            return Err(error);
        }

        let message_ids: Vec<String> = responses
            .iter()
            .filter_map(|response| {
                response
                    .pointer("/data/message_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string)
            })
            .collect();
        let message_id = message_ids.last().cloned().unwrap_or_default();
        self.update_state(|state| {
            state.status = if state.connected {
                "connected".to_string()
            } else {
                format!("{}_idle", settings.connection_mode)
            };
            state.last_send_status = "sent".to_string();
            state.last_send_provider_message_id = message_id.clone();
            state.last_error.clear();
        });

        Ok(json!({
            "platform": "feishu",
            "chat_id": outbound.chat_id,
            "text": outbound.text,
            "timestamp": outbound.timestamp,
            "delivery": "feishu",
            "sent": true,
            "turn_id": outbound.metadata.get("turn_id"),
            "delivery_receipts": delivery_receipts,
            "message_id": message_id,
            "provider_message_id": message_id,
            "message_ids": message_ids,
            "attachments": outbound.attachments,
            "metadata": {
                "connection_mode": settings.connection_mode,
                "attachment_count": native_count,
                "native_image_reply": native_kinds.iter().any(|k| k == "image"),
                "native_audio_reply": native_kinds.iter().any(|k| k == "audio"),
                "native_file_reply": native_kinds.iter().any(|k| k == "file"),
                "native_attachment_count": native_count,
                "native_attachment_kind": if native_kinds.is_empty() { Value::Null } else { json!(native_kinds.join("+")) },
                "native_attachment_fallback": false,
                "feishu_image_keys": image_keys,
            },
            "responses": responses,
            "response": responses.last().cloned().unwrap_or_else(|| json!({})),
        }))
    }

    fn profile(&self) -> Value {
        let settings = self.settings_snapshot();
        json!({
            "adapter_name": "feishu",
            "surface_family": settings.domain,
            "transport_mode": settings.connection_mode,
            "supports_mentions": true,
            "supports_attachments": true,
            "supports_replies": true,
            "supports_updates": false,
            "supports_live_receive": settings.connection_mode == "websocket",
        })
    }

    fn status(&self) -> Value {
        let settings = self.settings_snapshot();
        let state = self
            .transport_state
            .lock()
            .expect("transport state lock poisoned")
            .clone();
        json!({
            "mode": settings.connection_mode,
            "status": state.status,
            "connected": state.connected,
            "last_error": redact_sensitive(&state.last_error, &settings),
            "last_connected_at": state.last_connected_at,
            "last_event_at": state.last_event_at,
            "last_send_status": state.last_send_status,
            "last_send_provider_message_id": state.last_send_provider_message_id,
            "configured": settings.configured(),
        })
    }
}

pub fn build_text_payload(chat_id: &str, text: &str) -> Value {
    json!({
        "receive_id": chat_id,
        "msg_type": "text",
        "content": serde_json::to_string(&json!({"text": text})).unwrap(),
    })
}

pub fn build_image_payload(chat_id: &str, image_key: &str) -> Value {
    json!({
        "receive_id": chat_id,
        "msg_type": "image",
        "content": serde_json::to_string(&json!({"image_key": image_key})).unwrap(),
    })
}

fn parse_message_content(value: &Value) -> serde_json::Map<String, Value> {
    if let Some(object) = value.as_object() {
        return object.clone();
    }
    if let Some(text) = value.as_str() {
        return serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_else(|| {
                let mut object = serde_json::Map::new();
                if !text.trim().is_empty() {
                    object.insert("text".into(), json!(text));
                }
                object
            });
    }
    serde_json::Map::new()
}

fn ordered_native_attachments(outbound: &OutboundMessage) -> Vec<Value> {
    let mut result: Vec<Value> = outbound
        .attachments
        .iter()
        .filter(|v| v.get("kind").and_then(Value::as_str) == Some("image"))
        .take(3)
        .cloned()
        .collect();
    result.extend(
        outbound
            .attachments
            .iter()
            .filter(|v| v.get("kind").and_then(Value::as_str) == Some("file"))
            .take(1)
            .cloned(),
    );
    result.extend(
        outbound
            .attachments
            .iter()
            .filter(|v| v.get("kind").and_then(Value::as_str) == Some("audio"))
            .take(1)
            .cloned(),
    );
    result
}

fn native_image_attachment_from_value(
    value: &Value,
) -> Result<NativeImageAttachment, GatewayError> {
    let object = value.as_object().ok_or_else(|| {
        GatewayError::validation("Feishu native image attachment must be an object")
    })?;
    let kind = str_field(object, "kind")
        .or_else(|| str_field(object, "type"))
        .unwrap_or_default();
    let mime_type = str_field(object, "mime_type").unwrap_or_default();
    if kind != "image" && !mime_type.starts_with("image/") {
        return Err(GatewayError::validation(
            "Feishu native image reply only supports image attachments",
        ));
    }
    let raw_path = str_field(object, "path").unwrap_or_default();
    let path = PathBuf::from(&raw_path);
    if raw_path.is_empty() || !Path::new(&path).is_file() {
        return Err(GatewayError::validation(
            "Feishu native image reply requires a readable same-host attachment path",
        ));
    }
    let file_name = object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("file_name"))
        .and_then(Value::as_str)
        .or_else(|| object.get("label").and_then(Value::as_str))
        .unwrap_or_else(|| {
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("image")
        })
        .trim()
        .to_string();
    let guessed = mime_guess::from_path(&path)
        .first_or_octet_stream()
        .to_string();
    Ok(NativeImageAttachment {
        path,
        mime_type: if mime_type.starts_with("image/") {
            mime_type
        } else if guessed.starts_with("image/") {
            guessed
        } else {
            "image/jpeg".to_string()
        },
        file_name,
    })
}

fn safe_multipart_filename(file_name: &str) -> String {
    let cleaned = file_name
        .replace('\\', "_")
        .replace('/', "_")
        .replace('"', "")
        .trim()
        .to_string();
    let ascii = cleaned
        .chars()
        .filter(|ch| ch.is_ascii() && !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if ascii.is_empty() {
        "image".to_string()
    } else {
        ascii
    }
}

fn str_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn redact_sensitive(text: &str, settings: &FeishuConfig) -> String {
    let mut redacted = text.to_string();
    for secret in [
        settings.app_id.as_str(),
        settings.app_secret.as_str(),
        settings.verification_token.as_str(),
    ] {
        if !secret.trim().is_empty() {
            redacted = redacted.replace(secret, "[REDACTED]");
        }
    }
    redacted
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PbHeader {
    #[prost(string, required, tag = "1")]
    pub key: String,
    #[prost(string, required, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PbFrame {
    #[prost(uint64, required, tag = "1")]
    pub seq_id: u64,
    #[prost(uint64, required, tag = "2")]
    pub log_id: u64,
    #[prost(int32, required, tag = "3")]
    pub service: i32,
    #[prost(int32, required, tag = "4")]
    pub method: i32,
    #[prost(message, repeated, tag = "5")]
    pub headers: Vec<PbHeader>,
    #[prost(string, optional, tag = "6")]
    pub payload_encoding: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub payload_type: Option<String>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub payload: Option<Vec<u8>>,
    #[prost(string, optional, tag = "9")]
    pub log_id_new: Option<String>,
}

impl PbFrame {
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.key == key)
            .map(|header| header.value.as_str())
    }
}

pub fn build_response_frame(request_frame: &PbFrame) -> Vec<u8> {
    use prost::Message;
    let mut headers = request_frame.headers.clone();
    headers.push(PbHeader {
        key: "biz_rt".to_string(),
        value: "0".to_string(),
    });
    PbFrame {
        seq_id: request_frame.seq_id,
        log_id: request_frame.log_id,
        service: request_frame.service,
        method: request_frame.method,
        headers,
        payload_encoding: None,
        payload_type: None,
        payload: Some(br#"{"code":200}"#.to_vec()),
        log_id_new: None,
    }
    .encode_to_vec()
}

pub fn parse_ws_frame_payload(bytes: &[u8]) -> Result<Option<Value>, GatewayError> {
    use prost::Message;
    let frame = PbFrame::decode(bytes).map_err(|err| {
        GatewayError::validation(format!("Could not decode Feishu websocket frame: {err}"))
    })?;
    let payload = match frame.payload {
        Some(payload) if !payload.is_empty() => payload,
        _ => return Ok(None),
    };
    let text = String::from_utf8(payload).map_err(|err| {
        GatewayError::validation(format!(
            "Feishu websocket frame payload is not UTF-8: {err}"
        ))
    })?;
    let value = serde_json::from_str(&text).map_err(|err| {
        GatewayError::validation(format!("Feishu websocket payload is not JSON: {err}"))
    })?;
    debug!("decoded Feishu websocket frame payload");
    Ok(Some(value))
}

#[derive(Deserialize)]
pub struct WsEndpointResponse {
    pub code: Option<i64>,
    pub data: Option<WsEndpointData>,
}

#[derive(Deserialize)]
pub struct WsEndpointData {
    #[serde(rename = "URL")]
    pub url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FeishuConfig;
    use prost::Message;

    fn settings() -> FeishuConfig {
        FeishuConfig {
            app_id: "cli_xxx".into(),
            app_secret: "secret_xxx".into(),
            domain: "feishu".into(),
            connection_mode: "websocket".into(),
            allowed_users: vec![],
            group_policy: "open".into(),
            bot_open_id: "ou_bot_1".into(),
            bot_user_id: "".into(),
            bot_name: "".into(),
            verification_token: "".into(),
            webhook_path: "/feishu/webhook".into(),
            base_url: "https://open.feishu.cn".into(),
            auth_base_url: "https://open.feishu.cn".into(),
            enable_live_send: false,
            timeout_seconds: 20,
        }
    }

    #[test]
    fn normalizes_text_event() {
        let adapter = FeishuAdapter::new(settings());
        let inbound = adapter
            .normalize_inbound(json!({
                "header": {"event_type": "im.message.receive_v1"},
                "event": {
                    "sender": {"sender_id": {"open_id": "ou_user_1"}},
                    "message": {
                        "chat_id": "oc_1",
                        "chat_type": "p2p",
                        "message_id": "om_1",
                        "message_type": "text",
                        "content": "{\"text\":\"你好\"}"
                    }
                }
            }))
            .unwrap();
        assert_eq!(inbound.platform, "feishu");
        assert_eq!(inbound.text, "你好");
        assert_eq!(inbound.message_id, "om_1");
    }

    #[test]
    fn normalizes_image_event_with_attachment() {
        let adapter = FeishuAdapter::new(settings());
        let inbound = adapter
            .normalize_inbound(json!({
                "header": {"event_type": "im.message.receive_v1"},
                "event": {
                    "sender": {"sender_id": {"open_id": "ou_user_1"}},
                    "message": {
                        "chat_id": "oc_1",
                        "chat_type": "p2p",
                        "message_id": "om_1",
                        "message_type": "image",
                        "content": "{\"image_key\":\"img_1\"}"
                    }
                }
            }))
            .unwrap();
        assert_eq!(inbound.text, "飞书图片消息");
        assert_eq!(inbound.attachments[0]["resource_key"], "img_1");
    }

    #[test]
    fn card_action_becomes_inbound_text() {
        let adapter = FeishuAdapter::new(settings());
        let inbound = adapter
            .normalize_inbound(json!({
                "header": {"event_id": "evt_card_1", "event_type": "card.action.trigger"},
                "event": {
                    "operator": {"operator_id": {"open_id": "ou_user_1"}},
                    "action": {"value": {"command": "继续"}},
                    "context": {"open_chat_id": "oc_1"}
                }
            }))
            .unwrap();
        assert_eq!(inbound.text, "继续");
        assert_eq!(inbound.message_id, "evt_card_1");
    }

    #[test]
    fn builds_text_and_image_payloads() {
        let text = build_text_payload("oc_1", "reply");
        assert_eq!(text["msg_type"], "text");
        assert_eq!(
            serde_json::from_str::<Value>(text["content"].as_str().unwrap()).unwrap()["text"],
            "reply"
        );

        let image = build_image_payload("oc_1", "img_1");
        assert_eq!(image["msg_type"], "image");
        assert_eq!(
            serde_json::from_str::<Value>(image["content"].as_str().unwrap()).unwrap()["image_key"],
            "img_1"
        );
    }

    #[test]
    fn parses_ws_frame_payload() {
        let payload = json!({"header": {"event_type": "im.message.receive_v1"}}).to_string();
        let frame = PbFrame {
            seq_id: 1,
            log_id: 1,
            service: 100,
            method: 1,
            headers: vec![],
            payload_encoding: None,
            payload_type: Some("json".into()),
            payload: Some(payload.into_bytes()),
            log_id_new: None,
        };
        let mut bytes = Vec::new();
        frame.encode(&mut bytes).unwrap();
        let decoded = parse_ws_frame_payload(&bytes).unwrap().unwrap();
        assert_eq!(decoded["header"]["event_type"], "im.message.receive_v1");
    }
}
