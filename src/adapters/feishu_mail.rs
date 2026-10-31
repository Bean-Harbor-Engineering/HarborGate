use crate::adapters::PlatformAdapter;
use crate::config::FeishuMailConfig;
use crate::error::GatewayError;
use crate::models::{InboundMessage, OutboundMessage};
use async_trait::async_trait;
use axum::http::StatusCode;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
struct TokenCache {
    tenant_access_token: String,
    expires_at: Option<Instant>,
    user_access_token: String,
    user_refresh_token: String,
    user_expires_at: Option<Instant>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct UserTokenState {
    #[serde(default)]
    user_access_token: String,
    #[serde(default)]
    user_refresh_token: String,
    #[serde(default)]
    access_expires_at_epoch_seconds: u64,
    #[serde(default)]
    refresh_expires_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, Default)]
struct MailTransportState {
    status: String,
    last_error: String,
    last_send_status: String,
    last_send_provider_message_id: String,
}

pub struct FeishuMailAdapter {
    settings: RwLock<FeishuMailConfig>,
    http: Client,
    token_cache: Mutex<TokenCache>,
    transport_state: Mutex<MailTransportState>,
}

impl FeishuMailAdapter {
    pub fn new(settings: FeishuMailConfig) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(settings.timeout_seconds.max(1)))
            .build()
            .unwrap_or_else(|_| Client::new());
        let status = if settings.configured() {
            "mail_idle".to_string()
        } else {
            "waiting_for_mail_credentials".to_string()
        };
        Self {
            settings: RwLock::new(settings),
            http,
            token_cache: Mutex::new(TokenCache::default()),
            transport_state: Mutex::new(MailTransportState {
                status,
                ..MailTransportState::default()
            }),
        }
    }

    fn settings_snapshot(&self) -> FeishuMailConfig {
        self.settings
            .read()
            .expect("settings lock poisoned")
            .clone()
    }

    async fn access_token(&self) -> Result<(String, &'static str), GatewayError> {
        let settings = self.settings_snapshot();
        let refresh_requested = !settings.user_refresh_token.trim().is_empty()
            || !settings.user_token_state_path.trim().is_empty();
        let app_credentials_configured =
            !settings.app_id.trim().is_empty() && !settings.app_secret.trim().is_empty();
        if refresh_requested && app_credentials_configured {
            return Ok((self.get_user_access_token().await?, "user_refresh_token"));
        }
        if !settings.user_access_token.trim().is_empty() {
            return Ok((
                settings.user_access_token.trim().to_string(),
                "user_access_token",
            ));
        }
        Ok((self.get_tenant_access_token().await?, "tenant_access_token"))
    }

    async fn get_user_access_token(&self) -> Result<String, GatewayError> {
        {
            let cache = self.token_cache.lock().expect("token cache lock poisoned");
            if !cache.user_access_token.is_empty()
                && cache
                    .user_expires_at
                    .is_some_and(|expires_at| Instant::now() < expires_at)
            {
                return Ok(cache.user_access_token.clone());
            }
        }
        let settings = self.settings_snapshot();
        let state = self.load_user_token_state(&settings)?;
        if let Some(state) = &state {
            if !state.user_access_token.trim().is_empty()
                && state.access_expires_at_epoch_seconds > now_epoch_seconds().saturating_add(60)
            {
                let ttl = Duration::from_secs(
                    state
                        .access_expires_at_epoch_seconds
                        .saturating_sub(now_epoch_seconds())
                        .saturating_sub(30)
                        .max(30),
                );
                let mut cache = self.token_cache.lock().expect("token cache lock poisoned");
                cache.user_access_token = state.user_access_token.trim().to_string();
                cache.user_refresh_token = state.user_refresh_token.trim().to_string();
                cache.user_expires_at = Some(Instant::now() + ttl);
                return Ok(cache.user_access_token.clone());
            }
        }

        let refresh_token = state
            .as_ref()
            .map(|state| state.user_refresh_token.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| settings.user_refresh_token.trim().to_string());
        if refresh_token.is_empty() {
            return Err(self.mail_error(
                "Feishu Mail authorization failed: user refresh token is not configured",
            ));
        }
        if settings.app_id.trim().is_empty() || settings.app_secret.trim().is_empty() {
            return Err(self.mail_error(
                "Feishu Mail authorization failed: app credentials are not configured",
            ));
        }
        let url = format!(
            "{}/open-apis/authen/v2/oauth/token",
            settings.auth_base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .json(&json!({
                "grant_type": "refresh_token",
                "client_id": settings.app_id,
                "client_secret": settings.app_secret,
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .map_err(|err| {
                self.mail_error(format!("Could not reach Feishu Mail refresh API: {err}"))
            })?;
        let payload = self.decode_openapi_response(response).await?;
        let data = payload.get("data").unwrap_or(&payload);
        let token = data
            .get("access_token")
            .or_else(|| data.get("user_access_token"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(
                self.mail_error("Feishu Mail authorization failed: refresh response was empty")
            );
        }
        let next_refresh_token = data
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(refresh_token.trim())
            .to_string();
        let expires_in = data
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(7200)
            .max(60) as u64;
        let refresh_expires_in = data
            .get("refresh_token_expires_in")
            .or_else(|| data.get("refresh_expires_in"))
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0) as u64;
        let access_expires_at = now_epoch_seconds().saturating_add(expires_in);
        let refresh_expires_at = if refresh_expires_in == 0 {
            state
                .as_ref()
                .map(|state| state.refresh_expires_at_epoch_seconds)
                .unwrap_or_default()
        } else {
            now_epoch_seconds().saturating_add(refresh_expires_in)
        };
        let next_state = UserTokenState {
            user_access_token: token.clone(),
            user_refresh_token: next_refresh_token.clone(),
            access_expires_at_epoch_seconds: access_expires_at,
            refresh_expires_at_epoch_seconds: refresh_expires_at,
        };
        self.save_user_token_state(&settings, &next_state)?;
        let ttl = Duration::from_secs(expires_in.saturating_sub(60).max(30));
        let mut cache = self.token_cache.lock().expect("token cache lock poisoned");
        cache.user_access_token = token.clone();
        cache.user_refresh_token = next_refresh_token;
        cache.user_expires_at = Some(Instant::now() + ttl);
        Ok(token)
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
        if settings.app_id.trim().is_empty() || settings.app_secret.trim().is_empty() {
            return Err(self.mail_error(
                "Feishu Mail authorization failed: app credentials are not configured",
            ));
        }
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
            .map_err(|err| {
                self.mail_error(format!("Could not reach Feishu Mail auth API: {err}"))
            })?;
        let payload = self.decode_openapi_response(response).await?;
        let token = payload
            .get("tenant_access_token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(self
                .mail_error("Feishu Mail authorization failed: tenant token response was empty"));
        }
        let expire = payload.get("expire").and_then(Value::as_i64).unwrap_or(0);
        let ttl = Duration::from_secs((expire - 60).max(60) as u64);
        let mut cache = self.token_cache.lock().expect("token cache lock poisoned");
        cache.tenant_access_token = token.clone();
        cache.expires_at = Some(Instant::now() + ttl);
        Ok(token)
    }

    async fn send_mail(
        &self,
        outbound: &OutboundMessage,
        token: &str,
    ) -> Result<Value, GatewayError> {
        let settings = self.settings_snapshot();
        let mailbox = settings.sender_mailbox.trim();
        let url = format!(
            "{}/open-apis/mail/v1/user_mailboxes/{}/messages/send",
            settings.base_url.trim_end_matches('/'),
            urlencoding::encode(mailbox)
        );
        let request = build_feishu_mail_request(outbound, &settings.default_from_name)?;
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .map_err(|err| self.mail_error(format!("Could not reach Feishu Mail API: {err}")))?;
        self.decode_openapi_response(response).await
    }

    async fn decode_openapi_response(
        &self,
        response: reqwest::Response,
    ) -> Result<Value, GatewayError> {
        let status = response.status();
        let raw = response.text().await.map_err(|err| {
            self.mail_error(format!("Could not read Feishu Mail API response: {err}"))
        })?;
        if !status.is_success() {
            let prefix = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                "Feishu Mail authorization failed"
            } else {
                "Feishu Mail API returned"
            };
            return Err(self.mail_error(format!("{prefix} HTTP {status}: {raw}")));
        }
        let payload: Value = serde_json::from_str(&raw).map_err(|err| {
            self.mail_error(format!("Feishu Mail API returned invalid JSON: {err}"))
        })?;
        if payload.get("code").and_then(Value::as_i64).unwrap_or(0) != 0 {
            let message = payload
                .get("msg")
                .or_else(|| payload.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            let lower = message.to_lowercase();
            let prefix = if lower.contains("auth")
                || lower.contains("token")
                || lower.contains("permission")
                || lower.contains("scope")
                || lower.contains("unauthorized")
                || lower.contains("forbidden")
            {
                "Feishu Mail authorization failed"
            } else {
                "Feishu Mail API returned code"
            };
            return Err(self.mail_error(format!(
                "{prefix} {}: {message}",
                payload.get("code").cloned().unwrap_or(Value::Null)
            )));
        }
        Ok(payload)
    }

    fn mail_error(&self, message: impl Into<String>) -> GatewayError {
        let settings = self.settings_snapshot();
        let message = redact_sensitive(&message.into(), &settings);
        GatewayError::new(StatusCode::BAD_GATEWAY, "PLATFORM_UNAVAILABLE", message)
    }

    fn load_user_token_state(
        &self,
        settings: &FeishuMailConfig,
    ) -> Result<Option<UserTokenState>, GatewayError> {
        let Some(path) = user_token_state_path(settings) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|err| {
            self.mail_error(format!(
                "Feishu Mail authorization failed: could not read token state: {err}"
            ))
        })?;
        serde_json::from_str(&raw).map(Some).map_err(|err| {
            self.mail_error(format!(
                "Feishu Mail authorization failed: token state is invalid JSON: {err}"
            ))
        })
    }

    fn save_user_token_state(
        &self,
        settings: &FeishuMailConfig,
        state: &UserTokenState,
    ) -> Result<(), GatewayError> {
        let Some(path) = user_token_state_path(settings) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                self.mail_error(format!(
                    "Feishu Mail authorization failed: could not create token state directory: {err}"
                ))
            })?;
        }
        let tmp = path.with_extension("tmp");
        let encoded = serde_json::to_vec_pretty(state).map_err(|err| {
            self.mail_error(format!(
                "Feishu Mail authorization failed: could not serialize token state: {err}"
            ))
        })?;
        fs::write(&tmp, encoded).map_err(|err| {
            self.mail_error(format!(
                "Feishu Mail authorization failed: could not write token state: {err}"
            ))
        })?;
        set_private_file_permissions(&tmp).map_err(|err| {
            self.mail_error(format!(
                "Feishu Mail authorization failed: could not protect token state: {err}"
            ))
        })?;
        fs::rename(&tmp, &path).map_err(|err| {
            self.mail_error(format!(
                "Feishu Mail authorization failed: could not replace token state: {err}"
            ))
        })
    }

    fn update_state(&self, update: impl FnOnce(&mut MailTransportState)) {
        let mut state = self
            .transport_state
            .lock()
            .expect("transport state lock poisoned");
        update(&mut state);
    }
}

#[async_trait]
impl PlatformAdapter for FeishuMailAdapter {
    fn name(&self) -> &str {
        "feishu_mail"
    }

    fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
        Err(GatewayError::validation(
            "Feishu Mail adapter is outbound-only",
        ))
    }

    async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
        let settings = self.settings_snapshot();
        if !settings.configured() {
            return Err(self.mail_error("Feishu Mail is not configured"));
        }
        if !outbound.attachments.is_empty() {
            return Err(GatewayError::validation(
                "Feishu Mail attachments are unsupported in the first delivery version",
            ));
        }
        let (token, auth_mode) = self.access_token().await?;
        self.update_state(|state| {
            state.status = "sending".to_string();
            state.last_send_status.clear();
            state.last_error.clear();
        });

        let response = match self.send_mail(&outbound, &token).await {
            Ok(response) => response,
            Err(error) => {
                let message = error.message.clone();
                self.update_state(|state| {
                    state.status = "error".to_string();
                    state.last_send_status = "failed".to_string();
                    state.last_error = message;
                });
                return Err(error);
            }
        };
        let message_id = response
            .pointer("/data/message_id")
            .or_else(|| response.pointer("/data/message/message_id"))
            .or_else(|| response.get("message_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let thread_id = response
            .pointer("/data/thread_id")
            .or_else(|| response.get("thread_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        self.update_state(|state| {
            state.status = "mail_idle".to_string();
            state.last_send_status = "sent".to_string();
            state.last_send_provider_message_id = message_id.clone();
            state.last_error.clear();
        });

        Ok(json!({
            "platform": "feishu_mail",
            "delivery": "feishu_mail",
            "sent": true,
            "message_id": message_id,
            "provider_message_id": message_id,
            "thread_id": thread_id,
            "timestamp": outbound.timestamp,
            "metadata": {
                "auth_mode": auth_mode,
                "sender_domain": mailbox_domain(&settings.sender_mailbox),
                "recipient_count": mail_recipient_count(&outbound),
            },
            "response": response,
        }))
    }

    fn profile(&self) -> Value {
        let settings = self.settings_snapshot();
        json!({
            "adapter_name": "feishu_mail",
            "surface_family": "mail",
            "transport_mode": "feishu_mail_v1",
            "enabled": settings.enabled,
            "configured": settings.configured(),
            "sender_configured": !settings.sender_mailbox.trim().is_empty(),
            "sender_domain": mailbox_domain(&settings.sender_mailbox),
            "auth_mode": settings.auth_mode(),
            "token_state_configured": !settings.user_token_state_path.trim().is_empty(),
            "supports_mentions": false,
            "supports_attachments": false,
            "supports_replies": false,
            "supports_updates": false,
            "supports_live_receive": false,
        })
    }

    fn status(&self) -> Value {
        let settings = self.settings_snapshot();
        let state = self
            .transport_state
            .lock()
            .expect("transport state lock poisoned")
            .clone();
        let last_provider = if state.last_send_provider_message_id.is_empty() {
            Value::Null
        } else {
            json!(state.last_send_provider_message_id)
        };
        json!({
            "status": state.status,
            "enabled": settings.enabled,
            "configured": settings.configured(),
            "sender_domain": mailbox_domain(&settings.sender_mailbox),
            "auth_mode": settings.auth_mode(),
            "token_state_configured": !settings.user_token_state_path.trim().is_empty(),
            "last_send_status": state.last_send_status,
            "last_send_provider_message_id": last_provider,
            "last_error": state.last_error,
        })
    }
}

pub(crate) fn build_feishu_mail_request(
    outbound: &OutboundMessage,
    default_from_name: &str,
) -> Result<Value, GatewayError> {
    let subject = metadata_string(outbound, "mail_subject")
        .or_else(|| metadata_string(outbound, "subject"))
        .or_else(|| {
            outbound
                .text
                .lines()
                .next()
                .map(str::trim)
                .map(ToString::to_string)
        })
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Harbor Outreach".to_string());
    let body_plain_text = metadata_string(outbound, "mail_body_plain_text")
        .or_else(|| metadata_string(outbound, "body_plain_text"))
        .unwrap_or_else(|| outbound.text.trim().to_string());
    let body_html = metadata_string(outbound, "mail_body_html")
        .or_else(|| metadata_string(outbound, "body_html"));
    let mut request = serde_json::Map::new();
    request.insert("subject".into(), json!(subject));
    request.insert(
        "to".into(),
        Value::Array(mail_recipient_list(outbound, "to")?),
    );
    if let Some(cc) = optional_mail_recipient_list(outbound, "cc")? {
        request.insert("cc".into(), Value::Array(cc));
    }
    if let Some(bcc) = optional_mail_recipient_list(outbound, "bcc")? {
        request.insert("bcc".into(), Value::Array(bcc));
    }
    if !body_plain_text.trim().is_empty() {
        request.insert("body_plain_text".into(), json!(body_plain_text));
    }
    if let Some(html) = body_html.filter(|value| !value.trim().is_empty()) {
        request.insert("body_html".into(), json!(html));
    }
    if let Some(dedupe_key) = metadata_string(outbound, "mail_dedupe_key")
        .or_else(|| metadata_string(outbound, "idempotency_key"))
        .filter(|value| !value.trim().is_empty())
    {
        request.insert("dedupe_key".into(), json!(dedupe_key));
    }
    if !default_from_name.trim().is_empty() {
        request.insert(
            "head_from".into(),
            json!({
                "name": default_from_name.trim(),
            }),
        );
    }
    Ok(Value::Object(request))
}

fn mail_recipient_list(outbound: &OutboundMessage, kind: &str) -> Result<Vec<Value>, GatewayError> {
    let recipients = optional_mail_recipient_list(outbound, kind)?;
    if let Some(recipients) = recipients {
        if !recipients.is_empty() {
            return Ok(recipients);
        }
    }
    if kind == "to" {
        let fallback = recipient_object_from_text(&outbound.chat_id, None);
        if let Some(recipient) = fallback {
            return Ok(vec![recipient]);
        }
    }
    Err(GatewayError::validation(format!(
        "Feishu Mail recipient list {kind} is required"
    )))
}

fn optional_mail_recipient_list(
    outbound: &OutboundMessage,
    kind: &str,
) -> Result<Option<Vec<Value>>, GatewayError> {
    let mut recipients = Vec::new();
    if let Some(value) = outbound
        .metadata
        .get("mail_recipients")
        .and_then(|value| value.get(kind))
    {
        recipients.extend(parse_recipient_value(value)?);
    }
    if let Some(value) = outbound
        .metadata
        .get("recipient")
        .and_then(|value| value.get(kind))
    {
        recipients.extend(parse_recipient_value(value)?);
    }
    if kind == "to" {
        if let Some(recipient) = outbound.metadata.get("recipient") {
            if let Some(value) = recipient_object_from_value(recipient)? {
                recipients.push(value);
            }
        }
    }
    Ok((!recipients.is_empty()).then_some(recipients))
}

fn parse_recipient_value(value: &Value) -> Result<Vec<Value>, GatewayError> {
    if let Some(items) = value.as_array() {
        let mut recipients = Vec::new();
        for item in items {
            if let Some(recipient) = recipient_object_from_value(item)? {
                recipients.push(recipient);
            }
        }
        return Ok(recipients);
    }
    Ok(recipient_object_from_value(value)?.into_iter().collect())
}

fn recipient_object_from_value(value: &Value) -> Result<Option<Value>, GatewayError> {
    match value {
        Value::String(raw) => Ok(recipient_object_from_text(raw, None)),
        Value::Object(object) => {
            let email = object
                .get("mail_address")
                .or_else(|| object.get("email"))
                .or_else(|| object.get("recipient_id"))
                .or_else(|| object.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let name = object.get("name").and_then(Value::as_str).map(str::trim);
            Ok(recipient_object_from_text(email, name))
        }
        Value::Null => Ok(None),
        _ => Err(GatewayError::validation(
            "Feishu Mail recipients must be strings or objects",
        )),
    }
}

fn recipient_object_from_text(email: &str, name: Option<&str>) -> Option<Value> {
    let email = email.trim();
    if email.is_empty() {
        return None;
    }
    let mut object = serde_json::Map::new();
    object.insert("mail_address".into(), json!(email));
    if let Some(name) = name.filter(|value| !value.trim().is_empty()) {
        object.insert("name".into(), json!(name));
    }
    Some(Value::Object(object))
}

fn metadata_string(outbound: &OutboundMessage, key: &str) -> Option<String> {
    outbound
        .metadata
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn mail_recipient_count(outbound: &OutboundMessage) -> usize {
    ["to", "cc", "bcc"]
        .iter()
        .filter_map(|kind| optional_mail_recipient_list(outbound, kind).ok().flatten())
        .map(|items| items.len())
        .sum()
}

fn mailbox_domain(mailbox: &str) -> String {
    mailbox
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_string())
        .unwrap_or_default()
}

fn user_token_state_path(settings: &FeishuMailConfig) -> Option<PathBuf> {
    let path = settings.user_token_state_path.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn set_private_file_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

fn redact_sensitive(message: &str, settings: &FeishuMailConfig) -> String {
    let mut redacted = message.to_string();
    for secret in [
        settings.user_access_token.trim(),
        settings.user_refresh_token.trim(),
        settings.app_secret.trim(),
        settings.app_id.trim(),
        settings.user_token_state_path.trim(),
    ] {
        if !secret.is_empty() {
            redacted = redacted.replace(secret, "[redacted]");
        }
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::utc_now_iso;
    use serde_json::json;

    fn outbound_fixture() -> OutboundMessage {
        let mut metadata = serde_json::Map::new();
        metadata.insert("mail_subject".into(), json!("Hello from Harbor"));
        metadata.insert("mail_body_plain_text".into(), json!("Plain body"));
        metadata.insert("mail_body_html".into(), json!("<p>HTML body</p>"));
        metadata.insert("mail_dedupe_key".into(), json!("idem-mail-1"));
        metadata.insert(
            "mail_recipients".into(),
            json!({
                "to": [{"mail_address": "lead@example.com", "name": "Lead"}],
                "cc": ["cc@example.com"],
                "bcc": [{"email": "bcc@example.com"}]
            }),
        );
        OutboundMessage {
            platform: "feishu_mail".into(),
            chat_id: "fallback@example.com".into(),
            text: "Hello from Harbor\n\nPlain body".into(),
            attachments: vec![],
            timestamp: utc_now_iso(),
            metadata,
        }
    }

    #[test]
    fn feishu_mail_request_builder_maps_subject_body_recipients_and_dedupe() {
        let request = build_feishu_mail_request(&outbound_fixture(), "Harbor Ops").unwrap();

        assert_eq!(request["subject"], json!("Hello from Harbor"));
        assert_eq!(request["body_plain_text"], json!("Plain body"));
        assert_eq!(request["body_html"], json!("<p>HTML body</p>"));
        assert_eq!(request["to"][0]["mail_address"], json!("lead@example.com"));
        assert_eq!(request["to"][0]["name"], json!("Lead"));
        assert_eq!(request["cc"][0]["mail_address"], json!("cc@example.com"));
        assert_eq!(request["bcc"][0]["mail_address"], json!("bcc@example.com"));
        assert_eq!(request["dedupe_key"], json!("idem-mail-1"));
        assert_eq!(request["head_from"]["name"], json!("Harbor Ops"));
    }

    #[test]
    fn feishu_mail_auth_mode_prefers_user_token() {
        let mut config = test_config("http://127.0.0.1:1");
        config.user_access_token = "user-token".into();
        assert_eq!(config.auth_mode(), "user_access_token");
        config.user_refresh_token = "refresh-token".into();
        assert_eq!(config.auth_mode(), "user_refresh_token");
        config.user_refresh_token.clear();
        config.user_access_token.clear();
        assert_eq!(config.auth_mode(), "tenant_access_token");
    }

    #[test]
    fn feishu_mail_redacts_tokens_from_provider_errors() {
        let mut config = test_config("http://127.0.0.1:1");
        config.user_access_token = "secret-user-token".into();
        config.user_refresh_token = "secret-refresh-token".into();
        let adapter = FeishuMailAdapter::new(config);

        let error = adapter.mail_error("secret-user-token and secret-refresh-token failed");

        assert!(!error.message.contains("secret-user-token"));
        assert!(!error.message.contains("secret-refresh-token"));
        assert!(error.message.contains("[redacted]"));
    }

    #[tokio::test]
    async fn feishu_mail_refreshes_user_token_and_persists_rotated_state() {
        let (base_url, request_handle) = spawn_http_responses(vec![
            r#"{"code":0,"access_token":"fresh-user-token","refresh_token":"fresh-refresh-token","expires_in":7200,"refresh_token_expires_in":2592000}"#,
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("feishu-mail-token.json");
        let mut config = test_config(&base_url);
        config.user_access_token = "stale-user-token".into();
        config.user_refresh_token = "initial-refresh-token".into();
        config.user_token_state_path = state_path.to_string_lossy().to_string();
        let adapter = FeishuMailAdapter::new(config);

        let (token, mode) = adapter.access_token().await.unwrap();
        let requests = request_handle.await.unwrap();
        let state: UserTokenState =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();

        assert_eq!(mode, "user_refresh_token");
        assert_eq!(token, "fresh-user-token");
        assert_eq!(state.user_access_token, "fresh-user-token");
        assert_eq!(state.user_refresh_token, "fresh-refresh-token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("POST /open-apis/authen/v2/oauth/token"));
        assert!(requests[0].contains(r#""client_id":"cli_test""#));
        assert!(requests[0].contains(r#""grant_type":"refresh_token""#));
        assert!(requests[0].contains(r#""refresh_token":"initial-refresh-token""#));
    }

    #[tokio::test]
    async fn feishu_mail_uses_fresh_token_state_without_refresh_request() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("feishu-mail-token.json");
        std::fs::write(
            &state_path,
            serde_json::to_string(&UserTokenState {
                user_access_token: "cached-user-token".into(),
                user_refresh_token: "cached-refresh-token".into(),
                access_expires_at_epoch_seconds: now_epoch_seconds() + 3600,
                refresh_expires_at_epoch_seconds: now_epoch_seconds() + 86400,
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = test_config("http://127.0.0.1:1");
        config.user_token_state_path = state_path.to_string_lossy().to_string();
        let adapter = FeishuMailAdapter::new(config);

        let (token, mode) = adapter.access_token().await.unwrap();

        assert_eq!(mode, "user_refresh_token");
        assert_eq!(token, "cached-user-token");
    }

    #[tokio::test]
    async fn feishu_mail_prefers_rotated_state_refresh_token_over_env_seed() {
        let (base_url, request_handle) = spawn_http_responses(vec![
            r#"{"code":0,"access_token":"next-user-token","refresh_token":"next-refresh-token","expires_in":7200,"refresh_token_expires_in":2592000}"#,
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("feishu-mail-token.json");
        std::fs::write(
            &state_path,
            serde_json::to_string(&UserTokenState {
                user_access_token: "expired-user-token".into(),
                user_refresh_token: "rotated-refresh-token".into(),
                access_expires_at_epoch_seconds: now_epoch_seconds().saturating_sub(60),
                refresh_expires_at_epoch_seconds: now_epoch_seconds() + 86400,
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = test_config(&base_url);
        config.user_refresh_token = "initial-env-seed-refresh-token".into();
        config.user_token_state_path = state_path.to_string_lossy().to_string();
        let adapter = FeishuMailAdapter::new(config);

        let (token, mode) = adapter.access_token().await.unwrap();
        let requests = request_handle.await.unwrap();
        let state: UserTokenState =
            serde_json::from_str(&std::fs::read_to_string(state_path).unwrap()).unwrap();

        assert_eq!(mode, "user_refresh_token");
        assert_eq!(token, "next-user-token");
        assert_eq!(state.user_refresh_token, "next-refresh-token");
        assert!(requests[0].contains(r#""refresh_token":"rotated-refresh-token""#));
        assert!(!requests[0].contains("initial-env-seed-refresh-token"));
    }

    #[tokio::test]
    async fn feishu_mail_keeps_static_user_token_when_refresh_config_is_incomplete() {
        let mut config = test_config("http://127.0.0.1:1");
        config.user_access_token = "static-user-token".into();
        config.user_token_state_path = "/tmp/feishu-mail-token.json".into();
        config.app_secret.clear();
        let adapter = FeishuMailAdapter::new(config);

        let (token, mode) = adapter.access_token().await.unwrap();

        assert_eq!(mode, "user_access_token");
        assert_eq!(token, "static-user-token");
    }

    fn test_config(base_url: &str) -> FeishuMailConfig {
        FeishuMailConfig {
            enabled: true,
            sender_mailbox: "sender@example.com".into(),
            user_access_token: String::new(),
            user_refresh_token: String::new(),
            user_token_state_path: String::new(),
            default_from_name: "Harbor Ops".into(),
            app_id: "cli_test".into(),
            app_secret: "secret_test".into(),
            base_url: base_url.into(),
            auth_base_url: base_url.into(),
            timeout_seconds: 2,
        }
    }

    async fn spawn_http_responses(
        bodies: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let mut request = Vec::new();
                loop {
                    let count = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer)
                        .await
                        .unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if http_request_complete(&request) {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                    .await
                    .unwrap();
                requests.push(String::from_utf8_lossy(&request).to_string());
            }
            requests
        });
        (base_url, handle)
    }

    fn http_request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.trim().eq_ignore_ascii_case("content-length"))
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        request.len() >= header_end + 4 + content_length
    }
}
