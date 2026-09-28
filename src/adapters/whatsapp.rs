//! Meta WhatsApp Business Platform transport. No household/device authority is
//! inferred from phone numbers: Beacon still resolves the authenticated route.
use super::{PlatformAdapter, PreparedOutbound};
#[cfg(test)]
use crate::models::utc_now_iso;
use crate::{
    error::GatewayError,
    models::{InboundMessage, OutboundMessage},
    navi_fleet::Selection,
};
use async_trait::async_trait;
use axum::http::StatusCode;
use hmac::{Hmac, Mac};
use reqwest::{
    multipart::{Form, Part},
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use sha2::Sha256;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

const MAX_INBOUND_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const INBOUND_MEDIA_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InboundMediaReference {
    pub attachment_id: String,
    pub provider_media_id: String,
    pub mime_type: String,
    pub sha256: String,
    pub recipient: String,
    pub route_key: String,
    pub conversation_handle: String,
    pub selection: Option<Selection>,
    pub expires_at: i64,
}

#[derive(Debug)]
pub(crate) struct InboundMediaBytes {
    pub bytes: Vec<u8>,
    pub mime_type: String,
    pub sha256: String,
}

#[derive(Clone, Default)]
pub struct WhatsAppConfig {
    pub phone_number_id: String,
    pub business_number: String,
    pub app_secret: String,
    pub verify_token: String,
    pub access_token: String,
    pub graph_version: String,
}
impl WhatsAppConfig {
    pub fn from_env() -> Self {
        let get = |name| std::env::var(name).unwrap_or_default();
        Self {
            phone_number_id: get("WHATSAPP_PHONE_NUMBER_ID"),
            business_number: get("WHATSAPP_BUSINESS_NUMBER"),
            app_secret: get("WHATSAPP_APP_SECRET"),
            verify_token: get("WHATSAPP_VERIFY_TOKEN"),
            access_token: get("WHATSAPP_ACCESS_TOKEN"),
            graph_version: get("WHATSAPP_GRAPH_VERSION"),
        }
    }
    pub fn configured(&self) -> bool {
        digits(&self.phone_number_id)
            && digits(&self.business_number)
            && self.app_secret.len() >= 16
            && self.verify_token.len() >= 32
            && !self.access_token.is_empty()
            && valid_version(&self.graph_version)
    }
}

pub struct WhatsAppAdapter {
    config: WhatsAppConfig,
    http: Client,
    cache: PathBuf,
}
impl WhatsAppAdapter {
    pub fn new(config: WhatsAppConfig, cache: PathBuf) -> Self {
        Self {
            config,
            cache,
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("WhatsApp HTTP client"),
        }
    }
    pub fn verification(
        &self,
        mode: &str,
        token: &str,
        challenge: &str,
    ) -> Result<String, GatewayError> {
        self.require_config()?;
        if mode != "subscribe"
            || challenge.len() > 256
            || challenge.is_empty()
            || !constant_time_eq::constant_time_eq(
                token.as_bytes(),
                self.config.verify_token.as_bytes(),
            )
        {
            return Err(denied());
        }
        Ok(challenge.into())
    }
    pub fn verified_messages(
        &self,
        body: &[u8],
        signature: &str,
    ) -> Result<Vec<Value>, GatewayError> {
        self.require_config()?;
        if body.len() > 1024 * 1024 {
            return Err(GatewayError::validation("WhatsApp webhook is too large"));
        }
        let signature = signature.strip_prefix("sha256=").ok_or_else(denied)?;
        if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(denied());
        }
        let signature = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&signature[i..i + 2], 16).map_err(|_| denied()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(self.config.app_secret.as_bytes())
            .map_err(|_| denied())?;
        mac.update(body);
        mac.verify_slice(&signature).map_err(|_| denied())?;
        let payload: Value = serde_json::from_slice(body)
            .map_err(|_| GatewayError::validation("Invalid WhatsApp webhook"))?;
        if payload["object"] != "whatsapp_business_account" {
            return Err(GatewayError::validation("Invalid WhatsApp account event"));
        }
        let mut messages = Vec::new();
        for entry in payload["entry"].as_array().into_iter().flatten() {
            for change in entry["changes"].as_array().into_iter().flatten() {
                let value = &change["value"];
                if change["field"] != "messages"
                    || value
                        .pointer("/metadata/phone_number_id")
                        .and_then(Value::as_str)
                        != Some(&self.config.phone_number_id)
                {
                    continue;
                }
                for message in value["messages"].as_array().into_iter().flatten() {
                    if message["type"] == "text" || message["type"] == "image" {
                        messages.push(json!({"phone_number_id":self.config.phone_number_id,"message":message}));
                    }
                    if messages.len() > 100 {
                        return Err(GatewayError::validation(
                            "WhatsApp webhook contains too many messages",
                        ));
                    }
                }
            }
        }
        Ok(messages)
    }
    fn require_config(&self) -> Result<(), GatewayError> {
        if self.config.configured() {
            Ok(())
        } else {
            Err(GatewayError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "WHATSAPP_NOT_CONFIGURED",
                "WhatsApp is not configured. Continue in the Navi web app.",
            ))
        }
    }
    fn inbox(&self) -> Result<PathBuf, GatewayError> {
        let path = self
            .cache
            .parent()
            .ok_or_else(denied)?
            .join("whatsapp-inbox");
        std::fs::create_dir_all(&path)
            .map_err(|_| GatewayError::infrastructure("WhatsApp inbox is unavailable"))?;
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(denied());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(path)
    }
    fn media_directory(&self) -> Result<PathBuf, GatewayError> {
        let path = self
            .cache
            .parent()
            .ok_or_else(denied)?
            .join("whatsapp-media");
        std::fs::create_dir_all(&path).map_err(|_| {
            GatewayError::infrastructure("WhatsApp media references are unavailable")
        })?;
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(denied());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(path)
    }
    pub(crate) fn stage_inbound_media(
        &self,
        payload: &Value,
        inbound: &InboundMessage,
        selection: Option<&Selection>,
        conversation_handle: &str,
    ) -> Result<(), GatewayError> {
        let Some(part) = inbound.attachments.first() else {
            return Ok(());
        };
        let media_id = payload
            .pointer("/message/image/id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let attachment_id = part["attachment_id"].as_str().unwrap_or("");
        let expected_id = crate::harborbeacon::stable_id(
            "wa_image_",
            &json!([self.config.phone_number_id, inbound.message_id, media_id]).to_string(),
            24,
        );
        let occurred = chrono::DateTime::parse_from_rfc3339(&inbound.timestamp)
            .map_err(|_| GatewayError::validation("Invalid WhatsApp image timestamp"))?
            .timestamp();
        let expires_at = occurred.saturating_add(INBOUND_MEDIA_TTL_SECONDS);
        if inbound.platform != "whatsapp"
            || inbound.attachments.len() != 1
            || attachment_id != expected_id
            || !valid_media_id(media_id)
            || conversation_handle.trim().is_empty()
            || payload["message"]["image"]["mime_type"] != part["mime_type"]
            || payload["message"]["image"]["sha256"]
                .as_str()
                .is_none_or(|hash| {
                    !hash.eq_ignore_ascii_case(part["metadata"]["sha256"].as_str().unwrap_or(""))
                })
            || expires_at <= chrono::Utc::now().timestamp()
        {
            return Err(GatewayError::validation("Invalid WhatsApp image reference"));
        }
        let record = InboundMediaReference {
            attachment_id: expected_id,
            provider_media_id: media_id.to_string(),
            mime_type: part["mime_type"].as_str().unwrap_or("").to_string(),
            sha256: part["metadata"]["sha256"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            recipient: inbound.chat_id.clone(),
            route_key: inbound.route_key.clone(),
            conversation_handle: conversation_handle.to_string(),
            selection: selection.cloned(),
            expires_at,
        };
        let directory = self.media_directory()?;
        use fs2::FileExt;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join("media.lock"))?;
        lock.lock_exclusive()?;
        let path = directory.join(format!("{}.json", record.attachment_id));
        if path.exists() {
            let existing: InboundMediaReference = serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|_| GatewayError::infrastructure("WhatsApp media reference is invalid"))?;
            if existing != record {
                return Err(GatewayError::validation(
                    "Conflicting WhatsApp media reference",
                ));
            }
            return Ok(());
        }
        if std::fs::read_dir(&directory)?.count() > 10000 {
            return Err(GatewayError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "WHATSAPP_MEDIA_STORE_FULL",
                "WhatsApp image intake is at capacity",
            ));
        }
        let value = serde_json::to_value(record)
            .map_err(|_| GatewayError::infrastructure("WhatsApp media reference is invalid"))?;
        inbox_write(&path, &value)
    }
    pub(crate) fn inbound_media_reference(
        &self,
        attachment_id: &str,
    ) -> Result<InboundMediaReference, GatewayError> {
        if !valid_attachment_id(attachment_id) {
            return Err(GatewayError::validation("Invalid WhatsApp attachment ID"));
        }
        let path = self
            .media_directory()?
            .join(format!("{attachment_id}.json"));
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| media_not_found())?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err(media_not_found());
        }
        let record: InboundMediaReference = serde_json::from_slice(&std::fs::read(&path)?)
            .map_err(|_| GatewayError::infrastructure("WhatsApp media reference is invalid"))?;
        if record.attachment_id != attachment_id || !valid_media_id(&record.provider_media_id) {
            return Err(media_not_found());
        }
        if record.expires_at <= chrono::Utc::now().timestamp() {
            let _ = std::fs::remove_file(path);
            return Err(GatewayError::new(
                StatusCode::GONE,
                "WHATSAPP_MEDIA_EXPIRED",
                "WhatsApp image reference expired",
            ));
        }
        Ok(record)
    }
    pub(crate) fn prune_expired_media_references(&self) -> Result<usize, GatewayError> {
        let directory = self.media_directory()?;
        let mut removed = 0;
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() > 4096 {
                continue;
            }
            let Ok(record) =
                serde_json::from_slice::<InboundMediaReference>(&std::fs::read(&path)?)
            else {
                continue;
            };
            if record.expires_at <= chrono::Utc::now().timestamp() {
                std::fs::remove_file(path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
    pub(crate) async fn download_inbound_media(
        &self,
        record: &InboundMediaReference,
    ) -> Result<InboundMediaBytes, GatewayError> {
        self.require_config()?;
        let response = self
            .http
            .get(format!(
                "https://graph.facebook.com/{}/{}",
                self.config.graph_version, record.provider_media_id
            ))
            .query(&[("phone_number_id", &self.config.phone_number_id)])
            .bearer_auth(&self.config.access_token)
            .send()
            .await
            .map_err(|_| media_unavailable())?;
        if !response.status().is_success() {
            return Err(media_unavailable());
        }
        let metadata_bytes = read_bounded(response, 4096).await?;
        let metadata: Value =
            serde_json::from_slice(&metadata_bytes).map_err(|_| media_invalid())?;
        if metadata["id"] != record.provider_media_id
            || metadata["mime_type"] != record.mime_type
            || metadata["sha256"]
                .as_str()
                .is_none_or(|hash| !hash.eq_ignore_ascii_case(&record.sha256))
            || metadata["file_size"]
                .as_u64()
                .is_none_or(|size| size == 0 || size > MAX_INBOUND_IMAGE_BYTES as u64)
        {
            return Err(media_invalid());
        }
        let url = metadata["url"]
            .as_str()
            .and_then(trusted_media_url)
            .ok_or_else(media_invalid)?;
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.config.access_token)
            .send()
            .await
            .map_err(|_| media_unavailable())?;
        if !response.status().is_success()
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                != Some(record.mime_type.as_str())
        {
            return Err(media_invalid());
        }
        let bytes = read_bounded(response, MAX_INBOUND_IMAGE_BYTES).await?;
        if !image_bytes_match(record, &metadata, &bytes) {
            return Err(media_invalid());
        }
        Ok(InboundMediaBytes {
            bytes,
            mime_type: record.mime_type.clone(),
            sha256: record.sha256.clone(),
        })
    }
    pub fn enqueue(&self, messages: Vec<Value>) -> Result<usize, GatewayError> {
        use fs2::FileExt;
        let directory = self.inbox()?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join("inbox.lock"))?;
        lock.lock_exclusive()?;
        let mut count = 0;
        for payload in messages {
            let inbound = self.normalize_inbound(payload.clone())?;
            let id = format!(
                "{:x}",
                Sha256::digest(
                    json!([self.config.phone_number_id, inbound.message_id])
                        .to_string()
                        .as_bytes()
                )
            );
            let path = directory.join(format!("{id}.json"));
            if path.exists() {
                continue;
            }
            if std::fs::read_dir(&directory)?.count() > 10000 {
                return Err(GatewayError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "WHATSAPP_INBOX_FULL",
                    "WhatsApp inbox is at capacity",
                ));
            }
            inbox_write(
                &path,
                &json!({"id":id,"status":"pending","created_at":chrono::Utc::now().timestamp(),"attempts":0,"payload":payload}),
            )?;
            count += 1;
        }
        Ok(count)
    }
    pub fn claim_message(&self) -> Result<Option<Value>, GatewayError> {
        if !self.config.configured() {
            return Ok(None);
        }
        use fs2::FileExt;
        let directory = self.inbox()?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join("inbox.lock"))?;
        lock.lock_exclusive()?;
        let now = chrono::Utc::now().timestamp();
        for entry in std::fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if !std::fs::symlink_metadata(&path)?.is_file()
                || std::fs::metadata(&path)?.len() > 65536
            {
                continue;
            }
            let mut item: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            if item["created_at"].as_i64().unwrap_or(now) < now - 7 * 86400
                && item["status"] == "done"
            {
                std::fs::remove_file(path)?;
                continue;
            }
            if item["status"] != "done"
                && (item["created_at"].as_i64().unwrap_or(0) < now - 86400
                    || item["attempts"].as_u64().unwrap_or(0) >= 30)
            {
                item["status"] = json!("done");
                item["payload"] = Value::Null;
                item["error_code"] = json!("WHATSAPP_RECEIVE_EXPIRED");
                inbox_write(&path, &item)?;
                continue;
            }
            if item["status"] == "pending"
                || (item["status"] == "running"
                    && item["claimed_at"].as_i64().unwrap_or(now) < now - 600)
            {
                if item["retry_at"].as_i64().unwrap_or(0) > now {
                    continue;
                }
                item["status"] = json!("running");
                item["claimed_at"] = json!(now);
                item["attempts"] = json!(item["attempts"].as_u64().unwrap_or(0) + 1);
                inbox_write(&path, &item)?;
                return Ok(Some(item));
            }
        }
        Ok(None)
    }
    pub fn finish_message(&self, mut item: Value, retry: bool) -> Result<(), GatewayError> {
        use fs2::FileExt;
        let id = item["id"].as_str().unwrap_or("").to_owned();
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(denied());
        }
        let directory = self.inbox()?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join("inbox.lock"))?;
        lock.lock_exclusive()?;
        let path = directory.join(format!("{id}.json"));
        let current: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        if current["status"] != "running"
            || current["attempts"] != item["attempts"]
            || current["claimed_at"] != item["claimed_at"]
        {
            return Ok(());
        }
        if retry {
            item["status"] = json!("pending");
            item["retry_at"] = json!(chrono::Utc::now().timestamp() + 60);
        } else {
            item["status"] = json!("done");
            item["payload"] = Value::Null;
        }
        inbox_write(&path, &item)
    }
    fn endpoint(&self, suffix: &str) -> String {
        format!(
            "https://graph.facebook.com/{}/{}/{}",
            self.config.graph_version, self.config.phone_number_id, suffix
        )
    }
    async fn decode(&self, response: reqwest::Response) -> Result<Value, GatewayError> {
        let status = response.status();
        if !status.is_success() {
            return Err(GatewayError::new(
                StatusCode::BAD_GATEWAY,
                "WHATSAPP_DELIVERY_FAILED",
                "WhatsApp rejected the message. Check the account, recipient and messaging window.",
            ));
        }
        if response
            .content_length()
            .is_some_and(|size| size > 1024 * 1024)
        {
            return Err(GatewayError::infrastructure(
                "WhatsApp response is too large",
            ));
        }
        response
            .json()
            .await
            .map_err(|_| GatewayError::infrastructure("WhatsApp returned an invalid response"))
    }
    fn message_body(
        &self,
        outbound: &OutboundMessage,
        prepared: Option<&PreparedOutbound>,
    ) -> Result<Value, GatewayError> {
        if !digits(&outbound.chat_id) || outbound.text.chars().count() > 4096 {
            return Err(GatewayError::validation(
                "Invalid WhatsApp recipient or message size",
            ));
        }
        let mut body = json!({"messaging_product":"whatsapp","recipient_type":"individual","to":outbound.chat_id});
        if let Some(media) = prepared {
            body["type"] = json!("image");
            body["image"] = json!({"id":media.provider_media_id});
            if !outbound.text.is_empty() {
                if outbound.text.chars().count() > 1024 {
                    return Err(GatewayError::validation(
                        "WhatsApp image caption is too long",
                    ));
                }
                body["image"]["caption"] = json!(outbound.text);
            }
        } else {
            if !outbound.attachments.is_empty() || outbound.text.trim().is_empty() {
                return Err(GatewayError::validation(
                    "WhatsApp media must be prepared before delivery",
                ));
            }
            body["type"] = json!("text");
            body["text"] = json!({"preview_url":false,"body":outbound.text});
        }
        Ok(body)
    }
}

#[async_trait]
impl PlatformAdapter for WhatsAppAdapter {
    fn name(&self) -> &str {
        "whatsapp"
    }
    fn normalize_inbound(&self, payload: Value) -> Result<InboundMessage, GatewayError> {
        self.require_config()?;
        if payload["phone_number_id"].as_str() != Some(&self.config.phone_number_id) {
            return Err(denied());
        }
        let message = &payload["message"];
        let from = message["from"].as_str().unwrap_or("");
        let id = message["id"].as_str().unwrap_or("");
        let message_type = message["type"].as_str().unwrap_or_else(|| {
            if message
                .pointer("/text/body")
                .and_then(Value::as_str)
                .is_some()
            {
                "text"
            } else {
                ""
            }
        });
        let text = match message_type {
            "text" => message.pointer("/text/body"),
            "image" => message.pointer("/image/caption"),
            _ => {
                return Err(GatewayError::validation(
                    "Unsupported WhatsApp message type",
                ))
            }
        }
        .and_then(Value::as_str)
        .unwrap_or("");
        let occurred = message["timestamp"]
            .as_str()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
            .ok_or_else(|| GatewayError::validation("WhatsApp event timestamp is invalid"))?;
        if !digits(from)
            || id.is_empty()
            || id.len() > 512
            || (message_type == "text" && text.is_empty())
            || text.chars().count() > 4096
        {
            return Err(GatewayError::validation("Invalid WhatsApp message event"));
        }
        let attachments = if message_type == "image" {
            let media_id = message
                .pointer("/image/id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let mime_type = message
                .pointer("/image/mime_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let sha256 = message
                .pointer("/image/sha256")
                .and_then(Value::as_str)
                .unwrap_or("");
            if media_id.is_empty()
                || !valid_media_id(media_id)
                || !["image/jpeg", "image/png"].contains(&mime_type)
                || sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(GatewayError::validation("Invalid WhatsApp image event"));
            }
            vec![json!({
                "attachment_id": crate::harborbeacon::stable_id(
                    "wa_image_",
                    &json!([self.config.phone_number_id, id, media_id]).to_string(),
                    24,
                ),
                "type": "image",
                "mime_type": mime_type,
                "metadata": {
                    "provider": "whatsapp",
                    "sha256": sha256.to_ascii_lowercase(),
                },
            })]
        } else {
            vec![]
        };
        Ok(InboundMessage {
            platform: "whatsapp".into(),
            chat_id: from.into(),
            user_id: from.into(),
            text: text.into(),
            message_id: id.into(),
            chat_type: "p2p".into(),
            route_key: crate::harborbeacon::stable_id(
                "gw_route_",
                &json!(["whatsapp", self.config.phone_number_id, from]).to_string(),
                24,
            ),
            session_id: String::new(),
            mentions: vec![],
            attachments,
            metadata: serde_json::Map::new(),
            timestamp: occurred.to_rfc3339(),
            raw_payload: Value::Null,
        })
    }
    async fn prepare_outbound(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<Option<PreparedOutbound>, GatewayError> {
        self.require_config()?;
        if outbound.attachments.is_empty() {
            return Ok(None);
        }
        if outbound.attachments.len() != 1 {
            return Err(GatewayError::validation(
                "Prepare one WhatsApp image per delivery item",
            ));
        }
        let item = &outbound.attachments[0];
        let mime = item["mime_type"].as_str().unwrap_or("");
        if !["image/jpeg", "image/png"].contains(&mime) {
            return Err(GatewayError::validation(
                "WhatsApp supports JPEG or PNG image replies",
            ));
        }
        let path = Path::new(item["path"].as_str().unwrap_or(""));
        let relative = path.strip_prefix(&self.cache).map_err(|_| denied())?;
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(denied());
        }
        let root = cap_std::fs::Dir::open_ambient_dir(&self.cache, cap_std::ambient_authority())
            .map_err(|_| denied())?;
        let mut file = root.open(relative).map_err(|_| denied())?;
        if file.metadata().map_err(|_| denied())?.len() > 5 * 1024 * 1024 {
            return Err(GatewayError::validation("WhatsApp image is too large"));
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(5 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| denied())?;
        if bytes.is_empty() || bytes.len() > 5 * 1024 * 1024 {
            return Err(GatewayError::validation("Invalid WhatsApp image"));
        }
        let form = Form::new().text("messaging_product", "whatsapp").part(
            "file",
            Part::bytes(bytes)
                .file_name(if mime == "image/png" {
                    "snapshot.png"
                } else {
                    "snapshot.jpg"
                })
                .mime_str(mime)
                .map_err(|_| denied())?,
        );
        let response = self
            .http
            .post(self.endpoint("media"))
            .bearer_auth(&self.config.access_token)
            .multipart(form)
            .send()
            .await
            .map_err(|_| GatewayError::infrastructure("WhatsApp media upload is unavailable"))?;
        let result = self.decode(response).await?;
        let id = result["id"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                GatewayError::infrastructure("WhatsApp upload did not return a media ID")
            })?;
        Ok(Some(PreparedOutbound {
            provider_media_id: id.into(),
            provider_client_id: None,
            state: json!({"kind":"image"}),
        }))
    }
    async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
        let prepared = self.prepare_outbound(&outbound).await?;
        self.send_prepared_outbound(outbound, prepared.as_ref())
            .await
    }
    async fn send_prepared_outbound(
        &self,
        outbound: OutboundMessage,
        prepared: Option<&PreparedOutbound>,
    ) -> Result<Value, GatewayError> {
        self.require_config()?;
        let body = self.message_body(&outbound, prepared)?;
        let response = self
            .http
            .post(self.endpoint("messages"))
            .bearer_auth(&self.config.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|_| {
                GatewayError::new(
                    StatusCode::BAD_GATEWAY,
                    "WHATSAPP_DELIVERY_UNCERTAIN",
                    "WhatsApp delivery could not be confirmed",
                )
            })?;
        let result = self.decode(response).await?;
        let id = result
            .pointer("/messages/0/id")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| GatewayError::infrastructure("WhatsApp did not return a message ID"))?;
        Ok(
            json!({"platform":"whatsapp","delivery":"whatsapp","sent":true,"message_id":id,"provider_message_id":id}),
        )
    }
    fn profile(&self) -> Value {
        json!({"adapter_name":"whatsapp","surface_family":"whatsapp","transport_mode":"cloud_api",
        "configured":self.config.configured(),"supports_live_receive":self.config.configured(),"supports_attachments":true,
        "supports_replies":true,"supports_updates":false,"supports_mentions":false,
        "business_number":if self.config.configured(){Some(&self.config.business_number)}else{None}})
    }
}
fn denied() -> GatewayError {
    GatewayError::new(
        StatusCode::FORBIDDEN,
        "WHATSAPP_VERIFICATION_FAILED",
        "WhatsApp verification failed",
    )
}
fn inbox_write(path: &Path, value: &Value) -> Result<(), GatewayError> {
    atomicwrites::AtomicFile::new(path, atomicwrites::AllowOverwrite)
        .write(|file| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            serde_json::to_writer(&mut *file, value)?;
            file.sync_all()
        })
        .map_err(|_| GatewayError::infrastructure("WhatsApp inbox could not be saved"))
}
fn digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_digit())
}
fn valid_version(value: &str) -> bool {
    value.strip_prefix('v').is_some_and(|v| {
        v.split_once('.')
            .is_some_and(|(a, b)| digits(a) && digits(b))
    })
}
fn valid_media_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn valid_attachment_id(value: &str) -> bool {
    value.strip_prefix("wa_image_").is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
fn trusted_media_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.host_str() == Some("lookaside.fbsbx.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(url)
}
fn image_signature_matches(mime_type: &str, bytes: &[u8]) -> bool {
    match mime_type {
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        _ => false,
    }
}
fn image_bytes_match(record: &InboundMediaReference, metadata: &Value, bytes: &[u8]) -> bool {
    bytes.len() as u64 == metadata["file_size"].as_u64().unwrap_or(0)
        && image_signature_matches(&record.mime_type, bytes)
        && format!("{:x}", Sha256::digest(bytes)) == record.sha256
}
async fn read_bounded(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, GatewayError> {
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes as u64)
    {
        return Err(media_invalid());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| media_unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(media_invalid());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(media_invalid());
    }
    Ok(bytes)
}
fn media_not_found() -> GatewayError {
    GatewayError::new(
        StatusCode::NOT_FOUND,
        "WHATSAPP_MEDIA_NOT_FOUND",
        "WhatsApp image reference was not found",
    )
}
fn media_unavailable() -> GatewayError {
    GatewayError::new(
        StatusCode::BAD_GATEWAY,
        "WHATSAPP_MEDIA_UNAVAILABLE",
        "WhatsApp image is temporarily unavailable",
    )
}
fn media_invalid() -> GatewayError {
    GatewayError::new(
        StatusCode::BAD_GATEWAY,
        "WHATSAPP_MEDIA_INVALID",
        "WhatsApp returned an invalid image",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn adapter() -> WhatsAppAdapter {
        WhatsAppAdapter::new(
            WhatsAppConfig {
                phone_number_id: "123".into(),
                business_number: "15555550100".into(),
                app_secret: "test-app-secret-value".into(),
                verify_token: "x".repeat(32),
                access_token: "test-token".into(),
                graph_version: "v25.0".into(),
            },
            PathBuf::from("/tmp/gate-cache"),
        )
    }
    fn sign(body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"test-app-secret-value").unwrap();
        mac.update(body);
        format!(
            "sha256={}",
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
    #[test]
    fn challenge_and_disabled_config_fail_closed() {
        let a = adapter();
        assert_eq!(
            a.verification("subscribe", &"x".repeat(32), "1234")
                .unwrap(),
            "1234"
        );
        assert!(a.verification("subscribe", "wrong", "1234").is_err());
        assert!(!WhatsAppConfig::default().configured());
    }
    #[test]
    fn raw_signature_batch_and_phone_filter() {
        let a = adapter();
        let body=json!({"object":"whatsapp_business_account","entry":[{"changes":[{"field":"messages","value":{
            "metadata":{"phone_number_id":"123"},"messages":[{"from":"15555550101","id":"wamid.1","timestamp":"1700000000","type":"text","text":{"body":"Hi Navi"}},
            {"from":"15555550101","id":"wamid.2","timestamp":"1700000001","type":"text","text":{"body":"Next"}}]}}]}]}).to_string().into_bytes();
        let messages = a.verified_messages(&body, &sign(&body)).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            a.normalize_inbound(messages[0].clone()).unwrap().message_id,
            "wamid.1"
        );
        let mut tampered = body.clone();
        tampered.push(b' ');
        assert!(a.verified_messages(&tampered, &sign(&body)).is_err());
        assert!(a.verified_messages(&body, "sha256=bad").is_err());
        let other = String::from_utf8(body)
            .unwrap()
            .replace("123", "456")
            .into_bytes();
        assert!(a
            .verified_messages(&other, &sign(&other))
            .unwrap()
            .is_empty());
    }
    #[test]
    fn signed_image_event_preserves_caption_and_opaque_media_reference() {
        let mut a = adapter();
        let root = tempfile::tempdir().unwrap();
        a.cache = root.path().join("attachment-cache");
        let sha256 = "a".repeat(64);
        let body = json!({"object":"whatsapp_business_account","entry":[{"changes":[{"field":"messages","value":{
            "metadata":{"phone_number_id":"123"},"messages":[{"from":"15555550101","id":"wamid.image.1",
            "timestamp":"1700000000","type":"image","image":{"caption":"电表读数","id":"2754859441498128",
            "mime_type":"image/jpeg","sha256":sha256}}]}}]}]}).to_string().into_bytes();
        let messages = a.verified_messages(&body, &sign(&body)).unwrap();
        assert_eq!(messages.len(), 1);
        let inbound = a.normalize_inbound(messages[0].clone()).unwrap();
        assert_eq!(inbound.text, "电表读数");
        assert_eq!(inbound.attachments.len(), 1);
        let part = &inbound.attachments[0];
        assert_eq!(part["type"], "image");
        assert_eq!(part["mime_type"], "image/jpeg");
        assert!(part["metadata"].get("provider_media_id").is_none());
        assert_eq!(part["metadata"]["sha256"], "a".repeat(64));
        assert!(part.get("download").is_none());
        let turn = crate::harborbeacon::build_turn_request(&inbound, None, None);
        assert_eq!(turn["input"]["parts"][0], *part);
        assert_eq!(a.enqueue(messages.clone()).unwrap(), 1);
        assert_eq!(a.enqueue(messages).unwrap(), 0);
        let claimed = a.claim_message().unwrap().unwrap();
        assert_eq!(claimed["payload"]["message"]["id"], "wamid.image.1");
        a.finish_message(claimed, false).unwrap();
    }
    #[test]
    fn captionless_image_is_valid_but_invalid_media_metadata_is_rejected() {
        let a = adapter();
        let mut payload = json!({"phone_number_id":"123","message":{"from":"15555550101",
            "id":"wamid.image.2","timestamp":"1700000000","type":"image",
            "image":{"id":"2754859441498128","mime_type":"image/png","sha256":"b".repeat(64)}}});
        let inbound = a.normalize_inbound(payload.clone()).unwrap();
        assert!(inbound.text.is_empty());
        assert_eq!(inbound.attachments[0]["mime_type"], "image/png");
        for (key, value) in [
            ("id", json!("https://untrusted.example/photo")),
            ("mime_type", json!("image/svg+xml")),
            ("sha256", json!("not-a-digest")),
        ] {
            let original = payload["message"]["image"][key].clone();
            payload["message"]["image"][key] = value;
            assert!(a.normalize_inbound(payload.clone()).is_err());
            payload["message"]["image"][key] = original;
        }
    }
    #[test]
    fn media_reference_is_private_idempotent_and_expires() {
        let mut a = adapter();
        let root = tempfile::tempdir().unwrap();
        a.cache = root.path().join("attachment-cache");
        let payload = json!({"phone_number_id":"123","message":{"from":"15555550101",
            "id":"wamid.image.3","timestamp":chrono::Utc::now().timestamp().to_string(),"type":"image",
            "image":{"id":"2754859441498128","mime_type":"image/jpeg","sha256":"c".repeat(64)}}});
        let inbound = a.normalize_inbound(payload.clone()).unwrap();
        let id = inbound.attachments[0]["attachment_id"].as_str().unwrap();
        a.stage_inbound_media(&payload, &inbound, None, "conv-local-1")
            .unwrap();
        a.stage_inbound_media(&payload, &inbound, None, "conv-local-1")
            .unwrap();
        let reference = a.inbound_media_reference(id).unwrap();
        assert_eq!(reference.provider_media_id, "2754859441498128");
        assert!(reference.selection.is_none());
        assert!(a.inbound_media_reference("../outside").is_err());
        let path = a.media_directory().unwrap().join(format!("{id}.json"));
        let mut expired: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        expired["expires_at"] = json!(chrono::Utc::now().timestamp() - 1);
        inbox_write(&path, &expired).unwrap();
        assert_eq!(
            a.inbound_media_reference(id).unwrap_err().status,
            StatusCode::GONE
        );
        a.stage_inbound_media(&payload, &inbound, None, "conv-local-1")
            .unwrap();
        inbox_write(&path, &expired).unwrap();
        assert_eq!(a.prune_expired_media_references().unwrap(), 1);
        assert!(!path.exists());
    }
    #[test]
    fn media_url_and_file_signatures_are_restricted() {
        assert!(trusted_media_url("https://lookaside.fbsbx.com/attachment?mid=1").is_some());
        for url in [
            "http://lookaside.fbsbx.com/attachment",
            "https://lookaside.fbsbx.com.evil.example/attachment",
            "https://evil.example@lookaside.fbsbx.com/attachment",
            "https://lookaside.fbsbx.com:8443/attachment",
        ] {
            assert!(trusted_media_url(url).is_none());
        }
        assert!(image_signature_matches(
            "image/jpeg",
            &[0xff, 0xd8, 0xff, 0x00]
        ));
        assert!(image_signature_matches(
            "image/png",
            b"\x89PNG\r\n\x1a\nrest"
        ));
        assert!(!image_signature_matches("image/png", b"<svg></svg>"));
        let bytes = [0xff, 0xd8, 0xff, 0xd9];
        let reference = InboundMediaReference {
            attachment_id: "wa_image_aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            provider_media_id: "123".into(),
            mime_type: "image/jpeg".into(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            recipient: "15555550101".into(),
            route_key: "route".into(),
            conversation_handle: "conv".into(),
            selection: None,
            expires_at: i64::MAX,
        };
        assert!(image_bytes_match(
            &reference,
            &json!({"file_size":bytes.len()}),
            &bytes
        ));
        assert!(!image_bytes_match(
            &reference,
            &json!({"file_size":bytes.len()+1}),
            &bytes
        ));
        assert!(!image_bytes_match(
            &reference,
            &json!({"file_size":bytes.len()}),
            b"not a photo"
        ));
    }
    #[tokio::test]
    async fn oversized_media_response_is_rejected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd")
                .await
                .unwrap();
        });
        let response = Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            read_bounded(response, 3).await.unwrap_err().code,
            "WHATSAPP_MEDIA_INVALID"
        );
    }
    #[test]
    fn payloads_never_treat_media_as_delivered_without_preparation() {
        let a = adapter();
        let mut out = OutboundMessage {
            platform: "whatsapp".into(),
            chat_id: "15555550101".into(),
            text: "hello".into(),
            attachments: vec![],
            timestamp: utc_now_iso(),
            metadata: Default::default(),
        };
        assert_eq!(
            a.message_body(&out, None).unwrap()["messaging_product"],
            "whatsapp"
        );
        out.attachments
            .push(json!({"url":"https://example.com/private.jpg"}));
        assert!(a.message_body(&out, None).is_err());
        assert!(!a.profile().to_string().contains("test-token"));
    }
    #[test]
    fn inbox_deduplicates_and_survives_restart() {
        let root = tempfile::tempdir().unwrap();
        let mut a = adapter();
        a.cache = root.path().join("attachment-cache");
        let payload = json!({"phone_number_id":"123","message":{"from":"15555550101","id":"wamid.1","timestamp":"1700000000","type":"text","text":{"body":"Hi"}}});
        assert_eq!(
            a.enqueue(vec![payload.clone(), payload.clone()]).unwrap(),
            1
        );
        let claimed = a.claim_message().unwrap().unwrap();
        assert!(a.claim_message().unwrap().is_none());
        a.finish_message(claimed, false).unwrap();
        assert_eq!(a.enqueue(vec![payload]).unwrap(), 0);
    }

    #[test]
    fn provider_time_and_official_number_scope_survive_normalization_and_retries() {
        let mut a = adapter();
        let root = tempfile::tempdir().unwrap();
        a.cache = root.path().join("attachment-cache");
        let payload = json!({"phone_number_id":"123","message":{"from":"15555550101","id":"same-wamid","timestamp":"1700000000","type":"text","text":{"body":"Hi"}}});
        let first = a.normalize_inbound(payload.clone()).unwrap();
        assert_eq!(first.timestamp, "2023-11-14T22:13:20+00:00");
        a.enqueue(vec![payload.clone()]).unwrap();
        let claimed = a.claim_message().unwrap().unwrap();
        assert_eq!(
            a.normalize_inbound(claimed["payload"].clone())
                .unwrap()
                .timestamp,
            first.timestamp
        );
        a.finish_message(claimed, false).unwrap();
        a.config.phone_number_id = "456".into();
        let mut second = payload.clone();
        second["phone_number_id"] = json!("456");
        let next = a.normalize_inbound(second.clone()).unwrap();
        assert_ne!(next.route_key, first.route_key);
        assert_ne!(
            crate::harborbeacon::build_turn_request(&first, None, None)["turn"]["turn_id"],
            crate::harborbeacon::build_turn_request(&next, None, None)["turn"]["turn_id"]
        );
        assert_eq!(a.enqueue(vec![second]).unwrap(), 1);
        let mut malformed = payload;
        malformed["phone_number_id"] = json!("456");
        malformed["message"]["timestamp"] = Value::Null;
        assert!(a.normalize_inbound(malformed).is_err());
    }
}
