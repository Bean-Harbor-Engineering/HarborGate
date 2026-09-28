use crate::cloud_relay::{valid_hub_id, CloudRelayClient};
use crate::config::AppConfig;
use crate::error::GatewayError;
use crate::gateway::AttachmentCacheRoot;
use crate::models::{InboundMessage, OutboundMessage};
use axum::http::StatusCode;
use base64::Engine as _;
use futures_util::StreamExt;
use reqwest::{redirect::Policy, Client};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use url::Url;
use uuid::Uuid;

pub const DEFAULT_CONTRACT_VERSION: &str = "2.0";
pub const DEFAULT_TURN_ENDPOINT: &str = "/api/web/turns";

#[derive(Clone)]
pub struct HarborBeaconTaskClient {
    cloud_relay: Option<(CloudRelayClient, String)>,
    base_url: String,
    api_token: String,
    turn_endpoint: String,
    contract_version: String,
    http: Client,
}

#[derive(Debug, Clone)]
pub struct TaskTurnResult {
    pub text: String,
    pub task_id: String,
    pub trace_id: String,
    pub status: String,
    pub route_key: String,
    pub conversation_handle: Option<String>,
    pub continuation: Option<Value>,
    pub active_frame: Option<Value>,
    pub next_actions: Vec<String>,
    pub response_payload: Value,
}

#[derive(Debug, Default)]
pub struct MaterializedAttachmentBatch {
    pub attachments: Vec<Value>,
    pub cache_files: Vec<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub failed_count: usize,
}

impl HarborBeaconTaskClient {
    /// For the authenticated fleet router, after it has selected and pinned a
    /// Navi. Neither inbound text nor a v2 envelope may supply this selection.
    pub fn from_cloud_relay(relay: CloudRelayClient, hub_id: &str) -> Result<Self, GatewayError> {
        if !valid_hub_id(hub_id) {
            return Err(GatewayError::validation("Invalid selected Navi"));
        }
        Ok(Self {
            cloud_relay: Some((relay, hub_id.into())),
            base_url: String::new(),
            api_token: String::new(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.into(),
            contract_version: DEFAULT_CONTRACT_VERSION.into(),
            http: media_http_client(),
        })
    }

    pub(crate) async fn authorize_whatsapp_delivery(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<(), GatewayError> {
        let denied = || {
            GatewayError::new(
                StatusCode::FORBIDDEN,
                "IM_DELIVERY_NOT_ALLOWED",
                "WhatsApp binding permission no longer permits this delivery",
            )
        };
        let unavailable =
            || GatewayError::infrastructure("WhatsApp delivery check is temporarily unavailable");
        let handle = outbound
            .metadata
            .get("conversation_handle")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(denied)?;
        let route = outbound
            .metadata
            .get("route_key")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(denied)?;
        let source_refs = match outbound.metadata.get("source_revalidation_refs") {
            None => Vec::new(),
            Some(Value::Array(refs))
                if refs.len() <= 5
                    && refs.iter().all(|item| {
                        item.as_str()
                            .is_some_and(|token| !token.is_empty() && token.len() <= 2048)
                    }) =>
            {
                refs.clone()
            }
            _ => return Err(denied()),
        };
        let request = json!({"recipient":outbound.chat_id,"route_key":route,"conversation_handle":handle,
            "text":outbound.text,"has_attachments":!outbound.attachments.is_empty(),
            "source_refs":source_refs});
        if let Some((relay, hub)) = &self.cloud_relay {
            let response = relay
                .authorize_delivery(hub, &request)
                .await
                .map_err(|error| {
                    if error.code == "NAVI_IDENTITY_CHANGED" {
                        denied()
                    } else {
                        unavailable()
                    }
                })?;
            if matches!(response.status.as_u16(), 400 | 401 | 403 | 404 | 410 | 422) {
                return Err(denied());
            }
            if response.status != StatusCode::OK
                || serde_json::to_vec(&response.body)
                    .map_err(|_| unavailable())?
                    .len()
                    > 4096
            {
                return Err(unavailable());
            }
            if response.body["allowed"] != true {
                return Err(denied());
            }
            return Ok(());
        }
        let mut response = self
            .http
            .post(format!(
                "{}/api/im/whatsapp/delivery-authorization",
                self.base_url
            ))
            .bearer_auth(&self.api_token)
            .header("X-Contract-Version", &self.contract_version)
            .timeout(Duration::from_secs(5))
            .json(&request)
            .send()
            .await
            .map_err(|_| unavailable())?;
        if matches!(
            response.status().as_u16(),
            400 | 401 | 403 | 404 | 410 | 422
        ) {
            return Err(denied());
        }
        if response.status() != StatusCode::OK {
            return Err(unavailable());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len() + chunk.len() > 4096 {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        let payload: Value = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        if payload["allowed"] != true {
            return Err(denied());
        }
        Ok(())
    }

    pub fn from_config(config: &AppConfig) -> Option<Self> {
        let base_url = config.harborbeacon_base_url.trim_end_matches('/');
        let api_token = config.harborbeacon_token.trim();
        if !config.harborbeacon_enabled()
            || api_token.is_empty()
            || !valid_beacon_base_url(base_url)
        {
            return None;
        }
        Some(Self {
            cloud_relay: None,
            base_url: base_url.to_string(),
            api_token: api_token.to_string(),
            turn_endpoint: config.harborbeacon_turn_endpoint.clone(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        })
    }

    pub async fn submit_turn(
        &self,
        incoming: &InboundMessage,
        session_metadata: &serde_json::Map<String, Value>,
    ) -> Result<TaskTurnResult, GatewayError> {
        let conversation_handle = session_metadata
            .get("conversation_handle")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string);
        let continuation = session_metadata
            .get("continuation")
            .filter(|value| value.is_object())
            .cloned();
        let request_payload =
            build_turn_request(incoming, conversation_handle.as_deref(), continuation);
        let response_payload = self.post_json(&request_payload).await?;
        Ok(map_turn_response(&request_payload, response_payload))
    }

    pub async fn submit_turn_payload(
        &self,
        request_payload: Value,
    ) -> Result<TaskTurnResult, GatewayError> {
        let response_payload = self.post_json(&request_payload).await?;
        Ok(map_turn_response(&request_payload, response_payload))
    }

    pub async fn materialize_attachments(
        &self,
        artifacts: Vec<Value>,
        cache_root: &Path,
        turn_id: &str,
    ) -> MaterializedAttachmentBatch {
        let count = artifacts.len();
        let trusted_parent = cache_root
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let cache_basename = cache_root.file_name().map(Path::new);
        let cache_root = match cache_basename
            .ok_or_else(|| std::io::Error::other("attachment cache path has no basename"))
            .and_then(|basename| AttachmentCacheRoot::open(trusted_parent, basename))
        {
            Ok(root) => root,
            Err(error) => {
                tracing::warn!(error = %error, "HarborGate could not open the attachment cache root");
                return MaterializedAttachmentBatch {
                    failed_count: count,
                    ..MaterializedAttachmentBatch::default()
                };
            }
        };
        self.materialize_attachments_in(artifacts, &cache_root, turn_id)
            .await
    }

    pub(crate) async fn materialize_attachments_in(
        &self,
        artifacts: Vec<Value>,
        cache_root: &AttachmentCacheRoot,
        turn_id: &str,
    ) -> MaterializedAttachmentBatch {
        let mut batch = MaterializedAttachmentBatch::default();
        for mut artifact in artifacts {
            let mime_type = artifact
                .get("mime_type")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| trusted_attachment_mime(value))
                .unwrap_or("");
            if mime_type.is_empty() {
                batch.failed_count += 1;
                continue;
            }
            let cache_dir = batch.cache_dir.get_or_insert_with(|| {
                cache_root.path().join(format!(
                    "turn-{}-{}",
                    safe_cache_segment(turn_id),
                    Uuid::new_v4().simple()
                ))
            });
            if cache_root.create_dir(cache_dir).is_err() {
                batch.failed_count += 1;
                continue;
            }
            let extension = attachment_extension(mime_type);
            let destination = cache_dir.join(format!(
                "attachment-{}.{extension}",
                Uuid::new_v4().simple()
            ));
            let result = if let Some((relay, hub)) = &self.cloud_relay {
                match artifact
                    .get("url")
                    .and_then(Value::as_str)
                    .and_then(remote_media_artifact_id)
                {
                    Some(id) => {
                        self.download_remote_media_artifact(
                            relay,
                            hub,
                            id,
                            mime_type,
                            cache_root,
                            &destination,
                        )
                        .await
                    }
                    None => Err(GatewayError::validation(
                        "Camera media artifact is not trusted",
                    )),
                }
            } else {
                self.download_local_media_artifact(&artifact, mime_type, cache_root, &destination)
                    .await
            };
            match result {
                Ok(()) => {
                    if let Some(object) = artifact.as_object_mut() {
                        object.insert(
                            "path".to_string(),
                            Value::String(destination.to_string_lossy().into_owned()),
                        );
                    }
                    batch.cache_files.push(destination);
                    batch.attachments.push(artifact);
                }
                Err(error) => {
                    if let Err(remove_error) = cache_root.remove_file(&destination) {
                        if remove_error.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(error = %remove_error, "HarborGate could not remove a partial media download");
                        }
                    }
                    tracing::warn!(error = %error, "HarborGate could not materialize media artifact");
                    batch.failed_count += 1;
                }
            }
        }
        if batch.failed_count > 0 {
            for path in batch.cache_files.drain(..) {
                if let Err(error) = cache_root.remove_file(&path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %path.display(),
                            error = %error,
                            "HarborGate could not roll back a partial attachment batch"
                        );
                    }
                }
            }
            batch.attachments.clear();
        }
        if batch.cache_files.is_empty() {
            if let Some(cache_dir) = batch.cache_dir.take() {
                if let Err(error) = cache_root.remove_dir(&cache_dir) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %cache_dir.display(),
                            error = %error,
                            "HarborGate could not remove an empty attachment cache directory"
                        );
                    }
                }
            }
        }
        batch
    }

    /// Check current camera consent even when a provider upload or local cache
    /// from an earlier attempt is reusable. Never follow an artifact redirect.
    pub(crate) async fn authorize_camera_attachments(
        &self,
        artifacts: &[Value],
    ) -> Result<(), GatewayError> {
        if let Some((relay, hub)) = &self.cloud_relay {
            for artifact in artifacts {
                let id = artifact["url"]
                    .as_str()
                    .and_then(remote_media_artifact_id)
                    .ok_or_else(|| {
                        GatewayError::validation("Camera attachment URL is not trusted")
                    })?;
                let response = relay
                    .media_artifact(hub, &json!({"artifact_id":id,"range":"bytes=0-0"}))
                    .await?;
                let mime_type = artifact["mime_type"]
                    .as_str()
                    .filter(|mime| trusted_attachment_mime(mime))
                    .ok_or_else(|| {
                        GatewayError::validation("Camera attachment MIME type is not trusted")
                    })?;
                decode_remote_media(&response, 0, 0, mime_type)?;
            }
            return Ok(());
        }
        for artifact in artifacts {
            let Some(raw) = artifact["url"].as_str() else {
                continue;
            };
            let Some(url) = trusted_media_artifact_url(&self.base_url, raw) else {
                return Err(GatewayError::validation(
                    "Camera attachment URL is not trusted",
                ));
            };
            if self.api_token.trim().is_empty() {
                return Err(GatewayError::infrastructure(
                    "Beacon media authorization is unavailable",
                ));
            }
            let response = self
                .http
                .get(url)
                .timeout(Duration::from_secs(5))
                .bearer_auth(&self.api_token)
                .header("X-Harbor-Media-Context", "chat")
                .header("Range", "bytes=0-0")
                .send()
                .await
                .map_err(|_| {
                    GatewayError::infrastructure("Camera media authorization is unavailable")
                })?;
            if !response.status().is_success() {
                return if matches!(response.status().as_u16(), 401 | 403 | 404 | 410) {
                    Err(GatewayError::new(
                        StatusCode::FORBIDDEN,
                        "CAMERA_MEDIA_DELIVERY_NOT_ALLOWED",
                        "Camera media permission was revoked or the attachment expired",
                    ))
                } else {
                    Err(GatewayError::infrastructure(
                        "Camera media authorization is unavailable",
                    ))
                };
            }
        }
        Ok(())
    }

    async fn download_local_media_artifact(
        &self,
        artifact: &Value,
        mime_type: &str,
        cache_root: &AttachmentCacheRoot,
        destination: &Path,
    ) -> Result<(), GatewayError> {
        let artifact_url = artifact
            .get("url")
            .and_then(Value::as_str)
            .and_then(|raw| trusted_media_artifact_url(&self.base_url, raw))
            .ok_or_else(|| GatewayError::validation("Camera attachment URL is not trusted"))?;
        self.download_media_artifact(cache_root, &artifact_url, mime_type, destination)
            .await
    }

    async fn download_remote_media_artifact(
        &self,
        relay: &CloudRelayClient,
        hub: &str,
        artifact_id: &str,
        mime_type: &str,
        cache_root: &AttachmentCacheRoot,
        destination: &Path,
    ) -> Result<(), GatewayError> {
        const CHUNK: u64 = 48 * 1024;
        const MAX: u64 = 128 * 1024 * 1024;
        // Use the same capability-scoped, exclusive cache creation as local media.
        let mut file = cache_root
            .create_new_file(destination)
            .map(tokio::fs::File::from_std)
            .map_err(|_| GatewayError::infrastructure("Gate media cache create failed"))?;
        tokio::time::timeout(Duration::from_secs(120), async {
            let (mut offset, mut total) = (0u64, None);
            loop {
                let end = (offset + CHUNK - 1).min(MAX - 1);
                let response = relay
                    .media_artifact(
                        hub,
                        &json!({"artifact_id":artifact_id,"range":format!("bytes={offset}-{end}")}),
                    )
                    .await?;
                let (bytes, reported_total) =
                    decode_remote_media(&response, offset, end, mime_type)?;
                if total.is_some_and(|previous| previous != reported_total) {
                    return Err(GatewayError::infrastructure(
                        "Camera media changed during transfer",
                    ));
                }
                total = Some(reported_total);
                file.write_all(&bytes)
                    .await
                    .map_err(|_| GatewayError::infrastructure("Gate media cache write failed"))?;
                offset += bytes.len() as u64;
                if offset == reported_total {
                    break;
                }
            }
            file.flush()
                .await
                .map_err(|_| GatewayError::infrastructure("Gate media cache flush failed"))?;
            file.sync_all()
                .await
                .map_err(|_| GatewayError::infrastructure("Gate media cache sync failed"))
        })
        .await
        .map_err(|_| GatewayError::infrastructure("Camera media transfer timed out"))?
    }

    async fn download_media_artifact(
        &self,
        cache_root: &AttachmentCacheRoot,
        artifact_url: &Url,
        expected_mime_type: &str,
        destination: &Path,
    ) -> Result<(), GatewayError> {
        const MAX_ATTACHMENT_BYTES: u64 = 128 * 1024 * 1024;
        if self.api_token.trim().is_empty() {
            return Err(GatewayError::validation(
                "HarborBeacon service token is required for media download",
            ));
        }
        let response = self
            .http
            .get(artifact_url.clone())
            .timeout(Duration::from_secs(45))
            .bearer_auth(&self.api_token)
            .header("X-Harbor-Media-Context", "chat")
            .send()
            .await
            .map_err(|error| {
                GatewayError::infrastructure(format!("Beacon media download failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(GatewayError::infrastructure(format!(
                "Beacon media download returned HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ATTACHMENT_BYTES)
        {
            return Err(GatewayError::validation(
                "Beacon media attachment exceeds the delivery size limit",
            ));
        }
        let response_mime_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .unwrap_or("");
        if !response_mime_type.eq_ignore_ascii_case(expected_mime_type) {
            return Err(GatewayError::validation(
                "Beacon media attachment MIME type does not match the artifact contract",
            ));
        }
        let mut file = cache_root
            .create_new_file(destination)
            .map(tokio::fs::File::from_std)
            .map_err(|error| {
                GatewayError::infrastructure(format!("Gate media cache create failed: {error}"))
            })?;
        let mut stream = response.bytes_stream();
        let mut written = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                GatewayError::infrastructure(format!("Beacon media body read failed: {error}"))
            })?;
            written = written.saturating_add(chunk.len() as u64);
            if written > MAX_ATTACHMENT_BYTES {
                return Err(GatewayError::validation(
                    "Beacon media attachment exceeds the delivery size limit",
                ));
            }
            file.write_all(&chunk).await.map_err(|error| {
                GatewayError::infrastructure(format!("Gate media cache write failed: {error}"))
            })?;
        }
        if written == 0 {
            return Err(GatewayError::validation("Beacon media attachment is empty"));
        }
        file.flush().await.map_err(|error| {
            GatewayError::infrastructure(format!("Gate media cache flush failed: {error}"))
        })?;
        file.sync_all().await.map_err(|error| {
            GatewayError::infrastructure(format!("Gate media cache sync failed: {error}"))
        })
    }

    async fn post_json(&self, payload: &Value) -> Result<Value, GatewayError> {
        if let Some((relay, hub)) = &self.cloud_relay {
            let response = relay.turn(hub, payload).await?;
            if !response.status.is_success() {
                return Err(GatewayError::new(
                    StatusCode::BAD_GATEWAY,
                    "UPSTREAM_TASK_API_ERROR",
                    format!("Navi task API returned HTTP {}", response.status),
                ));
            }
            return Ok(response.body);
        }
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            self.turn_endpoint.trim_start_matches('/')
        );
        let mut request = self
            .http
            .post(url)
            .header("X-Contract-Version", &self.contract_version)
            .json(payload);
        if !self.api_token.trim().is_empty() {
            request = request.bearer_auth(&self.api_token);
        }
        let response = request.send().await.map_err(|err| {
            GatewayError::infrastructure(format!("Could not reach HarborBeacon task API: {err}"))
        })?;
        let status = response.status();
        let body = response.text().await.map_err(|err| {
            GatewayError::infrastructure(format!(
                "Could not read HarborBeacon task API response: {err}"
            ))
        })?;
        let payload: Value = if body.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&body).map_err(|err| {
                GatewayError::infrastructure(format!(
                    "HarborBeacon task API returned invalid JSON: {err}"
                ))
            })?
        };
        if !status.is_success() {
            let message = payload
                .get("error")
                .and_then(Value::as_object)
                .and_then(|error| {
                    let code = error.get("code").and_then(Value::as_str).unwrap_or("");
                    let text = error.get("message").and_then(Value::as_str).unwrap_or("");
                    let detail = [code, text]
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    (!detail.is_empty()).then_some(detail)
                })
                .unwrap_or_else(|| body.trim().to_string());
            return Err(GatewayError::new(
                StatusCode::BAD_GATEWAY,
                "UPSTREAM_TASK_API_ERROR",
                format!("HarborBeacon task API returned HTTP {status}: {message}"),
            ));
        }
        Ok(payload)
    }
}

fn valid_beacon_base_url(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn trusted_media_artifact_url(base_url: &str, raw: &str) -> Option<Url> {
    let base = Url::parse(base_url).ok()?;
    if !valid_beacon_base_url(base_url) {
        return None;
    }
    let raw = raw.trim();
    let artifact = if raw.starts_with('/') && !raw.starts_with("//") {
        base.join(raw).ok()?
    } else {
        Url::parse(raw).ok()?
    };
    if artifact.scheme() != base.scheme()
        || artifact.host_str() != base.host_str()
        || artifact.port_or_known_default() != base.port_or_known_default()
        || !artifact.username().is_empty()
        || artifact.password().is_some()
        || artifact
            .query()
            .is_some_and(|query| query != "media_context=chat")
        || artifact.fragment().is_some()
    {
        return None;
    }
    let decoded_segments = artifact
        .path_segments()?
        .map(|segment| {
            urlencoding::decode(segment)
                .ok()
                .map(|value| value.into_owned())
        })
        .collect::<Option<Vec<_>>>()?;
    if decoded_segments.len() != 5
        || decoded_segments[..4] != ["api", "cameras", "recordings", "artifacts"]
    {
        return None;
    }
    let artifact_id = &decoded_segments[4];
    if artifact_id.is_empty()
        || matches!(artifact_id.as_str(), "." | "..")
        || !artifact_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~')
        })
    {
        return None;
    }
    Some(artifact)
}

fn remote_media_artifact_id(raw: &str) -> Option<&str> {
    let (path, query) = raw
        .split_once('?')
        .map_or((raw, None), |(path, query)| (path, Some(query)));
    if raw.contains('#') || query.is_some_and(|value| value != "media_context=chat") {
        return None;
    }
    let id = path.strip_prefix("/api/cameras/recordings/artifacts/")?;
    if id.is_empty()
        || id.len() > 256
        || matches!(id, "." | "..")
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~'))
    {
        None
    } else {
        Some(id)
    }
}

fn decode_remote_media(
    response: &crate::cloud_relay::RelayResponse,
    offset: u64,
    end: u64,
    mime_type: &str,
) -> Result<(Vec<u8>, u64), GatewayError> {
    if matches!(response.status.as_u16(), 400 | 401 | 403 | 404 | 410 | 416) {
        return Err(GatewayError::new(
            StatusCode::FORBIDDEN,
            "CAMERA_MEDIA_DELIVERY_NOT_ALLOWED",
            "Camera media permission was revoked or the attachment expired",
        ));
    }
    let invalid = || GatewayError::infrastructure("Navi returned invalid camera media");
    if !matches!(response.status.as_u16(), 200 | 206) {
        return Err(invalid());
    }
    let total = response.body["totalBytes"]
        .as_u64()
        .filter(|n| *n > offset && *n <= 128 * 1024 * 1024)
        .ok_or_else(invalid)?;
    if response.body["artifactOffset"].as_u64() != Some(offset)
        || (response.status == StatusCode::OK && (offset != 0 || total > end + 1))
        || !response.body["contentType"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(mime_type))
    {
        return Err(invalid());
    }
    let encoded = response.body["dataBase64"]
        .as_str()
        .filter(|v| v.len() <= 65_536)
        .ok_or_else(invalid)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 != (end + 1).min(total) - offset
        || response.body["bytes"].as_u64() != Some(bytes.len() as u64)
        || response.body["sha256"].as_str()
            != Some(format!("{:x}", Sha256::digest(&bytes)).as_str())
    {
        return Err(invalid());
    }
    Ok((bytes, total))
}

fn trusted_attachment_mime(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "image/jpeg" | "image/png" | "image/webp" | "video/mp4" | "video/quicktime"
    )
}

fn media_http_client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("reqwest client with disabled redirects must build")
}

fn safe_cache_segment(value: &str) -> String {
    let mut safe = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(48)
        .collect::<String>();
    if safe.is_empty() {
        safe.push_str("unknown");
    }
    safe
}

fn attachment_extension(mime_type: &str) -> &'static str {
    match mime_type.trim().to_ascii_lowercase().as_str() {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/webp" => "webp",
        "video/mp4" => "mp4",
        "video/quicktime" => "mov",
        _ => "bin",
    }
}

pub fn derive_route_key(incoming: &InboundMessage) -> String {
    if !incoming.route_key.trim().is_empty() {
        return incoming.route_key.trim().to_string();
    }
    stable_id(
        "gw_route_",
        &format!("{}|{}", incoming.platform, incoming.chat_id),
        20,
    )
}

pub fn derive_session_id(incoming: &InboundMessage) -> String {
    if !incoming.session_id.trim().is_empty() {
        return incoming.session_id.trim().to_string();
    }
    stable_id(
        "gw_sess_",
        &format!(
            "{}|{}|{}",
            incoming.platform, incoming.chat_id, incoming.user_id
        ),
        20,
    )
}

pub fn build_turn_request(
    incoming: &InboundMessage,
    conversation_handle: Option<&str>,
    continuation: Option<Value>,
) -> Value {
    let event_fingerprint = event_fingerprint(incoming);
    let route_key = derive_route_key(incoming);
    let raw_payload = incoming.raw_payload.as_object();
    let mut metadata = serde_json::Map::new();
    let mut intent = json!({
        "domain": raw_lookup(raw_payload, "domain")
            .or_else(|| metadata_lookup(&incoming.metadata, "domain"))
            .unwrap_or_else(|| "general".to_string()),
        "action": raw_lookup(raw_payload, "action")
            .or_else(|| metadata_lookup(&incoming.metadata, "action"))
            .unwrap_or_else(|| "message".to_string()),
        "raw_text": incoming.text,
    });
    if let Some(channel_intent) = incoming
        .metadata
        .get("intent")
        .filter(|value| value.is_object())
    {
        if let Some(object) = intent.as_object_mut() {
            for key in ["domain", "action", "raw_text"] {
                if let Some(value) = channel_intent.get(key).filter(|value| value.is_string()) {
                    object.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    metadata.insert("intent".into(), intent);
    if let Some(entity_refs) = raw_payload
        .and_then(|raw| raw.get("entity_refs"))
        .filter(|value| value.is_object())
    {
        metadata.insert("entity_refs".into(), entity_refs.clone());
    }
    if let Some(args) = raw_payload
        .and_then(|raw| raw.get("args"))
        .filter(|value| value.is_object())
    {
        metadata.insert("args".into(), args.clone());
    }
    if let Some(args) = incoming
        .metadata
        .get("args")
        .filter(|value| value.is_object())
    {
        metadata.insert("args".into(), args.clone());
    }
    if let Some(entity_refs) = incoming
        .metadata
        .get("entity_refs")
        .filter(|value| value.is_object())
    {
        metadata.insert("entity_refs".into(), entity_refs.clone());
    }

    json!({
        "turn": {
            "turn_id": stable_id("turn_", &event_fingerprint, 24),
            "trace_id": stable_id("trace_", &format!("trace|{event_fingerprint}"), 24),
            "occurred_at": incoming.timestamp,
            "retry_of": null,
        },
        "actor": {
            "user_id": incoming.user_id,
            "workspace_id": raw_lookup(raw_payload, "workspace_id").or_else(|| metadata_lookup(&incoming.metadata, "workspace_id")).unwrap_or_else(|| "home-1".to_string()),
            "account_id": raw_lookup(raw_payload, "account_id").or_else(|| metadata_lookup(&incoming.metadata, "account_id")),
        },
        "conversation": {
            "handle": conversation_handle.filter(|value| !value.trim().is_empty()),
            "channel": incoming.platform,
            "surface": "harborgate",
            "thread_id": incoming.chat_id,
            "chat_type": if incoming.chat_type.trim().is_empty() { "unknown" } else { incoming.chat_type.as_str() },
        },
        "transport": {
            "route_key": route_key,
            "message_id": incoming.message_id.trim(),
            "capabilities": {
                "text": true,
                "image": true,
                "file": true,
                "video": true,
            },
            "metadata": metadata,
        },
        "input": {
            "text": incoming.text,
            "parts": incoming.attachments,
        },
        "continuation": continuation,
        "autonomy": {
            "level": "supervised",
        },
    })
}

pub fn build_channel_turn_request(
    incoming: &InboundMessage,
    source_payload: &Value,
    conversation_handle: Option<&str>,
    continuation: Option<Value>,
) -> Value {
    let mut payload = build_turn_request(incoming, conversation_handle, continuation);
    apply_channel_turn_overrides(&mut payload, source_payload);
    payload
}

fn apply_channel_turn_overrides(payload: &mut Value, source_payload: &Value) {
    if let Some(turn) = payload.get_mut("turn").and_then(Value::as_object_mut) {
        if let Some(turn_id) = source_payload
            .pointer("/turn/turn_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            turn.insert("turn_id".into(), json!(turn_id.trim()));
        }
        if let Some(trace_id) = source_payload
            .pointer("/turn/trace_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            turn.insert("trace_id".into(), json!(trace_id.trim()));
        }
        if let Some(occurred_at) = source_payload
            .pointer("/turn/occurred_at")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            turn.insert("occurred_at".into(), json!(occurred_at.trim()));
        }
        if let Some(retry_of) = source_payload.pointer("/turn/retry_of") {
            turn.insert("retry_of".into(), retry_of.clone());
        }
    }
    if let Some(actor) = payload.get_mut("actor").and_then(Value::as_object_mut) {
        if let Some(workspace_id) = source_payload
            .pointer("/actor/workspace_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            actor.insert("workspace_id".into(), json!(workspace_id.trim()));
        }
        if let Some(account_id) = source_payload.pointer("/actor/account_id") {
            actor.insert("account_id".into(), account_id.clone());
        }
    }
    if let Some(conversation) = payload
        .get_mut("conversation")
        .and_then(Value::as_object_mut)
    {
        if let Some(surface) = source_payload
            .pointer("/conversation/surface")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            conversation.insert("surface".into(), json!(surface.trim()));
        }
    }
    if let Some(autonomy) = payload.get_mut("autonomy").and_then(Value::as_object_mut) {
        if let Some(level) = source_payload
            .pointer("/autonomy/level")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            autonomy.insert("level".into(), json!(level.trim()));
        }
    }
}

fn map_turn_response(request_payload: &Value, response_payload: Value) -> TaskTurnResult {
    let turn = response_payload.get("turn").and_then(Value::as_object);
    let conversation = response_payload
        .get("conversation")
        .and_then(Value::as_object);
    let reply = response_payload.get("reply").and_then(Value::as_object);
    let active_frame = response_payload
        .get("active_frame")
        .filter(|value| value.is_object())
        .cloned();
    let error = response_payload.get("error").and_then(Value::as_object);
    let text = reply
        .and_then(|reply| reply.get("text"))
        .and_then(Value::as_str)
        .or_else(|| {
            error
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
        })
        .unwrap_or("HarborBeacon returned an empty reply.")
        .trim()
        .to_string();
    let task_id = turn
        .and_then(|turn| turn.get("turn_id"))
        .and_then(Value::as_str)
        .or_else(|| {
            request_payload
                .pointer("/turn/turn_id")
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_string();
    let trace_id = turn
        .and_then(|turn| turn.get("trace_id"))
        .and_then(Value::as_str)
        .or_else(|| {
            request_payload
                .pointer("/turn/trace_id")
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_string();
    let continuation = continuation_from_active_frame(active_frame.as_ref(), turn);
    let next_actions = active_frame
        .as_ref()
        .and_then(|frame| frame.get("expected_reply"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    TaskTurnResult {
        text,
        task_id,
        trace_id,
        status: turn
            .and_then(|turn| turn.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("completed")
            .to_string(),
        route_key: request_payload
            .pointer("/transport/route_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        conversation_handle: conversation
            .and_then(|conversation| conversation.get("handle"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string),
        continuation,
        active_frame,
        next_actions,
        response_payload,
    }
}

fn continuation_from_active_frame(
    active_frame: Option<&Value>,
    turn: Option<&serde_json::Map<String, Value>>,
) -> Option<Value> {
    let frame = active_frame?.as_object()?;
    let token = frame.get("continuation_token")?.as_str()?.trim();
    if token.is_empty() {
        return None;
    }
    Some(json!({
        "token": token,
        "frame_id": frame.get("frame_id").and_then(Value::as_str).unwrap_or(""),
        "reply_to_turn_id": turn.and_then(|turn| turn.get("turn_id")).and_then(Value::as_str).unwrap_or(""),
        "expires_at": frame.get("expires_at").cloned().unwrap_or(Value::Null),
    }))
}

fn event_fingerprint(incoming: &InboundMessage) -> String {
    if incoming.platform == "whatsapp" && !incoming.message_id.trim().is_empty() {
        return serde_json::json!([
            incoming.platform,
            derive_route_key(incoming),
            incoming.message_id
        ])
        .to_string();
    }
    if !incoming.message_id.trim().is_empty() {
        return format!(
            "{}|{}|{}",
            incoming.platform, incoming.chat_id, incoming.message_id
        );
    }
    for key in ["message_id", "msg_id", "event_id", "client_id"] {
        if let Some(value) = incoming.raw_payload.get(key).and_then(Value::as_str) {
            if !value.trim().is_empty() {
                return format!("{}|{}|{}", incoming.platform, incoming.chat_id, value);
            }
        }
    }
    format!(
        "{}|{}|{}",
        incoming.platform,
        incoming.chat_id,
        canonical_json(&json!({
            "platform": incoming.platform,
            "chat_id": incoming.chat_id,
            "user_id": incoming.user_id,
            "text": incoming.text,
            "timestamp": incoming.timestamp,
            "raw_payload": incoming.raw_payload,
        }))
    )
}

pub fn stable_id(prefix: &str, payload: &str, length: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{prefix}{}", &digest[..length.min(digest.len())])
}

pub fn canonical_json(payload: &Value) -> String {
    match payload {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let body = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        Value::Array(items) => {
            let body = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        _ => serde_json::to_string(payload).unwrap_or_else(|_| "\"\"".to_string()),
    }
}

fn raw_lookup(raw_payload: Option<&serde_json::Map<String, Value>>, key: &str) -> Option<String> {
    raw_payload?
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn metadata_lookup(metadata: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::utc_now_iso;
    use axum::{
        body::{Body, Bytes},
        http::{header, HeaderMap, HeaderValue, Response, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn build_turn_request_uses_web_contract_shape() {
        let incoming = InboundMessage {
            platform: "feishu".into(),
            chat_id: "oc_123".into(),
            user_id: "ou_123".into(),
            text: "hello".into(),
            message_id: "om_123".into(),
            chat_type: "p2p".into(),
            route_key: "".into(),
            session_id: "".into(),
            mentions: vec![],
            attachments: vec![],
            metadata: serde_json::Map::new(),
            timestamp: utc_now_iso(),
            raw_payload: json!({"message_id": "om_123"}),
        };

        let payload = build_turn_request(&incoming, Some("conv_1"), None);

        assert_eq!(payload["conversation"]["handle"], "conv_1");
        assert_eq!(payload["conversation"]["surface"], "harborgate");
        assert_eq!(
            payload["transport"]["route_key"],
            derive_route_key(&incoming)
        );
        assert!(payload.get("args").is_none());
        assert!(payload.get("source").is_none());
    }

    #[test]
    fn build_channel_turn_request_preserves_client_turn_identity() {
        let incoming = InboundMessage {
            platform: "android".into(),
            chat_id: "device-1".into(),
            user_id: "user-1".into(),
            text: "show camera".into(),
            message_id: "client-msg-1".into(),
            chat_type: "p2p".into(),
            route_key: "".into(),
            session_id: "".into(),
            mentions: vec![],
            attachments: vec![],
            metadata: serde_json::Map::new(),
            timestamp: utc_now_iso(),
            raw_payload: json!({"turn": {"turn_id": "turn-client-1"}}),
        };
        let source = json!({
            "turn": {
                "turn_id": "turn-client-1",
                "trace_id": "trace-client-1",
                "occurred_at": "2026-05-09T10:00:00Z",
                "retry_of": null
            },
            "actor": {"workspace_id": "home-android", "account_id": "acct-1"},
            "conversation": {"surface": "android"},
            "autonomy": {"level": "supervised"}
        });

        let payload = build_channel_turn_request(&incoming, &source, Some("conv-1"), None);

        assert_eq!(payload["turn"]["turn_id"], "turn-client-1");
        assert_eq!(payload["turn"]["trace_id"], "trace-client-1");
        assert_eq!(payload["actor"]["workspace_id"], "home-android");
        assert_eq!(payload["conversation"]["channel"], "android");
        assert_eq!(payload["conversation"]["surface"], "android");
        assert_eq!(payload["conversation"]["handle"], "conv-1");
        assert!(payload.get("args").is_none());
        assert!(payload.get("source").is_none());
    }

    #[test]
    fn harborbeacon_client_requires_service_token() {
        let mut config = AppConfig::from_env();
        config.harborbeacon_base_url = "https://beacon.example".to_string();
        config.harborbeacon_token.clear();
        assert!(HarborBeaconTaskClient::from_config(&config).is_none());

        config.harborbeacon_token = "service-token".to_string();
        assert!(HarborBeaconTaskClient::from_config(&config).is_some());
    }

    #[test]
    fn media_artifact_download_accepts_only_same_origin_single_safe_id() {
        let base_url = "https://beacon.example:8443";
        assert!(trusted_media_artifact_url(
            base_url,
            "/api/cameras/recordings/artifacts/photo.jpg?media_context=chat"
        )
        .is_some());
        assert_eq!(
            trusted_media_artifact_url(
                base_url,
                "/api/cameras/recordings/artifacts/clips~cam-252~1785289217123.mp4"
            )
            .map(|url| url.to_string())
            .as_deref(),
            Some(
                "https://beacon.example:8443/api/cameras/recordings/artifacts/clips~cam-252~1785289217123.mp4"
            )
        );
        assert_eq!(
            trusted_media_artifact_url(
                base_url,
                "https://beacon.example:8443/api/cameras/recordings/artifacts/video-1.mp4"
            )
            .map(|url| url.path().to_string())
            .as_deref(),
            Some("/api/cameras/recordings/artifacts/video-1.mp4")
        );
        for rejected in [
            "https://example.com/clip.mp4",
            "https://beacon.example:9443/api/cameras/recordings/artifacts/clip.mp4",
            "/api/cameras/recordings/artifacts/../secret",
            "/api/cameras/recordings/artifacts/%2e%2e/secret",
            "/api/cameras/recordings/artifacts/%2fsecret.mp4",
            "/api/cameras/recordings/artifacts/%5csecret.mp4",
            "/api/cameras/recordings/artifacts/clip%2fsecret.mp4",
            "/api/cameras/recordings/artifacts/clip%5csecret.mp4",
            "/api/cameras/recordings/artifacts/clip.mp4/extra",
            "/api/cameras/recordings/artifacts/.",
            "/api/cameras/recordings/artifacts/clip.mp4?token=secret",
            "/api/cameras/recordings/artifacts/clip.mp4?media_context=local",
            "/api/cameras/recordings/artifacts/clip.mp4?media_context=chat&token=secret",
            "/api/cameras/recordings/artifacts/clip.mp4?media_context=chat&media_context=local",
            "/api/cameras/recordings/artifacts/clip.mp4#fragment",
            "/shared/cameras/token-252",
        ] {
            assert!(
                trusted_media_artifact_url(base_url, rejected).is_none(),
                "unexpected trusted URL: {rejected}"
            );
        }
    }

    #[tokio::test]
    async fn encoded_or_nonwhitelisted_media_path_never_reaches_http_or_disk() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = hits.clone();
        let app = Router::new().fallback(get(move || {
            let server_hits = server_hits.clone();
            async move {
                server_hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::NOT_FOUND
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let cache_root = tempdir().unwrap();

        let batch = client
            .materialize_attachments(
                vec![
                    json!({"artifact_id": "encoded", "kind": "video", "mime_type": "video/mp4", "url": "/api/cameras/recordings/artifacts/clip%2fsecret.mp4"}),
                    json!({"artifact_id": "other", "kind": "video", "mime_type": "video/mp4", "url": "/api/internal/media/clip.mp4"}),
                ],
                cache_root.path(),
                "turn-invalid-url",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 2);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read_dir(cache_root.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn materialize_attachments_downloads_into_gate_owned_cache() {
        let app = Router::new().route(
            "/api/cameras/recordings/artifacts/snapshots~cam-252~frame.jpg",
            get(|headers: HeaderMap| async move {
                assert_eq!(headers.get("X-Harbor-Media-Context").unwrap(), "chat");
                (
                    [(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"))],
                    [0xFF_u8, 0xD8, 0xFF, 0xD9],
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Beacon");
        let address = listener.local_addr().expect("mock Beacon address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Beacon");
        });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let cache_root = tempdir().expect("attachment cache root");

        let batch = client
            .materialize_attachments(
                vec![json!({
                    "kind": "image",
                    "mime_type": "image/jpeg",
                    "url": "/api/cameras/recordings/artifacts/snapshots~cam-252~frame.jpg?media_context=chat"
                })],
                cache_root.path(),
                "turn/camera-252",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 0);
        assert_eq!(batch.attachments.len(), 1);
        assert_eq!(batch.cache_files.len(), 1);
        let cached_path = batch.attachments[0]["path"]
            .as_str()
            .map(PathBuf::from)
            .expect("materialized path");
        assert!(cached_path.starts_with(cache_root.path()));
        assert_eq!(
            tokio::fs::read(&cached_path).await.expect("cached bytes"),
            [0xFF, 0xD8, 0xFF, 0xD9]
        );
    }

    #[tokio::test]
    async fn materialize_attachments_fails_closed_after_cache_root_is_replaced() {
        let app = Router::new().route(
            "/api/cameras/recordings/artifacts/snapshots~cam-252~frame.jpg",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"))],
                    [0xFF_u8, 0xD8, 0xFF, 0xD9],
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let dir = tempdir().unwrap();
        #[cfg(windows)]
        let (cache_root, displaced_cache_root, outside_dir) = {
            let state_dir = dir.path().join("state");
            let real_state_dir = dir.path().join("real-state");
            let outside_state_dir = dir.path().join("outside-state");
            let outside_dir = outside_state_dir.join("attachment-cache");
            fs::create_dir_all(&real_state_dir).unwrap();
            fs::create_dir_all(&outside_dir).unwrap();
            assert!(std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(&state_dir)
                .arg(&real_state_dir)
                .status()
                .unwrap()
                .success());
            let cache_root =
                AttachmentCacheRoot::open(&state_dir, Path::new("attachment-cache")).unwrap();
            fs::remove_dir(&state_dir).unwrap();
            assert!(std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(&state_dir)
                .arg(&outside_state_dir)
                .status()
                .unwrap()
                .success());
            (
                cache_root,
                real_state_dir.join("attachment-cache"),
                outside_dir,
            )
        };
        #[cfg(unix)]
        let (cache_root, displaced_cache_root, outside_dir) = {
            let state_dir = dir.path().join("state");
            let visible_cache_root = state_dir.join("attachment-cache");
            let displaced_cache_root = state_dir.join("attachment-cache-original");
            let outside_dir = dir.path().join("outside");
            fs::create_dir_all(&outside_dir).unwrap();
            let cache_root =
                AttachmentCacheRoot::open(&state_dir, Path::new("attachment-cache")).unwrap();
            fs::rename(&visible_cache_root, &displaced_cache_root).unwrap();
            std::os::unix::fs::symlink(&outside_dir, &visible_cache_root).unwrap();
            (cache_root, displaced_cache_root, outside_dir)
        };
        let outside_marker = outside_dir.join("marker.txt");
        fs::write(&outside_marker, b"outside-must-survive").unwrap();

        let batch = client
            .materialize_attachments_in(
                vec![json!({
                    "kind": "image",
                    "mime_type": "image/jpeg",
                    "url": "/api/cameras/recordings/artifacts/snapshots~cam-252~frame.jpg"
                })],
                &cache_root,
                "turn-root-swap",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 1);
        assert!(batch.attachments.is_empty());
        assert_eq!(fs::read(&outside_marker).unwrap(), b"outside-must-survive");
        assert_eq!(fs::read_dir(&outside_dir).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&displaced_cache_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn materialize_attachments_rejects_beacon_supplied_local_path() {
        let local = tempdir().expect("local artifact root");
        let local_path = local.path().join("secret.mp4");
        tokio::fs::write(&local_path, b"private")
            .await
            .expect("write local artifact");
        let cache_root = tempdir().expect("attachment cache root");
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: "http://127.0.0.1:9".to_string(),
            api_token: "service-secret".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };

        let batch = client
            .materialize_attachments(
                vec![json!({
                    "id": "artifact-secret",
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "path": local_path,
                })],
                cache_root.path(),
                "turn-local-path",
            )
            .await;

        assert_eq!(batch.failed_count, 1);
        assert!(batch.attachments.is_empty());
        assert!(batch.cache_files.is_empty());
    }

    #[tokio::test]
    async fn materialize_attachments_rejects_mismatched_response_mime() {
        let app = Router::new().route(
            "/api/cameras/recordings/artifacts/clip.mp4",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
                    "not a video",
                )
                    .into_response()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Beacon");
        let address = listener.local_addr().expect("mock Beacon address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Beacon");
        });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let cache_root = tempdir().expect("attachment cache root");

        let batch = client
            .materialize_attachments(
                vec![json!({
                    "id": "artifact-clip",
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "url": "/api/cameras/recordings/artifacts/clip.mp4",
                })],
                cache_root.path(),
                "turn-wrong-mime",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 1);
        assert!(batch.attachments.is_empty());
    }

    #[tokio::test]
    async fn materialize_attachments_does_not_follow_redirects() {
        let app = Router::new()
            .route(
                "/api/cameras/recordings/artifacts/clip.mp4",
                get(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, HeaderValue::from_static("/secret.mp4"))],
                    )
                }),
            )
            .route(
                "/secret.mp4",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, HeaderValue::from_static("video/mp4"))],
                        "secret",
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Beacon");
        let address = listener.local_addr().expect("mock Beacon address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Beacon");
        });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let cache_root = tempdir().expect("attachment cache root");

        let batch = client
            .materialize_attachments(
                vec![json!({
                    "id": "artifact-clip",
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "url": "/api/cameras/recordings/artifacts/clip.mp4",
                })],
                cache_root.path(),
                "turn-redirect",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 1);
        assert!(batch.attachments.is_empty());
    }

    #[tokio::test]
    async fn materialize_attachments_rejects_wrong_bearer_and_oversized_content_length() {
        let app = Router::new()
            .route(
                "/api/cameras/recordings/artifacts/auth.mp4",
                get(|headers: HeaderMap| async move {
                    if headers.get(header::AUTHORIZATION)
                        == Some(&HeaderValue::from_static("Bearer expected-service-token"))
                    {
                        (
                            [(header::CONTENT_TYPE, HeaderValue::from_static("video/mp4"))],
                            "clip",
                        )
                            .into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }),
            )
            .route(
                "/api/cameras/recordings/artifacts/oversized.mp4",
                get(|| async {
                    Response::builder()
                        .header(header::CONTENT_TYPE, "video/mp4")
                        .header(header::CONTENT_LENGTH, "134217729")
                        .body(Body::from_stream(futures_util::stream::once(async {
                            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"x"))
                        })))
                        .unwrap()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Beacon");
        let address = listener.local_addr().expect("mock Beacon address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Beacon");
        });
        let cache_root = tempdir().expect("attachment cache root");
        let artifact = |url: &str| {
            json!({
                "artifact_id": "artifact-video",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": url,
            })
        };
        let wrong_token_client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "wrong-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let wrong_bearer = wrong_token_client
            .materialize_attachments(
                vec![artifact("/api/cameras/recordings/artifacts/auth.mp4")],
                cache_root.path(),
                "turn-wrong-bearer",
            )
            .await;
        assert_eq!(wrong_bearer.failed_count, 1);
        assert!(wrong_bearer.cache_dir.is_none());

        let authorized_client = HarborBeaconTaskClient {
            cloud_relay: None,
            api_token: "expected-service-token".to_string(),
            ..wrong_token_client
        };
        let oversized = authorized_client
            .materialize_attachments(
                vec![artifact("/api/cameras/recordings/artifacts/oversized.mp4")],
                cache_root.path(),
                "turn-oversized",
            )
            .await;

        server.abort();
        assert_eq!(oversized.failed_count, 1);
        assert!(oversized.cache_files.is_empty());
        assert!(oversized.cache_dir.is_none());
    }

    #[tokio::test]
    async fn unknown_length_body_over_limit_is_aborted_and_partial_batch_is_removed() {
        const CHUNK_SIZE: usize = 1024 * 1024;
        const CHUNK_COUNT: usize = 129;
        let app = Router::new().route(
            "/api/cameras/recordings/artifacts/chunked.mp4",
            get(|| async {
                let chunks = futures_util::stream::iter((0..CHUNK_COUNT).map(|_| {
                    Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0_u8; CHUNK_SIZE]))
                }));
                Response::builder()
                    .header(header::CONTENT_TYPE, "video/mp4")
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Beacon");
        let address = listener.local_addr().expect("mock Beacon address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Beacon");
        });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let cache_root = tempdir().expect("attachment cache root");

        let batch = client
            .materialize_attachments(
                vec![json!({
                    "artifact_id": "artifact-chunked",
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "url": "/api/cameras/recordings/artifacts/chunked.mp4",
                })],
                cache_root.path(),
                "turn-chunked",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 1);
        assert!(batch.attachments.is_empty());
        assert!(batch.cache_files.is_empty());
        assert!(batch.cache_dir.is_none());
        assert_eq!(std::fs::read_dir(cache_root.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn later_attachment_error_rolls_back_earlier_files_in_the_same_batch() {
        let app = Router::new()
            .route(
                "/api/cameras/recordings/artifacts/good.jpg",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"))],
                        [0xFF_u8, 0xD8, 0xFF, 0xD9],
                    )
                }),
            )
            .route(
                "/api/cameras/recordings/artifacts/bad.mp4",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
                        "not-video",
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = HarborBeaconTaskClient {
            cloud_relay: None,
            base_url: format!("http://{address}"),
            api_token: "service-token".to_string(),
            turn_endpoint: DEFAULT_TURN_ENDPOINT.to_string(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: media_http_client(),
        };
        let cache_root = tempdir().unwrap();

        let batch = client
            .materialize_attachments(
                vec![
                    json!({"artifact_id": "good", "kind": "image", "mime_type": "image/jpeg", "url": "/api/cameras/recordings/artifacts/good.jpg"}),
                    json!({"artifact_id": "bad", "kind": "video", "mime_type": "video/mp4", "url": "/api/cameras/recordings/artifacts/bad.mp4"}),
                ],
                cache_root.path(),
                "turn-partial",
            )
            .await;

        server.abort();
        assert_eq!(batch.failed_count, 1);
        assert!(batch.attachments.is_empty());
        assert!(batch.cache_files.is_empty());
        assert!(batch.cache_dir.is_none());
        assert_eq!(std::fs::read_dir(cache_root.path()).unwrap().count(), 0);
    }
}
