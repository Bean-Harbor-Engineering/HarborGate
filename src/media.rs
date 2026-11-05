//! Short-lived, single-file capabilities for platform media. No platform token crosses the seam.
use crate::error::GatewayError;
use axum::http::StatusCode;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_MEDIA_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct CachedMedia {
    token: String,
    expires_at: DateTime<Utc>,
    mime_type: String,
    name: String,
    size_bytes: usize,
    duration_ms: u64,
}

pub struct MediaCache {
    root: PathBuf,
    origin: String,
}

impl MediaCache {
    pub fn new(root: PathBuf, port: u16) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            origin: format!("http://127.0.0.1:{port}"),
        })
    }

    fn paths(&self, id: &str) -> Result<(PathBuf, PathBuf), GatewayError> {
        if id.is_empty()
            || id.len() > 100
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(GatewayError::validation(
                "Invalid media attachment identity",
            ));
        }
        Ok((
            self.root.join(format!("{id}.json")),
            self.root.join(format!("{id}.bin")),
        ))
    }

    pub fn descriptor(&self, id: &str) -> Result<Option<Value>, GatewayError> {
        let (manifest, _) = self.paths(id)?;
        if !manifest.exists() {
            return Ok(None);
        }
        let entry: CachedMedia = serde_json::from_slice(&std::fs::read(manifest)?)?;
        // Stable on retries: expired capabilities are never silently renewed for the same turn.
        Ok(Some(self.to_descriptor(id, &entry)))
    }

    fn to_descriptor(&self, id: &str, entry: &CachedMedia) -> Value {
        json!({
            "attachment_id": id, "type": "audio", "name": entry.name,
            "mime_type": entry.mime_type, "size_bytes": entry.size_bytes,
            "download": {"mode": "proxy", "url": format!("{}/api/media/{id}", self.origin),
                "method": "GET", "headers": {"Authorization": format!("Bearer {}", entry.token)},
                "auth": {"type": "bearer"}, "expires_at": entry.expires_at.to_rfc3339(),
                "max_size_bytes": MAX_MEDIA_BYTES},
            "metadata": {"duration_ms": entry.duration_ms}
        })
    }

    pub fn store(
        &self,
        id: &str,
        bytes: &[u8],
        mime_type: &str,
        duration_ms: u64,
    ) -> Result<Value, GatewayError> {
        if bytes.is_empty() || bytes.len() > MAX_MEDIA_BYTES {
            return Err(GatewayError::validation(
                "Audio must contain 1 byte to 32 MiB",
            ));
        }
        if let Some(existing) = self.descriptor(id)? {
            return Ok(existing);
        }
        self.cleanup()?;
        let (manifest, path) = self.paths(id)?;
        let entry = CachedMedia {
            token: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            expires_at: Utc::now() + ChronoDuration::minutes(10),
            mime_type: if mime_type.starts_with("audio/") {
                mime_type.to_string()
            } else {
                "audio/opus".into()
            },
            name: if mime_type == "audio/wav" {
                "voice.wav".into()
            } else {
                "voice.opus".into()
            },
            size_bytes: bytes.len(),
            duration_ms,
        };
        std::fs::write(path, bytes)?;
        std::fs::write(manifest, serde_json::to_vec(&entry)?)?;
        Ok(self.to_descriptor(id, &entry))
    }

    pub fn read(&self, id: &str, authorization: &str) -> Result<(String, Vec<u8>), GatewayError> {
        let (manifest, path) = self.paths(id)?;
        let unavailable = || {
            GatewayError::new(
                StatusCode::NOT_FOUND,
                "MEDIA_NOT_AVAILABLE",
                "Media capability is unavailable or expired",
            )
        };
        let raw = std::fs::read(manifest).map_err(|_| unavailable())?;
        let entry: CachedMedia = serde_json::from_slice(&raw).map_err(|_| unavailable())?;
        if entry.expires_at <= Utc::now() || authorization != format!("Bearer {}", entry.token) {
            return Err(unavailable());
        }
        let metadata = std::fs::metadata(&path).map_err(|_| unavailable())?;
        if metadata.len() as usize > MAX_MEDIA_BYTES {
            return Err(unavailable());
        }
        let bytes = std::fs::read(path).map_err(|_| unavailable())?;
        Ok((entry.mime_type, bytes))
    }

    fn cleanup(&self) -> Result<(), GatewayError> {
        for item in std::fs::read_dir(&self.root)? {
            let path = item?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = std::fs::read(&path) else {
                continue;
            };
            let Ok(entry) = serde_json::from_slice::<CachedMedia>(&raw) else {
                continue;
            };
            if entry.expires_at <= Utc::now() {
                if let Some(id) = path.file_stem().and_then(|v| v.to_str()) {
                    if let Ok((manifest, binary)) = self.paths(id) {
                        let _ = std::fs::remove_file(binary);
                        let _ = std::fs::remove_file(manifest);
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn media_client(seconds: u64) -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(seconds))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("valid media HTTP client")
}

pub async fn read_bounded_response(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, GatewayError> {
    if !response.status().is_success() {
        return Err(GatewayError::infrastructure(format!(
            "Media download failed with HTTP {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_MEDIA_BYTES as u64)
    {
        return Err(GatewayError::validation("Media exceeds 32 MiB"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GatewayError::infrastructure("Media download did not complete"))?
    {
        if bytes.len() + chunk.len() > MAX_MEDIA_BYTES {
            return Err(GatewayError::validation("Media exceeds 32 MiB"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(GatewayError::validation("Media is empty"));
    }
    Ok(bytes)
}

/// Audio generated by Beacon is fetched only from its configured loopback origin.
pub async fn fetch_beacon_audio(
    artifact: &Value,
    beacon_origin: &str,
) -> Result<Vec<u8>, GatewayError> {
    let download = artifact.pointer("/metadata/download").ok_or_else(|| {
        GatewayError::validation("Audio artifact requires an HTTP download descriptor")
    })?;
    let raw_url = download
        .get("url")
        .and_then(Value::as_str)
        .or_else(|| artifact.get("url").and_then(Value::as_str))
        .unwrap_or("");
    let url =
        Url::parse(raw_url).map_err(|_| GatewayError::validation("Invalid audio download URL"))?;
    let origin = Url::parse(beacon_origin)
        .map_err(|_| GatewayError::validation("Invalid configured Beacon origin"))?;
    let host = url.host_str().unwrap_or_default();
    let local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !local
        || url.origin() != origin.origin()
        || !url.path().starts_with("/api/web/media/")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(GatewayError::validation(
            "Audio download must use the configured local Beacon origin",
        ));
    }
    if download
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        != "GET"
    {
        return Err(GatewayError::validation("Audio download requires GET"));
    }
    let auth = download
        .pointer("/headers/Authorization")
        .and_then(Value::as_str)
        .filter(|s| s.starts_with("Bearer "))
        .ok_or_else(|| GatewayError::validation("Audio download capability is missing"))?;
    let expiry = download
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .ok_or_else(|| GatewayError::validation("Audio download expiry is missing"))?;
    if expiry <= Utc::now() {
        return Err(GatewayError::validation(
            "Audio download capability has expired",
        ));
    }
    let response = media_client(20)
        .get(url)
        .header("Authorization", auth)
        .send()
        .await
        .map_err(|_| GatewayError::infrastructure("Beacon audio download did not complete"))?;
    read_bounded_response(response).await
}

/// Return duration only for the exact ASR input format, checking RIFF chunks.
pub fn pcm_wav_duration_ms(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 44 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return None;
    }
    let mut cursor = 12usize;
    let mut valid_format = false;
    let mut data_bytes = None;
    while cursor.checked_add(8)? <= bytes.len() {
        let size = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().ok()?) as usize;
        let start = cursor.checked_add(8)?;
        let end = start.checked_add(size)?;
        if end > bytes.len() {
            return None;
        }
        if &bytes[cursor..cursor + 4] == b"fmt " {
            if size < 16 {
                return None;
            }
            valid_format = u16::from_le_bytes(bytes[start..start + 2].try_into().ok()?) == 1
                && u16::from_le_bytes(bytes[start + 2..start + 4].try_into().ok()?) == 1
                && u32::from_le_bytes(bytes[start + 4..start + 8].try_into().ok()?) == 16000
                && u16::from_le_bytes(bytes[start + 14..start + 16].try_into().ok()?) == 16;
        } else if &bytes[cursor..cursor + 4] == b"data" {
            data_bytes = Some(size);
        }
        cursor = end.checked_add(size % 2)?;
    }
    let length = data_bytes?;
    (valid_format && length > 0 && length % 2 == 0).then_some((length as u64 * 1000) / 32000)
}

pub async fn normalize_inbound_audio(
    ffmpeg: &Path,
    root: &Path,
    bytes: &[u8],
) -> Result<(Vec<u8>, u64), GatewayError> {
    if bytes.is_empty() || bytes.len() > MAX_MEDIA_BYTES {
        return Err(GatewayError::validation("Invalid inbound audio size"));
    }
    if let Some(duration) = pcm_wav_duration_ms(bytes) {
        return Ok((bytes.to_vec(), duration));
    }
    tokio::fs::create_dir_all(root).await?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let input = root.join(format!("inbound-{id}.bin"));
    let output = root.join(format!("inbound-{id}.wav"));
    tokio::fs::write(&input, bytes).await?;
    let result = async {
        let mut command = tokio::process::Command::new(ffmpeg);
        command
            .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
            .arg(&input)
            .args([
                "-vn",
                "-ac",
                "1",
                "-ar",
                "16000",
                "-c:a",
                "pcm_s16le",
                "-fs",
                "33554433",
                "-f",
                "wav",
            ])
            .arg(&output)
            .kill_on_drop(true);
        let completed = tokio::time::timeout(Duration::from_secs(20), command.output())
            .await
            .map_err(|_| GatewayError::infrastructure("Inbound audio normalization timed out"))?
            .map_err(|_| GatewayError::infrastructure("Configured ffmpeg could not start"))?;
        if !completed.status.success() {
            return Err(GatewayError::validation(
                "Inbound audio could not be decoded",
            ));
        }
        let meta = tokio::fs::metadata(&output).await?;
        if meta.len() == 0 || meta.len() >= MAX_MEDIA_BYTES as u64 {
            return Err(GatewayError::validation("Normalized audio exceeds 32 MiB"));
        }
        let wav = tokio::fs::read(&output).await?;
        let duration = pcm_wav_duration_ms(&wav).ok_or_else(|| {
            GatewayError::validation("Normalized audio is not mono 16 kHz PCM WAV")
        })?;
        Ok((wav, duration))
    }
    .await;
    let _ = tokio::fs::remove_file(input).await;
    let _ = tokio::fs::remove_file(output).await;
    result
}

pub async fn convert_to_opus(
    ffmpeg: &Path,
    input: &Path,
    output: &Path,
) -> Result<(), GatewayError> {
    let mut command = tokio::process::Command::new(ffmpeg);
    command
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
        .arg(input)
        .args([
            "-vn", "-ac", "1", "-ar", "48000", "-c:a", "libopus", "-b:a", "32k", "-f", "opus",
        ])
        .arg(output)
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(20), command.output())
        .await
        .map_err(|_| GatewayError::infrastructure("Audio conversion timed out"))?
        .map_err(|_| GatewayError::infrastructure("Configured ffmpeg could not start"))?;
    if !status.status.success() {
        return Err(GatewayError::infrastructure("Audio conversion failed"));
    }
    let meta = tokio::fs::metadata(output).await?;
    if meta.len() == 0 || meta.len() > MAX_MEDIA_BYTES as u64 {
        return Err(GatewayError::validation("Invalid converted audio size"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_is_stable_and_cannot_read_another_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MediaCache::new(dir.path().into(), 8787).unwrap();
        let part = cache
            .store("att_one", b"audio", "audio/opus", 1200)
            .unwrap();
        assert_eq!(
            cache.store("att_one", b"changed", "audio/opus", 3).unwrap(),
            part
        );
        let auth = part
            .pointer("/download/headers/Authorization")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cache.read("att_one", auth).unwrap().1, b"audio");
        assert!(cache.read("att_two", auth).is_err());
        assert!(cache.read("att_one", "Bearer wrong").is_err());
        assert!(cache.read("../secret", auth).is_err());
    }
    #[test]
    fn expired_capability_and_oversize_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MediaCache::new(dir.path().into(), 8787).unwrap();
        let part = cache.store("att_one", b"audio", "audio/opus", 1).unwrap();
        let manifest = dir.path().join("att_one.json");
        let mut value: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        value["expires_at"] = json!((Utc::now() - ChronoDuration::seconds(1)).to_rfc3339());
        std::fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(cache
            .read(
                "att_one",
                part["download"]["headers"]["Authorization"]
                    .as_str()
                    .unwrap()
            )
            .is_err());
        assert!(cache
            .store("att_large", &vec![0; MAX_MEDIA_BYTES + 1], "audio/opus", 1)
            .is_err());
    }
    #[tokio::test]
    async fn outbound_audio_rejects_foreign_origin_before_network() {
        let artifact = json!({"metadata":{"download":{"url":"https://outside.invalid/a.wav"}}});
        assert!(fetch_beacon_audio(&artifact, "http://127.0.0.1:4174")
            .await
            .is_err());
    }
}
