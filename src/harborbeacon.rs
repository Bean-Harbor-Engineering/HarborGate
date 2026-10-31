use crate::config::AppConfig;
use crate::error::GatewayError;
use crate::models::InboundMessage;
use axum::http::StatusCode;
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const DEFAULT_CONTRACT_VERSION: &str = "2.0";
pub const DEFAULT_TURN_ENDPOINT: &str = "/api/web/turns";

#[derive(Clone)]
pub struct HarborBeaconTaskClient {
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

impl HarborBeaconTaskClient {
    pub fn from_config(config: &AppConfig) -> Option<Self> {
        config.harborbeacon_enabled().then(|| Self {
            base_url: config
                .harborbeacon_base_url
                .trim_end_matches('/')
                .to_string(),
            api_token: config.harborbeacon_token.clone(),
            turn_endpoint: config.harborbeacon_turn_endpoint.clone(),
            contract_version: DEFAULT_CONTRACT_VERSION.to_string(),
            http: Client::builder().connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(200)).redirect(reqwest::redirect::Policy::none())
                .build().expect("valid Beacon HTTP client"),
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
        let mut request_payload =
            build_turn_request(incoming, conversation_handle.as_deref(), continuation);
        if let Some(previous) = session_metadata.get("previous_delivery").filter(|v| v.is_object()) {
            request_payload["transport"]["metadata"]["previous_delivery"] = previous.clone();
        }
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

    async fn post_json(&self, payload: &Value) -> Result<Value, GatewayError> {
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
    metadata.insert(
        "intent".into(),
        json!({
            "domain": raw_lookup(raw_payload, "domain").or_else(|| metadata_lookup(&incoming.metadata, "domain")).unwrap_or_else(|| "general".to_string()),
            "action": raw_lookup(raw_payload, "action").or_else(|| metadata_lookup(&incoming.metadata, "action")).unwrap_or_else(|| "message".to_string()),
            "raw_text": incoming.text,
        }),
    );
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
                "video": incoming.platform != "feishu",
                "audio": incoming.platform == "feishu",
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
}
