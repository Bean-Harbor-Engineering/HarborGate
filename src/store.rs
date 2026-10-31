use crate::models::ConversationTurn;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct FileSessionStore {
    root: PathBuf,
    max_turns: usize,
    lock: Mutex<()>,
}

impl FileSessionStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create session root {}", root.display()))?;
        Ok(Self {
            root,
            max_turns: 20,
            lock: Mutex::new(()),
        })
    }

    pub fn load_history(&self, platform: &str, chat_id: &str) -> Result<Vec<ConversationTurn>> {
        let payload = self.load_payload(platform, chat_id)?;
        let turns = payload
            .get("turns")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut result = Vec::new();
        for item in turns {
            if let Ok(turn) = serde_json::from_value(item) {
                result.push(turn);
            }
        }
        Ok(result)
    }

    pub fn load_metadata(
        &self,
        platform: &str,
        chat_id: &str,
    ) -> Result<serde_json::Map<String, Value>> {
        let payload = self.load_payload(platform, chat_id)?;
        Ok(payload
            .get("metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default())
    }

    pub fn set_metadata(
        &self,
        platform: &str,
        chat_id: &str,
        metadata: serde_json::Map<String, Value>,
    ) -> Result<()> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let mut payload = self.load_payload_unlocked(platform, chat_id)?;
        payload["platform"] = json!(platform);
        payload["chat_id"] = json!(chat_id);
        payload["metadata"] = Value::Object(metadata);
        if !payload.get("turns").is_some_and(Value::is_array) {
            payload["turns"] = json!([]);
        }
        self.write_json(&self.session_path(platform, chat_id), &payload)
    }

    pub fn append_turns(
        &self,
        platform: &str,
        chat_id: &str,
        turns: Vec<ConversationTurn>,
    ) -> Result<()> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let mut payload = self.load_payload_unlocked(platform, chat_id)?;
        let mut history: Vec<ConversationTurn> = payload
            .get("turns")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect();
        history.extend(turns);
        if self.max_turns > 0 && history.len() > self.max_turns {
            history = history[history.len() - self.max_turns..].to_vec();
        }
        payload["platform"] = json!(platform);
        payload["chat_id"] = json!(chat_id);
        payload["turns"] = serde_json::to_value(history)?;
        if !payload.get("metadata").is_some_and(Value::is_object) {
            payload["metadata"] = json!({});
        }
        self.write_json(&self.session_path(platform, chat_id), &payload)
    }

    pub fn register_route(&self, route_key: &str, route: Value) -> Result<()> {
        if route_key.trim().is_empty() {
            anyhow::bail!("route_key is required");
        }
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let mut routes = self.load_shared_map_unlocked("_routes.json")?;
        routes.insert(route_key.to_string(), route);
        self.write_shared_map_unlocked("_routes.json", &routes)
    }

    pub fn resolve_route(&self, route_key: &str) -> Result<Option<Value>> {
        if route_key.trim().is_empty() {
            return Ok(None);
        }
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let routes = self.load_shared_map_unlocked("_routes.json")?;
        Ok(routes.get(route_key).cloned())
    }

    pub fn load_inbound_record(&self, key: &str) -> Result<Option<Value>> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        Ok(self
            .load_shared_map_unlocked("_inbound.json")?
            .get(key)
            .cloned())
    }

    pub fn save_inbound_record(&self, key: &str, record: Value) -> Result<()> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let mut records = self.load_shared_map_unlocked("_inbound.json")?;
        records.insert(key.to_string(), record);
        self.write_shared_map_unlocked("_inbound.json", &records)
    }

    pub fn load_delivery_record(&self, idempotency_key: &str) -> Result<Option<Value>> {
        if idempotency_key.trim().is_empty() {
            return Ok(None);
        }
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let records = self.load_shared_map_unlocked("_deliveries.json")?;
        Ok(records.get(idempotency_key).cloned())
    }

    pub fn save_delivery_record(
        &self,
        idempotency_key: &str,
        request_fingerprint: &str,
        response_payload: Value,
        classification: Value,
    ) -> Result<()> {
        if idempotency_key.trim().is_empty() {
            anyhow::bail!("idempotency_key is required");
        }
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let mut records = self.load_shared_map_unlocked("_deliveries.json")?;
        records.insert(
            idempotency_key.to_string(),
            json!({
                "request_fingerprint": request_fingerprint,
                "response_payload": response_payload,
                "classification": classification,
            }),
        );
        self.write_shared_map_unlocked("_deliveries.json", &records)
    }

    pub fn delivery_health(&self) -> Result<Value> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        let records = self.load_shared_map_unlocked("_deliveries.json")?;
        Ok(json!({
            "record_count": records.len(),
            "route_mode_counts": {},
            "queue_state_counts": {},
            "source_bound": {"ready": records.is_empty(), "health_state": if records.is_empty() { "unknown" } else { "ready" }},
            "proactive": {"ready": records.is_empty(), "health_state": if records.is_empty() { "unknown" } else { "ready" }},
            "unknown": {"ready": false, "health_state": "unknown"},
            "failure_class_counts": {},
        }))
    }

    fn load_payload(&self, platform: &str, chat_id: &str) -> Result<Value> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.load_payload_unlocked(platform, chat_id)
    }

    fn load_payload_unlocked(&self, platform: &str, chat_id: &str) -> Result<Value> {
        let path = self.session_path(platform, chat_id);
        if !path.exists() {
            return Ok(
                json!({"platform": platform, "chat_id": chat_id, "metadata": {}, "turns": []}),
            );
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read session {}", path.display()))?;
        let mut payload: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
        if !payload.is_object() {
            payload = json!({});
        }
        payload["platform"] = payload
            .get("platform")
            .cloned()
            .unwrap_or_else(|| json!(platform));
        payload["chat_id"] = payload
            .get("chat_id")
            .cloned()
            .unwrap_or_else(|| json!(chat_id));
        if !payload.get("metadata").is_some_and(Value::is_object) {
            payload["metadata"] = json!({});
        }
        if !payload.get("turns").is_some_and(Value::is_array) {
            payload["turns"] = json!([]);
        }
        Ok(payload)
    }

    fn load_shared_map_unlocked(&self, file_name: &str) -> Result<BTreeMap<String, Value>> {
        let path = self.root.join(file_name);
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read shared map {}", path.display()))?;
        let payload: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
        let mut result = BTreeMap::new();
        if let Some(object) = payload.as_object() {
            for (key, value) in object {
                result.insert(key.clone(), value.clone());
            }
        }
        Ok(result)
    }

    fn write_shared_map_unlocked(
        &self,
        file_name: &str,
        map: &BTreeMap<String, Value>,
    ) -> Result<()> {
        self.write_json(&self.root.join(file_name), &serde_json::to_value(map)?)
    }

    fn write_json(&self, path: &Path, payload: &Value) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(payload)?)
            .with_context(|| format!("failed to write {}", path.display()))
    }

    fn session_path(&self, platform: &str, chat_id: &str) -> PathBuf {
        self.root
            .join(format!("{}__{}.json", slug(platform), slug(chat_id)))
    }
}

fn slug(value: &str) -> String {
    let text = value.trim().to_lowercase();
    let text = if text.is_empty() { "unknown" } else { &text };
    text.chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_python_compatible_session_file_name() {
        let dir = tempdir().unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();
        let mut metadata = serde_json::Map::new();
        metadata.insert("route_key".into(), json!("gw_route_123"));
        store
            .set_metadata("feishu", "oc 123", metadata)
            .expect("metadata should save");

        let path = dir.path().join("feishu__oc_123.json");
        assert!(path.exists());
        let payload: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(payload["metadata"]["route_key"], "gw_route_123");
    }
}
