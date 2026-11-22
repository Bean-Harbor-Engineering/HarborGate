use crate::models::{utc_now_iso, ConversationTurn};
use anyhow::{Context, Result};
use atomicwrites::{AllowOverwrite, AtomicFile};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fs2::FileExt;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

const DELIVERY_ITEMS_LOCK_FILE: &str = "_delivery_items.lock";
const LEGACY_DELIVERY_CLAIM_LEASE_SECONDS: i64 = 300;

pub struct FileSessionStore {
    root: PathBuf,
    max_turns: usize,
    lock: Mutex<()>,
    #[cfg(test)]
    fail_next_write: Mutex<Option<&'static str>>,
}

pub struct DeliveryItemClaimRequest<'a> {
    pub delivery_key: &'a str,
    pub request_fingerprint: &'a str,
    pub item_key: &'a str,
    pub artifact_id: &'a str,
    pub kind: &'a str,
    pub owner: &'a str,
    pub cache_path: Option<&'a Path>,
    pub lease_seconds: u64,
}

pub struct DeliveryPlanItem {
    pub item_key: String,
    pub artifact_id: String,
    pub kind: String,
    pub planned_outbound: Value,
    pub materialization_required: bool,
}

pub struct DeliveryMaterializationCompletion<'a> {
    pub delivery_key: &'a str,
    pub item_key: &'a str,
    pub claim_token: &'a str,
    pub status: &'a str,
    pub materialized_outbound: Option<Value>,
    pub cache_path: Option<&'a Path>,
    pub retryable: bool,
    pub last_error: Option<&'a str>,
}

pub struct DeliveryItemCompletion<'a> {
    pub delivery_key: &'a str,
    pub item_key: &'a str,
    pub claim_token: &'a str,
    pub status: &'a str,
    pub provider_media_id: Option<&'a str>,
    pub provider_client_id: Option<&'a str>,
    pub provider_message_id: Option<&'a str>,
    pub retryable: bool,
    pub last_error: Option<&'a str>,
    pub fallback_used: bool,
}

pub struct DeliveryStageCompletion<'a> {
    pub delivery_key: &'a str,
    pub item_key: &'a str,
    pub claim_token: &'a str,
    pub stage: &'a str,
    pub status: &'a str,
    pub provider_media_id: Option<&'a str>,
    pub provider_client_id: Option<&'a str>,
    pub provider_message_id: Option<&'a str>,
    pub retryable: bool,
    pub last_error: Option<&'a str>,
}

pub struct DeliveryItemUpload<'a> {
    pub delivery_key: &'a str,
    pub item_key: &'a str,
    pub claim_token: &'a str,
    pub stage: &'a str,
    pub provider_media_id: &'a str,
    pub provider_media_state: Value,
    pub provider_client_id: Option<&'a str>,
}

pub struct DeliveryCacheReconciliation {
    pub retained_paths: Vec<PathBuf>,
    pub delete_paths: Vec<PathBuf>,
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
            #[cfg(test)]
            fail_next_write: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_write(&self, operation: &'static str) {
        *self
            .fail_next_write
            .lock()
            .expect("session store failpoint lock poisoned") = Some(operation);
    }

    #[cfg(test)]
    fn fail_write_if_requested(&self, operation: &'static str) -> Result<()> {
        let mut fail_next = self
            .fail_next_write
            .lock()
            .expect("session store failpoint lock poisoned");
        if fail_next.as_ref() == Some(&operation) {
            fail_next.take();
            anyhow::bail!("injected {operation} write failure");
        }
        Ok(())
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
        #[cfg(test)]
        self.fail_write_if_requested("metadata")?;
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
        #[cfg(test)]
        self.fail_write_if_requested("history")?;
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
        #[cfg(test)]
        self.fail_write_if_requested("route")?;
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

    pub fn claim_delivery_item(&self, request: DeliveryItemClaimRequest<'_>) -> Result<Value> {
        let DeliveryItemClaimRequest {
            delivery_key,
            request_fingerprint,
            item_key,
            artifact_id,
            kind,
            owner,
            cache_path,
            lease_seconds,
        } = request;
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let record = records.entry(delivery_key.to_string()).or_insert_with(|| {
                json!({
                    "request_fingerprint": request_fingerprint,
                    "items": {},
                    "updated_at": utc_now_iso(),
                })
            });
            let existing_fingerprint = record
                .get("request_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            if existing_fingerprint != request_fingerprint {
                anyhow::bail!("delivery item request fingerprint conflict");
            }
            let items = record
                .get_mut("items")
                .and_then(Value::as_object_mut)
                .context("delivery item ledger is invalid")?;
            let item = items.entry(item_key.to_string()).or_insert_with(|| {
                json!({
                    "item_key": item_key,
                    "request_fingerprint": request_fingerprint,
                    "artifact_id": artifact_id,
                    "kind": kind,
                    "status": "pending",
                    "attempts": 0,
                    "provider_media_id": null,
                    "provider_media_state": null,
                    "provider_client_id": null,
                    "provider_message_id": null,
                    "stages": {
                        "native": delivery_stage_value(),
                        "fallback": delivery_stage_value(),
                    },
                    "retryable": true,
                    "last_error": null,
                    "owner": null,
                    "claim_token": null,
                    "claim_expires_at": null,
                    "cache_path": cache_path.map(|path| path.to_string_lossy().into_owned()),
                    "updated_at": utc_now_iso(),
                })
            });
            let existing_artifact_id = item.get("artifact_id").and_then(Value::as_str);
            let existing_kind = item.get("kind").and_then(Value::as_str);
            if existing_artifact_id != Some(artifact_id) || existing_kind != Some(kind) {
                anyhow::bail!("delivery item identity conflict");
            }
            match item.get("request_fingerprint").and_then(Value::as_str) {
                Some(existing) if existing != request_fingerprint => {
                    anyhow::bail!("delivery item request fingerprint conflict");
                }
                None => {
                    item.as_object_mut()
                        .context("delivery item ledger entry is invalid")?
                        .insert("request_fingerprint".into(), json!(request_fingerprint));
                }
                Some(_) => {}
            }
            let previous_cache_path = item.get("cache_path").cloned().unwrap_or(Value::Null);
            let status = item.get("status").and_then(Value::as_str).unwrap_or("");
            if status == "succeeded" {
                return Ok(json!({"claim": "succeeded", "item": item.clone()}));
            }
            if status == "failed" && item.get("retryable").and_then(Value::as_bool) == Some(false) {
                return Ok(json!({"claim": "terminal_failed", "item": item.clone()}));
            }
            if status == "sending" && delivery_claim_is_unexpired(item)? {
                return Ok(json!({"claim": "busy", "item": item.clone()}));
            }
            let attempts = item
                .get("attempts")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_add(1);
            let claim_token = Uuid::new_v4().simple().to_string();
            let object = item
                .as_object_mut()
                .context("delivery item ledger entry is invalid")?;
            object.insert("status".into(), json!("sending"));
            object.insert("attempts".into(), json!(attempts));
            object.insert("owner".into(), json!(owner));
            object.insert("claim_token".into(), json!(claim_token));
            object.insert(
                "claim_expires_at".into(),
                json!(delivery_claim_expires_at(lease_seconds)),
            );
            object.insert(
                "cache_path".into(),
                cache_path.map_or(Value::Null, |path| {
                    json!(path.to_string_lossy().into_owned())
                }),
            );
            object.insert("updated_at".into(), json!(utc_now_iso()));
            let claimed = item.clone();
            record["updated_at"] = json!(utc_now_iso());
            self.write_shared_map_unlocked("_delivery_items.json", &records)?;
            Ok(json!({
                "claim": "claimed",
                "claim_token": claim_token,
                "item": claimed,
                "previous_cache_path": previous_cache_path,
            }))
        })
    }

    pub fn persist_delivery_plan(
        &self,
        delivery_key: &str,
        request_fingerprint: &str,
        planned_outbound: Value,
        planned_items: Vec<DeliveryPlanItem>,
    ) -> Result<()> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let record = records.entry(delivery_key.to_string()).or_insert_with(|| {
                json!({
                    "request_fingerprint": request_fingerprint,
                    "planned_outbound": planned_outbound,
                    "items": {},
                    "updated_at": utc_now_iso(),
                })
            });
            if record.get("request_fingerprint").and_then(Value::as_str)
                != Some(request_fingerprint)
            {
                anyhow::bail!("delivery item request fingerprint conflict");
            }
            if record.get("planned_outbound").is_none() {
                record["planned_outbound"] = planned_outbound;
            }
            let items = record
                .get_mut("items")
                .and_then(Value::as_object_mut)
                .context("delivery item ledger is invalid")?;
            for planned in planned_items {
                let materialization_status = if planned.materialization_required {
                    "pending"
                } else {
                    "not_required"
                };
                let item = items.entry(planned.item_key.clone()).or_insert_with(|| {
                    json!({
                        "item_key": planned.item_key,
                        "request_fingerprint": request_fingerprint,
                        "artifact_id": planned.artifact_id,
                        "kind": planned.kind,
                        "planned_outbound": planned.planned_outbound,
                        "materialization": {
                            "status": materialization_status,
                            "attempts": 0,
                            "retryable": planned.materialization_required,
                            "last_error": null,
                            "owner": null,
                            "claim_token": null,
                            "claim_expires_at": null,
                            "updated_at": utc_now_iso(),
                        },
                        "status": "pending",
                        "attempts": 0,
                        "provider_media_id": null,
                        "provider_media_state": null,
                        "provider_client_id": null,
                        "provider_message_id": null,
                        "stages": {
                            "native": delivery_stage_value(),
                            "fallback": delivery_stage_value(),
                        },
                        "retryable": true,
                        "last_error": null,
                        "owner": null,
                        "claim_token": null,
                        "claim_expires_at": null,
                        "cache_path": null,
                        "updated_at": utc_now_iso(),
                    })
                });
                if item.get("artifact_id").and_then(Value::as_str)
                    != Some(planned.artifact_id.as_str())
                    || item.get("kind").and_then(Value::as_str) != Some(planned.kind.as_str())
                    || item.get("request_fingerprint").and_then(Value::as_str)
                        != Some(request_fingerprint)
                {
                    anyhow::bail!("delivery item identity conflict");
                }
                if item.get("planned_outbound").is_none() {
                    item["planned_outbound"] = planned.planned_outbound;
                }
                if item.get("materialization").is_none() {
                    item["materialization"] = json!({
                        "status": materialization_status,
                        "attempts": 0,
                        "retryable": planned.materialization_required,
                        "last_error": null,
                        "owner": null,
                        "claim_token": null,
                        "claim_expires_at": null,
                        "updated_at": utc_now_iso(),
                    });
                }
            }
            record["updated_at"] = json!(utc_now_iso());
            self.write_shared_map_unlocked("_delivery_items.json", &records)
        })
    }

    pub fn claim_delivery_materialization(
        &self,
        delivery_key: &str,
        item_key: &str,
        owner: &str,
        lease_seconds: u64,
    ) -> Result<Value> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let item = records
                .get_mut(delivery_key)
                .and_then(|record| record.get_mut("items"))
                .and_then(Value::as_object_mut)
                .and_then(|items| items.get_mut(item_key))
                .context("delivery materialization item is missing")?;
            let materialization = item
                .get_mut("materialization")
                .and_then(Value::as_object_mut)
                .context("delivery materialization state is invalid")?;
            let status = materialization
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("");
            if matches!(status, "materialized" | "not_required") {
                return Ok(json!({"claim": status, "item": item.clone()}));
            }
            if status == "failed"
                && materialization.get("retryable").and_then(Value::as_bool) == Some(false)
            {
                return Ok(json!({"claim": "terminal_failed", "item": item.clone()}));
            }
            if status == "materializing" && nested_claim_is_unexpired(materialization)? {
                return Ok(json!({"claim": "busy", "item": item.clone()}));
            }
            let attempts = materialization
                .get("attempts")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_add(1);
            let claim_token = Uuid::new_v4().simple().to_string();
            materialization.insert("status".into(), json!("materializing"));
            materialization.insert("attempts".into(), json!(attempts));
            materialization.insert("owner".into(), json!(owner));
            materialization.insert("claim_token".into(), json!(claim_token));
            materialization.insert(
                "claim_expires_at".into(),
                json!(delivery_claim_expires_at(lease_seconds)),
            );
            materialization.insert("updated_at".into(), json!(utc_now_iso()));
            let claimed_item = item.clone();
            self.write_shared_map_unlocked("_delivery_items.json", &records)?;
            Ok(json!({
                "claim": "claimed",
                "claim_token": claim_token,
                "item": claimed_item,
            }))
        })
    }

    pub fn finish_delivery_materialization(
        &self,
        completion: DeliveryMaterializationCompletion<'_>,
    ) -> Result<()> {
        let DeliveryMaterializationCompletion {
            delivery_key,
            item_key,
            claim_token,
            status,
            materialized_outbound,
            cache_path,
            retryable,
            last_error,
        } = completion;
        if !matches!(status, "materialized" | "failed") {
            anyhow::bail!("invalid delivery materialization completion status");
        }
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let item = records
                .get_mut(delivery_key)
                .and_then(|record| record.get_mut("items"))
                .and_then(Value::as_object_mut)
                .and_then(|items| items.get_mut(item_key))
                .context("delivery materialization item is missing")?;
            let materialization = item
                .get_mut("materialization")
                .and_then(Value::as_object_mut)
                .context("delivery materialization state is invalid")?;
            require_active_nested_claim(materialization, claim_token, "materializing")?;
            materialization.insert("status".into(), json!(status));
            materialization.insert("retryable".into(), json!(retryable));
            materialization.insert(
                "last_error".into(),
                last_error.map_or(Value::Null, |value| json!(value)),
            );
            materialization.insert("owner".into(), Value::Null);
            materialization.insert("claim_token".into(), Value::Null);
            materialization.insert("claim_expires_at".into(), Value::Null);
            materialization.insert("updated_at".into(), json!(utc_now_iso()));
            if let Some(materialized_outbound) = materialized_outbound {
                item["materialized_outbound"] = materialized_outbound;
            }
            item["cache_path"] = cache_path.map_or(Value::Null, |path| {
                json!(path.to_string_lossy().into_owned())
            });
            item["status"] = json!(if status == "materialized" {
                "pending"
            } else {
                "failed"
            });
            item["retryable"] = json!(retryable);
            item["last_error"] = last_error.map_or(Value::Null, |value| json!(value));
            item["updated_at"] = json!(utc_now_iso());
            self.write_shared_map_unlocked("_delivery_items.json", &records)
        })
    }

    pub fn retryable_delivery_plans(&self) -> Result<Vec<Value>> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let records = self.load_shared_map_unlocked("_delivery_items.json")?;
            Ok(records
                .into_iter()
                .filter_map(|(delivery_key, record)| {
                    let items = record
                        .get("items")
                        .and_then(Value::as_object);
                    let terminal_failure = items.is_some_and(|items| {
                        items.values().any(|item| {
                            matches!(
                                item.get("status").and_then(Value::as_str),
                                Some("failed" | "terminal_failed")
                            ) && item.get("retryable").and_then(Value::as_bool) == Some(false)
                        })
                    });
                    let retryable = !terminal_failure
                        && items.is_some_and(|items| {
                            items.values().any(|item| {
                                matches!(
                                    item.get("status").and_then(Value::as_str),
                                    Some("pending" | "sending" | "failed")
                                ) && item.get("retryable").and_then(Value::as_bool) != Some(false)
                            })
                        });
                    (retryable && record.get("planned_outbound").is_some()).then(|| {
                        json!({
                            "delivery_key": delivery_key,
                            "request_fingerprint": record.get("request_fingerprint").cloned().unwrap_or(Value::Null),
                            "planned_outbound": record.get("planned_outbound").cloned().unwrap_or(Value::Null),
                        })
                    })
                })
                .collect())
        })
    }

    pub fn retryable_delivery_cache_paths(&self) -> Result<Vec<PathBuf>> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let mut paths = Vec::new();
            for item in records
                .values()
                .filter_map(|record| record.get("items").and_then(Value::as_object))
                .flat_map(|items| items.values())
            {
                let status = item.get("status").and_then(Value::as_str).unwrap_or("");
                let retryable = item
                    .get("retryable")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if matches!(status, "pending" | "sending" | "failed") && retryable {
                    if let Some(path) = item
                        .get("cache_path")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        paths.push(PathBuf::from(path));
                    }
                }
            }
            Ok(paths)
        })
    }

    pub fn reconcile_delivery_cache(
        &self,
        now: DateTime<Utc>,
        ttl: ChronoDuration,
    ) -> Result<DeliveryCacheReconciliation> {
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let mut retained_paths = Vec::new();
            let mut delete_paths = Vec::new();
            let mut changed = false;
            for item in records
                .values_mut()
                .filter_map(|record| record.get_mut("items").and_then(Value::as_object_mut))
                .flat_map(|items| items.values_mut())
            {
                let Some(cache_path) = item
                    .get("cache_path")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                else {
                    continue;
                };
                let status = item.get("status").and_then(Value::as_str).unwrap_or("");
                let retryable = item
                    .get("retryable")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let retryable_state =
                    matches!(status, "pending" | "sending" | "failed") && retryable;
                let updated_at = item
                    .get("updated_at")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
                let expired = retryable_state
                    && updated_at.is_some_and(|updated_at| {
                        now.signed_duration_since(updated_at.with_timezone(&Utc)) > ttl
                    });
                if retryable_state && !expired {
                    if updated_at.is_none() {
                        item.as_object_mut()
                            .context("delivery item ledger entry is invalid")?
                            .insert("updated_at".into(), json!(now.to_rfc3339()));
                        changed = true;
                    }
                    retained_paths.push(cache_path);
                    continue;
                }
                let object = item
                    .as_object_mut()
                    .context("delivery item ledger entry is invalid")?;
                object.insert("cache_path".into(), Value::Null);
                delete_paths.push(cache_path);
                if expired {
                    object.insert("status".into(), json!("expired"));
                    object.insert("retryable".into(), json!(false));
                    object.insert("last_error".into(), json!("delivery cache expired"));
                    object.insert("owner".into(), Value::Null);
                    object.insert("claim_expires_at".into(), Value::Null);
                }
                object.insert("updated_at".into(), json!(now.to_rfc3339()));
                changed = true;
            }
            if changed {
                self.write_shared_map_unlocked("_delivery_items.json", &records)?;
            }
            Ok(DeliveryCacheReconciliation {
                retained_paths,
                delete_paths,
            })
        })
    }

    pub fn record_delivery_item_upload(&self, upload: DeliveryItemUpload<'_>) -> Result<()> {
        let DeliveryItemUpload {
            delivery_key,
            item_key,
            claim_token,
            stage,
            provider_media_id,
            provider_media_state,
            provider_client_id,
        } = upload;
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let item = records
                .get_mut(delivery_key)
                .and_then(|record| record.get_mut("items"))
                .and_then(Value::as_object_mut)
                .and_then(|items| items.get_mut(item_key))
                .context("delivery item claim is missing")?;
            require_active_delivery_claim(item, claim_token)?;
            let item = item
                .as_object_mut()
                .context("delivery item ledger entry is invalid")?;
            let stage_item = delivery_stage_object(item, stage)?;
            stage_item.insert("status".into(), json!("prepared"));
            stage_item.insert("provider_media_id".into(), json!(provider_media_id));
            stage_item.insert("provider_media_state".into(), provider_media_state.clone());
            stage_item.insert(
                "provider_client_id".into(),
                provider_client_id.map_or(Value::Null, |value| json!(value)),
            );
            stage_item.insert("updated_at".into(), json!(utc_now_iso()));
            item.insert("provider_media_id".into(), json!(provider_media_id));
            item.insert("provider_media_state".into(), provider_media_state);
            if let Some(provider_client_id) = provider_client_id {
                item.insert("provider_client_id".into(), json!(provider_client_id));
            }
            item.insert("updated_at".into(), json!(utc_now_iso()));
            self.write_shared_map_unlocked("_delivery_items.json", &records)
        })
    }

    pub fn finish_delivery_stage(&self, completion: DeliveryStageCompletion<'_>) -> Result<()> {
        let DeliveryStageCompletion {
            delivery_key,
            item_key,
            claim_token,
            stage,
            status,
            provider_media_id,
            provider_client_id,
            provider_message_id,
            retryable,
            last_error,
        } = completion;
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let item = records
                .get_mut(delivery_key)
                .and_then(|record| record.get_mut("items"))
                .and_then(Value::as_object_mut)
                .and_then(|items| items.get_mut(item_key))
                .context("delivery item claim is missing")?;
            require_active_delivery_claim(item, claim_token)?;
            let item = item
                .as_object_mut()
                .context("delivery item ledger entry is invalid")?;
            let stage_item = delivery_stage_object(item, stage)?;
            stage_item.insert("status".into(), json!(status));
            if let Some(value) = provider_media_id {
                stage_item.insert("provider_media_id".into(), json!(value));
            }
            if let Some(value) = provider_client_id {
                stage_item.insert("provider_client_id".into(), json!(value));
            }
            if let Some(value) = provider_message_id {
                stage_item.insert("provider_message_id".into(), json!(value));
            }
            stage_item.insert("retryable".into(), json!(retryable));
            stage_item.insert(
                "last_error".into(),
                last_error.map_or(Value::Null, |value| json!(value)),
            );
            stage_item.insert("updated_at".into(), json!(utc_now_iso()));
            self.write_shared_map_unlocked("_delivery_items.json", &records)
        })
    }

    pub fn finish_delivery_item(
        &self,
        completion: DeliveryItemCompletion<'_>,
    ) -> Result<Option<PathBuf>> {
        let DeliveryItemCompletion {
            delivery_key,
            item_key,
            claim_token,
            status,
            provider_media_id,
            provider_client_id,
            provider_message_id,
            retryable,
            last_error,
            fallback_used,
        } = completion;
        let _guard = self.lock.lock().expect("session store lock poisoned");
        self.with_delivery_items_lock(|| {
            let mut records = self.load_shared_map_unlocked("_delivery_items.json")?;
            let item = records
                .get_mut(delivery_key)
                .and_then(|record| record.get_mut("items"))
                .and_then(Value::as_object_mut)
                .and_then(|items| items.get_mut(item_key))
                .context("delivery item claim is missing")?;
            require_active_delivery_claim(item, claim_token)?;
            let item = item
                .as_object_mut()
                .context("delivery item ledger entry is invalid")?;
            item.insert("status".into(), json!(status));
            if let Some(provider_media_id) = provider_media_id {
                item.insert("provider_media_id".into(), json!(provider_media_id));
            }
            if let Some(provider_client_id) = provider_client_id {
                item.insert("provider_client_id".into(), json!(provider_client_id));
            }
            if let Some(provider_message_id) = provider_message_id {
                item.insert("provider_message_id".into(), json!(provider_message_id));
            }
            item.insert("retryable".into(), json!(retryable));
            item.insert(
                "last_error".into(),
                last_error.map_or(Value::Null, |value| json!(value)),
            );
            item.insert("fallback_used".into(), json!(fallback_used));
            item.insert("owner".into(), Value::Null);
            item.insert("claim_expires_at".into(), Value::Null);
            item.insert("updated_at".into(), json!(utc_now_iso()));
            let terminal_cache_path = if status == "succeeded" || !retryable {
                let path = item
                    .get("cache_path")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from);
                item.insert("cache_path".into(), Value::Null);
                path
            } else {
                None
            };
            self.write_shared_map_unlocked("_delivery_items.json", &records)?;
            Ok(terminal_cache_path)
        })
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
        let backup = backup_path(&path);
        if !path.exists() && backup.exists() {
            fs::rename(&backup, &path).with_context(|| {
                format!("failed to recover shared map backup {}", backup.display())
            })?;
        }
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read shared map {}", path.display()))?;
        let payload: Value = serde_json::from_str(&raw)
            .with_context(|| format!("shared map {} contains invalid JSON", path.display()))?;
        if !payload.is_object() {
            anyhow::bail!("shared map {} must be a JSON object", path.display());
        }
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

    fn with_delivery_items_lock<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock_path = self.root.join(DELIVERY_ITEMS_LOCK_FILE);
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| {
                format!("failed to open delivery item lock {}", lock_path.display())
            })?;
        lock_file.lock_exclusive().with_context(|| {
            format!(
                "failed to acquire delivery item lock {}",
                lock_path.display()
            )
        })?;
        action()
    }

    fn write_json(&self, path: &Path, payload: &Value) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let backup = backup_path(path);
        if path.exists() && backup.exists() {
            fs::remove_file(&backup)
                .with_context(|| format!("failed to remove stale backup {}", backup.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(payload)?;
        AtomicFile::new(path, AllowOverwrite)
            .write(|file| -> std::io::Result<()> {
                use std::io::Write as _;
                file.write_all(&bytes)?;
                file.sync_all()?;
                #[cfg(test)]
                if let Err(error) = self.fail_write_if_requested("atomic_replace") {
                    return Err(std::io::Error::other(error.to_string()));
                }
                Ok(())
            })
            .map_err(std::io::Error::from)
            .with_context(|| format!("failed to atomically replace {}", path.display()))
    }

    fn session_path(&self, platform: &str, chat_id: &str) -> PathBuf {
        self.root
            .join(format!("{}__{}.json", slug(platform), slug(chat_id)))
    }
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("bak")
}

fn delivery_claim_is_unexpired(item: &Value) -> Result<bool> {
    let updated_at = item
        .get("updated_at")
        .and_then(Value::as_str)
        .context("delivery claim lease updated_at is missing")?;
    let updated_at = DateTime::parse_from_rfc3339(updated_at)
        .context("delivery claim lease updated_at is malformed")?
        .with_timezone(&Utc);
    let expires_at = match item.get("claim_expires_at") {
        Some(Value::String(value)) => DateTime::parse_from_rfc3339(value)
            .context("delivery claim lease claim_expires_at is malformed")?
            .with_timezone(&Utc),
        Some(_) => anyhow::bail!("delivery claim lease claim_expires_at is malformed"),
        None => updated_at + ChronoDuration::seconds(LEGACY_DELIVERY_CLAIM_LEASE_SECONDS),
    };
    Ok(expires_at > Utc::now())
}

fn nested_claim_is_unexpired(claim: &serde_json::Map<String, Value>) -> Result<bool> {
    let updated_at = claim
        .get("updated_at")
        .and_then(Value::as_str)
        .context("nested delivery claim updated_at is missing")?;
    let updated_at = DateTime::parse_from_rfc3339(updated_at)
        .context("nested delivery claim updated_at is malformed")?
        .with_timezone(&Utc);
    let expires_at = match claim.get("claim_expires_at") {
        Some(Value::String(value)) => DateTime::parse_from_rfc3339(value)
            .context("nested delivery claim claim_expires_at is malformed")?
            .with_timezone(&Utc),
        Some(_) => anyhow::bail!("nested delivery claim claim_expires_at is malformed"),
        None => updated_at + ChronoDuration::seconds(LEGACY_DELIVERY_CLAIM_LEASE_SECONDS),
    };
    Ok(expires_at > Utc::now())
}

fn require_active_nested_claim(
    claim: &serde_json::Map<String, Value>,
    claim_token: &str,
    active_status: &str,
) -> Result<()> {
    let active = claim.get("status").and_then(Value::as_str) == Some(active_status)
        && claim
            .get("claim_token")
            .and_then(Value::as_str)
            .is_some_and(|stored| !stored.is_empty() && stored == claim_token)
        && nested_claim_is_unexpired(claim)?;
    if !active {
        anyhow::bail!("stale nested delivery claim");
    }
    Ok(())
}

fn require_active_delivery_claim(item: &Value, claim_token: &str) -> Result<()> {
    let lease_is_unexpired = delivery_claim_is_unexpired(item)?;
    let active = item.get("status").and_then(Value::as_str) == Some("sending")
        && item
            .get("claim_token")
            .and_then(Value::as_str)
            .is_some_and(|stored| !stored.is_empty() && stored == claim_token)
        && lease_is_unexpired;
    if !active {
        anyhow::bail!("stale delivery item claim");
    }
    Ok(())
}

fn delivery_claim_expires_at(lease_seconds: u64) -> String {
    let seconds = i64::try_from(lease_seconds.max(1)).unwrap_or(i64::MAX);
    Utc::now()
        .checked_add_signed(ChronoDuration::seconds(seconds))
        .unwrap_or_else(|| Utc::now() + ChronoDuration::days(365_000))
        .to_rfc3339()
}

fn delivery_stage_value() -> Value {
    json!({
        "status": "pending",
        "provider_media_id": null,
        "provider_media_state": null,
        "provider_client_id": null,
        "provider_message_id": null,
        "retryable": true,
        "last_error": null,
        "updated_at": utc_now_iso(),
    })
}

fn delivery_stage_object<'a>(
    item: &'a mut serde_json::Map<String, Value>,
    stage: &str,
) -> Result<&'a mut serde_json::Map<String, Value>> {
    if !matches!(stage, "native" | "fallback") {
        anyhow::bail!("invalid delivery stage");
    }
    let stages = item
        .entry("stages")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("delivery item stages are invalid")?;
    stages
        .entry(stage)
        .or_insert_with(delivery_stage_value)
        .as_object_mut()
        .context("delivery stage is invalid")
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
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::tempdir;

    fn write_sending_claim_fixture(
        ledger_path: &Path,
        claim_expires_at: Option<&str>,
        updated_at: &str,
    ) -> Vec<u8> {
        let mut item = json!({
            "item_key": "delivery-lease:artifact-1",
            "artifact_id": "artifact-1",
            "kind": "video",
            "status": "sending",
            "attempts": 1,
            "owner": "legacy-process",
            "retryable": true,
            "updated_at": updated_at,
        });
        if let Some(value) = claim_expires_at {
            item["claim_expires_at"] = json!(value);
        }
        let bytes = serde_json::to_vec(&json!({
            "delivery-lease": {
                "request_fingerprint": "fingerprint",
                "items": {"delivery-lease:artifact-1": item}
            }
        }))
        .unwrap();
        fs::write(ledger_path, &bytes).unwrap();
        bytes
    }

    fn claim_lease_fixture(store: &FileSessionStore) -> Result<Value> {
        store.claim_delivery_item(DeliveryItemClaimRequest {
            delivery_key: "delivery-lease",
            request_fingerprint: "fingerprint",
            item_key: "delivery-lease:artifact-1",
            artifact_id: "artifact-1",
            kind: "video",
            owner: "replacement-process",
            cache_path: None,
            lease_seconds: 300,
        })
    }

    #[test]
    fn delivery_item_claim_rejects_existing_item_identity_changes() {
        let dir = tempdir().unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();
        let claim = |artifact_id: &str, kind: &str, fingerprint: &str| {
            store.claim_delivery_item(DeliveryItemClaimRequest {
                delivery_key: "delivery-identity",
                request_fingerprint: fingerprint,
                item_key: "delivery-identity:item:v1:8:artifact",
                artifact_id,
                kind,
                owner: "test-process",
                cache_path: None,
                lease_seconds: 300,
            })
        };

        claim("artifact", "video", "fingerprint").unwrap();

        assert!(claim("other-artifact", "video", "fingerprint")
            .unwrap_err()
            .to_string()
            .contains("identity conflict"));
        assert!(claim("artifact", "file", "fingerprint")
            .unwrap_err()
            .to_string()
            .contains("identity conflict"));
        assert!(claim("artifact", "video", "different-fingerprint")
            .unwrap_err()
            .to_string()
            .contains("fingerprint conflict"));
    }

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

    #[test]
    fn atomic_replace_fault_keeps_previous_main_file_unchanged() {
        let dir = tempdir().unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();
        let route_path = dir.path().join("_routes.json");
        store
            .register_route("route-atomic", json!({"version": "old"}))
            .unwrap();
        let original = fs::read(&route_path).unwrap();
        assert!(!backup_path(&route_path).exists());
        store.fail_next_write("atomic_replace");

        let result = store.register_route("route-atomic", json!({"version": "new"}));

        assert!(result.is_err());
        assert_eq!(fs::read(&route_path).unwrap(), original);
        assert!(!backup_path(&route_path).exists());
    }

    #[test]
    fn legacy_backup_is_recovered_only_when_main_file_is_missing() {
        let missing_main_dir = tempdir().unwrap();
        let missing_main = missing_main_dir.path().join("_routes.json");
        let missing_main_backup = backup_path(&missing_main);
        fs::write(
            &missing_main_backup,
            serde_json::to_vec(&json!({"route-backup": {"source": "backup"}})).unwrap(),
        )
        .unwrap();
        let store = FileSessionStore::new(missing_main_dir.path()).unwrap();
        assert_eq!(
            store.resolve_route("route-backup").unwrap().unwrap()["source"],
            "backup"
        );
        assert!(missing_main.exists());

        let stale_backup_dir = tempdir().unwrap();
        let main = stale_backup_dir.path().join("_routes.json");
        let stale_backup = backup_path(&main);
        fs::write(
            &main,
            serde_json::to_vec(&json!({"route-main": {"source": "main"}})).unwrap(),
        )
        .unwrap();
        let stale_bytes =
            serde_json::to_vec(&json!({"route-main": {"source": "stale-backup"}})).unwrap();
        fs::write(&stale_backup, &stale_bytes).unwrap();
        let store = FileSessionStore::new(stale_backup_dir.path()).unwrap();
        assert_eq!(
            store.resolve_route("route-main").unwrap().unwrap()["source"],
            "main"
        );
        assert_eq!(fs::read(stale_backup).unwrap(), stale_bytes);
    }

    #[test]
    fn independent_stores_allow_only_one_unexpired_delivery_claim() {
        let dir = tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for owner in ["process-a", "process-b"] {
            let store = FileSessionStore::new(dir.path()).unwrap();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .claim_delivery_item(DeliveryItemClaimRequest {
                        delivery_key: "delivery-concurrent",
                        request_fingerprint: "fingerprint",
                        item_key: "delivery-concurrent:artifact-1",
                        artifact_id: "artifact-1",
                        kind: "video",
                        owner,
                        cache_path: None,
                        lease_seconds: 300,
                    })
                    .unwrap()
            }));
        }

        let claims: Vec<Value> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            claims
                .iter()
                .filter(|claim| claim["claim"] == "claimed")
                .count(),
            1
        );
        assert_eq!(
            claims
                .iter()
                .filter(|claim| claim["claim"] == "busy")
                .count(),
            1
        );
        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        assert!(
            ledger["delivery-concurrent"]["items"]["delivery-concurrent:artifact-1"]
                ["claim_expires_at"]
                .as_str()
                .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
        );
    }

    #[test]
    fn expired_delivery_claim_can_be_recovered_by_another_owner() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("_delivery_items.json");
        let expired_at = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        fs::write(
            &ledger_path,
            serde_json::to_vec(&json!({
                "delivery-expired": {
                    "request_fingerprint": "fingerprint",
                    "items": {
                        "delivery-expired:artifact-1": {
                            "item_key": "delivery-expired:artifact-1",
                            "artifact_id": "artifact-1",
                            "kind": "video",
                            "status": "sending",
                            "attempts": 1,
                            "owner": "dead-process",
                            "claim_expires_at": expired_at,
                            "retryable": true,
                            "updated_at": (chrono::Utc::now() - chrono::Duration::minutes(2)).to_rfc3339()
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();

        let claim = store
            .claim_delivery_item(DeliveryItemClaimRequest {
                delivery_key: "delivery-expired",
                request_fingerprint: "fingerprint",
                item_key: "delivery-expired:artifact-1",
                artifact_id: "artifact-1",
                kind: "video",
                owner: "replacement-process",
                cache_path: None,
                lease_seconds: 900,
            })
            .unwrap();

        assert_eq!(claim["claim"], "claimed");
        assert_eq!(claim["item"]["owner"], "replacement-process");
        assert_eq!(claim["item"]["attempts"], 2);
        let renewed_at = claim["item"]["claim_expires_at"].as_str().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(renewed_at).unwrap()
                > chrono::Utc::now() + chrono::Duration::minutes(14)
        );
    }

    #[test]
    fn reclaimed_delivery_claim_gets_a_new_fencing_token() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("_delivery_items.json");
        let store = FileSessionStore::new(dir.path()).unwrap();
        let claim_a = store
            .claim_delivery_item(DeliveryItemClaimRequest {
                delivery_key: "delivery-fenced",
                request_fingerprint: "fingerprint",
                item_key: "delivery-fenced:artifact-1",
                artifact_id: "artifact-1",
                kind: "video",
                owner: "process-a",
                cache_path: None,
                lease_seconds: 300,
            })
            .unwrap();
        let mut ledger: Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
        ledger["delivery-fenced"]["items"]["delivery-fenced:artifact-1"]["claim_expires_at"] =
            json!((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
        fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();

        let claim_b = store
            .claim_delivery_item(DeliveryItemClaimRequest {
                delivery_key: "delivery-fenced",
                request_fingerprint: "fingerprint",
                item_key: "delivery-fenced:artifact-1",
                artifact_id: "artifact-1",
                kind: "video",
                owner: "process-b",
                cache_path: None,
                lease_seconds: 300,
            })
            .unwrap();

        let token_a = claim_a["claim_token"].as_str().unwrap();
        let token_b = claim_b["claim_token"].as_str().unwrap();
        assert!(!token_a.is_empty());
        assert!(!token_b.is_empty());
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn stale_delivery_claim_cannot_write_after_reclaim() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("_delivery_items.json");
        let store = FileSessionStore::new(dir.path()).unwrap();
        let claim_a = store
            .claim_delivery_item(DeliveryItemClaimRequest {
                delivery_key: "delivery-stale",
                request_fingerprint: "fingerprint",
                item_key: "delivery-stale:artifact-1",
                artifact_id: "artifact-1",
                kind: "video",
                owner: "process-a",
                cache_path: None,
                lease_seconds: 300,
            })
            .unwrap();
        let token_a = claim_a["claim_token"].as_str().unwrap().to_string();
        let mut ledger: Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
        ledger["delivery-stale"]["items"]["delivery-stale:artifact-1"]["claim_expires_at"] =
            json!((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
        fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        let claim_b = store
            .claim_delivery_item(DeliveryItemClaimRequest {
                delivery_key: "delivery-stale",
                request_fingerprint: "fingerprint",
                item_key: "delivery-stale:artifact-1",
                artifact_id: "artifact-1",
                kind: "video",
                owner: "process-b",
                cache_path: None,
                lease_seconds: 300,
            })
            .unwrap();
        assert_ne!(claim_b["claim_token"], claim_a["claim_token"]);
        let claimed_by_b = fs::read(&ledger_path).unwrap();

        let upload = store.record_delivery_item_upload(DeliveryItemUpload {
            delivery_key: "delivery-stale",
            item_key: "delivery-stale:artifact-1",
            claim_token: &token_a,
            stage: "native",
            provider_media_id: "media-from-a",
            provider_media_state: json!({"upload": "from-a"}),
            provider_client_id: Some("client-from-a"),
        });
        assert!(upload.unwrap_err().to_string().contains("stale"));
        assert_eq!(fs::read(&ledger_path).unwrap(), claimed_by_b);

        let stage = store.finish_delivery_stage(DeliveryStageCompletion {
            delivery_key: "delivery-stale",
            item_key: "delivery-stale:artifact-1",
            claim_token: &token_a,
            stage: "native",
            status: "succeeded",
            provider_media_id: Some("media-from-a"),
            provider_client_id: Some("client-from-a"),
            provider_message_id: Some("message-from-a"),
            retryable: false,
            last_error: None,
        });
        assert!(stage.unwrap_err().to_string().contains("stale"));
        assert_eq!(fs::read(&ledger_path).unwrap(), claimed_by_b);

        let finish = store.finish_delivery_item(DeliveryItemCompletion {
            delivery_key: "delivery-stale",
            item_key: "delivery-stale:artifact-1",
            claim_token: &token_a,
            status: "succeeded",
            provider_media_id: Some("media-from-a"),
            provider_client_id: Some("client-from-a"),
            provider_message_id: Some("message-from-a"),
            retryable: false,
            last_error: None,
            fallback_used: false,
        });
        assert!(finish.unwrap_err().to_string().contains("stale"));
        assert_eq!(fs::read(&ledger_path).unwrap(), claimed_by_b);
    }

    #[test]
    fn legacy_sending_claim_uses_updated_at_for_lease() {
        let fresh_dir = tempdir().unwrap();
        write_sending_claim_fixture(
            &fresh_dir.path().join("_delivery_items.json"),
            None,
            &(Utc::now() - ChronoDuration::minutes(1)).to_rfc3339(),
        );
        let fresh_store = FileSessionStore::new(fresh_dir.path()).unwrap();
        assert_eq!(claim_lease_fixture(&fresh_store).unwrap()["claim"], "busy");

        let expired_dir = tempdir().unwrap();
        write_sending_claim_fixture(
            &expired_dir.path().join("_delivery_items.json"),
            None,
            &(Utc::now() - ChronoDuration::minutes(6)).to_rfc3339(),
        );
        let expired_store = FileSessionStore::new(expired_dir.path()).unwrap();
        assert_eq!(
            claim_lease_fixture(&expired_store).unwrap()["claim"],
            "claimed"
        );
    }

    #[test]
    fn malformed_delivery_claim_lease_fields_fail_closed_without_rewrite() {
        let valid_updated_at = Utc::now().to_rfc3339();
        let valid_expires_at = (Utc::now() + ChronoDuration::minutes(5)).to_rfc3339();
        for (claim_expires_at, updated_at) in [
            (Some("not-a-timestamp"), valid_updated_at.as_str()),
            (None, "not-a-timestamp"),
            (Some(valid_expires_at.as_str()), "not-a-timestamp"),
        ] {
            let dir = tempdir().unwrap();
            let ledger_path = dir.path().join("_delivery_items.json");
            let original = write_sending_claim_fixture(&ledger_path, claim_expires_at, updated_at);
            let store = FileSessionStore::new(dir.path()).unwrap();

            let error = claim_lease_fixture(&store).unwrap_err();

            assert!(error.to_string().contains("lease"));
            assert_eq!(fs::read(&ledger_path).unwrap(), original);
        }
    }

    #[test]
    fn nonretryable_failed_delivery_claim_is_terminal() {
        let dir = tempdir().unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();
        let first = claim_lease_fixture(&store).unwrap();
        let claim_token = first["claim_token"].as_str().unwrap();
        store
            .finish_delivery_item(DeliveryItemCompletion {
                delivery_key: "delivery-lease",
                item_key: "delivery-lease:artifact-1",
                claim_token,
                status: "failed",
                provider_media_id: Some("provider-media-terminal"),
                provider_client_id: Some("provider-client-terminal"),
                provider_message_id: Some("provider-message-terminal"),
                retryable: false,
                last_error: Some("provider authorization failed deterministically"),
                fallback_used: false,
            })
            .unwrap();

        let replay = claim_lease_fixture(&store).unwrap();

        assert_eq!(replay["claim"], "terminal_failed");
        assert_eq!(replay["item"]["status"], "failed");
        assert_eq!(replay["item"]["retryable"], false);
        assert_eq!(
            replay["item"]["provider_media_id"],
            "provider-media-terminal"
        );
        assert_eq!(
            replay["item"]["provider_client_id"],
            "provider-client-terminal"
        );
        assert_eq!(
            replay["item"]["provider_message_id"],
            "provider-message-terminal"
        );
        assert_eq!(
            replay["item"]["last_error"],
            "provider authorization failed deterministically"
        );
    }

    #[test]
    fn terminal_failed_item_blocks_recovery_of_remaining_delivery_items() {
        let dir = tempdir().unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();
        fs::write(
            dir.path().join("_delivery_items.json"),
            serde_json::to_vec_pretty(&json!({
                "delivery-terminal-batch": {
                    "request_fingerprint": "fingerprint",
                    "planned_outbound": {"platform": "weixin", "chat_id": "wx-user"},
                    "items": {
                        "delivery-terminal-batch:text": {
                            "status": "failed",
                            "retryable": false
                        },
                        "delivery-terminal-batch:image": {
                            "status": "pending",
                            "retryable": true
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert!(store.retryable_delivery_plans().unwrap().is_empty());
    }

    #[test]
    fn corrupt_delivery_ledger_is_not_rewritten_during_claim() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("_delivery_items.json");
        let corrupt = b"{\"delivery\":";
        fs::write(&ledger_path, corrupt).unwrap();
        let store = FileSessionStore::new(dir.path()).unwrap();

        let result = store.claim_delivery_item(DeliveryItemClaimRequest {
            delivery_key: "delivery-corrupt",
            request_fingerprint: "fingerprint",
            item_key: "delivery-corrupt:artifact-1",
            artifact_id: "artifact-1",
            kind: "video",
            owner: "process-a",
            cache_path: None,
            lease_seconds: 300,
        });

        assert!(result.is_err());
        assert_eq!(fs::read(ledger_path).unwrap(), corrupt);
    }
}
