use crate::adapters::feishu::FeishuAdapter;
use crate::adapters::feishu_mail::FeishuMailAdapter;
use crate::adapters::webhook::WebhookAdapter;
use crate::adapters::weixin::WeixinAdapter;
use crate::adapters::whatsapp::{WhatsAppAdapter, WhatsAppConfig};
use crate::adapters::{PlatformAdapter, PreparedOutbound};
use crate::cloud_relay::CloudRelayClient;
use crate::config::AppConfig;
use crate::error::GatewayError;
use crate::harborbeacon::{
    build_channel_turn_request, derive_route_key, derive_session_id, stable_id,
    HarborBeaconTaskClient,
};
use crate::models::{ConversationTurn, InboundMessage, OutboundMessage};
use crate::navi_fleet::NaviFleet;
use crate::store::{
    DeliveryItemClaimRequest, DeliveryItemCompletion, DeliveryItemUpload,
    DeliveryMaterializationCompletion, DeliveryPlanItem, DeliveryStageCompletion, FileSessionStore,
};
use axum::http::StatusCode;
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use cap_std::io_lifetimes::AsFilelike;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

#[cfg(test)]
#[path = "whatsapp_delivery_tests.rs"]
mod whatsapp_delivery_tests;

#[cfg(test)]
#[path = "gateway_fleet_tests.rs"]
mod fleet_tests;

pub(crate) struct AttachmentCacheRoot {
    path: PathBuf,
    trusted_parent_path: PathBuf,
    cache_basename: PathBuf,
    trusted_parent_dir: Dir,
    dir: Dir,
}

impl AttachmentCacheRoot {
    pub(crate) fn open(trusted_parent: &Path, cache_basename: &Path) -> std::io::Result<Self> {
        Self::open_after_create(trusted_parent, cache_basename, || {})
    }

    fn open_after_create(
        trusted_parent: &Path,
        cache_basename: &Path,
        after_create: impl FnOnce(),
    ) -> std::io::Result<Self> {
        let mut components = cache_basename.components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "attachment cache basename must be one normal path component",
            ));
        }
        fs::create_dir_all(trusted_parent)?;
        let trusted_parent_dir = Dir::open_ambient_dir(trusted_parent, ambient_authority())?;
        if let Err(error) = trusted_parent_dir.create_dir(cache_basename) {
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        after_create();
        let child_dir = cap_primitives::fs::open_dir_nofollow(
            &trusted_parent_dir.as_filelike_view::<fs::File>(),
            cache_basename,
        )?;
        Ok(Self {
            path: trusted_parent.join(cache_basename),
            trusted_parent_path: trusted_parent.to_path_buf(),
            cache_basename: cache_basename.to_path_buf(),
            trusted_parent_dir,
            dir: Dir::from_std_file(child_dir),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn relative_path(&self, candidate: &Path) -> std::io::Result<PathBuf> {
        let relative = candidate.strip_prefix(&self.path).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "attachment cache path is outside the capability root",
            )
        })?;
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "attachment cache path is not a safe root-relative path",
            ));
        }
        Ok(relative.to_path_buf())
    }

    fn ensure_visible_root(&self) -> std::io::Result<()> {
        let visible_parent = Dir::open_ambient_dir(&self.trusted_parent_path, ambient_authority())?;
        if !same_directory(&visible_parent, &self.trusted_parent_dir)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "attachment cache parent was replaced after startup",
            ));
        }
        let visible_root = Dir::from_std_file(cap_primitives::fs::open_dir_nofollow(
            &visible_parent.as_filelike_view::<fs::File>(),
            &self.cache_basename,
        )?);
        if !same_directory(&visible_root, &self.dir)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "attachment cache root was replaced after startup",
            ));
        }
        Ok(())
    }

    pub(crate) fn create_dir(&self, candidate: &Path) -> std::io::Result<()> {
        self.ensure_visible_root()?;
        let relative = self.relative_path(candidate)?;
        match self.dir.create_dir(&relative) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let opened = cap_primitives::fs::open_dir_nofollow(
            &self.dir.as_filelike_view::<fs::File>(),
            &relative,
        )?;
        drop(opened);
        Ok(())
    }

    pub(crate) fn create_new_file(&self, candidate: &Path) -> std::io::Result<fs::File> {
        self.ensure_visible_root()?;
        let relative = self.relative_path(candidate)?;
        self.dir
            .open_with(
                relative,
                cap_std::fs::OpenOptions::new().create_new(true).write(true),
            )
            .map(cap_std::fs::File::into_std)
    }

    fn entries(&self) -> std::io::Result<cap_std::fs::ReadDir> {
        self.dir.entries()
    }

    fn open_dir(&self, candidate: &Path) -> std::io::Result<Dir> {
        let relative = self.relative_path(candidate)?;
        cap_primitives::fs::open_dir_nofollow(&self.dir.as_filelike_view::<fs::File>(), &relative)
            .map(Dir::from_std_file)
    }

    pub(crate) fn remove_file(&self, candidate: &Path) -> std::io::Result<()> {
        let relative = self.relative_path(candidate)?;
        self.dir.remove_file(relative)
    }

    #[cfg(test)]
    fn remove_file_with_hook(&self, candidate: &Path, hook: impl FnOnce()) -> std::io::Result<()> {
        let relative = self.relative_path(candidate)?;
        hook();
        self.dir.remove_file(relative)
    }

    pub(crate) fn remove_dir(&self, candidate: &Path) -> std::io::Result<()> {
        let relative = self.relative_path(candidate)?;
        self.dir.remove_dir(relative)
    }
}

#[cfg(unix)]
fn same_directory(left: &Dir, right: &Dir) -> std::io::Result<bool> {
    use cap_std::fs::MetadataExt;

    let left = left.dir_metadata()?;
    let right = right.dir_metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_directory(left: &Dir, right: &Dir) -> std::io::Result<bool> {
    use cap_primitives::fs::_WindowsByHandle;

    let left = left.dir_metadata()?;
    let right = right.dir_metadata()?;
    Ok(matches!(
        (
            left.volume_serial_number(),
            left.file_index(),
            right.volume_serial_number(),
            right.file_index(),
        ),
        (Some(left_volume), Some(left_index), Some(right_volume), Some(right_index))
            if left_volume == right_volume && left_index == right_index
    ))
}

pub struct GatewayService {
    store: Arc<FileSessionStore>,
    task_client: Option<HarborBeaconTaskClient>,
    fleet: Option<NaviFleet>,
    adapters: BTreeMap<String, Arc<dyn PlatformAdapter>>,
    feishu_adapter: Arc<FeishuAdapter>,
    feishu_mail_adapter: Arc<FeishuMailAdapter>,
    weixin_adapter: Arc<WeixinAdapter>,
    whatsapp_adapter: Arc<WhatsAppAdapter>,
    attachment_cache_root: Arc<AttachmentCacheRoot>,
    public_origin: String,
    delivery_instance_id: String,
}

struct AttachmentCacheGuard {
    root: Arc<AttachmentCacheRoot>,
    files: Vec<PathBuf>,
    directory: Option<PathBuf>,
}

struct DeliveryStageRequest<'a> {
    claim: &'a Value,
    delivery_key: &'a str,
    item_key: &'a str,
    claim_token: &'a str,
    stage: &'a str,
}

impl AttachmentCacheGuard {
    fn new(
        root: Arc<AttachmentCacheRoot>,
        files: Vec<PathBuf>,
        directory: Option<PathBuf>,
    ) -> Self {
        Self {
            root,
            files,
            directory,
        }
    }

    fn disarm_path(&mut self, path: &Path) {
        self.files.retain(|candidate| candidate != path);
        if self.files.is_empty() {
            self.directory = None;
        }
    }
}

impl Drop for AttachmentCacheGuard {
    fn drop(&mut self) {
        for path in self.files.drain(..) {
            if let Err(error) = self.root.remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %path.display(), error = %error, "Could not remove guarded Gate attachment cache file");
                }
            }
        }
        if let Some(path) = self.directory.take() {
            if let Err(error) = self.root.remove_dir(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %path.display(), error = %error, "Could not remove guarded Gate attachment cache directory");
                }
            }
        }
    }
}

impl GatewayService {
    pub fn from_config(config: &AppConfig) -> anyhow::Result<Self> {
        let store = Arc::new(FileSessionStore::new(&config.data_dir)?);
        let attachment_cache_root = Arc::new(AttachmentCacheRoot::open(
            &config.state_dir,
            Path::new("attachment-cache"),
        )?);
        let cache_reconciliation = store.reconcile_delivery_cache(
            chrono::Utc::now(),
            chrono::Duration::from_std(ATTACHMENT_CACHE_TTL)?,
        )?;
        remove_reconciled_attachment_cache(
            &attachment_cache_root,
            cache_reconciliation.delete_paths,
        )?;
        sweep_expired_attachment_cache(
            &attachment_cache_root,
            &cache_reconciliation.retained_paths,
            SystemTime::now(),
        )?;
        let mut adapters: BTreeMap<String, Arc<dyn PlatformAdapter>> = BTreeMap::new();
        let webhook = Arc::new(WebhookAdapter);
        adapters.insert(webhook.name().to_string(), webhook);
        let feishu = Arc::new(FeishuAdapter::new(config.feishu.clone()));
        adapters.insert(feishu.name().to_string(), feishu.clone());
        let feishu_mail = Arc::new(FeishuMailAdapter::new(config.feishu_mail.clone()));
        adapters.insert(feishu_mail.name().to_string(), feishu_mail.clone());
        let weixin = Arc::new(WeixinAdapter::new(config.weixin.clone()));
        adapters.insert(weixin.name().to_string(), weixin.clone());
        let whatsapp = Arc::new(WhatsAppAdapter::new(
            WhatsAppConfig::from_env(),
            config.state_dir.join("attachment-cache"),
        ));
        adapters.insert(whatsapp.name().to_string(), whatsapp.clone());
        let fleet = if config.cloud_relay_url.is_empty() && config.cloud_relay_region.is_empty() {
            None
        } else {
            Some(NaviFleet::new(
                CloudRelayClient::from_ecs(&config.cloud_relay_url, &config.cloud_relay_region)?,
                config.state_dir.join("navi-routes"),
            ))
        };
        Ok(Self {
            fleet,
            store,
            task_client: HarborBeaconTaskClient::from_config(config),
            adapters,
            feishu_adapter: feishu,
            feishu_mail_adapter: feishu_mail,
            weixin_adapter: weixin,
            whatsapp_adapter: whatsapp,
            attachment_cache_root,
            public_origin: config.public_origin.trim_end_matches('/').to_string(),
            delivery_instance_id: Uuid::new_v4().simple().to_string(),
        })
    }

    pub fn adapter(&self, name: &str) -> Option<Arc<dyn PlatformAdapter>> {
        self.adapters.get(name).cloned()
    }

    pub fn feishu_adapter(&self) -> Arc<FeishuAdapter> {
        self.feishu_adapter.clone()
    }

    pub fn feishu_mail_adapter(&self) -> Arc<FeishuMailAdapter> {
        self.feishu_mail_adapter.clone()
    }

    pub fn weixin_adapter(&self) -> Arc<WeixinAdapter> {
        self.weixin_adapter.clone()
    }
    pub fn whatsapp_adapter(&self) -> Arc<WhatsAppAdapter> {
        self.whatsapp_adapter.clone()
    }

    pub async fn retry_pending_deliveries(&self) -> Result<usize, GatewayError> {
        let plans = self
            .store
            .retryable_delivery_plans()
            .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
        let mut attempted = 0usize;
        for plan in plans {
            let delivery_key = plan
                .get("delivery_key")
                .and_then(Value::as_str)
                .unwrap_or("");
            let request_fingerprint = plan
                .get("request_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            let outbound: OutboundMessage = serde_json::from_value(
                plan.get("planned_outbound").cloned().unwrap_or(Value::Null),
            )
            .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
            let adapter_name = outbound
                .metadata
                .get("adapter")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(&outbound.platform);
            let Some(adapter) = self.adapter(adapter_name) else {
                tracing::warn!(
                    delivery_key,
                    adapter = adapter_name,
                    "Could not recover delivery because its adapter is unavailable"
                );
                continue;
            };
            attempted = attempted.saturating_add(1);
            if let Err(error) = self
                .deliver_outbound_items_guarded(
                    adapter,
                    outbound,
                    delivery_key,
                    request_fingerprint,
                    None,
                )
                .await
            {
                tracing::warn!(delivery_key, error = %error, "Retryable delivery recovery failed");
            }
        }
        Ok(attempted)
    }

    pub async fn handle_inbound(
        &self,
        adapter_name: &str,
        payload: Value,
    ) -> Result<Value, GatewayError> {
        let adapter = self
            .adapter(adapter_name)
            .ok_or_else(|| GatewayError::validation(format!("Unknown adapter: {adapter_name}")))?;
        let inbound = adapter.normalize_inbound(payload)?;
        let selection = if inbound.platform == "whatsapp" {
            if let Some(fleet) = &self.fleet {
                if inbound.text.trim().starts_with("NAVI ") {
                    fleet.begin(&inbound)?;
                    self.store.register_route(&inbound.route_key,json!({"route_key":inbound.route_key,
                        "platform":inbound.platform,"chat_id":inbound.chat_id,"user_id":inbound.user_id,
                        "adapter_name":adapter_name,"session_id":inbound.session_id,"status":"active"}))
                        .map_err(|err|GatewayError::infrastructure(err.to_string()))?;
                    return Ok(json!({"accepted":true,"status":"awaiting_navi_confirmation"}));
                }
                Some(fleet.select(&inbound)?)
            } else {
                None
            }
        } else {
            None
        };
        let session_key = selection
            .as_ref()
            .map(|selection| selection.session_key(&inbound))
            .unwrap_or_else(|| inbound.chat_id.clone());
        let selected_client = match (&self.fleet, &selection) {
            (Some(fleet), Some(selection)) => Some(HarborBeaconTaskClient::from_cloud_relay(
                fleet.relay.with_hub_identity(&selection.hub_identity)?,
                &selection.hub_id,
            )?),
            _ => self.task_client.clone(),
        };
        let history = self
            .store
            .load_history(&inbound.platform, &session_key)
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        let session_metadata = self
            .store
            .load_metadata(&inbound.platform, &session_key)
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        let resolved_route_key = inbound
            .route_key
            .trim()
            .to_string()
            .if_empty_then(|| {
                session_metadata
                    .get("route_key")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .if_empty_then(|| derive_route_key(&inbound));
        let resolved_session_id = inbound
            .session_id
            .trim()
            .to_string()
            .if_empty_then(|| derive_session_id(&inbound));

        let (reply_text, outbound_attachments, mut outbound_metadata, next_metadata) =
            if let Some(task_client) = &selected_client {
                let task_result = task_client.submit_turn(&inbound, &session_metadata).await?;
                let attachment_candidates =
                    native_source_bound_attachments(adapter_name, &task_result.response_payload);
                let reply_text = render_retrieval_reply(
                    &task_result.text,
                    &task_result.response_payload,
                    !attachment_candidates.is_empty(),
                    &self.public_origin,
                );
                let mut next_metadata = session_metadata.clone();
                next_metadata.insert("route_key".into(), json!(task_result.route_key));
                next_metadata.insert("session_id".into(), json!(resolved_session_id));
                next_metadata.insert("last_turn_id".into(), json!(task_result.task_id));
                next_metadata.insert("last_trace_id".into(), json!(task_result.trace_id));
                if !inbound.message_id.trim().is_empty() {
                    next_metadata.insert("last_message_id".into(), json!(inbound.message_id));
                }
                if let Some(handle) = &task_result.conversation_handle {
                    next_metadata.insert("conversation_handle".into(), json!(handle));
                }
                if let Some(continuation) = &task_result.continuation {
                    next_metadata.insert("continuation".into(), continuation.clone());
                } else {
                    next_metadata.remove("continuation");
                }
                if !inbound.message_id.trim().is_empty() {
                    let mut message_turns = session_metadata
                        .get("message_turn_ids")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();
                    message_turns.insert(inbound.message_id.clone(), json!(task_result.task_id));
                    next_metadata.insert("message_turn_ids".into(), Value::Object(message_turns));
                }
                let mut metadata = serde_json::Map::new();
                metadata.insert("adapter".into(), json!(adapter_name));
                metadata.insert("source".into(), json!("harborbeacon"));
                metadata.insert("turn_id".into(), json!(task_result.task_id));
                metadata.insert("task_id".into(), json!(task_result.task_id));
                metadata.insert("trace_id".into(), json!(task_result.trace_id));
                metadata.insert("status".into(), json!(task_result.status));
                metadata.insert("route_key".into(), json!(task_result.route_key));
                metadata.insert(
                    "delivery_request_fingerprint".into(),
                    json!(fingerprint(&task_result.response_payload)),
                );
                metadata.insert(
                    "conversation_handle".into(),
                    json!(task_result.conversation_handle),
                );
                metadata.insert(
                    "active_frame".into(),
                    task_result.active_frame.unwrap_or(Value::Null),
                );
                metadata.insert(
                    "continuation".into(),
                    task_result.continuation.unwrap_or(Value::Null),
                );
                metadata.insert("next_actions".into(), json!(task_result.next_actions));
                metadata.insert(
                    "native_attachment_count".into(),
                    json!(attachment_candidates.len()),
                );
                metadata.insert("native_attachment_materialize_failed".into(), json!(0));
                (reply_text, attachment_candidates, metadata, next_metadata)
            } else {
                let mut next_metadata = session_metadata.clone();
                next_metadata.insert("route_key".into(), json!(resolved_route_key));
                next_metadata.insert("session_id".into(), json!(resolved_session_id));
                let mut metadata = serde_json::Map::new();
                metadata.insert("adapter".into(), json!(adapter_name));
                metadata.insert("source".into(), json!("rule_based_fallback"));
                (
                    fallback_reply(&history, &inbound),
                    vec![],
                    metadata,
                    next_metadata,
                )
            };

        self.store
            .set_metadata(&inbound.platform, &session_key, next_metadata)
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        self.store
            .register_route(
                &resolved_route_key,
                json!({
                    "route_key": resolved_route_key,
                    "platform": inbound.platform,
                    "chat_id": inbound.chat_id,
                    "user_id": inbound.user_id,
                    "adapter_name": adapter_name,
                    "session_id": resolved_session_id,
                    "status": "active",
                }),
            )
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        self.store
            .append_turns(
                &inbound.platform,
                &session_key,
                vec![
                    ConversationTurn {
                        role: "user".into(),
                        content: inbound.text.clone(),
                        timestamp: crate::models::utc_now_iso(),
                    },
                    ConversationTurn {
                        role: "assistant".into(),
                        content: reply_text.clone(),
                        timestamp: crate::models::utc_now_iso(),
                    },
                ],
            )
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        outbound_metadata.insert("route_key".into(), json!(resolved_route_key));
        if let Some(selection) = selection {
            outbound_metadata.insert(
                "navi_selection".into(),
                serde_json::to_value(selection).map_err(|_| {
                    GatewayError::infrastructure("Navi routing is temporarily unavailable")
                })?,
            );
        }
        let outbound = OutboundMessage {
            platform: inbound.platform,
            chat_id: inbound.chat_id,
            text: reply_text,
            attachments: outbound_attachments,
            timestamp: crate::models::utc_now_iso(),
            metadata: outbound_metadata,
        };
        let delivery_key = outbound
            .metadata
            .get("turn_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let delivery_fingerprint = outbound
            .metadata
            .get("delivery_request_fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
            .if_empty_then(|| fingerprint(&json!({"turn_id": delivery_key})));
        self.deliver_outbound_items_guarded(
            adapter,
            outbound,
            &delivery_key,
            &delivery_fingerprint,
            None,
        )
        .await
    }

    pub async fn handle_gateway_turn(&self, payload: Value) -> Result<Value, GatewayError> {
        let Some(task_client) = &self.task_client else {
            return Err(GatewayError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "HARBORBEACON_DISABLED",
                "HarborBeacon turn forwarding is not configured",
            ));
        };
        let inbound = gateway_turn_to_inbound(&payload)?;
        if inbound.platform == "whatsapp" && self.fleet.is_some() {
            return Err(GatewayError::validation(
                "Use the official WhatsApp inbox for Navi conversations",
            ));
        }
        reject_unbound_dlna_turn(&payload)?;
        let mut session_metadata = self
            .store
            .load_metadata(&inbound.platform, &inbound.chat_id)
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        if let Some(handle) = payload
            .pointer("/conversation/handle")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            session_metadata.insert("conversation_handle".into(), json!(handle.trim()));
        }
        if let Some(continuation) = payload
            .get("continuation")
            .filter(|value| value.is_object())
        {
            session_metadata.insert("continuation".into(), continuation.clone());
        }

        let conversation_handle = session_metadata
            .get("conversation_handle")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string);
        let continuation = session_metadata
            .get("continuation")
            .filter(|value| value.is_object())
            .cloned();
        let request_payload = build_channel_turn_request(
            &inbound,
            &payload,
            conversation_handle.as_deref(),
            continuation,
        );
        let task_result = task_client.submit_turn_payload(request_payload).await?;

        let resolved_route_key = task_result
            .route_key
            .trim()
            .to_string()
            .if_empty_then(|| derive_route_key(&inbound));
        let resolved_session_id = derive_session_id(&inbound);
        let mut next_metadata = session_metadata;
        next_metadata.insert("route_key".into(), json!(resolved_route_key));
        next_metadata.insert("session_id".into(), json!(resolved_session_id));
        next_metadata.insert("last_turn_id".into(), json!(task_result.task_id));
        next_metadata.insert("last_trace_id".into(), json!(task_result.trace_id));
        if let Some(handle) = &task_result.conversation_handle {
            next_metadata.insert("conversation_handle".into(), json!(handle));
        }
        if let Some(continuation) = &task_result.continuation {
            next_metadata.insert("continuation".into(), continuation.clone());
        } else {
            next_metadata.remove("continuation");
        }
        if !inbound.message_id.trim().is_empty() {
            next_metadata.insert("last_message_id".into(), json!(inbound.message_id));
        }
        self.store
            .set_metadata(&inbound.platform, &inbound.chat_id, next_metadata)
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        self.store
            .register_route(
                &resolved_route_key,
                json!({
                    "route_key": resolved_route_key,
                    "platform": inbound.platform,
                    "chat_id": inbound.chat_id,
                    "user_id": inbound.user_id,
                    "adapter_name": inbound.platform,
                    "session_id": resolved_session_id,
                    "status": "active",
                    "route_mode": "channel_edge",
                    "route_source": "gateway_turn",
                }),
            )
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;
        self.store
            .append_turns(
                &inbound.platform,
                &inbound.chat_id,
                vec![
                    ConversationTurn {
                        role: "user".into(),
                        content: inbound.text.clone(),
                        timestamp: crate::models::utc_now_iso(),
                    },
                    ConversationTurn {
                        role: "assistant".into(),
                        content: task_result.text.clone(),
                        timestamp: crate::models::utc_now_iso(),
                    },
                ],
            )
            .map_err(|err| GatewayError::infrastructure(err.to_string()))?;

        Ok(task_result.response_payload)
    }

    pub async fn handle_notification_delivery(
        &self,
        payload: Value,
    ) -> Result<Value, GatewayError> {
        self.handle_notification_delivery_from(payload, None).await
    }

    async fn handle_notification_delivery_from(
        &self,
        payload: Value,
        selection: Option<&crate::navi_fleet::Selection>,
    ) -> Result<Value, GatewayError> {
        let trace_id = notification_trace_id(&payload);
        let notification_id = notification_id(&payload);
        if notification_id.is_empty() {
            return Err(
                GatewayError::validation("notification_id is required").with_trace(trace_id)
            );
        }
        let destination = payload
            .get("destination")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                GatewayError::validation("destination must be an object")
                    .with_trace(trace_id.clone())
            })?;
        let delivery = payload
            .get("delivery")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                GatewayError::validation("delivery must be an object").with_trace(trace_id.clone())
            })?;
        let mode = delivery
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let idempotency_key = delivery
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let reply_to_message_id = delivery
            .get("reply_to_message_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let update_message_id = delivery
            .get("update_message_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        validate_delivery_mode(&mode, &reply_to_message_id, &update_message_id, &trace_id)?;
        if idempotency_key.is_empty() {
            return Err(
                GatewayError::validation("delivery.idempotency_key is required")
                    .with_trace(trace_id),
            );
        }

        let route_key = destination
            .get("route_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let route = self.resolve_notification_route(destination, &route_key, &trace_id)?;
        let adapter_name = route
            .get("adapter_name")
            .or_else(|| route.get("platform"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let adapter = self.adapter(&adapter_name).ok_or_else(|| {
            GatewayError::validation(format!(
                "No adapter is enabled for outbound platform route: {}",
                if adapter_name.is_empty() {
                    "unknown"
                } else {
                    &adapter_name
                }
            ))
            .with_trace(trace_id.clone())
        })?;

        if route["platform"] == "whatsapp" && self.fleet.is_some() && selection.is_none() {
            return Err(GatewayError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NAVI_REMOTE_NOTIFICATION_REQUIRED",
                "Navi notifications require their originating device connection",
            ));
        }
        let mut effective_request = json!({
            "notification_id": notification_id,
            "trace_id": trace_id,
            "destination": {
                "route_key": route_key,
                "platform": route.get("platform").cloned().unwrap_or(Value::Null),
                "chat_id": route.get("chat_id").cloned().unwrap_or(Value::Null),
                "recipient": destination.get("recipient").cloned().unwrap_or(Value::Null),
            },
            "content": delivery_content(&payload),
            "delivery": {
                "mode": mode,
                "reply_to_message_id": reply_to_message_id,
                "update_message_id": update_message_id,
            },
        });
        let peer_reminder = matches!(
            route["platform"].as_str(),
            Some("feishu" | "weixin" | "feishu_mail")
        ) && peer_reminder_notification(&payload);
        if peer_reminder {
            effective_request["peer_reminder"] = json!(true);
        }
        if route["platform"] == "whatsapp" || payload.get("conversation").is_some() {
            effective_request["conversation"] =
                payload.get("conversation").cloned().unwrap_or(Value::Null);
        }
        if let Some(selection) = selection {
            effective_request["navi_selection"] = json!(selection);
        }
        let fingerprint = fingerprint(&effective_request);
        if let Some(record) = self
            .store
            .load_delivery_record(&idempotency_key)
            .map_err(|err| {
                GatewayError::infrastructure(err.to_string()).with_trace(trace_id.clone())
            })?
        {
            let existing = record
                .get("request_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            if existing != fingerprint {
                return Err(GatewayError::new(
                    StatusCode::CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "delivery.idempotency_key was reused with a different effective request",
                )
                .with_trace(trace_id));
            }
            if let Some(response) = record.get("response_payload") {
                let retryable_failure = response
                    .get("ok")
                    .and_then(Value::as_bool)
                    .is_some_and(|ok| !ok)
                    && response
                        .get("retryable")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                if !retryable_failure {
                    return Ok(response.clone());
                }
            }
        }

        let content = delivery_content(&payload);
        let outbound_attachments = hinted_notification_attachments(&content);
        let mut outbound = OutboundMessage {
            platform: route
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or(&adapter_name)
                .to_string(),
            chat_id: route
                .get("chat_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            text: notification_text(&content),
            attachments: outbound_attachments,
            timestamp: crate::models::utc_now_iso(),
            metadata: outbound_delivery_metadata(NotificationDeliveryMetadata {
                notification_id: &notification_id,
                trace_id: &trace_id,
                mode: &mode,
                route_key: &route_key,
                reply_to_message_id: &reply_to_message_id,
                update_message_id: &update_message_id,
                route: &route,
                content: &content,
                destination,
                idempotency_key: &idempotency_key,
            }),
        };
        if peer_reminder {
            outbound
                .metadata
                .insert("peer_reminder".into(), json!(true));
        }
        if let Some(event) = payload
            .pointer("/source/event_type")
            .or_else(|| payload.pointer("/notification/event_type"))
            .and_then(Value::as_str)
        {
            outbound
                .metadata
                .insert("notification_event_type".into(), json!(event));
        }
        // Preserve the originating Beacon handle, never substitute the latest
        // route's handle when an old notification is retried after rebinding.
        if outbound.platform == "whatsapp" || payload.get("conversation").is_some() {
            outbound.metadata.insert(
                "conversation_handle".into(),
                payload
                    .pointer("/conversation/handle")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        if let Some(selection) = selection {
            outbound
                .metadata
                .insert("navi_selection".into(), json!(selection));
        }
        let delivery_id = stable_id("delivery_", &idempotency_key, 24);
        let response_payload = match self
            .deliver_outbound_items_guarded(adapter, outbound, &idempotency_key, &fingerprint, None)
            .await
        {
            Ok(adapter_response) => {
                let provider_message_id = adapter_response
                    .get("message_id")
                    .or_else(|| adapter_response.get("provider_message_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                json!({
                    "delivery_id": delivery_id,
                    "notification_id": notification_id,
                    "trace_id": trace_id,
                    "ok": true,
                    "status": adapter_response.get("placeholder_status").and_then(Value::as_str).unwrap_or("sent"),
                    "platform": route.get("platform").and_then(Value::as_str).unwrap_or(&adapter_name),
                    "provider_message_id": if provider_message_id.is_empty() { Value::Null } else { json!(provider_message_id) },
                    "retryable": false,
                    "error": null,
                })
            }
            Err(error) if error.code == "IDEMPOTENCY_CONFLICT" => {
                return Err(error.with_trace(trace_id))
            }
            Err(error) => {
                let (code, retryable) = map_delivery_failure(&error.message);
                let provider_message_id = error
                    .delivery_failure
                    .as_ref()
                    .and_then(|item| item.get("provider_message_id"))
                    .cloned()
                    .unwrap_or(Value::Null);
                json!({
                    "delivery_id": delivery_id,
                    "notification_id": notification_id,
                    "trace_id": trace_id,
                    "ok": false,
                    "status": "failed",
                    "platform": route.get("platform").and_then(Value::as_str).unwrap_or(&adapter_name),
                    "provider_message_id": provider_message_id,
                    "retryable": retryable,
                    "error": {
                        "code": code,
                        "message": error.message,
                    },
                })
            }
        };
        if response_payload
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let classification = classify_delivery_attempt(&route, &response_payload);
            self.store
                .save_delivery_record(
                    &idempotency_key,
                    &fingerprint,
                    response_payload.clone(),
                    classification,
                )
                .map_err(|err| {
                    GatewayError::infrastructure(err.to_string()).with_trace(trace_id)
                })?;
        }
        Ok(response_payload)
    }

    async fn authorize_delivery_context(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<(), GatewayError> {
        let result: Result<(), GatewayError> = async {
            self.authorize_camera_delivery(outbound).await?;
            if matches!(
                outbound.platform.as_str(),
                "feishu" | "weixin" | "feishu_mail"
            ) && peer_reminder_outbound(outbound)
            {
                self.outbound_task_client(outbound)?
                    .authorize_peer_delivery(outbound)
                    .await?;
            }
            if outbound.platform == "whatsapp" {
                let client = self.outbound_task_client(outbound)?;
                client.authorize_whatsapp_delivery(outbound).await?;
                if let Some(fleet) = &self.fleet {
                    fleet.check(outbound)?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            if error.code == "NAVI_IDENTITY_CHANGED" {
                if let (Some(fleet), Some(value)) =
                    (&self.fleet, outbound.metadata.get("navi_selection"))
                {
                    if let Ok(selection) = serde_json::from_value(value.clone()) {
                        fleet.invalidate_identity(&selection)?;
                    }
                }
            }
        }
        result
    }

    async fn authorize_camera_delivery(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<(), GatewayError> {
        let cameras: Vec<_> = outbound
            .attachments
            .iter()
            .filter(|artifact| {
                artifact["url"]
                    .as_str()
                    .is_some_and(|url| url.contains("/api/cameras/recordings/artifacts/"))
            })
            .cloned()
            .collect();
        if cameras.is_empty() {
            return Ok(());
        }
        let client = self.outbound_task_client(outbound)?;
        client.authorize_camera_attachments(&cameras).await
    }

    fn outbound_task_client(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<HarborBeaconTaskClient, GatewayError> {
        if outbound.platform == "whatsapp" {
            if let Some(fleet) = &self.fleet {
                let selection = fleet.check(outbound)?;
                return HarborBeaconTaskClient::from_cloud_relay(
                    fleet.relay.with_hub_identity(&selection.hub_identity)?,
                    &selection.hub_id,
                );
            }
            if outbound.metadata.contains_key("navi_selection") {
                return Err(GatewayError::infrastructure(
                    "Navi routing is temporarily unavailable",
                ));
            }
        }
        self.task_client.clone().ok_or_else(|| {
            GatewayError::infrastructure("WhatsApp delivery check is temporarily unavailable")
        })
    }

    pub async fn refresh_navi_binding(&self) -> Result<bool, GatewayError> {
        let Some(fleet) = &self.fleet else {
            return Ok(false);
        };
        let proof = fleet.refresh_one().await;
        // An unavailable new proof must not prevent a persisted route update
        // for the former home from being delivered.
        let route = fleet.refresh_route_update().await;
        Ok(proof? | route?)
    }

    /// Pull only from a currently selected, device-authenticated Navi. Browser
    /// notification POSTs cannot supply the Selection authority used here.
    pub async fn poll_navi_notifications(&self) -> Result<usize, GatewayError> {
        let Some(fleet) = &self.fleet else {
            return Ok(0);
        };
        let Some((selection, scope)) = fleet.notification_target()? else {
            return Ok(0);
        };
        let relay = fleet.relay.with_hub_identity(&selection.hub_identity)?;
        let batch = match relay.notification_outbox(&selection.hub_id, &scope).await {
            Ok(batch) => batch,
            Err(error) => {
                if error.code == "NAVI_IDENTITY_CHANGED" {
                    fleet.invalidate_identity(&selection)?;
                }
                return Err(error);
            }
        };
        let items = batch["items"]
            .as_array()
            .filter(|items| items.len() <= 4)
            .ok_or_else(|| GatewayError::infrastructure("Invalid Navi notification batch"))?;
        let mut acknowledged = 0;
        for item in items {
            let payload = &item["payload"];
            if item["queue_id"]
                .as_str()
                .is_none_or(|id| id.is_empty() || id.len() > 128)
                || payload["notification"]["notification_id"] != item["queue_id"]
                || payload["destination"]["route_key"] != scope["route_key"]
            {
                return Err(GatewayError::infrastructure(
                    "Invalid Navi notification scope",
                ));
            }
            let route = self
                .store
                .resolve_route(scope["route_key"].as_str().unwrap_or(""))
                .map_err(|_| {
                    GatewayError::infrastructure("Navi notification route is unavailable")
                })?;
            if route.as_ref().is_none_or(|route| {
                route["platform"] != "whatsapp" || route["chat_id"] != scope["recipient"]
            }) {
                return Err(GatewayError::infrastructure(
                    "Navi notification route has changed",
                ));
            }
            let receipt = self
                .handle_notification_delivery_from(payload.clone(), Some(&selection))
                .await?;
            let mut request = scope.clone();
            request["queue_id"] = item["queue_id"].clone();
            request["receipt"] = receipt;
            if relay
                .notification_receipt(&selection.hub_id, &request)
                .await?["acknowledged"]
                != true
            {
                return Err(GatewayError::infrastructure(
                    "Navi did not acknowledge notification receipt",
                ));
            }
            acknowledged += 1;
        }
        Ok(acknowledged)
    }

    async fn send_delivery_stage(
        &self,
        adapter: &Arc<dyn PlatformAdapter>,
        outbound: OutboundMessage,
        request: DeliveryStageRequest<'_>,
    ) -> (Result<Value, GatewayError>, Option<PreparedOutbound>) {
        let DeliveryStageRequest {
            claim,
            delivery_key,
            item_key,
            claim_token,
            stage,
        } = request;
        let stage_pointer = format!("/item/stages/{stage}");
        let stage_item = claim.pointer(&stage_pointer).unwrap_or(&Value::Null);
        let mut prepared = stage_item
            .get("provider_media_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|provider_media_id| PreparedOutbound {
                provider_media_id: provider_media_id.to_string(),
                provider_client_id: stage_item
                    .get("provider_client_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
                state: stage_item
                    .get("provider_media_state")
                    .cloned()
                    .unwrap_or(Value::Null),
            });
        if prepared.is_none() && stage == "native" {
            prepared = claim
                .pointer("/item/provider_media_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|provider_media_id| PreparedOutbound {
                    provider_media_id: provider_media_id.to_string(),
                    provider_client_id: claim
                        .pointer("/item/provider_client_id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string),
                    state: claim
                        .pointer("/item/provider_media_state")
                        .cloned()
                        .unwrap_or(Value::Null),
                });
        }

        let result = if let Err(error) = self.authorize_delivery_context(&outbound).await {
            Err(error)
        } else if prepared.is_none() {
            match adapter.prepare_outbound(&outbound).await {
                Ok(Some(value)) => {
                    if let Err(error) = self.store.record_delivery_item_upload(DeliveryItemUpload {
                        delivery_key,
                        item_key,
                        claim_token,
                        stage,
                        provider_media_id: &value.provider_media_id,
                        provider_media_state: value.state.clone(),
                        provider_client_id: value.provider_client_id.as_deref(),
                    }) {
                        return (
                            Err(GatewayError::infrastructure(error.to_string())),
                            Some(value),
                        );
                    }
                    prepared = Some(value);
                    match self.authorize_delivery_context(&outbound).await {
                        Ok(()) => {
                            adapter
                                .send_prepared_outbound(outbound, prepared.as_ref())
                                .await
                        }
                        Err(error) => Err(error),
                    }
                }
                Ok(None) => match self.authorize_delivery_context(&outbound).await {
                    Ok(()) => adapter.send_prepared_outbound(outbound, None).await,
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            }
        } else {
            adapter
                .send_prepared_outbound(outbound, prepared.as_ref())
                .await
        };

        let stage_completion = match &result {
            Ok(response) => DeliveryStageCompletion {
                delivery_key,
                item_key,
                claim_token,
                stage,
                status: "succeeded",
                provider_media_id: response
                    .get("provider_media_id")
                    .or_else(|| response.get("media_id"))
                    .and_then(Value::as_str)
                    .or_else(|| {
                        prepared
                            .as_ref()
                            .map(|value| value.provider_media_id.as_str())
                    }),
                provider_client_id: response
                    .get("provider_client_id")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        prepared
                            .as_ref()
                            .and_then(|value| value.provider_client_id.as_deref())
                    }),
                provider_message_id: response
                    .get("provider_message_id")
                    .or_else(|| response.get("message_id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty()),
                retryable: false,
                last_error: None,
            },
            Err(error) => {
                let unsupported = should_fallback_to_file(error);
                let (_, retryable) = map_delivery_failure(&error.message);
                DeliveryStageCompletion {
                    delivery_key,
                    item_key,
                    claim_token,
                    stage,
                    status: if unsupported { "unsupported" } else { "failed" },
                    provider_media_id: prepared
                        .as_ref()
                        .map(|value| value.provider_media_id.as_str()),
                    provider_client_id: prepared
                        .as_ref()
                        .and_then(|value| value.provider_client_id.as_deref()),
                    provider_message_id: None,
                    retryable: !unsupported && retryable,
                    last_error: Some(&error.message),
                }
            }
        };
        if let Err(error) = self.store.finish_delivery_stage(stage_completion) {
            return (
                Err(GatewayError::infrastructure(error.to_string())),
                prepared,
            );
        }
        (result, prepared)
    }

    #[cfg(test)]
    async fn deliver_outbound_items(
        &self,
        adapter: Arc<dyn PlatformAdapter>,
        outbound: OutboundMessage,
        delivery_key: &str,
        request_fingerprint: &str,
    ) -> Result<Value, GatewayError> {
        self.deliver_outbound_items_guarded(
            adapter,
            outbound,
            delivery_key,
            request_fingerprint,
            None,
        )
        .await
    }

    async fn deliver_outbound_items_guarded(
        &self,
        adapter: Arc<dyn PlatformAdapter>,
        outbound: OutboundMessage,
        delivery_key: &str,
        request_fingerprint: &str,
        mut cache_guard: Option<&mut AttachmentCacheGuard>,
    ) -> Result<Value, GatewayError> {
        if delivery_key.trim().is_empty() {
            if outbound.platform == "whatsapp" {
                return Err(GatewayError::new(
                    StatusCode::FORBIDDEN,
                    "IM_DELIVERY_NOT_ALLOWED",
                    "WhatsApp delivery permission requires a persistent delivery reference",
                ));
            }
            self.authorize_delivery_context(&outbound).await?;
            return adapter.send_outbound(outbound).await;
        }
        let planned_outbound = serde_json::to_value(&outbound)
            .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
        let delivery_items = split_outbound_items(outbound)?;
        let planned_items = delivery_items
            .iter()
            .map(
                |(item_identity, artifact_id, kind, item_outbound)| -> Result<_, GatewayError> {
                    Ok(DeliveryPlanItem {
                        item_key: delivery_item_key(delivery_key, item_identity),
                        artifact_id: artifact_id.clone(),
                        kind: kind.clone(),
                        planned_outbound: serde_json::to_value(item_outbound)
                            .map_err(|error| GatewayError::infrastructure(error.to_string()))?,
                        materialization_required: delivery_item_requires_materialization(
                            adapter.name(),
                            item_outbound,
                        ),
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        self.store
            .persist_delivery_plan(
                delivery_key,
                request_fingerprint,
                planned_outbound,
                planned_items,
            )
            .map_err(|error| {
                if error.to_string().contains("conflict") {
                    GatewayError::new(
                        StatusCode::CONFLICT,
                        "IDEMPOTENCY_CONFLICT",
                        "delivery key was reused with a different effective plan",
                    )
                } else {
                    GatewayError::infrastructure(error.to_string())
                }
            })?;
        let mut last_response = json!({});
        for (item_identity, artifact_id, kind, item_outbound) in delivery_items {
            let item_key = delivery_item_key(delivery_key, &item_identity);
            let mut item_outbound = self
                .materialize_delivery_item(&adapter, delivery_key, &item_key, item_outbound)
                .await?;
            let cache_path = item_outbound
                .attachments
                .first()
                .and_then(|attachment| attachment.get("path"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from);
            let claim = self
                .store
                .claim_delivery_item(DeliveryItemClaimRequest {
                    delivery_key,
                    request_fingerprint,
                    item_key: &item_key,
                    artifact_id: &artifact_id,
                    kind: &kind,
                    owner: &self.delivery_instance_id,
                    cache_path: cache_path.as_deref(),
                    lease_seconds: adapter.delivery_claim_lease_seconds(),
                })
                .map_err(|error| {
                    if error.to_string().contains("fingerprint conflict")
                        || error.to_string().contains("identity conflict")
                    {
                        GatewayError::new(
                            StatusCode::CONFLICT,
                            "IDEMPOTENCY_CONFLICT",
                            "delivery key was reused with a different effective request",
                        )
                    } else {
                        GatewayError::infrastructure(error.to_string())
                    }
                })?;
            match claim.get("claim").and_then(Value::as_str) {
                Some("succeeded") => {
                    last_response = json!({
                        "message_id": claim.pointer("/item/provider_message_id").cloned().unwrap_or(Value::Null),
                        "provider_message_id": claim.pointer("/item/provider_message_id").cloned().unwrap_or(Value::Null),
                        "provider_media_id": claim.pointer("/item/provider_media_id").cloned().unwrap_or(Value::Null),
                        "provider_client_id": claim.pointer("/item/provider_client_id").cloned().unwrap_or(Value::Null),
                    });
                    continue;
                }
                Some("terminal_failed") => {
                    let item = claim.get("item").cloned().unwrap_or(Value::Null);
                    let message = item
                        .get("last_error")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .unwrap_or("delivery item previously failed terminally")
                        .to_string();
                    return Err(GatewayError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DELIVERY_TERMINAL_FAILED",
                        message,
                    )
                    .with_delivery_failure(item));
                }
                Some("busy") => {
                    return Err(GatewayError::infrastructure(
                        "delivery item is already being sent",
                    ));
                }
                Some("claimed") => {
                    if let (Some(cache_path), Some(cache_guard)) =
                        (cache_path.as_deref(), cache_guard.as_deref_mut())
                    {
                        cache_guard.disarm_path(cache_path);
                    }
                }
                _ => {
                    return Err(GatewayError::infrastructure(
                        "delivery item ledger returned an invalid claim",
                    ));
                }
            }
            let claim_token = claim
                .get("claim_token")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    GatewayError::infrastructure(
                        "delivery item ledger returned a claim without a fencing token",
                    )
                })?;
            item_outbound
                .metadata
                .insert("delivery_key".into(), json!(delivery_key));
            item_outbound
                .metadata
                .insert("delivery_item_key".into(), json!(item_key));
            if let Some(metadata) = item_outbound
                .attachments
                .first_mut()
                .and_then(Value::as_object_mut)
                .and_then(|attachment| attachment.get_mut("metadata"))
                .and_then(Value::as_object_mut)
            {
                metadata.insert("delivery_item_key".into(), json!(item_key));
            }
            let fallback_outbound = native_video_file_fallback(&item_outbound);
            let native_is_unsupported = claim
                .pointer("/item/stages/native/status")
                .and_then(Value::as_str)
                == Some("unsupported");
            let (send_result, prepared, fallback_used) = if native_is_unsupported {
                if let Some(fallback_outbound) = fallback_outbound {
                    let (result, prepared) = self
                        .send_delivery_stage(
                            &adapter,
                            fallback_outbound,
                            DeliveryStageRequest {
                                claim: &claim,
                                delivery_key,
                                item_key: &item_key,
                                claim_token,
                                stage: "fallback",
                            },
                        )
                        .await;
                    (result, prepared, true)
                } else {
                    (
                        Err(GatewayError::infrastructure(
                            "native delivery is unsupported and no fallback is available",
                        )),
                        None,
                        false,
                    )
                }
            } else {
                let (native_result, native_prepared) = self
                    .send_delivery_stage(
                        &adapter,
                        item_outbound,
                        DeliveryStageRequest {
                            claim: &claim,
                            delivery_key,
                            item_key: &item_key,
                            claim_token,
                            stage: "native",
                        },
                    )
                    .await;
                match (native_result, fallback_outbound) {
                    (Err(native_error), Some(fallback_outbound))
                        if should_fallback_to_file(&native_error) =>
                    {
                        let (result, prepared) = self
                            .send_delivery_stage(
                                &adapter,
                                fallback_outbound,
                                DeliveryStageRequest {
                                    claim: &claim,
                                    delivery_key,
                                    item_key: &item_key,
                                    claim_token,
                                    stage: "fallback",
                                },
                            )
                            .await;
                        (result, prepared, true)
                    }
                    (result, _) => (result, native_prepared, false),
                }
            };
            match send_result {
                Ok(response) => {
                    let provider_message_id = response
                        .get("provider_message_id")
                        .or_else(|| response.get("message_id"))
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty());
                    let provider_media_id = response
                        .get("provider_media_id")
                        .or_else(|| response.get("media_id"))
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .or_else(|| {
                            prepared
                                .as_ref()
                                .map(|value| value.provider_media_id.as_str())
                        });
                    let provider_client_id = response
                        .get("provider_client_id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .or_else(|| {
                            prepared
                                .as_ref()
                                .and_then(|value| value.provider_client_id.as_deref())
                        });
                    let terminal_cache_path = self
                        .store
                        .finish_delivery_item(DeliveryItemCompletion {
                            delivery_key,
                            item_key: &item_key,
                            claim_token,
                            status: "succeeded",
                            provider_media_id,
                            provider_client_id,
                            provider_message_id,
                            retryable: false,
                            last_error: None,
                            fallback_used,
                        })
                        .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
                    if let Some(path) = terminal_cache_path {
                        cleanup_attachment_cache(
                            &self.attachment_cache_root,
                            vec![path.clone()],
                            path.parent().map(Path::to_path_buf),
                        )
                        .await;
                    }
                    if let Some(previous) = claim
                        .get("previous_cache_path")
                        .and_then(Value::as_str)
                        .map(PathBuf::from)
                        .filter(|path| cache_path.as_ref() != Some(path))
                    {
                        cleanup_attachment_cache(
                            &self.attachment_cache_root,
                            vec![previous.clone()],
                            previous.parent().map(Path::to_path_buf),
                        )
                        .await;
                    }
                    last_response = response;
                }
                Err(error) => {
                    let (_, retryable) = map_delivery_failure(&error.message);
                    let terminal_cache_path = self
                        .store
                        .finish_delivery_item(DeliveryItemCompletion {
                            delivery_key,
                            item_key: &item_key,
                            claim_token,
                            status: "failed",
                            provider_media_id: prepared
                                .as_ref()
                                .map(|value| value.provider_media_id.as_str()),
                            provider_client_id: prepared
                                .as_ref()
                                .and_then(|value| value.provider_client_id.as_deref()),
                            provider_message_id: None,
                            retryable,
                            last_error: Some(&error.message),
                            fallback_used,
                        })
                        .map_err(|store_error| {
                            GatewayError::infrastructure(store_error.to_string())
                        })?;
                    if let Some(path) = terminal_cache_path {
                        cleanup_attachment_cache(
                            &self.attachment_cache_root,
                            vec![path.clone()],
                            path.parent().map(Path::to_path_buf),
                        )
                        .await;
                    }
                    return Err(error);
                }
            }
        }
        Ok(last_response)
    }

    async fn materialize_delivery_item(
        &self,
        adapter: &Arc<dyn PlatformAdapter>,
        delivery_key: &str,
        item_key: &str,
        planned_outbound: OutboundMessage,
    ) -> Result<OutboundMessage, GatewayError> {
        if !delivery_item_requires_materialization(adapter.name(), &planned_outbound) {
            return Ok(planned_outbound);
        }
        let claim = self
            .store
            .claim_delivery_materialization(
                delivery_key,
                item_key,
                &self.delivery_instance_id,
                adapter.delivery_claim_lease_seconds(),
            )
            .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
        match claim.get("claim").and_then(Value::as_str) {
            Some("materialized") => {
                return serde_json::from_value(
                    claim
                        .pointer("/item/materialized_outbound")
                        .cloned()
                        .ok_or_else(|| {
                            GatewayError::infrastructure(
                                "materialized delivery item is missing its outbound payload",
                            )
                        })?,
                )
                .map_err(|error| GatewayError::infrastructure(error.to_string()));
            }
            Some("not_required") => return Ok(planned_outbound),
            Some("terminal_failed") => {
                return Err(GatewayError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "DELIVERY_MATERIALIZATION_TERMINAL_FAILED",
                    claim
                        .pointer("/item/materialization/last_error")
                        .and_then(Value::as_str)
                        .unwrap_or("delivery materialization previously failed terminally"),
                ));
            }
            Some("busy") => {
                return Err(GatewayError::infrastructure(
                    "delivery item is already being materialized",
                ));
            }
            Some("claimed") => {}
            _ => {
                return Err(GatewayError::infrastructure(
                    "delivery materialization ledger returned an invalid claim",
                ));
            }
        }
        let claim_token = claim
            .get("claim_token")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                GatewayError::infrastructure(
                    "delivery materialization claim is missing a fencing token",
                )
            })?;
        if planned_outbound.platform == "whatsapp" {
            let authorization = self.authorize_delivery_context(&planned_outbound).await;
            if let Err(error) = authorization {
                self.store
                    .finish_delivery_materialization(DeliveryMaterializationCompletion {
                        delivery_key,
                        item_key,
                        claim_token,
                        status: "failed",
                        materialized_outbound: None,
                        cache_path: None,
                        retryable: map_delivery_failure(&error.message).1,
                        last_error: Some(&error.message),
                    })
                    .map_err(|e| GatewayError::infrastructure(e.to_string()))?;
                return Err(error);
            }
        }
        let Some(task_client) = self.outbound_task_client(&planned_outbound).ok() else {
            let message = "HarborBeacon media proxy is not configured";
            self.store
                .finish_delivery_materialization(DeliveryMaterializationCompletion {
                    delivery_key,
                    item_key,
                    claim_token,
                    status: "failed",
                    materialized_outbound: None,
                    cache_path: None,
                    retryable: true,
                    last_error: Some(message),
                })
                .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
            return Err(GatewayError::infrastructure(message));
        };
        let materialized = task_client
            .materialize_attachments_in(
                planned_outbound.attachments.clone(),
                &self.attachment_cache_root,
                &delivery_idempotency_cache_segment(delivery_key),
            )
            .await;
        let mut cache_guard = AttachmentCacheGuard::new(
            self.attachment_cache_root.clone(),
            materialized.cache_files.clone(),
            materialized.cache_dir.clone(),
        );
        if materialized.failed_count > 0 || materialized.attachments.len() != 1 {
            let message = "media attachment materialization failed";
            self.store
                .finish_delivery_materialization(DeliveryMaterializationCompletion {
                    delivery_key,
                    item_key,
                    claim_token,
                    status: "failed",
                    materialized_outbound: None,
                    cache_path: None,
                    retryable: true,
                    last_error: Some(message),
                })
                .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
            return Err(GatewayError::infrastructure(message));
        }
        let mut materialized_outbound = planned_outbound;
        materialized_outbound.attachments = materialized.attachments;
        let cache_path = materialized_outbound
            .attachments
            .first()
            .and_then(|attachment| attachment.get("path"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| {
                GatewayError::infrastructure(
                    "materialized delivery item is missing its trusted cache path",
                )
            })?;
        let serialized_outbound = serde_json::to_value(&materialized_outbound)
            .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
        self.store
            .finish_delivery_materialization(DeliveryMaterializationCompletion {
                delivery_key,
                item_key,
                claim_token,
                status: "materialized",
                materialized_outbound: Some(serialized_outbound),
                cache_path: Some(&cache_path),
                retryable: true,
                last_error: None,
            })
            .map_err(|error| GatewayError::infrastructure(error.to_string()))?;
        cache_guard.disarm_path(&cache_path);
        Ok(materialized_outbound)
    }

    pub fn status(&self) -> Value {
        let mut adapters = serde_json::Map::new();
        for (name, adapter) in &self.adapters {
            adapters.insert(
                name.clone(),
                json!({
                    "name": name,
                    "enabled": true,
                    "profile": adapter.profile(),
                    "transport": adapter.status(),
                }),
            );
        }
        json!({
            "status": "ok",
            "runtime": "rust",
            "contract_version": "2.0",
            "gateway_turn_contract_version": "3.0",
            "gateway_turn_endpoint": "/api/gateway/turns",
            "beacon_proxy_prefix": "/api/beacon",
            "harbor_assistant_proxy_prefix": "/api/harbor-assistant",
            "turn_endpoint": "/api/web/turns",
            "adapters": adapters,
            "delivery_health": self.store.delivery_health().unwrap_or_else(|_| json!({"record_count": 0})),
        })
    }

    fn resolve_notification_route(
        &self,
        destination: &serde_json::Map<String, Value>,
        route_key: &str,
        trace_id: &str,
    ) -> Result<Value, GatewayError> {
        if !route_key.is_empty() {
            let route = self
                .store
                .resolve_route(route_key)
                .map_err(|err| {
                    GatewayError::infrastructure(err.to_string()).with_trace(trace_id.to_string())
                })?
                .ok_or_else(|| {
                    GatewayError::new(
                        StatusCode::NOT_FOUND,
                        "ROUTE_NOT_FOUND",
                        format!("route_key not found: {route_key}"),
                    )
                    .with_trace(trace_id.to_string())
                })?;
            if route
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("active")
                == "expired"
            {
                return Err(GatewayError::new(
                    StatusCode::GONE,
                    "ROUTE_EXPIRED",
                    format!("route_key expired: {route_key}"),
                )
                .with_trace(trace_id.to_string()));
            }
            let mut object = route.as_object().cloned().unwrap_or_default();
            object.insert("route_mode".into(), json!("source_bound"));
            object.insert("route_source".into(), json!("route_key"));
            if !object.contains_key("adapter_name") {
                let platform = object.get("platform").cloned().unwrap_or(Value::Null);
                object.insert("adapter_name".into(), platform);
            }
            return Ok(Value::Object(object));
        }
        let recipient = destination
            .get("recipient")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let platform = destination
            .get("platform")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                recipient
                    .get("platform")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or("")
            .trim()
            .to_string();
        let chat_id = destination
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                recipient
                    .get("recipient_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| {
                recipient
                    .get("email")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| {
                recipient
                    .get("mail_address")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or("")
            .trim()
            .to_string();
        if platform.is_empty() || chat_id.is_empty() {
            return Err(GatewayError::validation(
                "destination.route_key is preferred; otherwise destination.platform with destination.id or destination.recipient is required",
            )
            .with_trace(trace_id.to_string()));
        }
        Ok(json!({
            "platform": platform,
            "chat_id": chat_id,
            "adapter_name": platform,
            "status": "active",
            "route_mode": "proactive",
            "route_source": if destination.get("id").and_then(Value::as_str).is_some_and(|value| !value.trim().is_empty()) { "platform_id" } else { "recipient" },
        }))
    }
}

fn delivery_item_key(delivery_key: &str, item_identity: &str) -> String {
    format!(
        "delivery:v1:{}:{delivery_key}:{item_identity}",
        delivery_key.len()
    )
}

fn attachment_item_identity(artifact_id: &str) -> String {
    format!("item:v1:artifact:{}:{artifact_id}", artifact_id.len())
}

fn delivery_item_requires_materialization(adapter_name: &str, outbound: &OutboundMessage) -> bool {
    matches!(adapter_name, "weixin" | "whatsapp")
        && outbound.attachments.len() == 1
        && outbound.attachments[0]
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(|path| path.trim().is_empty())
        && outbound.attachments[0]
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| !url.trim().is_empty())
}

fn split_outbound_items(
    outbound: OutboundMessage,
) -> Result<Vec<(String, String, String, OutboundMessage)>, GatewayError> {
    let mut items = Vec::new();
    let mut artifact_ids = HashSet::new();
    if !outbound.text.trim().is_empty() {
        let mut text_outbound = outbound.clone();
        text_outbound.attachments.clear();
        items.push((
            "item:v1:text".to_string(),
            "__text".to_string(),
            "text".to_string(),
            text_outbound,
        ));
    }
    for attachment in &outbound.attachments {
        let Some(artifact_id) = delivery_artifact_id(attachment) else {
            continue;
        };
        if !artifact_ids.insert(artifact_id.clone()) {
            return Err(GatewayError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "DUPLICATE_DELIVERY_ARTIFACT",
                format!("duplicate artifact_id in delivery plan: {artifact_id}"),
            ));
        }
        let kind = attachment
            .get("kind")
            .or_else(|| attachment.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("file")
            .trim()
            .to_string();
        let mut attachment_outbound = outbound.clone();
        attachment_outbound.text.clear();
        attachment_outbound.attachments = vec![attachment.clone()];
        items.push((
            attachment_item_identity(&artifact_id),
            artifact_id,
            kind,
            attachment_outbound,
        ));
    }
    if items.is_empty() {
        items.push((
            "item:v1:text".to_string(),
            "__text".to_string(),
            "text".to_string(),
            outbound,
        ));
    }
    Ok(items)
}

fn native_video_file_fallback(outbound: &OutboundMessage) -> Option<OutboundMessage> {
    let attachment = outbound.attachments.first()?;
    if outbound.attachments.len() != 1
        || attachment
            .pointer("/metadata/native_attachment_fallback")
            .and_then(Value::as_str)
            != Some("file")
    {
        return None;
    }
    let is_video = attachment
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "video")
        || attachment
            .get("mime_type")
            .and_then(Value::as_str)
            .is_some_and(|mime_type| mime_type.starts_with("video/"));
    if !is_video {
        return None;
    }
    let mut fallback = outbound.clone();
    if let Some(object) = fallback
        .attachments
        .first_mut()
        .and_then(Value::as_object_mut)
    {
        object.insert("kind".into(), json!("file"));
        object.insert("mime_type".into(), json!("application/octet-stream"));
    }
    fallback
        .metadata
        .insert("native_attachment_fallback_used".into(), json!(true));
    Some(fallback)
}

fn should_fallback_to_file(error: &GatewayError) -> bool {
    matches!(
        error.code.as_str(),
        "UNSUPPORTED_NATIVE_VIDEO" | "NATIVE_MEDIA_PRE_SEND_FAILED"
    )
}

fn hinted_notification_attachments(content: &Value) -> Vec<Value> {
    let artifacts = content
        .get("attachments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut selected = hinted_native_videos(&artifacts, content);
    if let Some(limit) = native_image_limit(content) {
        let images = artifacts.into_iter().filter(|artifact| {
            artifact
                .get("mime_type")
                .and_then(Value::as_str)
                .is_some_and(|mime_type| mime_type.starts_with("image/"))
                && artifact_media_location(artifact).is_some()
        });
        selected.extend(images.take(limit));
    }
    selected
}

fn delivery_idempotency_cache_segment(delivery_key: &str) -> String {
    stable_id("delivery-", delivery_key, 24)
}

const ATTACHMENT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

fn remove_reconciled_attachment_cache(
    cache_root: &AttachmentCacheRoot,
    paths: Vec<PathBuf>,
) -> std::io::Result<()> {
    let mut directories = HashSet::new();
    for path in paths {
        if let Some(parent) = path.parent() {
            directories.insert(parent.to_path_buf());
        }
        if let Err(error) = cache_root.remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error);
            }
        }
    }
    for directory in directories {
        if let Err(error) = cache_root.remove_dir(&directory) {
            if !matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn sweep_expired_attachment_cache(
    cache_root: &AttachmentCacheRoot,
    retryable_cache_paths: &[PathBuf],
    now: SystemTime,
) -> std::io::Result<()> {
    let retryable = retryable_cache_paths.iter().collect::<HashSet<_>>();
    for entry in cache_root.entries()? {
        let entry = entry?;
        let path = cache_root.path().join(entry.file_name());
        let batch_dir = match cache_root.open_dir(&path) {
            Ok(directory) => directory,
            Err(error) => {
                if entry.file_type()?.is_dir() {
                    return Err(error);
                }
                continue;
            }
        };
        let metadata = batch_dir.dir_metadata()?;
        let expired = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified.into_std()).ok())
            .is_some_and(|age| age > ATTACHMENT_CACHE_TTL);
        if !expired {
            continue;
        }
        let mut children = Vec::new();
        let mut can_remove = true;
        let mut has_retryable_child = false;
        for child in batch_dir.entries()? {
            let child = child?;
            let child_name = child.file_name();
            let child_path = path.join(&child_name);
            let child_type = child.file_type()?;
            has_retryable_child |= retryable.contains(&child_path);
            if child_type.is_file() || child_type.is_symlink() {
                children.push(child_name);
            } else {
                can_remove = false;
                break;
            }
        }
        if has_retryable_child {
            continue;
        }
        if can_remove {
            for child in children {
                batch_dir.remove_file(child)?;
            }
            drop(batch_dir);
            cache_root.remove_dir(&path)?;
        }
    }
    Ok(())
}

fn gateway_turn_to_inbound(payload: &Value) -> Result<InboundMessage, GatewayError> {
    let channel = first_string(
        payload,
        &[
            "/conversation/channel",
            "/channel",
            "/surface",
            "/transport/channel",
        ],
    )
    .unwrap_or_else(|| "webui".to_string());
    let thread_id = first_string(
        payload,
        &[
            "/conversation/thread_id",
            "/thread_id",
            "/session_id",
            "/transport/session_id",
            "/actor/user_id",
        ],
    )
    .unwrap_or_else(|| stable_id("thread_", &crate::harborbeacon::canonical_json(payload), 16));
    let user_id = first_string(payload, &["/actor/user_id", "/user_id", "/open_id"])
        .unwrap_or_else(|| "anonymous".to_string());
    let text = first_string(payload, &["/input/text", "/text", "/message/text"])
        .ok_or_else(|| GatewayError::validation("input.text is required"))?;
    let mut metadata = payload
        .pointer("/transport/metadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    metadata.insert("source".into(), json!("gateway_turn"));
    if let Some(surface) = payload
        .pointer("/conversation/surface")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        metadata.insert("surface".into(), json!(surface.trim()));
    }
    Ok(InboundMessage {
        platform: channel,
        chat_id: thread_id,
        user_id,
        text,
        message_id: first_string(
            payload,
            &["/transport/message_id", "/message_id", "/turn/turn_id"],
        )
        .unwrap_or_default(),
        chat_type: first_string(payload, &["/conversation/chat_type", "/chat_type"])
            .unwrap_or_else(|| "p2p".to_string()),
        route_key: first_string(payload, &["/transport/route_key", "/route_key"])
            .unwrap_or_default(),
        session_id: first_string(payload, &["/transport/session_id", "/session_id"])
            .unwrap_or_default(),
        mentions: vec![],
        attachments: payload
            .pointer("/input/parts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        metadata,
        timestamp: first_string(payload, &["/turn/occurred_at"])
            .unwrap_or_else(crate::models::utc_now_iso),
        raw_payload: payload.clone(),
    })
}

fn reject_unbound_dlna_turn(payload: &Value) -> Result<(), GatewayError> {
    let structured_dlna = [
        "/intent/domain",
        "/domain",
        "/transport/metadata/intent/domain",
        "/transport/metadata/domain",
    ]
    .into_iter()
    .filter_map(|pointer| payload.pointer(pointer).and_then(Value::as_str))
    .any(|domain| domain.trim().eq_ignore_ascii_case("dlna"));
    let command_dlna = first_string(payload, &["/input/text", "/text", "/message/text"])
        .is_some_and(|text| {
            let text = text.trim_start().to_ascii_lowercase();
            text.strip_prefix("/dlna").is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix
                        .chars()
                        .next()
                        .is_some_and(|ch| ch.is_whitespace() || ch == '/')
            })
        });
    if structured_dlna || command_dlna {
        return Err(GatewayError::new(
            StatusCode::FORBIDDEN,
            "DLNA_MEMBER_BINDING_REQUIRED",
            "DLNA control requires a verified Home and member binding",
        ));
    }
    Ok(())
}

fn first_string(payload: &Value, pointers: &[&str]) -> Option<String> {
    pointers.iter().find_map(|pointer| {
        payload
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn fallback_reply(history: &[ConversationTurn], inbound: &InboundMessage) -> String {
    if history.is_empty() {
        format!("收到：{}", inbound.text)
    } else {
        format!("继续收到：{}", inbound.text)
    }
}

fn native_source_bound_attachments(adapter_name: &str, response_payload: &Value) -> Vec<Value> {
    if adapter_name != "feishu" && adapter_name != "weixin" && adapter_name != "whatsapp" {
        return vec![];
    }
    let artifacts = artifact_candidates(response_payload);
    if adapter_name == "weixin" {
        return weixin_native_attachments(artifacts, response_payload);
    }
    let images: Vec<Value> = artifacts
        .into_iter()
        .filter(|artifact| {
            let kind = artifact
                .get("kind")
                .or_else(|| artifact.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let mime_type = artifact
                .get("mime_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let location = artifact_media_location(artifact).unwrap_or("");
            kind == "image" && mime_type.starts_with("image/") && !location.trim().is_empty()
        })
        .collect();
    if images.is_empty() {
        return vec![];
    }
    if let Some(limit) = native_image_limit(response_payload) {
        return images.into_iter().take(limit).collect();
    }
    if images.len() == 1 {
        images
    } else {
        vec![]
    }
}

fn weixin_native_attachments(artifacts: Vec<Value>, response_payload: &Value) -> Vec<Value> {
    let media: Vec<Value> = artifacts
        .iter()
        .filter(|artifact| {
            let kind = artifact
                .get("kind")
                .or_else(|| artifact.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let mime_type = artifact
                .get("mime_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let location = artifact_media_location(artifact).unwrap_or("");
            !location.trim().is_empty()
                && (kind == "image"
                    || kind == "video"
                    || kind == "file"
                    || mime_type.starts_with("image/")
                    || mime_type.starts_with("video/"))
        })
        .cloned()
        .collect();
    if media.is_empty() {
        return vec![];
    }
    let images = media
        .iter()
        .filter(|artifact| {
            let kind = artifact
                .get("kind")
                .or_else(|| artifact.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let mime_type = artifact
                .get("mime_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            kind == "image" || mime_type.starts_with("image/")
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut selected = if let Some(limit) = native_image_limit(response_payload) {
        images.into_iter().take(limit).collect()
    } else if images.len() == 1 && media.len() == 1 {
        images
    } else {
        vec![]
    };
    selected.extend(hinted_native_videos(&artifacts, response_payload));
    selected
}

fn hinted_native_videos(artifacts: &[Value], response_payload: &Value) -> Vec<Value> {
    let hints = response_payload
        .get("delivery_hints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut selected = Vec::new();
    for hint in hints {
        if hint.get("kind").and_then(Value::as_str) != Some("native_video")
            || hint.get("fallback").and_then(Value::as_str) != Some("file")
        {
            continue;
        }
        let Some(artifact_id) = hint
            .get("artifact_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(mut artifact) = artifacts
            .iter()
            .find(|artifact| hint_artifact_id(artifact) == Some(artifact_id))
            .cloned()
        else {
            continue;
        };
        let is_video = artifact
            .get("mime_type")
            .and_then(Value::as_str)
            .is_some_and(|mime_type| mime_type.starts_with("video/"));
        if !is_video || artifact_media_location(&artifact).is_none() {
            continue;
        }
        if let Some(object) = artifact.as_object_mut() {
            let metadata = object
                .entry("metadata")
                .or_insert_with(|| json!({}))
                .as_object_mut();
            if let Some(metadata) = metadata {
                metadata.insert("native_attachment_fallback".into(), json!("file"));
            }
        }
        if !selected
            .iter()
            .any(|existing| hint_artifact_id(existing) == Some(artifact_id))
        {
            selected.push(artifact);
        }
    }
    selected
}

fn hint_artifact_id(artifact: &Value) -> Option<&str> {
    artifact
        .get("artifact_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn delivery_artifact_id(artifact: &Value) -> Option<String> {
    artifact
        .get("artifact_id")
        .or_else(|| artifact.get("id"))
        .or_else(|| artifact.pointer("/metadata/harborlink_artifact_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn artifact_media_location(artifact: &Value) -> Option<&str> {
    artifact
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            artifact
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

fn artifact_candidates(response_payload: &Value) -> Vec<Value> {
    response_payload
        .get("artifacts")
        .and_then(Value::as_array)
        .or_else(|| {
            response_payload
                .pointer("/result/artifacts")
                .and_then(Value::as_array)
        })
        .or_else(|| {
            response_payload
                .pointer("/result/attachments")
                .and_then(Value::as_array)
        })
        .or_else(|| {
            response_payload
                .pointer("/result/evidence")
                .and_then(Value::as_array)
        })
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|value| value.is_object())
        .collect()
}

fn native_image_limit(response_payload: &Value) -> Option<usize> {
    let hint = response_payload
        .get("delivery_hints")
        .and_then(Value::as_array)?
        .iter()
        .find(|hint| {
            matches!(
                hint.get("kind").and_then(Value::as_str),
                Some("native_image" | "native_images")
            )
        })?;
    let raw = hint
        .get("max_items")
        .or_else(|| hint.pointer("/metadata/max_items"))
        .or_else(|| hint.pointer("/metadata/limit"))
        .and_then(Value::as_u64)
        .unwrap_or(3);
    Some(raw.clamp(1, 3) as usize)
}

fn render_retrieval_reply(
    base_text: &str,
    response_payload: &Value,
    suppress_artifacts: bool,
    public_origin: &str,
) -> String {
    let citations = response_payload
        .pointer("/result/citations")
        .and_then(Value::as_array)
        .or_else(|| {
            response_payload
                .pointer("/result/references")
                .and_then(Value::as_array)
        })
        .or_else(|| {
            response_payload
                .pointer("/result/sources")
                .and_then(Value::as_array)
        })
        .or_else(|| {
            response_payload
                .pointer("/result/top_hits")
                .and_then(Value::as_array)
        })
        .or_else(|| {
            response_payload
                .pointer("/result/hits")
                .and_then(Value::as_array)
        })
        .cloned()
        .unwrap_or_default();
    let artifacts = artifact_candidates(response_payload);
    if citations.is_empty() && (artifacts.is_empty() || suppress_artifacts) {
        return base_text.trim().to_string();
    }
    let mut sections = Vec::new();
    sections.push(format!(
        "检索结果（{} 条引用，{} 个附件）",
        citations.len(),
        artifacts.len()
    ));
    if !base_text.trim().is_empty() {
        sections.push(base_text.trim().to_string());
    }
    if !citations.is_empty() {
        sections.push(format!(
            "引用\n{}",
            render_entries(&citations, "citation", public_origin)
        ));
    }
    if !artifacts.is_empty() && !suppress_artifacts {
        sections.push(format!(
            "附件\n{}",
            render_entries(&artifacts, "artifact", public_origin)
        ));
    }
    sections.join("\n\n")
}

fn render_entries(records: &[Value], kind: &str, public_origin: &str) -> String {
    records
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, record)| {
            let entry = if kind == "citation" {
                first_text(
                    record,
                    &[
                        "title", "name", "headline", "summary", "snippet", "text", "id",
                    ],
                )
            } else {
                first_text(
                    record,
                    &["title", "name", "filename", "file_name", "label", "id"],
                )
            };
            let label = entry.unwrap_or_else(|| "未命名".to_string());
            let url = record
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| public_artifact_url(value, public_origin));
            match url {
                Some(url) => format!("{}. {}\n{}", index + 1, label, url),
                None => format!("{}. {}", index + 1, label),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_text(record: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = record.get(*key).and_then(Value::as_str) {
            if !text.trim().is_empty() {
                return Some(text.trim().to_string());
            }
        }
    }
    None
}

fn validate_delivery_mode(
    mode: &str,
    reply_to_message_id: &str,
    update_message_id: &str,
    trace_id: &str,
) -> Result<(), GatewayError> {
    if !matches!(mode, "send" | "reply" | "update") {
        return Err(
            GatewayError::validation("delivery.mode must be send, reply, or update")
                .with_trace(trace_id.to_string()),
        );
    }
    if mode == "send" && (!reply_to_message_id.is_empty() || !update_message_id.is_empty()) {
        return Err(GatewayError::validation(
            "delivery.mode=send requires empty reply_to_message_id and update_message_id",
        )
        .with_trace(trace_id.to_string()));
    }
    if mode == "reply" && (reply_to_message_id.is_empty() || !update_message_id.is_empty()) {
        return Err(GatewayError::validation(
            "delivery.mode=reply requires reply_to_message_id and forbids update_message_id",
        )
        .with_trace(trace_id.to_string()));
    }
    if mode == "update" && (update_message_id.is_empty() || !reply_to_message_id.is_empty()) {
        return Err(GatewayError::validation(
            "delivery.mode=update requires update_message_id and forbids reply_to_message_id",
        )
        .with_trace(trace_id.to_string()));
    }
    Ok(())
}

fn notification_id(payload: &Value) -> String {
    payload
        .pointer("/notification/notification_id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("notification_id").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn notification_trace_id(payload: &Value) -> String {
    payload
        .pointer("/notification/trace_id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("trace_id").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn delivery_content(payload: &Value) -> Value {
    if let Some(content) = payload.get("content").filter(|value| value.is_object()) {
        let mut content = content.clone();
        if let Some(object) = content.as_object_mut() {
            object.insert(
                "attachments".into(),
                payload.get("artifacts").cloned().unwrap_or_else(|| {
                    object
                        .get("attachments")
                        .cloned()
                        .unwrap_or_else(|| json!([]))
                }),
            );
            object.insert(
                "delivery_hints".into(),
                payload.get("delivery_hints").cloned().unwrap_or_else(|| {
                    object
                        .get("delivery_hints")
                        .cloned()
                        .unwrap_or_else(|| json!([]))
                }),
            );
        }
        return content;
    }
    let reply = payload.get("reply").and_then(Value::as_object);
    json!({
        "title": reply.and_then(|reply| reply.get("title")).and_then(Value::as_str).unwrap_or(""),
        "body": reply.and_then(|reply| reply.get("text")).and_then(Value::as_str).unwrap_or(""),
        "attachments": payload.get("artifacts").cloned().unwrap_or_else(|| json!([])),
        "delivery_hints": payload.get("delivery_hints").cloned().unwrap_or_else(|| json!([])),
        "payload_format": reply.and_then(|reply| reply.get("payload_format")).and_then(Value::as_str).unwrap_or("plain_text"),
        "structured_payload": reply.and_then(|reply| reply.get("structured_payload")).cloned().unwrap_or_else(|| json!({})),
    })
}

fn notification_text(content: &Value) -> String {
    let title = content
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let body = content
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !title.is_empty() && !body.is_empty() {
        format!("{title}\n\n{body}")
    } else if !body.is_empty() {
        body.to_string()
    } else {
        title.to_string()
    }
}

struct NotificationDeliveryMetadata<'a> {
    notification_id: &'a str,
    trace_id: &'a str,
    mode: &'a str,
    route_key: &'a str,
    reply_to_message_id: &'a str,
    update_message_id: &'a str,
    route: &'a Value,
    content: &'a Value,
    destination: &'a serde_json::Map<String, Value>,
    idempotency_key: &'a str,
}

fn peer_reminder_notification(payload: &Value) -> bool {
    ["/source/event_type", "/notification/event_type"]
        .iter()
        .any(|path| {
            matches!(
                payload.pointer(path).and_then(Value::as_str),
                Some("rule.reminder" | "plan.reminder")
            )
        })
        || payload
            .pointer("/conversation/handle")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with("im_peer_notice_"))
}

fn peer_reminder_outbound(outbound: &OutboundMessage) -> bool {
    outbound.metadata.get("peer_reminder") == Some(&json!(true))
        || matches!(outbound.metadata.get("notification_event_type").and_then(Value::as_str), Some("rule.reminder" | "plan.reminder"))
        || outbound.metadata.get("conversation_handle").and_then(Value::as_str).is_some_and(|value| value.starts_with("im_peer_notice_"))
        // Pre-fix queued Native mail reminders did not preserve their permit.
        || outbound.platform == "feishu_mail" && outbound.metadata.get("notification_id")
            .and_then(Value::as_str).is_some_and(|value| value.starts_with("reminder-im-"))
}

fn outbound_delivery_metadata(
    input: NotificationDeliveryMetadata<'_>,
) -> serde_json::Map<String, Value> {
    let NotificationDeliveryMetadata {
        notification_id,
        trace_id,
        mode,
        route_key,
        reply_to_message_id,
        update_message_id,
        route,
        content,
        destination,
        idempotency_key,
    } = input;
    let mut metadata = serde_json::Map::new();
    metadata.insert("source".into(), json!("notification_delivery"));
    metadata.insert("notification_id".into(), json!(notification_id));
    metadata.insert("trace_id".into(), json!(trace_id));
    metadata.insert("delivery_mode".into(), json!(mode));
    metadata.insert("route_key".into(), json!(route_key));
    metadata.insert(
        "route_mode".into(),
        route
            .get("route_mode")
            .cloned()
            .unwrap_or_else(|| json!("unknown")),
    );
    metadata.insert(
        "route_source".into(),
        route
            .get("route_source")
            .cloned()
            .unwrap_or_else(|| json!("unknown")),
    );
    metadata.insert("reply_to_message_id".into(), json!(reply_to_message_id));
    metadata.insert("update_message_id".into(), json!(update_message_id));
    metadata.insert(
        "payload_format".into(),
        content
            .get("payload_format")
            .cloned()
            .unwrap_or_else(|| json!("plain_text")),
    );
    metadata.insert(
        "structured_payload".into(),
        content
            .get("structured_payload")
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    metadata.insert("idempotency_key".into(), json!(idempotency_key));
    metadata.insert("mail_dedupe_key".into(), json!(idempotency_key));
    if let Some(recipient) = destination.get("recipient").cloned() {
        metadata.insert("recipient".into(), recipient);
    }
    if let Some(recipients) = content
        .get("recipients")
        .or_else(|| content.pointer("/structured_payload/recipients"))
        .cloned()
    {
        metadata.insert("mail_recipients".into(), recipients);
    }
    let subject = content
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !subject.is_empty() {
        metadata.insert("mail_subject".into(), json!(subject));
    }
    let body_plain_text = content
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !body_plain_text.is_empty() {
        metadata.insert("mail_body_plain_text".into(), json!(body_plain_text));
    }
    if let Some(html_body) = content
        .pointer("/structured_payload/html_body")
        .or_else(|| content.pointer("/structured_payload/body_html"))
        .or_else(|| content.get("html_body"))
        .or_else(|| content.get("body_html"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        metadata.insert("mail_body_html".into(), json!(html_body));
    }
    metadata
}

fn fingerprint(payload: &Value) -> String {
    let encoded = crate::harborbeacon::canonical_json(payload);
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn map_delivery_failure(message: &str) -> (&'static str, bool) {
    let lower = message.to_lowercase();
    if lower.contains("context_token") {
        ("INVALID_RECIPIENT", false)
    } else if lower.contains("not configured")
        || lower.contains("authorization")
        || lower.contains("auth")
        || lower.contains("permission")
        || lower.contains("scope")
        || lower.contains("forbidden")
        || lower.contains("unauthorized")
    {
        ("PROVIDER_AUTH_FAILED", false)
    } else if lower.contains("unsupported") {
        ("UNSUPPORTED_CONTENT", false)
    } else {
        ("PLATFORM_UNAVAILABLE", true)
    }
}

fn classify_delivery_attempt(route: &Value, response_payload: &Value) -> Value {
    let ok = response_payload
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let retryable = response_payload
        .get("retryable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let failure_class = if ok {
        ""
    } else {
        response_payload
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("INTERNAL_ERROR")
    };
    json!({
        "route_mode": route.get("route_mode").and_then(Value::as_str).unwrap_or("unknown"),
        "route_source": route.get("route_source").and_then(Value::as_str).unwrap_or("unknown"),
        "outcome": if ok { "sent" } else { "failed" },
        "failure_class": failure_class,
        "queue_state": if ok { "complete" } else if retryable { "retry_queue" } else { "terminal_failure" },
        "retryable": retryable,
    })
}

trait IfEmptyThen {
    fn if_empty_then(self, producer: impl FnOnce() -> String) -> String;
}

impl IfEmptyThen for String {
    fn if_empty_then(self, producer: impl FnOnce() -> String) -> String {
        if self.trim().is_empty() {
            producer()
        } else {
            self
        }
    }
}

fn public_artifact_url(url: &str, public_origin: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }
    if url.starts_with('/') && !public_origin.trim().is_empty() {
        return format!("{}{}", public_origin.trim_end_matches('/'), url);
    }
    url.to_string()
}

async fn cleanup_attachment_cache(
    cache_root: &AttachmentCacheRoot,
    cache_files: Vec<PathBuf>,
    cache_dir: Option<PathBuf>,
) {
    for path in cache_files {
        if let Err(error) = cache_root.remove_file(&path) {
            tracing::warn!(path = %path.display(), error = %error, "Could not remove Gate attachment cache file");
        }
    }
    if let Some(path) = cache_dir {
        if let Err(error) = cache_root.remove_dir(&path) {
            tracing::warn!(path = %path.display(), error = %error, "Could not remove Gate attachment cache directory");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn camera_authorization_fixture(
        config: &mut AppConfig,
    ) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let code = Arc::new(AtomicUsize::new(200));
        let current = code.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.harborbeacon_base_url = format!("http://{}", listener.local_addr().unwrap());
        config.harborbeacon_token = "fixture-service-token".into();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().fallback(axum::routing::get(
                move |headers: axum::http::HeaderMap| {
                    let current = current.clone();
                    async move {
                        assert_eq!(headers.get("range").unwrap(), "bytes=0-0");
                        assert_eq!(headers.get("X-Harbor-Media-Context").unwrap(), "chat");
                        StatusCode::from_u16(current.load(Ordering::SeqCst) as u16).unwrap()
                    }
                },
            ));
            axum::serve(listener, app).await.unwrap();
        });
        (code, server)
    }

    struct RetryOnceAdapter {
        attempts: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PlatformAdapter for RetryOnceAdapter {
        fn name(&self) -> &str {
            "retry_once"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, _outbound: OutboundMessage) -> Result<Value, GatewayError> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == 1 {
                return Err(GatewayError::infrastructure("temporary provider timeout"));
            }
            Ok(json!({
                "message_id": format!("provider-{attempt}"),
                "provider_message_id": format!("provider-{attempt}"),
            }))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "retry_once"})
        }
    }

    struct FailSecondItemAdapter {
        calls: Arc<StdMutex<Vec<String>>>,
        failed_once: Arc<AtomicUsize>,
    }

    struct VideoFallbackAdapter {
        kinds: Arc<StdMutex<Vec<String>>>,
    }

    struct RetryableVideoAdapter {
        kinds: Arc<StdMutex<Vec<String>>>,
    }

    struct CaptureAttachmentAdapter {
        sent_attachments: Arc<StdMutex<Vec<Vec<Value>>>>,
    }

    struct TerminalFailureAdapter {
        attempts: Arc<AtomicUsize>,
    }

    struct StagedFallbackAdapter {
        uploads: Arc<StdMutex<Vec<String>>>,
        sends: Arc<StdMutex<Vec<String>>>,
        fallback_sends: Arc<AtomicUsize>,
    }

    impl StagedFallbackAdapter {
        fn send_stage(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
            let kind = outbound
                .attachments
                .first()
                .and_then(|artifact| artifact.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or("text")
                .to_string();
            self.sends.lock().unwrap().push(kind.clone());
            if kind == "video" {
                return Err(GatewayError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "UNSUPPORTED_NATIVE_VIDEO",
                    "provider explicitly rejected native video",
                ));
            }
            if self.fallback_sends.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(GatewayError::infrastructure("fallback send timeout"));
            }
            Ok(json!({
                "provider_media_id": "file-media",
                "provider_client_id": "file-client",
                "provider_message_id": "file-message",
            }))
        }
    }

    #[async_trait]
    impl PlatformAdapter for StagedFallbackAdapter {
        fn name(&self) -> &str {
            "staged_fallback"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
            self.send_stage(outbound)
        }

        async fn prepare_outbound(
            &self,
            outbound: &OutboundMessage,
        ) -> Result<Option<PreparedOutbound>, GatewayError> {
            let kind = outbound
                .attachments
                .first()
                .and_then(|artifact| artifact.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or("text")
                .to_string();
            self.uploads.lock().unwrap().push(kind.clone());
            Ok(Some(PreparedOutbound {
                provider_media_id: format!("{kind}-media"),
                provider_client_id: Some(format!("{kind}-client")),
                state: json!({
                    "kind": kind,
                }),
            }))
        }

        async fn send_prepared_outbound(
            &self,
            outbound: OutboundMessage,
            _prepared: Option<&PreparedOutbound>,
        ) -> Result<Value, GatewayError> {
            self.send_stage(outbound)
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "staged_fallback"})
        }
    }

    struct UploadThenFailAdapter {
        uploads: Arc<AtomicUsize>,
        sends: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PlatformAdapter for UploadThenFailAdapter {
        fn name(&self) -> &str {
            "upload_then_fail"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, _outbound: OutboundMessage) -> Result<Value, GatewayError> {
            unreachable!("staged test adapter must use send_prepared_outbound")
        }

        async fn prepare_outbound(
            &self,
            _outbound: &OutboundMessage,
        ) -> Result<Option<PreparedOutbound>, GatewayError> {
            let upload = self.uploads.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(Some(PreparedOutbound {
                provider_media_id: format!("provider-media-{upload}"),
                provider_client_id: Some(format!("provider-client-{upload}")),
                state: json!({"upload": upload}),
            }))
        }

        async fn send_prepared_outbound(
            &self,
            _outbound: OutboundMessage,
            prepared: Option<&PreparedOutbound>,
        ) -> Result<Value, GatewayError> {
            let media_id = prepared
                .expect("staged send requires prepared media")
                .provider_media_id
                .clone();
            let send = self.sends.fetch_add(1, Ordering::SeqCst) + 1;
            if send == 2 {
                return Err(GatewayError::infrastructure("provider send timeout"));
            }
            Ok(json!({
                "provider_media_id": media_id,
                "provider_message_id": format!("provider-message-{send}"),
            }))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "upload_then_fail"})
        }
    }

    #[async_trait]
    impl PlatformAdapter for VideoFallbackAdapter {
        fn name(&self) -> &str {
            "video_fallback"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
            let kind = outbound
                .attachments
                .first()
                .and_then(|artifact| artifact.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or("text")
                .to_string();
            self.kinds.lock().unwrap().push(kind.clone());
            if kind == "video" {
                return Err(GatewayError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "UNSUPPORTED_NATIVE_VIDEO",
                    "provider explicitly does not support native video",
                ));
            }
            Ok(json!({"provider_message_id": "provider-file-1"}))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "video_fallback"})
        }
    }

    #[async_trait]
    impl PlatformAdapter for RetryableVideoAdapter {
        fn name(&self) -> &str {
            "retryable_video"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
            let kind = outbound
                .attachments
                .first()
                .and_then(|artifact| artifact.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or("text")
                .to_string();
            self.kinds.lock().unwrap().push(kind.clone());
            if kind == "video" {
                return Err(GatewayError::infrastructure("provider send timeout"));
            }
            Ok(json!({"provider_message_id": "unexpected-file-message"}))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "retryable_video"})
        }
    }

    #[async_trait]
    impl PlatformAdapter for CaptureAttachmentAdapter {
        fn name(&self) -> &str {
            "weixin"
        }

        fn normalize_inbound(&self, payload: Value) -> Result<InboundMessage, GatewayError> {
            Ok(InboundMessage {
                platform: "weixin".into(),
                chat_id: "wx-chat-turn".into(),
                user_id: "wx-user".into(),
                text: "cat clips".into(),
                message_id: "wx-message".into(),
                chat_type: "p2p".into(),
                route_key: String::new(),
                session_id: String::new(),
                mentions: vec![],
                attachments: vec![],
                metadata: serde_json::Map::new(),
                timestamp: crate::models::utc_now_iso(),
                raw_payload: payload,
            })
        }

        async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
            self.sent_attachments
                .lock()
                .unwrap()
                .push(outbound.attachments);
            Ok(json!({"provider_message_id": "provider-text-only"}))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "weixin"})
        }
    }

    #[async_trait]
    impl PlatformAdapter for TerminalFailureAdapter {
        fn name(&self) -> &str {
            "terminal_failure"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, _outbound: OutboundMessage) -> Result<Value, GatewayError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(GatewayError::validation(
                "provider authorization failed deterministically",
            ))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "terminal_failure"})
        }
    }

    #[async_trait]
    impl PlatformAdapter for FailSecondItemAdapter {
        fn name(&self) -> &str {
            "item_delivery"
        }

        fn normalize_inbound(&self, _payload: Value) -> Result<InboundMessage, GatewayError> {
            unreachable!("test adapter is outbound-only")
        }

        async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
            let item = outbound
                .attachments
                .first()
                .and_then(delivery_artifact_id)
                .unwrap_or_else(|| "__text".to_string());
            let call_number = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(item.clone());
                calls.len()
            };
            if call_number == 2 && self.failed_once.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(GatewayError::infrastructure("temporary item timeout"));
            }
            Ok(json!({
                "message_id": format!("provider-{item}"),
                "provider_message_id": format!("provider-{item}"),
            }))
        }

        fn profile(&self) -> Value {
            json!({"adapter_name": "item_delivery"})
        }
    }

    #[tokio::test]
    async fn webhook_inbound_registers_route_and_replies() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let gateway = GatewayService::from_config(&config).unwrap();
        let response = gateway
            .handle_inbound(
                "webhook",
                json!({"chat_id": "chat1", "user_id": "user1", "text": "hello", "message_id": "msg1"}),
            )
            .await
            .unwrap();
        assert_eq!(response["delivery"], "webhook");
        let routes: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("_routes.json")).unwrap(),
        )
        .unwrap();
        assert!(routes
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .starts_with("gw_route_"));
    }

    #[tokio::test]
    async fn notification_delivery_is_idempotent() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .handle_inbound(
                "webhook",
                json!({"chat_id": "chat1", "user_id": "user1", "text": "hello", "message_id": "msg1"}),
            )
            .await
            .unwrap();
        let route_key = serde_json::from_str::<Value>(
            &std::fs::read_to_string(dir.path().join("_routes.json")).unwrap(),
        )
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .to_string();
        let payload = json!({
            "notification": {"notification_id": "notif_1", "trace_id": "trace_1"},
            "destination": {"route_key": route_key},
            "reply": {"kind": "tool_result", "text": "done"},
            "delivery": {"mode": "send", "idempotency_key": "idem_1", "reply_to_message_id": null, "update_message_id": null}
        });
        let first = gateway
            .handle_notification_delivery(payload.clone())
            .await
            .unwrap();
        let second = gateway.handle_notification_delivery(payload).await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn retryable_notification_failure_is_retried_instead_of_cached_forever() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "retry_once".to_string(),
            Arc::new(RetryOnceAdapter {
                attempts: attempts.clone(),
            }),
        );
        gateway
            .store
            .register_route(
                "gw_retry_once",
                json!({
                    "platform": "retry_once",
                    "adapter_name": "retry_once",
                    "chat_id": "chat-1",
                    "status": "active"
                }),
            )
            .unwrap();
        let payload = notification_payload_for_route("gw_retry_once", "idem_retry_once");

        let first = gateway
            .handle_notification_delivery(payload.clone())
            .await
            .unwrap();
        let delivery_records: Value = fs::read_to_string(dir.path().join("_deliveries.json"))
            .ok()
            .map(|raw| serde_json::from_str(&raw).unwrap())
            .unwrap_or_else(|| json!({}));
        assert!(delivery_records.get("idem_retry_once").is_none());
        let second = gateway.handle_notification_delivery(payload).await.unwrap();

        assert_eq!(first["ok"], false);
        assert_eq!(first["retryable"], true);
        assert_eq!(second["ok"], true);
        assert_eq!(second["provider_message_id"], "provider-2");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn notification_delivery_resumes_failed_item_after_restart_without_resending_success() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        let _authorization = camera_authorization_fixture(&mut config).await;
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let failed_once = Arc::new(AtomicUsize::new(0));
        let build_gateway = || {
            let mut gateway = GatewayService::from_config(&config).unwrap();
            gateway.adapters.insert(
                "item_delivery".to_string(),
                Arc::new(FailSecondItemAdapter {
                    calls: calls.clone(),
                    failed_once: failed_once.clone(),
                }),
            );
            gateway
        };
        let gateway = build_gateway();
        gateway
            .store
            .register_route(
                "gw_item_delivery",
                json!({
                    "platform": "item_delivery",
                    "adapter_name": "item_delivery",
                    "chat_id": "chat-1",
                    "status": "active"
                }),
            )
            .unwrap();
        let payload = json!({
            "notification": {"notification_id": "notif-items", "trace_id": "trace-items"},
            "destination": {"route_key": "gw_item_delivery"},
            "reply": {"kind": "tool_result", "text": "cat clips"},
            "artifacts": [
                {"artifact_id": "artifact-1", "kind": "video", "mime_type": "video/mp4", "url": "/api/cameras/recordings/artifacts/artifact-1"},
                {"artifact_id": "artifact-2", "kind": "video", "mime_type": "video/mp4", "url": "/api/cameras/recordings/artifacts/artifact-2"}
            ],
            "delivery_hints": [
                {"kind": "native_video", "artifact_id": "artifact-1", "fallback": "file"},
                {"kind": "native_video", "artifact_id": "artifact-2", "fallback": "file"}
            ],
            "delivery": {"mode": "send", "idempotency_key": "idem-items", "reply_to_message_id": null, "update_message_id": null}
        });

        let first = gateway
            .handle_notification_delivery(payload.clone())
            .await
            .unwrap();
        assert_eq!(first["ok"], false);
        drop(gateway);

        let gateway = build_gateway();
        let recovered = gateway
            .handle_notification_delivery(payload.clone())
            .await
            .unwrap();
        assert_eq!(recovered["ok"], true);
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            ["__text", "artifact-1", "artifact-1", "artifact-2"]
        );
        let item_ledger: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let text_item_key = delivery_item_key("idem-items", "item:v1:text");
        assert_eq!(
            item_ledger["idem-items"]["items"][&text_item_key]["provider_message_id"],
            "provider-__text"
        );
        drop(gateway);

        let gateway = build_gateway();
        let replay = gateway.handle_notification_delivery(payload).await.unwrap();
        assert_eq!(replay, recovered);
        assert_eq!(calls.lock().unwrap().len(), 4);
    }

    #[test]
    fn delivery_item_identity_distinguishes_caption_from_reserved_artifact_id() {
        let outbound = OutboundMessage {
            platform: "weixin".to_string(),
            chat_id: "chat-1".to_string(),
            text: "cat clip".to_string(),
            attachments: vec![json!({
                "artifact_id": "__text",
                "kind": "video",
                "mime_type": "video/mp4",
                "path": "gate-owned-video.mp4"
            })],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };

        let items = split_outbound_items(outbound).expect("valid delivery plan");

        assert_eq!(items.len(), 2);
        assert_ne!(items[0].0, items[1].0);
        assert_eq!(items[0].1, "__text");
        assert_eq!(items[1].1, "__text");
        assert_eq!(items[0].2, "text");
        assert_eq!(items[1].2, "video");
    }

    #[test]
    fn delivery_item_identity_is_unambiguous_for_separator_like_artifact_ids() {
        let outbound = OutboundMessage {
            platform: "weixin".to_string(),
            chat_id: "chat-1".to_string(),
            text: String::new(),
            attachments: vec![
                json!({"artifact_id": "a:b", "kind": "video"}),
                json!({"artifact_id": "a", "kind": "b:video"}),
            ],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };

        let items = split_outbound_items(outbound).expect("valid delivery plan");

        assert_eq!(items.len(), 2);
        assert_ne!(items[0].0, items[1].0);
    }

    #[test]
    fn duplicate_artifact_ids_are_rejected_before_delivery() {
        let outbound = OutboundMessage {
            platform: "weixin".to_string(),
            chat_id: "chat-1".to_string(),
            text: "cat clips".to_string(),
            attachments: vec![
                json!({"artifact_id": "duplicate", "kind": "video"}),
                json!({"artifact_id": "duplicate", "kind": "file"}),
            ],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };

        let error =
            split_outbound_items(outbound).expect_err("duplicate artifact IDs must fail closed");

        assert_eq!(error.code, "DUPLICATE_DELIVERY_ARTIFACT");
    }

    #[tokio::test]
    async fn native_video_failure_falls_back_to_file_and_persists_item_state() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        let _authorization = camera_authorization_fixture(&mut config).await;
        let kinds = Arc::new(StdMutex::new(Vec::new()));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "video_fallback".to_string(),
            Arc::new(VideoFallbackAdapter {
                kinds: kinds.clone(),
            }),
        );
        gateway
            .store
            .register_route(
                "gw_video_fallback",
                json!({
                    "platform": "video_fallback",
                    "adapter_name": "video_fallback",
                    "chat_id": "chat-1",
                    "status": "active"
                }),
            )
            .unwrap();
        let payload = json!({
            "notification": {"notification_id": "notif-fallback", "trace_id": "trace-fallback"},
            "destination": {"route_key": "gw_video_fallback"},
            "reply": {"kind": "tool_result", "text": ""},
            "artifacts": [{
                "artifact_id": "artifact-video",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/artifact-video"
            }],
            "delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "artifact-video",
                "fallback": "file"
            }],
            "delivery": {"mode": "send", "idempotency_key": "idem-fallback", "reply_to_message_id": null, "update_message_id": null}
        });

        let response = gateway.handle_notification_delivery(payload).await.unwrap();

        assert_eq!(response["ok"], true);
        assert_eq!(kinds.lock().unwrap().as_slice(), ["video", "file"]);
        let ledger: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let item_key =
            delivery_item_key("idem-fallback", &attachment_item_identity("artifact-video"));
        let item = &ledger["idem-fallback"]["items"][&item_key];
        assert_eq!(item["status"], "succeeded");
        assert_eq!(item["fallback_used"], true);
        assert_eq!(item["provider_message_id"], "provider-file-1");
    }

    #[tokio::test]
    async fn retryable_native_video_failure_does_not_fallback_to_file() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let kinds = Arc::new(StdMutex::new(Vec::new()));
        let gateway = GatewayService::from_config(&config).unwrap();
        let outbound = OutboundMessage {
            platform: "retryable_video".to_string(),
            chat_id: "chat-1".to_string(),
            text: String::new(),
            attachments: vec![json!({
                "artifact_id": "artifact-video",
                "kind": "video",
                "mime_type": "video/mp4",
                "path": "gate-owned-video.mp4",
                "metadata": {"native_attachment_fallback": "file"}
            })],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };

        let error = gateway
            .deliver_outbound_items(
                Arc::new(RetryableVideoAdapter {
                    kinds: kinds.clone(),
                }),
                outbound,
                "idem-retryable-video",
                "fingerprint",
            )
            .await
            .expect_err("ambiguous provider timeout must remain on native retry path");

        assert!(map_delivery_failure(&error.message).1);
        assert_eq!(kinds.lock().unwrap().as_slice(), ["video"]);
    }

    #[tokio::test]
    async fn fallback_stage_restart_reuses_both_uploads_and_only_retries_fallback_send() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let uploads = Arc::new(StdMutex::new(Vec::new()));
        let sends = Arc::new(StdMutex::new(Vec::new()));
        let fallback_sends = Arc::new(AtomicUsize::new(0));
        let adapter = || {
            Arc::new(StagedFallbackAdapter {
                uploads: uploads.clone(),
                sends: sends.clone(),
                fallback_sends: fallback_sends.clone(),
            }) as Arc<dyn PlatformAdapter>
        };
        let outbound = OutboundMessage {
            platform: "staged_fallback".to_string(),
            chat_id: "chat-1".to_string(),
            text: String::new(),
            attachments: vec![json!({
                "artifact_id": "artifact-video",
                "kind": "video",
                "mime_type": "video/mp4",
                "path": "gate-owned-video.mp4",
                "metadata": {"native_attachment_fallback": "file"}
            })],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };
        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .deliver_outbound_items(
                adapter(),
                outbound.clone(),
                "idem-staged-fallback",
                "fingerprint",
            )
            .await
            .expect_err("first fallback send must time out");
        drop(gateway);

        let failed_ledger: Value = serde_json::from_str(
            &fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let item_key = delivery_item_key(
            "idem-staged-fallback",
            &attachment_item_identity("artifact-video"),
        );
        let failed = &failed_ledger["idem-staged-fallback"]["items"][&item_key];
        assert_eq!(
            failed["stages"]["native"]["provider_media_id"],
            "video-media"
        );
        assert_eq!(
            failed["stages"]["native"]["provider_client_id"],
            "video-client"
        );
        assert_eq!(failed["stages"]["native"]["status"], "unsupported");
        assert_eq!(
            failed["stages"]["fallback"]["provider_media_id"],
            "file-media"
        );
        assert_eq!(
            failed["stages"]["fallback"]["provider_client_id"],
            "file-client"
        );
        assert_eq!(failed["stages"]["fallback"]["status"], "failed");

        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .deliver_outbound_items(adapter(), outbound, "idem-staged-fallback", "fingerprint")
            .await
            .unwrap();

        assert_eq!(uploads.lock().unwrap().as_slice(), ["video", "file"]);
        assert_eq!(sends.lock().unwrap().as_slice(), ["video", "file", "file"]);
        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let item = &ledger["idem-staged-fallback"]["items"][&item_key];
        assert_eq!(item["status"], "succeeded");
        assert_eq!(item["provider_client_id"], "file-client");
        assert_eq!(item["provider_message_id"], "file-message");
        assert_eq!(item["stages"]["fallback"]["status"], "succeeded");
        assert_eq!(
            item["stages"]["fallback"]["provider_message_id"],
            "file-message"
        );
    }

    #[tokio::test]
    async fn delivery_plan_drift_conflicts_without_another_provider_call() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        let _authorization = camera_authorization_fixture(&mut config).await;
        let attempts = Arc::new(AtomicUsize::new(1));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "retry_once".to_string(),
            Arc::new(RetryOnceAdapter {
                attempts: attempts.clone(),
            }),
        );
        gateway
            .store
            .register_route(
                "gw_plan_conflict",
                json!({"platform": "retry_once", "adapter_name": "retry_once", "chat_id": "chat-1", "status": "active"}),
            )
            .unwrap();
        let mut original = notification_payload_for_route("gw_plan_conflict", "idem-plan");
        original["artifacts"] = json!([{
            "artifact_id": "artifact-plan",
            "kind": "video",
            "mime_type": "video/mp4",
            "url": "/api/cameras/recordings/artifacts/artifact-plan"
        }]);
        original["delivery_hints"] = json!([{
            "kind": "native_video",
            "artifact_id": "artifact-plan",
            "fallback": "file"
        }]);
        let first = gateway
            .handle_notification_delivery(original.clone())
            .await
            .unwrap();
        let replay = gateway
            .handle_notification_delivery(original.clone())
            .await
            .unwrap();
        assert_eq!(first, replay);
        let provider_calls = attempts.load(Ordering::SeqCst);

        let mut changed_content = original.clone();
        changed_content["reply"]["text"] = json!("changed content");
        let mut changed_artifact = original.clone();
        changed_artifact["artifacts"][0]["url"] =
            json!("/api/cameras/recordings/artifacts/other-artifact");
        let mut changed_hint = original;
        changed_hint["delivery_hints"][0]["fallback"] = json!("changed-fallback");
        for changed in [changed_content, changed_artifact, changed_hint] {
            let error = gateway
                .handle_notification_delivery(changed)
                .await
                .expect_err("same delivery key with a changed plan must conflict");
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");
            assert_eq!(attempts.load(Ordering::SeqCst), provider_calls);
        }
    }

    #[test]
    fn truncated_delivery_ledger_fails_closed_without_rewriting_bytes() {
        let dir = tempdir().unwrap();
        let corrupt = dir.path().join("_delivery_items.json");
        let original = b"{\"idem\":";
        fs::write(&corrupt, original).unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();

        let result = GatewayService::from_config(&config);

        assert!(result.is_err());
        assert_eq!(fs::read(corrupt).unwrap(), original);
    }

    #[tokio::test]
    async fn camera_revocation_after_restart_blocks_a_previously_uploaded_retry() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        let (authorization, server) = camera_authorization_fixture(&mut config).await;
        let uploads = Arc::new(AtomicUsize::new(0));
        let sends = Arc::new(AtomicUsize::new(1));
        let adapter: Arc<dyn PlatformAdapter> = Arc::new(UploadThenFailAdapter {
            uploads: uploads.clone(),
            sends: sends.clone(),
        });
        let outbound = OutboundMessage {
            platform: "upload_then_fail".into(),
            chat_id: "fixture-home".into(),
            text: "".into(),
            attachments: vec![
                json!({"artifact_id":"private-photo","kind":"image","mime_type":"image/jpeg",
                "url":"/api/cameras/recordings/artifacts/private-photo?media_context=chat"}),
            ],
            metadata: serde_json::Map::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let gateway = GatewayService::from_config(&config).unwrap();
        assert!(gateway
            .deliver_outbound_items_guarded(
                adapter.clone(),
                outbound.clone(),
                "camera-revocation",
                "same-plan",
                None
            )
            .await
            .is_err());
        assert_eq!(uploads.load(Ordering::SeqCst), 1);
        assert_eq!(sends.load(Ordering::SeqCst), 2);
        drop(gateway);
        authorization.store(403, Ordering::SeqCst);
        let restarted = GatewayService::from_config(&config).unwrap();
        assert!(restarted
            .deliver_outbound_items_guarded(
                adapter,
                outbound,
                "camera-revocation",
                "same-plan",
                None
            )
            .await
            .is_err());
        assert_eq!(uploads.load(Ordering::SeqCst), 1);
        assert_eq!(sends.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn whatsapp_camera_attachment_is_downloaded_before_adapter_delivery() {
        struct WhatsappFixture(Arc<AtomicUsize>);
        #[async_trait]
        impl PlatformAdapter for WhatsappFixture {
            fn name(&self) -> &str {
                "whatsapp"
            }
            fn normalize_inbound(&self, _: Value) -> Result<InboundMessage, GatewayError> {
                unreachable!()
            }
            async fn send_outbound(
                &self,
                outbound: OutboundMessage,
            ) -> Result<Value, GatewayError> {
                let path = outbound.attachments[0]["path"]
                    .as_str()
                    .expect("downloaded camera attachment");
                assert_eq!(fs::read(path).unwrap(), [255, 216, 255, 217]);
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"provider_message_id":"fixture-image"}))
            }
            fn profile(&self) -> Value {
                json!({"adapter_name":"whatsapp"})
            }
        }
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_token = "fixture-service-token".into();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.harborbeacon_base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let app = axum::Router::new()
                .route(
                    "/api/cameras/recordings/artifacts/whatsapp-photo",
                    axum::routing::get(|headers: axum::http::HeaderMap| async move {
                        assert_eq!(headers.get("X-Harbor-Media-Context").unwrap(), "chat");
                        (
                            [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
                            [255u8, 216, 255, 217],
                        )
                    }),
                )
                .route(
                    "/api/im/whatsapp/delivery-authorization",
                    axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
                        assert_eq!(body["conversation_handle"], "fixture-binding-handle");
                        axum::Json(json!({"allowed":true}))
                    }),
                );
            axum::serve(listener, app).await.unwrap();
        });
        let gateway = GatewayService::from_config(&config).unwrap();
        let sends = Arc::new(AtomicUsize::new(0));
        let outbound = OutboundMessage {
            platform: "whatsapp".into(),
            chat_id: "fixture-home".into(),
            text: "".into(),
            attachments: vec![
                json!({"artifact_id":"whatsapp-photo","kind":"image","mime_type":"image/jpeg",
                "url":"/api/cameras/recordings/artifacts/whatsapp-photo?media_context=chat"}),
            ],
            metadata:
                json!({"conversation_handle":"fixture-binding-handle","route_key":"fixture-route"})
                    .as_object()
                    .unwrap()
                    .clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        gateway
            .deliver_outbound_items_guarded(
                Arc::new(WhatsappFixture(sends.clone())),
                outbound,
                "whatsapp-camera",
                "same-plan",
                None,
            )
            .await
            .unwrap();
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        server.abort();
    }

    mod peer_reminder_tests {
        include!("gateway/peer_reminder_tests.rs");
    }

    #[tokio::test]
    async fn restart_reuses_uploaded_media_after_send_failure() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let uploads = Arc::new(AtomicUsize::new(0));
        let sends = Arc::new(AtomicUsize::new(0));
        let adapter = || {
            Arc::new(UploadThenFailAdapter {
                uploads: uploads.clone(),
                sends: sends.clone(),
            }) as Arc<dyn PlatformAdapter>
        };
        let outbound = OutboundMessage {
            platform: "upload_then_fail".to_string(),
            chat_id: "chat-1".to_string(),
            text: String::new(),
            attachments: vec![
                json!({
                    "artifact_id": "artifact-file-1",
                    "kind": "file",
                    "mime_type": "application/octet-stream",
                    "path": "gate-owned-cache-file-1"
                }),
                json!({
                    "artifact_id": "artifact-file-2",
                    "kind": "file",
                    "mime_type": "application/octet-stream",
                    "path": "gate-owned-cache-file-2"
                }),
            ],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };
        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .deliver_outbound_items(adapter(), outbound.clone(), "idem-upload", "fingerprint")
            .await
            .expect_err("first send must fail after upload");
        let first_ledger: Value = serde_json::from_str(
            &fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let first_items = &first_ledger["idem-upload"]["items"];
        let item_1_key =
            delivery_item_key("idem-upload", &attachment_item_identity("artifact-file-1"));
        let item_2_key =
            delivery_item_key("idem-upload", &attachment_item_identity("artifact-file-2"));
        assert_eq!(first_items[&item_1_key]["status"], "succeeded");
        assert_eq!(
            first_items[&item_1_key]["provider_message_id"],
            "provider-message-1"
        );
        assert_eq!(first_items[&item_2_key]["status"], "failed");
        assert_eq!(
            first_items[&item_2_key]["provider_media_id"],
            "provider-media-2"
        );
        assert!(first_items[&item_2_key]["provider_message_id"].is_null());
        drop(gateway);

        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .deliver_outbound_items(adapter(), outbound, "idem-upload", "fingerprint")
            .await
            .unwrap();

        assert_eq!(uploads.load(Ordering::SeqCst), 2);
        assert_eq!(sends.load(Ordering::SeqCst), 3);
        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(dir.path().join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let items = &ledger["idem-upload"]["items"];
        assert_eq!(items[&item_1_key]["provider_media_id"], "provider-media-1");
        assert_eq!(
            items[&item_1_key]["provider_message_id"],
            "provider-message-1"
        );
        assert_eq!(items[&item_2_key]["provider_media_id"], "provider-media-2");
        assert_eq!(
            items[&item_2_key]["provider_message_id"],
            "provider-message-3"
        );
    }

    #[tokio::test]
    async fn notification_delivery_accepts_safe_local_vision_event_payload() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .store
            .register_route(
                "gw_route_harbornavi_dev",
                json!({
                    "platform": "webhook",
                    "adapter_name": "webhook",
                    "chat_id": "chat1",
                    "status": "active"
                }),
            )
            .unwrap();
        let payload = json!({
            "notification_id": "notif_lve_1",
            "trace_id": "trace_lve_1",
            "source": {
                "service": "harborbeacon",
                "module": "local_vision_event",
                "event_type": "harbornavi.local_vision_event"
            },
            "destination": {"route_key": "gw_route_harbornavi_dev"},
            "content": {
                "title": "HarborNavi 人员事件",
                "body": "检测到人员活动：K3 本地视觉检测到人员活动。",
                "payload_format": "plain_text",
                "structured_payload": {
                    "event": {
                        "event_id": "lve_1",
                        "camera_id": "cam-real-231",
                        "event_type": "person_detected",
                        "confidence": 0.82,
                        "vlm_status": "not_sampled"
                    },
                    "privacy": {
                        "text_only": true,
                        "raw_image_included": false,
                        "local_paths_included": false
                    }
                },
                "attachments": []
            },
            "delivery": {"mode": "send", "idempotency_key": "idem_lve_1", "reply_to_message_id": "", "update_message_id": ""}
        });

        let response = gateway
            .handle_notification_delivery(payload.clone())
            .await
            .unwrap();
        let replay = gateway.handle_notification_delivery(payload).await.unwrap();

        assert_eq!(response, replay);
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["platform"], json!("webhook"));
        assert_eq!(response["notification_id"], json!("notif_lve_1"));
    }

    #[tokio::test]
    async fn notification_delivery_classifies_missing_and_expired_routes() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url.clear();
        let gateway = GatewayService::from_config(&config).unwrap();
        let missing = gateway
            .handle_notification_delivery(notification_payload_for_route(
                "gw_route_missing",
                "idem_missing",
            ))
            .await
            .expect_err("missing route must fail before delivery");
        assert_eq!(missing.code, "ROUTE_NOT_FOUND");
        assert_eq!(missing.status, axum::http::StatusCode::NOT_FOUND);

        gateway
            .store
            .register_route(
                "gw_route_expired",
                json!({
                    "platform": "webhook",
                    "adapter_name": "webhook",
                    "chat_id": "chat1",
                    "status": "expired"
                }),
            )
            .unwrap();
        let expired = gateway
            .handle_notification_delivery(notification_payload_for_route(
                "gw_route_expired",
                "idem_expired",
            ))
            .await
            .expect_err("expired route must fail before delivery");
        assert_eq!(expired.code, "ROUTE_EXPIRED");
        assert_eq!(expired.status, axum::http::StatusCode::GONE);
    }

    #[tokio::test]
    async fn notification_delivery_sends_feishu_mail_via_adapter_preview_shape() {
        let (base_url, request_handle) = spawn_http_response(
            200,
            r#"{"code":0,"data":{"message_id":"om_mail_1","thread_id":"omt_mail_1"}}"#,
        )
        .await;
        let dir = tempdir().unwrap();
        let gateway = feishu_mail_gateway(dir.path(), &base_url);
        let payload = json!({
            "notification": {"notification_id": "notif_mail_1", "trace_id": "trace_mail_1"},
            "destination": {
                "platform": "feishu_mail",
                "recipient": {
                    "email": "lead@example.com",
                    "cc": ["ops@example.com"]
                }
            },
            "content": {
                "title": "[Harbor Outreach Smoke]",
                "body": "Approved body",
                "structured_payload": {
                    "html_body": "<p>Approved body</p>"
                }
            },
            "delivery": {"mode": "send", "idempotency_key": "idem_mail_1", "reply_to_message_id": "", "update_message_id": ""}
        });

        let response = gateway.handle_notification_delivery(payload).await.unwrap();
        let request = request_handle.await.unwrap();

        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["platform"], json!("feishu_mail"));
        assert_eq!(response["provider_message_id"], json!("om_mail_1"));
        assert!(request
            .contains("POST /open-apis/mail/v1/user_mailboxes/sender%40example.com/messages/send"));
        assert!(request
            .to_lowercase()
            .contains("authorization: bearer user-token"));
        assert!(request.contains(r#""subject":"[Harbor Outreach Smoke]""#));
        assert!(request.contains(r#""mail_address":"lead@example.com""#));
        assert!(request.contains(r#""body_plain_text":"Approved body""#));
        assert!(request.contains(r#""body_html":"<p>Approved body</p>""#));
        assert!(request.contains(r#""dedupe_key":"idem_mail_1""#));
    }

    #[tokio::test]
    async fn notification_delivery_maps_feishu_mail_permission_failure() {
        let (base_url, request_handle) =
            spawn_http_response(403, r#"{"code":99991663,"msg":"permission denied"}"#).await;
        let dir = tempdir().unwrap();
        let gateway = feishu_mail_gateway(dir.path(), &base_url);

        let response = gateway
            .handle_notification_delivery(feishu_mail_payload("idem_mail_auth"))
            .await
            .unwrap();
        let _request = request_handle.await.unwrap();

        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["platform"], json!("feishu_mail"));
        assert_eq!(response["retryable"], json!(false));
        assert_eq!(response["error"]["code"], json!("PROVIDER_AUTH_FAILED"));
    }

    #[tokio::test]
    async fn notification_delivery_maps_feishu_mail_unavailable_as_retryable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let dir = tempdir().unwrap();
        let gateway = feishu_mail_gateway(dir.path(), &base_url);

        let response = gateway
            .handle_notification_delivery(feishu_mail_payload("idem_mail_unavailable"))
            .await
            .unwrap();

        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["platform"], json!("feishu_mail"));
        assert_eq!(response["retryable"], json!(true));
        assert_eq!(response["error"]["code"], json!("PLATFORM_UNAVAILABLE"));
    }

    fn notification_payload_for_route(route_key: &str, idempotency_key: &str) -> Value {
        json!({
            "notification": {"notification_id": "notif_route_test", "trace_id": "trace_route_test"},
            "destination": {"route_key": route_key},
            "reply": {"kind": "tool_result", "text": "HarborNavi 本地事件通知。"},
            "delivery": {"mode": "send", "idempotency_key": idempotency_key, "reply_to_message_id": null, "update_message_id": null}
        })
    }

    fn feishu_mail_payload(idempotency_key: &str) -> Value {
        json!({
            "notification": {"notification_id": "notif_mail_failure", "trace_id": "trace_mail_failure"},
            "destination": {
                "platform": "feishu_mail",
                "recipient": {"email": "lead@example.com"}
            },
            "content": {
                "title": "Harbor Outreach",
                "body": "Approved body"
            },
            "delivery": {"mode": "send", "idempotency_key": idempotency_key, "reply_to_message_id": "", "update_message_id": ""}
        })
    }

    fn feishu_mail_gateway(data_dir: &std::path::Path, base_url: &str) -> GatewayService {
        let mut config = AppConfig::from_env();
        config.data_dir = data_dir.to_path_buf();
        config.harborbeacon_base_url.clear();
        config.feishu_mail.enabled = true;
        config.feishu_mail.sender_mailbox = "sender@example.com".into();
        config.feishu_mail.user_access_token = "user-token".into();
        config.feishu_mail.default_from_name = "Harbor Ops".into();
        config.feishu_mail.base_url = base_url.into();
        config.feishu_mail.timeout_seconds = 1;
        GatewayService::from_config(&config).unwrap()
    }

    async fn spawn_http_response(
        status: u16,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let mut request = Vec::new();
            loop {
                let count = socket.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if http_request_complete(&request) {
                    break;
                }
            }
            let status_text = if status == 200 { "OK" } else { "ERROR" };
            let response = format!(
                "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (base_url, handle)
    }

    async fn spawn_turn_and_media_server(
        response_payload: Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let response_payload = Arc::new(response_payload);
        let turn_payload = response_payload.clone();
        let app = axum::Router::new()
            .route(
                "/api/web/turns",
                axum::routing::post(move || {
                    let response_payload = turn_payload.clone();
                    async move { axum::Json((*response_payload).clone()) }
                }),
            )
            .route(
                "/api/cameras/recordings/artifacts/artifact-cache-guard",
                axum::routing::get(|| async {
                    (
                        [
                            (axum::http::header::CONTENT_TYPE, "video/mp4"),
                            (axum::http::header::CONTENT_LENGTH, "4"),
                        ],
                        "clip",
                    )
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base_url, server)
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

    #[test]
    fn gateway_turn_normalizes_android_payload_without_forwarding_push_secret() {
        let payload = json!({
            "turn": {"turn_id": "turn-android-1", "trace_id": "trace-android-1"},
            "actor": {"user_id": "user-1", "workspace_id": "home-1"},
            "conversation": {"channel": "android", "surface": "android", "thread_id": "device-1"},
            "transport": {
                "message_id": "msg-1",
                "metadata": {
                    "client_version": "1.0",
                    "push_token": "secret-token"
                }
            },
            "input": {"text": "hello", "parts": []}
        });

        let inbound = gateway_turn_to_inbound(&payload).unwrap();

        assert_eq!(inbound.platform, "android");
        assert_eq!(inbound.chat_id, "device-1");
        assert_eq!(inbound.user_id, "user-1");
        assert_eq!(inbound.text, "hello");
        assert_eq!(inbound.message_id, "msg-1");
        assert_eq!(
            inbound.raw_payload["transport"]["metadata"]["push_token"],
            "secret-token"
        );
        let turn_payload =
            build_channel_turn_request(&inbound, &payload, Some("conv-android-1"), None);
        assert_eq!(turn_payload["conversation"]["channel"], "android");
        assert_eq!(turn_payload["conversation"]["handle"], "conv-android-1");
        assert!(turn_payload["transport"]["metadata"]["push_token"].is_null());
    }

    #[test]
    fn gateway_turn_rejects_unbound_dlna_without_trusting_actor_home() {
        for payload in [
            json!({
                "actor": {"user_id": "unverified", "workspace_id": "home-other"},
                "intent": {"domain": "dlna", "action": "play"},
                "input": {"text": "Play the video"}
            }),
            json!({
                "transport": {"metadata": {"intent": {"domain": "DLNA"}}},
                "input": {"text": "Play the video"}
            }),
            json!({"input": {"text": " /dlna\tplay"}}),
        ] {
            let error = reject_unbound_dlna_turn(&payload)
                .expect_err("unbound DLNA channel turn must be denied");
            assert_eq!(error.status, StatusCode::FORBIDDEN);
            assert_eq!(error.code, "DLNA_MEMBER_BINDING_REQUIRED");
        }

        assert!(reject_unbound_dlna_turn(&json!({
            "actor": {"workspace_id": "home-other"},
            "input": {"text": "Ordinary message"}
        }))
        .is_ok());
        assert!(reject_unbound_dlna_turn(&json!({"input": {"text": "/dlnatest"}})).is_ok());
    }

    #[tokio::test]
    async fn gateway_turn_handler_denies_dlna_before_beacon_forwarding() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url = "http://127.0.0.1:4174".into();
        config.harborbeacon_token = "local-test-token".into();
        let gateway = GatewayService::from_config(&config).unwrap();

        let error = gateway
            .handle_gateway_turn(json!({
                "actor": {"user_id": "unverified", "workspace_id": "home-other"},
                "conversation": {"channel": "android", "thread_id": "device-1"},
                "transport": {"metadata": {"intent": {"domain": "dlna", "action": "play"}}},
                "input": {"text": "Play the video"}
            }))
            .await
            .expect_err("unbound DLNA turn must stop before Beacon forwarding");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "DLNA_MEMBER_BINDING_REQUIRED");
    }

    #[test]
    fn weixin_selects_url_backed_media_for_gate_materialization() {
        let response = json!({
            "artifacts": [{
                "kind": "image",
                "label": "抓拍图片",
                "mime_type": "image/jpeg",
                "path": null,
                "url": "/api/cameras/recordings/artifacts/snapshots~cam-252~frame.jpg"
            }],
            "delivery_hints": [{"kind": "native_image", "metadata": {"max_items": 1}}]
        });

        let attachments = native_source_bound_attachments("weixin", &response);

        assert_eq!(attachments.len(), 1);
        assert_eq!(
            attachments[0]["url"],
            "/api/cameras/recordings/artifacts/snapshots~cam-252~frame.jpg"
        );
    }

    #[test]
    fn structured_package_notification_selects_one_native_image() {
        let payload = json!({
            "content": {
                "title": "HarborNavi 包裹提醒",
                "body": "门口可能出现了一个包裹。",
                "attachments": [{
                    "artifact_id": "snapshots~camera.252~frame.jpg",
                    "kind": "image",
                    "label": "包裹抓拍",
                    "mime_type": "image/jpeg",
                    "path": null,
                    "url": "/api/cameras/recordings/artifacts/snapshots~camera.252~frame.jpg"
                }],
                "delivery_hints": [{"kind": "native_image", "max_items": 1}]
            }
        });

        let content = delivery_content(&payload);
        let attachments = hinted_notification_attachments(&content);

        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0]["kind"], "image");
        assert_eq!(
            attachments[0]["artifact_id"],
            "snapshots~camera.252~frame.jpg"
        );
    }

    #[test]
    fn weixin_selects_mixed_url_backed_snapshot_and_clip() {
        let response = json!({
            "artifacts": [
                {
                    "kind": "image",
                    "mime_type": "image/jpeg",
                    "path": null,
                    "url": "/api/cameras/recordings/artifacts/snapshot-252"
                },
                {
                    "artifact_id": "clip-252",
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "path": null,
                    "url": "/api/cameras/recordings/artifacts/clip-252",
                    "metadata": {"harborlink_artifact_id": "clip-252"}
                }
            ],
            "delivery_hints": [
                {"kind": "native_image", "metadata": {"max_items": 1}},
                {"kind": "native_video", "artifact_id": "clip-252", "fallback": "file"}
            ]
        });

        let attachments = native_source_bound_attachments("weixin", &response);

        assert_eq!(attachments.len(), 2);
        assert_eq!(attachments[0]["kind"], "image");
        assert_eq!(attachments[1]["kind"], "video");
    }

    #[test]
    fn weixin_keeps_all_cat_activity_videos_for_delivery() {
        let response = json!({
            "artifacts": (1..=5).map(|index| json!({
                "artifact_id": format!("cat-{index}"),
                "kind": "video",
                "mime_type": "video/mp4",
                "url": format!("/api/cameras/recordings/artifacts/cat-{index}"),
                "metadata": {"harborlink_artifact_id": format!("cat-{index}")}
            })).collect::<Vec<_>>(),
            "delivery_hints": (1..=5).map(|index| json!({
                "kind": "native_video",
                "artifact_id": format!("cat-{index}"),
                "fallback": "file"
            })).collect::<Vec<_>>()
        });

        let attachments = native_source_bound_attachments("weixin", &response);

        assert_eq!(attachments.len(), 5);
    }

    #[test]
    fn weixin_video_delivery_rejects_missing_hint_wrong_id_and_non_target_artifacts() {
        let artifacts = vec![
            json!({
                "artifact_id": "cat-1",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/cat-1",
                "metadata": {"harborlink_artifact_id": "cat-1"}
            }),
            json!({
                "artifact_id": "cat-2",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/cat-2",
                "metadata": {"harborlink_artifact_id": "cat-2"}
            }),
        ];
        assert!(hinted_native_videos(&artifacts, &json!({})).is_empty());
        assert!(hinted_native_videos(
            &artifacts,
            &json!({"delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "missing",
                "fallback": "file"
            }]})
        )
        .is_empty());

        let selected = hinted_native_videos(
            &artifacts,
            &json!({"delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "cat-2",
                "fallback": "file"
            }]}),
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(delivery_artifact_id(&selected[0]).as_deref(), Some("cat-2"));
        assert_eq!(
            selected[0]["metadata"]["native_attachment_fallback"],
            "file"
        );
    }

    #[test]
    fn native_video_hint_rejects_artifact_id_aliases() {
        for artifact in [
            json!({
                "id": "artifact-alias",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/artifact-alias"
            }),
            json!({
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/artifact-alias",
                "metadata": {"harborlink_artifact_id": "artifact-alias"}
            }),
        ] {
            let selected = hinted_native_videos(
                &[artifact],
                &json!({"delivery_hints": [{
                    "kind": "native_video",
                    "artifact_id": "artifact-alias",
                    "fallback": "file"
                }]}),
            );
            assert!(selected.is_empty());
        }
    }

    #[test]
    fn turn_and_notification_use_the_same_strict_native_video_plan() {
        let payload = json!({
            "reply": {"kind": "tool_result", "text": "cat clips"},
            "artifacts": [
                {"artifact_id": "artifact-1", "kind": "video", "mime_type": "video/mp4", "url": "/api/cameras/recordings/artifacts/artifact-1"},
                {"artifact_id": "artifact-2", "kind": "video", "mime_type": "video/mp4", "url": "/api/cameras/recordings/artifacts/artifact-2"}
            ],
            "delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "artifact-2",
                "fallback": "file"
            }]
        });

        let turn_plan = native_source_bound_attachments("weixin", &payload);
        let notification_plan = hinted_notification_attachments(&delivery_content(&payload));

        assert_eq!(turn_plan, notification_plan);
        assert_eq!(turn_plan.len(), 1);
        assert_eq!(
            delivery_artifact_id(&turn_plan[0]).as_deref(),
            Some("artifact-2")
        );

        let without_hints = json!({"artifacts": payload["artifacts"].clone()});
        assert!(native_source_bound_attachments("weixin", &without_hints).is_empty());
        assert!(hinted_notification_attachments(&delivery_content(&without_hints)).is_empty());

        let wrong_id = json!({
            "artifacts": payload["artifacts"].clone(),
            "delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "artifact-missing",
                "fallback": "file"
            }]
        });
        assert!(native_source_bound_attachments("weixin", &wrong_id).is_empty());
        assert!(hinted_notification_attachments(&delivery_content(&wrong_id)).is_empty());
    }

    #[tokio::test]
    async fn turn_and_notification_handlers_do_not_send_alias_only_video_artifacts() {
        let (base_url, request_handle) = spawn_http_response(
            200,
            r#"{"turn":{"turn_id":"turn-alias","trace_id":"trace-alias","status":"completed"},"reply":{"text":"cat clips"},"artifacts":[{"id":"artifact-alias","kind":"video","mime_type":"video/mp4","url":"/api/cameras/recordings/artifacts/artifact-alias"}],"delivery_hints":[{"kind":"native_video","artifact_id":"artifact-alias","fallback":"file"}]}"#,
        )
        .await;
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().to_path_buf();
        config.state_dir = dir.path().to_path_buf();
        config.harborbeacon_base_url = base_url;
        config.harborbeacon_token = "service-token".into();
        let sent_attachments = Arc::new(StdMutex::new(Vec::new()));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "weixin".into(),
            Arc::new(CaptureAttachmentAdapter {
                sent_attachments: sent_attachments.clone(),
            }),
        );

        gateway
            .handle_inbound("weixin", json!({"event": "turn"}))
            .await
            .unwrap();
        let _request = request_handle.await.unwrap();
        gateway
            .handle_notification_delivery(json!({
                "notification": {"notification_id": "notification-alias", "trace_id": "trace-notification-alias"},
                "destination": {"platform": "weixin", "id": "wx-chat-notification"},
                "reply": {"kind": "tool_result", "text": "cat clips"},
                "artifacts": [{
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "url": "/api/cameras/recordings/artifacts/artifact-alias",
                    "metadata": {"harborlink_artifact_id": "artifact-alias"}
                }],
                "delivery_hints": [{
                    "kind": "native_video",
                    "artifact_id": "artifact-alias",
                    "fallback": "file"
                }],
                "delivery": {"mode": "send", "idempotency_key": "idem-notification-alias", "reply_to_message_id": null, "update_message_id": null}
            }))
            .await
            .unwrap();

        let sent_attachments = sent_attachments.lock().unwrap();
        assert_eq!(sent_attachments.len(), 2);
        assert!(sent_attachments.iter().all(Vec::is_empty));
    }

    #[tokio::test]
    async fn notification_materialization_failure_keeps_durable_retryable_item_after_text_send() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/api/cameras/recordings/artifacts/artifact-materialize-retry",
                axum::routing::get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_base_url = base_url;
        config.harborbeacon_token = "service-token".into();
        let sent_attachments = Arc::new(StdMutex::new(Vec::new()));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "weixin".into(),
            Arc::new(CaptureAttachmentAdapter {
                sent_attachments: sent_attachments.clone(),
            }),
        );
        gateway
            .store
            .register_route(
                "gw_materialize_retry",
                json!({
                    "platform": "weixin",
                    "adapter_name": "weixin",
                    "chat_id": "wx-materialize-retry",
                    "status": "active"
                }),
            )
            .unwrap();

        let response = gateway
            .handle_notification_delivery(json!({
                "notification": {"notification_id": "notification-materialize-retry", "trace_id": "trace-materialize-retry"},
                "destination": {"route_key": "gw_materialize_retry"},
                "reply": {"kind": "tool_result", "text": "cat clip"},
                "artifacts": [{
                    "artifact_id": "artifact-materialize-retry",
                    "kind": "video",
                    "mime_type": "video/mp4",
                    "url": "/api/cameras/recordings/artifacts/artifact-materialize-retry"
                }],
                "delivery_hints": [{
                    "kind": "native_video",
                    "artifact_id": "artifact-materialize-retry",
                    "fallback": "file"
                }],
                "delivery": {"mode": "send", "idempotency_key": "idem-materialize-retry", "reply_to_message_id": null, "update_message_id": null}
            }))
            .await
            .expect("materialization failure must be represented as retryable delivery state");
        server.abort();

        assert_eq!(response["ok"], false);
        assert_eq!(response["retryable"], true);
        let sent_attachments = sent_attachments.lock().unwrap();
        assert_eq!(sent_attachments.len(), 1);
        assert!(sent_attachments[0].is_empty());
        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(config.data_dir.join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let items = ledger["idem-materialize-retry"]["items"]
            .as_object()
            .unwrap();
        assert_eq!(items.len(), 2);
        let video = items
            .values()
            .find(|item| item["artifact_id"] == "artifact-materialize-retry")
            .unwrap();
        assert_eq!(video["status"], "failed");
        assert_eq!(video["retryable"], true);
        assert_eq!(video["materialization"]["status"], "failed");
        assert_eq!(
            video["planned_outbound"]["attachments"][0]["url"],
            "/api/cameras/recordings/artifacts/artifact-materialize-retry"
        );
        assert_eq!(
            video["planned_outbound"]["attachments"][0]["mime_type"],
            "video/mp4"
        );
    }

    #[tokio::test]
    async fn delivery_recovery_after_restart_does_not_resend_text_and_sends_video_once() {
        use axum::response::IntoResponse as _;

        let materialize_attempts = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let attempts = materialize_attempts.clone();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/api/cameras/recordings/artifacts/artifact-restart-retry",
                axum::routing::get(move |headers: axum::http::HeaderMap| {
                    let attempts = attempts.clone();
                    async move {
                        if headers.contains_key("range") {
                            return StatusCode::OK.into_response();
                        }
                        if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        } else {
                            (
                                [
                                    (axum::http::header::CONTENT_TYPE, "video/mp4"),
                                    (axum::http::header::CONTENT_LENGTH, "4"),
                                ],
                                "clip",
                            )
                                .into_response()
                        }
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_base_url = base_url;
        config.harborbeacon_token = "service-token".into();
        let sent_attachments = Arc::new(StdMutex::new(Vec::new()));
        let build_gateway = || {
            let mut gateway = GatewayService::from_config(&config).unwrap();
            gateway.adapters.insert(
                "weixin".into(),
                Arc::new(CaptureAttachmentAdapter {
                    sent_attachments: sent_attachments.clone(),
                }),
            );
            gateway
        };
        let gateway = build_gateway();
        gateway
            .store
            .register_route(
                "gw_restart_retry",
                json!({
                    "platform": "weixin",
                    "adapter_name": "weixin",
                    "chat_id": "wx-restart-retry",
                    "status": "active"
                }),
            )
            .unwrap();
        let payload = json!({
            "notification": {"notification_id": "notification-restart-retry", "trace_id": "trace-restart-retry"},
            "destination": {"route_key": "gw_restart_retry"},
            "reply": {"kind": "tool_result", "text": "cat clip"},
            "artifacts": [{
                "artifact_id": "artifact-restart-retry",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/artifact-restart-retry"
            }],
            "delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "artifact-restart-retry",
                "fallback": "file"
            }],
            "delivery": {"mode": "send", "idempotency_key": "idem-restart-retry", "reply_to_message_id": null, "update_message_id": null}
        });

        let first = gateway.handle_notification_delivery(payload).await.unwrap();
        assert_eq!(first["ok"], false);
        drop(gateway);

        let gateway = build_gateway();
        assert_eq!(gateway.retry_pending_deliveries().await.unwrap(), 1);
        assert_eq!(gateway.retry_pending_deliveries().await.unwrap(), 0);
        server.abort();

        assert_eq!(materialize_attempts.load(Ordering::SeqCst), 2);
        let sent = sent_attachments.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].is_empty(), "first provider call must be text");
        assert_eq!(sent[1].len(), 1, "recovery must send one video item");
        assert_eq!(sent[1][0]["artifact_id"], "artifact-restart-retry");
        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(config.data_dir.join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let video = ledger["idem-restart-retry"]["items"]
            .as_object()
            .unwrap()
            .values()
            .find(|item| item["artifact_id"] == "artifact-restart-retry")
            .unwrap();
        assert_eq!(video["status"], "succeeded");
        assert_eq!(video["materialization"]["status"], "materialized");
    }

    #[tokio::test]
    async fn materialized_turn_cache_is_cleaned_on_metadata_early_return() {
        assert_materialized_turn_cache_cleanup("metadata").await;
    }

    #[tokio::test]
    async fn materialized_turn_cache_is_cleaned_on_route_early_return() {
        assert_materialized_turn_cache_cleanup("route").await;
    }

    #[tokio::test]
    async fn materialized_turn_cache_is_cleaned_on_history_early_return() {
        assert_materialized_turn_cache_cleanup("history").await;
    }

    #[tokio::test]
    async fn materialized_notification_cache_is_cleaned_on_busy_claim() {
        assert_materialized_notification_cache_cleanup("busy").await;
    }

    #[tokio::test]
    async fn materialized_notification_cache_is_cleaned_on_claim_error() {
        assert_materialized_notification_cache_cleanup("claim_error").await;
    }

    #[tokio::test]
    async fn materialized_notification_cache_is_cleaned_on_ledger_error() {
        assert_materialized_notification_cache_cleanup("ledger_error").await;
    }

    async fn assert_materialized_notification_cache_cleanup(failure: &str) {
        let (base_url, server) = spawn_turn_and_media_server(json!({})).await;
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_base_url = base_url;
        config.harborbeacon_token = "service-token".into();
        let sent_attachments = Arc::new(StdMutex::new(Vec::new()));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "weixin".into(),
            Arc::new(CaptureAttachmentAdapter {
                sent_attachments: sent_attachments.clone(),
            }),
        );
        let route = json!({
            "platform": "weixin",
            "adapter_name": "weixin",
            "chat_id": "wx-notification-guard",
            "status": "active"
        });
        gateway
            .store
            .register_route("gw_notification_guard", route.clone())
            .unwrap();
        let payload = json!({
            "notification": {"notification_id": "notification-guard", "trace_id": "trace-notification-guard"},
            "destination": {"route_key": "gw_notification_guard"},
            "reply": {"kind": "tool_result", "text": "cat clip"},
            "artifacts": [{
                "artifact_id": "artifact-cache-guard",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/artifact-cache-guard"
            }],
            "delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "artifact-cache-guard",
                "fallback": "file"
            }],
            "delivery": {"mode": "send", "idempotency_key": "notification-guard-key", "reply_to_message_id": null, "update_message_id": null}
        });
        let request_fingerprint = fingerprint(&json!({
            "notification_id": "notification-guard",
            "trace_id": "trace-notification-guard",
            "destination": {
                "route_key": "gw_notification_guard",
                "platform": route["platform"].clone(),
                "chat_id": route["chat_id"].clone(),
                "recipient": null,
            },
            "content": delivery_content(&payload),
            "delivery": {
                "mode": "send",
                "reply_to_message_id": "",
                "update_message_id": "",
            },
        }));
        match failure {
            "busy" | "claim_error" => {
                gateway
                    .store
                    .claim_delivery_item(DeliveryItemClaimRequest {
                        delivery_key: "notification-guard-key",
                        request_fingerprint: if failure == "busy" {
                            &request_fingerprint
                        } else {
                            "conflicting-fingerprint"
                        },
                        item_key: &delivery_item_key("notification-guard-key", "item:v1:text"),
                        artifact_id: "__text",
                        kind: "text",
                        owner: "other-gateway",
                        cache_path: None,
                        lease_seconds: 300,
                    })
                    .unwrap();
            }
            "ledger_error" => {
                fs::write(
                    config.data_dir.join("_delivery_items.json"),
                    b"{\"notification-guard-key\":",
                )
                .unwrap();
            }
            _ => unreachable!("unknown notification cache failure fixture"),
        }

        let response = gateway.handle_notification_delivery(payload).await;
        server.abort();

        if failure == "claim_error" {
            let error = response.unwrap_err();
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");
        } else {
            assert_eq!(response.unwrap()["ok"], false);
        }
        assert!(sent_attachments.lock().unwrap().is_empty());
        let cache_root = config.state_dir.join("attachment-cache");
        assert!(fs::read_dir(cache_root).unwrap().next().is_none());
    }

    async fn assert_materialized_turn_cache_cleanup(failed_write: &'static str) {
        let response_payload = json!({
            "turn": {"turn_id": "turn-cache-guard", "trace_id": "trace-cache-guard", "status": "completed"},
            "reply": {"text": "cat clip"},
            "artifacts": [{
                "artifact_id": "artifact-cache-guard",
                "kind": "video",
                "mime_type": "video/mp4",
                "url": "/api/cameras/recordings/artifacts/artifact-cache-guard"
            }],
            "delivery_hints": [{
                "kind": "native_video",
                "artifact_id": "artifact-cache-guard",
                "fallback": "file"
            }]
        });
        let (base_url, server) = spawn_turn_and_media_server(response_payload).await;
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_base_url = base_url;
        config.harborbeacon_token = "service-token".into();
        let sent_attachments = Arc::new(StdMutex::new(Vec::new()));
        let mut gateway = GatewayService::from_config(&config).unwrap();
        gateway.adapters.insert(
            "weixin".into(),
            Arc::new(CaptureAttachmentAdapter {
                sent_attachments: sent_attachments.clone(),
            }),
        );
        gateway.store.fail_next_write(failed_write);

        let error = gateway
            .handle_inbound("weixin", json!({"event": "turn"}))
            .await
            .expect_err("store write must fail after materialization");
        server.abort();

        assert!(error
            .message
            .contains(&format!("injected {failed_write} write failure")));
        assert!(sent_attachments.lock().unwrap().is_empty());
        let cache_root = config.state_dir.join("attachment-cache");
        assert!(
            !cache_root.exists() || fs::read_dir(cache_root).unwrap().next().is_none(),
            "materialized cache leaked after {failed_write} early return"
        );
    }

    #[test]
    fn startup_cache_sweep_preserves_ledger_retained_cache_and_removes_unreferenced_cache() {
        let root = tempdir().unwrap();
        let cache_path = root.path().join("attachment-cache");
        let retry_dir = cache_path.join("retry");
        let terminal_dir = cache_path.join("terminal");
        fs::create_dir_all(&retry_dir).unwrap();
        fs::create_dir_all(&terminal_dir).unwrap();
        let retry_file = retry_dir.join("clip.mp4");
        let terminal_file = terminal_dir.join("clip.mp4");
        fs::write(&retry_file, b"retry").unwrap();
        fs::write(&terminal_file, b"done").unwrap();

        let now = fs::metadata(&terminal_dir).unwrap().modified().unwrap()
            + ATTACHMENT_CACHE_TTL
            + Duration::from_secs(1);
        let cache_root =
            AttachmentCacheRoot::open(root.path(), Path::new("attachment-cache")).unwrap();
        sweep_expired_attachment_cache(&cache_root, std::slice::from_ref(&retry_file), now)
            .unwrap();

        assert!(retry_file.exists());
        assert!(!terminal_dir.exists());
    }

    #[test]
    fn startup_cache_sweep_preserves_recent_unclaimed_batch_across_instances() {
        let root = tempdir().unwrap();
        let materializing_gateway =
            AttachmentCacheRoot::open(root.path(), Path::new("attachment-cache")).unwrap();
        let sweeping_gateway =
            AttachmentCacheRoot::open(root.path(), Path::new("attachment-cache")).unwrap();
        let batch_dir = materializing_gateway.path().join("materializing-unclaimed");
        fs::create_dir_all(&batch_dir).unwrap();
        fs::write(batch_dir.join("clip.partial"), b"in progress").unwrap();
        let modified_at = fs::metadata(&batch_dir).unwrap().modified().unwrap();

        sweep_expired_attachment_cache(
            &sweeping_gateway,
            &[],
            modified_at + ATTACHMENT_CACHE_TTL - Duration::from_secs(1),
        )
        .unwrap();

        assert!(batch_dir.exists());
        sweep_expired_attachment_cache(
            &sweeping_gateway,
            &[],
            modified_at + ATTACHMENT_CACHE_TTL + Duration::from_secs(1),
        )
        .unwrap();
        assert!(!batch_dir.exists());
    }

    #[test]
    fn cache_sweep_uses_held_root_after_visible_path_is_replaced() {
        let root = tempdir().unwrap();
        #[cfg(windows)]
        let (cache_root, displaced_cache_root, outside_dir) = {
            let state_dir = root.path().join("state");
            let real_state_dir = root.path().join("real-state");
            let outside_state_dir = root.path().join("outside-state");
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
            let visible_cache_root = root.path().join("attachment-cache");
            let displaced_cache_root = root.path().join("attachment-cache-original");
            let outside_dir = root.path().join("outside");
            fs::create_dir_all(&outside_dir).unwrap();
            let cache_root =
                AttachmentCacheRoot::open(root.path(), Path::new("attachment-cache")).unwrap();
            fs::rename(&visible_cache_root, &displaced_cache_root).unwrap();
            std::os::unix::fs::symlink(&outside_dir, &visible_cache_root).unwrap();
            (cache_root, displaced_cache_root, outside_dir)
        };
        let original_batch = displaced_cache_root.join("expired-original");
        let original_file = original_batch.join("clip.mp4");
        let outside_batch = outside_dir.join("expired-outside");
        let outside_file = outside_batch.join("marker.txt");
        fs::create_dir_all(&original_batch).unwrap();
        fs::create_dir_all(&outside_batch).unwrap();
        fs::write(&original_file, b"inside").unwrap();
        fs::write(&outside_file, b"outside-must-survive").unwrap();
        let now = fs::metadata(&outside_batch).unwrap().modified().unwrap()
            + ATTACHMENT_CACHE_TTL
            + Duration::from_secs(1);

        sweep_expired_attachment_cache(&cache_root, &[], now).unwrap();

        assert!(outside_file.exists());
        assert!(!displaced_cache_root.join("expired-original").exists());
    }

    #[test]
    fn startup_expires_retryable_cache_by_ledger_timestamp_before_deleting_file() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("sessions");
        let state_dir = dir.path().join("state");
        let batch_dir = state_dir.join("attachment-cache").join("expired-retryable");
        let legacy_batch_dir = state_dir.join("attachment-cache").join("legacy-retryable");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&batch_dir).unwrap();
        fs::create_dir_all(&legacy_batch_dir).unwrap();
        let cache_file = batch_dir.join("clip.mp4");
        let legacy_cache_file = legacy_batch_dir.join("clip.mp4");
        fs::write(&cache_file, b"clip").unwrap();
        fs::write(&legacy_cache_file, b"legacy").unwrap();
        let expired_at = (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
        fs::write(
            data_dir.join("_delivery_items.json"),
            serde_json::to_vec_pretty(&json!({
                "delivery-expired": {
                    "request_fingerprint": "fingerprint-expired",
                    "items": {
                        "delivery-expired:artifact-expired": {
                            "item_key": "delivery-expired:artifact-expired",
                            "artifact_id": "artifact-expired",
                            "kind": "video",
                            "status": "failed",
                            "retryable": true,
                            "cache_path": cache_file,
                            "updated_at": expired_at
                        }
                    }
                },
                "delivery-legacy": {
                    "request_fingerprint": "fingerprint-legacy",
                    "items": {
                        "delivery-legacy:artifact-legacy": {
                            "item_key": "delivery-legacy:artifact-legacy",
                            "artifact_id": "artifact-legacy",
                            "kind": "video",
                            "status": "failed",
                            "retryable": true,
                            "cache_path": legacy_cache_file
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = data_dir.clone();
        config.state_dir = state_dir;
        config.harborbeacon_base_url.clear();

        let _gateway = GatewayService::from_config(&config).unwrap();

        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(data_dir.join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let item = &ledger["delivery-expired"]["items"]["delivery-expired:artifact-expired"];
        assert_eq!(item["status"], "expired");
        assert!(item["cache_path"].is_null());
        assert!(!cache_file.exists());
        let legacy_item = &ledger["delivery-legacy"]["items"]["delivery-legacy:artifact-legacy"];
        assert_eq!(legacy_item["status"], "failed");
        assert_eq!(legacy_item["cache_path"], json!(legacy_cache_file));
        assert!(legacy_item["updated_at"].as_str().is_some());
        assert!(legacy_cache_file.exists());
    }

    #[tokio::test]
    async fn successful_delivery_cleanup_removes_files_and_batch_directory() {
        let root = tempdir().unwrap();
        let batch_dir = root.path().join("attachment-cache").join("turn-success");
        fs::create_dir_all(&batch_dir).unwrap();
        let file = batch_dir.join("clip.mp4");
        fs::write(&file, b"clip").unwrap();
        let cache_root =
            AttachmentCacheRoot::open(root.path(), Path::new("attachment-cache")).unwrap();

        cleanup_attachment_cache(&cache_root, vec![file.clone()], Some(batch_dir.clone())).await;

        assert!(!file.exists());
        assert!(!batch_dir.exists());
    }

    #[test]
    fn safe_cache_removal_rejects_parent_traversal_and_symlinked_directory() {
        let dir = tempdir().unwrap();
        let cache_root = dir.path().join("attachment-cache");
        let outside_dir = dir.path().join("outside");
        fs::create_dir_all(&cache_root).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_marker = outside_dir.join("marker.txt");
        fs::write(&outside_marker, b"must survive").unwrap();
        let cache = AttachmentCacheRoot::open(dir.path(), Path::new("attachment-cache")).unwrap();

        let traversal = cache_root
            .join("batch")
            .join("..")
            .join("..")
            .join("outside")
            .join("marker.txt");
        assert!(cache.remove_file(&traversal).is_err());

        let linked_dir = cache_root.join("linked-outside");
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&linked_dir)
            .arg(&outside_dir)
            .status()
            .unwrap()
            .success());
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_dir, &linked_dir).unwrap();
        assert!(cache.remove_file(&linked_dir.join("marker.txt")).is_err());
        assert_eq!(fs::read(outside_marker).unwrap(), b"must survive");
    }

    #[test]
    fn capability_cache_delete_rejects_directory_swap_after_relative_resolution() {
        let dir = tempdir().unwrap();
        let cache_root = dir.path().join("attachment-cache");
        let batch_dir = cache_root.join("batch");
        let moved_batch_dir = cache_root.join("batch-original");
        let outside_dir = dir.path().join("outside");
        fs::create_dir_all(&batch_dir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        let candidate = batch_dir.join("marker.txt");
        let moved_candidate = moved_batch_dir.join("marker.txt");
        let outside_marker = outside_dir.join("marker.txt");
        let ledger_path = dir.path().join("_delivery_items.json");
        fs::write(&candidate, b"inside").unwrap();
        fs::write(&outside_marker, b"outside-must-survive").unwrap();
        fs::write(&ledger_path, b"ledger-must-survive").unwrap();
        let cache = AttachmentCacheRoot::open(dir.path(), Path::new("attachment-cache")).unwrap();

        let result = cache.remove_file_with_hook(&candidate, || {
            fs::rename(&batch_dir, &moved_batch_dir).unwrap();
            #[cfg(windows)]
            assert!(std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(&batch_dir)
                .arg(&outside_dir)
                .status()
                .unwrap()
                .success());
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside_dir, &batch_dir).unwrap();
        });

        assert!(result.is_err());
        assert_eq!(fs::read(&outside_marker).unwrap(), b"outside-must-survive");
        assert_eq!(fs::read(&moved_candidate).unwrap(), b"inside");
        assert_eq!(fs::read(&ledger_path).unwrap(), b"ledger-must-survive");
    }

    #[test]
    fn attachment_cache_root_rejects_preexisting_root_link() {
        let dir = tempdir().unwrap();
        let state_dir = dir.path().join("trusted-state");
        let cache_root = state_dir.join("attachment-cache");
        let outside_dir = dir.path().join("outside");
        let data_dir = dir.path().join("sessions");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        fs::create_dir_all(&data_dir).unwrap();
        let outside_marker = outside_dir.join("marker.txt");
        let ledger_path = data_dir.join("_delivery_items.json");
        let ledger_bytes = b"{}";
        fs::write(&outside_marker, b"outside-must-survive").unwrap();
        fs::write(&ledger_path, ledger_bytes).unwrap();
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&cache_root)
            .arg(&outside_dir)
            .status()
            .unwrap()
            .success());
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_dir, &cache_root).unwrap();

        assert!(AttachmentCacheRoot::open(&state_dir, Path::new("attachment-cache")).is_err());
        let mut config = AppConfig::from_env();
        config.data_dir = data_dir;
        config.state_dir = state_dir;
        config.harborbeacon_base_url.clear();
        assert!(GatewayService::from_config(&config).is_err());
        assert_eq!(fs::read(&outside_marker).unwrap(), b"outside-must-survive");
        assert_eq!(fs::read(&ledger_path).unwrap(), ledger_bytes);
    }

    #[test]
    fn attachment_cache_root_rejects_link_swapped_between_create_and_open() {
        let dir = tempdir().unwrap();
        let state_dir = dir.path().join("trusted-state");
        let cache_root = state_dir.join("attachment-cache");
        let displaced_cache_root = state_dir.join("attachment-cache-original");
        let outside_dir = dir.path().join("outside");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_marker = outside_dir.join("marker.txt");
        fs::write(&outside_marker, b"outside-must-survive").unwrap();

        let result = AttachmentCacheRoot::open_after_create(
            &state_dir,
            Path::new("attachment-cache"),
            || {
                fs::rename(&cache_root, &displaced_cache_root).unwrap();
                #[cfg(windows)]
                assert!(std::process::Command::new("cmd")
                    .arg("/C")
                    .arg("mklink")
                    .arg("/J")
                    .arg(&cache_root)
                    .arg(&outside_dir)
                    .status()
                    .unwrap()
                    .success());
                #[cfg(unix)]
                std::os::unix::fs::symlink(&outside_dir, &cache_root).unwrap();
            },
        );

        assert!(result.is_err());
        assert!(displaced_cache_root.is_dir());
        assert_eq!(fs::read(outside_marker).unwrap(), b"outside-must-survive");
    }

    #[test]
    fn attachment_cache_root_requires_a_single_relative_basename() {
        let dir = tempdir().unwrap();

        assert!(AttachmentCacheRoot::open(dir.path(), Path::new("../attachment-cache")).is_err());
        assert!(
            AttachmentCacheRoot::open(dir.path(), Path::new("nested/attachment-cache")).is_err()
        );
        assert!(AttachmentCacheRoot::open(dir.path(), dir.path()).is_err());
    }

    #[tokio::test]
    async fn successful_item_terminally_clears_ledger_cache_path_and_file() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_base_url.clear();
        let batch_dir = config
            .state_dir
            .join("attachment-cache")
            .join("terminal-success");
        fs::create_dir_all(&batch_dir).unwrap();
        let cache_file = batch_dir.join("clip.mp4");
        fs::write(&cache_file, b"clip").unwrap();
        let gateway = GatewayService::from_config(&config).unwrap();
        gateway
            .deliver_outbound_items(
                Arc::new(RetryOnceAdapter {
                    attempts: Arc::new(AtomicUsize::new(1)),
                }),
                OutboundMessage {
                    platform: "retry_once".into(),
                    chat_id: "chat-terminal-success".into(),
                    text: String::new(),
                    attachments: vec![json!({
                        "artifact_id": "artifact-terminal-success",
                        "kind": "file",
                        "mime_type": "application/octet-stream",
                        "path": cache_file
                    })],
                    timestamp: crate::models::utc_now_iso(),
                    metadata: serde_json::Map::new(),
                },
                "delivery-terminal-success",
                "fingerprint-terminal-success",
            )
            .await
            .unwrap();

        let ledger: Value = serde_json::from_str(
            &fs::read_to_string(config.data_dir.join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let item_key = delivery_item_key(
            "delivery-terminal-success",
            &attachment_item_identity("artifact-terminal-success"),
        );
        let item = &ledger["delivery-terminal-success"]["items"][&item_key];
        assert!(item["cache_path"].is_null());
        assert!(!cache_file.exists());
        assert!(!batch_dir.exists());
    }

    #[tokio::test]
    async fn nonretryable_failure_terminally_clears_ledger_cache_path_and_file() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        config.harborbeacon_base_url.clear();
        let batch_dir = config
            .state_dir
            .join("attachment-cache")
            .join("terminal-failure");
        fs::create_dir_all(&batch_dir).unwrap();
        let cache_file = batch_dir.join("clip.mp4");
        fs::write(&cache_file, b"clip").unwrap();
        let gateway = GatewayService::from_config(&config).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let adapter = Arc::new(TerminalFailureAdapter {
            attempts: attempts.clone(),
        }) as Arc<dyn PlatformAdapter>;
        let outbound = OutboundMessage {
            platform: "terminal_failure".into(),
            chat_id: "chat-terminal-failure".into(),
            text: String::new(),
            attachments: vec![json!({
                "artifact_id": "artifact-terminal-failure",
                "kind": "file",
                "mime_type": "application/octet-stream",
                "path": cache_file
            })],
            timestamp: crate::models::utc_now_iso(),
            metadata: serde_json::Map::new(),
        };

        let error = gateway
            .deliver_outbound_items(
                adapter.clone(),
                outbound.clone(),
                "delivery-terminal-failure",
                "fingerprint-terminal-failure",
            )
            .await
            .expect_err("authorization failure must be terminal");

        assert!(error.message.contains("authorization failed"));
        let mut ledger: Value = serde_json::from_str(
            &fs::read_to_string(config.data_dir.join("_delivery_items.json")).unwrap(),
        )
        .unwrap();
        let item_key = delivery_item_key(
            "delivery-terminal-failure",
            &attachment_item_identity("artifact-terminal-failure"),
        );
        let item = &mut ledger["delivery-terminal-failure"]["items"][&item_key];
        assert_eq!(item["status"], "failed");
        assert_eq!(item["retryable"], false);
        assert!(item["cache_path"].is_null());
        assert!(!cache_file.exists());
        assert!(!batch_dir.exists());
        item["provider_media_id"] = json!("provider-media-terminal");
        item["provider_client_id"] = json!("provider-client-terminal");
        item["provider_message_id"] = json!("provider-message-terminal");
        fs::write(
            config.data_dir.join("_delivery_items.json"),
            serde_json::to_vec_pretty(&ledger).unwrap(),
        )
        .unwrap();

        let replay = gateway
            .deliver_outbound_items(
                adapter,
                outbound,
                "delivery-terminal-failure",
                "fingerprint-terminal-failure",
            )
            .await
            .expect_err("terminal failure must replay without provider access");

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            replay.delivery_failure.as_ref().unwrap()["provider_media_id"],
            "provider-media-terminal"
        );
        assert_eq!(
            replay.delivery_failure.as_ref().unwrap()["provider_client_id"],
            "provider-client-terminal"
        );
        assert_eq!(
            replay.delivery_failure.as_ref().unwrap()["provider_message_id"],
            "provider-message-terminal"
        );
        assert!(replay.message.contains("authorization failed"));
        assert!(!config.data_dir.join("_deliveries.json").exists());
    }

    #[tokio::test]
    async fn tampered_previous_cache_path_cannot_delete_outside_marker() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("sessions");
        let state_dir = dir.path().join("state");
        let safe_batch_dir = state_dir.join("attachment-cache").join("safe-retry");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&safe_batch_dir).unwrap();
        let safe_cache_file = safe_batch_dir.join("clip.mp4");
        fs::write(&safe_cache_file, b"clip").unwrap();
        let outside_marker = dir.path().join("outside-marker.txt");
        fs::write(&outside_marker, b"must survive").unwrap();
        fs::write(
            data_dir.join("_delivery_items.json"),
            serde_json::to_vec_pretty(&json!({
                "delivery-tampered": {
                    "request_fingerprint": "fingerprint-tampered",
                    "items": {
                        "delivery-tampered:artifact-tampered": {
                            "item_key": "delivery-tampered:artifact-tampered",
                            "artifact_id": "artifact-tampered",
                            "kind": "file",
                            "status": "failed",
                            "attempts": 1,
                            "retryable": true,
                            "cache_path": outside_marker,
                            "updated_at": crate::models::utc_now_iso()
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = data_dir;
        config.state_dir = state_dir;
        config.harborbeacon_base_url.clear();
        let gateway = GatewayService::from_config(&config).unwrap();

        gateway
            .deliver_outbound_items(
                Arc::new(RetryOnceAdapter {
                    attempts: Arc::new(AtomicUsize::new(1)),
                }),
                OutboundMessage {
                    platform: "retry_once".into(),
                    chat_id: "chat-tampered".into(),
                    text: String::new(),
                    attachments: vec![json!({
                        "artifact_id": "artifact-tampered",
                        "kind": "file",
                        "mime_type": "application/octet-stream",
                        "path": safe_cache_file
                    })],
                    timestamp: crate::models::utc_now_iso(),
                    metadata: serde_json::Map::new(),
                },
                "delivery-tampered",
                "fingerprint-tampered",
            )
            .await
            .unwrap();

        assert_eq!(fs::read(&outside_marker).unwrap(), b"must survive");
        assert!(!safe_cache_file.exists());
    }

    #[test]
    fn rendered_link_artifact_contains_clickable_public_url() {
        let rendered = render_entries(
            &[json!({
                "kind": "link",
                "label": "共享观看链接",
                "url": "/shared/cameras/token-252"
            })],
            "artifact",
            "http://198.51.100.70",
        );

        assert!(rendered.contains("http://198.51.100.70/shared/cameras/token-252"));
    }
}
