//! Gate-owned IM endpoint selection. Household membership stays in Beacon.
use crate::{
    cloud_relay::{valid_hub_id, CloudRelayClient},
    error::GatewayError,
    models::{InboundMessage, OutboundMessage},
};
use atomicwrites::{AllowOverwrite, AtomicFile};
use fs2::FileExt;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    path::PathBuf,
};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct NaviFleet {
    pub relay: CloudRelayClient,
    directory: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct Selection {
    pub hub_id: String,
    pub hub_identity: String,
    pub binding_id: String,
    pub generation: String,
    pub selected_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    id: String,
    hub_id: String,
    token: String,
    recipient: String,
    route_key: String,
    occurred_at: String,
    expires_at: i64,
    next_poll: i64,
    session_id: Option<String>,
    hub_identity: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Route {
    active: Option<Selection>,
    pending: Option<Pending>,
    seen: BTreeMap<String, i64>,
    newest_proof_at: i64,
    #[serde(default)]
    recipient: String,
    #[serde(default)]
    route_key: String,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    updates: BTreeMap<String, RouteUpdate>,
    #[serde(default)]
    notification_next_poll: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct RouteUpdate {
    selection: Selection,
    recipient: String,
    route_key: String,
    revision: u64,
    status: String,
    issued_at: i64,
    next_poll: i64,
}

fn queue_route_update(route: &mut Route, status: &str) -> Result<(), GatewayError> {
    let Some(selection) = route.active.clone() else {
        return Ok(());
    };
    // Older development directories learn transport coordinates on their next
    // signed phone message; never reverse or guess the hashed directory key.
    if route.recipient.is_empty() || route.route_key.is_empty() {
        return Ok(());
    }
    if route.updates.len() >= 64 && !route.updates.contains_key(&selection.generation) {
        return Err(unavailable());
    }
    route.revision = route
        .revision
        .checked_add(1)
        .filter(|v| *v <= 9_007_199_254_740_991)
        .ok_or_else(unavailable)?;
    route.updates.insert(
        selection.generation.clone(),
        RouteUpdate {
            selection,
            recipient: route.recipient.clone(),
            route_key: route.route_key.clone(),
            revision: route.revision,
            status: status.into(),
            issued_at: now(),
            next_poll: 0,
        },
    );
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
struct Directory {
    routes: BTreeMap<String, Route>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn hash(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
fn key(recipient: &str, route: &str) -> String {
    hash(&json!([recipient, route]))
}
fn unavailable() -> GatewayError {
    GatewayError::infrastructure("Navi routing is temporarily unavailable")
}
fn denied() -> GatewayError {
    GatewayError::new(
        StatusCode::FORBIDDEN,
        "IM_DELIVERY_NOT_ALLOWED",
        "Navi selection permission no longer permits this delivery",
    )
}
fn valid_proof_id(value: &str) -> bool {
    matches!(value.len(), 32 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl NaviFleet {
    pub fn invalidate_identity(&self, selection: &Selection) -> Result<(), GatewayError> {
        self.transaction(|state| {
            for route in state.routes.values_mut() {
                let matches = |item: &Selection| {
                    item.hub_id == selection.hub_id && item.hub_identity == selection.hub_identity
                };
                if route.active.as_ref().is_some_and(matches) {
                    route.active = None;
                }
                if route.pending.as_ref().is_some_and(|item| {
                    item.hub_id == selection.hub_id
                        && item
                            .hub_identity
                            .as_ref()
                            .is_none_or(|identity| identity == &selection.hub_identity)
                }) {
                    route.pending = None;
                }
                route
                    .updates
                    .retain(|_, update| !matches(&update.selection));
            }
            Ok(())
        })
    }

    pub fn notification_target(&self) -> Result<Option<(Selection, Value)>, GatewayError> {
        self.transaction(|state| {
            let route = state
                .routes
                .values_mut()
                .filter(|r| {
                    r.active.is_some()
                        && !r.recipient.is_empty()
                        && !r.route_key.is_empty()
                        && r.notification_next_poll <= now()
                        && r.pending.as_ref().is_none_or(|p| p.expires_at <= now())
                })
                .min_by_key(|r| r.notification_next_poll);
            let Some(route) = route else { return Ok(None) };
            route.notification_next_poll = now() + 15;
            let selection = route.active.clone().ok_or_else(denied)?;
            let scope = json!({"binding_id":selection.binding_id,"generation":selection.generation,
                "recipient":route.recipient,"route_key":route.route_key});
            Ok(Some((selection, scope)))
        })
    }

    pub fn new(relay: CloudRelayClient, directory: PathBuf) -> Self {
        Self { relay, directory }
    }

    fn transaction<T>(
        &self,
        f: impl FnOnce(&mut Directory) -> Result<T, GatewayError>,
    ) -> Result<T, GatewayError> {
        fs::create_dir_all(&self.directory).map_err(|_| unavailable())?;
        if !fs::symlink_metadata(&self.directory)
            .map_err(|_| unavailable())?
            .is_dir()
        {
            return Err(unavailable());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| unavailable())?;
        }
        let path = self.directory.join("routes.json");
        let lock_path = self.directory.join("routes.lock");
        for file in [&path, &lock_path] {
            match fs::symlink_metadata(file) {
                Ok(meta) if !meta.is_file() || meta.len() > 4 * 1024 * 1024 => {
                    return Err(unavailable())
                }
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(unavailable())
                }
                _ => {}
            }
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path)
            .map_err(|_| unavailable())?;
        lock.lock_exclusive().map_err(|_| unavailable())?;
        let mut state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| unavailable())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Directory::default(),
            Err(_) => return Err(unavailable()),
        };
        let result = f(&mut state)?;
        let bytes = serde_json::to_vec(&state).map_err(|_| unavailable())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(unavailable());
        }
        AtomicFile::new(path, AllowOverwrite)
            .write(|file| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
                use std::io::Write;
                file.write_all(&bytes)?;
                file.sync_all()
            })
            .map_err(|_| unavailable())?;
        Ok(result)
    }

    /// A routing hint is not ownership. Only a valid proof returned by the
    /// selected device, after its Owner confirms, can replace the active route.
    pub fn begin(&self, incoming: &InboundMessage) -> Result<(), GatewayError> {
        let message = incoming
            .text
            .trim()
            .strip_prefix("NAVI ")
            .ok_or_else(denied)?;
        let (hub, token) = message.split_once('.').ok_or_else(denied)?;
        let occurred = chrono::DateTime::parse_from_rfc3339(&incoming.timestamp)
            .map_err(|_| denied())?
            .timestamp();
        if !valid_hub_id(hub)
            || token.len() != 64
            || !token.bytes().all(|b| b.is_ascii_hexdigit())
            || incoming.platform != "whatsapp"
            || incoming.chat_type != "p2p"
            || incoming.chat_id != incoming.user_id
            || !(7..=15).contains(&incoming.user_id.len())
            || !incoming.user_id.bytes().all(|b| b.is_ascii_digit())
            || incoming.route_key.is_empty()
            || incoming.route_key.len() > 256
            || incoming.message_id.is_empty()
            || occurred <= now() - 300
            || occurred > now() + 60
        {
            return Err(denied());
        }
        self.transaction(|state| {
            if state.routes.len() >= 4096
                && !state
                    .routes
                    .contains_key(&key(&incoming.user_id, &incoming.route_key))
            {
                return Err(unavailable());
            }
            let route = state
                .routes
                .entry(key(&incoming.user_id, &incoming.route_key))
                .or_default();
            route.recipient = incoming.user_id.clone();
            route.route_key = incoming.route_key.clone();
            route.seen.retain(|_, expiry| *expiry > now());
            let id = hash(&json!([hub, token]));
            if route.seen.contains_key(&id) {
                return Ok(());
            }
            if occurred < route.newest_proof_at || route.seen.len() >= 64 {
                return Err(denied());
            }
            let expires = (occurred + 300).min(now() + 300);
            route.seen.insert(id.clone(), occurred + 360);
            route.newest_proof_at = occurred;
            route.pending = Some(Pending {
                id,
                hub_id: hub.into(),
                token: token.into(),
                recipient: incoming.user_id.clone(),
                route_key: incoming.route_key.clone(),
                occurred_at: incoming.timestamp.clone(),
                expires_at: expires,
                next_poll: 0,
                session_id: None,
                hub_identity: None,
            });
            queue_route_update(route, "paused")?;
            Ok(())
        })
    }

    fn claim(&self) -> Result<Option<Pending>, GatewayError> {
        self.transaction(|state| {
            for route in state.routes.values_mut() {
                if route
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.expires_at <= now())
                {
                    route.pending = None;
                    queue_route_update(route, "active")?;
                }
            }
            let pending = state
                .routes
                .values_mut()
                .filter_map(|route| route.pending.as_mut())
                .filter(|pending| pending.next_poll <= now())
                .min_by_key(|pending| pending.next_poll);
            Ok(pending.map(|pending| {
                pending.next_poll = now() + 10;
                pending.clone()
            }))
        })
    }

    /// Polling resumes after a Gate restart. A newer phone proof fences out
    /// late results; errors leave the old confirmed device unchanged.
    pub async fn refresh_one(&self) -> Result<bool, GatewayError> {
        let Some(pending) = self.claim()? else {
            return Ok(false);
        };
        let relay = match &pending.hub_identity {
            Some(identity) => self.relay.with_hub_identity(identity)?,
            None => self.relay.clone(),
        };
        let response = relay
            .binding_proof(
                &pending.hub_id,
                &json!({"token":pending.token,"recipient":pending.recipient,
            "route_key":pending.route_key,"occurred_at":pending.occurred_at}),
            )
            .await?;
        self.finish(
            &pending,
            response.status,
            &response.body,
            &response.hub_identity,
        )?;
        Ok(true)
    }

    fn finish(
        &self,
        pending: &Pending,
        status: StatusCode,
        proof: &Value,
        identity: &str,
    ) -> Result<(), GatewayError> {
        self.transaction(|state| {
            let route = state
                .routes
                .get_mut(&key(&pending.recipient, &pending.route_key))
                .ok_or_else(unavailable)?;
            let Some(current) = route
                .pending
                .as_mut()
                .filter(|current| current.id == pending.id)
            else {
                return Ok(());
            };
            if current.expires_at <= now()
                || matches!(status.as_u16(), 400 | 401 | 403 | 404 | 410 | 422)
            {
                route.pending = None;
                queue_route_update(route, "active")?;
                return Ok(());
            }
            if status != StatusCode::OK {
                return Err(unavailable());
            }
            if identity.len() != 64
                || !identity.bytes().all(|b| b.is_ascii_hexdigit())
                || current
                    .hub_identity
                    .as_deref()
                    .is_some_and(|expected| expected != identity)
            {
                return Err(unavailable());
            }
            current.hub_identity = Some(identity.into());
            let session = proof["session_id"]
                .as_str()
                .filter(|id| valid_proof_id(id))
                .ok_or_else(unavailable)?;
            let expires = proof["expires_at"]
                .as_i64()
                .filter(|expires| *expires > now())
                .ok_or_else(unavailable)?;
            if current
                .session_id
                .as_deref()
                .is_some_and(|original| original != session)
            {
                return Err(unavailable());
            }
            current.session_id = Some(session.into());
            current.expires_at = current.expires_at.min(expires);
            match proof["status"].as_str() {
                Some("awaiting_owner_confirmation") => {
                    current.next_poll = now() + 1;
                }
                Some("bound") => {
                    let occurred = chrono::DateTime::parse_from_rfc3339(&current.occurred_at)
                        .map_err(|_| unavailable())?
                        .timestamp();
                    if proof["binding_id"] != session
                        || proof["confirmed_at"]
                            .as_i64()
                            .is_none_or(|at| at < occurred || at > now() + 60)
                    {
                        return Err(unavailable());
                    }
                    queue_route_update(route, "retired")?;
                    route.active = Some(Selection {
                        hub_id: pending.hub_id.clone(),
                        hub_identity: identity.into(),
                        binding_id: session.into(),
                        generation: Uuid::new_v4().simple().to_string(),
                        selected_at: now(),
                    });
                    route.pending = None;
                    queue_route_update(route, "active")?;
                }
                _ => return Err(unavailable()),
            }
            Ok(())
        })
    }

    fn claim_route_update(&self) -> Result<Option<RouteUpdate>, GatewayError> {
        self.transaction(|state| {
            let update = state
                .routes
                .values_mut()
                .flat_map(|route| route.updates.values_mut())
                .filter(|update| update.next_poll <= now())
                .min_by_key(|update| update.next_poll);
            Ok(update.map(|update| {
                update.next_poll = now() + 10;
                update.clone()
            }))
        })
    }

    fn finish_route_update(
        &self,
        update: &RouteUpdate,
        status: StatusCode,
        receipt: &Value,
    ) -> Result<(), GatewayError> {
        self.transaction(|state| {
            let Some(route) = state
                .routes
                .get_mut(&key(&update.recipient, &update.route_key))
            else {
                return Ok(());
            };
            let Some(current) = route.updates.get(&update.selection.generation) else {
                return Ok(());
            };
            if current.revision != update.revision {
                return Ok(());
            } // A later switch superseded this call.
            if status == StatusCode::OK {
                if receipt["binding_id"] != update.selection.binding_id
                    || receipt["generation"] != update.selection.generation
                    || receipt["revision"] != update.revision
                    || receipt["status"] != update.status
                    || receipt["applied"] != true
                {
                    return Err(unavailable());
                }
            } else if !matches!(status.as_u16(), 403 | 410) {
                return Err(unavailable());
            }
            route.updates.remove(&update.selection.generation);
            Ok(())
        })
    }

    pub async fn refresh_route_update(&self) -> Result<bool, GatewayError> {
        let Some(update) = self.claim_route_update()? else {
            return Ok(false);
        };
        let client = self
            .relay
            .with_hub_identity(&update.selection.hub_identity)?;
        let result=client.binding_route(&update.selection.hub_id,&json!({"binding_id":update.selection.binding_id,
            "recipient":update.recipient,"route_key":update.route_key,"generation":update.selection.generation,
            "revision":update.revision,"status":update.status,"issued_at":update.issued_at})).await;
        match result {
            Ok(response) => self.finish_route_update(&update, response.status, &response.body)?,
            Err(error) if error.code == "NAVI_IDENTITY_CHANGED" => {
                self.finish_route_update(&update, StatusCode::FORBIDDEN, &Value::Null)?
            }
            Err(error) => return Err(error),
        }
        Ok(true)
    }

    pub fn select(&self, incoming: &InboundMessage) -> Result<Selection, GatewayError> {
        self.transaction(|state| {
            let route = state
                .routes
                .get(&key(&incoming.user_id, &incoming.route_key))
                .ok_or_else(denied)?;
            if route
                .pending
                .as_ref()
                .is_some_and(|pending| pending.expires_at > now())
            {
                return Err(unavailable());
            }
            let selection = route.active.as_ref().ok_or_else(denied)?;
            let occurred = chrono::DateTime::parse_from_rfc3339(&incoming.timestamp)
                .map_err(|_| denied())?
                .timestamp();
            if incoming.platform != "whatsapp"
                || incoming.chat_id != incoming.user_id
                || incoming.chat_type != "p2p"
                || occurred <= selection.selected_at
                || occurred > now() + 60
            {
                return Err(denied());
            }
            Ok(selection.clone())
        })
    }

    pub fn check(&self, outbound: &OutboundMessage) -> Result<Selection, GatewayError> {
        let original: Selection = serde_json::from_value(
            outbound
                .metadata
                .get("navi_selection")
                .cloned()
                .ok_or_else(denied)?,
        )
        .map_err(|_| denied())?;
        let route = outbound
            .metadata
            .get("route_key")
            .and_then(Value::as_str)
            .ok_or_else(denied)?;
        self.transaction(|state| {
            let route = state
                .routes
                .get(&key(&outbound.chat_id, route))
                .ok_or_else(denied)?;
            if route
                .pending
                .as_ref()
                .is_some_and(|pending| pending.expires_at > now())
            {
                return Err(unavailable());
            }
            if route.active.as_ref() != Some(&original) {
                return Err(denied());
            }
            Ok(original)
        })
    }
}

impl Selection {
    pub fn session_key(&self, incoming: &InboundMessage) -> String {
        hash(&json!([
            incoming.route_key,
            incoming.chat_id,
            self.hub_id,
            self.generation
        ]))
    }
}

#[cfg(test)]
impl NaviFleet {
    pub(crate) fn activate_for_media_test(
        &self,
        pairing: &InboundMessage,
        identity: &str,
    ) -> Result<Selection, GatewayError> {
        self.begin(pairing)?;
        let pending = self.claim()?.ok_or_else(unavailable)?;
        let now = now();
        self.finish(
            &pending,
            StatusCode::OK,
            &json!({"status":"bound","session_id":"a".repeat(32),
                "binding_id":"a".repeat(32),"confirmed_at":now,"expires_at":now+300}),
            identity,
        )?;
        let mut ordinary = pairing.clone();
        ordinary.text.clear();
        ordinary.timestamp = (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc3339();
        self.select(&ordinary)
    }
}

#[cfg(test)]
#[path = "navi_fleet_tests.rs"]
mod tests;
