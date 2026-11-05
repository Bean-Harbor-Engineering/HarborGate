use serde_json::Value;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub runtime_profile: String,
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub device_session_state_dir: PathBuf,
    pub public_origin: String,
    pub contract_version: String,
    pub service_token: String,
    pub service_token_previous: String,
    pub harborbeacon_base_url: String,
    pub harborbeacon_token: String,
    pub harborbeacon_web_api_token: String,
    pub harborbeacon_turn_endpoint: String,
    pub harbor_workspace_id: String,
    pub cloud_relay_url: String,
    pub cloud_relay_region: String,
    pub feishu: FeishuConfig,
    pub feishu_mail: FeishuMailConfig,
    pub weixin: WeixinConfig,
    pub enable_feishu_websocket: bool,
    pub enable_weixin_runtime: bool,
}

#[derive(Debug, Clone)]
pub struct FeishuConfig {
    pub app_id: String,
    pub app_secret: String,
    pub domain: String,
    pub connection_mode: String,
    pub allowed_users: Vec<String>,
    pub group_policy: String,
    pub bot_open_id: String,
    pub bot_user_id: String,
    pub bot_name: String,
    pub verification_token: String,
    pub webhook_path: String,
    pub base_url: String,
    pub auth_base_url: String,
    pub enable_live_send: bool,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct FeishuMailConfig {
    pub enabled: bool,
    pub sender_mailbox: String,
    pub user_access_token: String,
    pub user_refresh_token: String,
    pub user_token_state_path: String,
    pub default_from_name: String,
    pub app_id: String,
    pub app_secret: String,
    pub base_url: String,
    pub auth_base_url: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct WeixinConfig {
    pub state_dir: PathBuf,
    pub account_id: String,
    pub token: String,
    pub base_url: String,
    pub user_id: String,
    pub cdn_base_url: String,
    pub timeout_seconds: u64,
    pub poll_timeout_ms: u64,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let feishu = FeishuConfig::from_env();
        let feishu_mail = FeishuMailConfig::from_env(&feishu);
        let data_dir = env_or("IM_AGENT_DATA_DIR", "data/sessions");
        let state_dir = env_or_else("IM_AGENT_STATE_DIR", || {
            PathBuf::from(&data_dir)
                .parent()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_else(|| "data".to_string())
        });
        let mut turn_endpoint = env_or("HARBORBEACON_TURN_ENDPOINT", "/api/web/turns");
        if !turn_endpoint.starts_with('/') {
            turn_endpoint = format!("/{turn_endpoint}");
        }
        let base_url = strip_endpoint_suffix(
            &strip_endpoint_suffix(
                &strip_endpoint_suffix(
                    &env_first(&["HARBORBEACON_WEB_API_URL", "HARBORBEACON_TASK_API_URL"]),
                    &turn_endpoint,
                ),
                "/api/web/turns",
            ),
            "/api/turns",
        );
        let device_session_state_dir = env_or_else("HARBORGATE_DEVICE_SESSION_STATE_DIR", || {
            PathBuf::from(&state_dir)
                .join("device-sessions")
                .to_string_lossy()
                .to_string()
        });
        let gate_to_beacon_token = credential_first(
            "HARBOR_GATE_TO_BEACON_TOKEN_FILE",
            "gate-to-beacon-send",
            &["HARBOR_GATE_TO_BEACON_TOKEN", "HARBORBEACON_WEB_API_TOKEN"],
        );
        let runtime_profile = env_or("HARBORGATE_RUNTIME_PROFILE", "standard");
        let harbor_workspace_id =
            workspace_id_for_profile(&runtime_profile, &env_trim("HARBOR_WORKSPACE_ID"));
        Self {
            runtime_profile,
            host: env_or("IM_AGENT_HOST", "127.0.0.1"),
            port: env_or("IM_AGENT_PORT", "8787").parse().unwrap_or(8787),
            data_dir: PathBuf::from(data_dir),
            state_dir: PathBuf::from(state_dir),
            device_session_state_dir: PathBuf::from(device_session_state_dir),
            public_origin: env_trim("IM_AGENT_PUBLIC_ORIGIN"),
            contract_version: env_or("IM_AGENT_CONTRACT_VERSION", "2.0"),
            service_token: credential_first(
                "HARBOR_BEACON_TO_GATE_TOKEN_FILE",
                "beacon-to-gate-accept-current",
                &["HARBOR_BEACON_TO_GATE_TOKEN", "IM_AGENT_SERVICE_TOKEN"],
            ),
            service_token_previous: credential_first(
                "HARBOR_BEACON_TO_GATE_TOKEN_PREVIOUS_FILE",
                "beacon-to-gate-accept-previous",
                &["HARBOR_BEACON_TO_GATE_TOKEN_PREVIOUS"],
            ),
            harborbeacon_base_url: base_url,
            harborbeacon_token: gate_to_beacon_token.clone(),
            harborbeacon_web_api_token: gate_to_beacon_token,
            harborbeacon_turn_endpoint: turn_endpoint,
            harbor_workspace_id,
            cloud_relay_url: env_trim("HARBORCLOUD_RELAY_URL"),
            cloud_relay_region: env_trim("HARBORCLOUD_RELAY_REGION"),
            feishu,
            feishu_mail,
            weixin: WeixinConfig::from_env(),
            enable_feishu_websocket: env_flag_default("HARBORGATE_RUST_FEISHU_WEBSOCKET", true),
            enable_weixin_runtime: env_flag_default("HARBORGATE_WEIXIN_RUNTIME_ENABLED", true),
        }
    }

    pub fn harborbeacon_enabled(&self) -> bool {
        !self.harborbeacon_base_url.trim().is_empty()
    }

    pub fn validate_runtime_profile(&self) -> anyhow::Result<()> {
        match self.runtime_profile.as_str() {
            "standard" => Ok(()),
            "k3" => self.validate_k3_runtime(),
            "nexus" => self.validate_nexus_runtime(),
            _ => anyhow::bail!("HARBORGATE_RUNTIME_PROFILE must be standard, k3 or nexus"),
        }
    }

    pub fn validate_nexus_runtime(&self) -> anyhow::Result<()> {
        let mut expected = self.clone();
        // Credential and loopback rules are shared; Nexus persists on the NAS
        // system volume instead of the N2 Home bootstrap data mount.
        anyhow::ensure!(
            self.state_dir == Path::new("/var/lib/harboros-im-gate"),
            "Nexus state must use /var/lib/harboros-im-gate"
        );
        anyhow::ensure!(
            self.data_dir == self.state_dir.join("sessions"),
            "Nexus sessions must stay in its state directory"
        );
        anyhow::ensure!(
            self.weixin.state_dir == self.state_dir.join("weixin"),
            "Nexus Weixin state must stay in its state directory"
        );
        anyhow::ensure!(
            self.device_session_state_dir == self.state_dir.join("device-sessions"),
            "Nexus device sessions must stay in its state directory"
        );
        anyhow::ensure!(
            self.feishu_mail.user_token_state_path
                == "/var/lib/harboros-im-gate/feishu-mail-token.json",
            "Nexus mail token state must stay in its state directory"
        );
        expected.state_dir = "/data/harborgate".into();
        expected.data_dir = "/data/harborgate/sessions".into();
        expected.weixin.state_dir = "/data/harborgate/weixin".into();
        expected.device_session_state_dir = "/data/harborgate/device-sessions".into();
        expected.feishu_mail.user_token_state_path =
            "/data/harborgate/feishu-mail-token.json".into();
        expected.validate_k3_runtime()
    }

    pub fn validate_k3_runtime(&self) -> anyhow::Result<()> {
        let host: IpAddr = self
            .host
            .parse()
            .map_err(|_| anyhow::anyhow!("IM_AGENT_HOST must be a numeric loopback address"))?;
        anyhow::ensure!(host.is_loopback(), "IM_AGENT_HOST must be loopback-only");
        anyhow::ensure!(self.port == 8787, "IM_AGENT_PORT must be 8787");
        anyhow::ensure!(
            self.contract_version == "2.0",
            "IM_AGENT_CONTRACT_VERSION must be 2.0"
        );
        anyhow::ensure!(
            self.data_dir == Path::new("/data/harborgate/sessions"),
            "IM_AGENT_DATA_DIR must be /data/harborgate/sessions"
        );
        anyhow::ensure!(
            self.state_dir == Path::new("/data/harborgate"),
            "IM_AGENT_STATE_DIR must be /data/harborgate"
        );
        anyhow::ensure!(
            self.device_session_state_dir == Path::new("/data/harborgate/device-sessions"),
            "HARBORGATE_DEVICE_SESSION_STATE_DIR must be /data/harborgate/device-sessions"
        );
        anyhow::ensure!(
            self.weixin.state_dir == Path::new("/data/harborgate/weixin"),
            "WEIXIN_STATE_DIR must be /data/harborgate/weixin"
        );
        anyhow::ensure!(
            self.feishu_mail.user_token_state_path == "/data/harborgate/feishu-mail-token.json",
            "FEISHU_MAIL_TOKEN_STATE_PATH must be /data/harborgate/feishu-mail-token.json"
        );
        anyhow::ensure!(
            self.harborbeacon_base_url == "http://127.0.0.1:4174",
            "HARBORBEACON_WEB_API_URL must use the K3 loopback endpoint"
        );
        anyhow::ensure!(
            self.harborbeacon_turn_endpoint == "/api/web/turns",
            "HARBORBEACON_TURN_ENDPOINT must be /api/web/turns"
        );
        anyhow::ensure!(
            valid_home_id(&self.harbor_workspace_id),
            "HARBOR_WORKSPACE_ID must contain the authoritative Home ID"
        );
        anyhow::ensure!(
            is_lower_hex_credential(&self.service_token),
            "IM_AGENT_SERVICE_TOKEN must be a 32-byte lowercase hex credential"
        );
        anyhow::ensure!(
            is_lower_hex_credential(&self.harborbeacon_web_api_token),
            "HARBORBEACON_WEB_API_TOKEN must be a 32-byte lowercase hex credential"
        );
        anyhow::ensure!(
            self.harborbeacon_token == self.harborbeacon_web_api_token,
            "HarborBeacon v2 transport must use the Web API bearer"
        );
        anyhow::ensure!(
            self.service_token != self.harborbeacon_web_api_token,
            "Gate ingress and Beacon upstream credentials must be distinct"
        );
        Ok(())
    }
}

fn is_lower_hex_credential(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_home_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'@' | b'-')
        })
}

fn workspace_id_for_profile(runtime_profile: &str, configured: &str) -> String {
    if configured.is_empty() && runtime_profile != "k3" {
        "home-1".to_string()
    } else {
        configured.to_string()
    }
}

impl WeixinConfig {
    pub const ILINK_BASE_URL: &'static str = "https://ilinkai.weixin.qq.com";
    pub const DEFAULT_CDN_BASE_URL: &'static str = "https://novac2c.cdn.weixin.qq.com/c2c";

    pub fn from_env() -> Self {
        Self {
            state_dir: PathBuf::from(env_or("WEIXIN_STATE_DIR", "data/weixin")),
            account_id: env_trim("WEIXIN_ACCOUNT_ID"),
            token: env_trim("WEIXIN_BOT_TOKEN"),
            base_url: env_or("WEIXIN_BASE_URL", Self::ILINK_BASE_URL),
            user_id: env_trim("WEIXIN_USER_ID"),
            cdn_base_url: env_or("WEIXIN_CDN_BASE_URL", Self::DEFAULT_CDN_BASE_URL),
            timeout_seconds: env_or("WEIXIN_TIMEOUT_SECONDS", "45").parse().unwrap_or(45),
            poll_timeout_ms: env_or("WEIXIN_POLL_TIMEOUT_MS", "35000")
                .parse()
                .unwrap_or(35000),
        }
    }
}

impl FeishuConfig {
    pub fn from_env() -> Self {
        let connection_mode_env = env_trim("FEISHU_CONNECTION_MODE");
        let enable_live_send_env = env_present("FEISHU_ENABLE_LIVE_SEND");
        let mut config = Self {
            app_id: env_trim("FEISHU_APP_ID"),
            app_secret: env_trim("FEISHU_APP_SECRET"),
            domain: env_or("FEISHU_DOMAIN", "feishu").to_lowercase(),
            connection_mode: if connection_mode_env.is_empty() {
                "websocket".to_string()
            } else {
                connection_mode_env.to_lowercase()
            },
            allowed_users: env_trim("FEISHU_ALLOWED_USERS")
                .split(',')
                .filter_map(|item| {
                    let item = item.trim();
                    (!item.is_empty()).then(|| item.to_string())
                })
                .collect(),
            group_policy: env_or("FEISHU_GROUP_POLICY", "allowlist").to_lowercase(),
            bot_open_id: env_trim("FEISHU_BOT_OPEN_ID"),
            bot_user_id: env_trim("FEISHU_BOT_USER_ID"),
            bot_name: env_trim("FEISHU_BOT_NAME"),
            verification_token: env_trim("FEISHU_VERIFICATION_TOKEN"),
            webhook_path: env_or("FEISHU_WEBHOOK_PATH", "/feishu/webhook"),
            base_url: env_or("FEISHU_BASE_URL", "https://open.feishu.cn"),
            auth_base_url: env_or("FEISHU_AUTH_BASE_URL", "https://open.feishu.cn"),
            enable_live_send: env_flag("FEISHU_ENABLE_LIVE_SEND"),
            timeout_seconds: env_or("FEISHU_TIMEOUT_SECONDS", "20").parse().unwrap_or(20),
        };
        for path in setup_portal_candidates() {
            if config.apply_setup_portal_file(
                &path,
                !connection_mode_env.is_empty(),
                enable_live_send_env,
            ) {
                break;
            }
        }
        config
    }

    pub fn configured(&self) -> bool {
        !self.app_id.is_empty() && !self.app_secret.is_empty()
    }

    fn apply_setup_portal_file(
        &mut self,
        path: &Path,
        connection_mode_is_env: bool,
        enable_live_send_is_env: bool,
    ) -> bool {
        let Ok(raw) = fs::read_to_string(path) else {
            return false;
        };
        let Ok(payload) = serde_json::from_str::<Value>(&raw) else {
            return false;
        };
        let Some(feishu) = setup_portal_feishu(&payload) else {
            return false;
        };
        fill_text_if_empty(&mut self.app_id, feishu, "app_id");
        fill_text_if_empty(&mut self.app_secret, feishu, "app_secret");
        fill_text_if_empty(&mut self.bot_open_id, feishu, "bot_open_id");
        fill_text_if_empty(&mut self.bot_user_id, feishu, "bot_user_id");
        fill_text_if_empty(&mut self.bot_name, feishu, "bot_name");
        fill_text_if_empty(&mut self.bot_name, feishu, "app_name");
        fill_text_if_empty(&mut self.verification_token, feishu, "verification_token");
        if !connection_mode_is_env {
            if let Some(connection_mode) = text_field(feishu, "connection_mode") {
                self.connection_mode = connection_mode.to_lowercase();
            }
        }
        if !enable_live_send_is_env {
            if let Some(enable_live_send) = bool_field(feishu, "enable_live_send") {
                self.enable_live_send = enable_live_send;
            }
        }
        true
    }
}

impl FeishuMailConfig {
    pub fn from_env(feishu: &FeishuConfig) -> Self {
        Self {
            enabled: env_flag("FEISHU_MAIL_ENABLED"),
            sender_mailbox: env_trim("FEISHU_MAIL_SENDER_MAILBOX"),
            user_access_token: env_trim("FEISHU_MAIL_USER_ACCESS_TOKEN"),
            user_refresh_token: env_trim("FEISHU_MAIL_USER_REFRESH_TOKEN"),
            user_token_state_path: env_trim("FEISHU_MAIL_TOKEN_STATE_PATH"),
            default_from_name: env_trim("FEISHU_MAIL_DEFAULT_FROM_NAME"),
            app_id: env_or_else("FEISHU_MAIL_APP_ID", || feishu.app_id.clone()),
            app_secret: env_or_else("FEISHU_MAIL_APP_SECRET", || feishu.app_secret.clone()),
            base_url: env_or_else("FEISHU_MAIL_BASE_URL", || feishu.base_url.clone()),
            auth_base_url: env_or_else("FEISHU_MAIL_AUTH_BASE_URL", || {
                feishu.auth_base_url.clone()
            }),
            timeout_seconds: env_or(
                "FEISHU_MAIL_TIMEOUT_SECONDS",
                &feishu.timeout_seconds.to_string(),
            )
            .parse()
            .unwrap_or(feishu.timeout_seconds),
        }
    }

    pub fn configured(&self) -> bool {
        let app_credentials_configured =
            !self.app_id.trim().is_empty() && !self.app_secret.trim().is_empty();
        let refresh_configured = (!self.user_refresh_token.trim().is_empty()
            || !self.user_token_state_path.trim().is_empty())
            && app_credentials_configured;
        self.enabled
            && !self.sender_mailbox.trim().is_empty()
            && (!self.user_access_token.trim().is_empty()
                || refresh_configured
                || app_credentials_configured)
    }

    pub fn auth_mode(&self) -> &'static str {
        if !self.user_refresh_token.trim().is_empty()
            || !self.user_token_state_path.trim().is_empty()
        {
            "user_refresh_token"
        } else if !self.user_access_token.trim().is_empty() {
            "user_access_token"
        } else if !self.app_id.trim().is_empty() && !self.app_secret.trim().is_empty() {
            "tenant_access_token"
        } else {
            "unconfigured"
        }
    }
}

pub fn env_flag(key: &str) -> bool {
    matches!(
        env_trim(key).to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn env_flag_default(key: &str, default_value: bool) -> bool {
    let value = env_trim(key);
    if value.is_empty() {
        default_value
    } else {
        matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on")
    }
}

fn env_trim(key: &str) -> String {
    env::var(key).unwrap_or_default().trim().to_string()
}

fn env_present(key: &str) -> bool {
    env::var_os(key).is_some()
}

fn env_or(key: &str, default_value: &str) -> String {
    let value = env_trim(key);
    if value.is_empty() {
        default_value.to_string()
    } else {
        value
    }
}

fn env_or_else(key: &str, default_value: impl FnOnce() -> String) -> String {
    let value = env_trim(key);
    if value.is_empty() {
        default_value()
    } else {
        value
    }
}

fn env_first(keys: &[&str]) -> String {
    for key in keys {
        let value = env_trim(key);
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

fn credential_first(file_env: &str, credential_name: &str, env_keys: &[&str]) -> String {
    if let Some(file_path) = credential_file_path(file_env, credential_name) {
        return fs::read_to_string(file_path)
            .ok()
            .map(|value| value.trim().to_string())
            .unwrap_or_default();
    }
    env_first(env_keys)
}

fn credential_file_path(file_env: &str, credential_name: &str) -> Option<PathBuf> {
    credential_file_path_from_values(
        &env_trim("CREDENTIALS_DIRECTORY"),
        &env_trim(file_env),
        credential_name,
    )
}

fn credential_file_path_from_values(
    credentials_directory: &str,
    configured_file: &str,
    credential_name: &str,
) -> Option<PathBuf> {
    if !credentials_directory.is_empty() {
        return Some(PathBuf::from(credentials_directory).join(credential_name));
    }
    (!configured_file.is_empty()).then(|| PathBuf::from(configured_file))
}

fn strip_endpoint_suffix(base_url: &str, endpoint_suffix: &str) -> String {
    let normalized = base_url.trim().trim_end_matches('/').to_string();
    if normalized.is_empty() {
        return normalized;
    }
    let suffix = endpoint_suffix.trim_end_matches('/');
    if normalized.ends_with(suffix) {
        normalized[..normalized.len() - suffix.len()]
            .trim_end_matches('/')
            .to_string()
    } else {
        normalized
    }
}

fn setup_portal_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    push_candidate(&mut paths, env_trim("FEISHU_SETUP_PORTAL_PATH"));
    let state_dir = env_trim("IM_AGENT_STATE_DIR");
    if !state_dir.is_empty() {
        push_candidate(
            &mut paths,
            PathBuf::from(state_dir)
                .join("_setup_portal.json")
                .to_string_lossy()
                .to_string(),
        );
    }
    let data_dir = env_trim("IM_AGENT_DATA_DIR");
    if !data_dir.is_empty() {
        let data_path = PathBuf::from(data_dir);
        if let Some(parent) = data_path.parent() {
            push_candidate(
                &mut paths,
                parent
                    .join("_setup_portal.json")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    paths
}

fn push_candidate(paths: &mut Vec<PathBuf>, raw: String) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    let path = PathBuf::from(trimmed);
    if !paths.iter().any(|item| item == &path) {
        paths.push(path);
    }
}

fn setup_portal_feishu(payload: &Value) -> Option<&Value> {
    payload
        .get("feishu")
        .or_else(|| payload.pointer("/platforms/feishu"))
        .or_else(|| payload.pointer("/setup/feishu"))
}

fn fill_text_if_empty(field: &mut String, object: &Value, key: &str) {
    if field.trim().is_empty() {
        if let Some(value) = text_field(object, key) {
            *field = value;
        }
    }
}

fn text_field(object: &Value, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn bool_field(object: &Value, key: &str) -> Option<bool> {
    match object.get(key)? {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn empty_feishu_config() -> FeishuConfig {
        FeishuConfig {
            app_id: String::new(),
            app_secret: String::new(),
            domain: "feishu".into(),
            connection_mode: "websocket".into(),
            allowed_users: vec![],
            group_policy: "allowlist".into(),
            bot_open_id: String::new(),
            bot_user_id: String::new(),
            bot_name: String::new(),
            verification_token: String::new(),
            webhook_path: "/feishu/webhook".into(),
            base_url: "https://open.feishu.cn".into(),
            auth_base_url: "https://open.feishu.cn".into(),
            enable_live_send: false,
            timeout_seconds: 20,
        }
    }

    fn valid_k3_config() -> AppConfig {
        let mut config = AppConfig::from_env();
        config.runtime_profile = "k3".into();
        config.host = "127.0.0.1".into();
        config.port = 8787;
        config.contract_version = "2.0".into();
        config.data_dir = PathBuf::from("/data/harborgate/sessions");
        config.state_dir = PathBuf::from("/data/harborgate");
        config.device_session_state_dir = PathBuf::from("/data/harborgate/device-sessions");
        config.weixin.state_dir = PathBuf::from("/data/harborgate/weixin");
        config.feishu_mail.user_token_state_path = "/data/harborgate/feishu-mail-token.json".into();
        config.harborbeacon_base_url = "http://127.0.0.1:4174".into();
        config.harborbeacon_turn_endpoint = "/api/web/turns".into();
        config.service_token = "a".repeat(64);
        config.harborbeacon_token = "b".repeat(64);
        config.harborbeacon_web_api_token = "b".repeat(64);
        config
    }

    #[test]
    fn nexus_runtime_uses_nas_state_without_changing_n2_paths() {
        let mut config = valid_k3_config();
        config.runtime_profile = "nexus".into();
        config.state_dir = "/var/lib/harboros-im-gate".into();
        config.data_dir = "/var/lib/harboros-im-gate/sessions".into();
        config.weixin.state_dir = "/var/lib/harboros-im-gate/weixin".into();
        config.device_session_state_dir = "/var/lib/harboros-im-gate/device-sessions".into();
        config.feishu_mail.user_token_state_path =
            "/var/lib/harboros-im-gate/feishu-mail-token.json".into();
        assert!(config.validate_runtime_profile().is_ok());
        config.state_dir = "/data/harborgate".into();
        assert!(config.validate_runtime_profile().is_err());
    }

    #[test]
    fn runtime_profile_preserves_standard_paths_and_enforces_k3_paths() {
        let mut config = valid_k3_config();
        assert!(config.validate_runtime_profile().is_ok());
        config.state_dir = PathBuf::from("/var/lib/harboros-im-gate");
        assert!(config.validate_runtime_profile().is_err());
        config.runtime_profile = "standard".into();
        assert!(config.validate_runtime_profile().is_ok());
        config.runtime_profile = "unknown".into();
        assert!(config.validate_runtime_profile().is_err());
    }

    #[test]
    fn k3_runtime_config_accepts_only_the_product_boundary() {
        assert!(valid_k3_config().validate_k3_runtime().is_ok());
        assert_eq!(workspace_id_for_profile("k3", ""), "");
        assert_eq!(workspace_id_for_profile("standard", ""), "home-1");
        assert_eq!(workspace_id_for_profile("k3", "home-173"), "home-173");

        let mut config = valid_k3_config();
        config.harbor_workspace_id = "home-non-default".into();
        assert!(config.validate_k3_runtime().is_ok());

        for invalid_home in ["", " home-1", "other/home", "a".repeat(129).as_str()] {
            let mut config = valid_k3_config();
            config.harbor_workspace_id = invalid_home.into();
            assert!(config.validate_k3_runtime().is_err());
        }

        let mut config = valid_k3_config();
        config.host = "0.0.0.0".into();
        assert!(config.validate_k3_runtime().is_err());

        let mut config = valid_k3_config();
        config.contract_version = "3.0".into();
        assert!(config.validate_k3_runtime().is_err());

        let mut config = valid_k3_config();
        config.state_dir = PathBuf::from("/data/harboros/harborgate");
        assert!(config.validate_k3_runtime().is_err());

        let mut config = valid_k3_config();
        config.device_session_state_dir =
            PathBuf::from("/var/lib/harboros-im-gate/device-sessions");
        assert!(config.validate_k3_runtime().is_err());

        let mut config = valid_k3_config();
        config.service_token.clear();
        assert!(config.validate_k3_runtime().is_err());

        let mut config = valid_k3_config();
        config.harborbeacon_web_api_token = config.service_token.clone();
        config.harborbeacon_token = config.service_token.clone();
        assert!(config.validate_k3_runtime().is_err());
    }

    #[test]
    fn systemd_credentials_directory_takes_precedence_over_configured_file() {
        assert_eq!(
            credential_file_path_from_values(
                "/run/credentials/harboros-im-gate.service",
                "/tmp/explicit-token",
                "gate-to-beacon-send",
            ),
            Some(PathBuf::from(
                "/run/credentials/harboros-im-gate.service/gate-to-beacon-send",
            ))
        );
        assert_eq!(
            credential_file_path_from_values("", "/tmp/explicit-token", "unused"),
            Some(PathBuf::from("/tmp/explicit-token"))
        );
        assert_eq!(credential_file_path_from_values("", "", "unused"), None);
    }

    #[test]
    fn setup_portal_fills_feishu_config_when_env_is_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("_setup_portal.json");
        fs::write(
            &path,
            json!({
                "feishu": {
                    "app_id": "cli_live",
                    "app_secret": "secret_live",
                    "app_name": "harbor-beacon",
                    "connection_mode": "webhook",
                    "enable_live_send": true,
                    "verification_token": "verify_live"
                }
            })
            .to_string(),
        )
        .unwrap();

        let mut config = empty_feishu_config();
        assert!(config.apply_setup_portal_file(&path, false, false));

        assert_eq!(config.app_id, "cli_live");
        assert_eq!(config.app_secret, "secret_live");
        assert_eq!(config.bot_name, "harbor-beacon");
        assert_eq!(config.connection_mode, "webhook");
        assert!(config.enable_live_send);
        assert_eq!(config.verification_token, "verify_live");
    }

    #[test]
    fn setup_portal_does_not_override_explicit_env_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("_setup_portal.json");
        fs::write(
            &path,
            json!({
                "feishu": {
                    "app_id": "cli_portal",
                    "app_secret": "secret_portal",
                    "connection_mode": "webhook",
                    "enable_live_send": true
                }
            })
            .to_string(),
        )
        .unwrap();

        let mut config = empty_feishu_config();
        config.app_id = "cli_env".into();
        config.app_secret = "secret_env".into();
        config.connection_mode = "websocket".into();
        config.enable_live_send = false;

        assert!(config.apply_setup_portal_file(&path, true, true));

        assert_eq!(config.app_id, "cli_env");
        assert_eq!(config.app_secret, "secret_env");
        assert_eq!(config.connection_mode, "websocket");
        assert!(!config.enable_live_send);
    }
}
