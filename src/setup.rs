use crate::adapters::weixin::WeixinAccount;
use crate::adapters::PlatformAdapter;
use crate::config::{AppConfig, FeishuConfig, WeixinConfig};
use crate::error::GatewayError;
use crate::gateway::GatewayService;
use crate::models::utc_now_iso;
use axum::http::StatusCode;
use qrcodegen::{QrCode, QrCodeEcc};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const SETUP_STATE_FILE: &str = "_setup_portal.json";
const WEIXIN_QR_TTL_SECONDS: u64 = 480;

pub struct SetupPortalStore {
    root: PathBuf,
    path: PathBuf,
    lock: Mutex<()>,
}

pub struct SetupPortalService {
    config: AppConfig,
    gateway: Arc<GatewayService>,
    store: SetupPortalStore,
    http: reqwest::Client,
}

impl SetupPortalStore {
    pub fn new(root: PathBuf) -> Self {
        let path = root.join(SETUP_STATE_FILE);
        Self {
            root,
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn load_state(&self) -> Result<Value, GatewayError> {
        let _guard = self.lock.lock().expect("setup store lock poisoned");
        self.load_state_unlocked()
    }

    pub fn current_session_code(&self) -> Result<String, GatewayError> {
        Ok(self
            .load_state()?
            .get("session_code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string())
    }

    pub fn save_feishu_state(&self, feishu: Value) -> Result<Value, GatewayError> {
        let _guard = self.lock.lock().expect("setup store lock poisoned");
        let mut state = self.load_state_unlocked()?;
        state["feishu"] = feishu;
        state["updated_at"] = json!(utc_now_iso());
        self.write_state_unlocked(&state)?;
        Ok(state["feishu"].clone())
    }

    pub fn load_weixin_login_state(&self) -> Result<Value, GatewayError> {
        Ok(self
            .load_state()?
            .get("weixin_login")
            .cloned()
            .unwrap_or_else(|| json!({})))
    }

    pub fn save_weixin_login_state(&self, login: Value) -> Result<Value, GatewayError> {
        let _guard = self.lock.lock().expect("setup store lock poisoned");
        let mut state = self.load_state_unlocked()?;
        state["weixin_login"] = login;
        state["updated_at"] = json!(utc_now_iso());
        self.write_state_unlocked(&state)?;
        Ok(state["weixin_login"].clone())
    }

    fn load_state_unlocked(&self) -> Result<Value, GatewayError> {
        fs::create_dir_all(&self.root)?;
        let payload = if self.path.exists() {
            serde_json::from_str::<Value>(&fs::read_to_string(&self.path)?)?
        } else {
            json!({})
        };
        let state = self.bootstrap_state(payload);
        self.write_state_unlocked(&state)?;
        Ok(state)
    }

    fn write_state_unlocked(&self, payload: &Value) -> Result<(), GatewayError> {
        fs::create_dir_all(&self.root)?;
        fs::write(&self.path, serde_json::to_string_pretty(payload)?)?;
        Ok(())
    }

    fn bootstrap_state(&self, payload: Value) -> Value {
        let mut object = payload.as_object().cloned().unwrap_or_default();
        let session = object
            .get("session_code")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_uppercase)
            .unwrap_or_else(generate_session_code);
        object.insert("session_code".into(), json!(session));
        if !object.get("feishu").is_some_and(Value::is_object) {
            object.insert("feishu".into(), json!({}));
        }
        if !object.get("weixin_login").is_some_and(Value::is_object) {
            object.insert("weixin_login".into(), json!({}));
        }
        object.entry("updated_at").or_insert_with(|| json!(""));
        Value::Object(object)
    }
}

impl SetupPortalService {
    pub fn new(config: AppConfig, gateway: Arc<GatewayService>) -> Self {
        let store = SetupPortalStore::new(config.state_dir.clone());
        Self {
            config,
            gateway,
            store,
            http: reqwest::Client::new(),
        }
    }

    pub fn status_payload(&self, request_host: &str) -> Value {
        self.status_payload_with_prefix(request_host, "")
    }

    pub fn status_payload_with_prefix(&self, request_host: &str, route_prefix: &str) -> Value {
        let state = self.store.load_state().unwrap_or_else(|_| json!({}));
        let session = state
            .get("session_code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let origin = self.resolve_public_origin(request_host);
        let prefix = normalized_route_prefix(route_prefix);
        let setup_url = format!(
            "{origin}{}?session={}",
            prefixed_path(&prefix, "/setup"),
            urlencoding::encode(&session)
        );
        let feishu_setup_url = format!(
            "{origin}{}?session={}",
            prefixed_path(&prefix, "/setup/feishu"),
            urlencoding::encode(&session)
        );
        let weixin_setup_url = format!("{origin}{}", prefixed_path(&prefix, "/setup/weixin"));
        let gateway_status = self.gateway.status();
        let feishu = self.feishu_status(&state, &origin, &feishu_setup_url, &prefix);
        let weixin = self.weixin_status(&state, &origin, &weixin_setup_url, &prefix);
        json!({
            "runtime": "rust",
            "session_code": session,
            "setup_url": setup_url,
            "static_setup_url": format!("{origin}{}", prefixed_path(&prefix, "/setup")),
            "qr_page_url": format!("{origin}{}", prefixed_path(&prefix, "/setup/qr")),
            "qr_svg_url": format!("{origin}{}", prefixed_path(&prefix, "/setup/qr.svg")),
            "mobile_reachable": !looks_like_loopback(&origin),
            "feishu": feishu,
            "weixin": weixin,
            "connectors": {
                "feishu": feishu,
                "weixin": weixin,
            },
            "channels": [
                self.channel_summary("feishu", "Feishu", &feishu),
                self.channel_summary("weixin", "Weixin", &weixin),
            ],
            "gateway_status": gateway_status,
        })
    }

    pub fn gateway_status_payload(&self, request_host: &str) -> Value {
        self.gateway_status_payload_with_prefix(request_host, "")
    }

    pub fn gateway_status_payload_with_prefix(
        &self,
        request_host: &str,
        route_prefix: &str,
    ) -> Value {
        let mut payload = self.gateway.status();
        let setup = self.status_payload_with_prefix(request_host, route_prefix);
        payload["setup"] = setup.clone();
        payload["feishu"] = setup["feishu"].clone();
        payload["weixin"] = setup["weixin"].clone();
        payload["channels"] = setup["channels"].clone();
        payload["setup_url"] = setup["setup_url"].clone();
        payload["static_setup_url"] = setup["static_setup_url"].clone();
        payload["qr_page_url"] = setup["qr_page_url"].clone();
        payload["qr_svg_url"] = setup["qr_svg_url"].clone();
        payload
    }

    pub fn build_feishu_setup_page(&self, request_host: &str) -> String {
        self.build_feishu_setup_page_with_prefix(request_host, "")
    }

    pub fn build_feishu_setup_page_with_prefix(
        &self,
        request_host: &str,
        route_prefix: &str,
    ) -> String {
        if self.config.runtime_profile == "nexus" {
            return portal_document(
                "消息连接",
                r#"<section class="card stack"><h1>消息连接</h1><p>请在 HarborOS 中管理连接。</p><a href="/ui/harbor-assistant?tab=messages">打开 Harbor Assistant</a></section>"#,
                true,
            );
        }
        let prefix = normalized_route_prefix(route_prefix);
        let status = self.status_payload_with_prefix(request_host, &prefix);
        let feishu = &status["feishu"];
        let configured = feishu["configured"].as_bool().unwrap_or(false);
        let connected = feishu["connected"].as_bool().unwrap_or(false);
        let state_label = customer_status_label(
            feishu["status"].as_str().unwrap_or(""),
            configured,
            connected,
        );
        let credential_label = if configured { "已配置" } else { "待配置" };
        let problem = if feishu["last_error"]
            .as_str()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            String::new()
        } else {
            r#"<div class="notice danger">飞书连接暂时不可用，请检查应用配置后重试。</div>"#.into()
        };
        let configure_url = prefixed_path(&prefix, "/api/setup/feishu/configure");
        let body = format!(
            r#"
    <section class="card stack">
      <header class="native-header">
        <div>
          <h1>飞书</h1>
          <p>消息连接</p>
        </div>
        <span class="badge {state_badge}">{state_label}</span>
      </header>
      {problem}
      <div class="summary">
        <div class="row"><span class="label">连接状态</span><span class="badge {state_badge}">{state_label}</span></div>
        <div class="row"><span class="label">配置状态</span><span class="badge {credential_badge}">{credential_label}</span></div>
        <div class="row"><span class="label">接收方式</span><span class="value">{mode}</span></div>
        <div class="row"><span class="label">应用名称</span><span class="value">{name}</span></div>
        <div class="row"><span class="label">App ID</span><span class="value">{app_id}</span></div>
      </div>
      <div class="form-panel">
        <label for="app-id">App ID</label>
        <input id="app-id" type="text" placeholder="cli_xxx" autocomplete="off" />
        <label for="app-secret">App Secret</label>
        <input id="app-secret" type="password" placeholder="输入飞书应用密钥" autocomplete="off" />
        <label for="verification-token">Verification Token（可选）</label>
        <input id="verification-token" type="text" placeholder="如未启用回调可留空" autocomplete="off" />
        <div class="actions"><button id="submit-btn" class="primary" type="button">保存飞书连接</button></div>
        <p id="result" class="hint" style="margin-top:12px;"></p>
      </div>
    </section>
  <script>
    document.getElementById('submit-btn').addEventListener('click', async () => {{
      const result = document.getElementById('result');
      result.className = 'hint';
      result.textContent = '正在保存飞书连接...';
      const payload = {{
        session_code: {session_json},
        app_id: document.getElementById('app-id').value.trim(),
        app_secret: document.getElementById('app-secret').value.trim(),
        verification_token: document.getElementById('verification-token').value.trim()
      }};
      try {{
        const response = await fetch('{configure_url}', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload)
        }});
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || '配置失败');
        result.className = 'hint ok';
        result.textContent = '飞书连接已保存。';
      }} catch (error) {{
        result.className = 'hint err';
        result.textContent = '保存失败，请检查 App ID 和 App Secret 后重试。';
      }}
    }});
  </script>
"#,
            state_badge = badge_class(&state_label),
            credential_badge = badge_class(credential_label),
            state_label = html_escape(&state_label),
            credential_label = html_escape(credential_label),
            mode = html_escape(connection_mode_label(
                feishu["connection_mode"].as_str().unwrap_or("websocket")
            )),
            name = html_escape(feishu["display_name"].as_str().unwrap_or("未设置")),
            app_id = html_escape(feishu["app_id_masked"].as_str().unwrap_or("未设置")),
            session_json = serde_json::to_string(status["session_code"].as_str().unwrap_or(""))
                .unwrap_or_else(|_| "\"\"".into()),
            configure_url = configure_url
        );
        portal_document("飞书连接", &body, false)
    }

    pub fn build_weixin_setup_page(&self, request_host: &str, unbound: bool) -> String {
        self.build_weixin_setup_page_with_prefix(request_host, unbound, "")
    }

    pub fn build_weixin_setup_page_with_prefix(
        &self,
        request_host: &str,
        unbound: bool,
        route_prefix: &str,
    ) -> String {
        if self.config.runtime_profile == "nexus" {
            return portal_document(
                "消息连接",
                r#"<section class="card stack"><h1>消息连接</h1><p>请在 HarborOS 中管理连接。</p><a href="/ui/harbor-assistant?tab=messages">打开 Harbor Assistant</a></section>"#,
                true,
            );
        }
        let prefix = normalized_route_prefix(route_prefix);
        let status = self.status_payload_with_prefix(request_host, &prefix);
        let weixin = &status["weixin"];
        let configured = weixin["configured"].as_bool().unwrap_or(false);
        let connected = weixin["connected"].as_bool().unwrap_or(false);
        let state_label = customer_status_label(
            weixin["status"].as_str().unwrap_or(""),
            configured,
            connected,
        );
        let binding_label = if configured { "已绑定" } else { "待绑定" };
        let notice = if unbound {
            r#"<div class="notice good">已解绑。请重新扫码绑定微信。</div>"#.to_string()
        } else if configured {
            r#"<div class="notice good">已绑定。</div>"#.to_string()
        } else {
            String::new()
        };
        let login_state_json =
            serde_json::to_string(&weixin["login"]).unwrap_or_else(|_| "{}".into());
        let unbind_disabled = if configured { "" } else { " disabled" };
        let login_hint = if configured {
            "需要更换账号时，重新扫码即可。"
        } else {
            "点击后使用微信扫码完成绑定。"
        };
        let login_button = if configured {
            "重新绑定微信"
        } else {
            "绑定微信"
        };
        let unbind_url = prefixed_path(&prefix, "/api/setup/weixin/unbind");
        let qr_svg_url = prefixed_path(&prefix, "/setup/weixin/qr.svg");
        let login_status_url = prefixed_path(&prefix, "/api/setup/weixin/login/status");
        let login_start_url = prefixed_path(&prefix, "/api/setup/weixin/login/start");
        let body = format!(
            r#"
    <section class="card stack">
      <header class="native-header">
        <div>
          <h1>微信</h1>
          <p>消息连接</p>
        </div>
        <span class="badge {state_badge}">{state_label}</span>
      </header>
      {notice}
      <div class="summary">
        <div class="row"><span class="label">绑定状态</span><span class="badge {binding_badge}">{binding_label}</span></div>
        <div class="row"><span class="label">连接状态</span><span class="badge {state_badge}">{state_label}</span></div>
        <div class="row"><span class="label">账号</span><span class="value">{account}</span></div>
      </div>
      <div class="form-panel">
        <h2>扫码绑定</h2>
        <p>{login_hint}</p>
        <div class="actions"><button id="weixin-login-start" class="primary" type="button">{login_button}</button></div>
        <div id="weixin-login-status" class="hint" style="margin-top:10px;"></div>
        <img id="weixin-login-qr" class="login-qr" src="" alt="微信登录二维码" />
      </div>
      <form method="post" action="{unbind_url}" onsubmit="return confirm('确认解绑微信？解绑后需要重新扫码。');">
        <div class="actions"><button class="danger" type="submit"{unbind_disabled}>解绑微信</button></div>
      </form>
    </section>
  <script>
    const initialLogin = {login_state_json};
    const startButton = document.getElementById('weixin-login-start');
    const statusEl = document.getElementById('weixin-login-status');
    const qrEl = document.getElementById('weixin-login-qr');
    let pollTimer = null;
    function statusText(status) {{
      const labels = {{not_started:'准备中', wait:'等待扫码', scaned:'已扫码，等待确认', scaned_but_redirect:'已扫码，正在确认', confirmed:'已绑定', expired:'二维码已过期', error:'二维码暂时不可用'}};
      return labels[status] || '准备中';
    }}
    function renderLogin(data) {{
      const login = data.weixin_login || data || {{}};
      const status = login.status || 'not_started';
      const expires = Number(login.expires_in_seconds || 0);
      const suffix = expires > 0 && ['wait','scaned','scaned_but_redirect'].includes(status) ? `，剩余约 ${{expires}} 秒` : '';
      statusEl.className = status === 'error' || status === 'expired' ? 'hint err' : 'hint';
      statusEl.textContent = `扫码状态：${{statusText(status)}}${{suffix}}`;
      if (login.qrcode_available) {{
        qrEl.style.display = 'block';
        qrEl.src = `{qr_svg_url}?ts=${{Date.now()}}`;
      }} else {{
        qrEl.style.display = 'none';
        qrEl.removeAttribute('src');
      }}
      if (status === 'confirmed') {{
        statusEl.className = 'hint ok';
        statusEl.textContent = '微信绑定完成，页面即将刷新。';
        window.setTimeout(() => window.location.reload(), 1200);
      }}
    }}
    async function pollLogin() {{
      window.clearTimeout(pollTimer);
      const response = await fetch('{login_status_url}');
      const data = await response.json();
      renderLogin(data);
      const status = (data.weixin_login || {{}}).status || '';
      if (['wait','scaned','scaned_but_redirect','error'].includes(status)) {{
        pollTimer = window.setTimeout(pollLogin, 2000);
      }}
    }}
    startButton.addEventListener('click', async () => {{
      startButton.disabled = true;
      statusEl.className = 'hint';
      statusEl.textContent = '正在生成二维码...';
      try {{
        const response = await fetch('{login_start_url}', {{ method: 'POST' }});
        const data = await response.json();
        renderLogin(data);
        if (!response.ok || !data.ok) throw new Error(data.message || '生成二维码失败');
        pollTimer = window.setTimeout(pollLogin, 1500);
      }} catch (error) {{
        statusEl.className = 'hint err';
        statusEl.textContent = '二维码暂时不可用，请稍后重试。';
      }} finally {{
        startButton.disabled = false;
      }}
    }});
    if (initialLogin && initialLogin.qrcode_available && ['wait','scaned','scaned_but_redirect'].includes(initialLogin.status)) {{
      renderLogin(initialLogin);
      pollTimer = window.setTimeout(pollLogin, 1500);
    }}
  </script>
"#,
            notice = notice,
            binding_badge = badge_class(binding_label),
            state_badge = badge_class(&state_label),
            binding_label = html_escape(binding_label),
            state_label = html_escape(&state_label),
            account = html_escape(weixin["account_id_masked"].as_str().unwrap_or("未绑定")),
            login_hint = html_escape(login_hint),
            login_button = html_escape(login_button),
            unbind_disabled = unbind_disabled,
            login_state_json = login_state_json,
            unbind_url = unbind_url,
            qr_svg_url = qr_svg_url,
            login_status_url = login_status_url,
            login_start_url = login_start_url
        );
        portal_document("微信连接", &body, false)
    }

    pub fn build_qr_page(&self) -> String {
        self.build_qr_page_with_prefix("")
    }

    pub fn build_qr_page_with_prefix(&self, route_prefix: &str) -> String {
        if self.config.runtime_profile == "nexus" {
            return portal_document(
                "消息连接",
                r#"<section class="card stack"><h1>消息连接</h1><p>请在 HarborOS 中管理连接。</p><a href="/ui/harbor-assistant?tab=messages">打开 Harbor Assistant</a></section>"#,
                true,
            );
        }
        let prefix = normalized_route_prefix(route_prefix);
        let qr_svg_url = prefixed_path(&prefix, "/setup/feishu/qr.svg");
        portal_document(
            "飞书连接",
            &format!(
                r#"
    <section class="card stack">
      <header class="native-header">
        <div>
          <h1>飞书</h1>
          <p>扫码打开连接页面</p>
        </div>
      </header>
      <img class="qr" src="{qr_svg_url}" alt="飞书连接二维码" />
    </section>
"#,
                qr_svg_url = qr_svg_url
            ),
            true,
        )
    }

    pub fn build_feishu_qr_svg(&self, request_host: &str) -> String {
        self.build_feishu_qr_svg_with_prefix(request_host, "")
    }

    pub fn build_feishu_qr_svg_with_prefix(
        &self,
        request_host: &str,
        route_prefix: &str,
    ) -> String {
        if self.config.runtime_profile == "nexus" {
            return qr_to_svg("/ui/harbor-assistant?tab=messages");
        }
        let status = self.status_payload_with_prefix(request_host, route_prefix);
        let target = status
            .pointer("/feishu/setup_url")
            .and_then(Value::as_str)
            .or_else(|| status.get("setup_url").and_then(Value::as_str))
            .unwrap_or("");
        qr_to_svg(target)
    }

    pub fn build_weixin_qr_svg(&self) -> String {
        let login = self
            .store
            .load_weixin_login_state()
            .unwrap_or_else(|_| json!({}));
        let target = login
            .get("qrcode_img_content")
            .or_else(|| login.get("qrcode"))
            .and_then(Value::as_str)
            .unwrap_or("");
        qr_to_svg(if target.trim().is_empty() {
            "微信二维码尚未生成"
        } else {
            target
        })
    }

    pub async fn configure_feishu(&self, body: Value) -> Result<(StatusCode, Value), GatewayError> {
        let expected = self.store.current_session_code()?.to_uppercase();
        let received = body
            .get("session_code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_uppercase();
        if received != expected {
            return Ok((
                StatusCode::FORBIDDEN,
                json!({"success": false, "message": "配置会话已失效，请刷新页面后重试。"}),
            ));
        }
        let app_id = string_field(&body, "app_id");
        let app_secret = string_field(&body, "app_secret");
        let verification_token = string_field(&body, "verification_token");
        if app_id.is_empty() || app_secret.is_empty() {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"success": false, "message": "请填写 App ID 和 App Secret。"}),
            ));
        }
        let mut settings = self.gateway.feishu_adapter().settings();
        settings.app_id = app_id.clone();
        settings.app_secret = app_secret.clone();
        settings.verification_token = verification_token.clone();
        settings.connection_mode = "websocket".into();
        settings.enable_live_send = true;
        let bot_info = match self.fetch_feishu_bot_info(&settings).await {
            Ok(bot_info) => bot_info,
            Err(error) => {
                return Ok((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    json!({"success": false, "message": "飞书连接验证失败。", "error": error.message}),
                ));
            }
        };
        settings.bot_name = string_field(&bot_info, "app_name");
        settings.bot_open_id = string_field(&bot_info, "open_id");
        settings.bot_user_id = string_field(&bot_info, "user_id");
        self.gateway.feishu_adapter().apply_settings(settings);
        let saved = self.store.save_feishu_state(json!({
            "app_id": app_id,
            "app_secret": app_secret,
            "verification_token": verification_token,
            "connection_mode": "websocket",
            "enable_live_send": true,
            "app_name": string_field(&bot_info, "app_name"),
            "tenant_key": string_field(&bot_info, "tenant_key"),
            "bot_open_id": string_field(&bot_info, "open_id"),
            "bot_user_id": string_field(&bot_info, "user_id"),
            "status": "validated",
            "last_validated_at": utc_now_iso(),
        }))?;
        Ok((
            StatusCode::OK,
            json!({
                "success": true,
                "message": "飞书连接已保存。",
                "connection_mode": "websocket",
                "bot_info": {
                    "app_name": saved.get("app_name").cloned().unwrap_or(Value::Null),
                    "tenant_key": saved.get("tenant_key").cloned().unwrap_or(Value::Null),
                    "open_id": saved.get("bot_open_id").cloned().unwrap_or(Value::Null),
                    "user_id": saved.get("bot_user_id").cloned().unwrap_or(Value::Null),
                },
            }),
        ))
    }

    pub async fn start_weixin_login(&self) -> Result<(StatusCode, Value), GatewayError> {
        self.start_weixin_login_with_prefix("").await
    }

    pub async fn start_weixin_login_with_prefix(
        &self,
        route_prefix: &str,
    ) -> Result<(StatusCode, Value), GatewayError> {
        let prefix = normalized_route_prefix(route_prefix);
        let bot_type = "3";
        match self
            .gateway
            .weixin_adapter()
            .request_qr_challenge(bot_type)
            .await
        {
            Ok(challenge) => {
                let state = self.store.save_weixin_login_state(json!({
                    "status": "wait",
                    "bot_type": challenge.bot_type,
                    "qrcode": challenge.qrcode,
                    "qrcode_img_content": challenge.qrcode_img_content,
                    "current_base_url": WeixinConfig::ILINK_BASE_URL,
                    "started_at": utc_now_iso(),
                    "last_checked_at": "",
                    "expires_at_epoch": epoch_seconds() + WEIXIN_QR_TTL_SECONDS,
                    "last_error": "",
                }))?;
                Ok((
                    StatusCode::OK,
                    json!({"ok": true, "message": "微信二维码已生成。", "weixin_login": self.project_weixin_login_state(&state, &prefix)}),
                ))
            }
            Err(error) => {
                let state = self.store.save_weixin_login_state(json!({
                    "status": "error",
                    "bot_type": bot_type,
                    "started_at": utc_now_iso(),
                    "last_checked_at": utc_now_iso(),
                    "last_error": error.message,
                }))?;
                Ok((
                    StatusCode::BAD_GATEWAY,
                    json!({"ok": false, "message": "微信二维码暂时不可用。", "weixin_login": self.project_weixin_login_state(&state, &prefix)}),
                ))
            }
        }
    }

    pub async fn poll_weixin_login(&self) -> Result<(StatusCode, Value), GatewayError> {
        self.poll_weixin_login_with_prefix("").await
    }

    pub async fn poll_weixin_login_with_prefix(
        &self,
        route_prefix: &str,
    ) -> Result<(StatusCode, Value), GatewayError> {
        let prefix = normalized_route_prefix(route_prefix);
        let mut login = self.store.load_weixin_login_state()?;
        let qrcode = login
            .get("qrcode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if qrcode.is_empty() {
            return Ok((
                StatusCode::NOT_FOUND,
                json!({"ok": false, "message": "请先生成微信二维码。", "weixin_login": self.project_weixin_login_state(&login, &prefix)}),
            ));
        }
        if login
            .get("expires_at_epoch")
            .and_then(Value::as_u64)
            .is_some_and(|expires| expires <= epoch_seconds())
        {
            login["status"] = json!("expired");
            login["last_checked_at"] = json!(utc_now_iso());
            let saved = self.store.save_weixin_login_state(login)?;
            return Ok((
                StatusCode::OK,
                json!({"ok": false, "message": "微信二维码已过期。", "weixin_login": self.project_weixin_login_state(&saved, &prefix)}),
            ));
        }
        let base_url = login
            .get("current_base_url")
            .and_then(Value::as_str)
            .unwrap_or(WeixinConfig::ILINK_BASE_URL)
            .to_string();
        let status = match self
            .gateway
            .weixin_adapter()
            .poll_qr_status(&base_url, &qrcode)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                login["status"] = json!("error");
                login["last_checked_at"] = json!(utc_now_iso());
                login["last_error"] = json!(error.message);
                let saved = self.store.save_weixin_login_state(login)?;
                return Ok((
                    StatusCode::OK,
                    json!({"ok": false, "message": "微信扫码状态暂时不可用。", "weixin_login": self.project_weixin_login_state(&saved, &prefix)}),
                ));
            }
        };
        let qr_status = status
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("wait")
            .trim()
            .to_string();
        login["status"] = json!(qr_status);
        login["last_checked_at"] = json!(utc_now_iso());
        login["last_error"] = json!("");
        if login["status"] == "scaned_but_redirect" {
            if let Some(host) = status.get("redirect_host").and_then(Value::as_str) {
                if !host.trim().is_empty() {
                    login["current_base_url"] = json!(format!("https://{}", host.trim()));
                }
            }
        } else if login["status"] == "expired" {
            login["expires_at_epoch"] = json!(epoch_seconds());
        } else if login["status"] == "confirmed" {
            let account = WeixinAccount {
                account_id: string_field(&status, "ilink_bot_id"),
                token: string_field(&status, "bot_token"),
                base_url: string_field(&status, "baseurl")
                    .if_empty_then(|| WeixinConfig::ILINK_BASE_URL.into()),
                user_id: string_field(&status, "ilink_user_id"),
            };
            if account.account_id.is_empty() || account.token.is_empty() {
                login["status"] = json!("error");
                login["last_error"] = json!("微信确认成功，但账号信息不完整。");
            } else {
                self.gateway
                    .weixin_adapter()
                    .save_account(account.clone())?;
                login["account_id"] = json!(account.account_id);
                login["user_id"] = json!(account.user_id);
                login["current_base_url"] = json!(account.base_url);
            }
        }
        let saved = self.store.save_weixin_login_state(login)?;
        Ok((
            StatusCode::OK,
            json!({
                "ok": saved.get("status").and_then(Value::as_str) == Some("confirmed"),
                "message": "微信扫码状态已更新。",
                "weixin_login": self.project_weixin_login_state(&saved, &prefix),
            }),
        ))
    }

    pub fn unbind_weixin(&self) -> Value {
        let response = self.gateway.weixin_adapter().unbind();
        if response.get("ok").and_then(Value::as_bool) == Some(true) {
            let _ = self.store.save_weixin_login_state(json!({}));
        }
        response
    }

    fn feishu_status(
        &self,
        state: &Value,
        origin: &str,
        setup_url: &str,
        route_prefix: &str,
    ) -> Value {
        let adapter = self.gateway.feishu_adapter();
        let settings = adapter.settings();
        let portal = state.get("feishu").and_then(Value::as_object);
        let app_id = if settings.app_id.trim().is_empty() {
            portal
                .and_then(|value| value.get("app_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        } else {
            settings.app_id.clone()
        };
        let configured = !app_id.trim().is_empty()
            && (!settings.app_secret.trim().is_empty()
                || portal
                    .and_then(|value| value.get("app_secret"))
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()));
        let transport = adapter.status();
        let connected = transport
            .get("connected")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let status = transport
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or(if configured {
                "websocket_idle"
            } else {
                "waiting_for_credentials"
            });
        let display_name = settings.bot_name.if_empty_then(|| {
            portal
                .and_then(|value| value.get("app_name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        });
        json!({
            "platform": "feishu",
            "display_name": if display_name.is_empty() { "Feishu" } else { &display_name },
            "configured": configured,
            "connected": connected,
            "status": status,
            "connection_mode": settings.connection_mode,
            "api_key_configured": configured,
            "credential_status": portal.and_then(|value| value.get("status")).and_then(Value::as_str).unwrap_or(if configured { "configured" } else { "not_configured" }),
            "app_id_masked": mask_secret(&app_id),
            "last_error": transport.get("last_error").cloned().unwrap_or_else(|| json!("")),
            "setup_url": setup_url,
            "manage_url": format!("{origin}{}", prefixed_path(route_prefix, "/admin/im/feishu")),
            "readiness": readiness(configured, connected, status),
            "transport": transport,
        })
    }

    fn weixin_status(
        &self,
        state: &Value,
        origin: &str,
        setup_url: &str,
        route_prefix: &str,
    ) -> Value {
        let adapter = self.gateway.weixin_adapter();
        let account = adapter.account();
        let transport = adapter.status();
        let configured = account.configured();
        let connected = transport
            .get("connected")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let status = transport
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or(if configured {
                "polling_idle"
            } else {
                "waiting_for_credentials"
            });
        let context_token_count = adapter.context_token_count();
        let blocker = if !configured {
            "account_restore"
        } else if context_token_count == 0 {
            "context_token_send"
        } else {
            ""
        };
        let login = state
            .get("weixin_login")
            .cloned()
            .unwrap_or_else(|| json!({}));
        json!({
            "platform": "weixin",
            "display_name": "Weixin",
            "configured": configured,
            "connected": connected,
            "status": status,
            "account_id_masked": mask_secret(&account.account_id),
            "user_id_masked": mask_secret(&account.user_id),
            "context_token_count": context_token_count,
            "blocker_category": blocker,
            "ingress_blocker_category": blocker,
            "qr_status": if configured { "configured" } else { "not_configured" },
            "manage_status": "available",
            "setup_url": setup_url,
            "manage_url": format!("{origin}{}", prefixed_path(route_prefix, "/admin/im/weixin")),
            "login": self.project_weixin_login_state(&login, route_prefix),
            "readiness": readiness(configured, connected && blocker.is_empty(), status),
            "poll": transport.clone(),
            "ingress_observability": transport.clone(),
            "delivery_observability": transport.clone(),
            "transport": transport,
        })
    }

    fn channel_summary(
        &self,
        platform: &str,
        display_name: &str,
        platform_status: &Value,
    ) -> Value {
        json!({
            "platform": platform,
            "display_name": display_name,
            "configured": platform_status.get("configured").cloned().unwrap_or(json!(false)),
            "connected": platform_status.get("connected").cloned().unwrap_or(json!(false)),
            "status": platform_status.get("status").cloned().unwrap_or_else(|| json!("")),
            "setup_url": platform_status.get("setup_url").cloned().unwrap_or_else(|| json!("")),
            "manage_url": platform_status.get("manage_url").cloned().unwrap_or_else(|| json!("")),
            "transport": platform_status.get("transport").cloned().unwrap_or_else(|| json!({})),
        })
    }

    fn project_weixin_login_state(&self, payload: &Value, route_prefix: &str) -> Value {
        let status = payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("not_started");
        let expires_at = payload
            .get("expires_at_epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let expires_in = expires_at.saturating_sub(epoch_seconds());
        let qrcode_value = payload
            .get("qrcode_img_content")
            .or_else(|| payload.get("qrcode"))
            .and_then(Value::as_str)
            .unwrap_or("");
        json!({
            "status": status,
            "started_at": payload.get("started_at").cloned().unwrap_or_else(|| json!("")),
            "last_checked_at": payload.get("last_checked_at").cloned().unwrap_or_else(|| json!("")),
            "expires_in_seconds": expires_in,
            "qrcode_url": qrcode_value,
            "qrcode_available": !qrcode_value.trim().is_empty(),
            "qr_svg_url": if qrcode_value.trim().is_empty() { String::new() } else { prefixed_path(route_prefix, "/setup/weixin/qr.svg") },
            "account_id_masked": mask_secret(payload.get("account_id").and_then(Value::as_str).unwrap_or("")),
            "user_id_masked": mask_secret(payload.get("user_id").and_then(Value::as_str).unwrap_or("")),
            "last_error": redact_sensitive(payload.get("last_error").and_then(Value::as_str).unwrap_or("")),
        })
    }

    async fn fetch_feishu_bot_info(&self, settings: &FeishuConfig) -> Result<Value, GatewayError> {
        let auth_url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            settings.auth_base_url.trim_end_matches('/')
        );
        let token_response = self
            .http
            .post(auth_url)
            .json(&json!({"app_id": settings.app_id, "app_secret": settings.app_secret}))
            .send()
            .await
            .map_err(|error| {
                GatewayError::new(
                    StatusCode::BAD_GATEWAY,
                    "PLATFORM_UNAVAILABLE",
                    format!("无法连接飞书认证服务: {error}"),
                )
            })?;
        let token_payload = decode_feishu_response(token_response).await?;
        let token = token_payload
            .get("tenant_access_token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(GatewayError::validation("飞书认证响应缺少访问令牌。"));
        }
        let bot_url = format!(
            "{}/open-apis/bot/v3/info",
            settings.base_url.trim_end_matches('/')
        );
        let bot_response = self
            .http
            .get(bot_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| {
                GatewayError::new(
                    StatusCode::BAD_GATEWAY,
                    "PLATFORM_UNAVAILABLE",
                    format!("无法读取飞书机器人信息: {error}"),
                )
            })?;
        let bot_payload = decode_feishu_response(bot_response).await?;
        Ok(bot_payload
            .get("data")
            .cloned()
            .unwrap_or_else(|| json!({})))
    }

    fn resolve_public_origin(&self, request_host: &str) -> String {
        if !self.config.public_origin.trim().is_empty() {
            return self
                .config
                .public_origin
                .trim()
                .trim_end_matches('/')
                .to_string();
        }
        if !request_host.trim().is_empty() && !looks_like_loopback(request_host) {
            return format!("http://{}", request_host.trim().trim_end_matches('/'));
        }
        let host = self.config.host.trim();
        if !matches!(host, "" | "0.0.0.0" | "::" | "127.0.0.1" | "localhost") {
            return format!("http://{}:{}", host, self.config.port);
        }
        format!("http://127.0.0.1:{}", self.config.port)
    }
}

async fn decode_feishu_response(response: reqwest::Response) -> Result<Value, GatewayError> {
    let status = response.status();
    let raw = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(GatewayError::new(
            StatusCode::BAD_GATEWAY,
            "PLATFORM_UNAVAILABLE",
            format!("飞书接口返回 HTTP {status}。"),
        ));
    }
    let payload: Value = serde_json::from_str(&raw).map_err(|error| {
        GatewayError::new(
            StatusCode::BAD_GATEWAY,
            "PLATFORM_UNAVAILABLE",
            format!("飞书接口响应不是有效 JSON: {error}"),
        )
    })?;
    if payload.get("code").and_then(Value::as_i64).unwrap_or(0) != 0 {
        return Err(GatewayError::new(
            StatusCode::BAD_GATEWAY,
            "PLATFORM_UNAVAILABLE",
            format!(
                "飞书接口返回错误: {}",
                payload
                    .get("msg")
                    .or_else(|| payload.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
        ));
    }
    Ok(payload)
}

fn portal_document(title: &str, body: &str, narrow: bool) -> String {
    let wrap = if narrow { "wrap narrow" } else { "wrap" };
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{}</title>
  <style>{}</style>
</head>
<body>
  <main class="{wrap}">
    <nav class="topbar" aria-label="页面导航"><a class="back-link" href="/ui/harbor-assistant?tab=messages&amp;ngsw-bypass=1">返回</a></nav>
    {body}
  </main>
</body>
</html>"#,
        html_escape(title),
        PORTAL_CSS,
        wrap = wrap,
        body = body
    )
}

fn qr_to_svg(text: &str) -> String {
    match QrCode::encode_text(text, QrCodeEcc::Medium) {
        Ok(qr) => {
            let border = 4;
            let size = qr.size();
            let dimension = size + border * 2;
            let mut path = String::new();
            for y in 0..size {
                for x in 0..size {
                    if qr.get_module(x, y) {
                        path.push_str(&format!("M{},{}h1v1h-1z ", x + border, y + border));
                    }
                }
            }
            format!(
                r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dimension} {dimension}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#f4efff"/><path d="{path}" fill="#40108f"/></svg>"##
            )
        }
        Err(_) => format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 180"><rect width="100%" height="100%" fill="#f4efff"/><text x="20" y="48" font-size="18" fill="#40108f">二维码暂不可用</text><text x="20" y="88" font-size="12" fill="#716982">{}</text></svg>"##,
            html_escape(text)
        ),
    }
}

fn readiness(configured: bool, ready_signal: bool, status: &str) -> Value {
    if !configured {
        json!({"ready": false, "state": "not_configured", "reason": "not_configured", "status": status})
    } else if ready_signal {
        json!({"ready": true, "state": "ready", "reason": "", "status": status})
    } else {
        json!({"ready": false, "state": "blocked", "reason": status, "status": status})
    }
}

fn generate_session_code() -> String {
    let bytes = Uuid::new_v4().as_bytes()[..4].to_vec();
    let token = hex_lower(&bytes).to_uppercase();
    format!("{}-{}", &token[..4], &token[4..])
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("")
        .to_string()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn normalized_route_prefix(route_prefix: &str) -> String {
    let trimmed = route_prefix.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn prefixed_path(route_prefix: &str, path: &str) -> String {
    let prefix = normalized_route_prefix(route_prefix);
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if prefix.is_empty() {
        path
    } else {
        format!("{prefix}{path}")
    }
}

fn mask_secret(value: &str) -> String {
    let text = value.trim();
    if text.is_empty() {
        return String::new();
    }
    if text.len() <= 6 {
        "*".repeat(text.len())
    } else {
        format!("{}***{}", &text[..4], &text[text.len() - 2..])
    }
}

fn redact_sensitive(value: &str) -> String {
    let mut redacted = value.to_string();
    redacted = redacted.replace("Bearer ", "Bearer [REDACTED] ");
    redacted
}

fn customer_status_label(status: &str, configured: bool, connected: bool) -> String {
    let normalized = status.trim().to_lowercase();
    if matches!(
        normalized.as_str(),
        "error" | "failed" | "send_failed" | "timeout" | "expired"
    ) {
        return "需要处理".into();
    }
    if connected
        || matches!(
            normalized.as_str(),
            "ready" | "connected" | "polling" | "polling_idle" | "validated" | "configured"
        )
    {
        return if configured { "已连接" } else { "可用" }.into();
    }
    if configured {
        "连接中".into()
    } else {
        "待配置".into()
    }
}

fn badge_class(label: &str) -> &'static str {
    match label {
        "已连接" | "已绑定" | "已配置" | "可用" => "good",
        "需要处理" => "danger",
        _ => "warn",
    }
}

fn connection_mode_label(value: &str) -> &'static str {
    if value.trim().eq_ignore_ascii_case("webhook") {
        "回调接收"
    } else {
        "自动接收"
    }
}

fn looks_like_loopback(value: &str) -> bool {
    let host = value
        .split("://")
        .last()
        .unwrap_or(value)
        .split('/')
        .next()
        .unwrap_or(value)
        .split(':')
        .next()
        .unwrap_or(value)
        .trim()
        .to_lowercase();
    matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1")
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

const PORTAL_CSS: &str = r#"
:root {
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-soft: #f7f8fa;
  --primary: #6715ff;
  --primary-dark: #40108f;
  --text: #20252b;
  --muted: #68707d;
  --border: #d9dde3;
  --success: #19745f;
  --danger: #b3261e;
  --warning: #8a5b00;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
}
.wrap { max-width: 920px; margin: 0 auto; padding: 24px 18px 48px; }
.wrap.narrow { max-width: 560px; text-align: center; }
.topbar { display: flex; justify-content: flex-end; margin-bottom: 14px; }
.back-link {
  display: inline-flex;
  align-items: center;
  min-height: 38px;
  padding: 8px 14px;
  border-radius: 8px;
  background: #fff;
  border: 1px solid var(--primary);
  color: var(--primary);
  font-weight: 700;
  text-decoration: none;
}
.back-link:hover { background: var(--surface-soft); }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06);
}
.stack { display: grid; gap: 0; }
.eyebrow { color: var(--primary); font-size: 13px; font-weight: 700; margin-bottom: 8px; }
h1 { margin: 0; font-size: 24px; line-height: 1.2; }
h2 { margin: 0; font-size: 20px; line-height: 1.25; }
p { margin: 0; line-height: 1.58; color: var(--muted); }
.native-header {
  align-items: center;
  border-bottom: 1px solid var(--border);
  display: flex;
  gap: 16px;
  justify-content: space-between;
  min-height: 72px;
  padding: 16px 20px;
}
label { display: block; margin: 14px 0 8px; font-weight: 700; }
input {
  width: 100%;
  padding: 13px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: #fff;
  color: var(--text);
  font-size: 16px;
}
button {
  min-height: 44px;
  border: 0;
  border-radius: 8px;
  padding: 12px 18px;
  font-weight: 700;
  cursor: pointer;
}
button.primary { background: var(--primary); color: #fff; }
button.danger { background: var(--danger); color: #fff; }
button:disabled { background: #d8d2e8; color: #766f8f; cursor: not-allowed; }
.actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 18px; }
.summary {
  display: grid;
  gap: 10px;
  margin: 0;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
}
.form-panel { padding: 18px 20px; }
.row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.label { color: var(--muted); }
.value { font-weight: 700; text-align: right; }
.badge {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 4px 12px;
  border-radius: 999px;
  font-weight: 700;
  background: #efe8ff;
  color: var(--primary-dark);
}
.badge.good { background: #e8f7f2; color: var(--success); }
.badge.warn { background: #fff6df; color: var(--warning); }
.badge.danger { background: #ffe8e5; color: var(--danger); }
.notice { border-bottom: 1px solid var(--border); padding: 14px 20px; color: var(--text); }
.notice.good { background: #edf9f5; border-color: #c7e9de; color: var(--success); }
.notice.danger { background: #ffe8e5; border-color: #f1b8b2; color: var(--danger); }
.hint { color: var(--muted); font-size: 14px; }
.ok { color: var(--success); }
.err { color: var(--danger); }
.login-qr, .qr {
  width: min(280px, 100%);
  aspect-ratio: 1;
  border-radius: 8px;
  background: var(--surface-soft);
  border: 1px solid var(--border);
}
.login-qr { display: none; margin: 16px 0 8px; }
.qr { display: block; margin: 20px auto; }
form { margin: 0; }
@media (max-width: 640px) {
  .wrap { padding: 18px 12px 36px; }
  h1 { font-size: 22px; }
  .native-header { align-items: flex-start; flex-direction: column; }
  .row { align-items: flex-start; flex-direction: column; gap: 4px; }
  .value { text-align: left; }
  .actions button { width: 100%; }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn setup_store_bootstraps_python_compatible_state() {
        let dir = tempdir().unwrap();
        let store = SetupPortalStore::new(dir.path().to_path_buf());
        let state = store.load_state().unwrap();
        assert!(state["session_code"].as_str().unwrap().contains('-'));
        assert!(dir.path().join(SETUP_STATE_FILE).exists());
        assert!(state["feishu"].is_object());
        assert!(state["weixin_login"].is_object());
    }

    #[test]
    fn setup_pages_include_harbor_assistant_back_link() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.state_dir = dir.path().to_path_buf();
        config.data_dir = dir.path().join("sessions");
        config.harborbeacon_base_url.clear();
        let gateway = Arc::new(GatewayService::from_config(&config).unwrap());
        let service = SetupPortalService::new(config, gateway);
        assert!(service
            .build_weixin_setup_page("127.0.0.1:8787", false)
            .contains(">返回</a>"));
        assert!(service
            .build_feishu_setup_page("127.0.0.1:8787")
            .contains(">返回</a>"));
        assert!(service
            .build_weixin_setup_page("127.0.0.1:8787", false)
            .contains("/ui/harbor-assistant?tab=messages&amp;ngsw-bypass=1"));
    }

    #[test]
    fn setup_pages_support_harbor_gate_prefix() {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.state_dir = dir.path().to_path_buf();
        config.data_dir = dir.path().join("sessions");
        config.harborbeacon_base_url.clear();
        let gateway = Arc::new(GatewayService::from_config(&config).unwrap());
        let service = SetupPortalService::new(config, gateway);

        let status =
            service.gateway_status_payload_with_prefix("127.0.0.1:8787", "/api/harbor-gate");
        assert!(status["setup_url"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:8787/api/harbor-gate/setup?session="));
        assert_eq!(
            status["static_setup_url"].as_str().unwrap(),
            "http://127.0.0.1:8787/api/harbor-gate/setup"
        );
        assert_eq!(
            status["qr_page_url"].as_str().unwrap(),
            "http://127.0.0.1:8787/api/harbor-gate/setup/qr"
        );
        assert_eq!(
            status["weixin"]["setup_url"].as_str().unwrap(),
            "http://127.0.0.1:8787/api/harbor-gate/setup/weixin"
        );
        assert_eq!(
            status["weixin"]["manage_url"].as_str().unwrap(),
            "http://127.0.0.1:8787/api/harbor-gate/admin/im/weixin"
        );

        let weixin_page = service.build_weixin_setup_page_with_prefix(
            "127.0.0.1:8787",
            false,
            "/api/harbor-gate",
        );
        assert!(weixin_page.contains(r#"action="/api/harbor-gate/api/setup/weixin/unbind""#));
        assert!(weixin_page.contains("fetch('/api/harbor-gate/api/setup/weixin/login/status')"));
        assert!(weixin_page
            .contains(r#"qrEl.src = `/api/harbor-gate/setup/weixin/qr.svg?ts=${Date.now()}`;"#));

        let feishu_page =
            service.build_feishu_setup_page_with_prefix("127.0.0.1:8787", "/api/harbor-gate");
        assert!(feishu_page.contains("fetch('/api/harbor-gate/api/setup/feishu/configure'"));
    }
}
