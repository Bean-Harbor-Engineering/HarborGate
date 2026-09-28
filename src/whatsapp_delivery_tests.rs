use super::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tempfile::tempdir;
use tokio::net::TcpListener;

struct FixtureAdapter {
    status: Arc<AtomicUsize>,
    uploads: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
    revoke_in_prepare: bool,
    fail_first_send: bool,
}

#[async_trait]
impl PlatformAdapter for FixtureAdapter {
    fn name(&self) -> &str {
        "whatsapp"
    }
    fn normalize_inbound(&self, _: Value) -> Result<InboundMessage, GatewayError> {
        unreachable!()
    }
    async fn send_outbound(&self, _: OutboundMessage) -> Result<Value, GatewayError> {
        let attempt = self.sends.fetch_add(1, Ordering::SeqCst);
        if self.fail_first_send && attempt == 0 {
            return Err(GatewayError::infrastructure("temporary provider timeout"));
        }
        Ok(json!({"provider_message_id":"fixture-message"}))
    }
    async fn prepare_outbound(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<Option<PreparedOutbound>, GatewayError> {
        if self.revoke_in_prepare {
            self.status.store(403, Ordering::SeqCst);
        }
        if outbound.attachments.is_empty() {
            return Ok(None);
        }
        self.uploads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(PreparedOutbound {
            provider_media_id: "fixture-upload".into(),
            provider_client_id: None,
            state: json!({}),
        }))
    }
    fn profile(&self) -> Value {
        json!({"adapter_name":"whatsapp"})
    }
}

async fn fixture(
    config: &mut AppConfig,
) -> (
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let status = Arc::new(AtomicUsize::new(200));
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.harborbeacon_base_url = format!("http://{}", listener.local_addr().unwrap());
    config.harborbeacon_token = "fixture-service-token".into();
    let current = status.clone();
    let count = calls.clone();
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/api/im/whatsapp/delivery-authorization",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                    let current = current.clone();
                    let count = count.clone();
                    async move {
                        assert_eq!(
                            headers.get("authorization").unwrap(),
                            "Bearer fixture-service-token"
                        );
                        assert_eq!(headers.get("x-contract-version").unwrap(), "2.0");
                        assert_eq!(body["recipient"], "15555550101");
                        assert_eq!(body["route_key"], "fixture-route");
                        assert_eq!(body["conversation_handle"], "fixture-binding-handle");
                        count.fetch_add(1, Ordering::SeqCst);
                        let code = current.load(Ordering::SeqCst) as u16;
                        (
                            StatusCode::from_u16(code).unwrap(),
                            axum::Json(json!({"allowed":code==200})),
                        )
                    }
                },
            ),
        );
        axum::serve(listener, app).await.unwrap();
    });
    (status, calls, server)
}

fn message(attachment: bool) -> OutboundMessage {
    OutboundMessage {
        platform: "whatsapp".into(),
        chat_id: "15555550101".into(),
        text: if attachment {
            ""
        } else {
            "Private home response"
        }
        .into(),
        attachments: if attachment {
            vec![
                json!({"artifact_id":"fixture-file","kind":"file", "mime_type":"application/octet-stream","path":"fixture-cached-file"}),
            ]
        } else {
            vec![]
        },
        timestamp: crate::models::utc_now_iso(),
        metadata:
            json!({"conversation_handle":"fixture-binding-handle","route_key":"fixture-route"})
                .as_object()
                .unwrap()
                .clone(),
    }
}

#[tokio::test]
async fn revoked_whatsapp_text_never_reaches_provider() {
    let dir = tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = dir.path().join("sessions");
    config.state_dir = dir.path().join("state");
    let (status, calls, server) = fixture(&mut config).await;
    status.store(403, Ordering::SeqCst);
    let sends = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(FixtureAdapter {
        status,
        uploads: Arc::new(AtomicUsize::new(0)),
        sends: sends.clone(),
        revoke_in_prepare: false,
        fail_first_send: false,
    });
    let gateway = GatewayService::from_config(&config).unwrap();
    let result = gateway
        .deliver_outbound_items_guarded(adapter, message(false), "revoked-text", "same-plan", None)
        .await;
    assert!(result.is_err());
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert!(calls.load(Ordering::SeqCst) > 0);
    server.abort();
}

#[tokio::test]
async fn whatsapp_rechecks_binding_after_media_and_text_preparation() {
    for attachment in [true, false] {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        let (status, calls, server) = fixture(&mut config).await;
        let sends = Arc::new(AtomicUsize::new(0));
        let uploads = Arc::new(AtomicUsize::new(0));
        let adapter = Arc::new(FixtureAdapter {
            status,
            uploads: uploads.clone(),
            sends: sends.clone(),
            revoke_in_prepare: true,
            fail_first_send: false,
        });
        let gateway = GatewayService::from_config(&config).unwrap();
        assert!(gateway
            .deliver_outbound_items_guarded(
                adapter,
                message(attachment),
                "revoke-during-prepare",
                "same-plan",
                None
            )
            .await
            .is_err());
        assert_eq!(sends.load(Ordering::SeqCst), 0);
        assert_eq!(uploads.load(Ordering::SeqCst), usize::from(attachment));
        assert!(calls.load(Ordering::SeqCst) >= 2);
        server.abort();
    }
}

#[tokio::test]
async fn whatsapp_restart_blocks_previously_uploaded_media_after_unbinding() {
    let dir = tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = dir.path().join("sessions");
    config.state_dir = dir.path().join("state");
    let (status, _, server) = fixture(&mut config).await;
    let sends = Arc::new(AtomicUsize::new(0));
    let uploads = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn PlatformAdapter> = Arc::new(FixtureAdapter {
        status: status.clone(),
        uploads: uploads.clone(),
        sends: sends.clone(),
        revoke_in_prepare: false,
        fail_first_send: true,
    });
    let gateway = GatewayService::from_config(&config).unwrap();
    assert!(gateway
        .deliver_outbound_items_guarded(
            adapter.clone(),
            message(true),
            "retry-uploaded",
            "same-plan",
            None
        )
        .await
        .is_err());
    assert_eq!(uploads.load(Ordering::SeqCst), 1);
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    drop(gateway);
    status.store(403, Ordering::SeqCst);
    let mut restarted = GatewayService::from_config(&config).unwrap();
    restarted.adapters.insert("whatsapp".into(), adapter);
    restarted.retry_pending_deliveries().await.unwrap();
    assert_eq!(uploads.load(Ordering::SeqCst), 1);
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(restarted
        .store
        .retryable_delivery_plans()
        .unwrap()
        .is_empty());
    server.abort();
}

struct PreviewDeliveryAdapter {
    fail_upload: bool,
    uploads: Arc<AtomicUsize>,
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
}

#[async_trait]
impl PlatformAdapter for PreviewDeliveryAdapter {
    fn name(&self) -> &str {
        "whatsapp"
    }
    fn normalize_inbound(&self, _: Value) -> Result<InboundMessage, GatewayError> {
        unreachable!()
    }
    async fn send_outbound(&self, _: OutboundMessage) -> Result<Value, GatewayError> {
        unreachable!()
    }
    async fn prepare_outbound(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<Option<PreparedOutbound>, GatewayError> {
        if outbound.attachments.is_empty() {
            return Ok(None);
        }
        self.uploads.fetch_add(1, Ordering::SeqCst);
        if self.fail_upload {
            return Err(GatewayError::new(
                StatusCode::BAD_GATEWAY,
                "WHATSAPP_PREVIEW_UNAVAILABLE",
                "WhatsApp photo preview is unavailable",
            ));
        }
        Ok(Some(PreparedOutbound {
            provider_media_id: "fixture-upload".into(),
            provider_client_id: None,
            state: json!({"kind":"image"}),
        }))
    }
    async fn send_prepared_outbound(
        &self,
        outbound: OutboundMessage,
        prepared: Option<&PreparedOutbound>,
    ) -> Result<Value, GatewayError> {
        assert_eq!(prepared.is_some(), !outbound.attachments.is_empty());
        self.sent.lock().unwrap().push(outbound);
        Ok(json!({"provider_message_id":"fixture-confirmation"}))
    }
    fn profile(&self) -> Value {
        json!({"adapter_name":"whatsapp"})
    }
}

#[tokio::test]
async fn photo_preview_delivery_is_single_item_and_replay_does_not_resend() {
    for fail_upload in [false, true] {
        let dir = tempdir().unwrap();
        let mut config = AppConfig::from_env();
        config.data_dir = dir.path().join("sessions");
        config.state_dir = dir.path().join("state");
        let (_, calls, server) = fixture(&mut config).await;
        let uploads = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let adapter: Arc<dyn PlatformAdapter> = Arc::new(PreviewDeliveryAdapter {
            fail_upload,
            uploads: uploads.clone(),
            sent: sent.clone(),
        });
        let gateway = GatewayService::from_config(&config).unwrap();
        let mut outbound = message(false);
        outbound.text = "Save this photo?".into();
        outbound.attachments = vec![json!({
            "artifact_id":"wa_image_1234567890abcdef12345678",
            "kind":"image",
            "mime_type":"image/jpeg",
            "metadata":{"whatsapp_inbound_confirmation_preview":true}
        })];
        outbound.metadata.insert(
            "whatsapp_context_message_id".into(),
            json!("wamid.source-image"),
        );
        let first = gateway
            .deliver_outbound_items_guarded(
                adapter.clone(),
                outbound.clone(),
                "preview-confirmation",
                "same-plan",
                None,
            )
            .await
            .unwrap();
        let replay = gateway
            .deliver_outbound_items_guarded(
                adapter,
                outbound,
                "preview-confirmation",
                "same-plan",
                None,
            )
            .await
            .unwrap();
        assert_eq!(first["provider_message_id"], "fixture-confirmation");
        assert_eq!(replay["provider_message_id"], "fixture-confirmation");
        assert_eq!(replay["message_id"], "fixture-confirmation");
        assert_eq!(uploads.load(Ordering::SeqCst), 1);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].text, "Save this photo?");
        assert_eq!(sent[0].attachments.is_empty(), fail_upload);
        assert_eq!(
            sent[0].metadata["whatsapp_context_message_id"],
            "wamid.source-image"
        );
        assert!(calls.load(Ordering::SeqCst) >= 2);
        server.abort();
    }
}

#[tokio::test]
async fn whatsapp_unavailable_binding_check_can_retry_without_sending() {
    let dir = tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = dir.path().join("sessions");
    config.state_dir = dir.path().join("state");
    let (status, _, server) = fixture(&mut config).await;
    status.store(503, Ordering::SeqCst);
    let sends = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn PlatformAdapter> = Arc::new(FixtureAdapter {
        status: status.clone(),
        uploads: Arc::new(AtomicUsize::new(0)),
        sends: sends.clone(),
        revoke_in_prepare: false,
        fail_first_send: false,
    });
    let mut gateway = GatewayService::from_config(&config).unwrap();
    gateway.adapters.insert("whatsapp".into(), adapter.clone());
    assert!(gateway
        .deliver_outbound_items_guarded(
            adapter,
            message(false),
            "check-unavailable",
            "same-plan",
            None
        )
        .await
        .is_err());
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert!(!gateway.store.retryable_delivery_plans().unwrap().is_empty());
    status.store(200, Ordering::SeqCst);
    gateway.retry_pending_deliveries().await.unwrap();
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn whatsapp_notification_keeps_its_originating_handle_across_restart() {
    let dir = tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = dir.path().join("sessions");
    config.state_dir = dir.path().join("state");
    let (status, _, server) = fixture(&mut config).await;
    let sends = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn PlatformAdapter> = Arc::new(FixtureAdapter {
        status: status.clone(),
        uploads: Arc::new(AtomicUsize::new(0)),
        sends: sends.clone(),
        revoke_in_prepare: false,
        fail_first_send: true,
    });
    let mut gateway = GatewayService::from_config(&config).unwrap();
    gateway.adapters.insert("whatsapp".into(), adapter.clone());
    gateway.store.register_route("fixture-route",json!({"platform":"whatsapp","adapter_name":"whatsapp","chat_id":"15555550101","status":"active",
        "conversation_handle":"a-different-latest-handle"})).unwrap();
    let notification = json!({"notification":{"notification_id":"fixture-notification","trace_id":"fixture-trace","event_type":"task.completed"},
        "conversation":{"handle":"fixture-binding-handle"},"destination":{"route_key":"fixture-route"},
        "reply":{"kind":"tool_result","text":"Private home response"},"artifacts":[],"delivery_hints":[],
        "delivery":{"mode":"send","idempotency_key":"fixture-notification-key"}});
    assert_eq!(
        gateway
            .handle_notification_delivery(notification.clone())
            .await
            .unwrap()["ok"],
        false
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    let mut changed = notification.clone();
    changed["conversation"]["handle"] = json!("a-different-latest-handle");
    assert_eq!(
        gateway
            .handle_notification_delivery(changed)
            .await
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    drop(gateway);
    status.store(403, Ordering::SeqCst);
    let mut restarted = GatewayService::from_config(&config).unwrap();
    restarted.adapters.insert("whatsapp".into(), adapter);
    let response = restarted
        .handle_notification_delivery(notification)
        .await
        .unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["retryable"], false);
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn whatsapp_cannot_send_without_an_originating_conversation() {
    let dir = tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = dir.path().join("sessions");
    config.state_dir = dir.path().join("state");
    let (status, calls, server) = fixture(&mut config).await;
    let sends = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn PlatformAdapter> = Arc::new(FixtureAdapter {
        status,
        uploads: Arc::new(AtomicUsize::new(0)),
        sends: sends.clone(),
        revoke_in_prepare: false,
        fail_first_send: false,
    });
    let gateway = GatewayService::from_config(&config).unwrap();
    let mut missing = message(false);
    missing.metadata.remove("conversation_handle");
    assert!(gateway
        .deliver_outbound_items_guarded(
            adapter.clone(),
            missing,
            "missing-handle",
            "same-plan",
            None
        )
        .await
        .is_err());
    assert!(gateway
        .deliver_outbound_items_guarded(adapter, message(false), "", "", None)
        .await
        .is_err());
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}
