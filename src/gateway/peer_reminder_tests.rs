use super::*;
struct PeerFixtureAdapter {
    platform: &'static str,
    authorization: Arc<AtomicUsize>,
    prepares: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
    change: &'static str,
}
#[async_trait]
impl PlatformAdapter for PeerFixtureAdapter {
    fn name(&self) -> &str {
        self.platform
    }
    fn normalize_inbound(&self, _: Value) -> Result<InboundMessage, GatewayError> {
        unreachable!()
    }
    async fn prepare_outbound(
        &self,
        _: &OutboundMessage,
    ) -> Result<Option<crate::adapters::PreparedOutbound>, GatewayError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        if self.change == "revoke" {
            self.authorization.store(403, Ordering::SeqCst);
        }
        Ok(None)
    }
    async fn send_outbound(&self, outbound: OutboundMessage) -> Result<Value, GatewayError> {
        assert_eq!(outbound.platform, self.platform);
        assert_eq!(
            outbound.chat_id,
            if self.platform == "feishu_mail" {
                "viewer@example.com"
            } else {
                "separate-direct-chat"
            }
        );
        assert_eq!(outbound.text, "Exact member reminder");
        assert_eq!(
            outbound.metadata["conversation_handle"],
            "im_peer_notice_original.fixture"
        );
        let attempts = self.sends.fetch_add(1, Ordering::SeqCst);
        if self.change == "retry" && attempts == 0 {
            return Err(GatewayError::infrastructure(
                "fixture transient send failure",
            ));
        }
        Ok(json!({"provider_message_id":"peer-provider-result"}))
    }
    fn profile(&self) -> Value {
        json!({"adapter_name":self.platform})
    }
}
fn payload(platform: &str, handle: Option<&str>) -> Value {
    let mut v = json!({"notification_id":"member-reminder","trace_id":"peer-trace",
        "source":{"service":"harborbeacon","module":"reminders","event_type":"rule.reminder"},
        "destination":{"kind":"conversation","platform":platform,"id":"separate-direct-chat","route_key":"opaque-peer-route"},
        "content":{"title":"","body":"Exact member reminder","payload_format":"plain_text","attachments":[]},
        "delivery":{"mode":"send","idempotency_key":"peer-reminder-notification"}});
    if platform == "feishu_mail" {
        v["destination"] = json!({"kind":"recipient","platform":"feishu_mail","id":"viewer@example.com","route_key":"",
            "recipient":{"recipient_id":"viewer@example.com","recipient_type":"email"}});
    }
    if let Some(handle) = handle {
        v["conversation"] = json!({"handle":handle});
    }
    v
}
#[tokio::test]
async fn peer_reminder_notification_preserves_permit_and_rechecks_before_prepare_send_retry_and_restart(
) {
    for platform in ["feishu", "weixin", "feishu_mail"] {
        for change in ["send", "revoke", "missing", "missing-envelope", "retry"] {
            let root = tempdir().unwrap();
            let mut config = AppConfig::from_env();
            config.data_dir = root.path().join("sessions");
            config.state_dir = root.path().join("state");
            config.harborbeacon_token = "fixture-service-token".into();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            config.harborbeacon_base_url = format!("http://{}", listener.local_addr().unwrap());
            let authorization = Arc::new(AtomicUsize::new(200));
            let code = authorization.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let checks = calls.clone();
            let server = tokio::spawn(async move {
                let app = axum::Router::new().route(
                    "/api/im/peer/delivery-authorization",
                    axum::routing::post(
                        move |headers: axum::http::HeaderMap,
                              axum::Json(body): axum::Json<Value>| {
                            let code = code.clone();
                            let checks = checks.clone();
                            async move {
                                assert_eq!(
                                    headers["Authorization"],
                                    "Bearer fixture-service-token"
                                );
                                assert_eq!(headers["X-Contract-Version"], "2.0");
                                assert_eq!(body["platform"], platform);
                                assert_eq!(
                                    body["delivery"]["recipient"],
                                    if platform == "feishu_mail" {
                                        "viewer@example.com"
                                    } else {
                                        "separate-direct-chat"
                                    }
                                );
                                assert_eq!(
                                    body["delivery"]["route_key"],
                                    if platform == "feishu_mail" {
                                        "member-email"
                                    } else {
                                        "opaque-peer-route"
                                    }
                                );
                                assert_eq!(
                                    body["delivery"]["conversation_handle"],
                                    "im_peer_notice_original.fixture"
                                );
                                assert_eq!(body["delivery"]["text"], "Exact member reminder");
                                assert_eq!(body["delivery"]["has_attachments"], false);
                                assert_eq!(body["delivery"]["source_refs"], json!([]));
                                checks.fetch_add(1, Ordering::SeqCst);
                                (
                                    StatusCode::from_u16(code.load(Ordering::SeqCst) as u16)
                                        .unwrap(),
                                    axum::Json(json!({"allowed":code.load(Ordering::SeqCst)==200})),
                                )
                            }
                        },
                    ),
                );
                axum::serve(listener, app).await.unwrap();
            });
            let prepares = Arc::new(AtomicUsize::new(0));
            let sends = Arc::new(AtomicUsize::new(0));
            let adapter = Arc::new(PeerFixtureAdapter {
                platform,
                authorization: authorization.clone(),
                prepares: prepares.clone(),
                sends: sends.clone(),
                change,
            });
            let mut gateway = GatewayService::from_config(&config).unwrap();
            gateway.adapters.insert(platform.into(), adapter.clone());
            if platform != "feishu_mail" {
                gateway.store.register_route("opaque-peer-route",json!({"platform":platform,"adapter_name":platform,"chat_id":"separate-direct-chat","status":"active","conversation_handle":"latest-route-must-not-replace-original"})).unwrap();
            }
            let mut request = payload(
                platform,
                if matches!(change, "missing" | "missing-envelope") {
                    None
                } else {
                    Some("im_peer_notice_original.fixture")
                },
            );
            if change == "missing-envelope" {
                request["source"]["event_type"] = Value::Null;
                request["notification"] = json!({"event_type":"plan.reminder"});
            }
            let first = gateway
                .handle_notification_delivery(request.clone())
                .await
                .unwrap();
            match change {
                "send" => {
                    assert_eq!(first["ok"], true);
                    assert_eq!(sends.load(Ordering::SeqCst), 1);
                    assert!(calls.load(Ordering::SeqCst) >= 2);
                }
                "retry" => {
                    assert_eq!(first["ok"], false);
                    assert_eq!(first["retryable"], true);
                    assert_eq!(sends.load(Ordering::SeqCst), 1);
                    authorization.store(403, Ordering::SeqCst);
                    let before = calls.load(Ordering::SeqCst);
                    drop(gateway);
                    let mut restarted = GatewayService::from_config(&config).unwrap();
                    restarted.adapters.insert(platform.into(), adapter.clone());
                    let second = restarted
                        .handle_notification_delivery(request)
                        .await
                        .unwrap();
                    assert_eq!(second["ok"], false);
                    assert!(calls.load(Ordering::SeqCst) > before);
                    assert_eq!(sends.load(Ordering::SeqCst), 1);
                }
                "revoke" => {
                    assert_eq!(first["ok"], false);
                    assert!(calls.load(Ordering::SeqCst) >= 2);
                    assert_eq!(prepares.load(Ordering::SeqCst), 1);
                    assert_eq!(sends.load(Ordering::SeqCst), 0);
                }
                "missing" | "missing-envelope" => {
                    assert_eq!(first["ok"], false);
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    assert_eq!(prepares.load(Ordering::SeqCst), 0);
                    assert_eq!(sends.load(Ordering::SeqCst), 0);
                }
                _ => unreachable!(),
            }
            server.abort();
        }
    }
}
#[test]
fn peer_reminder_required_marker_covers_flat_and_enveloped_contracts_with_missing_or_altered_handles(
) {
    assert!(peer_reminder_notification(&payload("feishu", None)));
    assert!(peer_reminder_notification(
        &json!({"notification":{"event_type":"plan.reminder"}})
    ));
    for outer in [Value::Null, json!(""), json!("camera.event"), json!({})] {
        assert!(peer_reminder_notification(
            &json!({"source":{"event_type":outer},"notification":{"event_type":"plan.reminder"}})
        ));
    }
    assert!(peer_reminder_notification(
        &json!({"source":{"event_type":"rule.reminder"},"notification":{"event_type":"camera.event"}})
    ));
    assert!(peer_reminder_notification(
        &json!({"conversation":{"handle":"im_peer_notice_original.fixture"}})
    ));
    assert!(!peer_reminder_notification(
        &json!({"source":{"event_type":"camera.event"}})
    ));
}

#[test]
fn mail_destination_ignores_blank_fields_and_legacy_queued_reminders_still_require_permit() {
    let root = tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = root.path().join("sessions");
    config.state_dir = root.path().join("state");
    let gateway = GatewayService::from_config(&config).unwrap();
    for recipient in [
        json!({"recipient_id":"viewer@example.com"}),
        json!({"recipient_id":"", "email":"viewer@example.com"}),
        json!({"recipient_id":" ", "email":"", "mail_address":"viewer@example.com"}),
    ] {
        let destination = json!({"platform":"feishu_mail", "id":" ", "recipient":recipient});
        let route = gateway
            .resolve_notification_route(destination.as_object().unwrap(), "", "trace")
            .unwrap();
        assert_eq!(route["chat_id"], "viewer@example.com");
        assert_eq!(route["route_mode"], "proactive");
        assert_eq!(route["route_source"], "recipient");
    }
    let mut outbound = OutboundMessage {
        platform: "feishu_mail".into(),
        chat_id: "viewer@example.com".into(),
        text: "Reminder".into(),
        attachments: vec![],
        timestamp: crate::models::utc_now_iso(),
        metadata: serde_json::Map::new(),
    };
    outbound.metadata.insert(
        "notification_id".into(),
        json!("reminder-im-original-attempt"),
    );
    assert!(peer_reminder_outbound(&outbound));
    outbound.metadata.insert(
        "notification_id".into(),
        json!("member-email-verification-session"),
    );
    outbound.metadata.insert(
        "notification_event_type".into(),
        json!("member.email_verification"),
    );
    assert!(!peer_reminder_outbound(&outbound));
}
