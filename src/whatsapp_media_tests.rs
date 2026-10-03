use super::*;
use crate::adapters::whatsapp::WhatsAppConfig;
use crate::cloud_relay::CloudRelayClient;
use crate::navi_fleet::NaviFleet;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

fn image_adapter(cache: PathBuf) -> Arc<WhatsAppAdapter> {
    Arc::new(WhatsAppAdapter::new(
        WhatsAppConfig {
            phone_number_id: "123".into(),
            business_number: "15555550100".into(),
            app_secret: "test-app-secret-value".into(),
            verify_token: "x".repeat(32),
            access_token: "test-token".into(),
            graph_version: "v25.0".into(),
        },
        cache,
    ))
}

#[tokio::test]
async fn media_pull_denies_cross_route_cross_hub_and_revoked_binding_before_provider_fetch() {
    let root = tempfile::tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = root.path().join("sessions");
    config.state_dir = root.path().join("state");
    config.harborbeacon_base_url.clear();
    config.cloud_relay_url.clear();
    config.cloud_relay_region.clear();
    let mut gateway = GatewayService::from_config(&config).unwrap();
    let adapter = image_adapter(config.state_dir.join("attachment-cache"));
    gateway.whatsapp_adapter = adapter.clone();
    let fleet = NaviFleet::new(
        CloudRelayClient::for_fixture("http://127.0.0.1:1"),
        root.path().join("routes"),
    );
    let payload = json!({"phone_number_id":"123","message":{"from":"15555550101",
        "id":"wamid.image.4","timestamp":(chrono::Utc::now()+chrono::Duration::seconds(2)).timestamp().to_string(),
        "type":"image","image":{"id":"2754859441498128","mime_type":"image/jpeg","sha256":"d".repeat(64)}}});
    let inbound = adapter.normalize_inbound(payload.clone()).unwrap();
    let mut pairing = inbound.clone();
    pairing.text = format!("NAVI navi-a.{}", "a".repeat(64));
    pairing.message_id = "pairing-message".into();
    pairing.timestamp = chrono::Utc::now().to_rfc3339();
    fleet
        .activate_for_media_test(&pairing, &"a".repeat(64))
        .unwrap();
    let selection = fleet.select(&inbound).unwrap();
    adapter
        .stage_inbound_media(&payload, &inbound, Some(&selection), "conv-image-1")
        .unwrap();
    let id = inbound.attachments[0]["attachment_id"].as_str().unwrap();
    gateway.fleet = Some(fleet);
    assert_eq!(
        gateway
            .pull_whatsapp_media(id, "another-route", &selection.hub_id)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        gateway
            .pull_whatsapp_media(id, &inbound.route_key, "another-hub")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    gateway
        .fleet
        .as_ref()
        .unwrap()
        .invalidate_identity(&selection)
        .unwrap();
    assert_eq!(
        gateway
            .pull_whatsapp_media(id, &inbound.route_key, &selection.hub_id)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn media_pull_rechecks_binding_after_provider_download() {
    let root = tempfile::tempdir().unwrap();
    let mut config = AppConfig::from_env();
    config.data_dir = root.path().join("sessions");
    config.state_dir = root.path().join("state");
    config.cloud_relay_url.clear();
    config.cloud_relay_region.clear();
    config.harborbeacon_token = "fixture-service-token".into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.harborbeacon_base_url = format!("http://{}", listener.local_addr().unwrap());

    let adapter = image_adapter(config.state_dir.join("attachment-cache"));
    let payload = json!({"phone_number_id":"123","message":{"from":"15555550101",
        "id":"wamid.image.revoked","timestamp":chrono::Utc::now().timestamp().to_string(),
        "type":"image","image":{"id":"2754859441498130","mime_type":"image/jpeg",
        "sha256":"e".repeat(64)}}});
    let inbound = adapter.normalize_inbound(payload.clone()).unwrap();
    adapter
        .stage_inbound_media(&payload, &inbound, None, "conv-image-revoked")
        .unwrap();
    let attachment_id = inbound.attachments[0]["attachment_id"]
        .as_str()
        .unwrap()
        .to_string();
    let route_key = inbound.route_key.clone();

    let status = Arc::new(AtomicUsize::new(200));
    let calls = Arc::new(AtomicUsize::new(0));
    let expected_route = route_key.clone();
    let current = status.clone();
    let count = calls.clone();
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/api/im/whatsapp/delivery-authorization",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                    let current = current.clone();
                    let count = count.clone();
                    let expected_route = expected_route.clone();
                    async move {
                        assert_eq!(
                            headers.get("authorization").unwrap(),
                            "Bearer fixture-service-token"
                        );
                        assert_eq!(headers.get("x-contract-version").unwrap(), "2.0");
                        assert_eq!(body["route_key"], expected_route);
                        assert_eq!(body["conversation_handle"], "conv-image-revoked");
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
    let mut gateway = GatewayService::from_config(&config).unwrap();
    gateway.whatsapp_adapter = adapter;
    let revoked = status.clone();
    let checked = calls.clone();
    let error = gateway
        .pull_whatsapp_media_with(&attachment_id, &route_key, "local", move |_| async move {
            assert_eq!(checked.load(Ordering::SeqCst), 1);
            revoked.store(403, Ordering::SeqCst);
            Ok(InboundMediaBytes {
                bytes: b"private photo bytes".to_vec(),
                mime_type: "image/jpeg".into(),
                sha256: "e".repeat(64),
            })
        })
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
}
