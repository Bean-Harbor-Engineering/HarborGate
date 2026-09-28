use super::*;
use crate::adapters::whatsapp::WhatsAppConfig;
use crate::cloud_relay::CloudRelayClient;
use crate::navi_fleet::NaviFleet;
use serde_json::json;

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
