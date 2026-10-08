//! Private final check for member-owned platform notifications; business state stays Native-owned.
use super::*;
impl HarborBeaconTaskClient {
    pub(crate) async fn authorize_peer_delivery(
        &self,
        outbound: &OutboundMessage,
    ) -> Result<(), GatewayError> {
        let denied = || {
            GatewayError::new(
                StatusCode::FORBIDDEN,
                "IM_DELIVERY_NOT_ALLOWED",
                "Member notification permission no longer permits this delivery",
            )
        };
        let unavailable = || {
            GatewayError::infrastructure(
                "Member notification delivery check is temporarily unavailable",
            )
        };
        let handle = outbound
            .metadata
            .get("conversation_handle")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(denied)?;
        let transport_route = outbound
            .metadata
            .get("route_key")
            .and_then(Value::as_str)
            .ok_or_else(denied)?;
        let route = if outbound.platform == "feishu_mail" {
            if !transport_route.is_empty()
                || outbound.metadata.get("route_mode").and_then(Value::as_str) != Some("proactive")
            {
                return Err(denied());
            }
            crate::adapters::feishu_mail::validate_member_reminder_recipient(outbound)?;
            "member-email"
        } else {
            if transport_route.is_empty() {
                return Err(denied());
            }
            transport_route
        };
        if !matches!(
            outbound.platform.as_str(),
            "feishu" | "weixin" | "feishu_mail"
        ) || self.cloud_relay.is_some()
        {
            return Err(denied());
        }
        let request = json!({"platform":outbound.platform,"delivery":{"recipient":outbound.chat_id,"route_key":route,
            "conversation_handle":handle,"text":outbound.text,"has_attachments":!outbound.attachments.is_empty(),"source_refs":[]}});
        let mut response = self
            .http
            .post(format!(
                "{}/api/im/peer/delivery-authorization",
                self.base_url
            ))
            .bearer_auth(&self.api_token)
            .header("X-Contract-Version", &self.contract_version)
            .timeout(Duration::from_secs(5))
            .json(&request)
            .send()
            .await
            .map_err(|_| unavailable())?;
        if matches!(
            response.status().as_u16(),
            400 | 401 | 403 | 404 | 410 | 422
        ) {
            return Err(denied());
        }
        if response.status() != StatusCode::OK {
            return Err(unavailable());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len() + chunk.len() > 4096 {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        if value["allowed"] != true {
            return Err(denied());
        }
        Ok(())
    }
}
