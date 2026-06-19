#![allow(dead_code)]

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result};
use dashmap::DashMap;
use matrix_sdk_crypto::{
    AttachmentDecryptor, AttachmentEncryptor, DecryptionSettings, EncryptionSettings,
    EncryptionSyncChanges, MediaEncryptionInfo, OlmMachine, TrustRequirement,
    types::{
        events::room::encrypted::EncryptedEvent,
        requests::{AnyIncomingResponse, AnyOutgoingRequest, ToDeviceRequest},
    },
};
use reqwest::Client as HttpClient;
use ruma::{
    api::client::{
        keys::{
            claim_keys::v3::Response as KeysClaimResponse,
            get_keys::v3::Response as KeysQueryResponse,
            upload_keys::v3::Response as KeysUploadResponse,
        },
        sync::sync_events::DeviceLists,
        to_device::send_event_to_device::v3::Response as ToDeviceResponse,
    },
    events::AnyToDeviceEvent,
    serde::Raw,
    OneTimeKeyAlgorithm, OwnedDeviceId, OwnedUserId, RoomId, UInt, UserId,
};
use serde::Deserialize;
use serde_json::{json, value::to_raw_value, Value};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{
    config::ServerConfig,
    messages::{DaemonToUi, UiToDaemon},
    store::PanStore,
};

/// Per-user crypto + session state, one per logged-in user.
///
/// `OlmMachine` is `Clone` (Arc-backed) and internally synchronized; no
/// external Mutex is needed.
pub struct PanClient {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    server_conf: ServerConfig,
    store: Arc<PanStore>,
    olm: OlmMachine,
    http_client: HttpClient,
    /// Rooms known to have m.room.encryption enabled (populated from sync state).
    encrypted_rooms: DashMap<String, bool>,
    ui_tx: Option<mpsc::Sender<DaemonToUi>>,
    pan_rx: Option<tokio::sync::Mutex<mpsc::Receiver<UiToDaemon>>>,
}

impl PanClient {
    pub async fn new(
        user_id: String,
        device_id: String,
        access_token: String,
        server_conf: ServerConfig,
        store: Arc<PanStore>,
        http_client: HttpClient,
        ui_tx: Option<mpsc::Sender<DaemonToUi>>,
        pan_rx: Option<mpsc::Receiver<UiToDaemon>>,
    ) -> Result<Self> {
        let ruma_uid = UserId::parse(&user_id)
            .with_context(|| format!("invalid user_id {user_id:?}"))?;
        let ruma_did = OwnedDeviceId::from(device_id.as_str());
        let olm = OlmMachine::new(&ruma_uid, ruma_did.as_ref()).await;

        Ok(Self {
            user_id,
            device_id,
            access_token,
            server_conf,
            store,
            olm,
            http_client,
            encrypted_rooms: DashMap::new(),
            ui_tx,
            pan_rx: pan_rx.map(tokio::sync::Mutex::new),
        })
    }

    pub fn mark_room_encrypted(&self, room_id: &str) {
        self.encrypted_rooms.insert(room_id.to_owned(), true);
    }

    pub fn is_room_encrypted(&self, room_id: &str) -> bool {
        self.encrypted_rooms.get(room_id).map(|v| *v).unwrap_or(false)
    }

    /// No background sync loop needed — the proxy intercepts sync calls.
    pub async fn start_sync(self: Arc<Self>) {
        debug!(user_id = %self.user_id, "PanClient ready");
    }

    // -----------------------------------------------------------------------
    // Sync interception
    // -----------------------------------------------------------------------

    /// Process a homeserver sync response in-place.
    ///
    /// 1. Extracts to-device events / device lists / OTK counts and feeds them
    ///    to the OlmMachine (`receive_sync_changes`).
    /// 2. Flushes any pending outgoing crypto requests (key upload/query/claim,
    ///    to-device messages) back to the homeserver.
    /// 3. Tracks rooms that gain `m.room.encryption` state.
    /// 4. Decrypts `m.room.encrypted` timeline events, replacing them with
    ///    their cleartext equivalents in the JSON.
    pub async fn process_sync(&self, body: &mut Value) -> Result<()> {
        // Step 1 — collect crypto inputs from the sync response
        let to_device_events: Vec<Raw<AnyToDeviceEvent>> = body
            .pointer("/to_device/events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| Some(Raw::from_json(to_raw_value(&e).ok()?)))
            .collect();

        let device_lists: DeviceLists = body
            .get("device_lists")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let otk_counts: BTreeMap<OneTimeKeyAlgorithm, UInt> = body
            .get("device_one_time_keys_count")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let next_batch = body
            .get("next_batch")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Step 2 — feed to OlmMachine
        let decryption_settings = DecryptionSettings {
            sender_device_trust_requirement: TrustRequirement::Untrusted,
        };
        let sync_changes = EncryptionSyncChanges {
            to_device_events,
            changed_devices: &device_lists,
            one_time_keys_counts: &otk_counts,
            unused_fallback_keys: None,
            next_batch_token: next_batch,
        };
        if let Err(e) = self.olm.receive_sync_changes(sync_changes, &decryption_settings).await {
            warn!("OlmMachine receive_sync_changes: {e}");
        }

        // Step 3 — flush outgoing crypto requests
        self.process_outgoing_requests().await;

        // Step 4 — track encryption-enabled rooms
        if let Some(join) = body.pointer("/rooms/join").and_then(|r| r.as_object()) {
            for (room_id, room_data) in join {
                for section in &["/state/events", "/timeline/events"] {
                    if let Some(events) =
                        room_data.pointer(section).and_then(|e| e.as_array())
                    {
                        for event in events {
                            if event.get("type").and_then(|t| t.as_str())
                                == Some("m.room.encryption")
                            {
                                self.mark_room_encrypted(room_id);
                            }
                        }
                    }
                }
            }
        }

        // Step 5 — decrypt m.room.encrypted timeline events
        let room_ids: Vec<String> = body
            .pointer("/rooms/join")
            .and_then(|r| r.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();

        for room_id_str in room_ids {
            let room_id = match RoomId::parse(&room_id_str) {
                Ok(id) => id,
                Err(_) => continue,
            };

            let events_ptr = format!("/rooms/join/{room_id_str}/timeline/events");
            let events = match body
                .pointer_mut(&events_ptr)
                .and_then(|e| e.as_array_mut())
            {
                Some(e) => e,
                None => continue,
            };

            for event in events.iter_mut() {
                if event.get("type").and_then(|t| t.as_str()) != Some("m.room.encrypted") {
                    continue;
                }

                let raw_json = match to_raw_value(event) {
                    Ok(j) => j,
                    Err(e) => {
                        warn!("serialize encrypted event: {e}");
                        continue;
                    }
                };
                let raw_event: Raw<EncryptedEvent> = Raw::from_json(raw_json);

                match self
                    .olm
                    .decrypt_room_event(&raw_event, &room_id, &decryption_settings)
                    .await
                {
                    Ok(decrypted) => match serde_json::to_value(&decrypted.event) {
                        Ok(mut cleartext) => {
                            for field in
                                ["event_id", "origin_server_ts", "sender", "room_id", "unsigned"]
                            {
                                if let Some(val) = event.get(field) {
                                    cleartext[field] = val.clone();
                                }
                            }
                            *event = cleartext;
                        }
                        Err(e) => warn!("serialize decrypted event: {e}"),
                    },
                    Err(e) => debug!("decrypt {room_id_str}: {e}"),
                }
            }
        }

        Ok(())
    }

    /// Decrypt a paginated-history event (same logic as sync timeline decryption).
    pub async fn decrypt_event(&self, room_id: &str, event: &Value) -> Option<Value> {
        let room_id = RoomId::parse(room_id).ok()?;
        let raw_event: Raw<EncryptedEvent> =
            Raw::from_json(to_raw_value(event).ok()?);
        let decryption_settings = DecryptionSettings {
            sender_device_trust_requirement: TrustRequirement::Untrusted,
        };
        let decrypted = self
            .olm
            .decrypt_room_event(&raw_event, &room_id, &decryption_settings)
            .await
            .ok()?;
        let mut cleartext = serde_json::to_value(&decrypted.event).ok()?;
        for field in ["event_id", "origin_server_ts", "sender", "room_id", "unsigned"] {
            if let Some(val) = event.get(field) {
                cleartext[field] = val.clone();
            }
        }
        Some(cleartext)
    }

    // -----------------------------------------------------------------------
    // Send interception
    // -----------------------------------------------------------------------

    /// Prepare a room event for sending.
    ///
    /// If the room is known to be E2E-encrypted, claims any missing OTKs,
    /// shares the room key, and returns `("m.room.encrypted", encrypted_json)`.
    /// Otherwise returns the original `(event_type, content)` unchanged.
    pub async fn prepare_and_encrypt(
        &self,
        room_id: &str,
        event_type: &str,
        mut content: Value,
    ) -> Result<(String, Value)> {
        if !self.is_room_encrypted(room_id) {
            return Ok((event_type.to_owned(), content));
        }

        // Inject encryption keys for any attached media before encrypting
        self.inject_media_keys(room_id, &mut content).await?;

        let ruma_room_id = RoomId::parse(room_id)?;
        let users = self.get_room_member_ids(&ruma_room_id).await?;

        // Claim missing 1-to-1 Olm sessions
        if let Some((txn_id, claim_req)) = self
            .olm
            .get_missing_sessions(users.iter().map(AsRef::as_ref))
            .await?
        {
            let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
            self.send_keys_claim(base, &self.access_token, &claim_req, &txn_id)
                .await?;
            self.process_outgoing_requests().await;
        }

        // Share the Megolm outbound session with all room members
        let share_reqs = self
            .olm
            .share_room_key(
                &ruma_room_id,
                users.iter().map(AsRef::as_ref),
                EncryptionSettings::default(),
            )
            .await?;

        let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
        for req in &share_reqs {
            let txn_id = req.txn_id.clone();
            if let Err(e) = self
                .send_to_device(base, &self.access_token, req, &txn_id)
                .await
            {
                warn!("share_room_key to-device: {e}");
            }
        }

        // Encrypt
        let raw_content: Raw<ruma::events::AnyMessageLikeEventContent> =
            Raw::from_json(to_raw_value(&content)?);
        let encrypted = self
            .olm
            .encrypt_room_event_raw(&ruma_room_id, event_type, &raw_content)
            .await?;
        let encrypted_value = serde_json::to_value(&encrypted)?;

        Ok(("m.room.encrypted".to_owned(), encrypted_value))
    }

    // -----------------------------------------------------------------------
    // Outgoing crypto request pump
    // -----------------------------------------------------------------------

    async fn process_outgoing_requests(&self) {
        let requests = match self.olm.outgoing_requests().await {
            Ok(r) => r,
            Err(e) => {
                warn!("outgoing_requests: {e}");
                return;
            }
        };

        let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
        let token = &self.access_token;

        for req in requests {
            let id = req.request_id().to_owned();
            let result = match req.request() {
                AnyOutgoingRequest::KeysUpload(r) => {
                    self.send_keys_upload(base, token, r, &id).await
                }
                AnyOutgoingRequest::KeysQuery(r) => {
                    self.send_keys_query(base, token, r, &id).await
                }
                AnyOutgoingRequest::KeysClaim(r) => {
                    self.send_keys_claim(base, token, r, &id).await
                }
                AnyOutgoingRequest::ToDeviceRequest(r) => {
                    self.send_to_device(base, token, r, &id).await
                }
                // SignatureUpload / RoomMessage: Phase 5 (SAS verification)
                _ => Ok(()),
            };

            if let Err(e) = result {
                warn!(%id, "outgoing crypto request failed: {e}");
            }
        }
    }

    async fn send_keys_upload(
        &self,
        base: &str,
        token: &str,
        req: &ruma::api::client::keys::upload_keys::v3::Request,
        request_id: &ruma::TransactionId,
    ) -> Result<()> {
        // Serialize only the body fields the spec expects.
        let body = json!({
            "device_keys": req.device_keys,
            "one_time_keys": req.one_time_keys,
            "fallback_keys": req.fallback_keys,
        });
        let resp_bytes = self
            .http_client
            .post(format!("{base}/_matrix/client/v3/keys/upload"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .bytes()
            .await?;

        let json: Value = serde_json::from_slice(&resp_bytes)?;
        let counts: BTreeMap<OneTimeKeyAlgorithm, UInt> = json
            .get("one_time_key_counts")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let ruma_resp = KeysUploadResponse::new(counts);
        self.olm
            .mark_request_as_sent(request_id, AnyIncomingResponse::KeysUpload(&ruma_resp))
            .await
            .context("mark keys_upload sent")
    }

    async fn send_keys_query(
        &self,
        base: &str,
        token: &str,
        req: &matrix_sdk_crypto::types::requests::KeysQueryRequest,
        request_id: &ruma::TransactionId,
    ) -> Result<()> {
        let body = json!({ "device_keys": req.device_keys });
        let resp_bytes = self
            .http_client
            .post(format!("{base}/_matrix/client/v3/keys/query"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .bytes()
            .await?;

        let json: Value = serde_json::from_slice(&resp_bytes)?;

        let mut ruma_resp = KeysQueryResponse::default();
        if let Some(v) = json.get("device_keys") {
            ruma_resp.device_keys = serde_json::from_value(v.clone()).unwrap_or_default();
        }
        if let Some(v) = json.get("master_keys") {
            ruma_resp.master_keys = serde_json::from_value(v.clone()).unwrap_or_default();
        }
        if let Some(v) = json.get("self_signing_keys") {
            ruma_resp.self_signing_keys = serde_json::from_value(v.clone()).unwrap_or_default();
        }
        if let Some(v) = json.get("user_signing_keys") {
            ruma_resp.user_signing_keys = serde_json::from_value(v.clone()).unwrap_or_default();
        }

        self.olm
            .mark_request_as_sent(request_id, AnyIncomingResponse::KeysQuery(&ruma_resp))
            .await
            .context("mark keys_query sent")
    }

    async fn send_keys_claim(
        &self,
        base: &str,
        token: &str,
        req: &ruma::api::client::keys::claim_keys::v3::Request,
        request_id: &ruma::TransactionId,
    ) -> Result<()> {
        let body = json!({ "one_time_keys": req.one_time_keys });
        let resp_bytes = self
            .http_client
            .post(format!("{base}/_matrix/client/v3/keys/claim"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .bytes()
            .await?;

        let json: Value = serde_json::from_slice(&resp_bytes)?;
        let one_time_keys = json
            .get("one_time_keys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let ruma_resp = KeysClaimResponse::new(one_time_keys);
        self.olm
            .mark_request_as_sent(request_id, AnyIncomingResponse::KeysClaim(&ruma_resp))
            .await
            .context("mark keys_claim sent")
    }

    async fn send_to_device(
        &self,
        base: &str,
        token: &str,
        req: &ToDeviceRequest,
        request_id: &ruma::TransactionId,
    ) -> Result<()> {
        let event_type = req.event_type.to_string();
        let txn_id = req.txn_id.as_str();
        let body = json!({ "messages": req.messages });

        self.http_client
            .put(format!("{base}/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        let ruma_resp = ToDeviceResponse::new();
        self.olm
            .mark_request_as_sent(request_id, AnyIncomingResponse::ToDevice(&ruma_resp))
            .await
            .context("mark to_device sent")
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    async fn get_room_member_ids(&self, room_id: &RoomId) -> Result<Vec<OwnedUserId>> {
        #[derive(Deserialize)]
        struct Resp {
            joined: BTreeMap<OwnedUserId, Value>,
        }

        let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
        let resp: Resp = self
            .http_client
            .get(format!("{base}/_matrix/client/v3/rooms/{room_id}/joined_members"))
            .bearer_auth(&self.access_token)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp.joined.into_keys().collect())
    }

    // -----------------------------------------------------------------------
    // Phase 4 — media encryption
    // -----------------------------------------------------------------------

    /// Encrypt raw bytes (a media upload) using AES-256-CTR.
    ///
    /// Returns `(ciphertext, MediaEncryptionInfo)`.  Runs in a blocking
    /// thread so the event loop is not stalled by the I/O-bound cipher loop.
    pub async fn encrypt_attachment(
        data: bytes::Bytes,
    ) -> Result<(bytes::Bytes, MediaEncryptionInfo)> {
        tokio::task::spawn_blocking(move || {
            let mut cursor = std::io::Cursor::new(data.as_ref());
            let mut encryptor = AttachmentEncryptor::new(&mut cursor);
            let mut ciphertext = Vec::new();
            std::io::Read::read_to_end(&mut encryptor, &mut ciphertext)?;
            let info = encryptor.finish();
            Ok((bytes::Bytes::from(ciphertext), info))
        })
        .await?
    }

    /// Decrypt a previously encrypted attachment.
    ///
    /// `info` must match the `MediaEncryptionInfo` produced at upload time.
    /// Runs in a blocking thread to avoid stalling the event loop.
    pub async fn decrypt_attachment(
        data: bytes::Bytes,
        info: MediaEncryptionInfo,
    ) -> Result<bytes::Bytes> {
        tokio::task::spawn_blocking(move || {
            let mut cursor = std::io::Cursor::new(data.as_ref());
            let mut decryptor = AttachmentDecryptor::new(&mut cursor, info)
                .map_err(|e| anyhow::anyhow!("AttachmentDecryptor::new: {e}"))?;
            let mut plaintext = Vec::new();
            std::io::Read::read_to_end(&mut decryptor, &mut plaintext)?;
            Ok(bytes::Bytes::from(plaintext))
        })
        .await?
    }

    /// If `content["url"]` is an mxc URI for which we stored encryption keys,
    /// transform the content so it uses `"file"` instead of `"url"`, ready for
    /// embedding in an encrypted event.
    ///
    /// No-op if the URL is not recognised or the room is not E2E.
    pub async fn inject_media_keys(
        &self,
        room_id: &str,
        content: &mut Value,
    ) -> Result<()> {
        if !self.is_room_encrypted(room_id) {
            return Ok(());
        }
        let url = match content.get("url").and_then(|v| v.as_str()) {
            Some(u) if u.starts_with("mxc://") => u.to_owned(),
            _ => return Ok(()),
        };

        // Parse mxc://server/path
        let without_prefix = url.trim_start_matches("mxc://");
        let slash = match without_prefix.find('/') {
            Some(i) => i,
            None => return Ok(()),
        };
        let mxc_server = &without_prefix[..slash];
        let mxc_path = &without_prefix[slash + 1..];

        let media = match self.store.load_media(&self.server_conf.name, mxc_server, mxc_path).await? {
            Some(m) => m,
            None => return Ok(()),
        };

        // Build the EncryptedFile object the spec expects
        let file_obj = serde_json::json!({
            "url": url,
            "key": media.key,
            "iv": media.iv,
            "hashes": media.hashes,
            "v": "v2"
        });

        if let Some(obj) = content.as_object_mut() {
            obj.remove("url");
            obj.insert("file".to_owned(), file_obj);
        }

        Ok(())
    }
}
