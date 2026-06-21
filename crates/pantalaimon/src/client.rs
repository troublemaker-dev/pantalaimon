#![allow(dead_code)]

use std::{collections::{BTreeMap, HashMap}, sync::Arc};

use anyhow::{Context, Result};
use dashmap::DashMap;
use matrix_sdk_crypto::{
    AttachmentDecryptor, AttachmentEncryptor, DecryptionSettings, EncryptionSettings,
    EncryptionSyncChanges, LocalTrust, MediaEncryptionInfo, OlmMachine, Sas,
    TrustRequirement,
    types::{
        events::room::encrypted::EncryptedEvent,
        requests::{
            AnyIncomingResponse, AnyOutgoingRequest, OutgoingVerificationRequest,
            RoomMessageRequest, ToDeviceRequest,
        },
    },
};
use reqwest::Client as HttpClient;
use ruma::{
    api::client::{
        keys::{
            claim_keys::v3::Response as KeysClaimResponse,
            get_keys::v3::Response as KeysQueryResponse,
            upload_keys::v3::Response as KeysUploadResponse,
            upload_signatures::v3::Response as SignatureUploadResponse,
        },
        message::send_message_event::v3::Response as RoomMessageResponse,
        sync::sync_events::DeviceLists,
        to_device::send_event_to_device::v3::Response as ToDeviceResponse,
    },
    events::{AnyToDeviceEvent, MessageLikeEventContent as _},
    serde::Raw,
    EventId, OneTimeKeyAlgorithm, OwnedDeviceId, OwnedUserId, RoomId, UInt, UserId,
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

    // Phase 5 — SAS verification state
    /// Active SAS flows keyed by "{user_id}:{device_id}".
    active_sas: DashMap<String, Sas>,
    /// Outgoing requests we initiated, keyed by flow_id → user_id string.
    /// Checked each sync to call start_sas() once the remote accepts.
    pending_requests: DashMap<String, String>,
    /// flow_ids for which we have already emitted SasInvite.
    notified_invite: DashMap<String, ()>,
    /// "{user_id}:{device_id}" keys for which we have already emitted SasShow.
    notified_show: DashMap<String, ()>,
    /// "{user_id}:{device_id}" keys for which we have already emitted SasDone.
    notified_done: DashMap<String, ()>,
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
            active_sas: DashMap::new(),
            pending_requests: DashMap::new(),
            notified_invite: DashMap::new(),
            notified_show: DashMap::new(),
            notified_done: DashMap::new(),
        })
    }

    pub fn mark_room_encrypted(&self, room_id: &str) {
        self.encrypted_rooms.insert(room_id.to_owned(), true);
    }

    pub fn is_room_encrypted(&self, room_id: &str) -> bool {
        self.encrypted_rooms.get(room_id).map(|v| *v).unwrap_or(false)
    }

    /// No background loop needed — sync is intercepted by the proxy.
    /// UI commands arrive via the shared `message_router` task in main.
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
        let t0 = std::time::Instant::now();
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
        debug!(elapsed_ms = t0.elapsed().as_millis(), "receive_sync_changes");

        // Step 3 — outgoing crypto requests are flushed after the response is
        // returned (see run_post_sync_tasks), so skip them here.

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
        let t_decrypt = std::time::Instant::now();
        let room_ids: Vec<String> = body
            .pointer("/rooms/join")
            .and_then(|r| r.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let n_rooms = room_ids.len();

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

        debug!(elapsed_ms = t_decrypt.elapsed().as_millis(), rooms = n_rooms, "decrypt loop");

        // Step 6 — detect new incoming verification requests
        self.check_incoming_verifications(body).await;

        // Steps 6-7 (check_pending_requests, check_sas_states) are also
        // deferred to run_post_sync_tasks.

        debug!(elapsed_ms = t0.elapsed().as_millis(), "process_sync total");
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
    // Post-sync background work
    // -----------------------------------------------------------------------

    /// Flush outgoing crypto requests and advance verification flows.
    /// Called from the sync handler in a spawned task so the sync response
    /// is returned to the client before any homeserver round-trips happen.
    pub async fn run_post_sync_tasks(self: std::sync::Arc<Self>) {
        self.process_outgoing_requests().await;
        self.check_pending_requests().await;
        self.check_sas_states().await;
    }

    // -----------------------------------------------------------------------
    // Outgoing crypto request pump
    // -----------------------------------------------------------------------

    pub async fn process_outgoing_requests(&self) {
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
                AnyOutgoingRequest::SignatureUpload(r) => {
                    self.send_signature_upload(base, token, r, &id).await
                }
                AnyOutgoingRequest::RoomMessage(r) => {
                    self.send_room_message(base, token, r, &id).await
                }
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

    // -----------------------------------------------------------------------
    // Phase 5 — SAS device verification
    // -----------------------------------------------------------------------

    /// Send a signal to the UI layer (no-op if no channel is configured).
    async fn emit(&self, msg: DaemonToUi) {
        if let Some(tx) = &self.ui_tx {
            let _ = tx.send(msg).await;
        }
    }

    /// Dispatch a command received from the D-Bus layer.
    pub async fn handle_ui_command(&self, cmd: UiToDaemon) {
        let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
        let token = &self.access_token;

        macro_rules! respond {
            ($mid:expr, $code:expr, $msg:expr) => {
                self.emit(DaemonToUi::Response {
                    message_id: $mid,
                    pan_user: self.user_id.clone(),
                    code: $code.into(),
                    message: $msg.into(),
                })
                .await
            };
        }

        match cmd {
            UiToDaemon::StartSas { message_id, user_id, device_id, .. } => {
                match self.start_sas_for_device(base, token, &user_id, &device_id).await {
                    Ok(()) => respond!(message_id, "M_OK", "SAS request sent"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::AcceptSas { message_id, user_id, device_id, .. } => {
                match self.accept_sas_from_device(base, token, &user_id, &device_id).await {
                    Ok(()) => respond!(message_id, "M_OK", "SAS accepted"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::ConfirmSas { message_id, user_id, device_id, .. } => {
                match self.confirm_sas_with_device(base, token, &user_id, &device_id).await {
                    Ok(()) => respond!(message_id, "M_OK", "SAS confirmed"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::CancelSas { message_id, user_id, device_id, .. } => {
                match self.cancel_sas_with_device(base, token, &user_id, &device_id).await {
                    Ok(()) => respond!(message_id, "M_OK", "SAS cancelled"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::VerifyDevice { message_id, user_id, device_id, .. } => {
                match self.set_device_trust(&user_id, &device_id, LocalTrust::Verified).await {
                    Ok(()) => respond!(message_id, "M_OK", "Device verified"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::UnverifyDevice { message_id, user_id, device_id, .. } => {
                match self.set_device_trust(&user_id, &device_id, LocalTrust::Unset).await {
                    Ok(()) => respond!(message_id, "M_OK", "Device unverified"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::BlacklistDevice { message_id, user_id, device_id, .. } => {
                match self.set_device_trust(&user_id, &device_id, LocalTrust::BlackListed).await {
                    Ok(()) => respond!(message_id, "M_OK", "Device blacklisted"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            UiToDaemon::UnblacklistDevice { message_id, user_id, device_id, .. } => {
                match self.set_device_trust(&user_id, &device_id, LocalTrust::Unset).await {
                    Ok(()) => respond!(message_id, "M_OK", "Device unblacklisted"),
                    Err(e) => respond!(message_id, "M_UNKNOWN", e.to_string()),
                }
            }
            // Key import/export and key-share decisions: Phase 7
            UiToDaemon::ImportKeys { message_id, .. } => {
                respond!(message_id, "M_NOT_IMPLEMENTED", "Key import: Phase 7");
            }
            UiToDaemon::ExportKeys { message_id, .. } => {
                respond!(message_id, "M_NOT_IMPLEMENTED", "Key export: Phase 7");
            }
            UiToDaemon::ContinueKeyShare { message_id, .. } => {
                respond!(message_id, "M_NOT_IMPLEMENTED", "Key share: Phase 7");
            }
            UiToDaemon::CancelKeyShare { message_id, .. } => {
                respond!(message_id, "M_NOT_IMPLEMENTED", "Key share: Phase 7");
            }
            // SendAnyways / CancelSending are handled by ProxyDaemon, not PanClient
            UiToDaemon::SendAnyways { .. } | UiToDaemon::CancelSending { .. } => {}
        }
    }

    /// Initiate outgoing SAS verification with a specific remote device.
    async fn start_sas_for_device(
        &self,
        base: &str,
        token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<()> {
        let uid = UserId::parse(user_id)?;
        let did = OwnedDeviceId::from(device_id);
        let device = self
            .olm
            .get_device(&uid, &did, None)
            .await?
            .with_context(|| format!("device {device_id} not found for {user_id}"))?;

        let (verification_request, outgoing) = device.request_verification();
        self.send_outgoing_verification(base, token, &outgoing).await;

        // Record the flow_id so check_pending_requests calls start_sas when ready.
        let flow_id = verification_request.flow_id().as_str().to_owned();
        self.pending_requests.insert(flow_id, user_id.to_owned());

        Ok(())
    }

    /// Accept an incoming SAS verification request from a remote device.
    async fn accept_sas_from_device(
        &self,
        base: &str,
        token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<()> {
        let uid = UserId::parse(user_id)?;
        let request = self
            .olm
            .get_verification_requests(&uid)
            .into_iter()
            .find(|r| {
                r.other_device_id()
                    .as_deref()
                    .map(|d| d.as_str() == device_id)
                    .unwrap_or(false)
                    && !r.is_done()
                    && !r.we_started()
            })
            .with_context(|| {
                format!("no pending verification request from {user_id}:{device_id}")
            })?;

        // Sends m.key.verification.ready
        if let Some(outgoing) = request.accept() {
            self.send_outgoing_verification(base, token, &outgoing).await;
        }

        // Sends m.key.verification.start, gives us the Sas object
        if let Some((sas, outgoing)) = request.start_sas().await? {
            self.send_outgoing_verification(base, token, &outgoing).await;
            self.active_sas
                .insert(format!("{user_id}:{device_id}"), sas);
        }

        Ok(())
    }

    /// Confirm that the SAS emoji/decimals match (sends MAC).
    async fn confirm_sas_with_device(
        &self,
        base: &str,
        token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<()> {
        let key = format!("{user_id}:{device_id}");
        let sas = self
            .active_sas
            .get(&key)
            .map(|e| e.clone())
            .with_context(|| format!("no active SAS with {user_id}:{device_id}"))?;

        let (requests, sig_req) = sas.confirm().await?;
        for req in &requests {
            self.send_outgoing_verification(base, token, req).await;
        }
        if let Some(sig) = sig_req {
            let txn_id = ruma::TransactionId::new();
            if let Err(e) = self.send_signature_upload(base, token, &sig, &txn_id).await {
                warn!("signature upload after SAS confirm: {e}");
            }
        }

        Ok(())
    }

    /// Cancel an active SAS flow.
    async fn cancel_sas_with_device(
        &self,
        base: &str,
        token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<()> {
        let key = format!("{user_id}:{device_id}");
        if let Some((_, sas)) = self.active_sas.remove(&key) {
            if let Some(outgoing) = sas.cancel() {
                self.send_outgoing_verification(base, token, &outgoing).await;
            }
        }
        Ok(())
    }

    /// Set the local trust level of a specific device.
    async fn set_device_trust(
        &self,
        user_id: &str,
        device_id: &str,
        trust: LocalTrust,
    ) -> Result<()> {
        let uid = UserId::parse(user_id)?;
        let did = OwnedDeviceId::from(device_id);
        let device = self
            .olm
            .get_device(&uid, &did, None)
            .await?
            .with_context(|| format!("device {device_id} not found for {user_id}"))?;
        device.set_local_trust(trust).await?;
        Ok(())
    }

    /// Scan to-device events in the sync body for incoming verification requests
    /// and emit a `SasInvite` signal for each new one.
    async fn check_incoming_verifications(&self, body: &Value) {
        let events = match body.pointer("/to_device/events").and_then(|v| v.as_array()) {
            Some(e) => e.clone(),
            None => return,
        };

        for event in &events {
            if event.get("type").and_then(|t| t.as_str()) != Some("m.key.verification.request") {
                continue;
            }
            let sender = match event.get("sender").and_then(|s| s.as_str()) {
                Some(s) => s.to_owned(),
                None => continue,
            };
            let txn_id = match event
                .get("content")
                .and_then(|c| c.get("transaction_id"))
                .and_then(|t| t.as_str())
            {
                Some(t) => t.to_owned(),
                None => continue,
            };

            if self.notified_invite.contains_key(&txn_id) {
                continue;
            }

            let uid = match UserId::parse(&sender) {
                Ok(u) => u,
                Err(_) => continue,
            };

            if let Some(req) = self.olm.get_verification_request(&uid, &txn_id) {
                self.notified_invite.insert(txn_id.clone(), ());
                let device_id = req
                    .other_device_id()
                    .map(|d| d.to_string())
                    .unwrap_or_default();
                self.emit(DaemonToUi::SasInvite {
                    pan_user: self.user_id.clone(),
                    user_id: sender,
                    device_id,
                    transaction_id: txn_id,
                })
                .await;
            }
        }
    }

    /// For outgoing requests we started, call start_sas() once the remote has
    /// accepted (request becomes ready).
    pub async fn check_pending_requests(&self) {
        let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
        let token = &self.access_token;
        let mut to_remove = Vec::new();

        for entry in self.pending_requests.iter() {
            let flow_id = entry.key().clone();
            let user_id_str = entry.value().clone();

            let uid = match UserId::parse(&user_id_str) {
                Ok(u) => u,
                Err(_) => {
                    to_remove.push(flow_id);
                    continue;
                }
            };

            let req = match self.olm.get_verification_request(&uid, &flow_id) {
                Some(r) => r,
                None => {
                    to_remove.push(flow_id);
                    continue;
                }
            };

            if req.is_done() || req.is_cancelled() {
                to_remove.push(flow_id);
                continue;
            }

            if req.is_ready() {
                match req.start_sas().await {
                    Ok(Some((sas, outgoing))) => {
                        self.send_outgoing_verification(base, token, &outgoing).await;
                        let device_id = sas.other_device_id().to_string();
                        self.active_sas
                            .insert(format!("{user_id_str}:{device_id}"), sas);
                        to_remove.push(flow_id);
                    }
                    Ok(None) => {} // not ready yet
                    Err(e) => {
                        warn!("start_sas on pending request: {e}");
                        to_remove.push(flow_id);
                    }
                }
            }
        }

        for key in to_remove {
            self.pending_requests.remove(&key);
        }
    }

    /// Check all active SAS flows and emit SasShow / SasDone signals as state
    /// advances.
    pub async fn check_sas_states(&self) {
        let mut to_remove = Vec::new();

        for entry in self.active_sas.iter() {
            let key = entry.key().clone();
            let sas = entry.value().clone();

            if sas.is_cancelled() || sas.is_done() {
                if !self.notified_done.contains_key(&key) {
                    self.notified_done.insert(key.clone(), ());
                    self.emit(DaemonToUi::SasDone {
                        pan_user: self.user_id.clone(),
                        user_id: sas.other_user_id().to_string(),
                        device_id: sas.other_device_id().to_string(),
                        transaction_id: sas.flow_id().as_str().to_owned(),
                    })
                    .await;
                }
                to_remove.push(key);
                continue;
            }

            if let Some(emojis) = sas.emoji() {
                if !self.notified_show.contains_key(&key) {
                    self.notified_show.insert(key.clone(), ());
                    let emoji_vec: Vec<(String, String)> = emojis
                        .iter()
                        .map(|e| (e.symbol.to_owned(), e.description.to_owned()))
                        .collect();
                    self.emit(DaemonToUi::SasShow {
                        pan_user: self.user_id.clone(),
                        user_id: sas.other_user_id().to_string(),
                        device_id: sas.other_device_id().to_string(),
                        transaction_id: sas.flow_id().as_str().to_owned(),
                        emoji: emoji_vec,
                    })
                    .await;
                }
            }
        }

        for key in to_remove {
            self.active_sas.remove(&key);
            self.notified_done.remove(&key);
        }
    }

    /// Dispatch an `OutgoingVerificationRequest` — either a to-device message
    /// or an in-room event.
    async fn send_outgoing_verification(
        &self,
        base: &str,
        token: &str,
        req: &OutgoingVerificationRequest,
    ) {
        match req {
            OutgoingVerificationRequest::ToDevice(r) => {
                let id = r.txn_id.clone();
                if let Err(e) = self.send_to_device(base, token, r, &id).await {
                    warn!("send verification to-device: {e}");
                }
            }
            OutgoingVerificationRequest::InRoom(r) => {
                let id = r.txn_id.clone();
                if let Err(e) = self.send_room_message(base, token, r, &id).await {
                    warn!("send verification in-room: {e}");
                }
            }
        }
    }

    /// POST cross-signing signatures to the homeserver.
    async fn send_signature_upload(
        &self,
        base: &str,
        token: &str,
        req: &ruma::api::client::keys::upload_signatures::v3::Request,
        request_id: &ruma::TransactionId,
    ) -> Result<()> {
        let body = serde_json::to_value(&req.signed_keys)?;
        self.http_client
            .post(format!("{base}/_matrix/client/v3/keys/signatures/upload"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        let ruma_resp = SignatureUploadResponse::new();
        self.olm
            .mark_request_as_sent(request_id, AnyIncomingResponse::SignatureUpload(&ruma_resp))
            .await
            .context("mark signature_upload sent")
    }

    /// PUT an in-room event (used for in-room verification messages).
    async fn send_room_message(
        &self,
        base: &str,
        token: &str,
        req: &RoomMessageRequest,
        request_id: &ruma::TransactionId,
    ) -> Result<()> {
        let event_type = req.content.event_type();
        let txn_id = req.txn_id.as_str();
        let room_id = &req.room_id;
        let body = serde_json::to_value(&*req.content)?;

        let resp: Value = self
            .http_client
            .put(format!(
                "{base}/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}"
            ))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        let event_id = resp
            .get("event_id")
            .and_then(|v| v.as_str())
            .and_then(|s| EventId::parse(s).ok())
            .unwrap_or_else(|| EventId::parse("$placeholder:placeholder.invalid").unwrap());

        let ruma_resp = RoomMessageResponse::new(event_id);
        self.olm
            .mark_request_as_sent(request_id, AnyIncomingResponse::RoomMessage(&ruma_resp))
            .await
            .context("mark room_message sent")
    }

    // -----------------------------------------------------------------------
    // Device listing (for D-Bus queries)
    // -----------------------------------------------------------------------

    pub async fn list_user_devices(&self, user_id: &str) -> Vec<HashMap<String, String>> {
        let uid = match UserId::parse(user_id) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        match self.olm.get_user_devices(&uid, None).await {
            Ok(devices) => devices
                .devices()
                .map(|d| {
                    let trust_state = match d.local_trust_state() {
                        LocalTrust::Verified => "verified",
                        LocalTrust::BlackListed => "blacklisted",
                        LocalTrust::Ignored => "ignored",
                        LocalTrust::Unset => "unset",
                    };
                    HashMap::from([
                        ("user_id".into(), d.user_id().to_string()),
                        ("device_id".into(), d.device_id().to_string()),
                        (
                            "device_display_name".into(),
                            d.display_name().unwrap_or("").to_owned(),
                        ),
                        (
                            "ed25519".into(),
                            d.ed25519_key()
                                .map(|k| k.to_base64())
                                .unwrap_or_default(),
                        ),
                        ("trust_state".into(), trust_state.to_owned()),
                    ])
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Returns all devices the OlmMachine knows about across all tracked users.
    /// OlmMachine has no list-all-users API; callers should iterate per-user
    /// via `list_user_devices` or derive from the pan_users set.
    pub fn list_all_devices(&self) -> Vec<HashMap<String, String>> {
        Vec::new()
    }
}
