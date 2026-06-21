use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use matrix_sdk_crypto::MediaEncryptionInfo;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::store::MediaInfo;

use crate::{client::PanClient, error::AppError, proxy::daemon::ProxyDaemon};

// ---------------------------------------------------------------------------
// Token extraction
// ---------------------------------------------------------------------------

/// Extract the Matrix access token from a request.
///
/// Checks `Authorization: Bearer <token>` first, then falls back to the
/// `?access_token=<token>` query parameter (deprecated but still in use).
pub fn extract_token(req: &Request) -> Option<String> {
    if let Some(auth) = req.headers().get(http::header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            if let Some(tok) = s.strip_prefix("Bearer ") {
                return Some(tok.trim().to_owned());
            }
        }
    }

    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("access_token=") {
                return Some(value.to_owned());
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Keyring helpers (best-effort; failures are logged, not fatal)
// ---------------------------------------------------------------------------

fn keyring_key(user_id: &str, device_id: &str) -> String {
    format!("{user_id}:{device_id}")
}

pub fn save_to_keyring(user_id: &str, device_id: &str, token: &str) {
    let key = keyring_key(user_id, device_id);
    match keyring::Entry::new("pantalaimon", &key).and_then(|e| e.set_password(token)) {
        Ok(_) => {}
        Err(e) => warn!(%user_id, "Keyring write failed: {e}"),
    }
}

pub fn load_from_keyring(user_id: &str, device_id: &str) -> Option<String> {
    let key = keyring_key(user_id, device_id);
    keyring::Entry::new("pantalaimon", &key)
        .ok()
        .and_then(|e| e.get_password().ok())
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct LoginResponse {
    user_id: String,
    device_id: String,
    access_token: String,
}

/// `POST /_matrix/client/{r0,v3}/login`
pub async fn login(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    let (parts, body) = req.into_parts();
    let body_bytes: Bytes =
        axum::body::to_bytes(body, 1024 * 1024).await.map_err(|_| AppError::Body)?;

    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let base = daemon.server_conf.homeserver.as_str().trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut builder = daemon.http_client.post(&url);
    for (name, value) in &parts.headers {
        if name != "host" {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    let upstream_resp = builder.body(body_bytes).send().await?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    if status.is_success() {
        match serde_json::from_slice::<LoginResponse>(&resp_bytes) {
            Ok(lr) => {
                info!(user_id = %lr.user_id, device_id = %lr.device_id, "Login captured");

                if let Err(e) = daemon
                    .store
                    .save_access_token(&lr.user_id, &lr.device_id, &lr.access_token)
                    .await
                {
                    warn!("Failed to save access token to DB: {e}");
                }

                if let Err(e) =
                    daemon.store.save_server_user(&daemon.name, &lr.user_id).await
                {
                    warn!("Failed to save server user to DB: {e}");
                }

                if daemon.server_conf.use_keyring {
                    save_to_keyring(&lr.user_id, &lr.device_id, &lr.access_token);
                }

                match PanClient::new(
                    lr.user_id,
                    lr.device_id,
                    lr.access_token,
                    daemon.server_conf.clone(),
                    daemon.store.clone(),
                    daemon.http_client.clone(),
                    daemon.ui_tx.clone(),
                )
                .await
                {
                    Ok(client) => {
                        let client = Arc::new(client);
                        client.clone().start_sync().await;
                        daemon.register_client(client);
                    }
                    Err(e) => warn!("Failed to create PanClient: {e}"),
                }
            }
            Err(e) => warn!("Could not parse login response: {e}"),
        }
    }

    build_response(status, resp_headers, resp_bytes)
}

// ---------------------------------------------------------------------------
// Sync  — decrypt incoming events
// ---------------------------------------------------------------------------

pub async fn sync(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    let token = extract_token(&req);

    // Forward the sync request to the homeserver.
    let (parts, body) = req.into_parts();
    let body_bytes: Bytes =
        axum::body::to_bytes(body, 100 * 1024 * 1024).await.map_err(|_| AppError::Body)?;

    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let base = daemon.server_conf.homeserver.as_str().trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut builder = daemon.http_client.request(parts.method.clone(), &url);
    for (name, value) in &parts.headers {
        if name != "host" && name.as_str() != "connection" {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }

    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    if status.is_success() {
        if let Some(tok) = token {
            if let Some(client) = daemon.resolve_client(&tok).await {
                if let Ok(mut body_json) = serde_json::from_slice::<serde_json::Value>(&resp_bytes)
                {
                    if let Err(e) = client.process_sync(&mut body_json).await {
                        warn!("process_sync error: {e}");
                    } else if let Ok(patched) = serde_json::to_vec(&body_json) {
                        let mut resp_builder = Response::builder().status(status.as_u16());
                        for (name, value) in &resp_headers {
                            if !should_strip_response_header(name.as_str()) {
                                resp_builder = resp_builder.header(name.as_str(), value.as_bytes());
                            }
                        }
                        return Ok(resp_builder
                            .body(Body::from(patched))
                            .unwrap());
                    }
                }
            }
        }
    }

    build_response(status, resp_headers, resp_bytes)
}

// ---------------------------------------------------------------------------
// Room messages  — decrypt paginated history
// ---------------------------------------------------------------------------

pub async fn messages(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    let token = extract_token(&req);

    let (parts, body) = req.into_parts();
    let room_id = parts
        .uri
        .path()
        .split('/')
        .find(|seg| seg.starts_with('!'))
        .map(str::to_owned);
    let body_bytes: Bytes =
        axum::body::to_bytes(body, 100 * 1024 * 1024).await.map_err(|_| AppError::Body)?;

    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let base = daemon.server_conf.homeserver.as_str().trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut builder = daemon.http_client.request(parts.method.clone(), &url);
    for (name, value) in &parts.headers {
        if name != "host" && name.as_str() != "connection" {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }

    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    if status.is_success() {
        if let (Some(tok), Some(rid)) = (token, room_id) {
            if let Some(client) = daemon.resolve_client(&tok).await {
                if let Ok(mut body_json) =
                    serde_json::from_slice::<serde_json::Value>(&resp_bytes)
                {
                    // Decrypt each event in chunk
                    if let Some(events) =
                        body_json.get_mut("chunk").and_then(|c| c.as_array_mut())
                    {
                        for event in events.iter_mut() {
                            if event.get("type").and_then(|t| t.as_str())
                                == Some("m.room.encrypted")
                            {
                                if let Some(cleartext) =
                                    client.decrypt_event(&rid, event).await
                                {
                                    *event = cleartext;
                                }
                            }
                        }
                    }

                    if let Ok(patched) = serde_json::to_vec(&body_json) {
                        let mut resp_builder = Response::builder().status(status.as_u16());
                        for (name, value) in &resp_headers {
                            if name.as_str() != "content-length" {
                                resp_builder =
                                    resp_builder.header(name.as_str(), value.as_bytes());
                            }
                        }
                        return Ok(resp_builder.body(Body::from(patched)).unwrap());
                    }
                }
            }
        }
    }

    build_response(status, resp_headers, resp_bytes)
}

// ---------------------------------------------------------------------------
// Send  — encrypt outgoing events
// ---------------------------------------------------------------------------

pub async fn send_message(
    State(daemon): State<Arc<ProxyDaemon>>,
    Path((room_id, event_type, _txn_id)): Path<(String, String, String)>,
    req: Request,
) -> Result<Response, AppError> {
    let token = extract_token(&req);

    let (parts, body) = req.into_parts();
    let body_bytes: Bytes =
        axum::body::to_bytes(body, 100 * 1024 * 1024).await.map_err(|_| AppError::Body)?;

    // Try to encrypt if we have a client for this token
    if let Some(tok) = token {
        if let Some(client) = daemon.resolve_client(&tok).await {
            if client.is_room_encrypted(&room_id) {
                match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    Ok(content) => {
                        match client.prepare_and_encrypt(&room_id, &event_type, content).await {
                            Ok((new_type, encrypted_content)) => {
                                // Re-assemble the request with the encrypted payload
                                let encrypted_bytes =
                                    serde_json::to_vec(&encrypted_content).map_err(|e| {
                                        AppError::Internal(anyhow::anyhow!(
                                            "serialize encrypted event: {e}"
                                        ))
                                    })?;

                                let path = parts
                                    .uri
                                    .path()
                                    .replacen(&event_type, &new_type, 1);
                                let qs = parts
                                    .uri
                                    .query()
                                    .map(|q| format!("?{q}"))
                                    .unwrap_or_default();
                                let base = daemon
                                    .server_conf
                                    .homeserver
                                    .as_str()
                                    .trim_end_matches('/');
                                let url = format!("{base}{path}{qs}");

                                let mut builder =
                                    daemon.http_client.put(&url);
                                for (name, value) in &parts.headers {
                                    if name != "host" && name.as_str() != "connection" {
                                        builder = builder.header(name.clone(), value.clone());
                                    }
                                }
                                let upstream_resp =
                                    builder.body(encrypted_bytes).send().await?;
                                let status = upstream_resp.status();
                                let resp_headers = upstream_resp.headers().clone();
                                let resp_bytes = upstream_resp.bytes().await?;
                                return build_response(status, resp_headers, resp_bytes);
                            }
                            Err(e) => warn!(%room_id, "Encryption failed, sending plaintext: {e}"),
                        }
                    }
                    Err(e) => debug!(%room_id, "Could not parse send body: {e}"),
                }
            }
        }
    }

    // Fallback: forward as-is
    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let base = daemon.server_conf.homeserver.as_str().trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut builder = daemon.http_client.put(&url);
    for (name, value) in &parts.headers {
        if name != "host" && name.as_str() != "connection" {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    let upstream_resp = builder.body(body_bytes).send().await?;
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;
    build_response(status, resp_headers, resp_bytes)
}

// ---------------------------------------------------------------------------
// Media upload — encrypt before forwarding
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UploadResponse {
    content_uri: String,
}

pub async fn upload(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    let token = extract_token(&req);

    let (parts, body) = req.into_parts();
    let body_bytes: Bytes =
        axum::body::to_bytes(body, 100 * 1024 * 1024).await.map_err(|_| AppError::Body)?;

    // Encrypt only for authenticated users we know about.
    // `token_to_user` is the O(1) cache; no async call needed here.
    let is_known = token
        .as_deref()
        .map(|t| daemon.is_known_token(t))
        .unwrap_or(false);

    let (upload_bytes, enc_info) = if is_known && !body_bytes.is_empty() {
        match crate::client::PanClient::encrypt_attachment(body_bytes.clone()).await {
            Ok((cipher, info)) => (cipher, Some(info)),
            Err(e) => {
                warn!("Failed to encrypt attachment: {e}");
                (body_bytes, None)
            }
        }
    } else {
        (body_bytes, None)
    };

    // Pull filename and content-type from original request
    let filename = parts.uri.query().and_then(|q| {
        q.split('&').find_map(|p| p.strip_prefix("filename=").map(str::to_owned))
    });
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();

    // Forward to homeserver
    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let base = daemon.server_conf.homeserver.as_str().trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut builder = daemon.http_client.post(&url);
    for (name, value) in &parts.headers {
        if name != "host" && name.as_str() != "content-length" {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    let upstream_resp = builder.body(upload_bytes).send().await?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    // If we encrypted, store the keys keyed by the returned mxc URI
    if let (Some(info), true) = (enc_info, status.is_success()) {
        if let Ok(upload_resp) = serde_json::from_slice::<UploadResponse>(&resp_bytes) {
            let uri = &upload_resp.content_uri; // "mxc://server/path"
            let without_prefix = uri.trim_start_matches("mxc://");
            if let Some(slash) = without_prefix.find('/') {
                let mxc_server = &without_prefix[..slash];
                let mxc_path = &without_prefix[slash + 1..];

                // Serialize MediaEncryptionInfo fields to match MediaInfo storage
                if let Ok(info_json) = serde_json::to_value(&info) {
                    let media = MediaInfo {
                        mxc_server: mxc_server.to_owned(),
                        mxc_path: mxc_path.to_owned(),
                        key: info_json["key"].clone(),
                        iv: info_json["iv"].as_str().unwrap_or("").to_owned(),
                        hashes: info_json["hashes"].clone(),
                    };

                    if let Err(e) = daemon.store.save_media(&daemon.name, &media).await {
                        warn!("Failed to store media keys: {e}");
                    } else {
                        // Also record filename + mimetype for later retrieval
                        if let Some(fname) = &filename {
                            if let Err(e) = daemon
                                .store
                                .save_upload(&daemon.name, uri, fname, &content_type)
                                .await
                            {
                                warn!("Failed to store upload info: {e}");
                            }
                        }
                        debug!(%uri, "Stored media encryption keys");
                    }
                }
            }
        }
    }

    build_response(status, resp_headers, resp_bytes)
}

// ---------------------------------------------------------------------------
// Media download — decrypt after fetching
// ---------------------------------------------------------------------------

/// Extract `(server_name, media_id)` from a Matrix media download path.
///
/// Handles both `/_matrix/media/{ver}/download/{server}/{id}` and the
/// `/{server}/{id}/{filename}` variant by finding the two segments that
/// follow "download/".
fn mxc_from_path(path: &str) -> Option<(&str, &str)> {
    let after = path.split("/download/").nth(1)?;
    let mut parts = after.splitn(3, '/');
    let server = parts.next()?;
    let media_id = parts.next()?;
    Some((server, media_id))
}

pub async fn download(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    // Extract server + media_id from path without a typed Path extractor so
    // the same handler works for both the 2- and 3-segment URL forms.
    let (server_name, media_id) = match mxc_from_path(req.uri().path()) {
        Some(pair) => (pair.0.to_owned(), pair.1.to_owned()),
        None => return daemon.forward_request(req).await,
    };

    let media = daemon
        .store
        .load_media(&daemon.name, &server_name, &media_id)
        .await
        .unwrap_or(None);

    if let Some(media_info) = media {
        let enc_info_result: anyhow::Result<MediaEncryptionInfo> = (|| {
            let info_json = serde_json::json!({
                "v": "v2",
                "key": media_info.key,
                "iv": media_info.iv,
                "hashes": media_info.hashes,
            });
            Ok(serde_json::from_value(info_json)?)
        })();

        match enc_info_result {
            Ok(enc_info) => {
                let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
                let base = daemon.server_conf.homeserver.as_str().trim_end_matches('/');
                let url = format!("{base}{path}");

                let mut builder = daemon.http_client.get(&url);
                for (name, value) in req.headers() {
                    if name != "host" {
                        builder = builder.header(name.clone(), value.clone());
                    }
                }
                let upstream_resp = builder.send().await?;
                let status = upstream_resp.status();
                let resp_headers = upstream_resp.headers().clone();

                if status.is_success() {
                    let cipher_bytes = upstream_resp.bytes().await?;
                    match crate::client::PanClient::decrypt_attachment(cipher_bytes, enc_info).await {
                        Ok(plaintext) => {
                            let mut resp_builder = Response::builder().status(status.as_u16());
                            for (name, value) in &resp_headers {
                                if name.as_str() != "content-length" {
                                    resp_builder =
                                        resp_builder.header(name.as_str(), value.as_bytes());
                                }
                            }
                            return Ok(resp_builder.body(Body::from(plaintext)).unwrap());
                        }
                        Err(e) => warn!(%server_name, %media_id, "Decrypt failed: {e}"),
                    }
                } else {
                    let resp_bytes = upstream_resp.bytes().await?;
                    return build_response(status, resp_headers, resp_bytes);
                }
            }
            Err(e) => warn!(%server_name, %media_id, "Bad stored enc info: {e}"),
        }
    }

    daemon.forward_request(req).await
}

// ---------------------------------------------------------------------------
// Misc pass-throughs
// ---------------------------------------------------------------------------

pub async fn create_room(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    daemon.forward_request(req).await
}

pub async fn filter(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    daemon.forward_request(req).await
}

pub async fn profile(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    daemon.forward_request(req).await
}

pub async fn well_known(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    daemon.forward_request(req).await
}

pub async fn search(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    if daemon.server_conf.search_requests {
        daemon.forward_request(req).await
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "errcode": "M_NOT_FOUND",
                "error": "Local search is not enabled",
            })),
        )
            .into_response())
    }
}

pub async fn search_opts(
    State(_daemon): State<Arc<ProxyDaemon>>,
    _req: Request,
) -> impl IntoResponse {
    StatusCode::OK
}

/// Catch-all: forward anything else to the homeserver unchanged.
pub async fn proxy_pass(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    daemon.forward_request(req).await
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Returns true for headers that must not be forwarded to downstream clients.
///
/// Hop-by-hop headers are framing concerns handled by hyper/reqwest.
/// content-encoding and content-length are stripped because reqwest
/// transparently decompresses response bodies, leaving the original
/// headers stale and mismatched.
fn should_strip_response_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-encoding"
            | "content-length"
    )
}

fn build_response(
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let axum_status =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = Response::builder().status(axum_status);
    for (name, value) in &headers {
        if !should_strip_response_header(name.as_str()) {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }
    Ok(builder.body(Body::from(body)).unwrap())
}
