use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, info, warn};

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
                    None,
                    None,
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
                            if name.as_str() != "content-length" {
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
// Media upload  (Phase 4: encrypt before forwarding)
// ---------------------------------------------------------------------------

pub async fn upload(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
    daemon.forward_request(req).await
}

// ---------------------------------------------------------------------------
// Media download  (Phase 4: decrypt after fetching)
// ---------------------------------------------------------------------------

pub async fn download(
    State(daemon): State<Arc<ProxyDaemon>>,
    req: Request,
) -> Result<Response, AppError> {
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

fn build_response(
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let axum_status =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = Response::builder().status(axum_status);
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    Ok(builder.body(Body::from(body)).unwrap())
}
