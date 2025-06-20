use axum::{
    extract::Path,
    middleware,
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use prometheus::{Encoder, TextEncoder};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    merkle_storage::StorageBackedMerkleTree,
    storage::CtStorage,
    types::{sct::SctBuilder, tree_head::SthBuilder, LogId},
    validation::Rfc6962Validator,
};

pub mod handlers;
pub mod static_handlers;

pub struct ApiState {
    pub storage: Arc<CtStorage>,
    pub merkle_tree: StorageBackedMerkleTree,
    pub sct_builder: Arc<SctBuilder>,
    pub sth_builder: Arc<SthBuilder>,
    pub validator: Option<Arc<RwLock<Rfc6962Validator>>>,
    pub log_id: LogId,
    pub public_key_der: Vec<u8>,
    pub base_url: String,
}

impl ApiState {
    pub fn new(
        storage: Arc<CtStorage>,
        merkle_tree: StorageBackedMerkleTree,
        log_id: LogId,
        private_key: Vec<u8>,
        public_key_der: Vec<u8>,
        base_url: String,
        validator: Option<Rfc6962Validator>,
    ) -> crate::types::Result<Self> {
        let sct_builder = Arc::new(SctBuilder::from_private_key_bytes(
            log_id.clone(),
            &private_key,
        )?);

        // Derive origin from base_url for checkpoints
        // Remove scheme (http:// or https://) and trailing slashes
        let origin = base_url
            .trim_end_matches('/')
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string();

        // Use the actual LogId bytes (which is already the SHA-256 of the public key)
        let log_id_bytes = log_id.to_bytes().to_vec();

        let sth_builder = Arc::new(SthBuilder::new(&private_key, origin, log_id_bytes)?);

        let validator = validator.map(|v| Arc::new(RwLock::new(v)));

        Ok(Self {
            storage,
            merkle_tree,
            sct_builder,
            sth_builder,
            validator,
            log_id,
            public_key_der,
            base_url,
        })
    }
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        // RFC 6962 endpoints
        .route("/ct/v1/add-chain", post(handlers::add_chain))
        .route("/ct/v1/add-pre-chain", post(handlers::add_pre_chain))
        .route("/ct/v1/get-sth", get(handlers::get_sth))
        .route(
            "/ct/v1/get-sth-consistency",
            get(handlers::get_sth_consistency),
        )
        .route("/ct/v1/get-proof-by-hash", get(handlers::get_proof_by_hash))
        .route("/ct/v1/get-entries", get(handlers::get_entries))
        .route("/ct/v1/get-roots", get(handlers::get_roots))
        .route(
            "/ct/v1/get-entry-and-proof",
            get(handlers::get_entry_and_proof),
        )
        // Static CT API endpoints
        .route("/checkpoint", get(static_handlers::get_checkpoint))
        .route("/tile/{level}/{*index}", get(handle_tile_request_with_path))
        .route(
            "/tile/data/{*index}",
            get(handle_data_tile_request_with_path),
        )
        .route("/issuer/{fingerprint}", get(static_handlers::get_issuer))
        .route("/inclusion_request.json", get(handlers::inclusion_request))
        .route("/health", get(health_check))
        // Prometheus metrics endpoint
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn(metrics_middleware))
        .with_state(Arc::new(state))
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// Handler wrappers for tile routes
async fn handle_tile_request_with_path(
    state: axum::extract::State<Arc<ApiState>>,
    Path((level, index_path)): Path<(u8, String)>,
) -> Result<Response, (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    // Parse the index path which may contain .p/{width}
    let (index, width) = parse_tile_path(&index_path);
    static_handlers::get_tile(state, Path((level, index, width))).await
}

async fn handle_data_tile_request_with_path(
    state: axum::extract::State<Arc<ApiState>>,
    Path(index_path): Path<String>,
) -> Result<Response, (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    // Parse the index path which may contain .p/{width}
    let (index, width) = parse_tile_path(&index_path);
    static_handlers::get_data_tile(state, Path((index, width))).await
}

// Helper function to parse tile paths like "x001/x234/067" or "x001/x234/067.p/123"
fn parse_tile_path(path: &str) -> (String, Option<u16>) {
    if let Some(dot_p_pos) = path.rfind(".p/") {
        let index = path[..dot_p_pos].to_string();
        let width_str = &path[dot_p_pos + 3..];
        if let Ok(width) = width_str.parse::<u16>() {
            if width > 0 && width <= 256 {
                return (index, Some(width));
            }
        }
    }
    (path.to_string(), None)
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl From<crate::types::CtError> for ErrorResponse {
    fn from(err: crate::types::CtError) -> Self {
        Self {
            error: err.to_string(),
        }
    }
}

impl From<crate::storage::StorageError> for ErrorResponse {
    fn from(err: crate::storage::StorageError) -> Self {
        Self {
            error: format!("Storage error: {}", err),
        }
    }
}

async fn metrics_handler() -> Result<String, (axum::http::StatusCode, String)> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode metrics: {}", e),
        )
    })?;
    String::from_utf8(buffer).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to convert metrics to string: {}", e),
        )
    })
}

use crate::metrics;
use axum::{body::Body, extract::Request};
use std::time::Instant;

async fn metrics_middleware(
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, axum::response::Response> {
    let start = Instant::now();
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    metrics::ACTIVE_CONNECTIONS.inc();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    // Only track CT API endpoints, not health or metrics
    if path.starts_with("/ct/v1/") {
        metrics::HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[&path, &method])
            .observe(duration);

        metrics::HTTP_REQUESTS_TOTAL
            .with_label_values(&[&path, &method, &status])
            .inc();
    }

    metrics::ACTIVE_CONNECTIONS.dec();

    Ok(response)
}
