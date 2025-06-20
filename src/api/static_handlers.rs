use crate::api::{ApiState, ErrorResponse};
use crate::merkle_tree::compute_subtree_root;
use crate::types::tiles::{parse_tile_index, DataTile, Tile, TileLeaf};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use flate2::write::GzEncoder;
use flate2::Compression;
use futures::future::try_join_all;
use std::io::Write;
use std::sync::Arc;

/// Get the checkpoint for this log following the C2SP specification
pub async fn get_checkpoint(
    State(state): State<Arc<ApiState>>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    let committed_root = state
        .merkle_tree
        .committed_root()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into())))?;

    let tree_size = committed_root.num_leaves();
    let root_hash = committed_root.as_bytes().to_vec();

    let timestamp = chrono::Utc::now().timestamp_millis() as u64;
    let checkpoint = state
        .sth_builder
        .create_checkpoint(tree_size, root_hash, Some(timestamp))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into())))?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "max-age=5, must-revalidate")
        .body(checkpoint.format())
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    Ok(response.into_response())
}

fn calculate_subtree_root_index(tile_level: u8, tile_index: u64, position_in_tile: u64) -> u64 {
    if tile_level == 0 {
        let leaf_position = tile_index * 256 + position_in_tile;
        return 2 * leaf_position;
    }

    let subtree_size = 256u64.pow(tile_level as u32);
    let start_leaf = (tile_index * 256 + position_in_tile) * subtree_size;
    let height = 8 * tile_level as u32;
    let p = start_leaf / subtree_size;

    (1u64 << (height + 1)) - 1 + p * (1u64 << (height + 1)) - 256
}

pub async fn get_tile(
    State(state): State<Arc<ApiState>>,
    Path((level, index_path, width)): Path<(u8, String, Option<u16>)>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    if level > 63 {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Invalid tile level, must be 0-63".to_string(),
            }),
        ));
    }

    let tile_index = parse_tile_index(&index_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: format!("Invalid tile index: {}", e),
            }),
        )
    })?;

    if let Some(w) = width {
        if w == 0 || w > 256 {
            return Err((
                StatusCode::BAD_REQUEST,
                axum::Json(ErrorResponse {
                    error: "Invalid tile width, must be 1-256".to_string(),
                }),
            ));
        }
    }

    let committed_root = state
        .merkle_tree
        .committed_root()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into())))?;
    let tree_size = committed_root.num_leaves();

    let tile = generate_merkle_tile(&state, level, tile_index, tree_size, width).await?;

    if level == 1 && tile_index == 3 {
        tracing::debug!(
            "Generating level 1 tile 3 with tree_size={} root_hash={:?}",
            tree_size,
            hex::encode(&committed_root.as_bytes()[..8])
        );
    }

    let tile_data = tile.to_bytes();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::from(tile_data))
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    Ok(response)
}

async fn generate_merkle_tile(
    state: &ApiState,
    level: u8,
    tile_index: u64,
    tree_size: u64,
    requested_width: Option<u16>,
) -> Result<Tile, (StatusCode, axum::Json<ErrorResponse>)> {
    let nodes_per_tile = 256u64;
    let start_offset = tile_index * nodes_per_tile;

    let max_hashes = if let Some(w) = requested_width {
        w as u64
    } else {
        // Calculate partial tile width per spec: floor(s / 256**l) mod 256
        let total_positions = if level == 0 {
            tree_size
        } else {
            let subtree_size = 256u64.pow(level as u32);
            tree_size / subtree_size
        };
        let full_tiles = total_positions / 256;
        let partial_width = total_positions % 256;

        if tile_index == full_tiles && partial_width > 0 {
            tracing::debug!(
                "Partial tile detected: level={} index={} tree_size={} total_positions={} partial_width={}",
                level, tile_index, tree_size, total_positions, partial_width
            );
        }

        if tile_index < full_tiles {
            nodes_per_tile
        } else if tile_index == full_tiles && partial_width > 0 {
            partial_width
        } else {
            0
        }
    };

    if max_hashes == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(ErrorResponse {
                error: "Tile not found".to_string(),
            }),
        ));
    }

    if level == 0 {
        let futures: Vec<_> = (0..max_hashes)
            .map(|i| {
                let leaf_index = start_offset + i;
                if leaf_index >= tree_size {
                    None
                } else {
                    let node_index = 2 * leaf_index;
                    let merkle_tree = state.merkle_tree.clone();

                    Some(tokio::spawn(async move {
                        let hash = merkle_tree
                            .get_node_hash_at_version(node_index, tree_size)
                            .await?;

                        let mut hash_array = [0u8; 32];
                        hash_array.copy_from_slice(hash.as_slice());
                        Ok::<[u8; 32], crate::types::CtError>(hash_array)
                    }))
                }
            })
            .collect();

        let valid_futures: Vec<_> = futures.into_iter().flatten().collect();

        let results = try_join_all(valid_futures).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: format!("Task failed: {}", e),
                }),
            )
        })?;

        let hashes: Vec<[u8; 32]> =
            results
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(ErrorResponse {
                            error: format!("Failed to get leaf hash: {}", e),
                        }),
                    )
                })?;

        if hashes.is_empty() {
            return Err((
                StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "Tile not found".to_string(),
                }),
            ));
        }

        Ok(Tile::new(level, tile_index, hashes))
    } else {
        let futures: Vec<_> = (0..max_hashes)
            .map(|i| {
                let position_in_tile = i;
                let subtree_size = 256u64.pow(level as u32);
                let start_leaf = (tile_index * 256 + position_in_tile) * subtree_size;

                if start_leaf >= tree_size {
                    None
                } else {
                    let merkle_tree = state.merkle_tree.clone();

                    Some(tokio::spawn(async move {
                        let end_leaf = std::cmp::min(start_leaf + subtree_size, tree_size);
                        let actual_subtree_size = end_leaf - start_leaf;

                        let hash = if actual_subtree_size == subtree_size
                            && subtree_size.is_power_of_two()
                        {
                            let node_index = calculate_subtree_root_index(level, tile_index, position_in_tile);
                             merkle_tree
                                .get_node_hash_at_version(node_index, tree_size)
                                .await?
                        } else {
                            let subtree_root_idx = compute_subtree_root(start_leaf, end_leaf);
                            if actual_subtree_size < subtree_size {
                                tracing::debug!(
                                    "Computing incomplete subtree: level={} tile={} pos={} start={} end={} size={} idx={}",
                                    level, tile_index, position_in_tile, start_leaf, end_leaf, actual_subtree_size, subtree_root_idx.as_u64()
                                );
                            }
                            merkle_tree
                                .get_node_hash_at_version(subtree_root_idx.as_u64(), tree_size)
                                .await?
                        };

                        let mut hash_array = [0u8; 32];
                        hash_array.copy_from_slice(hash.as_slice());
                        Ok::<[u8; 32], crate::types::CtError>(hash_array)
                    }))
                }
            })
            .collect();

        let valid_futures: Vec<_> = futures.into_iter().flatten().collect();

        let results = try_join_all(valid_futures).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: format!("Task failed: {}", e),
                }),
            )
        })?;

        let hashes: Vec<[u8; 32]> =
            results
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(ErrorResponse {
                            error: format!("Failed to get node hash: {}", e),
                        }),
                    )
                })?;

        if hashes.is_empty() {
            return Err((
                StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "Tile not found".to_string(),
                }),
            ));
        }

        Ok(Tile::new(level, tile_index, hashes))
    }
}

pub async fn get_data_tile(
    State(state): State<Arc<ApiState>>,
    Path((index_path, width)): Path<(String, Option<u16>)>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    let tile_index = parse_tile_index(&index_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: format!("Invalid tile index: {}", e),
            }),
        )
    })?;

    if let Some(w) = width {
        if w == 0 || w > 256 {
            return Err((
                StatusCode::BAD_REQUEST,
                axum::Json(ErrorResponse {
                    error: "Invalid tile width, must be 1-256".to_string(),
                }),
            ));
        }
    }

    let committed_root = state
        .merkle_tree
        .committed_root()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into())))?;
    let tree_size = committed_root.num_leaves();

    let data_tile = generate_data_tile(&state, tile_index, tree_size, width).await?;

    // Always compress data tiles with gzip as per spec
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&data_tile.data).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Failed to compress data tile".to_string(),
            }),
        )
    })?;
    let compressed = encoder.finish().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Failed to finish compression".to_string(),
            }),
        )
    })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_ENCODING, "gzip")
        .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::from(compressed))
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    Ok(response)
}

async fn generate_data_tile(
    state: &ApiState,
    tile_index: u64,
    tree_size: u64,
    requested_width: Option<u16>,
) -> Result<DataTile, (StatusCode, axum::Json<ErrorResponse>)> {
    let entries_per_tile = 256u64;
    let start_offset = tile_index * entries_per_tile;

    let max_entries = if let Some(w) = requested_width {
        w as u64
    } else {
        entries_per_tile
    };

    let futures: Vec<_> = (0..max_entries)
        .map(|i| {
            let entry_index = start_offset + i;
            if entry_index >= tree_size {
                None
            } else {
                let storage = state.storage.clone();

                Some(tokio::spawn(async move {
                    let entry = storage
                        .get_deduplicated_entry(entry_index)
                        .await?
                        .ok_or_else(|| {
                            crate::types::CtError::Internal(format!(
                                "Entry {} not found",
                                entry_index
                            ))
                        })?;

                    let certificate = storage
                        .get_certificate(&entry.certificate_hash)
                        .await?
                        .ok_or_else(|| {
                            crate::types::CtError::Internal(
                                "Certificate not found in storage".to_string(),
                            )
                        })?;

                    let pre_certificate =
                        if entry.entry_type == crate::types::LogEntryType::PrecertEntry {
                            if let Some(precert_hash) = &entry.original_precert_hash {
                                storage.get_certificate(precert_hash).await?
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                    let tile_leaf = TileLeaf::from_entry(&entry, certificate, pre_certificate);
                    let leaf_bytes = tile_leaf.to_bytes();

                    Ok::<Vec<u8>, crate::types::CtError>(leaf_bytes)
                }))
            }
        })
        .collect();

    let valid_futures: Vec<_> = futures.into_iter().flatten().collect();

    let results = try_join_all(valid_futures).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: format!("Task failed: {}", e),
            }),
        )
    })?;

    let leaf_bytes_vec: Vec<Vec<u8>> =
        results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(ErrorResponse {
                        error: format!("Failed to get entry data: {}", e),
                    }),
                )
            })?;

    if leaf_bytes_vec.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(ErrorResponse {
                error: "Data tile not found".to_string(),
            }),
        ));
    }

    let mut data = Vec::new();
    for leaf_bytes in leaf_bytes_vec {
        data.extend_from_slice(&leaf_bytes);
    }

    Ok(DataTile { data })
}

pub async fn get_issuer(
    State(state): State<Arc<ApiState>>,
    Path(fingerprint): Path<String>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    let fingerprint_bytes = hex::decode(&fingerprint).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Invalid fingerprint format, must be hex-encoded".to_string(),
            }),
        )
    })?;

    if fingerprint_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Invalid fingerprint length, must be 32 bytes (64 hex chars)".to_string(),
            }),
        ));
    }

    let mut fingerprint_array = [0u8; 32];
    fingerprint_array.copy_from_slice(&fingerprint_bytes);

    let certificate = state
        .storage
        .get_certificate(&fingerprint_array)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: format!("Failed to get certificate: {}", e),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "Certificate not found".to_string(),
                }),
            )
        })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pkix-cert")
        .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::from(certificate))
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::types::signed_note::SignedNote;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn test_checkpoint_format_parsing() {
        let checkpoint_text = r#"example.com/log
12345
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— example.com/log Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8="#;

        let lines: Vec<&str> = checkpoint_text.lines().collect();

        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "example.com/log");
        assert_eq!(lines[1], "12345");
        assert!(lines[2].len() > 0);
        assert_eq!(lines[3], "");
        assert!(lines[4].starts_with("— example.com/log "));

        let sig_parts: Vec<&str> = lines[4].split_whitespace().collect();
        assert_eq!(sig_parts[0], "—");
        assert_eq!(sig_parts[1], "example.com/log");

        let sig_bytes = STANDARD.decode(sig_parts[2]).expect("Invalid base64");
        assert!(sig_bytes.len() > 4);
    }

    #[test]
    fn test_origin_extraction_from_base_url() {
        let test_cases = vec![
            ("https://example.com/log/", "example.com/log"),
            ("http://localhost:8080/", "localhost:8080"),
            ("https://ct.example.org/2024h1/", "ct.example.org/2024h1"),
            ("http://test.com", "test.com"),
        ];

        for (base_url, expected_origin) in test_cases {
            let origin = base_url
                .trim_end_matches('/')
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            assert_eq!(origin, expected_origin);
        }
    }

    #[test]
    fn test_signed_note_formatting() {
        let note = SignedNote::new(
            "example.com/log\n0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string(),
        );

        let formatted = note.format();

        let lines: Vec<&str> = formatted.lines().collect();
        assert_eq!(lines[0], "example.com/log");
        assert_eq!(lines[1], "0");
        assert_eq!(lines[2], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(lines[3], "");
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_partial_tile_width_calculation() {
        let test_cases = vec![
            (70000, 0, 112),
            (70000, 1, 17),
            (70000, 2, 1),
            (256, 0, 0),
            (256, 1, 1),
            (512, 0, 0),
            (512, 1, 2),
            (1, 0, 1),
            (257, 0, 1),
        ];

        for (tree_size, level, expected_width) in test_cases {
            let subtree_size = 256u64.pow(level as u32);
            let total_positions = tree_size / subtree_size;
            let partial_width = (total_positions % 256) as u64;

            assert_eq!(
                partial_width, expected_width,
                "For tree_size={} at level={}, expected width {} but got {}",
                tree_size, level, expected_width, partial_width
            );
        }
    }

    #[test]
    fn test_calculate_subtree_root_index() {
        use super::calculate_subtree_root_index;

        assert_eq!(calculate_subtree_root_index(0, 0, 0), 0);
        assert_eq!(calculate_subtree_root_index(0, 0, 1), 2);
        assert_eq!(calculate_subtree_root_index(0, 0, 255), 510);
        assert_eq!(calculate_subtree_root_index(0, 1, 0), 512);

        let level1_tile0_pos0 = calculate_subtree_root_index(1, 0, 0);
        assert_eq!(level1_tile0_pos0, 255);

        let level1_tile0_pos1 = calculate_subtree_root_index(1, 0, 1);
        assert_eq!(level1_tile0_pos1, 767);
    }

    #[test]
    fn test_tile_index_parsing_edge_cases() {
        use crate::types::tiles::parse_tile_index;

        assert_eq!(
            parse_tile_index("x999/x999/x999/999").unwrap(),
            999999999999u64
        );

        let long_path = "x001/x002/x003/x004/x005/006";
        assert_eq!(parse_tile_index(long_path).unwrap(), 1002003004005006u64);

        assert!(parse_tile_index("x1000/000").is_err());
        assert!(parse_tile_index("001/x002").is_err());
        assert!(parse_tile_index("x00/123").is_err());
        assert!(parse_tile_index("x123/45").is_err());
    }
}
