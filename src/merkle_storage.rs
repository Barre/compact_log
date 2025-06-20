use crate::merkle_tree::{ConsistencyProof, InclusionProof, RootHash, SlateDbBackedTree};
use crate::types::{CtError, Result};
use sha2::Sha256;
use slatedb::Db;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub data: Vec<u8>, // MerkleTreeLeaf data, not raw certificate
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl serde::Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.data.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Certificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Ok(Certificate { data })
    }
}

/// Storage-backed Merkle tree using ct-merkle's SlateDbBackedTree
#[derive(Clone)]
pub struct StorageBackedMerkleTree {
    tree: Arc<SlateDbBackedTree<Sha256, Certificate>>,
}

impl StorageBackedMerkleTree {
    pub async fn new(db: Arc<Db>) -> Result<Self> {
        let tree = SlateDbBackedTree::new(db).await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to create SlateDbBackedTree: {:?}",
                e
            )))
        })?;

        Ok(Self {
            tree: Arc::new(tree),
        })
    }

    pub async fn size(&self) -> Result<u64> {
        self.tree.len().await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to get tree size: {:?}",
                e
            )))
        })
    }

    /// Get the last committed tree size (for STH generation)
    pub async fn committed_size(&self) -> Result<u64> {
        self.tree.get_committed_size().await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to get committed tree size: {:?}",
                e
            )))
        })
    }

    pub async fn batch_push_with_data(
        &self,
        cert_data_vec: Vec<Vec<u8>>,
        additional_data: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<u64> {
        let certificates: Vec<Certificate> = cert_data_vec
            .into_iter()
            .map(|data| Certificate { data })
            .collect();
        let result = self
            .tree
            .batch_push_with_data(certificates, additional_data)
            .await
            .map_err(|e| {
                CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                    "Failed to batch push with data: {:?}",
                    e
                )))
            })?;

        if let Ok(size) = self.size().await {
            crate::metrics::MERKLE_TREE_SIZE.set(size as i64);
        }

        Ok(result)
    }

    /// Get the root at the committed tree size (for STH generation)
    pub async fn committed_root(&self) -> Result<RootHash<Sha256>> {
        let committed_size = self.committed_size().await?;
        self.tree.root_at_size(committed_size).await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to get root at committed size: {:?}",
                e
            )))
        })
    }

    pub async fn prove_inclusion_efficient(
        &self,
        tree_size: u64,
        leaf_index: u64,
    ) -> Result<InclusionProof<Sha256>> {
        if leaf_index >= tree_size {
            return Err(CtError::BadRequest(
                "Leaf index out of bounds for requested tree size".into(),
            ));
        }

        // Check if requested tree size is valid (not larger than current tree)
        let current_tree_size = self.size().await?;
        if tree_size > current_tree_size {
            return Err(CtError::BadRequest(format!(
                "Requested tree size {} exceeds current tree size {}",
                tree_size, current_tree_size
            )));
        }

        let proof = self
            .tree
            .prove_inclusion_at_size(leaf_index, tree_size)
            .await
            .map_err(|e| {
                let error_str = format!("{:?}", e);
                if error_str.contains("not a published STH boundary") {
                    CtError::BadRequest(format!(
                        "Tree size {} is not a published STH boundary",
                        tree_size
                    ))
                } else {
                    CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                        "Failed to prove inclusion: {:?}",
                        e
                    )))
                }
            })?;

        Ok(proof)
    }

    pub async fn consistency_proof_between_sizes(
        &self,
        old_tree_size: u64,
        new_tree_size: u64,
    ) -> Result<ConsistencyProof<Sha256>> {
        if old_tree_size > new_tree_size {
            return Err(CtError::BadRequest(
                "Old tree size cannot be larger than new tree size".into(),
            ));
        }

        if old_tree_size == new_tree_size {
            return Ok(ConsistencyProof::from_digests(std::iter::empty()));
        }

        if old_tree_size == 0 {
            return Err(CtError::BadRequest(
                "Cannot produce consistency proof starting from empty tree".into(),
            ));
        }

        let current_tree_size = self.size().await?;
        if old_tree_size > current_tree_size {
            return Err(CtError::BadRequest(format!(
                "Old tree size {} exceeds current tree size {}",
                old_tree_size, current_tree_size
            )));
        }
        if new_tree_size > current_tree_size {
            return Err(CtError::BadRequest(format!(
                "New tree size {} exceeds current tree size {}",
                new_tree_size, current_tree_size
            )));
        }

        let proof = self
            .tree
            .prove_consistency_between(old_tree_size, new_tree_size)
            .await
            .map_err(|e| {
                let error_str = format!("{:?}", e);
                if error_str.contains("not a published STH boundary") {
                    CtError::BadRequest(error_str)
                } else {
                    CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                        "Failed to prove consistency: {:?}",
                        e
                    )))
                }
            })?;

        Ok(proof)
    }

    /// Check if multiple keys exist in the underlying database
    pub async fn check_keys_exist(&self, keys: &[Vec<u8>]) -> Result<Vec<bool>> {
        self.tree.check_keys_exist(keys).await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to check keys: {:?}",
                e
            )))
        })
    }

    /// Get the hash of an internal node at the given index for a specific tree version
    pub async fn get_node_hash_at_version(
        &self,
        node_index: u64,
        version: u64,
    ) -> Result<digest::Output<Sha256>> {
        self.tree
            .get_node_hash_at_version(node_index, version)
            .await
            .map_err(|e| {
                CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                    "Failed to get node hash at version: {:?}",
                    e
                )))
            })
    }

    /// Precompute and store subtree roots for efficient static API tile generation
    /// This computes subtree roots only for the range of entries specified
    /// Returns a vector of (key, value) pairs to be included in the batch write
    pub async fn precompute_tile_subtree_roots_for_range(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        (*self.tree)
            .precompute_tile_subtree_roots_for_range(start_index, end_index)
            .await
            .map_err(|e| {
                CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                    "Failed to precompute tile subtree roots: {:?}",
                    e
                )))
            })
    }
}

pub mod serialization {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    pub fn inclusion_proof_to_audit_path(proof: &InclusionProof<Sha256>) -> Vec<String> {
        // Get the raw proof bytes
        let proof_bytes = proof.as_bytes();

        // Each hash in the proof is 32 bytes (SHA256 output size)
        const HASH_SIZE: usize = 32;

        // Split the proof bytes into individual hashes and encode each as base64
        proof_bytes
            .chunks(HASH_SIZE)
            .map(|hash_bytes| BASE64.encode(hash_bytes))
            .collect()
    }

    pub fn consistency_proof_to_path(proof: &ConsistencyProof<Sha256>) -> Vec<String> {
        // Get the raw proof bytes
        let proof_bytes = proof.as_bytes();

        // Each hash in the proof is 32 bytes (SHA256 output size)
        const HASH_SIZE: usize = 32;

        // Split the proof bytes into individual hashes and encode each as base64
        proof_bytes
            .chunks(HASH_SIZE)
            .map(|hash_bytes| BASE64.encode(hash_bytes))
            .collect()
    }
}
