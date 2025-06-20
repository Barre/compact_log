use crate::merkle_tree::{
    consistency::indices_for_consistency_proof,
    ct_merkle_vendored::{
        indices_for_inclusion_proof, leaf_hash, parent_hash, root_idx, ConsistencyProof,
        HashableLeaf, InclusionProof, InternalIdx, LeafIdx, RootHash,
    },
};
use digest::Digest;
use moka::future::Cache;
use slatedb::{Db, WriteBatch};
use std::{fmt, sync::Arc};
use tokio::sync::{Mutex, RwLock};

#[derive(Debug)]
pub enum SlateDbTreeError {
    DbError(slatedb::SlateDBError),
    EncodingError(String),
    InconsistentState(String),
}

impl fmt::Display for SlateDbTreeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SlateDbTreeError::DbError(e) => write!(f, "SlateDB error: {}", e),
            SlateDbTreeError::EncodingError(e) => write!(f, "Encoding error: {}", e),
            SlateDbTreeError::InconsistentState(e) => write!(f, "Inconsistent state: {}", e),
        }
    }
}

impl std::error::Error for SlateDbTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SlateDbTreeError::DbError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<slatedb::SlateDBError> for SlateDbTreeError {
    fn from(e: slatedb::SlateDBError) -> Self {
        SlateDbTreeError::DbError(e)
    }
}

/// A SlateDB-backed append-only Merkle tree implementation.
///
/// This implementation stores only the necessary data in SlateDB:
/// - Leaf values at keys "leaf:{index}"
/// - Internal node hashes at keys "node:{index}"
/// - Tree metadata at key "meta"
///
/// Operations are designed to minimize reads by only fetching nodes
/// along the paths needed for proofs and root calculation.
///
/// Thread-safety: This implementation is thread-safe by default.
/// Write operations (push, batch_push_with_data) are serialized using an internal
/// RwLock, while read operations can proceed concurrently.
pub struct SlateDbBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf,
{
    db: Arc<Db>,
    _phantom_h: core::marker::PhantomData<H>,
    _phantom_t: core::marker::PhantomData<T>,
    // Cache for frequently accessed upper tree nodes
    // Key: (node index, version), Value: node hash
    node_cache: Option<Cache<(u64, u64), Vec<u8>>>,
    // Write lock to ensure write operations are serialized
    write_lock: Arc<Mutex<()>>,
}

const LEAF_PREFIX: &[u8] = b"leaf:";
const META_KEY: &[u8] = b"meta";
const VERSIONED_NODE_PREFIX: &[u8] = b"vnode:";
const COMMITTED_SIZE_KEY: &[u8] = b"committed_size";
const NODE_LATEST_VERSION_PREFIX: &[u8] = b"nver:";

impl<H, T> SlateDbBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Check if multiple keys exist in the database
    pub async fn check_keys_exist(&self, keys: &[Vec<u8>]) -> Result<Vec<bool>, SlateDbTreeError> {
        let futures: Vec<_> = keys
            .iter()
            .map(|key| async move {
                match self.db.get(key).await {
                    Ok(Some(_)) => Ok(true),
                    Ok(None) => Ok(false),
                    Err(e) => Err(SlateDbTreeError::DbError(e)),
                }
            })
            .collect();

        futures::future::try_join_all(futures).await
    }

    pub async fn new(db: Arc<Db>) -> Result<Self, SlateDbTreeError> {
        let cache = Cache::builder()
            .max_capacity(500_000)
            .time_to_live(std::time::Duration::from_secs(60 * 30)) // 30 minutes
            .build();

        let tree = Self {
            db,
            _phantom_h: core::marker::PhantomData,
            _phantom_t: core::marker::PhantomData,
            node_cache: Some(cache),
            write_lock: Arc::new(Mutex::new(())),
        };

        let existing_leaves = tree.get_num_leaves().await?;

        if existing_leaves.is_none() {
            tree.set_num_leaves(0).await?;
            // Also initialize committed size to 0
            tree.db.put(COMMITTED_SIZE_KEY, &0u64.to_be_bytes()).await?;
        }

        Ok(tree)
    }

    fn leaf_key(index: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(LEAF_PREFIX.len() + 8);
        key.extend_from_slice(LEAF_PREFIX);
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    fn versioned_node_key(index: u64, version: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(VERSIONED_NODE_PREFIX.len() + 16);
        key.extend_from_slice(VERSIONED_NODE_PREFIX);
        key.extend_from_slice(&index.to_be_bytes());
        key.push(b'@');
        key.extend_from_slice(&version.to_be_bytes());
        key
    }

    fn node_latest_version_key(index: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(NODE_LATEST_VERSION_PREFIX.len() + 8);
        key.extend_from_slice(NODE_LATEST_VERSION_PREFIX);
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    async fn get_num_leaves(&self) -> Result<Option<u64>, SlateDbTreeError> {
        match self.db.get(META_KEY).await? {
            Some(bytes) => {
                let bytes_ref: &[u8] = bytes.as_ref();
                let bytes_array: [u8; 8] = bytes_ref
                    .try_into()
                    .map_err(|_| SlateDbTreeError::EncodingError("Invalid metadata".into()))?;
                let num_leaves = u64::from_be_bytes(bytes_array);
                Ok(Some(num_leaves))
            }
            None => Ok(None),
        }
    }

    async fn set_num_leaves(&self, num_leaves: u64) -> Result<(), SlateDbTreeError> {
        self.db
            .put(META_KEY, &num_leaves.to_be_bytes())
            .await
            .map_err(Into::into)
    }

    pub async fn len(&self) -> Result<u64, SlateDbTreeError> {
        Ok(self.get_num_leaves().await?.unwrap_or(0))
    }

    /// Get the last committed tree size (for STH generation)
    pub async fn get_committed_size(&self) -> Result<u64, SlateDbTreeError> {
        match self.db.get(COMMITTED_SIZE_KEY).await? {
            Some(bytes) => {
                let bytes_ref: &[u8] = bytes.as_ref();
                let bytes_array: [u8; 8] = bytes_ref.try_into().map_err(|_| {
                    SlateDbTreeError::EncodingError("Invalid committed size".into())
                })?;
                Ok(u64::from_be_bytes(bytes_array))
            }
            None => {
                // If no committed size is stored, use 0 (empty tree)
                Ok(0)
            }
        }
    }

    /// Appends multiple items to the tree along with additional key-value pairs in a single atomic batch.
    /// This ensures consistency between the merkle tree and any associated data.
    /// Returns the starting index of the newly added items.
    pub async fn batch_push_with_data(
        &self,
        items: Vec<T>,
        additional_data: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<u64, SlateDbTreeError> {
        // Acquire write lock to ensure serialization of write operations
        let _write_guard = self.write_lock.lock().await;

        let starting_index = self.len().await?;

        if items.is_empty() && additional_data.is_empty() {
            return Ok(starting_index);
        }

        // Pre-fetch nodes that exist in the original tree
        let mut nodes_to_prefetch = std::collections::BTreeSet::new();

        // Calculate which nodes we'll need that exist in the original tree
        for i in 0..items.len() {
            let leaf_position = starting_index + i as u64;
            let new_leaf_idx = LeafIdx::new(leaf_position);
            let tree_size_when_processing = leaf_position + 1;

            let mut cur_idx: InternalIdx = new_leaf_idx.into();
            let root_idx = root_idx(tree_size_when_processing);

            while cur_idx != root_idx {
                let sibling_idx = cur_idx.sibling(tree_size_when_processing);

                // Only prefetch siblings that exist in the original tree
                if sibling_idx.as_u64() < starting_index * 2 {
                    nodes_to_prefetch.insert(sibling_idx.as_u64());
                }

                cur_idx = cur_idx.parent(tree_size_when_processing);
            }
        }

        let mut prefetched_nodes = std::collections::BTreeMap::new();
        if !nodes_to_prefetch.is_empty() {
            // Prefetch latest versions for these nodes
            let futures: Vec<_> = nodes_to_prefetch
                .iter()
                .map(|&idx| self.get_node_hash(idx))
                .collect();

            let results = futures::future::try_join_all(futures).await?;

            for (&idx, hash) in nodes_to_prefetch.iter().zip(results.iter()) {
                prefetched_nodes.insert(idx, hash.clone());
            }
        }

        let mut batch = WriteBatch::new();
        let mut current_num_leaves = starting_index;
        let mut computed_hashes = std::collections::BTreeMap::<u64, digest::Output<H>>::new();

        for item in items.iter() {
            let leaf_bytes = postcard::to_stdvec(item)
                .map_err(|e| SlateDbTreeError::EncodingError(e.to_string()))?;
            batch.put(Self::leaf_key(current_num_leaves), &leaf_bytes);

            let new_leaf_idx = LeafIdx::new(current_num_leaves);
            let new_num_leaves = current_num_leaves + 1;

            let mut cur_idx: InternalIdx = new_leaf_idx.into();
            let leaf_hash = leaf_hash::<H, _>(item);
            computed_hashes.insert(cur_idx.as_u64(), leaf_hash.clone());

            let root_idx = root_idx(new_num_leaves);
            let mut cur_hash = leaf_hash;

            while cur_idx != root_idx {
                let parent_idx = cur_idx.parent(new_num_leaves);
                let sibling_idx = cur_idx.sibling(new_num_leaves);

                let sibling_hash = if let Some(hash) = computed_hashes.get(&sibling_idx.as_u64()) {
                    hash.clone()
                } else if sibling_idx.as_u64() >= current_num_leaves * 2 {
                    digest::Output::<H>::default()
                } else if let Some(hash) = prefetched_nodes.get(&sibling_idx.as_u64()) {
                    hash.clone()
                } else {
                    // Read the node at the version before this batch started
                    self.get_node_hash_at_version(sibling_idx.as_u64(), starting_index)
                        .await?
                };

                let parent_hash = if cur_idx.is_left(new_num_leaves) {
                    parent_hash::<H>(&cur_hash, &sibling_hash)
                } else {
                    parent_hash::<H>(&sibling_hash, &cur_hash)
                };

                computed_hashes.insert(parent_idx.as_u64(), parent_hash.clone());

                cur_idx = parent_idx;
                cur_hash = parent_hash;
            }

            current_num_leaves = new_num_leaves;
        }

        // After processing all entries, store versioned nodes for the final tree state
        let final_tree_size = current_num_leaves;
        for (node_idx, node_hash) in computed_hashes.iter() {
            batch.put(
                Self::versioned_node_key(*node_idx, final_tree_size),
                node_hash.as_ref(),
            );
            batch.put(
                Self::node_latest_version_key(*node_idx),
                final_tree_size.to_be_bytes(),
            );
        }

        batch.put(META_KEY, current_num_leaves.to_be_bytes());
        batch.put(COMMITTED_SIZE_KEY, current_num_leaves.to_be_bytes());

        // Add additional key-value pairs to the same batch
        for (key, value) in additional_data {
            batch.put(&key, &value);
        }

        self.db.write(batch).await?;

        Ok(starting_index)
    }

    pub async fn prove_consistency_between(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof<H>, SlateDbTreeError> {
        if old_size == 0 {
            return Err(SlateDbTreeError::InconsistentState(
                "Cannot create consistency proof from empty tree".into(),
            ));
        }

        if old_size > new_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Old size {} must be less than or equal to new size {}",
                old_size, new_size
            )));
        }

        if old_size == new_size {
            return Ok(ConsistencyProof::from_digests(std::iter::empty()));
        }

        let current_size = self.get_committed_size().await?;
        if new_size > current_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "New size {} exceeds current committed tree size {}",
                new_size, current_size
            )));
        }

        // Check if both sizes have versioned nodes
        let old_root_idx = root_idx(old_size);
        let new_root_idx = root_idx(new_size);
        let old_version_check = Self::versioned_node_key(old_root_idx.as_u64(), old_size);
        let new_version_check = Self::versioned_node_key(new_root_idx.as_u64(), new_size);

        let (old_exists, new_exists) = tokio::join!(
            self.db.get(&old_version_check),
            self.db.get(&new_version_check)
        );

        match (old_exists?, new_exists?) {
            (Some(_), Some(_)) => {
                // Both are published STH boundaries
                let idxs = indices_for_consistency_proof(old_size, new_size - old_size);

                // For consistency proofs, we need nodes at the new_size version
                let hash_futures: Vec<_> = idxs
                    .iter()
                    .map(|&node_idx| self.get_node_hash_at_version(node_idx, new_size))
                    .collect();

                let proof_hashes = futures::future::try_join_all(hash_futures).await?;

                Ok(ConsistencyProof::from_digests(proof_hashes.iter()))
            }
            (None, _) => Err(SlateDbTreeError::InconsistentState(format!(
                "Old tree size {} is not a published STH boundary",
                old_size
            ))),
            (_, None) => Err(SlateDbTreeError::InconsistentState(format!(
                "New tree size {} is not a published STH boundary",
                new_size
            ))),
        }
    }

    pub async fn get_node_hash(&self, idx: u64) -> Result<digest::Output<H>, SlateDbTreeError> {
        // Get the latest version for this node
        match self.db.get(&Self::node_latest_version_key(idx)).await? {
            Some(version_bytes) => {
                let version_ref: &[u8] = version_bytes.as_ref();
                let version_array: [u8; 8] = version_ref.try_into().map_err(|_| {
                    SlateDbTreeError::EncodingError("Invalid version format".into())
                })?;
                let latest_version = u64::from_be_bytes(version_array);

                // Get the versioned node at the latest version
                self.get_node_hash_at_version(idx, latest_version).await
            }
            None => {
                // No version pointer means this node doesn't exist yet
                Ok(digest::Output::<H>::default())
            }
        }
    }

    pub async fn get_node_hash_at_version(
        &self,
        idx: u64,
        version: u64,
    ) -> Result<digest::Output<H>, SlateDbTreeError> {
        if let Some(ref cache) = self.node_cache {
            if let Some(cached_hash) = cache.get(&(idx, version)).await {
                let mut hash = digest::Output::<H>::default();
                if cached_hash.len() == hash.len() {
                    hash.copy_from_slice(&cached_hash);
                    return Ok(hash);
                }
            }
        }

        let exact_key = Self::versioned_node_key(idx, version);
        if let Some(bytes) = self.db.get(&exact_key).await? {
            let mut hash = digest::Output::<H>::default();
            if bytes.len() == hash.len() {
                hash.copy_from_slice(&bytes);

                if let Some(ref cache) = self.node_cache {
                    cache.insert((idx, version), bytes.to_vec()).await;
                }

                return Ok(hash);
            } else {
                return Err(SlateDbTreeError::EncodingError("Invalid hash size".into()));
            }
        }

        match self.db.get(&Self::node_latest_version_key(idx)).await? {
            Some(latest_version_bytes) => {
                let latest_version_ref: &[u8] = latest_version_bytes.as_ref();
                let latest_version_array: [u8; 8] =
                    latest_version_ref.try_into().map_err(|_| {
                        SlateDbTreeError::EncodingError("Invalid version format".into())
                    })?;
                let latest_version = u64::from_be_bytes(latest_version_array);

                if latest_version > version {
                    // Node was created after the requested version
                    let default_hash = digest::Output::<H>::default();

                    if let Some(ref cache) = self.node_cache {
                        cache.insert((idx, version), default_hash.to_vec()).await;
                    }

                    Ok(default_hash)
                } else {
                    // Node exists at this version, read from its latest version
                    let versioned_key = Self::versioned_node_key(idx, latest_version);
                    match self.db.get(&versioned_key).await? {
                        Some(bytes) => {
                            let mut hash = digest::Output::<H>::default();
                            if bytes.len() == hash.len() {
                                hash.copy_from_slice(&bytes);

                                // Cache the result with the requested version (not latest_version)
                                if let Some(ref cache) = self.node_cache {
                                    cache.insert((idx, version), bytes.to_vec()).await;
                                }

                                Ok(hash)
                            } else {
                                Err(SlateDbTreeError::EncodingError("Invalid hash size".into()))
                            }
                        }
                        None => {
                            // This shouldn't happen if latest_version pointer is correct
                            Err(SlateDbTreeError::InconsistentState(format!(
                                "Node {} has latest version {} but no data",
                                idx, latest_version
                            )))
                        }
                    }
                }
            }
            None => {
                // No latest version pointer means node doesn't exist at all
                let default_hash = digest::Output::<H>::default();

                // Cache the default result
                if let Some(ref cache) = self.node_cache {
                    cache.insert((idx, version), default_hash.to_vec()).await;
                }

                Ok(default_hash)
            }
        }
    }

    /// Returns the root hash at a specific tree size (for committed STH)
    pub async fn root_at_size(&self, tree_size: u64) -> Result<RootHash<H>, SlateDbTreeError> {
        if tree_size == 0 {
            return Ok(RootHash::new(H::digest(b""), 0));
        }

        let current_size = self.get_committed_size().await?;
        if tree_size > current_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Requested tree size {} exceeds current committed tree size {}",
                tree_size, current_size
            )));
        }

        let root_idx = root_idx(tree_size);

        // Check if this is a published STH boundary
        let version_check_key = Self::versioned_node_key(root_idx.as_u64(), tree_size);
        if self.db.get(&version_check_key).await?.is_none() {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Tree size {} is not a published STH boundary",
                tree_size
            )));
        }

        // Get the root hash for this STH
        let root_hash = self
            .get_node_hash_at_version(root_idx.as_u64(), tree_size)
            .await?;

        Ok(RootHash::new(root_hash, tree_size))
    }

    /// Returns a proof of inclusion of the item at the given index for a specific tree size.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds, tree_size is invalid, or if there's a database error.
    pub async fn prove_inclusion_at_size(
        &self,
        idx: u64,
        tree_size: u64,
    ) -> Result<InclusionProof<H>, SlateDbTreeError> {
        let current_leaves = self.get_committed_size().await?;

        if tree_size > current_leaves {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Requested tree size {} exceeds current committed tree size {}",
                tree_size, current_leaves
            )));
        }

        if idx >= tree_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Index {} out of bounds for requested tree size {}",
                idx, tree_size
            )));
        }

        // Check if we have versioned nodes for this tree size
        // The root node is always stored for each batch
        let root_idx = root_idx(tree_size);
        let version_check_key = Self::versioned_node_key(root_idx.as_u64(), tree_size);

        match self.db.get(&version_check_key).await? {
            Some(_) => {
                // We have versioned nodes for this tree size (published STH)
                let idxs = indices_for_inclusion_proof(tree_size, idx);

                let hash_futures: Vec<_> = idxs
                    .iter()
                    .map(|&node_idx| self.get_node_hash_at_version(node_idx, tree_size))
                    .collect();

                let sibling_hashes = futures::future::try_join_all(hash_futures).await?;

                Ok(InclusionProof::from_digests(sibling_hashes.iter()))
            }
            None => {
                // No versioned nodes for this tree size - not a published STH
                // This is the correct behavior per RFC 6962
                Err(SlateDbTreeError::InconsistentState(format!(
                    "Tree size {} is not a published STH boundary",
                    tree_size
                )))
            }
        }
    }
}

// Test-only methods
#[cfg(test)]
impl<H, T> SlateDbBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf + serde::Serialize + serde::de::DeserializeOwned,
{
    pub async fn is_empty(&self) -> Result<bool, SlateDbTreeError> {
        Ok(self.len().await? == 0)
    }

    pub async fn push(&self, new_val: T) -> Result<(), SlateDbTreeError> {
        // Acquire write lock to ensure serialization of write operations
        let _write_guard = self.write_lock.lock().await;

        let num_leaves = self.len().await?;

        if num_leaves >= u64::MAX / 2 {
            return Err(SlateDbTreeError::InconsistentState("Tree is full".into()));
        }

        let mut batch = WriteBatch::new();

        let leaf_bytes = postcard::to_stdvec(&new_val)
            .map_err(|e| SlateDbTreeError::EncodingError(e.to_string()))?;
        batch.put(Self::leaf_key(num_leaves), &leaf_bytes);

        let new_leaf_idx = LeafIdx::new(num_leaves);
        self.recalculate_path_batch(&mut batch, new_leaf_idx, &new_val, num_leaves + 1)
            .await?;

        batch.put(META_KEY, (num_leaves + 1).to_be_bytes());
        batch.put(COMMITTED_SIZE_KEY, (num_leaves + 1).to_be_bytes());

        self.db.write(batch).await?;

        Ok(())
    }

    async fn recalculate_path_batch(
        &self,
        batch: &mut WriteBatch,
        leaf_idx: LeafIdx,
        leaf_val: &T,
        num_leaves: u64,
    ) -> Result<(), SlateDbTreeError> {
        let mut cur_idx: InternalIdx = leaf_idx.into();
        let leaf_hash = leaf_hash::<H, _>(leaf_val);

        let root_idx = root_idx(num_leaves);

        let mut computed_hashes = std::collections::BTreeMap::<u64, digest::Output<H>>::new();
        computed_hashes.insert(cur_idx.as_u64(), leaf_hash);

        while cur_idx != root_idx {
            let parent_idx = cur_idx.parent(num_leaves);
            let sibling_idx = cur_idx.sibling(num_leaves);

            let cur_node = computed_hashes
                .get(&cur_idx.as_u64())
                .cloned()
                .ok_or_else(|| {
                    SlateDbTreeError::InconsistentState(format!(
                        "Missing computed hash for node {}",
                        cur_idx.as_u64()
                    ))
                })?;

            let sibling = if let Some(hash) = computed_hashes.get(&sibling_idx.as_u64()) {
                hash.clone()
            } else {
                // Read the node at the version before this single-entry batch
                self.get_node_hash_at_version(sibling_idx.as_u64(), num_leaves - 1)
                    .await?
            };

            let parent_hash = if cur_idx.is_left(num_leaves) {
                parent_hash::<H>(&cur_node, &sibling)
            } else {
                parent_hash::<H>(&sibling, &cur_node)
            };

            computed_hashes.insert(parent_idx.as_u64(), parent_hash);

            cur_idx = parent_idx;
        }

        // Store versioned nodes for the final tree state (single-entry batch)
        for (node_idx, node_hash) in computed_hashes.iter() {
            batch.put(
                Self::versioned_node_key(*node_idx, num_leaves),
                node_hash.as_ref(),
            );
            batch.put(
                Self::node_latest_version_key(*node_idx),
                num_leaves.to_be_bytes(),
            );
        }

        Ok(())
    }

    pub async fn root(&self) -> Result<RootHash<H>, SlateDbTreeError> {
        let num_leaves = self.get_committed_size().await?;

        let root_hash = if num_leaves == 0 {
            H::digest(b"")
        } else {
            let root_idx = root_idx(num_leaves);
            self.get_node_hash_at_version(root_idx.as_u64(), num_leaves)
                .await?
        };

        Ok(RootHash::new(root_hash, num_leaves))
    }

    pub async fn get(&self, idx: u64) -> Result<Option<T>, SlateDbTreeError> {
        match self.db.get(&Self::leaf_key(idx)).await? {
            Some(bytes) => {
                let leaf = postcard::from_bytes(&bytes)
                    .map_err(|e| SlateDbTreeError::EncodingError(e.to_string()))?;
                Ok(Some(leaf))
            }
            None => Ok(None),
        }
    }

    pub async fn prove_inclusion(&self, idx: u64) -> Result<InclusionProof<H>, SlateDbTreeError> {
        let num_leaves = self.get_committed_size().await?;

        if idx >= num_leaves {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Index {} out of bounds (tree has {} leaves)",
                idx, num_leaves
            )));
        }

        self.prove_inclusion_at_size(idx, num_leaves).await
    }

    pub async fn prove_consistency(
        &self,
        old_size: u64,
    ) -> Result<ConsistencyProof<H>, SlateDbTreeError> {
        let new_size = self.get_committed_size().await?;

        if old_size == 0 {
            return Err(SlateDbTreeError::InconsistentState(
                "Cannot create consistency proof from empty tree".into(),
            ));
        }

        self.prove_consistency_between(old_size, new_size).await
    }
}

// Separate impl block for methods that need H: Digest constraint
impl<H, T> SlateDbBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Precompute and store subtree roots for efficient static API tile generation
    /// This computes subtree roots only for the range of entries specified
    /// Returns a vector of (key, value) pairs to be included in the batch write
    pub async fn precompute_tile_subtree_roots_for_range(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, SlateDbTreeError> {
        let tree_size = self.get_committed_size().await?;
        if tree_size == 0 || start_index >= end_index {
            return Ok(vec![]);
        }

        let mut potential_subtrees = Vec::new();

        for level in 1..=7 {
            let subtree_size = match 256u64.checked_pow(level as u32) {
                Some(size) => size,
                None => break,
            };
            let positions_per_tile = 256u64;

            let first_affected_position = start_index / (subtree_size / positions_per_tile);
            let last_affected_position = (end_index - 1) / (subtree_size / positions_per_tile);

            let first_tile = first_affected_position / positions_per_tile;
            let last_tile = last_affected_position / positions_per_tile;

            for tile_idx in first_tile..=last_tile {
                let tile_start = match tile_idx.checked_mul(positions_per_tile) {
                    Some(start) => start,
                    None => break,
                };

                for pos in 0..positions_per_tile {
                    let leaf_offset = match tile_start.checked_add(pos) {
                        Some(offset) => offset,
                        None => break,
                    };

                    let leaves_per_position = subtree_size / positions_per_tile;
                    let start_leaf = match leaf_offset.checked_mul(leaves_per_position) {
                        Some(leaf) => leaf,
                        None => break,
                    };

                    let end_leaf = match start_leaf.checked_add(leaves_per_position) {
                        Some(leaf) => leaf,
                        None => tree_size,
                    };

                    if end_leaf <= start_index || start_leaf >= tree_size {
                        continue;
                    }

                    if start_leaf < end_index {
                        let actual_end_leaf = std::cmp::min(end_leaf, tree_size);
                        let subtree_root_idx =
                            crate::merkle_tree::compute_subtree_root(start_leaf, actual_end_leaf);
                        let node_idx = subtree_root_idx.as_u64();
                        potential_subtrees.push((node_idx, start_leaf, actual_end_leaf));
                    }
                }
            }
        }

        potential_subtrees.sort_by_key(|(idx, _, _)| *idx);
        potential_subtrees.dedup_by_key(|(idx, _, _)| *idx);

        let versioned_keys: Vec<Vec<u8>> = potential_subtrees
            .iter()
            .map(|(node_idx, _, _)| Self::versioned_node_key(*node_idx, tree_size))
            .collect();

        let existence_checks =
            futures::future::join_all(versioned_keys.iter().map(|key| self.db.get(key))).await;

        let nodes_to_compute: Vec<(u64, u64, u64)> = potential_subtrees
            .into_iter()
            .zip(existence_checks.iter())
            .filter_map(|((node_idx, start, end), result)| match result {
                Ok(None) => Some((node_idx, start, end)),
                _ => None,
            })
            .collect();

        if nodes_to_compute.is_empty() {
            return Ok(vec![]);
        }

        let mut nodes_by_size: std::collections::BTreeMap<u64, Vec<(u64, u64, u64)>> =
            std::collections::BTreeMap::new();
        for (node_idx, start, end) in nodes_to_compute {
            let size = end - start;
            nodes_by_size
                .entry(size)
                .or_default()
                .push((node_idx, start, end));
        }

        let computed_hashes = Arc::new(RwLock::new(std::collections::BTreeMap::new()));
        let mut batch_data = Vec::new();

        for (_size, nodes_at_size) in nodes_by_size {
            let futures: Vec<_> = nodes_at_size
                .into_iter()
                .map(|(node_idx, start_leaf, end_leaf)| {
                    let computed_hashes = computed_hashes.clone();

                    async move {
                        // Check cache first
                        {
                            let cache = computed_hashes.read().await;
                            if cache.contains_key(&node_idx) {
                                return Ok(None);
                            }
                        }

                        let hash = self
                            .compute_subtree_root_hash_parallel(
                                start_leaf,
                                end_leaf,
                                tree_size,
                                &computed_hashes,
                            )
                            .await?;

                        // Store in cache
                        {
                            let mut cache = computed_hashes.write().await;
                            cache.insert(node_idx, hash.clone());
                        }

                        let versioned_key = Self::versioned_node_key(node_idx, tree_size);
                        let latest_version_key = Self::node_latest_version_key(node_idx);

                        Ok(Some(vec![
                            (versioned_key, hash.as_ref().to_vec()),
                            (latest_version_key, tree_size.to_be_bytes().to_vec()),
                        ]))
                    }
                })
                .collect();

            #[allow(clippy::type_complexity)]
            let results: Vec<
                Result<Option<Vec<(Vec<u8>, Vec<u8>)>>, SlateDbTreeError>,
            > = futures::future::join_all(futures).await;

            for data in results.into_iter().flatten().flatten() {
                batch_data.extend(data);
            }
        }

        Ok(batch_data)
    }

    /// Parallel version of compute_subtree_root_hash that computes left and right subtrees concurrently
    async fn compute_subtree_root_hash_parallel(
        &self,
        start_leaf: u64,
        end_leaf: u64,
        tree_size: u64,
        cache: &Arc<RwLock<std::collections::BTreeMap<u64, digest::Output<H>>>>,
    ) -> Result<digest::Output<H>, SlateDbTreeError> {
        use crate::merkle_tree::ct_merkle_vendored::LeafIdx;

        let size = end_leaf - start_leaf;

        if size == 1 {
            let leaf_idx: InternalIdx = LeafIdx::new(start_leaf).into();
            let node_idx = leaf_idx.as_u64();

            {
                let cache_read = cache.read().await;
                if let Some(hash) = cache_read.get(&node_idx) {
                    return Ok(hash.clone());
                }
            }

            return self.get_node_hash_at_version(node_idx, tree_size).await;
        }

        let subtree_root_idx = crate::merkle_tree::compute_subtree_root(start_leaf, end_leaf);
        let node_idx = subtree_root_idx.as_u64();

        {
            let cache_read = cache.read().await;
            if let Some(hash) = cache_read.get(&node_idx) {
                return Ok(hash.clone());
            }
        }

        let k = crate::merkle_tree::consistency::largest_power_of_two_less_than(size);

        let (left_hash, right_hash) = futures::future::try_join(
            Box::pin(self.compute_subtree_root_hash_parallel(
                start_leaf,
                start_leaf + k,
                tree_size,
                cache,
            )),
            Box::pin(self.compute_subtree_root_hash_parallel(
                start_leaf + k,
                end_leaf,
                tree_size,
                cache,
            )),
        )
        .await?;

        Ok(parent_hash::<H>(&left_hash, &right_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestLeaf {
        data: Vec<u8>,
    }

    impl HashableLeaf for TestLeaf {
        fn hash<H: digest::Update>(&self, hasher: &mut H) {
            hasher.update(&self.data);
        }
    }

    async fn create_test_db() -> Arc<Db> {
        // Use in-memory mode for testing
        let object_store = Arc::new(object_store::memory::InMemory::new());
        let db = Db::builder(object_store::path::Path::from("/test"), object_store)
            .build()
            .await
            .unwrap();
        Arc::new(db)
    }

    #[tokio::test]
    async fn test_new_tree() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        assert!(tree.is_empty().await.unwrap());
        assert_eq!(tree.len().await.unwrap(), 0);
        assert_eq!(tree.get_committed_size().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_single_push() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaf = TestLeaf {
            data: vec![1, 2, 3],
        };
        tree.push(leaf.clone()).await.unwrap();

        assert!(!tree.is_empty().await.unwrap());
        assert_eq!(tree.len().await.unwrap(), 1);
        assert_eq!(tree.get_committed_size().await.unwrap(), 1);

        let retrieved = tree.get(0).await.unwrap();
        assert_eq!(retrieved, Some(leaf));
    }

    #[tokio::test]
    async fn test_batch_push() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaves = vec![
            TestLeaf { data: vec![1] },
            TestLeaf { data: vec![2] },
            TestLeaf { data: vec![3] },
            TestLeaf { data: vec![4] },
        ];

        let start_idx = tree
            .batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();
        assert_eq!(start_idx, 0);
        assert_eq!(tree.len().await.unwrap(), 4);
        assert_eq!(tree.get_committed_size().await.unwrap(), 4);

        // Verify all leaves
        for (i, leaf) in leaves.iter().enumerate() {
            let retrieved = tree.get(i as u64).await.unwrap();
            assert_eq!(retrieved.as_ref(), Some(leaf));
        }
    }

    #[tokio::test]
    async fn test_batch_push_with_data() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> =
            SlateDbBackedTree::new(db.clone()).await.unwrap();

        let leaves = vec![TestLeaf {
            data: vec![1, 2, 3],
        }];
        let additional_data = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
        ];

        tree.batch_push_with_data(leaves, additional_data)
            .await
            .unwrap();

        // Verify the additional data was written
        assert!(db.get(b"key1").await.unwrap().is_some());
        assert!(db.get(b"key2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_root_hash() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Empty tree root
        let empty_root = tree.root().await.unwrap();
        assert_eq!(empty_root.num_leaves(), 0);

        // Add one leaf
        tree.push(TestLeaf { data: vec![1] }).await.unwrap();
        let root1 = tree.root().await.unwrap();
        assert_eq!(root1.num_leaves(), 1);

        // Add another leaf
        tree.push(TestLeaf { data: vec![2] }).await.unwrap();
        let root2 = tree.root().await.unwrap();
        assert_eq!(root2.num_leaves(), 2);

        // Roots should be different
        assert_ne!(root1.as_bytes(), root2.as_bytes());
    }

    #[tokio::test]
    async fn test_root_at_size() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Add leaves in batches to create STH boundaries
        let batch1 = vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }];
        tree.batch_push_with_data(batch1, vec![]).await.unwrap();

        let batch2 = vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }];
        tree.batch_push_with_data(batch2, vec![]).await.unwrap();

        // Should be able to get root at STH boundaries
        let root2 = tree.root_at_size(2).await.unwrap();
        assert_eq!(root2.num_leaves(), 2);

        let root4 = tree.root_at_size(4).await.unwrap();
        assert_eq!(root4.num_leaves(), 4);

        // Should fail for non-STH boundary
        let result = tree.root_at_size(3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_inclusion_proof() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaves = vec![
            TestLeaf { data: vec![1] },
            TestLeaf { data: vec![2] },
            TestLeaf { data: vec![3] },
            TestLeaf { data: vec![4] },
        ];
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();

        let root = tree.root().await.unwrap();

        // Test inclusion proof and verification for each leaf
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove_inclusion(idx as u64).await.unwrap();
            proof
                .verify(leaf, idx as u64, &root)
                .expect("Inclusion proof should verify");
        }

        // Out of bounds should fail
        let result = tree.prove_inclusion(4).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_inclusion_proof_at_size() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create STH boundaries
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();

        // Should work for STH boundaries
        let proof = tree.prove_inclusion_at_size(0, 2).await.unwrap();
        assert!(!proof.as_bytes().is_empty());

        let proof = tree.prove_inclusion_at_size(1, 4).await.unwrap();
        assert!(!proof.as_bytes().is_empty());

        // Should fail for non-STH boundary
        let result = tree.prove_inclusion_at_size(0, 3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_consistency_proof() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create two STH boundaries
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();

        // Consistency proof between STH boundaries
        let proof = tree.prove_consistency_between(2, 4).await.unwrap();
        assert!(!proof.as_bytes().is_empty());

        // Same size should give empty proof
        let proof = tree.prove_consistency(4).await.unwrap();
        assert!(proof.as_bytes().is_empty());

        // Cannot prove from empty tree
        let result = tree.prove_consistency_between(0, 4).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_error_handling() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Test various error conditions

        // Get non-existent leaf
        let result = tree.get(100).await.unwrap();
        assert!(result.is_none());

        // Inclusion proof out of bounds
        let result = tree.prove_inclusion(100).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        // Consistency proof with invalid sizes
        let result = tree.prove_consistency_between(10, 5).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));
    }

    #[tokio::test]
    async fn test_large_batch() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create a large batch
        let leaves: Vec<TestLeaf> = (0..100)
            .map(|i| TestLeaf {
                data: vec![i as u8],
            })
            .collect();

        let start_idx = tree
            .batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();
        assert_eq!(start_idx, 0);
        assert_eq!(tree.len().await.unwrap(), 100);

        // Verify random samples
        for i in [0, 25, 50, 75, 99] {
            let retrieved = tree.get(i as u64).await.unwrap();
            assert_eq!(retrieved, Some(leaves[i].clone()));
        }

        // Consistency proof requires STH boundaries, so this should fail for size 50
        let result = tree.prove_consistency_between(50, 100).await;
        assert!(result.is_err()); // Not a published STH boundary
    }

    #[tokio::test]
    async fn test_node_versioning_and_cache() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Add leaves to create different versions
        tree.batch_push_with_data(vec![TestLeaf { data: vec![1] }], vec![])
            .await
            .unwrap();
        tree.batch_push_with_data(vec![TestLeaf { data: vec![2] }], vec![])
            .await
            .unwrap();
        tree.batch_push_with_data(vec![TestLeaf { data: vec![3] }], vec![])
            .await
            .unwrap();

        // Test that we can get node hashes at different versions
        let root1 = tree.root_at_size(1).await.unwrap();
        let root2 = tree.root_at_size(2).await.unwrap();
        let root3 = tree.root_at_size(3).await.unwrap();

        // All roots should be different
        assert_ne!(root1.as_bytes(), root2.as_bytes());
        assert_ne!(root2.as_bytes(), root3.as_bytes());
        assert_ne!(root1.as_bytes(), root3.as_bytes());

        // Test cache behavior by accessing the same node multiple times
        for _ in 0..3 {
            let root_again = tree.root_at_size(2).await.unwrap();
            assert_eq!(root2.as_bytes(), root_again.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_versioning_node_reuse() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Build a tree structure where some nodes will be reused across versions
        // Tree at size 4: complete binary tree
        tree.batch_push_with_data(
            vec![
                TestLeaf { data: vec![1] },
                TestLeaf { data: vec![2] },
                TestLeaf { data: vec![3] },
                TestLeaf { data: vec![4] },
            ],
            vec![],
        )
        .await
        .unwrap();

        // Add more leaves - the left subtree (nodes 0-3) remains unchanged
        tree.batch_push_with_data(
            vec![
                TestLeaf { data: vec![5] },
                TestLeaf { data: vec![6] },
                TestLeaf { data: vec![7] },
                TestLeaf { data: vec![8] },
            ],
            vec![],
        )
        .await
        .unwrap();

        // Test that nodes in the unchanged subtree have the same hash at both versions

        // Leaf 0 node should be the same at both versions
        let leaf0_idx: InternalIdx = LeafIdx::new(0).into();
        let leaf0_at_v4 = tree
            .get_node_hash_at_version(leaf0_idx.as_u64(), 4)
            .await
            .unwrap();
        let leaf0_at_v8 = tree
            .get_node_hash_at_version(leaf0_idx.as_u64(), 8)
            .await
            .unwrap();
        assert_eq!(
            leaf0_at_v4, leaf0_at_v8,
            "Unchanged leaf should have same hash"
        );

        // But the root should be different
        let root_at_v4 = tree.root_at_size(4).await.unwrap();
        let root_at_v8 = tree.root_at_size(8).await.unwrap();
        assert_ne!(
            root_at_v4.as_bytes(),
            root_at_v8.as_bytes(),
            "Roots should differ"
        );
    }

    #[tokio::test]
    async fn test_versioning_non_existent_nodes() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create a small tree
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();

        // Try to get nodes that don't exist at version 2
        // Node at index 4 (would be leaf 2) doesn't exist yet
        let non_existent = tree.get_node_hash_at_version(4, 2).await.unwrap();
        assert_eq!(
            non_existent,
            digest::Output::<Sha256>::default(),
            "Non-existent node should return default hash"
        );

        // Add more leaves
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();

        // Now node 4 exists at version 4
        let exists_now = tree.get_node_hash_at_version(4, 4).await.unwrap();
        assert_ne!(
            exists_now,
            digest::Output::<Sha256>::default(),
            "Node should exist at version 4"
        );

        // But still doesn't exist at version 2
        let still_not_at_v2 = tree.get_node_hash_at_version(4, 2).await.unwrap();
        assert_eq!(
            still_not_at_v2,
            digest::Output::<Sha256>::default(),
            "Node should still not exist at version 2"
        );
    }

    #[tokio::test]
    async fn test_versioning_with_gaps() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create versions 1, 3, 7 (with gaps)
        tree.batch_push_with_data(vec![TestLeaf { data: vec![1] }], vec![])
            .await
            .unwrap();
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![2] }, TestLeaf { data: vec![3] }],
            vec![],
        )
        .await
        .unwrap();
        tree.batch_push_with_data(
            vec![
                TestLeaf { data: vec![4] },
                TestLeaf { data: vec![5] },
                TestLeaf { data: vec![6] },
                TestLeaf { data: vec![7] },
            ],
            vec![],
        )
        .await
        .unwrap();

        // Test accessing at non-STH boundaries fails
        assert!(
            tree.root_at_size(2).await.is_err(),
            "Size 2 is not an STH boundary"
        );
        assert!(
            tree.root_at_size(4).await.is_err(),
            "Size 4 is not an STH boundary"
        );
        assert!(
            tree.root_at_size(5).await.is_err(),
            "Size 5 is not an STH boundary"
        );
        assert!(
            tree.root_at_size(6).await.is_err(),
            "Size 6 is not an STH boundary"
        );

        // But STH boundaries work
        assert!(tree.root_at_size(1).await.is_ok());
        assert!(tree.root_at_size(3).await.is_ok());
        assert!(tree.root_at_size(7).await.is_ok());
    }

    #[tokio::test]
    async fn test_versioning_latest_pointer_consistency() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> =
            SlateDbBackedTree::new(db.clone()).await.unwrap();

        // Add initial batch
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();

        // Get node hash using latest version
        let node0_latest = tree.get_node_hash(0).await.unwrap();
        let node0_at_v2 = tree.get_node_hash_at_version(0, 2).await.unwrap();
        assert_eq!(node0_latest, node0_at_v2, "Latest should match version 2");

        // Add more leaves
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();

        // Latest pointer should now point to version 4 for unchanged nodes
        let node0_latest_after = tree.get_node_hash(0).await.unwrap();
        assert_eq!(
            node0_latest, node0_latest_after,
            "Unchanged node should have same hash even with new latest version"
        );

        // But nodes that changed should have different latest
        let root_idx = root_idx(4).as_u64();
        let root_latest = tree.get_node_hash(root_idx).await.unwrap();
        let root_at_v2 = tree.get_node_hash_at_version(root_idx, 2).await.unwrap();
        assert_ne!(
            root_latest, root_at_v2,
            "Root should be different at different versions"
        );
    }

    #[tokio::test]
    async fn test_versioning_proof_consistency() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Build tree with multiple versions
        let batch1 = vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }];
        tree.batch_push_with_data(batch1.clone(), vec![])
            .await
            .unwrap();

        let batch2 = vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }];
        tree.batch_push_with_data(batch2.clone(), vec![])
            .await
            .unwrap();

        let batch3 = vec![
            TestLeaf { data: vec![5] },
            TestLeaf { data: vec![6] },
            TestLeaf { data: vec![7] },
            TestLeaf { data: vec![8] },
        ];
        tree.batch_push_with_data(batch3, vec![]).await.unwrap();

        // Get inclusion proofs for leaf 0 at different tree sizes
        let proof_at_2 = tree.prove_inclusion_at_size(0, 2).await.unwrap();
        let proof_at_4 = tree.prove_inclusion_at_size(0, 4).await.unwrap();
        let proof_at_8 = tree.prove_inclusion_at_size(0, 8).await.unwrap();

        // Get roots at those sizes
        let root2 = tree.root_at_size(2).await.unwrap();
        let root4 = tree.root_at_size(4).await.unwrap();
        let root8 = tree.root_at_size(8).await.unwrap();

        // All proofs should verify correctly at their respective tree sizes
        proof_at_2
            .verify(&batch1[0], 0, &root2)
            .expect("Proof at size 2 should verify");
        proof_at_4
            .verify(&batch1[0], 0, &root4)
            .expect("Proof at size 4 should verify");
        proof_at_8
            .verify(&batch1[0], 0, &root8)
            .expect("Proof at size 8 should verify");

        // Cross-version verification should fail
        assert!(
            proof_at_2.verify(&batch1[0], 0, &root4).is_err(),
            "Proof from size 2 should not verify against root at size 4"
        );
        assert!(
            proof_at_4.verify(&batch1[0], 0, &root8).is_err(),
            "Proof from size 4 should not verify against root at size 8"
        );
    }

    #[tokio::test]
    async fn test_versioning_concurrent_reads() {
        use futures::future::join_all;

        let db = create_test_db().await;
        let tree = Arc::new(
            SlateDbBackedTree::<Sha256, TestLeaf>::new(db)
                .await
                .unwrap(),
        );

        // Create multiple versions
        for i in 0..5 {
            let batch: Vec<TestLeaf> = (0..4)
                .map(|j| TestLeaf {
                    data: vec![(i * 4 + j) as u8],
                })
                .collect();
            tree.batch_push_with_data(batch, vec![]).await.unwrap();
        }

        // Now we have versions at sizes: 4, 8, 12, 16, 20
        let versions = vec![4, 8, 12, 16, 20];

        // Concurrent reads of different versions
        let mut handles = vec![];

        for _ in 0..10 {
            for &version in &versions {
                let tree_clone = Arc::clone(&tree);
                let handle = tokio::spawn(async move {
                    // Get root at specific version
                    let root = tree_clone.root_at_size(version).await.unwrap();
                    assert_eq!(root.num_leaves(), version);

                    // Get some node hashes at this version
                    for i in 0..3 {
                        let _ = tree_clone
                            .get_node_hash_at_version(i, version)
                            .await
                            .unwrap();
                    }

                    // Get inclusion proof at this version
                    if version > 0 {
                        let _ = tree_clone
                            .prove_inclusion_at_size(0, version)
                            .await
                            .unwrap();
                    }
                });
                handles.push(handle);
            }
        }

        // All concurrent operations should succeed
        let results: Vec<_> = join_all(handles).await;
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_versioning_node_evolution() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Track how a specific internal node changes across versions
        // We'll track node at index 1 (parent of leaves 0 and 1)
        let parent_idx = 1u64;

        // Version 1: Only one leaf, so parent doesn't exist yet
        tree.batch_push_with_data(vec![TestLeaf { data: vec![1] }], vec![])
            .await
            .unwrap();
        let parent_v1 = tree.get_node_hash_at_version(parent_idx, 1).await.unwrap();
        assert_eq!(
            parent_v1,
            digest::Output::<Sha256>::default(),
            "Parent shouldn't exist with only one leaf"
        );

        // Version 2: Two leaves, parent now exists
        tree.batch_push_with_data(vec![TestLeaf { data: vec![2] }], vec![])
            .await
            .unwrap();
        let parent_v2 = tree.get_node_hash_at_version(parent_idx, 2).await.unwrap();
        assert_ne!(
            parent_v2,
            digest::Output::<Sha256>::default(),
            "Parent should exist with two leaves"
        );

        // Version 4: Four leaves, parent remains the same (leaves 0,1 unchanged)
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();
        let parent_v4 = tree.get_node_hash_at_version(parent_idx, 4).await.unwrap();
        assert_eq!(
            parent_v2, parent_v4,
            "Parent of unchanged subtree should remain the same"
        );

        // Verify latest version pointer
        let parent_latest = tree.get_node_hash(parent_idx).await.unwrap();
        assert_eq!(
            parent_latest, parent_v4,
            "Latest should match most recent version"
        );
    }

    #[tokio::test]
    async fn test_mixed_push_and_batch_operations() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Mix single push and batch operations
        tree.push(TestLeaf { data: vec![1] }).await.unwrap();
        assert_eq!(tree.len().await.unwrap(), 1);

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![2] }, TestLeaf { data: vec![3] }],
            vec![],
        )
        .await
        .unwrap();
        assert_eq!(tree.len().await.unwrap(), 3);

        tree.push(TestLeaf { data: vec![4] }).await.unwrap();
        assert_eq!(tree.len().await.unwrap(), 4);

        // Verify all data is accessible
        for i in 0..4 {
            let leaf = tree.get(i).await.unwrap().unwrap();
            assert_eq!(leaf.data, vec![(i + 1) as u8]);
        }

        // Verify proofs work across mixed operations
        let proof = tree.prove_inclusion(0).await.unwrap();
        assert!(!proof.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn test_empty_batch_operations() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Empty batch should be no-op
        let start_idx = tree.batch_push_with_data(vec![], vec![]).await.unwrap();
        assert_eq!(start_idx, 0);
        assert_eq!(tree.len().await.unwrap(), 0);

        // Empty batch with data should still work
        let additional_data = vec![(b"key".to_vec(), b"value".to_vec())];
        tree.batch_push_with_data(vec![], additional_data)
            .await
            .unwrap();
        assert_eq!(tree.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_committed_size_tracking() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Initially committed size should be 0
        assert_eq!(tree.get_committed_size().await.unwrap(), 0);
        assert_eq!(tree.len().await.unwrap(), 0);

        // After adding leaves, committed size should update
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();

        assert_eq!(tree.get_committed_size().await.unwrap(), 2);
        assert_eq!(tree.len().await.unwrap(), 2);

        // Root should be available at committed size
        let root = tree.root().await.unwrap();
        assert_eq!(root.num_leaves(), 2);
    }

    #[tokio::test]
    async fn test_tree_size_validation() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        tree.batch_push_with_data(
            vec![
                TestLeaf { data: vec![1] },
                TestLeaf { data: vec![2] },
                TestLeaf { data: vec![3] },
            ],
            vec![],
        )
        .await
        .unwrap();

        // Test root_at_size with invalid sizes
        let result = tree.root_at_size(5).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        // Test prove_inclusion_at_size with invalid sizes
        let result = tree.prove_inclusion_at_size(0, 5).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        let result = tree.prove_inclusion_at_size(5, 3).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        // Test consistency proof with invalid sizes
        let result = tree.prove_consistency_between(5, 3).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        let result = tree.prove_consistency_between(2, 5).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));
    }

    #[tokio::test]
    async fn test_sth_boundary_enforcement() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create multiple batches to establish STH boundaries
        tree.batch_push_with_data(vec![TestLeaf { data: vec![1] }], vec![])
            .await
            .unwrap(); // STH at size 1
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![2] }, TestLeaf { data: vec![3] }],
            vec![],
        )
        .await
        .unwrap(); // STH at size 3

        // Should be able to prove inclusion at STH boundaries
        tree.prove_inclusion_at_size(0, 1).await.unwrap();
        tree.prove_inclusion_at_size(1, 3).await.unwrap();

        // Should NOT be able to prove inclusion at non-STH boundary (size 2)
        let result = tree.prove_inclusion_at_size(0, 2).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        // Should be able to get roots at STH boundaries
        tree.root_at_size(1).await.unwrap();
        tree.root_at_size(3).await.unwrap();

        // Should NOT be able to get root at non-STH boundary
        let result = tree.root_at_size(2).await;
        assert!(matches!(
            result,
            Err(SlateDbTreeError::InconsistentState(_))
        ));

        // Consistency proofs should work between STH boundaries
        tree.prove_consistency_between(1, 3).await.unwrap();
    }

    #[tokio::test]
    async fn test_single_leaf_tree() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Add single leaf
        tree.push(TestLeaf { data: vec![42] }).await.unwrap();

        // Single leaf tree should have empty inclusion proof
        let proof = tree.prove_inclusion(0).await.unwrap();
        assert!(proof.as_bytes().is_empty());

        // Root should be the leaf hash (with prefix)
        let root = tree.root().await.unwrap();
        assert_eq!(root.num_leaves(), 1);
        assert!(!root.as_bytes().iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn test_node_hash_retrieval() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Add some leaves to create internal nodes
        tree.batch_push_with_data(
            vec![
                TestLeaf { data: vec![1] },
                TestLeaf { data: vec![2] },
                TestLeaf { data: vec![3] },
                TestLeaf { data: vec![4] },
            ],
            vec![],
        )
        .await
        .unwrap();

        // Get root hash
        let root_hash = tree.get_node_hash(root_idx(4).as_u64()).await.unwrap();
        assert!(!root_hash.iter().all(|&b| b == 0));

        // Get leaf hashes (even indices)
        let leaf0_hash = tree.get_node_hash(0).await.unwrap();
        let leaf1_hash = tree.get_node_hash(2).await.unwrap();
        assert_ne!(leaf0_hash, leaf1_hash);

        // Test that we can get the root hash consistently
        let root_hash_again = tree.get_node_hash(root_idx(4).as_u64()).await.unwrap();
        assert_eq!(root_hash, root_hash_again);
    }

    #[tokio::test]
    async fn test_consistency_proof_same_size() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();

        // Consistency proof for same size should be empty
        let proof = tree.prove_consistency_between(2, 2).await.unwrap();
        assert!(proof.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn test_multiple_sequential_batches() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Add multiple batches sequentially
        for batch_num in 0..5 {
            let batch: Vec<TestLeaf> = (0..3)
                .map(|i| TestLeaf {
                    data: vec![batch_num * 3 + i],
                })
                .collect();

            let start_idx = tree.batch_push_with_data(batch, vec![]).await.unwrap();
            assert_eq!(start_idx, (batch_num * 3) as u64);
        }

        assert_eq!(tree.len().await.unwrap(), 15);

        // Test consistency proofs between different batch boundaries
        tree.prove_consistency_between(3, 6).await.unwrap();
        tree.prove_consistency_between(6, 12).await.unwrap();
        tree.prove_consistency_between(3, 15).await.unwrap();

        // Test inclusion proofs at various boundaries
        tree.prove_inclusion_at_size(0, 3).await.unwrap();
        tree.prove_inclusion_at_size(5, 9).await.unwrap();
        tree.prove_inclusion_at_size(8, 15).await.unwrap();
    }

    #[tokio::test]
    async fn test_inclusion_proof_at_historical_sizes() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Build tree with multiple STH boundaries
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![0] }, TestLeaf { data: vec![1] }],
            vec![],
        )
        .await
        .unwrap(); // STH at size 2

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![2] }, TestLeaf { data: vec![3] }],
            vec![],
        )
        .await
        .unwrap(); // STH at size 4

        tree.batch_push_with_data(
            vec![
                TestLeaf { data: vec![4] },
                TestLeaf { data: vec![5] },
                TestLeaf { data: vec![6] },
                TestLeaf { data: vec![7] },
            ],
            vec![],
        )
        .await
        .unwrap(); // STH at size 8

        // Get inclusion proofs for the same leaf at different tree sizes
        let proof_leaf0_at_size2 = tree.prove_inclusion_at_size(0, 2).await.unwrap();
        let proof_leaf0_at_size4 = tree.prove_inclusion_at_size(0, 4).await.unwrap();
        let proof_leaf0_at_size8 = tree.prove_inclusion_at_size(0, 8).await.unwrap();

        // These should all be different proofs
        assert_ne!(
            proof_leaf0_at_size2.as_bytes(),
            proof_leaf0_at_size4.as_bytes()
        );
        assert_ne!(
            proof_leaf0_at_size4.as_bytes(),
            proof_leaf0_at_size8.as_bytes()
        );

        // Proof lengths should increase with tree size
        assert!(proof_leaf0_at_size2.as_bytes().len() < proof_leaf0_at_size8.as_bytes().len());

        // Test that we can get proofs for later leaves only at appropriate sizes
        let result = tree.prove_inclusion_at_size(3, 2).await;
        assert!(result.is_err()); // Leaf 3 doesn't exist at size 2

        let proof_leaf3_at_size4 = tree.prove_inclusion_at_size(3, 4).await.unwrap();
        let proof_leaf3_at_size8 = tree.prove_inclusion_at_size(3, 8).await.unwrap();
        assert_ne!(
            proof_leaf3_at_size4.as_bytes(),
            proof_leaf3_at_size8.as_bytes()
        );
    }

    #[tokio::test]
    async fn test_inclusion_proof_consistency_across_sizes() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create a larger tree to test various scenarios
        let leaves: Vec<TestLeaf> = (0..16).map(|i| TestLeaf { data: vec![i] }).collect();
        tree.batch_push_with_data(leaves, vec![]).await.unwrap();

        // Test that inclusion proofs are generated correctly for various positions
        for idx in [0, 1, 7, 8, 15] {
            let proof = tree.prove_inclusion(idx).await.unwrap();

            // Calculate expected proof length based on tree structure
            // For a tree of size 16 (perfect binary tree), all proofs should be log2(16) = 4 hashes
            assert_eq!(
                proof.as_bytes().len(),
                4 * 32,
                "Unexpected proof length for index {}",
                idx
            );
        }

        // Add more leaves to make it non-perfect
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![16] }, TestLeaf { data: vec![17] }],
            vec![],
        )
        .await
        .unwrap();

        // Now tree size is 18, proofs will have varying lengths
        let proof16 = tree.prove_inclusion(16).await.unwrap();
        let proof17 = tree.prove_inclusion(17).await.unwrap();

        // These new leaves should have different proof structures
        assert!(!proof16.as_bytes().is_empty());
        assert!(!proof17.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn test_inclusion_indices_calculation() {
        // Test the indices calculation directly

        // Single leaf tree - empty proof
        let indices = indices_for_inclusion_proof(1, 0);
        assert!(indices.is_empty());

        // Tree size 2
        let indices = indices_for_inclusion_proof(2, 0);
        assert_eq!(indices.len(), 1); // Need sibling

        let indices = indices_for_inclusion_proof(2, 1);
        assert_eq!(indices.len(), 1); // Need sibling

        // Tree size 8 (perfect binary tree)
        for idx in 0..8 {
            let indices = indices_for_inclusion_proof(8, idx);
            assert_eq!(indices.len(), 3); // log2(8) = 3
        }

        // Tree size 7 (non-perfect)
        let indices_0 = indices_for_inclusion_proof(7, 0);
        let indices_6 = indices_for_inclusion_proof(7, 6);

        // Different positions might need different numbers of hashes
        assert!(!indices_0.is_empty());
        assert!(!indices_6.is_empty());
    }

    #[tokio::test]
    async fn test_inclusion_proof_single_leaf() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaf = TestLeaf { data: vec![42] };
        tree.push(leaf.clone()).await.unwrap();

        let root = tree.root().await.unwrap();
        let proof = tree.prove_inclusion(0).await.unwrap();

        // Single leaf tree should have empty proof
        assert!(proof.as_bytes().is_empty());

        // Should still verify
        proof
            .verify(&leaf, 0, &root)
            .expect("Single leaf proof should verify");
    }

    #[tokio::test]
    async fn test_inclusion_proof_at_historical_size_verification() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Build tree with multiple STH boundaries
        let batch1 = vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }];
        tree.batch_push_with_data(batch1.clone(), vec![])
            .await
            .unwrap();
        let root2 = tree.root_at_size(2).await.unwrap();

        let batch2 = vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }];
        tree.batch_push_with_data(batch2, vec![]).await.unwrap();
        let root4 = tree.root_at_size(4).await.unwrap();

        // Verify inclusion at historical size
        let proof_at_2 = tree.prove_inclusion_at_size(0, 2).await.unwrap();
        proof_at_2
            .verify(&batch1[0], 0, &root2)
            .expect("Historical inclusion proof should verify");

        // Same leaf at different tree size should have different proof
        let proof_at_4 = tree.prove_inclusion_at_size(0, 4).await.unwrap();
        proof_at_4
            .verify(&batch1[0], 0, &root4)
            .expect("Inclusion proof at larger tree should verify");

        // Proofs should be different
        assert_ne!(proof_at_2.as_bytes(), proof_at_4.as_bytes());

        // Wrong tree size should fail
        assert!(proof_at_2.verify(&batch1[0], 0, &root4).is_err());
    }

    #[tokio::test]
    async fn test_consistency_proof_verification() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create STH boundaries
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();
        let root2 = tree.root_at_size(2).await.unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();
        let root4 = tree.root_at_size(4).await.unwrap();

        // Get and verify consistency proof
        let proof = tree.prove_consistency_between(2, 4).await.unwrap();

        // Verify the consistency proof
        proof
            .verify(&root2, &root4)
            .expect("Consistency proof should verify");
    }

    #[tokio::test]
    async fn test_consistency_proof_same_size_verification() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();
        let root = tree.root_at_size(2).await.unwrap();

        // Same size consistency proof should be empty
        let proof = tree.prove_consistency_between(2, 2).await.unwrap();
        assert!(proof.as_bytes().is_empty());

        // Should verify successfully
        proof
            .verify(&root, &root)
            .expect("Same size consistency proof should verify");
    }

    #[tokio::test]
    async fn test_inclusion_proof_wrong_root() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaves = vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }];
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();
        let root2 = tree.root().await.unwrap();

        // Add more leaves
        tree.batch_push_with_data(vec![TestLeaf { data: vec![3] }], vec![])
            .await
            .unwrap();
        let root3 = tree.root().await.unwrap();

        // Get proof for leaf 0 at size 2
        let proof = tree.prove_inclusion_at_size(0, 2).await.unwrap();

        // Should verify against correct root
        proof
            .verify(&leaves[0], 0, &root2)
            .expect("Should verify against correct root");

        // Should fail against wrong root
        assert!(proof.verify(&leaves[0], 0, &root3).is_err());
    }

    #[tokio::test]
    async fn test_consistency_proof_wrong_roots() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create multiple STH boundaries
        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![1] }, TestLeaf { data: vec![2] }],
            vec![],
        )
        .await
        .unwrap();
        let root2 = tree.root_at_size(2).await.unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![3] }, TestLeaf { data: vec![4] }],
            vec![],
        )
        .await
        .unwrap();
        let root4 = tree.root_at_size(4).await.unwrap();

        tree.batch_push_with_data(
            vec![TestLeaf { data: vec![5] }, TestLeaf { data: vec![6] }],
            vec![],
        )
        .await
        .unwrap();
        let root6 = tree.root_at_size(6).await.unwrap();

        // Get consistency proof between 2 and 4
        let proof_2_4 = tree.prove_consistency_between(2, 4).await.unwrap();

        // Should verify correctly
        proof_2_4
            .verify(&root2, &root4)
            .expect("Consistency proof 2->4 should verify");

        // Should fail with wrong old root
        assert!(
            proof_2_4.verify(&root4, &root4).is_err(),
            "Should fail with wrong old root"
        );

        // Should fail with wrong new root
        assert!(
            proof_2_4.verify(&root2, &root6).is_err(),
            "Should fail with wrong new root"
        );

        // Should fail with swapped roots
        assert!(
            proof_2_4.verify(&root4, &root2).is_err(),
            "Should fail with swapped roots"
        );
    }

    #[tokio::test]
    async fn test_batch_push_thread_safe() {
        // This test demonstrates that batch_push_with_data is thread-safe
        use futures::future::join_all;

        let db = create_test_db().await;
        let tree = Arc::new(
            SlateDbBackedTree::<Sha256, TestLeaf>::new(db)
                .await
                .unwrap(),
        );

        // Launch multiple concurrent batch pushes WITHOUT external mutex
        let mut handles = vec![];

        for i in 0..5 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                let batch: Vec<TestLeaf> = (0..10)
                    .map(|j| TestLeaf {
                        data: vec![(i * 10 + j) as u8],
                    })
                    .collect();
                tree_clone.batch_push_with_data(batch, vec![]).await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<_> = join_all(handles).await;

        // All operations should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // The tree should contain all 50 leaves correctly
        // (internal write lock ensures no race condition)
        assert_eq!(tree.len().await.unwrap(), 50);

        // Tree is consistent
        let root = tree.root().await.unwrap();
        assert_eq!(root.num_leaves(), 50);

        // All leaves are valid and in order
        for i in 0..50 {
            let leaf = tree.get(i).await.unwrap();
            assert!(leaf.is_some(), "Leaf at index {} should exist", i);
        }
    }

    #[tokio::test]
    async fn test_rfc6962_hash_prefixes() {
        use sha2::Digest as Sha2Digest;

        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Add two leaves to create a parent node
        let leaf1 = TestLeaf { data: vec![1] };
        let leaf2 = TestLeaf { data: vec![2] };
        tree.batch_push_with_data(vec![leaf1.clone(), leaf2.clone()], vec![])
            .await
            .unwrap();

        // Manually compute leaf hashes with 0x00 prefix
        let mut leaf1_hasher = Sha256::new();
        leaf1_hasher.update([0x00]); // Leaf prefix
        leaf1_hasher.update(&leaf1.data);
        let expected_leaf1_hash = leaf1_hasher.finalize();

        let mut leaf2_hasher = Sha256::new();
        leaf2_hasher.update([0x00]); // Leaf prefix
        leaf2_hasher.update(&leaf2.data);
        let expected_leaf2_hash = leaf2_hasher.finalize();

        // Compute expected parent hash with 0x01 prefix
        let mut parent_hasher = Sha256::new();
        parent_hasher.update([0x01]); // Parent prefix
        parent_hasher.update(expected_leaf1_hash);
        parent_hasher.update(expected_leaf2_hash);
        let expected_parent_hash = parent_hasher.finalize();

        // Get actual hashes from tree
        let leaf1_node_hash = tree.get_node_hash(0).await.unwrap(); // Leaf 1 is at index 0
        let leaf2_node_hash = tree.get_node_hash(2).await.unwrap(); // Leaf 2 is at index 2
        let parent_node_hash = tree.get_node_hash(1).await.unwrap(); // Parent is at index 1

        // Verify leaf hashes use 0x00 prefix
        assert_eq!(
            leaf1_node_hash.as_slice(),
            expected_leaf1_hash.as_slice(),
            "Leaf 1 hash should use 0x00 prefix"
        );
        assert_eq!(
            leaf2_node_hash.as_slice(),
            expected_leaf2_hash.as_slice(),
            "Leaf 2 hash should use 0x00 prefix"
        );

        // Verify parent hash uses 0x01 prefix
        assert_eq!(
            parent_node_hash.as_slice(),
            expected_parent_hash.as_slice(),
            "Parent hash should use 0x01 prefix"
        );

        // Test with inclusion proof to ensure it's using correct hashes
        let proof = tree.prove_inclusion(0).await.unwrap();
        let root = tree.root().await.unwrap();

        // This should verify successfully only if hashes use correct prefixes
        proof
            .verify(&leaf1, 0, &root)
            .expect("Proof should verify with correct prefixes");
    }

    #[tokio::test]
    async fn test_concurrent_read_operations() {
        use futures::future::join_all;

        let db = create_test_db().await;
        let tree = SlateDbBackedTree::<Sha256, TestLeaf>::new(db)
            .await
            .unwrap();

        // Add some data
        let leaves: Vec<TestLeaf> = (0..100)
            .map(|i| TestLeaf {
                data: vec![i as u8],
            })
            .collect();
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();

        // Now wrap in Arc for concurrent reads
        let tree = Arc::new(tree);

        // Perform many concurrent read operations
        let mut handles = vec![];

        // Concurrent gets
        for i in 0..20 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                for j in 0..5 {
                    let idx = (i * 5 + j) % 100;
                    let leaf = tree_clone.get(idx).await.unwrap();
                    assert_eq!(leaf.unwrap().data, vec![idx as u8]);
                }
            });
            handles.push(handle);
        }

        // Concurrent proof generation
        for i in 0..10 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                let idx = (i * 10) % 100;
                let proof = tree_clone.prove_inclusion(idx).await.unwrap();
                let root = tree_clone.root().await.unwrap();
                let leaf = tree_clone.get(idx).await.unwrap().unwrap();
                proof
                    .verify(&leaf, idx, &root)
                    .expect("Proof should verify");
            });
            handles.push(handle);
        }

        // Concurrent root calculations
        for _ in 0..10 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                let root = tree_clone.root().await.unwrap();
                assert_eq!(root.num_leaves(), 100);
            });
            handles.push(handle);
        }

        // Wait for all operations
        let results: Vec<_> = join_all(handles).await;
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_malformed_proof_detection() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaves = vec![
            TestLeaf { data: vec![1] },
            TestLeaf { data: vec![2] },
            TestLeaf { data: vec![3] },
            TestLeaf { data: vec![4] },
        ];
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();

        let root = tree.root().await.unwrap();
        let _valid_proof = tree.prove_inclusion(0).await.unwrap();

        // Create malformed proofs

        // Wrong length proof (too short)
        let short_proof = InclusionProof::from_digests(std::iter::empty());
        assert!(
            short_proof.verify(&leaves[0], 0, &root).is_err(),
            "Should reject too short proof"
        );
    }

    #[tokio::test]
    async fn test_thread_safe_concurrent_writes() {
        use futures::future::join_all;

        let db = create_test_db().await;
        let tree = Arc::new(
            SlateDbBackedTree::<Sha256, TestLeaf>::new(db)
                .await
                .unwrap(),
        );

        // Create multiple concurrent write operations
        let mut handles = vec![];

        for i in 0..10 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                let batch: Vec<TestLeaf> = (0..5)
                    .map(|j| TestLeaf {
                        data: vec![(i * 5 + j) as u8],
                    })
                    .collect();
                tree_clone.batch_push_with_data(batch, vec![]).await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<_> = join_all(handles).await;

        // All operations should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // All 50 leaves should be added (10 batches * 5 leaves each)
        assert_eq!(tree.len().await.unwrap(), 50);

        // All leaves should be retrievable and in order
        for i in 0..50 {
            let leaf = tree.get(i).await.unwrap();
            assert!(leaf.is_some(), "Leaf at index {} should exist", i);
        }

        // Tree should be consistent
        let root = tree.root().await.unwrap();
        assert_eq!(root.num_leaves(), 50);
    }

    #[tokio::test]
    async fn test_thread_safe_mixed_operations() {
        use futures::future::join_all;

        let db = create_test_db().await;
        let tree = Arc::new(
            SlateDbBackedTree::<Sha256, TestLeaf>::new(db)
                .await
                .unwrap(),
        );

        // First add some data
        let initial_batch: Vec<TestLeaf> = (0..20)
            .map(|i| TestLeaf {
                data: vec![i as u8],
            })
            .collect();
        tree.batch_push_with_data(initial_batch, vec![])
            .await
            .unwrap();

        // Now perform mixed read and write operations concurrently
        let mut write_handles = vec![];
        let mut read_handles = vec![];

        // Writers
        for i in 0..5 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                let batch: Vec<TestLeaf> = (0..4)
                    .map(|j| TestLeaf {
                        data: vec![(100 + i * 4 + j) as u8],
                    })
                    .collect();
                tree_clone.batch_push_with_data(batch, vec![]).await
            });
            write_handles.push(handle);
        }

        // Readers performing various operations
        for i in 0..10 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                // Get operations
                for j in 0..5 {
                    let idx = (i * 2 + j) % 20; // Only read initial data
                    let _ = tree_clone.get(idx).await.unwrap();
                }

                // Root calculations
                let _ = tree_clone.root().await.unwrap();

                // Length checks
                let _ = tree_clone.len().await.unwrap();
            });
            read_handles.push(handle);
        }

        // Wait for all write operations
        let write_results: Vec<_> = join_all(write_handles).await;
        for result in write_results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // Wait for all read operations
        let read_results: Vec<_> = join_all(read_handles).await;
        for result in read_results {
            assert!(result.is_ok());
        }

        // Should have initial 20 + 5 batches * 4 leaves = 40 total
        assert_eq!(tree.len().await.unwrap(), 40);
    }

    #[tokio::test]
    async fn test_thread_safe_single_push() {
        use futures::future::join_all;

        let db = create_test_db().await;
        let tree = Arc::new(
            SlateDbBackedTree::<Sha256, TestLeaf>::new(db)
                .await
                .unwrap(),
        );

        // Create multiple concurrent single push operations
        let mut handles = vec![];

        for i in 0..20 {
            let tree_clone = Arc::clone(&tree);
            let handle = tokio::spawn(async move {
                let leaf = TestLeaf {
                    data: vec![i as u8],
                };
                tree_clone.push(leaf).await
            });
            handles.push(handle);
        }

        // Wait for all operations
        let results: Vec<_> = join_all(handles).await;

        // All operations should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // All 20 leaves should be added
        assert_eq!(tree.len().await.unwrap(), 20);

        // Tree should be consistent
        let root = tree.root().await.unwrap();
        assert_eq!(root.num_leaves(), 20);
    }

    #[tokio::test]
    async fn test_rfc6962_inclusion_proof_path_algorithm() {
        // Test the PATH algorithm from RFC 6962 Section 2.1.1
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create a tree with known structure from RFC examples
        let leaves: Vec<TestLeaf> = (0..8).map(|i| TestLeaf { data: vec![i] }).collect();
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();

        // Test PATH(0, 8) - leftmost leaf
        let proof0 = tree.prove_inclusion(0).await.unwrap();
        let root = tree.root().await.unwrap();
        proof0
            .verify(&leaves[0], 0, &root)
            .expect("PATH(0, 8) should verify");

        // Test PATH(7, 8) - rightmost leaf
        let proof7 = tree.prove_inclusion(7).await.unwrap();
        proof7
            .verify(&leaves[7], 7, &root)
            .expect("PATH(7, 8) should verify");

        // Test PATH(3, 8) - middle leaf
        let proof3 = tree.prove_inclusion(3).await.unwrap();
        proof3
            .verify(&leaves[3], 3, &root)
            .expect("PATH(3, 8) should verify");

        // All proofs for perfect binary tree of size 8 should be 3 hashes
        assert_eq!(
            proof0.as_bytes().len(),
            3 * 32,
            "PATH length should be log2(8) = 3"
        );
        assert_eq!(
            proof3.as_bytes().len(),
            3 * 32,
            "PATH length should be log2(8) = 3"
        );
        assert_eq!(
            proof7.as_bytes().len(),
            3 * 32,
            "PATH length should be log2(8) = 3"
        );
    }

    #[tokio::test]
    async fn test_rfc6962_consistency_proof_algorithm() {
        // Test the PROOF algorithm from RFC 6962 Section 2.1.2
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Build tree incrementally to test consistency proofs
        let leaves: Vec<TestLeaf> = (0..8).map(|i| TestLeaf { data: vec![i] }).collect();

        // Tree size 1
        tree.batch_push_with_data(vec![leaves[0].clone()], vec![])
            .await
            .unwrap();
        let root1 = tree.root_at_size(1).await.unwrap();

        // Tree size 2
        tree.batch_push_with_data(vec![leaves[1].clone()], vec![])
            .await
            .unwrap();
        let root2 = tree.root_at_size(2).await.unwrap();

        // Tree size 4
        tree.batch_push_with_data(leaves[2..4].to_vec(), vec![])
            .await
            .unwrap();
        let root4 = tree.root_at_size(4).await.unwrap();

        // Tree size 8
        tree.batch_push_with_data(leaves[4..8].to_vec(), vec![])
            .await
            .unwrap();
        let root8 = tree.root_at_size(8).await.unwrap();

        // Test PROOF(1, 2)
        let proof_1_2 = tree.prove_consistency_between(1, 2).await.unwrap();
        proof_1_2
            .verify(&root1, &root2)
            .expect("PROOF(1, 2) should verify");

        // Test PROOF(2, 4)
        let proof_2_4 = tree.prove_consistency_between(2, 4).await.unwrap();
        proof_2_4
            .verify(&root2, &root4)
            .expect("PROOF(2, 4) should verify");

        // Test PROOF(4, 8) - power of 2 case
        let proof_4_8 = tree.prove_consistency_between(4, 8).await.unwrap();
        proof_4_8
            .verify(&root4, &root8)
            .expect("PROOF(4, 8) should verify");

        // Test PROOF(1, 8) - non-power of 2 to power of 2
        let proof_1_8 = tree.prove_consistency_between(1, 8).await.unwrap();
        proof_1_8
            .verify(&root1, &root8)
            .expect("PROOF(1, 8) should verify");
    }

    #[tokio::test]
    async fn test_rfc6962_mth_algorithm() {
        // Test the MTH (Merkle Tree Hash) algorithm from RFC 6962 Section 2.1
        use sha2::Digest as Sha2Digest;

        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Test MTH({}) = SHA256()
        let empty_root = tree.root().await.unwrap();
        assert_eq!(empty_root.num_leaves(), 0);
        let expected_empty = Sha256::digest(b"");
        assert_eq!(
            empty_root.as_bytes(),
            &expected_empty,
            "MTH of empty tree should be SHA256()"
        );

        // Test MTH({d0}) = SHA256(0x00 || d0)
        let leaf0 = TestLeaf { data: vec![0x42] };
        tree.push(leaf0.clone()).await.unwrap();
        let root1 = tree.root().await.unwrap();

        let mut expected_single = Sha256::new();
        expected_single.update([0x00]); // Leaf prefix
        expected_single.update([0x42]);
        let expected_single_hash = expected_single.finalize();
        assert_eq!(
            root1.as_bytes(),
            &expected_single_hash,
            "MTH of single leaf should use 0x00 prefix"
        );

        // Test MTH with multiple leaves uses 0x01 prefix for parents
        let leaf1 = TestLeaf { data: vec![0x43] };
        tree.push(leaf1).await.unwrap();
        let root2 = tree.root().await.unwrap();

        // This root should be different from just hashing the two leaves
        let mut wrong_hash = Sha256::new();
        wrong_hash.update([0x42, 0x43]);
        let wrong_root = wrong_hash.finalize();
        assert_ne!(
            root2.as_bytes(),
            &wrong_root,
            "MTH should use proper prefixes, not raw concatenation"
        );
    }

    #[tokio::test]
    async fn test_rfc6962_non_full_tree_inclusion() {
        // Test inclusion proofs for non-full trees (RFC 6962 examples)
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        // Create tree of size 7 (non-power of 2)
        let leaves: Vec<TestLeaf> = (0..7).map(|i| TestLeaf { data: vec![i] }).collect();
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();
        let root7 = tree.root_at_size(7).await.unwrap();

        // Test inclusion proofs at different positions
        for i in 0..7 {
            let proof = tree.prove_inclusion_at_size(i, 7).await.unwrap();
            proof
                .verify(&leaves[i as usize], i, &root7)
                .unwrap_or_else(|_| {
                    panic!(
                        "Inclusion proof for leaf {} in tree of size 7 should verify",
                        i
                    )
                });
        }

        // Also test with size 5 (another non-power of 2)
        let leaves5: Vec<TestLeaf> = (0..5).map(|i| TestLeaf { data: vec![i + 10] }).collect();
        let tree2: SlateDbBackedTree<Sha256, TestLeaf> =
            SlateDbBackedTree::new(create_test_db().await)
                .await
                .unwrap();
        tree2
            .batch_push_with_data(leaves5.clone(), vec![])
            .await
            .unwrap();
        let root5 = tree2.root_at_size(5).await.unwrap();

        for i in 0..5 {
            let proof = tree2.prove_inclusion_at_size(i, 5).await.unwrap();
            proof
                .verify(&leaves5[i as usize], i, &root5)
                .unwrap_or_else(|_| {
                    panic!(
                        "Inclusion proof for leaf {} in tree of size 5 should verify",
                        i
                    )
                });
        }
    }

    #[tokio::test]
    async fn test_rfc6962_proof_verification_edge_cases() {
        let db = create_test_db().await;
        let tree: SlateDbBackedTree<Sha256, TestLeaf> = SlateDbBackedTree::new(db).await.unwrap();

        let leaves = vec![
            TestLeaf { data: vec![1] },
            TestLeaf { data: vec![2] },
            TestLeaf { data: vec![3] },
        ];
        tree.batch_push_with_data(leaves.clone(), vec![])
            .await
            .unwrap();
        let root = tree.root().await.unwrap();

        // Test 1: Wrong leaf index
        let proof0 = tree.prove_inclusion(0).await.unwrap();
        assert!(
            proof0.verify(&leaves[0], 1, &root).is_err(),
            "Wrong index should fail"
        );
        assert!(
            proof0.verify(&leaves[0], 10, &root).is_err(),
            "Out of bounds index should fail"
        );

        // Test 2: Wrong leaf data
        let wrong_leaf = TestLeaf { data: vec![99] };
        assert!(
            proof0.verify(&wrong_leaf, 0, &root).is_err(),
            "Wrong leaf data should fail"
        );

        // Test 3: Empty tree verification should fail
        use sha2::Digest as Sha2Digest;
        let empty_root = RootHash::<Sha256>::new(Sha256::digest(b""), 0);
        assert!(
            proof0.verify(&leaves[0], 0, &empty_root).is_err(),
            "Empty tree verification should fail"
        );

        // Test 4: Consistency proof edge cases
        // Cannot prove consistency from empty tree
        let result = tree.prove_consistency_between(0, 3).await;
        assert!(result.is_err(), "Consistency from empty tree should fail");

        // Old size > new size should fail
        let result = tree.prove_consistency_between(3, 2).await;
        assert!(result.is_err(), "Old size > new size should fail");

        // Same size should give empty proof
        let proof_same = tree.prove_consistency_between(3, 3).await.unwrap();
        assert!(
            proof_same.as_bytes().is_empty(),
            "Same size consistency proof should be empty"
        );
    }

    #[tokio::test]
    async fn test_rfc6962_subproof_algorithm() {
        // Test the SUBPROOF algorithm used in consistency proofs
        use crate::merkle_tree::consistency::subproof;

        // Test cases from understanding of RFC 6962

        // SUBPROOF(m, m, true) should be empty
        let result = subproof(5, 5, true);
        assert!(result.is_empty(), "SUBPROOF(m, m, true) should be empty");

        // SUBPROOF(m, m, false) should contain MTH(m)
        let result = subproof(5, 5, false);
        assert_eq!(
            result,
            vec![root_idx(5).as_u64()],
            "SUBPROOF(m, m, false) should be MTH(m)"
        );

        // Test with various tree sizes
        let test_cases = vec![
            (1, 2, true), // Single leaf to two leaves
            (2, 4, true), // Two leaves to four leaves
            (3, 7, true), // Non-power-of-2 cases
            (4, 8, true), // Power of 2 to power of 2
        ];

        for (old_size, new_size, b) in test_cases {
            let result = subproof(old_size, new_size, b);
            assert!(
                !result.is_empty() || old_size == new_size,
                "SUBPROOF({}, {}, {}) should produce nodes",
                old_size,
                new_size,
                b
            );
        }
    }
}
