use crate::{
    consistency::{indices_for_consistency_proof, ConsistencyProof},
    indices_for_inclusion_proof, leaf_hash, parent_hash, root_idx, HashableLeaf, InclusionProof,
    InternalIdx, LeafIdx, RootHash,
};
use alloc::{format, string::String, string::ToString, vec::Vec};
use core::fmt;
use digest::Digest;
use moka::future::Cache;
use slatedb::{Db, DbReader, WriteBatch};
use std::sync::Arc;

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

/// Enum to hold either a read-write Db or a read-only DbReader
pub enum DbHandle {
    ReadWrite(Arc<Db>),
    ReadOnly(Arc<DbReader>),
}

impl DbHandle {
    async fn get(
        &self,
        key: &[u8],
    ) -> Result<Option<slatedb::bytes::Bytes>, slatedb::SlateDBError> {
        match self {
            DbHandle::ReadWrite(db) => db.get(key).await,
            DbHandle::ReadOnly(reader) => reader.get(key).await,
        }
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), SlateDbTreeError> {
        match self {
            DbHandle::ReadWrite(db) => db.put(key, value).await.map_err(Into::into),
            DbHandle::ReadOnly(_) => Err(SlateDbTreeError::InconsistentState(
                "Cannot write to read-only database".into(),
            )),
        }
    }

    async fn write(&self, batch: WriteBatch) -> Result<(), SlateDbTreeError> {
        match self {
            DbHandle::ReadWrite(db) => db.write(batch).await.map_err(Into::into),
            DbHandle::ReadOnly(_) => Err(SlateDbTreeError::InconsistentState(
                "Cannot write to read-only database".into(),
            )),
        }
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
pub struct SlateDbBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf,
{
    db: DbHandle,
    _phantom_h: core::marker::PhantomData<H>,
    _phantom_t: core::marker::PhantomData<T>,
    // Cache for frequently accessed upper tree nodes
    // Key: node index, Value: node hash
    node_cache: Option<Cache<u64, Vec<u8>>>,
}

const LEAF_PREFIX: &[u8] = b"leaf:";
const NODE_PREFIX: &[u8] = b"node:";
const META_KEY: &[u8] = b"meta";
const VERSIONED_NODE_PREFIX: &[u8] = b"vnode:";

impl<H, T> SlateDbBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf + serde::Serialize + serde::de::DeserializeOwned,
{
    pub async fn new(db: Arc<Db>) -> Result<Self, SlateDbTreeError> {
        // Create cache with reasonable size, upper tree levels that are frequently accessed
        let cache = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(std::time::Duration::from_secs(60 * 5))
            .build();

        let tree = Self {
            db: DbHandle::ReadWrite(db),
            _phantom_h: core::marker::PhantomData,
            _phantom_t: core::marker::PhantomData,
            node_cache: Some(cache),
        };

        let existing_leaves = tree.get_num_leaves().await?;

        if existing_leaves.is_none() {
            tree.set_num_leaves(0).await?;
        }

        Ok(tree)
    }

    pub async fn from_reader(reader: Arc<DbReader>) -> Result<Self, SlateDbTreeError> {
        let tree = Self {
            db: DbHandle::ReadOnly(reader),
            _phantom_h: core::marker::PhantomData,
            _phantom_t: core::marker::PhantomData,
            node_cache: None, // No cache for read-only instances
        };

        Ok(tree)
    }

    fn leaf_key(index: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(LEAF_PREFIX.len() + 8);
        key.extend_from_slice(LEAF_PREFIX);
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    fn node_key(index: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(NODE_PREFIX.len() + 8);
        key.extend_from_slice(NODE_PREFIX);
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
        self.db.put(META_KEY, &num_leaves.to_be_bytes()).await
    }

    pub async fn len(&self) -> Result<u64, SlateDbTreeError> {
        Ok(self.get_num_leaves().await?.unwrap_or(0))
    }

    pub async fn is_empty(&self) -> Result<bool, SlateDbTreeError> {
        Ok(self.len().await? == 0)
    }

    /// Appends multiple items to the tree in a single atomic batch operation.
    /// Returns the starting index of the newly added items.
    pub async fn batch_push(&mut self, items: Vec<T>) -> Result<u64, SlateDbTreeError> {
        self.batch_push_with_data(items, alloc::vec![]).await
    }

    /// Appends multiple items to the tree along with additional key-value pairs in a single atomic batch.
    /// This ensures consistency between the merkle tree and any associated data.
    /// Returns the starting index of the newly added items.
    pub async fn batch_push_with_data(
        &self,
        items: Vec<T>,
        additional_data: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<u64, SlateDbTreeError> {
        let starting_index = self.len().await?;

        if items.is_empty() && additional_data.is_empty() {
            return Ok(starting_index);
        }

        // Pre-fetch nodes that exist in the original tree
        let mut nodes_to_prefetch = alloc::collections::BTreeSet::new();

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

        let mut prefetched_nodes = alloc::collections::BTreeMap::new();
        if !nodes_to_prefetch.is_empty() {
            let node_keys: Vec<Vec<u8>> = nodes_to_prefetch
                .iter()
                .map(|&idx| Self::node_key(idx))
                .collect();

            let futures: Vec<_> = node_keys.iter().map(|key| self.db.get(key)).collect();

            let results = futures::future::try_join_all(futures).await?;

            for (&idx, result) in nodes_to_prefetch.iter().zip(results.iter()) {
                if let Some(bytes) = result {
                    let mut hash = digest::Output::<H>::default();
                    if bytes.len() == hash.len() {
                        hash.copy_from_slice(&bytes);
                        prefetched_nodes.insert(idx, hash);

                        if let Some(ref cache) = self.node_cache {
                            cache.insert(idx, bytes.to_vec()).await;
                        }
                    }
                }
            }
        }

        let mut batch = WriteBatch::new();
        let mut current_num_leaves = starting_index;
        let mut computed_hashes = alloc::collections::BTreeMap::<u64, digest::Output<H>>::new();

        for item in items.iter() {
            let leaf_bytes = bincode::serialize(item)
                .map_err(|e| SlateDbTreeError::EncodingError(e.to_string()))?;
            batch.put(&Self::leaf_key(current_num_leaves), &leaf_bytes);

            let new_leaf_idx = LeafIdx::new(current_num_leaves);
            let new_num_leaves = current_num_leaves + 1;

            let mut cur_idx: InternalIdx = new_leaf_idx.into();
            let leaf_hash = leaf_hash::<H, _>(item);
            batch.put(&Self::node_key(cur_idx.as_u64()), leaf_hash.as_ref());
            // Store versioned node for historical queries
            batch.put(
                &Self::versioned_node_key(cur_idx.as_u64(), new_num_leaves),
                leaf_hash.as_ref(),
            );
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
                    match self.db.get(&Self::node_key(sibling_idx.as_u64())).await? {
                        Some(bytes) => {
                            let mut hash = digest::Output::<H>::default();
                            if bytes.len() == hash.len() {
                                hash.copy_from_slice(&bytes);
                                hash
                            } else {
                                return Err(SlateDbTreeError::EncodingError(
                                    "Invalid hash size".into(),
                                ));
                            }
                        }
                        None => digest::Output::<H>::default(),
                    }
                };

                let parent_hash = if cur_idx.is_left(new_num_leaves) {
                    parent_hash::<H>(&cur_hash, &sibling_hash)
                } else {
                    parent_hash::<H>(&sibling_hash, &cur_hash)
                };

                // Store both current version and versioned node
                batch.put(&Self::node_key(parent_idx.as_u64()), parent_hash.as_ref());
                // Store versioned node for historical queries
                batch.put(
                    &Self::versioned_node_key(parent_idx.as_u64(), new_num_leaves),
                    parent_hash.as_ref(),
                );
                computed_hashes.insert(parent_idx.as_u64(), parent_hash.clone());

                cur_idx = parent_idx;
                cur_hash = parent_hash;
            }

            current_num_leaves = new_num_leaves;
        }

        batch.put(META_KEY, &current_num_leaves.to_be_bytes());

        // Add additional key-value pairs to the same batch
        for (key, value) in additional_data {
            batch.put(&key, &value);
        }

        self.db.write(batch).await?;

        Ok(starting_index)
    }

    /// Appends the given item to the end of the list.
    pub async fn push(&mut self, new_val: T) -> Result<(), SlateDbTreeError> {
        let num_leaves = self.len().await?;

        if num_leaves >= u64::MAX / 2 {
            return Err(SlateDbTreeError::InconsistentState("Tree is full".into()));
        }

        let mut batch = WriteBatch::new();

        let leaf_bytes = bincode::serialize(&new_val)
            .map_err(|e| SlateDbTreeError::EncodingError(e.to_string()))?;
        batch.put(&Self::leaf_key(num_leaves), &leaf_bytes);

        let new_leaf_idx = LeafIdx::new(num_leaves);
        self.recalculate_path_batch(&mut batch, new_leaf_idx, &new_val, num_leaves + 1)
            .await?;

        batch.put(META_KEY, &(num_leaves + 1).to_be_bytes());

        self.db.write(batch).await?;

        Ok(())
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

        let current_size = self.len().await?;
        if new_size > current_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "New size {} exceeds current tree size {}",
                new_size, current_size
            )));
        }

        let idxs = indices_for_consistency_proof(old_size, new_size - old_size);

        // Fetch all proof hashes in parallel
        let hash_futures: Vec<_> = idxs
            .iter()
            .map(|&node_idx| self.get_node_hash_internal(InternalIdx::new(node_idx)))
            .collect();

        let proof_hashes = futures::future::try_join_all(hash_futures).await?;

        Ok(ConsistencyProof::from_digests(proof_hashes.iter()))
    }

    /// Recalculates the hashes on the path from `leaf_idx` to the root.
    async fn recalculate_path_batch(
        &self,
        batch: &mut WriteBatch,
        leaf_idx: LeafIdx,
        leaf_val: &T,
        num_leaves: u64,
    ) -> Result<(), SlateDbTreeError> {
        let mut cur_idx: InternalIdx = leaf_idx.into();
        let leaf_hash = leaf_hash::<H, _>(leaf_val);
        batch.put(&Self::node_key(cur_idx.as_u64()), leaf_hash.as_ref());
        // Store versioned node for historical queries
        batch.put(
            &Self::versioned_node_key(cur_idx.as_u64(), num_leaves),
            leaf_hash.as_ref(),
        );

        let root_idx = root_idx(num_leaves);

        let mut computed_hashes = alloc::collections::BTreeMap::<u64, digest::Output<H>>::new();
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
                match self.db.get(&Self::node_key(sibling_idx.as_u64())).await? {
                    Some(bytes) => {
                        let mut hash = digest::Output::<H>::default();
                        if bytes.len() == hash.len() {
                            hash.copy_from_slice(&bytes);
                            hash
                        } else {
                            return Err(SlateDbTreeError::EncodingError(
                                "Invalid hash size".into(),
                            ));
                        }
                    }
                    None => digest::Output::<H>::default(),
                }
            };

            let parent_hash = if cur_idx.is_left(num_leaves) {
                parent_hash::<H>(&cur_node, &sibling)
            } else {
                parent_hash::<H>(&sibling, &cur_node)
            };

            batch.put(&Self::node_key(parent_idx.as_u64()), parent_hash.as_ref());
            // Store versioned node for historical queries
            batch.put(
                &Self::versioned_node_key(parent_idx.as_u64(), num_leaves),
                parent_hash.as_ref(),
            );
            computed_hashes.insert(parent_idx.as_u64(), parent_hash);

            cur_idx = parent_idx;
        }

        Ok(())
    }

    pub async fn get_node_hash(&self, idx: u64) -> Result<digest::Output<H>, SlateDbTreeError> {
        match self.db.get(&Self::node_key(idx)).await? {
            Some(bytes) => {
                let mut hash = digest::Output::<H>::default();
                if bytes.len() == hash.len() {
                    hash.copy_from_slice(&bytes);
                    Ok(hash)
                } else {
                    Err(SlateDbTreeError::EncodingError("Invalid hash size".into()))
                }
            }
            None => Err(SlateDbTreeError::InconsistentState(format!(
                "Missing node at index {}",
                idx
            ))),
        }
    }

    async fn get_node_hash_internal(
        &self,
        idx: InternalIdx,
    ) -> Result<digest::Output<H>, SlateDbTreeError> {
        self.get_node_hash(idx.as_u64()).await
    }

    async fn get_node_hash_at_version(
        &self,
        idx: u64,
        version: u64,
    ) -> Result<digest::Output<H>, SlateDbTreeError> {
        // First try to get the versioned node
        match self.db.get(&Self::versioned_node_key(idx, version)).await? {
            Some(bytes) => {
                let mut hash = digest::Output::<H>::default();
                if bytes.len() == hash.len() {
                    hash.copy_from_slice(&bytes);
                    Ok(hash)
                } else {
                    Err(SlateDbTreeError::EncodingError("Invalid hash size".into()))
                }
            }
            None => {
                // If versioned node doesn't exist, it means the node hasn't changed since that version
                // Fall back to the current node value
                self.get_node_hash(idx).await
            }
        }
    }

    /// Returns the root hash of this tree.
    pub async fn root(&self) -> Result<RootHash<H>, SlateDbTreeError> {
        let num_leaves = self.len().await?;

        let root_hash = if num_leaves == 0 {
            H::digest(b"")
        } else {
            let root_idx = root_idx(num_leaves);
            self.get_node_hash_internal(root_idx).await?
        };

        Ok(RootHash::new(root_hash, num_leaves))
    }

    pub async fn get(&self, idx: u64) -> Result<Option<T>, SlateDbTreeError> {
        match self.db.get(&Self::leaf_key(idx)).await? {
            Some(bytes) => {
                let leaf = bincode::deserialize(&bytes)
                    .map_err(|e| SlateDbTreeError::EncodingError(e.to_string()))?;
                Ok(Some(leaf))
            }
            None => Ok(None),
        }
    }

    /// Returns a proof of inclusion of the item at the given index.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or if there's a database error.
    pub async fn prove_inclusion(&self, idx: u64) -> Result<InclusionProof<H>, SlateDbTreeError> {
        let num_leaves = self.len().await?;

        if idx >= num_leaves {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Index {} out of bounds (tree has {} leaves)",
                idx, num_leaves
            )));
        }

        let idxs = indices_for_inclusion_proof(num_leaves, idx);

        // Fetch all sibling hashes in parallel
        let hash_futures: Vec<_> = idxs
            .iter()
            .map(|&node_idx| self.get_node_hash_internal(InternalIdx::new(node_idx)))
            .collect();

        let sibling_hashes = futures::future::try_join_all(hash_futures).await?;

        Ok(InclusionProof::from_digests(sibling_hashes.iter()))
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
        let current_leaves = self.len().await?;

        if tree_size > current_leaves {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Requested tree size {} exceeds current tree size {}",
                tree_size, current_leaves
            )));
        }

        if idx >= tree_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Index {} out of bounds for requested tree size {}",
                idx, tree_size
            )));
        }

        let idxs = indices_for_inclusion_proof(tree_size, idx);

        // Fetch all sibling hashes in parallel - using versioned nodes
        let hash_futures: Vec<_> = idxs
            .iter()
            .map(|&node_idx| self.get_node_hash_at_version(node_idx, tree_size))
            .collect();

        let sibling_hashes = futures::future::try_join_all(hash_futures).await?;

        Ok(InclusionProof::from_digests(sibling_hashes.iter()))
    }

    /// Produces a proof that a tree with `old_size` leaves is a prefix of this tree.
    ///
    /// # Errors
    /// Returns an error if `old_size` is 0, greater than or equal to the current tree size,
    /// or if there's a database error.
    pub async fn prove_consistency(
        &self,
        old_size: u64,
    ) -> Result<ConsistencyProof<H>, SlateDbTreeError> {
        let new_size = self.len().await?;

        if old_size == 0 {
            return Err(SlateDbTreeError::InconsistentState(
                "Cannot create consistency proof from empty tree".into(),
            ));
        }

        if old_size >= new_size {
            return Err(SlateDbTreeError::InconsistentState(format!(
                "Old size {} must be less than current size {}",
                old_size, new_size
            )));
        }

        let num_additions = new_size - old_size;

        let idxs = indices_for_consistency_proof(old_size, num_additions);

        // Fetch all proof hashes in parallel
        let hash_futures: Vec<_> = idxs
            .iter()
            .map(|&node_idx| self.get_node_hash_internal(InternalIdx::new(node_idx)))
            .collect();

        let proof_hashes = futures::future::try_join_all(hash_futures).await?;

        Ok(ConsistencyProof::from_digests(proof_hashes.iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem_backed_tree::MemoryBackedTree;
    use alloc::vec;
    use sha2::Sha256;
    use slatedb::config::DbOptions;

    type TestTree = SlateDbBackedTree<Sha256, Vec<u8>>;
    type MemTree = MemoryBackedTree<Sha256, Vec<u8>>;

    #[tokio::test]
    async fn test_basic_operations() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_tree", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();

        assert!(tree.is_empty().await.unwrap());
        assert_eq!(tree.len().await.unwrap(), 0);

        tree.push(vec![1, 2, 3]).await.unwrap();
        tree.push(vec![4, 5, 6]).await.unwrap();
        tree.push(vec![7, 8, 9]).await.unwrap();

        assert_eq!(tree.len().await.unwrap(), 3);
        assert!(!tree.is_empty().await.unwrap());

        assert_eq!(tree.get(0).await.unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(tree.get(1).await.unwrap(), Some(vec![4, 5, 6]));
        assert_eq!(tree.get(2).await.unwrap(), Some(vec![7, 8, 9]));
        assert_eq!(tree.get(3).await.unwrap(), None);

        let root1 = tree.root().await.unwrap();
        tree.push(vec![10, 11, 12]).await.unwrap();
        let root2 = tree.root().await.unwrap();

        assert_ne!(root1.as_bytes(), root2.as_bytes());
        assert_eq!(root1.num_leaves(), 3);
        assert_eq!(root2.num_leaves(), 4);
    }

    #[tokio::test]
    async fn test_matches_memory_backed_tree() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_tree2", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        assert_eq!(
            slate_tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Empty trees should have same root"
        );

        let test_values = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
            vec![13, 14, 15],
            vec![16, 17, 18],
            vec![19, 20, 21],
            vec![22, 23, 24],
        ];

        for (i, value) in test_values.iter().enumerate() {
            slate_tree.push(value.clone()).await.unwrap();
            mem_tree.push(value.clone());

            let slate_root = slate_tree.root().await.unwrap();
            let mem_root = mem_tree.root();

            assert_eq!(
                slate_root.as_bytes(),
                mem_root.as_bytes(),
                "Roots should match after {} additions",
                i + 1
            );
            assert_eq!(
                slate_root.num_leaves(),
                mem_root.num_leaves(),
                "Leaf counts should match after {} additions",
                i + 1
            );
        }
    }

    #[tokio::test]
    async fn test_edge_cases_match() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_tree3", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        slate_tree.push(vec![42]).await.unwrap();
        mem_tree.push(vec![42]);
        assert_eq!(
            slate_tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Single element trees should match"
        );

        for i in 1..16u32 {
            slate_tree.push(vec![i as u8]).await.unwrap();
            mem_tree.push(vec![i as u8]);

            if (i + 1).is_power_of_two() {
                assert_eq!(
                    slate_tree.root().await.unwrap().as_bytes(),
                    mem_tree.root().as_bytes(),
                    "Trees should match at power of 2 boundary: {} elements",
                    i + 1
                );
            }
        }
    }

    #[tokio::test]
    async fn test_large_tree_matches() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_tree4", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        for i in 0..100u8 {
            slate_tree.push(vec![i]).await.unwrap();
            mem_tree.push(vec![i]);

            if i == 9 || i == 49 || i == 99 {
                assert_eq!(
                    slate_tree.root().await.unwrap().as_bytes(),
                    mem_tree.root().as_bytes(),
                    "Trees should match after {} additions",
                    i + 1
                );
            }
        }
    }

    #[tokio::test]
    async fn test_known_root_hashes() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_tree5", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        let empty_root = slate_tree.root().await.unwrap();
        assert_eq!(
            hex::encode(empty_root.as_bytes()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Empty tree root should be SHA256('')"
        );

        slate_tree.push(b"hello".to_vec()).await.unwrap();
        mem_tree.push(b"hello".to_vec());

        let slate_root = slate_tree.root().await.unwrap();
        let mem_root = mem_tree.root();
        assert_eq!(
            slate_root.as_bytes(),
            mem_root.as_bytes(),
            "Single element roots should match"
        );

        slate_tree.push(b"world".to_vec()).await.unwrap();
        mem_tree.push(b"world".to_vec());

        let slate_root = slate_tree.root().await.unwrap();
        let mem_root = mem_tree.root();
        assert_eq!(
            slate_root.as_bytes(),
            mem_root.as_bytes(),
            "Two element roots should match"
        );
    }

    #[tokio::test]
    async fn test_stress_random_operations() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(12345);

        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_tree6", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        for i in 0..500 {
            let data_len = rng.random_range(1..100);
            let data: Vec<u8> = (0..data_len).map(|_| rng.random()).collect();

            slate_tree.push(data.clone()).await.unwrap();
            mem_tree.push(data);

            if i % 10 == 9 {
                let slate_root = slate_tree.root().await.unwrap();
                let mem_root = mem_tree.root();
                assert_eq!(
                    slate_root.as_bytes(),
                    mem_root.as_bytes(),
                    "Roots should match after {} operations",
                    i + 1
                );
                assert_eq!(
                    slate_root.num_leaves(),
                    mem_root.num_leaves(),
                    "Leaf counts should match after {} operations",
                    i + 1
                );
            }
        }

        assert_eq!(slate_tree.len().await.unwrap(), 500);

        for i in 0..500 {
            assert!(
                slate_tree.get(i).await.unwrap().is_some(),
                "Leaf {} should exist",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_tree_persistence() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db_path = "/tmp/test_tree_persist";

        let initial_root = {
            let db = Arc::new(
                Db::open_with_opts(db_path, DbOptions::default(), object_store.clone())
                    .await
                    .unwrap(),
            );

            let mut tree = TestTree::new(db.clone()).await.unwrap();

            tree.push(b"first".to_vec()).await.unwrap();
            tree.push(b"second".to_vec()).await.unwrap();
            tree.push(b"third".to_vec()).await.unwrap();

            let root = tree.root().await.unwrap();

            db.close().await.unwrap();

            root
        };

        {
            let db = Arc::new(
                Db::open_with_opts(db_path, DbOptions::default(), object_store)
                    .await
                    .unwrap(),
            );

            let mut tree = TestTree::new(db).await.unwrap();

            assert_eq!(tree.len().await.unwrap(), 3);
            assert_eq!(tree.get(0).await.unwrap(), Some(b"first".to_vec()));
            assert_eq!(tree.get(1).await.unwrap(), Some(b"second".to_vec()));
            assert_eq!(tree.get(2).await.unwrap(), Some(b"third".to_vec()));

            let root = tree.root().await.unwrap();
            assert_eq!(root.as_bytes(), initial_root.as_bytes());

            tree.push(b"fourth".to_vec()).await.unwrap();
            assert_eq!(tree.len().await.unwrap(), 4);
        }
    }

    #[tokio::test]
    async fn test_rightmost_path_edge_cases() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts(
                "/tmp/test_tree_rightmost",
                DbOptions::default(),
                object_store,
            )
            .await
            .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        let critical_sizes = vec![1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33];

        for target_size in critical_sizes {
            while slate_tree.len().await.unwrap() < target_size {
                let val = vec![slate_tree.len().await.unwrap() as u8];
                slate_tree.push(val.clone()).await.unwrap();
                mem_tree.push(val);
            }

            let slate_root = slate_tree.root().await.unwrap();
            let mem_root = mem_tree.root();

            assert_eq!(
                slate_root.as_bytes(),
                mem_root.as_bytes(),
                "Roots should match at size {}",
                target_size
            );

            for i in 0..target_size {
                let leaf = slate_tree.get(i).await.unwrap();
                assert!(
                    leaf.is_some(),
                    "Leaf {} should exist in tree of size {}",
                    i,
                    target_size
                );
                assert_eq!(leaf.unwrap(), vec![i as u8]);
            }
        }
    }

    #[tokio::test]
    async fn test_batch_push() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_batch_push", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        let items = vec![vec![1], vec![2], vec![3], vec![4], vec![5]];
        tree.batch_push(items.clone()).await.unwrap();

        for item in items {
            mem_tree.push(item);
        }

        assert_eq!(tree.len().await.unwrap(), 5);
        assert_eq!(tree.get(0).await.unwrap(), Some(vec![1]));
        assert_eq!(tree.get(4).await.unwrap(), Some(vec![5]));

        assert_eq!(
            tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Roots should match after batch push"
        );

        let more_items = vec![vec![6], vec![7], vec![8], vec![9], vec![10]];
        tree.batch_push(more_items.clone()).await.unwrap();

        for item in more_items {
            mem_tree.push(item);
        }

        assert_eq!(tree.len().await.unwrap(), 10);
        assert_eq!(tree.get(9).await.unwrap(), Some(vec![10]));

        assert_eq!(
            tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Roots should match after second batch"
        );

        tree.batch_push(vec![]).await.unwrap();
        assert_eq!(tree.len().await.unwrap(), 10);
    }

    #[tokio::test]
    async fn test_default_push_uses_durable_writes() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_default_push", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        for i in 0..20u8 {
            let val = vec![i];
            tree.push(val.clone()).await.unwrap();
            mem_tree.push(val);
        }

        assert_eq!(tree.len().await.unwrap(), 20);

        assert_eq!(
            tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Roots should match after durable writes"
        );

        for i in 0..20 {
            assert_eq!(tree.get(i).await.unwrap(), Some(vec![i as u8]));
        }
    }

    #[tokio::test]
    async fn test_batch_push_with_persistence() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());

        let initial_root = {
            let db = Arc::new(
                Db::open_with_opts(
                    "/tmp/test_batch_persist",
                    DbOptions::default(),
                    object_store.clone(),
                )
                .await
                .unwrap(),
            );

            let mut tree = TestTree::new(db.clone()).await.unwrap();

            for chunk_start in (0..1000).step_by(100) {
                let chunk: Vec<Vec<u8>> = (chunk_start..chunk_start + 100)
                    .map(|i| (i as u16).to_be_bytes().to_vec())
                    .collect();
                tree.batch_push(chunk).await.unwrap();
            }

            assert_eq!(tree.len().await.unwrap(), 1000);

            assert_eq!(
                tree.get(0).await.unwrap(),
                Some(0u16.to_be_bytes().to_vec())
            );
            assert_eq!(
                tree.get(500).await.unwrap(),
                Some(500u16.to_be_bytes().to_vec())
            );
            assert_eq!(
                tree.get(999).await.unwrap(),
                Some(999u16.to_be_bytes().to_vec())
            );

            let root = tree.root().await.unwrap();
            db.close().await.unwrap();
            root
        };

        {
            let db = Arc::new(
                Db::open_with_opts(
                    "/tmp/test_batch_persist",
                    DbOptions::default(),
                    object_store.clone(),
                )
                .await
                .unwrap(),
            );

            let tree = TestTree::new(db).await.unwrap();

            assert_eq!(tree.len().await.unwrap(), 1000);

            let root = tree.root().await.unwrap();
            assert_eq!(
                root.as_bytes(),
                initial_root.as_bytes(),
                "Root should match after reopening"
            );

            assert_eq!(
                tree.get(0).await.unwrap(),
                Some(0u16.to_be_bytes().to_vec())
            );
            assert_eq!(
                tree.get(999).await.unwrap(),
                Some(999u16.to_be_bytes().to_vec())
            );
        }
    }

    #[tokio::test]
    async fn test_batch_push_comprehensive_verification() {
        let test_cases = vec![
            (5, vec![2, 3]),
            (10, vec![3, 5, 7]),
            (16, vec![8]),
            (20, vec![5, 10, 15]),
        ];

        for (size, splits) in test_cases {
            for split_point in splits {
                let items: Vec<Vec<u8>> = (0..size).map(|i| vec![i as u8]).collect();

                let object_store1 = Arc::new(slatedb::object_store::memory::InMemory::new());
                let db1 = Arc::new(
                    Db::open_with_opts(
                        format!("/tmp/comp_ind_{}_{}", size, split_point).as_str(),
                        DbOptions::default(),
                        object_store1,
                    )
                    .await
                    .unwrap(),
                );
                let mut tree_individual = TestTree::new(db1).await.unwrap();

                for item in &items {
                    tree_individual.push(item.clone()).await.unwrap();
                }

                let object_store2 = Arc::new(slatedb::object_store::memory::InMemory::new());
                let db2 = Arc::new(
                    Db::open_with_opts(
                        format!("/tmp/comp_batch_{}_{}", size, split_point).as_str(),
                        DbOptions::default(),
                        object_store2,
                    )
                    .await
                    .unwrap(),
                );
                let mut tree_batch = TestTree::new(db2).await.unwrap();
                tree_batch.batch_push(items.clone()).await.unwrap();

                let object_store3 = Arc::new(slatedb::object_store::memory::InMemory::new());
                let db3 = Arc::new(
                    Db::open_with_opts(
                        format!("/tmp/comp_split_{}_{}", size, split_point).as_str(),
                        DbOptions::default(),
                        object_store3,
                    )
                    .await
                    .unwrap(),
                );
                let mut tree_split = TestTree::new(db3).await.unwrap();
                tree_split
                    .batch_push(items[..split_point].to_vec())
                    .await
                    .unwrap();
                tree_split
                    .batch_push(items[split_point..].to_vec())
                    .await
                    .unwrap();

                let mut mem_tree = MemTree::new();
                for item in &items {
                    mem_tree.push(item.clone());
                }

                let root_individual = tree_individual.root().await.unwrap();
                let root_batch = tree_batch.root().await.unwrap();
                let root_split = tree_split.root().await.unwrap();
                let root_mem = mem_tree.root();

                assert_eq!(
                    root_individual.as_bytes(),
                    root_batch.as_bytes(),
                    "Individual vs Batch mismatch: size={}, split={}",
                    size,
                    split_point
                );
                assert_eq!(
                    root_batch.as_bytes(),
                    root_split.as_bytes(),
                    "Batch vs Split mismatch: size={}, split={}",
                    size,
                    split_point
                );
                assert_eq!(
                    root_split.as_bytes(),
                    root_mem.as_bytes(),
                    "Split vs Memory mismatch: size={}, split={}",
                    size,
                    split_point
                );

                for i in 0..size {
                    let v1 = tree_individual.get(i as u64).await.unwrap();
                    let v2 = tree_batch.get(i as u64).await.unwrap();
                    let v3 = tree_split.get(i as u64).await.unwrap();

                    assert_eq!(v1, Some(vec![i as u8]));
                    assert_eq!(v1, v2);
                    assert_eq!(v2, v3);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_inclusion_proof_basic() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_inclusion", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        tree.push(b"hello".to_vec()).await.unwrap();
        tree.push(b"world".to_vec()).await.unwrap();
        mem_tree.push(b"hello".to_vec());
        mem_tree.push(b"world".to_vec());

        let root = tree.root().await.unwrap();

        let proof0 = tree.prove_inclusion(0).await.unwrap();
        let proof1 = tree.prove_inclusion(1).await.unwrap();

        assert!(root
            .verify_inclusion(&b"hello".to_vec(), 0, &proof0)
            .is_ok());
        assert!(root
            .verify_inclusion(&b"world".to_vec(), 1, &proof1)
            .is_ok());

        let mem_proof0 = mem_tree.prove_inclusion(0);
        let mem_proof1 = mem_tree.prove_inclusion(1);

        assert_eq!(
            proof0.as_bytes(),
            mem_proof0.as_bytes(),
            "Inclusion proofs should match between SlateDB and memory trees"
        );
        assert_eq!(
            proof1.as_bytes(),
            mem_proof1.as_bytes(),
            "Inclusion proofs should match between SlateDB and memory trees"
        );
    }

    #[tokio::test]
    async fn test_inclusion_proof_comprehensive() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts(
                "/tmp/test_inclusion_comp",
                DbOptions::default(),
                object_store,
            )
            .await
            .unwrap(),
        );

        let mut slate_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        for size in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 50, 100] {
            while slate_tree.len().await.unwrap() < size {
                let val = vec![slate_tree.len().await.unwrap() as u8];
                slate_tree.push(val.clone()).await.unwrap();
                mem_tree.push(val);
            }

            let slate_root = slate_tree.root().await.unwrap();
            let mem_root = mem_tree.root();

            for idx in 0..size {
                let leaf = slate_tree.get(idx).await.unwrap().unwrap();

                let slate_proof = slate_tree.prove_inclusion(idx).await.unwrap();

                let mem_proof = mem_tree.prove_inclusion(idx as usize);

                assert_eq!(
                    slate_proof.as_bytes(),
                    mem_proof.as_bytes(),
                    "Proofs should match for idx {} in tree of size {}",
                    idx,
                    size
                );

                assert!(
                    slate_root
                        .verify_inclusion(&leaf, idx, &slate_proof)
                        .is_ok(),
                    "SlateDB proof should verify for idx {} in tree of size {}",
                    idx,
                    size
                );
                assert!(
                    mem_root.verify_inclusion(&leaf, idx, &mem_proof).is_ok(),
                    "Memory proof should verify for idx {} in tree of size {}",
                    idx,
                    size
                );
            }
        }
    }

    #[tokio::test]
    async fn test_consistency_proof_basic() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_consistency", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();

        for i in 0..5u8 {
            tree.push(vec![i]).await.unwrap();
        }
        let old_root = tree.root().await.unwrap();
        let old_size = tree.len().await.unwrap();

        for i in 5..10u8 {
            tree.push(vec![i]).await.unwrap();
        }
        let new_root = tree.root().await.unwrap();

        let proof = tree.prove_consistency(old_size).await.unwrap();

        assert!(
            new_root.verify_consistency(&old_root, &proof).is_ok(),
            "Consistency proof should verify"
        );
    }

    #[tokio::test]
    async fn test_consistency_proof_comprehensive() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts(
                "/tmp/test_consistency_comp",
                DbOptions::default(),
                object_store,
            )
            .await
            .unwrap(),
        );

        let mut slate_tree: TestTree;
        let mut mem_tree: MemTree;

        let test_cases = vec![
            (1, 2),
            (1, 5),
            (2, 3),
            (2, 4),
            (3, 8),
            (4, 5),
            (4, 8),
            (5, 10),
            (8, 16),
            (15, 20),
            (16, 32),
            (20, 50),
            (32, 64),
        ];

        for (old_size, new_size) in test_cases {
            let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
            let db = Arc::new(
                Db::open_with_opts(
                    format!("/tmp/test_cons_{}_{}", old_size, new_size).as_str(),
                    DbOptions::default(),
                    object_store,
                )
                .await
                .unwrap(),
            );
            slate_tree = TestTree::new(db).await.unwrap();
            mem_tree = MemTree::new();

            for i in 0..old_size {
                let val = vec![i as u8];
                slate_tree.push(val.clone()).await.unwrap();
                mem_tree.push(val);
            }

            let old_slate_root = slate_tree.root().await.unwrap();
            let old_mem_root = mem_tree.root();

            for i in old_size..new_size {
                let val = vec![i as u8];
                slate_tree.push(val.clone()).await.unwrap();
                mem_tree.push(val);
            }

            let new_slate_root = slate_tree.root().await.unwrap();
            let new_mem_root = mem_tree.root();

            let slate_proof = slate_tree.prove_consistency(old_size).await.unwrap();
            let mem_proof = mem_tree.prove_consistency((new_size - old_size) as usize);

            assert_eq!(
                slate_proof.as_bytes(),
                mem_proof.as_bytes(),
                "Consistency proofs should match for {} -> {} transition",
                old_size,
                new_size
            );

            assert!(
                new_slate_root
                    .verify_consistency(&old_slate_root, &slate_proof)
                    .is_ok(),
                "SlateDB consistency proof should verify for {} -> {}",
                old_size,
                new_size
            );
            assert!(
                new_mem_root
                    .verify_consistency(&old_mem_root, &mem_proof)
                    .is_ok(),
                "Memory consistency proof should verify for {} -> {}",
                old_size,
                new_size
            );
        }
    }

    #[tokio::test]
    async fn test_proof_errors() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_proof_errors", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();

        assert!(tree.prove_inclusion(0).await.is_err());

        for i in 0..10u8 {
            tree.push(vec![i]).await.unwrap();
        }

        assert!(tree.prove_inclusion(10).await.is_err());
        assert!(tree.prove_inclusion(100).await.is_err());

        assert!(tree.prove_consistency(0).await.is_err()); // old_size = 0
        assert!(tree.prove_consistency(10).await.is_err()); // old_size = current size
        assert!(tree.prove_consistency(11).await.is_err()); // old_size > current size
    }
}
