use crate::merkle_storage::StorageBackedMerkleTree;
use crate::types::{sct::SignedCertificateTimestamp, DeduplicatedLogEntry, LogEntry};
use crate::validation::tbs_extractor::TbsExtractor;
use bytes::Bytes;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use slatedb::Db;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("SlateDB error: {0}")]
    SlateDb(slatedb::SlateDBError),

    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    #[error("Queue full - system at capacity")]
    QueueFull,
}

impl Clone for StorageError {
    fn clone(&self) -> Self {
        match self {
            StorageError::SlateDb(_) => {
                StorageError::InvalidFormat("SlateDB error during batch processing".to_string())
            }
            StorageError::InvalidFormat(s) => StorageError::InvalidFormat(s.clone()),
            StorageError::QueueFull => StorageError::QueueFull,
        }
    }
}

impl From<slatedb::SlateDBError> for StorageError {
    fn from(e: slatedb::SlateDBError) -> Self {
        StorageError::SlateDb(e)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Entry to be batched and flushed
pub struct BatchEntry {
    pub log_entry: LogEntry,
    pub cert_hash: [u8; 32],
    pub sct_callback: Box<dyn FnOnce(u64) -> SignedCertificateTimestamp + Send>,
    pub completion_tx: oneshot::Sender<Result<(u64, SignedCertificateTimestamp)>>,
}

/// Certificate SCT mapping entry for deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSctEntry {
    pub index: u64,
    pub sct: SignedCertificateTimestamp,
    pub timestamp: u64,
}

/// Statistics for batch processing
#[derive(Debug, Default)]
struct BatchStats {
    batches_flushed: u64,
    total_entries: u64,
    total_flush_time_ms: u64,
    min_batch_size: usize,
    max_batch_size: usize,
    // Certificate deduplication stats
    total_certs_checked: u64,
    total_certs_deduplicated: u64,
    total_bytes_saved: u64,
    total_dedup_check_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of entries to batch before flushing
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing (in milliseconds)
    pub max_batch_timeout_ms: u64,
}

pub struct KeyPrefix;

impl KeyPrefix {
    /// Log entries
    pub const ENTRY: &'static [u8] = b"entry:";

    /// Hash to index mapping for efficient proof-by-hash lookups
    pub const HASH_INDEX: &'static [u8] = b"hash:";

    /// Certificate hash to SCT mapping for deduplication
    pub const CERT_SCT: &'static [u8] = b"cert_sct:";

    /// Certificate store - maps certificate hash to certificate data
    pub const CERT: &'static [u8] = b"cert:";
}

/// Storage backend for Certificate Transparency log using SlateDB with batching
#[derive(Clone)]
pub struct CtStorage {
    pub(crate) db: Arc<Db>,
    batch_sender: mpsc::Sender<BatchEntry>,
}

impl BatchConfig {
    pub fn default() -> Self {
        Self {
            max_batch_size: 1_000,
            max_batch_timeout_ms: 500,
        }
    }
}

impl CtStorage {
    pub async fn new(
        db: Arc<Db>,
        config: BatchConfig,
        merkle_tree: StorageBackedMerkleTree,
    ) -> Result<Self> {
        // Use a bounded channel to provide backpressure
        let channel_capacity = (config.max_batch_size * 2).max(500);
        let (batch_sender, batch_receiver) = mpsc::channel(channel_capacity);
        let batch_mutex = Arc::new(Mutex::new(()));

        let mutex_clone = batch_mutex.clone();
        let tree_clone = merkle_tree.clone();
        let batch_stats = Arc::new(Mutex::new(BatchStats::default()));
        let stats_clone = batch_stats.clone();

        tokio::spawn(async move {
            Self::batch_worker(batch_receiver, config, mutex_clone, tree_clone, stats_clone).await;
        });

        // Start metrics logging task
        let metrics_sender = batch_sender.clone();
        let metrics_stats = batch_stats.clone();
        tokio::spawn(async move {
            Self::metrics_worker(metrics_sender, metrics_stats).await;
        });

        Ok(Self { db, batch_sender })
    }

    /// Add entry to batch queue and return assigned index and SCT
    pub async fn add_entry_batched<F>(
        &self,
        log_entry: LogEntry,
        cert_hash: [u8; 32],
        sct_callback: F,
    ) -> Result<(u64, SignedCertificateTimestamp)>
    where
        F: FnOnce(u64) -> SignedCertificateTimestamp + Send + 'static,
    {
        let (completion_tx, completion_rx) = oneshot::channel();

        let batch_entry = BatchEntry {
            log_entry,
            cert_hash,
            sct_callback: Box::new(sct_callback),
            completion_tx,
        };

        match self.batch_sender.try_send(batch_entry) {
            Ok(_) => {
                tracing::trace!(
                    "add_entry_batched: Added entry to batch queue, current depth: {}/{}",
                    self.batch_sender.capacity(),
                    self.batch_sender.max_capacity()
                );
            }
            Err(e) => match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(
                        "add_entry_batched: Batch queue is full at capacity {}",
                        self.batch_sender.max_capacity()
                    );
                    return Err(StorageError::QueueFull);
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("add_entry_batched: Batch worker not running");
                    return Err(StorageError::InvalidFormat(
                        "Batch worker not running".into(),
                    ));
                }
            },
        }

        completion_rx.await.map_err(|_| {
            tracing::error!("add_entry_batched: Completion channel closed");
            StorageError::InvalidFormat("Batch completion channel closed".into())
        })?
    }

    /// Background worker that batches and flushes entries
    async fn batch_worker(
        mut batch_receiver: mpsc::Receiver<BatchEntry>,
        config: BatchConfig,
        batch_mutex: Arc<Mutex<()>>,
        merkle_tree: StorageBackedMerkleTree,
        batch_stats: Arc<Mutex<BatchStats>>,
    ) {
        tracing::trace!("batch_worker: Starting background worker");
        let mut pending_entries = Vec::with_capacity(config.max_batch_size);
        let timeout_duration = std::time::Duration::from_millis(config.max_batch_timeout_ms);

        let mut interval = tokio::time::interval(timeout_duration);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                entry = batch_receiver.recv() => {
                    match entry {
                        Some(entry) => {
                            tracing::debug!("batch_worker: Received entry");
                            pending_entries.push(entry);

                            // After receiving one entry, try to drain more without blocking
                            while pending_entries.len() < config.max_batch_size {
                                match batch_receiver.try_recv() {
                                    Ok(entry) => {
                                        pending_entries.push(entry);
                                    }
                                    Err(_) => break, // Channel empty or closed
                                }
                            }

                            if pending_entries.len() >= config.max_batch_size {
                                tracing::trace!("batch_worker: Batch full ({}), flushing {} entries", config.max_batch_size, pending_entries.len());
                                Self::flush_batch(&mut pending_entries, batch_mutex.clone(), merkle_tree.clone(), batch_stats.clone()).await;
                            }
                        }
                        None => {
                            if !pending_entries.is_empty() {
                                tracing::trace!("batch_worker: Channel closed, flushing {} remaining entries", pending_entries.len());
                                Self::flush_batch(&mut pending_entries, batch_mutex.clone(), merkle_tree.clone(), batch_stats.clone()).await;
                            }
                            tracing::info!("batch_worker: Exiting");
                            break;
                        }
                    }
                }

                _ = interval.tick() => {
                    // Time-based flush
                    if !pending_entries.is_empty() {
                        let time = Instant::now();
                        tracing::trace!("batch_worker: Time flush after {}ms, flushing {} entries",
                            timeout_duration.as_millis(), pending_entries.len());
                        Self::flush_batch(&mut pending_entries, batch_mutex.clone(), merkle_tree.clone(), batch_stats.clone()).await;
                        tracing::trace!("batch_worker: Flushed in {}ms", time.elapsed().as_millis());
                    }
                }
            }
        }
    }

    /// Flush a batch of entries atomically
    async fn flush_batch(
        entries: &mut Vec<BatchEntry>,
        batch_mutex: Arc<Mutex<()>>,
        merkle_tree: StorageBackedMerkleTree,
        batch_stats: Arc<Mutex<BatchStats>>,
    ) {
        if entries.is_empty() {
            tracing::trace!("flush_batch: No entries to flush");
            return;
        }

        let _lock = batch_mutex.lock().await;
        let start_time = Instant::now();
        let batch_size = entries.len();

        tracing::trace!("flush_batch: Flushing {} entries", batch_size);

        let mut leaf_data_vec = Vec::new();

        #[allow(clippy::type_complexity)]
        let mut entry_metadata: Vec<(
            usize,
            Vec<u8>,
            [u8; 32],
            SignedCertificateTimestamp,
            LogEntry,
        )> = Vec::new();

        // Store completion info separately
        #[allow(clippy::type_complexity)]
        let mut completion_info: Vec<(
            oneshot::Sender<Result<(u64, SignedCertificateTimestamp)>>,
            Option<SignedCertificateTimestamp>,
        )> = Vec::new();
        let mut failed_entries = Vec::new();

        // Deduplication tracking variables
        let mut cert_hashes_to_check = std::collections::HashSet::new();
        let mut bytes_saved = 0u64;
        let mut dedup_check_time_ms = 0u64;
        let mut total_certs_in_batch = 0usize;
        let mut total_certs_skipped = 0usize;

        // Get the starting index first to assign indices
        let starting_index = match merkle_tree.size().await {
            Ok(size) => size,
            Err(e) => {
                tracing::error!("Failed to get tree size: {:?}", e);
                for entry in entries.drain(..) {
                    let _ = entry
                        .completion_tx
                        .send(Err(StorageError::InvalidFormat(format!(
                            "Failed to get tree size: {:?}",
                            e
                        ))));
                }
                return;
            }
        };

        tracing::trace!(
            "Elapsed time before processing entries: {:?}",
            start_time.elapsed()
        );

        // Process entries and generate SCTs with assigned indices
        for (i, mut entry) in entries.drain(..).enumerate() {
            let assigned_index = starting_index + i as u64;

            // Update the log entry with the assigned index
            entry.log_entry.index = assigned_index;

            // Generate SCT with the assigned index
            let sct = (entry.sct_callback)(assigned_index);

            // Regenerate leaf_data with the assigned index
            let leaf_data_with_index = LogEntry::compute_leaf_data_with_index(
                &entry.log_entry.certificate,
                entry.log_entry.entry_type,
                entry.log_entry.issuer_key_hash.as_deref(),
                entry.log_entry.timestamp,
                assigned_index,
            );

            // Update the leaf_data in the entry to match what we're storing in the merkle tree
            entry.log_entry.leaf_data = leaf_data_with_index.clone();

            // Debug: print the hash for the first entry
            if assigned_index == 0 {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update([0x00]);
                hasher.update(&leaf_data_with_index);
                let hash = hasher.finalize();
                println!(
                    "DEBUG: Pushing entry 0 to merkle tree with hash: {}",
                    hex::encode(hash)
                );
            }

            let dedup_entry = DeduplicatedLogEntry::from_log_entry(&entry.log_entry);

            match postcard::to_stdvec(&dedup_entry) {
                Ok(entry_data) => {
                    entry_metadata.push((
                        i,
                        entry_data,
                        entry.cert_hash,
                        sct.clone(),
                        entry.log_entry.clone(), // Keep original for certificate storage
                    ));
                    leaf_data_vec.push(leaf_data_with_index);
                    completion_info.push((entry.completion_tx, Some(sct)));
                }
                Err(e) => {
                    failed_entries.push((i, StorageError::InvalidFormat(e.to_string())));
                    completion_info.push((entry.completion_tx, None));
                }
            }
        }

        tracing::trace!(
            "Elapsed time after processing entries: {:?}",
            start_time.elapsed(),
        );

        let push_result = if !leaf_data_vec.is_empty() {
            tracing::trace!(
                "flush_batch: Pushing {} entries to merkle tree",
                leaf_data_vec.len()
            );

            // Build the additional data that needs to be written atomically with the tree

            // Collect all unique certificate hashes to check
            cert_hashes_to_check.clear();
            let mut cert_data_map = std::collections::HashMap::new();

            for (_orig_idx, _entry_data, _cert_hash, _sct, log_entry) in entry_metadata.iter() {
                if log_entry.entry_type != crate::types::LogEntryType::PrecertEntry {
                    let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
                    total_certs_in_batch += 1;
                    if cert_hashes_to_check.insert(cert_hash) {
                        cert_data_map.insert(cert_hash, log_entry.certificate.clone());
                    }
                }

                // Chain certificates
                if let Some(chain) = &log_entry.chain {
                    for cert in chain {
                        let cert_hash = DeduplicatedLogEntry::hash_certificate(cert);
                        total_certs_in_batch += 1;
                        if cert_hashes_to_check.insert(cert_hash) {
                            cert_data_map.insert(cert_hash, cert.clone());
                        }
                    }
                }

                if let Some(precert) = &log_entry.original_precert {
                    let precert_hash = DeduplicatedLogEntry::hash_certificate(precert);
                    total_certs_in_batch += 1;
                    if cert_hashes_to_check.insert(precert_hash) {
                        cert_data_map.insert(precert_hash, precert.clone());
                    }
                }
            }

            // Check which certificates already exist
            let keys_to_check: Vec<Vec<u8>> = cert_hashes_to_check
                .iter()
                .map(|hash| {
                    let mut key = Vec::with_capacity(KeyPrefix::CERT.len() + 32);
                    key.extend_from_slice(KeyPrefix::CERT);
                    key.extend_from_slice(hash);
                    key
                })
                .collect();

            let dedup_check_start = Instant::now();

            let existence_results = match merkle_tree.check_keys_exist(&keys_to_check).await {
                Ok(results) => results,
                Err(e) => {
                    tracing::warn!(
                        "Failed to check certificate existence: {:?}, will write all certificates",
                        e
                    );
                    vec![false; keys_to_check.len()]
                }
            };
            dedup_check_time_ms = dedup_check_start.elapsed().as_millis() as u64;

            let existing_certs: std::collections::HashSet<[u8; 32]> = cert_hashes_to_check
                .iter()
                .zip(existence_results.iter())
                .filter_map(|(hash, exists)| if *exists { Some(*hash) } else { None })
                .collect();

            bytes_saved = 0;

            // Calculate actual certificates skipped and bytes saved
            for (_orig_idx, _entry_data, _cert_hash, _sct, log_entry) in entry_metadata.iter() {
                if log_entry.entry_type != crate::types::LogEntryType::PrecertEntry {
                    let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
                    if existing_certs.contains(&cert_hash) {
                        total_certs_skipped += 1;
                        bytes_saved += log_entry.certificate.len() as u64;
                    }
                }

                if let Some(chain) = &log_entry.chain {
                    for cert in chain {
                        let cert_hash = DeduplicatedLogEntry::hash_certificate(cert);
                        if existing_certs.contains(&cert_hash) {
                            total_certs_skipped += 1;
                            bytes_saved += cert.len() as u64;
                        }
                    }
                }

                if let Some(precert) = &log_entry.original_precert {
                    let precert_hash = DeduplicatedLogEntry::hash_certificate(precert);
                    if existing_certs.contains(&precert_hash) {
                        total_certs_skipped += 1;
                        bytes_saved += precert.len() as u64;
                    }
                }
            }

            // Prepare all additional data with correct indices
            let mut additional_data = Vec::new();
            for (vec_idx, (_orig_idx, entry_data, cert_hash, sct, _log_entry)) in
                entry_metadata.iter().enumerate()
            {
                let index = starting_index + vec_idx as u64;

                let mut entry_key = Vec::with_capacity(KeyPrefix::ENTRY.len() + 8);
                entry_key.extend_from_slice(KeyPrefix::ENTRY);
                entry_key.extend_from_slice(&index.to_be_bytes());

                // For get-proof-by-hash API, we need to store hash->index mapping
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update([0x00]); // Leaf prefix
                hasher.update(&leaf_data_vec[vec_idx]);
                let computed_leaf_hash: [u8; 32] = hasher.finalize().into();

                let mut hash_key = Vec::with_capacity(KeyPrefix::HASH_INDEX.len() + 32);
                hash_key.extend_from_slice(KeyPrefix::HASH_INDEX);
                hash_key.extend_from_slice(&computed_leaf_hash);

                let mut cert_sct_key = Vec::with_capacity(KeyPrefix::CERT_SCT.len() + 32);
                cert_sct_key.extend_from_slice(KeyPrefix::CERT_SCT);
                cert_sct_key.extend_from_slice(cert_hash);
                let sct_entry = CertificateSctEntry {
                    index,
                    sct: sct.clone(),
                    timestamp: sct.timestamp,
                };
                let sct_data = match postcard::to_stdvec(&sct_entry) {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("Failed to serialize SCT entry: {}", e);
                        continue;
                    }
                };

                // Store deduplicated entry
                additional_data.push((entry_key, entry_data.clone()));
                additional_data.push((hash_key, index.to_be_bytes().to_vec()));
                additional_data.push((cert_sct_key, sct_data));
            }

            // Add only new certificates to additional_data
            for (hash, cert_data) in cert_data_map.iter() {
                if !existing_certs.contains(hash) {
                    let mut cert_key = Vec::with_capacity(KeyPrefix::CERT.len() + 32);
                    cert_key.extend_from_slice(KeyPrefix::CERT);
                    cert_key.extend_from_slice(hash);
                    additional_data.push((cert_key, cert_data.clone()));
                }
            }

            // Precompute subtree roots for static API for the range we're about to add
            let end_index = starting_index + batch_size as u64;
            let precomputed_subtree_roots = merkle_tree
                .precompute_tile_subtree_roots_for_range(starting_index, end_index)
                .await
                .expect("Precomputing tile subtree roots should never fail");

            // Add precomputed subtree roots to additional_data
            additional_data.extend(precomputed_subtree_roots);

            tracing::trace!("Elapsed time before batch push: {:?}", start_time.elapsed());
            match merkle_tree
                .batch_push_with_data(leaf_data_vec, additional_data)
                .await
            {
                Ok(actual_starting_index) => Ok(actual_starting_index),
                Err(e) => Err(StorageError::InvalidFormat(format!(
                    "Merkle tree error: {:?}",
                    e
                ))),
            }
        } else {
            Err(StorageError::InvalidFormat(
                "No valid entries to flush".into(),
            ))
        };
        tracing::trace!("Elapsed time after batch push: {:?}", start_time.elapsed());

        tracing::trace!(
            "flush_batch: Completed with result: {:?}",
            push_result.is_ok()
        );

        // Notify all entries with their results
        match push_result {
            Ok(_) => {
                let mut valid_idx = 0;
                for (i, (tx, sct_opt)) in completion_info.into_iter().enumerate() {
                    if let Some((_, error)) = failed_entries.iter().find(|(idx, _)| *idx == i) {
                        tracing::info!(
                            "flush_batch: Notifying entry {} with serialization error",
                            i
                        );
                        let _ = tx.send(Err(error.clone()));
                    } else if let Some(sct) = sct_opt {
                        let assigned_index = starting_index + valid_idx;
                        valid_idx += 1;
                        tracing::trace!(
                            "flush_batch: Notifying entry {} with assigned index {} and SCT",
                            i,
                            assigned_index
                        );
                        let _ = tx.send(Ok((assigned_index, sct)));
                    } else {
                        // This shouldn't happen as failed entries are already handled above
                        let _ =
                            tx.send(Err(StorageError::InvalidFormat("Unexpected error".into())));
                    }
                }
            }
            Err(ref e) => {
                for (i, (tx, _)) in completion_info.into_iter().enumerate() {
                    if let Some((_, error)) = failed_entries.iter().find(|(idx, _)| *idx == i) {
                        let _ = tx.send(Err(error.clone()));
                    } else {
                        let _ = tx.send(Err(e.clone()));
                    }
                }
            }
        }

        tracing::trace!(
            "Elapsed time after notifying entries: {:?}",
            start_time.elapsed()
        );

        // Record batch statistics
        let flush_time_ms = start_time.elapsed().as_millis() as u64;
        let flush_time_secs = start_time.elapsed().as_secs_f64();

        match &push_result {
            Ok(_) => {
                crate::metrics::STORAGE_BATCHES_FLUSHED
                    .with_label_values(&["success"])
                    .inc();
                crate::metrics::STORAGE_FLUSH_DURATION_SECONDS
                    .with_label_values(&["success"])
                    .observe(flush_time_secs);
            }
            Err(_) => {
                crate::metrics::STORAGE_BATCHES_FLUSHED
                    .with_label_values(&["failed"])
                    .inc();
                crate::metrics::STORAGE_FLUSH_DURATION_SECONDS
                    .with_label_values(&["failed"])
                    .observe(flush_time_secs);
            }
        }

        crate::metrics::STORAGE_ENTRIES_PROCESSED
            .with_label_values(&["total"])
            .inc_by(batch_size as u64);

        // Update deduplication metrics
        if total_certs_in_batch > 0 {
            crate::metrics::DEDUPLICATED_CERTIFICATES
                .with_label_values(&["checked"])
                .inc_by(total_certs_in_batch as u64);
            crate::metrics::DEDUPLICATED_CERTIFICATES
                .with_label_values(&["skipped"])
                .inc_by(total_certs_skipped as u64);
        }

        let mut stats = batch_stats.lock().await;
        stats.batches_flushed += 1;
        stats.total_entries += batch_size as u64;
        stats.total_flush_time_ms += flush_time_ms;

        if stats.min_batch_size == 0 || batch_size < stats.min_batch_size {
            stats.min_batch_size = batch_size;
        }
        if batch_size > stats.max_batch_size {
            stats.max_batch_size = batch_size;
        }

        // Update deduplication stats if we had any certificates
        if total_certs_in_batch > 0 {
            stats.total_certs_checked += total_certs_in_batch as u64;
            stats.total_certs_deduplicated += total_certs_skipped as u64;
            stats.total_bytes_saved += bytes_saved;
            stats.total_dedup_check_time_ms += dedup_check_time_ms;
        }

        tracing::trace!(
            "flush_batch: Flushed {} entries in {}ms (total batches: {}, total time: {}ms)",
            batch_size,
            flush_time_ms,
            stats.batches_flushed,
            stats.total_flush_time_ms
        );
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        Ok(self.db.get(key).await?)
    }

    /// Find index by hash
    pub async fn find_index_by_hash(&self, hash: &[u8]) -> Result<Option<u64>> {
        let mut hash_key = Vec::with_capacity(KeyPrefix::HASH_INDEX.len() + hash.len());
        hash_key.extend_from_slice(KeyPrefix::HASH_INDEX);
        hash_key.extend_from_slice(hash);
        match self.get(&hash_key).await? {
            Some(bytes) => {
                let index_array: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StorageError::InvalidFormat("Invalid index format".into()))?;
                Ok(Some(u64::from_be_bytes(index_array)))
            }
            None => Ok(None),
        }
    }

    /// Get SCT by certificate hash for deduplication
    pub async fn get_sct_by_cert_hash(
        &self,
        cert_hash: &[u8; 32],
    ) -> Result<Option<CertificateSctEntry>> {
        let mut key = Vec::with_capacity(KeyPrefix::CERT_SCT.len() + 32);
        key.extend_from_slice(KeyPrefix::CERT_SCT);
        key.extend_from_slice(cert_hash);
        match self.get(&key).await? {
            Some(bytes) => {
                let entry: CertificateSctEntry = postcard::from_bytes(&bytes).map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to deserialize SCT entry: {}", e))
                })?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Get a certificate by its hash
    pub async fn get_certificate(&self, cert_hash: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut key = Vec::with_capacity(KeyPrefix::CERT.len() + cert_hash.len());
        key.extend_from_slice(KeyPrefix::CERT);
        key.extend_from_slice(cert_hash);
        match self.get(&key).await? {
            Some(bytes) => Ok(Some(bytes.to_vec())),
            None => Ok(None),
        }
    }

    /// Get a deduplicated log entry by index
    pub async fn get_deduplicated_entry(&self, index: u64) -> Result<Option<DeduplicatedLogEntry>> {
        let mut key = Vec::with_capacity(KeyPrefix::ENTRY.len() + 8);
        key.extend_from_slice(KeyPrefix::ENTRY);
        key.extend_from_slice(&index.to_be_bytes());
        match self.get(&key).await? {
            Some(bytes) => {
                let entry: DeduplicatedLogEntry = postcard::from_bytes(&bytes).map_err(|e| {
                    StorageError::InvalidFormat(format!(
                        "Failed to deserialize deduplicated entry: {}",
                        e
                    ))
                })?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Reconstruct a full LogEntry from a DeduplicatedLogEntry
    pub async fn reconstruct_log_entry(
        &self,
        dedup_entry: &DeduplicatedLogEntry,
    ) -> Result<LogEntry> {
        let (certificate, original_precert) = if dedup_entry.entry_type
            == crate::types::LogEntryType::PrecertEntry
        {
            let storage_clone = self.clone();
            let cert_hash = dedup_entry.certificate_hash;
            let precert_result =
                tokio::spawn(async move { storage_clone.get_certificate(&cert_hash).await })
                    .await
                    .map_err(|e| StorageError::InvalidFormat(format!("Task join error: {}", e)))??
                    .ok_or_else(|| {
                        StorageError::InvalidFormat("Original precert not found".to_string())
                    })?;

            let chain_handles = dedup_entry.chain_hashes.as_ref().map(|hashes| {
                hashes
                    .iter()
                    .map(|hash| {
                        let storage_clone = self.clone();
                        let hash_clone = *hash;
                        tokio::spawn(
                            async move { storage_clone.get_certificate(&hash_clone).await },
                        )
                    })
                    .collect::<Vec<_>>()
            });

            let chain = match chain_handles {
                Some(handles) => {
                    let results = join_all(handles).await;
                    let mut chain_certs = Vec::new();
                    for result in results {
                        let cert = result
                            .map_err(|e| {
                                StorageError::InvalidFormat(format!("Task join error: {}", e))
                            })??
                            .ok_or_else(|| {
                                StorageError::InvalidFormat(
                                    "Chain certificate not found".to_string(),
                                )
                            })?;
                        chain_certs.push(cert);
                    }
                    chain_certs
                }
                None => Vec::new(),
            };

            let tbs_certificate = TbsExtractor::extract_tbs_certificate(&precert_result, &chain)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to transform precert: {}", e))
                })?;

            (tbs_certificate, Some(precert_result))
        } else {
            let storage_clone = self.clone();
            let cert_hash = dedup_entry.certificate_hash;
            let main_cert_handle =
                tokio::spawn(async move { storage_clone.get_certificate(&cert_hash).await });

            let certificate = main_cert_handle
                .await
                .map_err(|e| StorageError::InvalidFormat(format!("Task join error: {}", e)))??
                .ok_or_else(|| StorageError::InvalidFormat("Certificate not found".to_string()))?;

            (certificate, None)
        };

        let chain_handles = dedup_entry.chain_hashes.as_ref().map(|hashes| {
            hashes
                .iter()
                .map(|hash| {
                    let storage_clone = self.clone();
                    let hash_clone = *hash;
                    tokio::spawn(async move { storage_clone.get_certificate(&hash_clone).await })
                })
                .collect::<Vec<_>>()
        });

        let chain = match chain_handles {
            Some(handles) => {
                let results = join_all(handles).await;
                let mut chain_certs = Vec::new();
                for result in results {
                    let cert = result
                        .map_err(|e| {
                            StorageError::InvalidFormat(format!("Task join error: {}", e))
                        })??
                        .ok_or_else(|| {
                            StorageError::InvalidFormat("Chain certificate not found".to_string())
                        })?;
                    chain_certs.push(cert);
                }
                Some(chain_certs)
            }
            None => None,
        };

        Ok(LogEntry {
            index: dedup_entry.index,
            timestamp: dedup_entry.timestamp,
            entry_type: dedup_entry.entry_type,
            certificate,
            chain,
            issuer_key_hash: dedup_entry.issuer_key_hash.map(|h| h.to_vec()),
            original_precert,
            leaf_data: dedup_entry.leaf_data.clone(),
        })
    }

    /// Get a full log entry by index (with reconstruction)
    pub async fn get_entry(&self, index: u64) -> Result<Option<LogEntry>> {
        match self.get_deduplicated_entry(index).await? {
            Some(dedup_entry) => Ok(Some(self.reconstruct_log_entry(&dedup_entry).await?)),
            None => Ok(None),
        }
    }

    /// Background worker that logs queue metrics periodically
    async fn metrics_worker(
        batch_sender: mpsc::Sender<BatchEntry>,
        batch_stats: Arc<Mutex<BatchStats>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_stats = BatchStats::default();

        loop {
            interval.tick().await;

            // Get current queue depth
            let capacity = batch_sender.capacity();
            let max_capacity = batch_sender.max_capacity();
            let current_depth = max_capacity - capacity;
            let utilization_percent = (current_depth as f64 / max_capacity as f64) * 100.0;

            crate::metrics::STORAGE_QUEUE_DEPTH.set(current_depth as i64);
            crate::metrics::STORAGE_QUEUE_CAPACITY.set(max_capacity as i64);

            // Get batch statistics
            let stats = batch_stats.lock().await;
            let interval_batches = stats
                .batches_flushed
                .saturating_sub(last_stats.batches_flushed);
            let interval_entries = stats.total_entries.saturating_sub(last_stats.total_entries);
            let interval_time_ms = stats
                .total_flush_time_ms
                .saturating_sub(last_stats.total_flush_time_ms);

            if interval_batches > 0 {
                let avg_batch_size = interval_entries / interval_batches;
                let avg_flush_time = interval_time_ms / interval_batches;
                let throughput = (interval_entries as f64 / 5.0) as u64; // entries per second

                // Calculate deduplication stats for this interval
                let interval_certs_checked = stats
                    .total_certs_checked
                    .saturating_sub(last_stats.total_certs_checked);
                let interval_certs_deduped = stats
                    .total_certs_deduplicated
                    .saturating_sub(last_stats.total_certs_deduplicated);
                let interval_bytes_saved = stats
                    .total_bytes_saved
                    .saturating_sub(last_stats.total_bytes_saved);
                let interval_dedup_time = stats
                    .total_dedup_check_time_ms
                    .saturating_sub(last_stats.total_dedup_check_time_ms);

                let dedup_rate = if interval_certs_checked > 0 {
                    (interval_certs_deduped as f64 / interval_certs_checked as f64) * 100.0
                } else {
                    0.0
                };

                tracing::info!(
                    "Batch stats: {} batches flushed (avg size: {}, avg time: {}ms), throughput: {} entries/sec, queue: {}/{}, dedup: {:.1}% ({}/{} certs, {} KB saved, {}ms)",
                    interval_batches,
                    avg_batch_size,
                    avg_flush_time,
                    throughput,
                    current_depth,
                    max_capacity,
                    dedup_rate,
                    interval_certs_deduped,
                    interval_certs_checked,
                    interval_bytes_saved / 1024,
                    interval_dedup_time
                );
            } else {
                tracing::info!(
                    "Batch stats: No batches flushed in last 5s, queue: {}/{}",
                    current_depth,
                    max_capacity
                );
            }

            // Clone current stats for next interval
            last_stats = BatchStats {
                batches_flushed: stats.batches_flushed,
                total_entries: stats.total_entries,
                total_flush_time_ms: stats.total_flush_time_ms,
                min_batch_size: stats.min_batch_size,
                max_batch_size: stats.max_batch_size,
                total_certs_checked: stats.total_certs_checked,
                total_certs_deduplicated: stats.total_certs_deduplicated,
                total_bytes_saved: stats.total_bytes_saved,
                total_dedup_check_time_ms: stats.total_dedup_check_time_ms,
            };
            drop(stats);

            if utilization_percent > 90.0 {
                crate::metrics::HEALTH_CHECK_STATUS
                    .with_label_values(&["storage_queue"])
                    .set(0.0);
                tracing::warn!(
                    "Queue utilization critical: {}%",
                    utilization_percent as u32
                );
            } else if utilization_percent > 75.0 {
                crate::metrics::HEALTH_CHECK_STATUS
                    .with_label_values(&["storage_queue"])
                    .set(0.5);
                tracing::warn!("Queue utilization high: {}%", utilization_percent as u32);
            } else {
                crate::metrics::HEALTH_CHECK_STATUS
                    .with_label_values(&["storage_queue"])
                    .set(1.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{sct::SctVersion, LogEntryType, LogId};
    use chrono::{TimeZone, Utc};
    use object_store::memory::InMemory;

    // Helper functions for creating test data
    fn create_test_log_entry(index: u64) -> LogEntry {
        let timestamp = Utc
            .timestamp_millis_opt(1234567890000 + (index as i64 * 1000))
            .unwrap();
        let certificate = vec![0x01, 0x02, 0x03, index as u8];
        let chain = Some(vec![vec![0x04, 0x05], vec![0x06, 0x07]]);

        LogEntry::new_with_timestamp(index, certificate, chain, timestamp)
    }

    fn create_test_precert_entry() -> (LogEntry, [u8; 32]) {
        let original_precert_der = crate::test_utils::utils::create_precertificate_with_poison();
        let issuer_cert_der = crate::test_utils::utils::create_test_certificate();
        // For precertificates, the chain includes [precert, issuer]
        let full_chain = vec![original_precert_der.clone(), issuer_cert_der.clone()];

        let issuer_key_hash: Vec<u8> =
            crate::test_utils::utils::extract_test_issuer_key_hash(&full_chain);

        let tbs_certificate =
            TbsExtractor::extract_tbs_certificate(&original_precert_der, &full_chain).unwrap();

        let timestamp = Utc.timestamp_millis_opt(1234567890000).unwrap();

        let log_entry = LogEntry::new_precert_with_timestamp(
            0,
            tbs_certificate.clone(),
            Some(vec![issuer_cert_der]),
            issuer_key_hash.clone(),
            original_precert_der,
            timestamp,
        );

        // Calculate cert hash for deduplication (using TBS certificate for pre-certs)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&tbs_certificate);
        hasher.update(&issuer_key_hash);
        let cert_hash: [u8; 32] = hasher.finalize().into();

        (log_entry, cert_hash)
    }

    fn create_test_sct(log_id: LogId, timestamp: u64) -> SignedCertificateTimestamp {
        SignedCertificateTimestamp {
            version: SctVersion::V1,
            log_id,
            timestamp,
            extensions: vec![],
            signature: vec![0xaa, 0xbb, 0xcc],
        }
    }

    fn create_test_log_id() -> LogId {
        LogId::new(&[0x42; 32])
    }

    async fn create_test_storage(config: BatchConfig) -> (CtStorage, StorageBackedMerkleTree) {
        let object_store = Arc::new(InMemory::new());
        let db = Arc::new(Db::open("test", object_store).await.unwrap());
        let merkle_tree = StorageBackedMerkleTree::new(db.clone()).await.unwrap();
        let storage = CtStorage::new(db.clone(), config, merkle_tree.clone())
            .await
            .unwrap();

        (storage, merkle_tree)
    }

    #[tokio::test]
    async fn test_add_and_retrieve_entry() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_entry = create_test_log_entry(0);
        let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, 1234567890000);

        let (index, _sct) = storage
            .add_entry_batched(log_entry.clone(), cert_hash, move |_| sct)
            .await
            .unwrap();
        assert_eq!(index, 0);

        // Retrieve entry
        let retrieved = storage.get_entry(index).await.unwrap().unwrap();
        assert_eq!(retrieved.index, log_entry.index);
        assert_eq!(retrieved.certificate, log_entry.certificate);
        assert_eq!(retrieved.timestamp, log_entry.timestamp);
    }

    #[tokio::test]
    async fn test_precert_storage_optimization() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let (log_entry, cert_hash) = create_test_precert_entry();
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, 1234567890000);

        let (index, _sct) = storage
            .add_entry_batched(log_entry.clone(), cert_hash, move |_| sct)
            .await
            .unwrap();

        let dedup_entry = storage
            .get_deduplicated_entry(index)
            .await
            .unwrap()
            .unwrap();

        let original_precert_hash =
            DeduplicatedLogEntry::hash_certificate(log_entry.original_precert.as_ref().unwrap());
        assert_eq!(dedup_entry.certificate_hash, original_precert_hash);
        assert_eq!(
            dedup_entry.original_precert_hash,
            Some(original_precert_hash)
        );

        // Retrieve full entry and verify TBS is reconstructed correctly
        let retrieved = storage.get_entry(index).await.unwrap().unwrap();
        assert_eq!(
            retrieved.entry_type,
            crate::types::LogEntryType::PrecertEntry
        );
        assert_eq!(retrieved.original_precert, log_entry.original_precert);

        // The certificate field should contain the reconstructed TBS
        // It should match what we originally computed
        assert_eq!(retrieved.certificate, log_entry.certificate);
        assert_eq!(retrieved.issuer_key_hash, log_entry.issuer_key_hash);
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let config = BatchConfig {
            max_batch_size: 3,
            max_batch_timeout_ms: 1000,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_id = create_test_log_id();
        let mut handles = vec![];

        // Add multiple entries concurrently
        for i in 0..3 {
            let storage_clone = storage.clone();
            let log_entry = create_test_log_entry(i);
            let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
            let sct = create_test_sct(log_id.clone(), 1234567890000 + i);

            let handle: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
                storage_clone
                    .add_entry_batched(log_entry, cert_hash, move |_| sct)
                    .await
                    .map(|(idx, _)| idx)
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap().unwrap());
        }

        // Check that indices are sequential
        results.sort();
        assert_eq!(results, vec![0, 1, 2]);

        // Verify all entries exist
        for i in 0..3 {
            let entry = storage.get_entry(i).await.unwrap().unwrap();
            assert_eq!(entry.index, i);
        }
    }

    #[tokio::test]
    async fn test_timeout_based_flush() {
        let config = BatchConfig {
            max_batch_size: 100, // Large enough to not trigger size-based flush
            max_batch_timeout_ms: 200,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_entry = create_test_log_entry(0);
        let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, 1234567890000);

        // Add single entry
        let (index, _sct) = storage
            .add_entry_batched(log_entry, cert_hash, move |_| sct)
            .await
            .unwrap();
        assert_eq!(index, 0);

        // Wait for timeout-based flush
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // Verify entry was flushed
        let entry = storage.get_entry(0).await.unwrap();
        assert!(entry.is_some());
    }

    #[tokio::test]
    async fn test_certificate_deduplication() {
        let config = BatchConfig {
            max_batch_size: 2,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_id = create_test_log_id();
        let certificate = vec![0x01, 0x02, 0x03, 0x04];
        let timestamp1 = Utc.timestamp_millis_opt(1234567890000).unwrap();
        let timestamp2 = Utc.timestamp_millis_opt(1234567891000).unwrap();

        // Create two entries with the same certificate
        let entry1 = LogEntry::new_with_timestamp(0, certificate.clone(), None, timestamp1);
        let entry2 = LogEntry::new_with_timestamp(1, certificate.clone(), None, timestamp2);

        let cert_hash = DeduplicatedLogEntry::hash_certificate(&certificate);
        let sct1 = create_test_sct(log_id.clone(), timestamp1.timestamp_millis() as u64);
        let sct2 = create_test_sct(log_id.clone(), timestamp2.timestamp_millis() as u64);

        // Add both entries
        let (index1, _sct1) = storage
            .add_entry_batched(entry1, cert_hash, move |_| sct1)
            .await
            .unwrap();
        let (index2, _sct2) = storage
            .add_entry_batched(entry2, cert_hash, move |_| sct2)
            .await
            .unwrap();

        assert_eq!(index1, 0);
        assert_eq!(index2, 1);

        // Check SCT deduplication - both should have SCT entries
        let sct_entry1 = storage.get_sct_by_cert_hash(&cert_hash).await.unwrap();
        assert!(sct_entry1.is_some());

        // The certificate should only be stored once
        let cert_data = storage.get_certificate(&cert_hash).await.unwrap();
        assert!(cert_data.is_some());
        assert_eq!(cert_data.unwrap(), certificate);
    }

    #[tokio::test]
    async fn test_find_index_by_hash() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_entry = create_test_log_entry(0);
        let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, 1234567890000);

        // Add entry
        let (index, _sct) = storage
            .add_entry_batched(log_entry.clone(), cert_hash, move |_| sct)
            .await
            .unwrap();

        // Calculate leaf hash with the assigned index
        use sha2::{Digest, Sha256};
        let leaf_data_with_index = LogEntry::compute_leaf_data_with_index(
            &log_entry.certificate,
            log_entry.entry_type,
            log_entry.issuer_key_hash.as_deref(),
            log_entry.timestamp,
            index,
        );
        let mut hasher = Sha256::new();
        hasher.update([0x00]); // Leaf prefix
        hasher.update(&leaf_data_with_index);
        let leaf_hash = hasher.finalize();

        // Find index by hash
        let found_index = storage.find_index_by_hash(&leaf_hash).await.unwrap();
        assert_eq!(found_index, Some(index));

        // Try non-existent hash
        let random_hash = [0xff; 32];
        let not_found = storage.find_index_by_hash(&random_hash).await.unwrap();
        assert_eq!(not_found, None);
    }

    #[tokio::test]
    async fn test_deduplicated_entry_serialization() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_entry = create_test_log_entry(0);
        let cert_hash = DeduplicatedLogEntry::hash_certificate(&log_entry.certificate);
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, 1234567890000);

        // Add entry
        storage
            .add_entry_batched(log_entry.clone(), cert_hash, move |_| sct)
            .await
            .unwrap();

        // Get deduplicated entry
        let dedup_entry = storage.get_deduplicated_entry(0).await.unwrap().unwrap();
        assert_eq!(dedup_entry.index, 0);
        assert_eq!(dedup_entry.certificate_hash, cert_hash);
        assert_eq!(dedup_entry.entry_type, LogEntryType::X509Entry);
    }

    #[tokio::test]
    async fn test_precert_entry_with_chain() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let (log_entry, cert_hash) = create_test_precert_entry();
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, log_entry.timestamp.timestamp_millis() as u64);

        let (index, _sct) = storage
            .add_entry_batched(log_entry.clone(), cert_hash, move |_| sct)
            .await
            .unwrap();

        let retrieved = storage.get_entry(index).await.unwrap().unwrap();
        assert_eq!(retrieved.entry_type, LogEntryType::PrecertEntry);
        assert_eq!(retrieved.issuer_key_hash, log_entry.issuer_key_hash);
        assert_eq!(retrieved.original_precert, log_entry.original_precert);
        assert_eq!(retrieved.chain, log_entry.chain);
        // Verify the certificate (TBS) is properly reconstructed
        assert_eq!(retrieved.certificate, log_entry.certificate);
    }

    #[tokio::test]
    async fn test_reconstruct_log_entry_missing_certificate() {
        let config = BatchConfig::default();
        let (storage, _tree) = create_test_storage(config).await;

        let dedup_entry = DeduplicatedLogEntry {
            index: 0,
            timestamp: Utc::now(),
            entry_type: LogEntryType::X509Entry,
            certificate_hash: [0xff; 32], // Non-existent certificate
            chain_hashes: None,
            issuer_key_hash: None,
            original_precert_hash: None,
            leaf_data: vec![],
        };

        let result = storage.reconstruct_log_entry(&dedup_entry).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::InvalidFormat(msg) => assert!(msg.contains("Certificate not found")),
            _ => panic!("Wrong error type"),
        }
    }

    #[tokio::test]
    async fn test_get_operations_on_non_existent_entries() {
        let config = BatchConfig::default();
        let (storage, _tree) = create_test_storage(config).await;

        // Test get non-existent entry
        let entry = storage.get_entry(999).await.unwrap();
        assert!(entry.is_none());

        // Test get non-existent deduplicated entry
        let dedup_entry = storage.get_deduplicated_entry(999).await.unwrap();
        assert!(dedup_entry.is_none());

        // Test get non-existent certificate
        let cert = storage.get_certificate(&[0xff; 32]).await.unwrap();
        assert!(cert.is_none());

        // Test get non-existent SCT
        let sct = storage.get_sct_by_cert_hash(&[0xff; 32]).await.unwrap();
        assert!(sct.is_none());
    }

    #[tokio::test]
    async fn test_batch_failure_handling() {
        // Test batch processing when some entries fail
        let config = BatchConfig {
            max_batch_size: 5,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_id = create_test_log_id();
        let mut handles = vec![];

        // Add entries where we simulate different scenarios
        for i in 0..5 {
            let storage_clone = storage.clone();
            let timestamp = Utc.timestamp_millis_opt(1234567890000 + i).unwrap();

            // Create entries with different characteristics
            let (certificate, chain) = if i == 2 {
                // Entry with very large certificate that might cause issues
                (vec![0xff; 1_000_000], None)
            } else {
                (
                    vec![0x01, 0x02, 0x03, i as u8],
                    Some(vec![vec![0x04, 0x05]]),
                )
            };

            let entry =
                LogEntry::new_with_timestamp(i as u64, certificate.clone(), chain, timestamp);
            let cert_hash = DeduplicatedLogEntry::hash_certificate(&certificate);
            let sct = create_test_sct(log_id.clone(), timestamp.timestamp_millis() as u64);

            let handle: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
                storage_clone
                    .add_entry_batched(entry, cert_hash, move |_| sct)
                    .await
                    .map(|(idx, _)| idx)
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let mut successes = 0;
        let mut failures = 0;

        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => successes += 1,
                Err(_) => failures += 1,
            }
        }

        // All should succeed in this case (large certificates are valid)
        assert_eq!(successes, 5);
        assert_eq!(failures, 0);

        // Verify all entries exist
        for i in 0..5 {
            let entry = storage.get_entry(i).await.unwrap();
            assert!(entry.is_some());
        }
    }

    #[tokio::test]
    async fn test_same_batch_deduplication() {
        let config = BatchConfig {
            max_batch_size: 5,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_id = create_test_log_id();
        let certificate = vec![0x01, 0x02, 0x03, 0x04];
        let cert_hash = DeduplicatedLogEntry::hash_certificate(&certificate);

        // Add the same certificate multiple times in the same batch
        let mut handles = vec![];
        for i in 0..5 {
            let storage_clone = storage.clone();
            let timestamp = Utc.timestamp_millis_opt(1234567890000 + i).unwrap();
            let entry =
                LogEntry::new_with_timestamp(i as u64, certificate.clone(), None, timestamp);
            let sct = create_test_sct(log_id.clone(), timestamp.timestamp_millis() as u64);

            let handle: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
                storage_clone
                    .add_entry_batched(entry, cert_hash, move |_| sct)
                    .await
                    .map(|(idx, _)| idx)
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap().unwrap());
        }

        // All should succeed with different indices
        results.sort();
        assert_eq!(results, vec![0, 1, 2, 3, 4]);

        // The certificate should only be stored once
        let cert_data = storage.get_certificate(&cert_hash).await.unwrap();
        assert!(cert_data.is_some());
        assert_eq!(cert_data.unwrap(), certificate);

        // All entries should exist
        for i in 0..5 {
            let entry = storage.get_entry(i).await.unwrap();
            assert!(entry.is_some());
            assert_eq!(entry.unwrap().certificate, certificate);
        }
    }

    #[tokio::test]
    async fn test_sct_replacement_behavior() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_id = create_test_log_id();
        let certificate = vec![0x01, 0x02, 0x03, 0x04];
        let cert_hash = DeduplicatedLogEntry::hash_certificate(&certificate);

        // Add first entry with SCT
        let timestamp1 = Utc.timestamp_millis_opt(1234567890000).unwrap();
        let entry1 = LogEntry::new_with_timestamp(0, certificate.clone(), None, timestamp1);
        let sct1 = create_test_sct(log_id.clone(), timestamp1.timestamp_millis() as u64);
        let sct1_timestamp = sct1.timestamp;

        let (index1, _sct1) = storage
            .add_entry_batched(entry1, cert_hash, move |_| sct1)
            .await
            .unwrap();

        // Check first SCT
        let sct_entry1 = storage
            .get_sct_by_cert_hash(&cert_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sct_entry1.index, index1);
        assert_eq!(sct_entry1.timestamp, sct1_timestamp);

        // Add second entry with same certificate but different SCT
        let timestamp2 = Utc.timestamp_millis_opt(1234567891000).unwrap();
        let entry2 = LogEntry::new_with_timestamp(1, certificate.clone(), None, timestamp2);
        let sct2 = SignedCertificateTimestamp {
            version: SctVersion::V1,
            log_id: log_id.clone(),
            timestamp: timestamp2.timestamp_millis() as u64,
            extensions: vec![0xff],            // Different extensions
            signature: vec![0xdd, 0xee, 0xff], // Different signature
        };
        let sct2_timestamp = sct2.timestamp;

        let (index2, _sct2) = storage
            .add_entry_batched(entry2, cert_hash, move |_| sct2)
            .await
            .unwrap();

        // Check SCT - it should be replaced with the latest one
        let sct_entry2 = storage
            .get_sct_by_cert_hash(&cert_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sct_entry2.index, index2);
        assert_eq!(sct_entry2.timestamp, sct2_timestamp);

        // Both log entries should exist
        let retrieved1 = storage.get_entry(index1).await.unwrap().unwrap();
        let retrieved2 = storage.get_entry(index2).await.unwrap().unwrap();
        assert_eq!(retrieved1.certificate, certificate);
        assert_eq!(retrieved2.certificate, certificate);
    }

    #[tokio::test]
    async fn test_chain_reconstruction_failures() {
        let config = BatchConfig {
            max_batch_size: 1,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        // Create an entry with a chain
        let timestamp = Utc.timestamp_millis_opt(1234567890000).unwrap();
        let certificate = vec![0x01, 0x02, 0x03, 0x04];
        let chain = Some(vec![vec![0x05, 0x06], vec![0x07, 0x08], vec![0x09, 0x0a]]);
        let entry = LogEntry::new_with_timestamp(0, certificate.clone(), chain.clone(), timestamp);

        let cert_hash = DeduplicatedLogEntry::hash_certificate(&certificate);
        let log_id = create_test_log_id();
        let sct = create_test_sct(log_id, timestamp.timestamp_millis() as u64);

        // Add entry
        let (index, _sct) = storage
            .add_entry_batched(entry, cert_hash, move |_| sct)
            .await
            .unwrap();

        // Get the deduplicated entry
        let dedup_entry = storage
            .get_deduplicated_entry(index)
            .await
            .unwrap()
            .unwrap();

        // Manually create a corrupted deduplicated entry with missing chain certificates
        let corrupted_dedup = DeduplicatedLogEntry {
            index: dedup_entry.index,
            timestamp: dedup_entry.timestamp,
            entry_type: dedup_entry.entry_type,
            certificate_hash: dedup_entry.certificate_hash,
            chain_hashes: Some(vec![
                dedup_entry.chain_hashes.as_ref().unwrap()[0], // First cert exists
                [0xff; 32],                                    // Second cert missing
                dedup_entry.chain_hashes.as_ref().unwrap()[2], // Third cert exists
            ]),
            issuer_key_hash: None,
            original_precert_hash: None,
            leaf_data: dedup_entry.leaf_data.clone(),
        };

        // Try to reconstruct - should fail
        let result = storage.reconstruct_log_entry(&corrupted_dedup).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::InvalidFormat(msg) => {
                assert!(msg.contains("Chain certificate not found"))
            }
            _ => panic!("Wrong error type"),
        }

        // Test with partially missing chain (only some certificates exist)
        let partial_dedup = DeduplicatedLogEntry {
            index: dedup_entry.index,
            timestamp: dedup_entry.timestamp,
            entry_type: dedup_entry.entry_type,
            certificate_hash: dedup_entry.certificate_hash,
            chain_hashes: Some(vec![
                dedup_entry.chain_hashes.as_ref().unwrap()[0], // Only first cert
            ]),
            issuer_key_hash: None,
            original_precert_hash: None,
            leaf_data: dedup_entry.leaf_data,
        };

        // This should succeed but with shorter chain
        let partial_result = storage.reconstruct_log_entry(&partial_dedup).await.unwrap();
        assert_eq!(partial_result.chain.as_ref().unwrap().len(), 1);
        assert_eq!(partial_result.chain.as_ref().unwrap()[0], vec![0x05, 0x06]);
    }

    #[tokio::test]
    async fn test_deduplication_with_chain_and_precert() {
        let config = BatchConfig {
            max_batch_size: 2,
            max_batch_timeout_ms: 100,
        };
        let (storage, _tree) = create_test_storage(config).await;

        let log_id = create_test_log_id();

        let issuer_cert = crate::test_utils::utils::create_test_certificate();

        let precert1 = crate::test_utils::utils::create_precertificate_with_poison();
        let precert2 = crate::test_utils::utils::create_precertificate_with_poison_and_serial(3); // Different precert

        let full_chain = vec![precert1.clone(), issuer_cert.clone()];
        let issuer_key_hash1 = crate::test_utils::utils::extract_test_issuer_key_hash(&full_chain);
        let tbs1 =
            TbsExtractor::extract_tbs_certificate(&precert1, &[issuer_cert.clone()]).unwrap();

        let full_chain2 = vec![precert2.clone(), issuer_cert.clone()];
        let issuer_key_hash2 = crate::test_utils::utils::extract_test_issuer_key_hash(&full_chain2);
        let tbs2 =
            TbsExtractor::extract_tbs_certificate(&precert2, &[issuer_cert.clone()]).unwrap();

        let timestamp1 = Utc.timestamp_millis_opt(1234567890000).unwrap();
        let entry1 = LogEntry::new_precert_with_timestamp(
            0,
            tbs1.clone(),
            Some(vec![issuer_cert.clone()]),
            issuer_key_hash1.clone(),
            precert1.clone(),
            timestamp1,
        );

        let timestamp2 = Utc.timestamp_millis_opt(1234567891000).unwrap();
        let entry2 = LogEntry::new_precert_with_timestamp(
            1,
            tbs2.clone(),
            Some(vec![issuer_cert.clone()]), // Same issuer
            issuer_key_hash2.clone(),
            precert2.clone(),
            timestamp2,
        );

        // Calculate cert hashes for deduplication
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&tbs1);
        hasher.update(&issuer_key_hash1);
        let cert_hash1: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(&tbs2);
        hasher.update(&issuer_key_hash2);
        let cert_hash2: [u8; 32] = hasher.finalize().into();

        let sct1 = create_test_sct(log_id.clone(), timestamp1.timestamp_millis() as u64);
        let sct2 = create_test_sct(log_id.clone(), timestamp2.timestamp_millis() as u64);

        let (index1, _sct1) = storage
            .add_entry_batched(entry1, cert_hash1, move |_| sct1)
            .await
            .unwrap();
        let (index2, _sct2) = storage
            .add_entry_batched(entry2, cert_hash2, move |_| sct2)
            .await
            .unwrap();

        // Check that the shared issuer certificate is deduplicated
        let issuer_hash = DeduplicatedLogEntry::hash_certificate(&issuer_cert);
        assert!(storage
            .get_certificate(&issuer_hash)
            .await
            .unwrap()
            .is_some());

        // Both entries should reconstruct correctly
        let retrieved1 = storage.get_entry(index1).await.unwrap().unwrap();
        let retrieved2 = storage.get_entry(index2).await.unwrap().unwrap();

        assert_eq!(retrieved1.chain.as_ref().unwrap().len(), 1);
        assert_eq!(retrieved2.chain.as_ref().unwrap().len(), 1);
        assert_eq!(retrieved1.original_precert, Some(precert1));
        assert_eq!(retrieved2.original_precert, Some(precert2));
    }
}
