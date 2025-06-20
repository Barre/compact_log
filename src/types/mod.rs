use crate::oids::*;
use chrono::{DateTime, Utc};
use der::Decode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::Certificate;

pub mod sct;
pub mod sct_extensions;
pub mod signed_note;
pub mod tiles;
pub mod tree_head;

/// Log entry type according to RFC 6962
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

#[derive(Error, Debug)]
pub enum CtError {
    #[error("Invalid certificate format: {0}")]
    InvalidCertificate(String),

    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CtError>;

/// Log ID (SHA-256 hash of the log's public key)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogId([u8; 32]);

impl LogId {
    pub fn new(public_key_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key_der);
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        Self(id)
    }

    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Certificate entry in the log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// The index of this entry in the log
    pub index: u64,

    /// Timestamp when the certificate was added
    pub timestamp: DateTime<Utc>,

    /// The entry type (X509 or Precert)
    pub entry_type: LogEntryType,

    /// The certificate data (DER-encoded)
    pub certificate: Vec<u8>,

    /// Optional certificate chain
    pub chain: Option<Vec<Vec<u8>>>,

    /// For pre-certificates: the issuer key hash (32 bytes)
    pub issuer_key_hash: Option<Vec<u8>>,

    /// For pre-certificates: the original pre-certificate (before poison extension removal)
    pub original_precert: Option<Vec<u8>>,

    /// The serialized MerkleTreeLeaf data NOT the hash
    pub leaf_data: Vec<u8>,
}

/// Deduplicated certificate entry that stores certificate hashes instead of full data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicatedLogEntry {
    /// The index of this entry in the log
    pub index: u64,

    /// Timestamp when the certificate was added
    pub timestamp: DateTime<Utc>,

    /// The entry type (X509 or Precert)
    pub entry_type: LogEntryType,

    /// SHA-256 hash of the certificate data (pointer to cert store)
    pub certificate_hash: [u8; 32],

    /// Optional certificate chain as array of certificate hashes
    pub chain_hashes: Option<Vec<[u8; 32]>>,

    /// For pre-certificates: the issuer key hash (32 bytes)
    pub issuer_key_hash: Option<[u8; 32]>,

    /// For pre-certificates: hash of the original pre-certificate
    pub original_precert_hash: Option<[u8; 32]>,

    /// The serialized MerkleTreeLeaf data NOT the hash
    pub leaf_data: Vec<u8>,
}

impl DeduplicatedLogEntry {
    /// Create a new deduplicated log entry from a regular log entry
    pub fn from_log_entry(entry: &LogEntry) -> Self {
        let (certificate_hash, original_precert_hash) =
            if entry.entry_type == LogEntryType::PrecertEntry {
                let precert_hash = entry
                    .original_precert
                    .as_ref()
                    .map(|precert| {
                        let mut hasher = Sha256::new();
                        hasher.update(precert);
                        hasher.finalize().into()
                    })
                    .expect("Precert entry must have original_precert");

                (precert_hash, Some(precert_hash))
            } else {
                let mut hasher = Sha256::new();
                hasher.update(&entry.certificate);
                let cert_hash = hasher.finalize().into();

                (cert_hash, None)
            };

        // Hash the chain certificates if present
        let chain_hashes = entry.chain.as_ref().map(|chain| {
            chain
                .iter()
                .map(|cert| {
                    let mut hasher = Sha256::new();
                    hasher.update(cert);
                    hasher.finalize().into()
                })
                .collect()
        });

        // Convert issuer_key_hash from Vec<u8> to [u8; 32] if present
        let issuer_key_hash = entry.issuer_key_hash.as_ref().map(|hash| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash[..32]);
            arr
        });

        Self {
            index: entry.index,
            timestamp: entry.timestamp,
            entry_type: entry.entry_type,
            certificate_hash,
            chain_hashes,
            issuer_key_hash,
            original_precert_hash,
            leaf_data: entry.leaf_data.clone(),
        }
    }

    /// Compute SHA-256 hash of certificate data
    pub fn hash_certificate(certificate: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(certificate);
        hasher.finalize().into()
    }
}

impl LogEntry {
    pub fn new_with_timestamp(
        index: u64,
        certificate: Vec<u8>,
        chain: Option<Vec<Vec<u8>>>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let entry_type = LogEntryType::X509Entry;
        let leaf_data = Self::compute_leaf_data(&certificate, entry_type, None, timestamp);

        Self {
            index,
            timestamp,
            entry_type,
            certificate,
            chain,
            issuer_key_hash: None,
            original_precert: None,
            leaf_data,
        }
    }

    pub fn new_precert_with_timestamp(
        index: u64,
        certificate: Vec<u8>,
        chain: Option<Vec<Vec<u8>>>,
        issuer_key_hash: Vec<u8>,
        original_precert: Vec<u8>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let entry_type = LogEntryType::PrecertEntry;
        let leaf_data =
            Self::compute_leaf_data(&certificate, entry_type, Some(&issuer_key_hash), timestamp);

        Self {
            index,
            timestamp,
            entry_type,
            certificate,
            chain,
            issuer_key_hash: Some(issuer_key_hash),
            original_precert: Some(original_precert),
            leaf_data,
        }
    }

    /// Serialize MerkleTreeLeaf structure for a given entry data
    fn serialize_merkle_tree_leaf(
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: DateTime<Utc>,
        index: Option<u64>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Version (1 byte) - RFC 6962 MerkleTreeLeaf version is always 0
        data.push(0x00);

        // LeafType (1 byte) - always timestamped_entry (0)
        data.push(0x00);

        // Timestamp (8 bytes, milliseconds since epoch)
        data.extend_from_slice(&(timestamp.timestamp_millis() as u64).to_be_bytes());

        // LogEntryType (2 bytes)
        match entry_type {
            LogEntryType::X509Entry => {
                data.extend_from_slice(&[0x00, 0x00]);

                // Certificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                data.push((cert_len >> 16) as u8);
                data.push((cert_len >> 8) as u8);
                data.push(cert_len as u8);

                // Certificate data
                data.extend_from_slice(certificate);
            }
            LogEntryType::PrecertEntry => {
                data.extend_from_slice(&[0x00, 0x01]);

                // PreCert structure: issuer_key_hash[32] + TBSCertificate
                if let Some(key_hash) = issuer_key_hash {
                    // Issuer key hash (32 bytes) - directly included, no length prefix
                    data.extend_from_slice(key_hash);
                } else {
                    // This should not happen for precerts, but handle gracefully
                    data.extend_from_slice(&[0u8; 32]);
                }

                // TBSCertificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                data.push((cert_len >> 16) as u8);
                data.push((cert_len >> 8) as u8);
                data.push(cert_len as u8);

                // TBSCertificate data
                data.extend_from_slice(certificate);
            }
        }

        // Extensions
        if let Some(idx) = index {
            // Extensions length (2 bytes) - leaf_index extension
            // Extension type (1 byte) + length (2 bytes) + data (5 bytes) = 8 bytes total
            data.extend_from_slice(&[0x00, 0x08]);

            // Extension type (1 byte) - leaf_index (0)
            data.push(0x00);
            // Extension data length (2 bytes) - 5 bytes for 40-bit index
            data.extend_from_slice(&[0x00, 0x05]);
            // LeafIndex as 40-bit big-endian integer
            let index_bytes = idx.to_be_bytes();
            data.extend_from_slice(&index_bytes[3..8]); // Take last 5 bytes for 40-bit value
        } else {
            // Extensions length (2 bytes) - no extensions
            data.extend_from_slice(&[0x00, 0x00]);
        }

        data
    }

    /// Get the serialized leaf data for the Merkle tree
    /// This returns the serialized MerkleTreeLeaf that will be hashed
    pub fn compute_leaf_data(
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: DateTime<Utc>,
    ) -> Vec<u8> {
        Self::serialize_merkle_tree_leaf(certificate, entry_type, issuer_key_hash, timestamp, None)
    }

    /// Compute leaf data with a specific index (for regenerating after index assignment)
    pub fn compute_leaf_data_with_index(
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: DateTime<Utc>,
        index: u64,
    ) -> Vec<u8> {
        Self::serialize_merkle_tree_leaf(
            certificate,
            entry_type,
            issuer_key_hash,
            timestamp,
            Some(index),
        )
    }

    /// Check if a certificate is a pre-certificate by looking for the poison extension
    pub fn is_precertificate(certificate_der: &[u8]) -> Result<bool> {
        let cert = Certificate::from_der(certificate_der).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse certificate: {}", e))
        })?;

        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == CT_POISON_EXTENSION_OID {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Serialize the log entry to CT binary format
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let issuer_key_hash = match self.entry_type {
            LogEntryType::X509Entry => None,
            LogEntryType::PrecertEntry => {
                if let Some(ref key_hash) = self.issuer_key_hash {
                    Some(key_hash.as_slice())
                } else {
                    return Err(CtError::InvalidCertificate(
                        "Pre-certificate entry missing issuer key hash".to_string(),
                    ));
                }
            }
        };

        let data = Self::serialize_merkle_tree_leaf(
            &self.certificate,
            self.entry_type,
            issuer_key_hash,
            self.timestamp,
            Some(self.index),
        );

        Ok(data)
    }
}

/// Request to add a certificate to the log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddChainRequest {
    /// The certificate chain (array of base64-encoded DER certificates)
    /// The first certificate is the end-entity certificate
    pub chain: Vec<String>,
}

/// Response to adding a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddChainResponse {
    /// The SCT for this certificate
    pub sct_version: u8,
    pub id: String,
    pub timestamp: u64,
    pub extensions: String,
    pub signature: String,
}

/// Request for an inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofByHashRequest {
    pub hash: String,
    pub tree_size: u64,
}

/// Response containing an inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofByHashResponse {
    pub leaf_index: u64,
    pub audit_path: Vec<String>,
}

/// Request for a consistency proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConsistencyProofRequest {
    pub first: u64,
    pub second: u64,
}

/// Response containing a consistency proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConsistencyProofResponse {
    pub consistency: Vec<String>,
}

/// Request for log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEntriesRequest {
    pub start: u64,
    pub end: u64,
}

/// Response containing log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEntriesResponse {
    pub entries: Vec<LeafEntry>,
}

/// A leaf entry in the response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafEntry {
    pub leaf_input: String,
    pub extra_data: String,
}

/// Response for get-roots endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRootsResponse {
    pub certificates: Vec<String>,
}

/// Temporal interval for the inclusion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalInterval {
    pub start_inclusive: String,
    pub end_exclusive: String,
}

/// Inclusion request response for RFC 6962 log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionRequestResponse {
    pub key: String,
    pub log_id: String,
    pub mmd: u64,
    pub temporal_interval: TemporalInterval,
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::tbs_extractor::TbsExtractor;
    use chrono::TimeZone;
    use der::asn1::SetOfVec;
    use der::{Decode, Encode};
    use x509_cert::ext::{Extension, Extensions};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::{Certificate, TbsCertificate, Version};

    pub fn create_test_timestamp() -> DateTime<Utc> {
        Utc.timestamp_millis_opt(1234567890000).unwrap()
    }

    pub fn create_test_public_key() -> Vec<u8> {
        use p256::ecdsa::SigningKey;
        use x509_cert::spki::EncodePublicKey;

        // Generate a deterministic test key using a fixed seed
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Export as SubjectPublicKeyInfo DER
        verifying_key.to_public_key_der().unwrap().to_vec()
    }

    pub fn create_test_certificate() -> Vec<u8> {
        use der::asn1::BitString;
        use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
        use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

        // Create a simple subject/issuer name
        let cn_oid = COMMON_NAME_OID;
        let cn_value = AttributeValue::from(der::asn1::Utf8StringRef::new("Test CA").unwrap());
        let cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };
        let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![cn_attr]).unwrap());
        let name = RdnSequence::from(vec![rdn]);

        // Create a TBSCertificate without extensions (normal certificate)
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            issuer: name.clone(),
            validity: x509_cert::time::Validity {
                not_before: x509_cert::time::Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
                not_after: x509_cert::time::Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
            },
            subject: name,
            subject_public_key_info: x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
                &create_test_public_key(),
            )
            .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        // Create a complete certificate
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        cert.to_der().unwrap()
    }

    pub fn create_precertificate_with_poison() -> Vec<u8> {
        use der::asn1::{BitString, OctetString};
        use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
        use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

        // Create a simple subject/issuer name
        let cn_oid = COMMON_NAME_OID;
        let cn_value = AttributeValue::from(der::asn1::Utf8StringRef::new("Test CA").unwrap());
        let cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };
        let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![cn_attr]).unwrap());
        let name = RdnSequence::from(vec![rdn]);

        // Create the poison extension
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(), // ASN.1 NULL
        };

        // Create a TBSCertificate with poison extension
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            issuer: name.clone(),
            validity: x509_cert::time::Validity {
                not_before: x509_cert::time::Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
                not_after: x509_cert::time::Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
            },
            subject: name,
            subject_public_key_info: x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
                &create_test_public_key(),
            )
            .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(Extensions::from(vec![poison_ext])),
        };

        // Create a complete certificate
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        cert.to_der().unwrap()
    }

    #[test]
    fn test_log_entry_type_values() {
        assert_eq!(LogEntryType::X509Entry as u16, 0);
        assert_eq!(LogEntryType::PrecertEntry as u16, 1);
    }

    #[test]
    fn test_log_id_creation() {
        let public_key = create_test_public_key();
        let log_id = LogId::new(&public_key);

        // Verify it produces a consistent hash
        let log_id2 = LogId::new(&public_key);
        assert_eq!(log_id, log_id2);

        // Verify different keys produce different IDs
        let mut different_key = public_key.clone();
        different_key[10] = 0xff;
        let different_log_id = LogId::new(&different_key);
        assert_ne!(log_id, different_log_id);
    }

    #[test]
    fn test_log_entry_new_with_timestamp() {
        let cert = create_test_certificate();
        let timestamp = create_test_timestamp();
        let chain = vec![cert.clone()];

        let entry = LogEntry::new_with_timestamp(42, cert.clone(), Some(chain), timestamp);

        assert_eq!(entry.index, 42);
        assert_eq!(entry.timestamp, timestamp);
        assert_eq!(entry.entry_type, LogEntryType::X509Entry);
        assert_eq!(entry.certificate, cert);
        assert!(entry.chain.is_some());
        assert!(entry.issuer_key_hash.is_none());
        assert!(entry.original_precert.is_none());
        assert!(!entry.leaf_data.is_empty());
    }

    #[test]
    fn test_log_entry_new_precert_with_timestamp() {
        let cert = create_test_certificate();
        let timestamp = create_test_timestamp();
        let chain = vec![cert.clone()];
        let issuer_key_hash = vec![0xaa; 32];
        let original_precert = create_precertificate_with_poison();

        let entry = LogEntry::new_precert_with_timestamp(
            42,
            cert.clone(),
            Some(chain),
            issuer_key_hash.clone(),
            original_precert.clone(),
            timestamp,
        );

        assert_eq!(entry.index, 42);
        assert_eq!(entry.timestamp, timestamp);
        assert_eq!(entry.entry_type, LogEntryType::PrecertEntry);
        assert_eq!(entry.certificate, cert);
        assert!(entry.chain.is_some());
        assert_eq!(entry.issuer_key_hash, Some(issuer_key_hash));
        assert_eq!(entry.original_precert, Some(original_precert));
        assert!(!entry.leaf_data.is_empty());
    }

    #[test]
    fn test_serialize_merkle_tree_leaf_x509() {
        let cert = vec![0x01, 0x02, 0x03, 0x04];
        let timestamp = create_test_timestamp();

        let leaf_data = LogEntry::serialize_merkle_tree_leaf(
            &cert,
            LogEntryType::X509Entry,
            None,
            timestamp,
            None,
        );

        // Check structure
        assert_eq!(leaf_data[0], 0x00); // Version
        assert_eq!(leaf_data[1], 0x00); // LeafType (timestamped_entry)

        // Timestamp (8 bytes)
        let ts_bytes = &leaf_data[2..10];
        let ts_value = u64::from_be_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(ts_value, 1234567890000);

        // LogEntryType (2 bytes)
        assert_eq!(&leaf_data[10..12], &[0x00, 0x00]); // X509Entry

        // Certificate length (3 bytes)
        assert_eq!(&leaf_data[12..15], &[0x00, 0x00, 0x04]);

        // Certificate data
        assert_eq!(&leaf_data[15..19], &[0x01, 0x02, 0x03, 0x04]);

        // Extensions length (2 bytes)
        assert_eq!(&leaf_data[19..21], &[0x00, 0x00]);
    }

    #[test]
    fn test_serialize_merkle_tree_leaf_precert() {
        let cert = vec![0x01, 0x02, 0x03, 0x04];
        let timestamp = create_test_timestamp();
        let issuer_key_hash = vec![0xaa; 32];

        let leaf_data = LogEntry::serialize_merkle_tree_leaf(
            &cert,
            LogEntryType::PrecertEntry,
            Some(&issuer_key_hash),
            timestamp,
            None,
        );

        // Check structure
        assert_eq!(leaf_data[0], 0x00); // Version
        assert_eq!(leaf_data[1], 0x00); // LeafType (timestamped_entry)

        // Timestamp (8 bytes)
        let ts_bytes = &leaf_data[2..10];
        let ts_value = u64::from_be_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(ts_value, 1234567890000);

        // LogEntryType (2 bytes)
        assert_eq!(&leaf_data[10..12], &[0x00, 0x01]); // PrecertEntry

        // Issuer key hash (32 bytes)
        assert_eq!(&leaf_data[12..44], &[0xaa; 32]);

        // TBSCertificate length (3 bytes)
        assert_eq!(&leaf_data[44..47], &[0x00, 0x00, 0x04]);

        // TBSCertificate data
        assert_eq!(&leaf_data[47..51], &[0x01, 0x02, 0x03, 0x04]);

        // Extensions length (2 bytes)
        assert_eq!(&leaf_data[51..53], &[0x00, 0x00]);
    }

    #[test]
    fn test_serialize_merkle_tree_leaf_with_index() {
        let cert = vec![0x01, 0x02, 0x03, 0x04];
        let timestamp = create_test_timestamp();
        let leaf_index = 12345u64;

        let leaf_data = LogEntry::serialize_merkle_tree_leaf(
            &cert,
            LogEntryType::X509Entry,
            None,
            timestamp,
            Some(leaf_index),
        );

        // Check structure
        assert_eq!(leaf_data[0], 0x00); // Version
        assert_eq!(leaf_data[1], 0x00); // LeafType (timestamped_entry)

        // Timestamp (8 bytes)
        let ts_bytes = &leaf_data[2..10];
        let ts_value = u64::from_be_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(ts_value, 1234567890000);

        // LogEntryType (2 bytes)
        assert_eq!(&leaf_data[10..12], &[0x00, 0x00]); // X509Entry

        // Certificate length (3 bytes)
        assert_eq!(&leaf_data[12..15], &[0x00, 0x00, 0x04]);

        // Certificate data
        assert_eq!(&leaf_data[15..19], &[0x01, 0x02, 0x03, 0x04]);

        // Extensions length (2 bytes) - should be 8 for leaf_index extension
        assert_eq!(&leaf_data[19..21], &[0x00, 0x08]); // 8 bytes

        // Extension data (directly, no length prefix in MerkleTreeLeaf)
        let extensions = &leaf_data[21..29];
        // Extension type
        assert_eq!(extensions[0], 0x00); // leaf_index
                                         // Extension data length
        assert_eq!(&extensions[1..3], &[0x00, 0x05]); // 5 bytes
                                                      // Leaf index value (40-bit big-endian)
        let encoded_index = &extensions[3..8];
        let decoded_index = ((encoded_index[0] as u64) << 32)
            | ((encoded_index[1] as u64) << 24)
            | ((encoded_index[2] as u64) << 16)
            | ((encoded_index[3] as u64) << 8)
            | (encoded_index[4] as u64);
        assert_eq!(decoded_index, leaf_index);
    }

    #[test]
    fn test_is_precertificate() {
        let normal_cert = create_test_certificate();
        assert!(!LogEntry::is_precertificate(&normal_cert).unwrap());

        let precert = create_precertificate_with_poison();
        assert!(LogEntry::is_precertificate(&precert).unwrap());

        // Test with invalid certificate
        let invalid_cert = vec![0x00, 0x01, 0x02];
        assert!(LogEntry::is_precertificate(&invalid_cert).is_err());
    }

    #[test]
    fn test_deduplicated_log_entry_from_log_entry() {
        let cert = create_test_certificate();
        let timestamp = create_test_timestamp();
        let chain = vec![cert.clone(), cert.clone()];
        let issuer_key_hash = vec![0xaa; 32];
        let original_precert = create_precertificate_with_poison();

        let entry = LogEntry::new_precert_with_timestamp(
            42,
            cert,
            Some(chain),
            issuer_key_hash,
            original_precert,
            timestamp,
        );

        let dedup_entry = DeduplicatedLogEntry::from_log_entry(&entry);

        assert_eq!(dedup_entry.index, entry.index);
        assert_eq!(dedup_entry.timestamp, entry.timestamp);
        assert_eq!(dedup_entry.entry_type, entry.entry_type);
        assert!(dedup_entry.chain_hashes.is_some());
        assert_eq!(dedup_entry.chain_hashes.as_ref().unwrap().len(), 2);
        assert!(dedup_entry.issuer_key_hash.is_some());
        assert!(dedup_entry.original_precert_hash.is_some());
        assert_eq!(dedup_entry.leaf_data, entry.leaf_data);
    }

    #[test]
    fn test_hash_certificate() {
        let cert = vec![0x01, 0x02, 0x03, 0x04];
        let hash1 = DeduplicatedLogEntry::hash_certificate(&cert);
        let hash2 = DeduplicatedLogEntry::hash_certificate(&cert);

        // Should produce consistent hashes
        assert_eq!(hash1, hash2);

        // Different certificates should produce different hashes
        let cert2 = vec![0x05, 0x06, 0x07, 0x08];
        let hash3 = DeduplicatedLogEntry::hash_certificate(&cert2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_request_response_serialization() {
        // Test AddChainRequest
        let add_req = AddChainRequest {
            chain: vec!["cert1".to_string(), "cert2".to_string()],
        };
        let json = serde_json::to_string(&add_req).unwrap();
        let deserialized: AddChainRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(add_req.chain, deserialized.chain);

        // Test GetProofByHashRequest
        let proof_req = GetProofByHashRequest {
            hash: "somehash".to_string(),
            tree_size: 1000,
        };
        let json = serde_json::to_string(&proof_req).unwrap();
        let deserialized: GetProofByHashRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(proof_req.hash, deserialized.hash);
        assert_eq!(proof_req.tree_size, deserialized.tree_size);
    }

    #[test]
    fn test_remove_poison_extension_and_transform() {
        // Test with pre-certificate and empty chain (legacy behavior)
        let precert = create_precertificate_with_poison();
        let tbs_cert = TbsExtractor::extract_tbs_certificate(&precert, &[]).unwrap();

        // Verify the poison extension was removed
        let tbs = x509_cert::TbsCertificate::from_der(&tbs_cert).unwrap();
        if let Some(extensions) = &tbs.extensions {
            for ext in extensions.iter() {
                assert_ne!(ext.extn_id, CT_POISON_EXTENSION_OID);
            }
        }
    }

    #[test]
    fn test_remove_poison_extension_with_regular_issuer() {
        // Test with pre-certificate signed by regular CA (not a Precertificate Signing Certificate)
        let precert = create_precertificate_with_poison();
        let issuer_cert = create_test_certificate();
        let chain = vec![issuer_cert];

        let original_precert = Certificate::from_der(&precert).unwrap();
        let original_issuer = original_precert.tbs_certificate.issuer.clone();

        let tbs_cert = TbsExtractor::extract_tbs_certificate(&precert, &chain).unwrap();
        let tbs = x509_cert::TbsCertificate::from_der(&tbs_cert).unwrap();

        // Verify the poison extension was removed
        if let Some(extensions) = &tbs.extensions {
            for ext in extensions.iter() {
                assert_ne!(ext.extn_id, CT_POISON_EXTENSION_OID);
            }
        }

        // Verify issuer was NOT changed (since it's not a Precertificate Signing Certificate)
        assert_eq!(tbs.issuer, original_issuer);
    }
}
