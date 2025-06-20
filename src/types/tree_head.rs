use crate::types::signed_note::{CheckpointBuilder, SignedNote};
use crate::types::{CtError, Result};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use serde::{Deserialize, Serialize};

/// Signed Tree Head (STH) as defined in RFC 6962
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Tree size (number of leaves)
    pub tree_size: u64,

    /// Timestamp in milliseconds since epoch
    pub timestamp: u64,

    /// Root hash of the Merkle tree
    pub root_hash: Vec<u8>,

    /// Digital signature over the tree head
    pub signature: Vec<u8>,
}

impl SignedTreeHead {
    /// Create a new STH (without signature)
    pub fn new(tree_size: u64, timestamp: u64, root_hash: Vec<u8>) -> Self {
        Self {
            tree_size,
            timestamp,
            root_hash,
            signature: Vec::new(),
        }
    }

    /// Get the data that needs to be signed for this STH
    pub fn get_signature_input(&self) -> Vec<u8> {
        let mut input = Vec::new();

        // Version: v1 (0)
        input.push(0);

        // SignatureType: tree_hash (1)
        input.push(1);

        // Timestamp (8 bytes)
        input.extend_from_slice(&self.timestamp.to_be_bytes());

        // Tree size (8 bytes)
        input.extend_from_slice(&self.tree_size.to_be_bytes());

        // Root hash (32 bytes for SHA-256)
        input.extend_from_slice(&self.root_hash);

        input
    }

    /// Convert to the format expected by CT API responses
    pub fn to_api_response(&self) -> SthResponse {
        SthResponse {
            tree_size: self.tree_size,
            timestamp: self.timestamp,
            sha256_root_hash: {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                STANDARD.encode(&self.root_hash)
            },
            tree_head_signature: {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                // Create the DigitallySigned structure
                let mut digitally_signed = Vec::new();
                // Hash algorithm: SHA256 (4)
                digitally_signed.push(4);
                // Signature algorithm: ECDSA (3)
                digitally_signed.push(3);
                // Signature length (2 bytes)
                let sig_len = self.signature.len() as u16;
                digitally_signed.extend_from_slice(&sig_len.to_be_bytes());
                // The actual signature
                digitally_signed.extend_from_slice(&self.signature);
                STANDARD.encode(&digitally_signed)
            },
        }
    }
}

/// STH response format for the CT API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SthResponse {
    pub tree_size: u64,
    pub timestamp: u64,
    pub sha256_root_hash: String,
    pub tree_head_signature: String,
}

pub struct SthBuilder {
    signing_key: SigningKey,
    origin: String,
    log_id: Vec<u8>,
}

impl SthBuilder {
    pub fn new(private_key_bytes: &[u8], origin: String, log_id: Vec<u8>) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key_bytes)
            .map_err(|_| CtError::InvalidCertificate("Invalid private key".into()))?;
        Ok(Self {
            signing_key,
            origin,
            log_id,
        })
    }

    pub fn create_sth(
        &self,
        tree_size: u64,
        root_hash: Vec<u8>,
        checkpoint_timestamp: Option<u64>,
    ) -> Result<SignedTreeHead> {
        let timestamp =
            checkpoint_timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis() as u64);
        let mut sth = SignedTreeHead::new(tree_size, timestamp, root_hash);

        let signature_input = sth.get_signature_input();

        let signature: DerSignature = self.signing_key.sign(&signature_input);
        sth.signature = signature.to_bytes().to_vec();

        Ok(sth)
    }

    /// Create a signed checkpoint following the C2SP specification
    pub fn create_checkpoint(
        &self,
        tree_size: u64,
        root_hash: Vec<u8>,
        checkpoint_timestamp: Option<u64>,
    ) -> Result<SignedNote> {
        let timestamp =
            checkpoint_timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis() as u64);

        let checkpoint_builder = CheckpointBuilder::new(
            self.signing_key.clone(),
            self.origin.clone(),
            self.log_id.clone(),
        );

        checkpoint_builder.create_checkpoint(tree_size, &root_hash, timestamp)
    }
}

/// Checkpoint format for CT logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Log identifier
    pub log_id: String,

    /// Tree size
    pub tree_size: u64,

    /// Root hash (hex-encoded)
    pub root_hash: String,

    /// Timestamp
    pub timestamp: u64,

    pub consistency_proof: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    fn create_test_root_hash() -> Vec<u8> {
        use sha2::{Digest, Sha256};

        // Create a deterministic root hash by hashing a known string
        let mut hasher = Sha256::new();
        hasher.update(b"test merkle tree root");
        hasher.finalize().to_vec()
    }

    fn create_test_key_pair() -> (SigningKey, VerifyingKey) {
        let private_key = SigningKey::random(&mut rand::thread_rng());
        let public_key = *private_key.verifying_key();
        (private_key, public_key)
    }

    #[test]
    fn test_signed_tree_head_new() {
        let tree_size = 1000u64;
        let timestamp = 1234567890000u64;
        let root_hash = create_test_root_hash();

        let sth = SignedTreeHead::new(tree_size, timestamp, root_hash.clone());

        assert_eq!(sth.tree_size, tree_size);
        assert_eq!(sth.timestamp, timestamp);
        assert_eq!(sth.root_hash, root_hash);
        assert!(sth.signature.is_empty());
    }

    #[test]
    fn test_get_signature_input() {
        let tree_size = 1000u64;
        let timestamp = 1234567890000u64;
        let root_hash = create_test_root_hash();

        let sth = SignedTreeHead::new(tree_size, timestamp, root_hash.clone());
        let input = sth.get_signature_input();

        // Check structure
        assert_eq!(input[0], 0); // Version: v1
        assert_eq!(input[1], 1); // SignatureType: tree_hash

        // Timestamp (8 bytes)
        let ts_bytes = &input[2..10];
        let ts_value = u64::from_be_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(ts_value, timestamp);

        // Tree size (8 bytes)
        let size_bytes = &input[10..18];
        let size_value = u64::from_be_bytes(size_bytes.try_into().unwrap());
        assert_eq!(size_value, tree_size);

        // Root hash (32 bytes)
        assert_eq!(&input[18..50], &root_hash[..]);

        // Total length should be 1 + 1 + 8 + 8 + 32 = 50
        assert_eq!(input.len(), 50);
    }

    #[test]
    fn test_to_api_response() {
        let tree_size = 1000u64;
        let timestamp = 1234567890000u64;
        let root_hash = create_test_root_hash();
        let signature = vec![0xaa, 0xbb, 0xcc, 0xdd];

        let mut sth = SignedTreeHead::new(tree_size, timestamp, root_hash.clone());
        sth.signature = signature.clone();

        let response = sth.to_api_response();

        assert_eq!(response.tree_size, tree_size);
        assert_eq!(response.timestamp, timestamp);

        // Verify root hash encoding
        assert_eq!(response.sha256_root_hash, STANDARD.encode(&root_hash));

        // Verify signature encoding
        let decoded_sig = STANDARD.decode(&response.tree_head_signature).unwrap();
        assert_eq!(decoded_sig[0], 4); // SHA-256
        assert_eq!(decoded_sig[1], 3); // ECDSA

        let sig_len = u16::from_be_bytes([decoded_sig[2], decoded_sig[3]]);
        assert_eq!(sig_len as usize, signature.len());
        assert_eq!(&decoded_sig[4..], &signature[..]);
    }

    #[test]
    fn test_sth_builder_new() {
        let (signing_key, _) = create_test_key_pair();
        let private_key_bytes = signing_key.to_bytes();
        let origin = "example.com/test-log".to_string();
        let log_id = vec![0u8; 32];

        let builder = SthBuilder::new(&private_key_bytes, origin.clone(), log_id.clone());
        assert!(builder.is_ok());

        // Test with invalid key bytes
        let invalid_key = vec![0x00; 16]; // Too short
        let builder_err = SthBuilder::new(&invalid_key, origin, log_id);
        assert!(builder_err.is_err());
    }

    #[test]
    fn test_create_sth_with_timestamp() {
        let (signing_key, verifying_key) = create_test_key_pair();
        let private_key_bytes = signing_key.to_bytes();
        let origin = "example.com/test-log".to_string();
        let log_id = vec![0u8; 32];

        let builder = SthBuilder::new(&private_key_bytes, origin, log_id).unwrap();

        let tree_size = 1000u64;
        let root_hash = create_test_root_hash();
        let timestamp = 1234567890000u64;

        let sth = builder
            .create_sth(tree_size, root_hash.clone(), Some(timestamp))
            .unwrap();

        // Verify STH fields
        assert_eq!(sth.tree_size, tree_size);
        assert_eq!(sth.timestamp, timestamp);
        assert_eq!(sth.root_hash, root_hash);
        assert!(!sth.signature.is_empty());

        // Verify the signature
        let signature_input = sth.get_signature_input();
        let signature = DerSignature::from_bytes(&sth.signature).unwrap();

        assert!(verifying_key.verify(&signature_input, &signature).is_ok());
    }

    #[test]
    fn test_create_sth_without_timestamp() {
        let (signing_key, verifying_key) = create_test_key_pair();
        let private_key_bytes = signing_key.to_bytes();
        let origin = "example.com/test-log".to_string();
        let log_id = vec![0u8; 32];

        let builder = SthBuilder::new(&private_key_bytes, origin, log_id).unwrap();

        let tree_size = 1000u64;
        let root_hash = create_test_root_hash();

        let before = chrono::Utc::now().timestamp_millis() as u64;
        let sth = builder
            .create_sth(tree_size, root_hash.clone(), None)
            .unwrap();
        let after = chrono::Utc::now().timestamp_millis() as u64;

        // Verify timestamp is auto-generated within reasonable bounds
        assert!(sth.timestamp >= before);
        assert!(sth.timestamp <= after);

        // Verify the signature
        let signature_input = sth.get_signature_input();
        let signature = DerSignature::from_bytes(&sth.signature).unwrap();

        assert!(verifying_key.verify(&signature_input, &signature).is_ok());
    }

    #[test]
    fn test_sth_signature_is_der_format() {
        let (signing_key, _) = create_test_key_pair();
        let private_key_bytes = signing_key.to_bytes();
        let origin = "example.com/test-log".to_string();
        let log_id = vec![0u8; 32];

        let builder = SthBuilder::new(&private_key_bytes, origin, log_id).unwrap();

        let tree_size = 100u64;
        let root_hash = create_test_root_hash();
        let timestamp = 1234567890000u64;

        let sth = builder
            .create_sth(tree_size, root_hash, Some(timestamp))
            .unwrap();

        // DER signatures should start with 0x30 (SEQUENCE tag)
        assert_eq!(
            sth.signature[0], 0x30,
            "Signature should start with DER SEQUENCE tag"
        );

        // DER format is typically 70-72 bytes for P-256, raw format is exactly 64 bytes
        assert!(
            sth.signature.len() > 64,
            "DER signature should be longer than raw format"
        );
        assert!(
            sth.signature.len() <= 72,
            "DER signature shouldn't be too long"
        );
    }

    #[test]
    fn test_sth_serialization() {
        let tree_size = 1000u64;
        let timestamp = 1234567890000u64;
        let root_hash = create_test_root_hash();
        let signature = vec![0xaa, 0xbb, 0xcc];

        let sth = SignedTreeHead {
            tree_size,
            timestamp,
            root_hash: root_hash.clone(),
            signature: signature.clone(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&sth).unwrap();
        let deserialized: SignedTreeHead = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tree_size, sth.tree_size);
        assert_eq!(deserialized.timestamp, sth.timestamp);
        assert_eq!(deserialized.root_hash, sth.root_hash);
        assert_eq!(deserialized.signature, sth.signature);
    }

    #[test]
    fn test_sth_response_serialization() {
        let response = SthResponse {
            tree_size: 1000,
            timestamp: 1234567890000,
            sha256_root_hash: "AQIDBAU=".to_string(),
            tree_head_signature: "BAMAAw==".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: SthResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tree_size, response.tree_size);
        assert_eq!(deserialized.timestamp, response.timestamp);
        assert_eq!(deserialized.sha256_root_hash, response.sha256_root_hash);
        assert_eq!(
            deserialized.tree_head_signature,
            response.tree_head_signature
        );
    }

    #[test]
    fn test_checkpoint_serialization() {
        let checkpoint = Checkpoint {
            log_id: "test-log".to_string(),
            tree_size: 1000,
            root_hash: "0123456789abcdef".to_string(),
            timestamp: 1234567890000,
            consistency_proof: Some(vec!["proof1".to_string(), "proof2".to_string()]),
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.log_id, checkpoint.log_id);
        assert_eq!(deserialized.tree_size, checkpoint.tree_size);
        assert_eq!(deserialized.root_hash, checkpoint.root_hash);
        assert_eq!(deserialized.timestamp, checkpoint.timestamp);
        assert_eq!(deserialized.consistency_proof, checkpoint.consistency_proof);
    }

    #[test]
    fn test_checkpoint_without_consistency_proof() {
        let checkpoint = Checkpoint {
            log_id: "test-log".to_string(),
            tree_size: 1000,
            root_hash: "0123456789abcdef".to_string(),
            timestamp: 1234567890000,
            consistency_proof: None,
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        assert!(json.contains("\"consistency_proof\":null"));

        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();
        assert!(deserialized.consistency_proof.is_none());
    }

    #[test]
    fn test_empty_root_hash() {
        let tree_size = 0u64;
        let timestamp = 1234567890000u64;
        let root_hash = vec![]; // Empty tree might have empty hash

        let sth = SignedTreeHead::new(tree_size, timestamp, root_hash.clone());
        let input = sth.get_signature_input();

        // Should still generate valid signature input
        assert_eq!(input.len(), 18); // 1 + 1 + 8 + 8 + 0
        assert_eq!(input[0], 0); // Version: v1
        assert_eq!(input[1], 1); // SignatureType: tree_hash
    }

    #[test]
    fn test_large_tree_size() {
        let tree_size = u64::MAX;
        let timestamp = 1234567890000u64;
        let root_hash = create_test_root_hash();

        let sth = SignedTreeHead::new(tree_size, timestamp, root_hash);
        let input = sth.get_signature_input();

        // Verify large tree size is properly encoded
        // After version (1 byte), signature type (1 byte), and timestamp (8 bytes)
        let size_bytes = &input[10..18];
        let size_value = u64::from_be_bytes(size_bytes.try_into().unwrap());
        assert_eq!(size_value, u64::MAX);
    }
}
