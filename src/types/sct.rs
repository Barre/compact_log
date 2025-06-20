use crate::types::sct_extensions::CtExtensions;
use crate::types::{CtError, LogEntryType, LogId, Result};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use serde::{Deserialize, Serialize};

/// Version of the SCT structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SctVersion {
    V1 = 0,
}

/// Signed Certificate Timestamp (SCT) as defined in RFC 6962
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificateTimestamp {
    /// SCT version
    pub version: SctVersion,

    /// Log ID (32-byte SHA-256 hash of the log's public key)
    pub log_id: LogId,

    /// Timestamp in milliseconds since epoch
    pub timestamp: u64,

    /// Extensions (currently unused, but included for future compatibility)
    pub extensions: Vec<u8>,

    /// Digital signature over the SCT data
    pub signature: Vec<u8>,
}

impl SignedCertificateTimestamp {
    /// Create a new SCT (without signature - must be signed separately)
    pub fn new(log_id: LogId, timestamp: u64) -> Self {
        Self {
            version: SctVersion::V1,
            log_id,
            timestamp,
            extensions: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Get the data that needs to be signed for this SCT
    pub fn get_signature_input(
        &self,
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut input = Vec::new();

        // Version (1 byte)
        input.push(self.version as u8);

        // SignatureType: certificate_timestamp (0)
        input.push(0);

        // Timestamp (8 bytes)
        input.extend_from_slice(&self.timestamp.to_be_bytes());

        // LogEntryType
        match entry_type {
            LogEntryType::X509Entry => {
                input.extend_from_slice(&[0, 0]);

                // Certificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                input.push((cert_len >> 16) as u8);
                input.push((cert_len >> 8) as u8);
                input.push(cert_len as u8);

                // Certificate data
                input.extend_from_slice(certificate);
            }
            LogEntryType::PrecertEntry => {
                input.extend_from_slice(&[0, 1]);

                // Issuer key hash (32 bytes) - required for pre-certificates
                if let Some(key_hash) = issuer_key_hash {
                    input.extend_from_slice(key_hash);
                } else {
                    // This should not happen for precerts
                    input.extend_from_slice(&[0u8; 32]);
                }

                // TBSCertificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                input.push((cert_len >> 16) as u8);
                input.push((cert_len >> 8) as u8);
                input.push(cert_len as u8);

                // TBSCertificate data
                input.extend_from_slice(certificate);
            }
        }

        // Extensions length (2 bytes)
        let ext_len = self.extensions.len() as u16;
        input.extend_from_slice(&ext_len.to_be_bytes());

        // Extensions data
        input.extend_from_slice(&self.extensions);

        input
    }
}

impl LogId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Builder for creating SCTs with proper signatures
pub struct SctBuilder {
    log_id: LogId,
    signing_key: SigningKey,
}

impl SctBuilder {
    pub fn from_private_key_bytes(log_id: LogId, private_key_bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key_bytes)
            .map_err(|_| CtError::InvalidCertificate("Invalid private key".into()))?;
        Ok(Self {
            log_id,
            signing_key,
        })
    }

    /// Create and sign an SCT for a certificate with a specific timestamp
    #[cfg(test)]
    pub fn create_sct_with_timestamp(
        &self,
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: u64,
    ) -> Result<SignedCertificateTimestamp> {
        self.create_sct_with_timestamp_and_index(
            certificate,
            entry_type,
            issuer_key_hash,
            timestamp,
            None,
        )
    }

    /// Create and sign an SCT for a certificate with a specific timestamp and optional index
    pub fn create_sct_with_timestamp_and_index(
        &self,
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: u64,
        index: Option<u64>,
    ) -> Result<SignedCertificateTimestamp> {
        let mut sct = SignedCertificateTimestamp::new(self.log_id.clone(), timestamp);

        // Add leaf_index extension if provided
        if let Some(idx) = index {
            sct.extensions = CtExtensions::with_leaf_index(idx).map_err(|e| {
                CtError::Internal(format!("Failed to create leaf_index extension: {}", e))
            })?;
        }

        let signature_input = sct.get_signature_input(certificate, entry_type, issuer_key_hash);

        let signature: DerSignature = self.signing_key.sign(&signature_input);

        let mut tls_signature = Vec::new();

        // SignatureAndHashAlgorithm: hash(1 byte) + signature(1 byte)
        // SHA-256 = 4, ECDSA = 3 (from RFC 5246)
        tls_signature.push(4); // SHA-256
        tls_signature.push(3); // ECDSA

        // Signature length (2 bytes) + signature data
        let sig_bytes = signature.to_bytes();
        let sig_len = sig_bytes.len() as u16;
        tls_signature.extend_from_slice(&sig_len.to_be_bytes());
        tls_signature.extend_from_slice(&sig_bytes);

        sct.signature = tls_signature;

        Ok(sct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    fn create_test_log_id() -> LogId {
        use x509_cert::spki::EncodePublicKey;

        // Generate a deterministic test key using a fixed seed (different from the one in mod.rs)
        let seed = [123u8; 32];
        let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Export as SubjectPublicKeyInfo DER and create LogId
        let spki_der = verifying_key.to_public_key_der().unwrap();
        LogId::new(spki_der.as_bytes())
    }

    fn create_test_key_pair() -> (SigningKey, VerifyingKey) {
        // Generate a test key pair
        let private_key = SigningKey::random(&mut rand::thread_rng());
        let public_key = *private_key.verifying_key();
        (private_key, public_key)
    }

    #[test]
    fn test_sct_version() {
        assert_eq!(SctVersion::V1 as u8, 0);
    }

    #[test]
    fn test_sct_new() {
        let log_id = create_test_log_id();
        let timestamp = 1234567890000u64;

        let sct = SignedCertificateTimestamp::new(log_id.clone(), timestamp);

        assert_eq!(sct.version, SctVersion::V1);
        assert_eq!(sct.log_id, log_id);
        assert_eq!(sct.timestamp, timestamp);
        assert!(sct.extensions.is_empty());
        assert!(sct.signature.is_empty());
    }

    #[test]
    fn test_get_signature_input_x509() {
        let log_id = create_test_log_id();
        let timestamp = 1234567890000u64;
        let certificate = vec![0x01, 0x02, 0x03, 0x04];

        let sct = SignedCertificateTimestamp::new(log_id, timestamp);
        let input = sct.get_signature_input(&certificate, LogEntryType::X509Entry, None);

        // Check structure
        assert_eq!(input[0], 0); // Version: v1
        assert_eq!(input[1], 0); // SignatureType: certificate_timestamp

        // Timestamp (8 bytes)
        let ts_bytes = &input[2..10];
        let ts_value = u64::from_be_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(ts_value, timestamp);

        // LogEntryType (2 bytes)
        assert_eq!(&input[10..12], &[0, 0]); // X509Entry

        // Certificate length (3 bytes)
        assert_eq!(&input[12..15], &[0, 0, 4]);

        // Certificate data
        assert_eq!(&input[15..19], &certificate);

        // Extensions length (2 bytes)
        assert_eq!(&input[19..21], &[0, 0]);
    }

    #[test]
    fn test_get_signature_input_precert() {
        let log_id = create_test_log_id();
        let timestamp = 1234567890000u64;
        let certificate = vec![0x01, 0x02, 0x03, 0x04];
        let issuer_key_hash = vec![0xaa; 32];

        let sct = SignedCertificateTimestamp::new(log_id, timestamp);
        let input = sct.get_signature_input(
            &certificate,
            LogEntryType::PrecertEntry,
            Some(&issuer_key_hash),
        );

        // Check structure
        assert_eq!(input[0], 0); // Version: v1
        assert_eq!(input[1], 0); // SignatureType: certificate_timestamp

        // Timestamp (8 bytes)
        let ts_bytes = &input[2..10];
        let ts_value = u64::from_be_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(ts_value, timestamp);

        // LogEntryType (2 bytes)
        assert_eq!(&input[10..12], &[0, 1]); // PrecertEntry

        // Issuer key hash (32 bytes)
        assert_eq!(&input[12..44], &issuer_key_hash);

        // TBSCertificate length (3 bytes)
        assert_eq!(&input[44..47], &[0, 0, 4]);

        // TBSCertificate data
        assert_eq!(&input[47..51], &certificate);

        // Extensions length (2 bytes)
        assert_eq!(&input[51..53], &[0, 0]);
    }

    #[test]
    fn test_get_signature_input_with_extensions() {
        let log_id = create_test_log_id();
        let timestamp = 1234567890000u64;
        let certificate = vec![0x01, 0x02, 0x03, 0x04];
        let extensions = vec![0xff, 0xfe, 0xfd];

        let mut sct = SignedCertificateTimestamp::new(log_id, timestamp);
        sct.extensions = extensions.clone();

        let input = sct.get_signature_input(&certificate, LogEntryType::X509Entry, None);

        // Check extensions at the end
        let ext_len_offset = 19;
        let ext_len_bytes = &input[ext_len_offset..ext_len_offset + 2];
        let ext_len = u16::from_be_bytes(ext_len_bytes.try_into().unwrap());
        assert_eq!(ext_len, 3);

        let ext_data = &input[ext_len_offset + 2..ext_len_offset + 2 + 3];
        assert_eq!(ext_data, &extensions);
    }

    #[test]
    fn test_log_id_to_hex() {
        let log_id = create_test_log_id();
        let hex_string = log_id.to_hex();

        // Should be 64 characters (32 bytes * 2)
        assert_eq!(hex_string.len(), 64);

        // Should be valid hex
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sct_builder_from_private_key_bytes() {
        let (signing_key, _) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder = SctBuilder::from_private_key_bytes(log_id.clone(), &private_key_bytes);
        assert!(builder.is_ok());

        // Test with invalid key bytes
        let invalid_key = vec![0x00; 16]; // Too short
        let builder_err = SctBuilder::from_private_key_bytes(log_id, &invalid_key);
        assert!(builder_err.is_err());
    }

    #[test]
    fn test_create_sct_with_timestamp() {
        let (signing_key, verifying_key) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder =
            SctBuilder::from_private_key_bytes(log_id.clone(), &private_key_bytes).unwrap();

        let certificate = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let timestamp = 1234567890000u64;

        let sct = builder
            .create_sct_with_timestamp(&certificate, LogEntryType::X509Entry, None, timestamp)
            .unwrap();

        // Verify SCT fields
        assert_eq!(sct.version, SctVersion::V1);
        assert_eq!(sct.log_id, log_id);
        assert_eq!(sct.timestamp, timestamp);
        assert!(sct.extensions.is_empty());
        assert!(!sct.signature.is_empty());

        // Verify signature format
        assert_eq!(sct.signature[0], 4); // SHA-256
        assert_eq!(sct.signature[1], 3); // ECDSA

        // Extract signature length
        let sig_len = u16::from_be_bytes([sct.signature[2], sct.signature[3]]);
        assert_eq!(sig_len as usize, sct.signature.len() - 4);

        // Verify the signature
        let signature_input = sct.get_signature_input(&certificate, LogEntryType::X509Entry, None);
        let sig_bytes = &sct.signature[4..];
        let signature = DerSignature::from_bytes(sig_bytes).unwrap();

        assert!(verifying_key.verify(&signature_input, &signature).is_ok());
    }

    #[test]
    fn test_create_sct_precert() {
        let (signing_key, verifying_key) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder =
            SctBuilder::from_private_key_bytes(log_id.clone(), &private_key_bytes).unwrap();

        let certificate = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let issuer_key_hash = vec![0xbb; 32];
        let timestamp = 1234567890000u64;

        let sct = builder
            .create_sct_with_timestamp(
                &certificate,
                LogEntryType::PrecertEntry,
                Some(&issuer_key_hash),
                timestamp,
            )
            .unwrap();

        // Verify the signature
        let signature_input = sct.get_signature_input(
            &certificate,
            LogEntryType::PrecertEntry,
            Some(&issuer_key_hash),
        );
        let sig_bytes = &sct.signature[4..];
        let signature = DerSignature::from_bytes(sig_bytes).unwrap();

        assert!(verifying_key.verify(&signature_input, &signature).is_ok());
    }

    #[test]
    fn test_sct_serialization() {
        let log_id = create_test_log_id();
        let timestamp = 1234567890000u64;

        let sct = SignedCertificateTimestamp {
            version: SctVersion::V1,
            log_id: log_id.clone(),
            timestamp,
            extensions: vec![0x01, 0x02],
            signature: vec![0x03, 0x04, 0x05],
        };

        // Test JSON serialization
        let json = serde_json::to_string(&sct).unwrap();
        let deserialized: SignedCertificateTimestamp = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, sct.version);
        assert_eq!(deserialized.log_id, sct.log_id);
        assert_eq!(deserialized.timestamp, sct.timestamp);
        assert_eq!(deserialized.extensions, sct.extensions);
        assert_eq!(deserialized.signature, sct.signature);
    }

    #[test]
    fn test_precert_without_issuer_key_hash() {
        let log_id = create_test_log_id();
        let timestamp = 1234567890000u64;
        let certificate = vec![0x01, 0x02, 0x03, 0x04];

        let sct = SignedCertificateTimestamp::new(log_id, timestamp);
        let input = sct.get_signature_input(&certificate, LogEntryType::PrecertEntry, None);

        // Should use zeros for missing issuer key hash
        assert_eq!(&input[12..44], &[0u8; 32]);
    }

    #[test]
    fn test_sct_signature_is_der_format() {
        let (signing_key, _) = create_test_key_pair();
        let private_key_bytes = signing_key.to_bytes();
        let log_id = create_test_log_id();

        let builder = SctBuilder::from_private_key_bytes(log_id, &private_key_bytes).unwrap();

        let timestamp = 1234567890000u64;
        let certificate = vec![0x01, 0x02, 0x03, 0x04];

        let sct = builder
            .create_sct_with_timestamp(&certificate, LogEntryType::X509Entry, None, timestamp)
            .unwrap();

        // Skip the TLS header (4 bytes) to get to the actual signature
        let sig_bytes = &sct.signature[4..];

        // DER signatures should start with 0x30 (SEQUENCE tag)
        assert_eq!(
            sig_bytes[0], 0x30,
            "Signature should start with DER SEQUENCE tag"
        );

        // DER format is typically 70-72 bytes for P-256, raw format is exactly 64 bytes
        assert!(
            sig_bytes.len() > 64,
            "DER signature should be longer than raw format"
        );
        assert!(sig_bytes.len() <= 72, "DER signature shouldn't be too long");
    }

    #[test]
    fn test_create_sct_with_leaf_index_extension() {
        let (signing_key, verifying_key) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder =
            SctBuilder::from_private_key_bytes(log_id.clone(), &private_key_bytes).unwrap();

        let certificate = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let timestamp = 1234567890000u64;
        let leaf_index = 12345u64;

        let sct = builder
            .create_sct_with_timestamp_and_index(
                &certificate,
                LogEntryType::X509Entry,
                None,
                timestamp,
                Some(leaf_index),
            )
            .unwrap();

        // Verify SCT fields
        assert_eq!(sct.version, SctVersion::V1);
        assert_eq!(sct.log_id, log_id);
        assert_eq!(sct.timestamp, timestamp);

        // Verify extensions are present and have correct length
        // According to spec: 2 bytes length + 1 byte type + 2 bytes data length + 5 bytes leaf index = 10 bytes total
        assert_eq!(sct.extensions.len(), 10);

        // Verify extension structure
        assert_eq!(&sct.extensions[0..2], &[0, 8]); // Total extensions length = 8
        assert_eq!(sct.extensions[2], 0); // Extension type = leaf_index (0)
        assert_eq!(&sct.extensions[3..5], &[0, 5]); // Extension data length = 5

        // Verify leaf index encoding (big-endian 40-bit)
        let encoded_index = &sct.extensions[5..10];
        let decoded_index = ((encoded_index[0] as u64) << 32)
            | ((encoded_index[1] as u64) << 24)
            | ((encoded_index[2] as u64) << 16)
            | ((encoded_index[3] as u64) << 8)
            | (encoded_index[4] as u64);
        assert_eq!(decoded_index, leaf_index);

        // Verify the signature is valid with the extensions
        let signature_input = sct.get_signature_input(&certificate, LogEntryType::X509Entry, None);
        let sig_bytes = &sct.signature[4..];
        let signature = DerSignature::from_bytes(sig_bytes).unwrap();
        assert!(verifying_key.verify(&signature_input, &signature).is_ok());
    }

    #[test]
    fn test_create_sct_with_max_leaf_index() {
        let (signing_key, _) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder = SctBuilder::from_private_key_bytes(log_id, &private_key_bytes).unwrap();

        let certificate = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let timestamp = 1234567890000u64;
        let max_leaf_index = 0xFFFFFFFFFF_u64; // Maximum 40-bit value

        let sct = builder
            .create_sct_with_timestamp_and_index(
                &certificate,
                LogEntryType::X509Entry,
                None,
                timestamp,
                Some(max_leaf_index),
            )
            .unwrap();

        // Verify the max index is encoded correctly
        let encoded_index = &sct.extensions[5..10];
        assert_eq!(encoded_index, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_create_sct_without_index_has_empty_extensions() {
        let (signing_key, _) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder = SctBuilder::from_private_key_bytes(log_id, &private_key_bytes).unwrap();

        let certificate = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let timestamp = 1234567890000u64;

        let sct = builder
            .create_sct_with_timestamp_and_index(
                &certificate,
                LogEntryType::X509Entry,
                None,
                timestamp,
                None, // No index provided
            )
            .unwrap();

        // Extensions should be empty when no index is provided
        assert!(sct.extensions.is_empty());
    }

    #[test]
    fn test_sct_with_precert_and_leaf_index() {
        let (signing_key, verifying_key) = create_test_key_pair();
        let log_id = create_test_log_id();
        let private_key_bytes = signing_key.to_bytes();

        let builder = SctBuilder::from_private_key_bytes(log_id, &private_key_bytes).unwrap();

        let certificate = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let issuer_key_hash = vec![0xbb; 32];
        let timestamp = 1234567890000u64;
        let leaf_index = 54321u64;

        let sct = builder
            .create_sct_with_timestamp_and_index(
                &certificate,
                LogEntryType::PrecertEntry,
                Some(&issuer_key_hash),
                timestamp,
                Some(leaf_index),
            )
            .unwrap();

        // Verify the signature with extensions
        let signature_input = sct.get_signature_input(
            &certificate,
            LogEntryType::PrecertEntry,
            Some(&issuer_key_hash),
        );
        let sig_bytes = &sct.signature[4..];
        let signature = DerSignature::from_bytes(sig_bytes).unwrap();

        assert!(verifying_key.verify(&signature_input, &signature).is_ok());

        // Verify leaf index in extensions
        let encoded_index = &sct.extensions[5..10];
        let decoded_index = ((encoded_index[0] as u64) << 32)
            | ((encoded_index[1] as u64) << 24)
            | ((encoded_index[2] as u64) << 16)
            | ((encoded_index[3] as u64) << 8)
            | (encoded_index[4] as u64);
        assert_eq!(decoded_index, leaf_index);
    }
}
