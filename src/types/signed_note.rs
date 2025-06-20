use crate::types::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use sha2::{Digest, Sha256};

/// A signed note following the C2SP specification
#[derive(Debug, Clone)]
pub struct SignedNote {
    pub text: String,
    pub signatures: Vec<NoteSignature>,
}

/// A single signature on a note
#[derive(Debug, Clone)]
pub struct NoteSignature {
    pub key_name: String,
    pub key_id: [u8; 4],
    pub signature: Vec<u8>,
}

impl SignedNote {
    pub fn new(text: String) -> Self {
        Self {
            text,
            signatures: Vec::new(),
        }
    }

    pub fn add_signature(&mut self, signature: NoteSignature) {
        self.signatures.push(signature);
    }

    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&self.text);
        if !self.text.ends_with('\n') {
            output.push('\n');
        }

        output.push('\n');

        for sig in &self.signatures {
            output.push_str(&sig.format());
            output.push('\n');
        }

        output
    }
}

impl NoteSignature {
    pub fn format(&self) -> String {
        let mut sig_bytes = Vec::with_capacity(4 + self.signature.len());
        sig_bytes.extend_from_slice(&self.key_id);
        sig_bytes.extend_from_slice(&self.signature);

        format!("— {} {}", self.key_name, STANDARD.encode(&sig_bytes))
    }
}

/// RFC 6962 TreeHeadSignature for CT logs (signature type 0x05)
pub struct RFC6962NoteSignature {
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl RFC6962NoteSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.timestamp.to_be_bytes());

        // DigitallySigned structure
        encoded.push(4); // Hash algorithm: SHA256
        encoded.push(3); // Signature algorithm: ECDSA

        let sig_len = self.signature.len() as u16;
        encoded.extend_from_slice(&sig_len.to_be_bytes());
        encoded.extend_from_slice(&self.signature);

        encoded
    }
}

/// Builder for creating signed checkpoints
pub struct CheckpointBuilder {
    signing_key: SigningKey,
    origin: String,
    log_id: Vec<u8>,
}

impl CheckpointBuilder {
    pub fn new(signing_key: SigningKey, origin: String, log_id: Vec<u8>) -> Self {
        Self {
            signing_key,
            origin,
            log_id,
        }
    }

    fn calculate_key_id(&self) -> [u8; 4] {
        let mut hasher = Sha256::new();
        hasher.update(&self.origin);
        hasher.update(b"\n");
        hasher.update([0x05]); // Signature type for RFC 6962
        hasher.update(&self.log_id);

        let hash = hasher.finalize();
        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&hash[..4]);
        key_id
    }

    pub fn create_checkpoint(
        &self,
        tree_size: u64,
        root_hash: &[u8],
        timestamp: u64,
    ) -> Result<SignedNote> {
        let checkpoint_text = format!(
            "{}\n{}\n{}",
            self.origin,
            tree_size,
            STANDARD.encode(root_hash)
        );

        let mut note = SignedNote::new(checkpoint_text.clone());

        let signature_input = self.build_signature_input(timestamp, tree_size, root_hash);

        let signature: DerSignature = self.signing_key.sign(&signature_input);
        let signature_bytes = signature.to_bytes().to_vec();

        let rfc6962_sig = RFC6962NoteSignature {
            timestamp,
            signature: signature_bytes,
        };

        let note_signature = NoteSignature {
            key_name: self.origin.clone(),
            key_id: self.calculate_key_id(),
            signature: rfc6962_sig.encode(),
        };

        note.add_signature(note_signature);

        Ok(note)
    }

    fn build_signature_input(&self, timestamp: u64, tree_size: u64, root_hash: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();

        input.push(0); // Version: v1
        input.push(1); // SignatureType: tree_hash
        input.extend_from_slice(&timestamp.to_be_bytes());
        input.extend_from_slice(&tree_size.to_be_bytes());
        input.extend_from_slice(root_hash);

        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    fn create_test_key() -> SigningKey {
        SigningKey::random(&mut rand::thread_rng())
    }

    fn create_test_log_id() -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"test-log-id");
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_signed_note_format() {
        let mut note = SignedNote::new("Test note content".to_string());

        let sig = NoteSignature {
            key_name: "example.com/test".to_string(),
            key_id: [0x12, 0x34, 0x56, 0x78],
            signature: vec![0xaa, 0xbb, 0xcc],
        };

        note.add_signature(sig);

        let formatted = note.format();
        let lines: Vec<&str> = formatted.lines().collect();

        assert_eq!(lines[0], "Test note content");
        assert_eq!(lines[1], "");
        assert!(lines[2].starts_with("— example.com/test "));

        let sig_part = lines[2].split_whitespace().nth(2).unwrap();
        let decoded = STANDARD.decode(sig_part).unwrap();
        assert_eq!(&decoded[..4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&decoded[4..], &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_checkpoint_builder() {
        let key = create_test_key();
        let origin = "example.com/test-log".to_string();
        let log_id = create_test_log_id();

        let builder = CheckpointBuilder::new(key, origin.clone(), log_id);

        let tree_size = 12345u64;
        let root_hash = vec![0u8; 32];
        let timestamp = 1234567890000u64;

        let checkpoint = builder
            .create_checkpoint(tree_size, &root_hash, timestamp)
            .unwrap();

        let formatted = checkpoint.format();
        let lines: Vec<&str> = formatted.lines().collect();

        assert_eq!(lines[0], "example.com/test-log");
        assert_eq!(lines[1], "12345");
        assert_eq!(lines[2], STANDARD.encode(&root_hash));
        assert_eq!(lines[3], "");
        assert!(lines[4].starts_with(&format!("— {} ", origin)));
    }

    #[test]
    fn test_key_id_calculation() {
        let key = create_test_key();
        let origin = "example.com/test-log".to_string();
        let log_id = create_test_log_id();

        let builder = CheckpointBuilder::new(key, origin.clone(), log_id.clone());
        let key_id = builder.calculate_key_id();

        let mut hasher = Sha256::new();
        hasher.update(&origin);
        hasher.update(b"\n");
        hasher.update(&[0x05]);
        hasher.update(&log_id);
        let expected_hash = hasher.finalize();

        assert_eq!(&key_id[..], &expected_hash[..4]);
    }

    #[test]
    fn test_rfc6962_signature_encoding() {
        let sig = RFC6962NoteSignature {
            timestamp: 0x0123456789abcdef,
            signature: vec![0xaa, 0xbb, 0xcc],
        };

        let encoded = sig.encode();

        assert_eq!(
            &encoded[..8],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(encoded[8], 4); // SHA256
        assert_eq!(encoded[9], 3); // ECDSA
        assert_eq!(&encoded[10..12], &[0x00, 0x03]); // Length = 3
        assert_eq!(&encoded[12..], &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_note_with_trailing_newline() {
        let note = SignedNote::new("Test note\n".to_string());
        let formatted = note.format();
        assert_eq!(formatted, "Test note\n\n");
    }

    #[test]
    fn test_note_without_trailing_newline() {
        let note = SignedNote::new("Test note".to_string());
        let formatted = note.format();
        assert_eq!(formatted, "Test note\n\n");
    }
}
