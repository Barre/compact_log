//! SCT Extensions for the Static CT API

/// Extension types as defined in the Static CT API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtensionType {
    LeafIndex = 0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Vec<u8>,
}

/// LeafIndex type - a 40-bit unsigned integer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafIndex(pub u64);

impl LeafIndex {
    pub fn new(index: u64) -> Result<Self, &'static str> {
        if index > 0xFFFFFFFFFF {
            return Err("Index exceeds 40-bit range");
        }
        Ok(Self(index))
    }

    pub fn as_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = ((self.0 >> 32) & 0xFF) as u8;
        bytes[1] = ((self.0 >> 24) & 0xFF) as u8;
        bytes[2] = ((self.0 >> 16) & 0xFF) as u8;
        bytes[3] = ((self.0 >> 8) & 0xFF) as u8;
        bytes[4] = (self.0 & 0xFF) as u8;
        bytes
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 5 {
            return Err("LeafIndex must be exactly 5 bytes");
        }

        let index = ((bytes[0] as u64) << 32)
            | ((bytes[1] as u64) << 24)
            | ((bytes[2] as u64) << 16)
            | ((bytes[3] as u64) << 8)
            | (bytes[4] as u64);

        Self::new(index)
    }
}

impl Extension {
    pub fn leaf_index(index: u64) -> Result<Self, &'static str> {
        let leaf_index = LeafIndex::new(index)?;
        Ok(Self {
            extension_type: ExtensionType::LeafIndex,
            extension_data: leaf_index.as_bytes().to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(self.extension_type as u8);

        let data_len = self.extension_data.len() as u16;
        encoded.extend_from_slice(&data_len.to_be_bytes());
        encoded.extend_from_slice(&self.extension_data);

        encoded
    }

    #[cfg(test)]
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        if bytes.len() < 3 {
            return Err("Extension too short");
        }

        let ext_type = bytes[0];
        let data_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;

        if bytes.len() < 3 + data_len {
            return Err("Extension data truncated");
        }

        let extension_type = match ext_type {
            0 => ExtensionType::LeafIndex,
            _ => return Err("Unknown extension type"),
        };

        let extension_data = bytes[3..3 + data_len].to_vec();

        Ok((
            Self {
                extension_type,
                extension_data,
            },
            3 + data_len,
        ))
    }
}

pub struct CtExtensions;

impl CtExtensions {
    pub fn encode(extensions: &[Extension]) -> Vec<u8> {
        let mut encoded = Vec::new();

        let total_len: u16 = extensions
            .iter()
            .map(|ext| ext.encode().len())
            .sum::<usize>() as u16;

        encoded.extend_from_slice(&total_len.to_be_bytes());

        for ext in extensions {
            encoded.extend_from_slice(&ext.encode());
        }

        encoded
    }

    /// Create a CtExtensions field containing only a leaf_index extension
    pub fn with_leaf_index(index: u64) -> Result<Vec<u8>, &'static str> {
        let leaf_ext = Extension::leaf_index(index)?;
        Ok(Self::encode(&[leaf_ext]))
    }

    #[cfg(test)]
    pub fn decode(bytes: &[u8]) -> Result<Vec<Extension>, &'static str> {
        if bytes.len() < 2 {
            return Err("CtExtensions too short");
        }

        let total_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;

        if bytes.len() != 2 + total_len {
            return Err("CtExtensions length mismatch");
        }

        let mut extensions = Vec::new();
        let mut offset = 2;

        while offset < bytes.len() {
            let (ext, consumed) = Extension::decode(&bytes[offset..])?;
            extensions.push(ext);
            offset += consumed;
        }

        Ok(extensions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_index_creation() {
        let index = LeafIndex::new(12345).unwrap();
        assert_eq!(index.0, 12345);

        let max_index = LeafIndex::new(0xFFFFFFFFFF).unwrap();
        assert_eq!(max_index.0, 0xFFFFFFFFFF);

        let result = LeafIndex::new(0x10000000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_leaf_index_bytes() {
        let index = LeafIndex::new(0x0102030405).unwrap();
        let bytes = index.as_bytes();
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0x05]);

        let decoded = LeafIndex::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.0, 0x0102030405);
    }

    #[test]
    fn test_extension_encoding() {
        let ext = Extension::leaf_index(12345).unwrap();
        let encoded = ext.encode();

        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[0], 0); // ExtensionType::LeafIndex
        assert_eq!(&encoded[1..3], &[0, 5]); // Data length = 5
    }

    #[test]
    fn test_extension_decoding() {
        let ext = Extension::leaf_index(12345).unwrap();
        let encoded = ext.encode();

        let (decoded, consumed) = Extension::decode(&encoded).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(decoded.extension_type, ExtensionType::LeafIndex);
        assert_eq!(decoded.extension_data, ext.extension_data);
    }

    #[test]
    fn test_ct_extensions_encoding() {
        let extensions = vec![Extension::leaf_index(12345).unwrap()];

        let encoded = CtExtensions::encode(&extensions);

        assert_eq!(encoded.len(), 10);
        assert_eq!(&encoded[0..2], &[0, 8]); // Total extensions length = 8
    }

    #[test]
    fn test_ct_extensions_with_leaf_index() {
        let encoded = CtExtensions::with_leaf_index(12345).unwrap();

        assert_eq!(encoded.len(), 10);

        let extensions = CtExtensions::decode(&encoded).unwrap();
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].extension_type, ExtensionType::LeafIndex);

        let leaf_index = LeafIndex::from_bytes(&extensions[0].extension_data).unwrap();
        assert_eq!(leaf_index.0, 12345);
    }

    #[test]
    fn test_max_40_bit_value() {
        let max_40_bit = 0xFFFFFFFFFF_u64;
        let index = LeafIndex::new(max_40_bit).unwrap();
        let bytes = index.as_bytes();
        assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        let decoded = LeafIndex::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.0, max_40_bit);
    }

    #[test]
    fn test_leaf_index_too_large() {
        let too_large = 0x10000000000_u64; // 2^40
        let result = LeafIndex::new(too_large);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Index exceeds 40-bit range");
    }

    #[test]
    fn test_leaf_index_zero() {
        let index = LeafIndex::new(0).unwrap();
        let bytes = index.as_bytes();
        assert_eq!(bytes, [0x00, 0x00, 0x00, 0x00, 0x00]);

        let decoded = LeafIndex::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.0, 0);
    }

    #[test]
    fn test_extension_decode_errors() {
        let result = Extension::decode(&[0x00]);
        assert!(result.is_err());

        let invalid_type = vec![0xFF, 0x00, 0x00];
        let result = Extension::decode(&invalid_type);
        assert!(result.is_err());

        let truncated = vec![0x00, 0x00, 0x05, 0x01, 0x02];
        let result = Extension::decode(&truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_ct_extensions_decode_errors() {
        let result = CtExtensions::decode(&[0x00]);
        assert!(result.is_err());

        let mismatch = vec![0x00, 0x10, 0x00];
        let result = CtExtensions::decode(&mismatch);
        assert!(result.is_err());
    }

    #[test]
    fn test_leaf_index_from_bytes_errors() {
        let result = LeafIndex::from_bytes(&[0x00, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "LeafIndex must be exactly 5 bytes");

        let result = LeafIndex::from_bytes(&[0x00; 6]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_extensions() {
        let ext1 = Extension::leaf_index(12345).unwrap();
        let ext2 = Extension::leaf_index(67890).unwrap();

        let extensions = vec![ext1, ext2];
        let encoded = CtExtensions::encode(&extensions);

        assert_eq!(encoded.len(), 18);

        let decoded = CtExtensions::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);

        assert_eq!(decoded[0].extension_type, ExtensionType::LeafIndex);
        let index1 = LeafIndex::from_bytes(&decoded[0].extension_data).unwrap();
        assert_eq!(index1.0, 12345);

        assert_eq!(decoded[1].extension_type, ExtensionType::LeafIndex);
        let index2 = LeafIndex::from_bytes(&decoded[1].extension_data).unwrap();
        assert_eq!(index2.0, 67890);
    }

    #[test]
    fn test_empty_extensions() {
        let extensions: Vec<Extension> = vec![];
        let encoded = CtExtensions::encode(&extensions);

        assert_eq!(encoded, vec![0x00, 0x00]);

        let decoded = CtExtensions::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }
}
