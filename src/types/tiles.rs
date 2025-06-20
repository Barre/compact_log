use crate::types::{DeduplicatedLogEntry, LogEntryType, Result};

#[derive(Debug, Clone)]
pub struct Tile {
    pub hashes: Vec<[u8; 32]>,
}

impl Tile {
    pub fn new(_level: u8, _index: u64, hashes: Vec<[u8; 32]>) -> Self {
        let width = hashes.len() as u16;
        assert!(width > 0 && width <= 256, "Tile width must be 1-256");
        Self { hashes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hashes.len() * 32);
        for hash in &self.hashes {
            bytes.extend_from_slice(hash);
        }
        bytes
    }
}

#[derive(Debug)]
pub struct DataTile {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TileLeaf {
    pub timestamped_entry_raw: Vec<u8>,
    pub pre_certificate: Option<Vec<u8>>,
    pub certificate_chain: Vec<[u8; 32]>,
}

impl TileLeaf {
    pub fn from_entry(
        entry: &DeduplicatedLogEntry,
        _certificate: Vec<u8>,
        pre_certificate: Option<Vec<u8>>,
    ) -> Self {
        let timestamped_entry_raw = entry.leaf_data[2..].to_vec();

        Self {
            timestamped_entry_raw,
            pre_certificate: if entry.entry_type == LogEntryType::PrecertEntry {
                pre_certificate
            } else {
                None
            },
            certificate_chain: entry.chain_hashes.clone().unwrap_or_default(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&self.timestamped_entry_raw);

        if let Some(precert) = &self.pre_certificate {
            let len = precert.len() as u32;
            data.push((len >> 16) as u8);
            data.push((len >> 8) as u8);
            data.push(len as u8);
            data.extend_from_slice(precert);
        }

        let chain_bytes_len = self.certificate_chain.len() * 32;
        data.extend_from_slice(&(chain_bytes_len as u16).to_be_bytes());
        for fingerprint in &self.certificate_chain {
            data.extend_from_slice(fingerprint);
        }

        data
    }
}

pub fn parse_tile_index(path: &str) -> Result<u64> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() || parts.len() > 64 {
        return Err(crate::types::CtError::BadRequest(
            "Invalid tile index path".to_string(),
        ));
    }

    let mut index = 0u64;
    for (i, part) in parts.iter().enumerate() {
        let is_last = i == parts.len() - 1;
        let num_str = if !is_last && part.starts_with('x') {
            &part[1..]
        } else {
            part
        };

        if num_str.len() != 3 {
            return Err(crate::types::CtError::BadRequest(
                "Each path element must be exactly 3 digits".to_string(),
            ));
        }

        let num: u64 = num_str.parse().map_err(|_| {
            crate::types::CtError::BadRequest("Invalid number in tile path".to_string())
        })?;

        if num > 999 {
            return Err(crate::types::CtError::BadRequest(
                "Path element must be 000-999".to_string(),
            ));
        }

        index = index * 1000 + num;
    }

    Ok(index)
}

#[cfg(test)]
fn format_tile_index(mut index: u64) -> String {
    if index == 0 {
        return "000".to_string();
    }

    let mut parts = Vec::new();
    while index > 0 {
        parts.push(format!("{:03}", index % 1000));
        index /= 1000;
    }
    parts.reverse();

    for i in 0..parts.len() - 1 {
        parts[i] = format!("x{}", parts[i]);
    }

    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tile_index() {
        assert_eq!(parse_tile_index("000").unwrap(), 0);
        assert_eq!(parse_tile_index("067").unwrap(), 67);
        assert_eq!(parse_tile_index("x001/234").unwrap(), 1234);
        assert_eq!(parse_tile_index("x001/x234/067").unwrap(), 1234067);
        assert_eq!(parse_tile_index("x999/x999/999").unwrap(), 999999999);

        assert!(parse_tile_index("").is_err());
        assert!(parse_tile_index("1").is_err());
        assert!(parse_tile_index("x001/23").is_err());
        assert!(parse_tile_index("x001/x234/67a").is_err());
    }

    #[test]
    fn test_format_tile_index() {
        assert_eq!(format_tile_index(0), "000");
        assert_eq!(format_tile_index(67), "067");
        assert_eq!(format_tile_index(1234), "x001/234");
        assert_eq!(format_tile_index(1234067), "x001/x234/067");
        assert_eq!(format_tile_index(999999999), "x999/x999/999");
    }

    #[test]
    fn test_tile_creation() {
        let hashes = vec![[0u8; 32]; 256];
        let tile = Tile::new(0, 0, hashes.clone());
        assert_eq!(tile.hashes.len(), 256);

        let partial_hashes = vec![[0u8; 32]; 100];
        let partial_tile = Tile::new(1, 5, partial_hashes.clone());
        assert_eq!(partial_tile.hashes.len(), 100);
    }

    #[test]
    fn test_tile_to_bytes() {
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let tile = Tile::new(0, 0, hashes);
        let bytes = tile.to_bytes();
        assert_eq!(bytes.len(), 3 * 32);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(&bytes[64..96], &[3u8; 32]);
    }
}
