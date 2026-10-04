//! Bounded JSON preflight using serde's parser, including duplicate-key rejection.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

pub(crate) const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 32;

/// Validate the entire envelope before adapters recurse into arbitrary tool input.
/// Typed decoding still owns field/schema validation; unknown native metadata is
/// accepted only within these limits. Duplicate keys are rejected at every level.
pub(crate) fn preflight(bytes: &[u8], max_bytes: usize) -> Result<(), serde_json::Error> {
    if bytes.len() > max_bytes {
        return Err(de::Error::custom("JSON payload exceeds byte limit"));
    }
    let mut nodes = 0;
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    BoundedValue {
        depth: 0,
        nodes: &mut nodes,
        max_nodes: (max_bytes / 16).min(8192),
    }
    .deserialize(&mut parser)?;
    parser.end()
}

struct BoundedValue<'a> {
    depth: usize,
    nodes: &'a mut usize,
    max_nodes: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, parser: D) -> Result<(), D::Error> {
        *self.nodes += 1;
        if self.depth > MAX_DEPTH || *self.nodes > self.max_nodes {
            return Err(de::Error::custom("JSON nesting or value limit exceeded"));
        }
        parser.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON with unique object keys")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > 16 * 1024 {
            return Err(de::Error::custom("JSON string exceeds 16 KiB"));
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence
            .next_element_seed(BoundedValue {
                depth: self.depth + 1,
                nodes: self.nodes,
                max_nodes: self.max_nodes,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 256 || !keys.insert(key) {
                return Err(de::Error::custom("JSON key is oversized or duplicated"));
            }
            map.next_value_seed(BoundedValue {
                depth: self.depth + 1,
                nodes: self.nodes,
                max_nodes: self.max_nodes,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REQUEST_BYTES, preflight};
    #[test]
    fn bounds_unknown_metadata_keys_strings_depth_and_values() {
        let key = serde_json::to_vec(&serde_json::json!({"x".repeat(257):null})).unwrap();
        let string =
            serde_json::to_vec(&serde_json::json!({"metadata":"x".repeat(16385)})).unwrap();
        let values = serde_json::to_vec(&serde_json::json!({"metadata":vec![0;4096]})).unwrap();
        let depth = format!("{}0{}", "[".repeat(33), "]".repeat(33)).into_bytes();
        for bytes in [key, string, values, depth] {
            assert!(preflight(&bytes, MAX_REQUEST_BYTES).is_err());
        }
        assert!(preflight(br#"{"metadata":{"safe":true}}"#, MAX_REQUEST_BYTES).is_ok());
    }
}
