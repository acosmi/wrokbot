//! Serde field boundary for owned request secrets. A later field/shape error still drops a
//! zeroizing allocation instead of an ordinary String.

use serde::{Deserialize, Deserializer, Serializer};
use zeroize::Zeroizing;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub(crate) fn serialize<S: Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.as_str())
}
