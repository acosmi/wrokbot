//! Pure shared content checks. These checks can only add refusals, never authorize effects.

/// Reject known secrets and non-null credential fields in tool arguments.
#[must_use]
pub fn arguments_contain_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            (is_secret_field_name(key) && !value.is_null()) || arguments_contain_secret(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(arguments_contain_secret),
        serde_json::Value::String(value) => contains_known_secret(value),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

/// Classify an argument field; this does not grant a schema field any authority.
#[must_use]
pub fn is_secret_field_name(value: &str) -> bool {
    let normalized = value
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    matches!(
        normalized.as_slice(),
        b"password"
            | b"passwd"
            | b"secret"
            | b"credentials"
            | b"token"
            | b"accesstoken"
            | b"refreshtoken"
            | b"apikey"
            | b"authorization"
            | b"privatekey"
            | b"clientsecret"
    )
}

/// Recognize the existing high-confidence secret/canary formats without I/O.
#[must_use]
pub fn contains_known_secret(value: &str) -> bool {
    if value.contains("-----BEGIN PRIVATE KEY-----")
        || value.contains("-----BEGIN RSA PRIVATE KEY-----")
        || value.contains("OPENBOT_SECRET_CANARY")
        || value.contains("SECRET-CANARY-")
    {
        return true;
    }
    value
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        })
        .any(|token| {
            let known_prefix = [
                "sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "xoxb-", "xoxp-",
            ]
            .iter()
            .any(|prefix| token.starts_with(prefix) && token.len() >= prefix.len() + 20);
            known_prefix || is_aws_access_key(token) || is_jwt_shape(token)
        })
}

fn is_aws_access_key(value: &str) -> bool {
    value.len() == 20
        && (value.starts_with("AKIA") || value.starts_with("ASIA"))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_jwt_shape(value: &str) -> bool {
    let mut segments = value.split('.');
    let valid_segment = |segment: &str| {
        segment.len() >= 16
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    matches!(
        (segments.next(), segments.next(), segments.next(), segments.next()),
        (Some(first), Some(second), Some(third), None)
            if first.starts_with("eyJ")
                && valid_segment(first)
                && valid_segment(second)
                && valid_segment(third)
    )
}

/// Scan JSON string values and keys for actual high-confidence secret values.
/// Unlike argument-field rejection, a schema declaring a password property is not a secret.
#[must_use]
pub fn value_contains_known_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object
            .iter()
            .any(|(key, value)| contains_known_secret(key) || value_contains_known_secret(value)),
        serde_json::Value::Array(values) => values.iter().any(value_contains_known_secret),
        serde_json::Value::String(value) => contains_known_secret(value),
        _ => false,
    }
}
