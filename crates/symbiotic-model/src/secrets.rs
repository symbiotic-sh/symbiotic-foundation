//! One non-Debug, non-serializable zeroizing container for provider secrets.
use base64::{Engine, engine::general_purpose};
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, Zeroizing};

/// Owns a secret and zeroizes it on drop, including clones and derived buffers.
/// Ordinary diagnostics and serialization cannot expose it.
/// ```compile_fail
/// use symbiotic_model::SecretValue;
/// let secret = SecretValue::new(String::from("synthetic"));
/// println!("{secret:?}");
/// ```
#[derive(Clone)]
pub struct SecretValue<T: Zeroize>(Zeroizing<T>);
impl<T: Zeroize> SecretValue<T> {
    /// Take ownership of a value and zeroize its storage when it is dropped.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }
}
impl<T: Zeroize> Deref for SecretValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Zeroize> DerefMut for SecretValue<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl From<String> for SecretValue<String> {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}
impl From<&str> for SecretValue<String> {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}
impl From<&String> for SecretValue<String> {
    fn from(value: &String) -> Self {
        Self::new(value.clone())
    }
}

/// Preserve useful error classes without retaining provider-controlled bytes.
pub(crate) fn safe_error(error: crate::ModelError) -> crate::ModelError {
    use crate::ModelError;
    let safe = "credential-bearing provider failure".to_owned();
    match error {
        ModelError::Auth(_) => ModelError::Auth(safe),
        ModelError::RateLimited(_) => ModelError::RateLimited(safe),
        ModelError::BudgetExhausted(_) => ModelError::BudgetExhausted(safe),
        ModelError::Timeout(_) => ModelError::Timeout(safe),
        ModelError::Unavailable(_) => ModelError::Unavailable(safe),
        _ => ModelError::Provider(safe),
    }
}

/// The finite encoding set previously enforced by the credential process.
fn credential_encodings(secret: &str) -> Result<SecretValue<Vec<String>>, crate::ModelError> {
    let mut encodings = SecretValue::new(vec![secret.to_owned()]);
    let escaped = SecretValue::new(
        serde_json::to_string(secret)
            .map_err(|_| crate::ModelError::Provider("invalid credential encoding".into()))?,
    );
    encodings.push(escaped[1..escaped.len() - 1].to_owned());
    for all in [false, true] {
        for upper in [false, true] {
            let mut encoded = String::new();
            for byte in secret.bytes() {
                if !all && (byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)) {
                    encoded.push(char::from(byte));
                } else if upper {
                    encoded.push_str(&format!("%{byte:02X}"));
                } else {
                    encoded.push_str(&format!("%{byte:02x}"));
                }
            }
            encodings.push(encoded);
        }
    }
    for engine in [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ] {
        encodings.push(engine.encode(secret.as_bytes()));
    }
    Ok(encodings)
}

/// Refuse credential echoes in decoded strings, object keys and encoded numbers.
/// Every HTTP adapter calls this before parsing or returning provider output.
pub(crate) fn check_response(
    value: &serde_json::Value,
    secret: &str,
) -> Result<(), crate::ModelError> {
    fn contains_text(text: &str, encodings: &[String]) -> bool {
        encodings.iter().any(|secret| text.contains(secret))
    }
    fn contains(value: &serde_json::Value, encodings: &[String]) -> bool {
        match value {
            serde_json::Value::String(text) => contains_text(text, encodings),
            serde_json::Value::Array(values) => {
                values.iter().any(|value| contains(value, encodings))
            }
            serde_json::Value::Object(values) => values
                .iter()
                .any(|(key, value)| contains_text(key, encodings) || contains(value, encodings)),
            _ => false,
        }
    }
    if secret.is_empty() {
        return Ok(());
    }
    let encodings = credential_encodings(secret)?;
    let wire = serde_json::to_string(value)
        .map_err(|_| crate::ModelError::Provider("invalid provider response".into()))?;
    if contains(value, &encodings) || contains_text(&wire, &encodings) {
        return Err(crate::ModelError::Provider(
            "credential-bearing provider response refused".into(),
        ));
    }
    Ok(())
}

/// Check the final typed response too, including numbers normalized by an adapter.
pub(crate) fn checked_response<T: serde::Serialize>(
    response: T,
    secret: &str,
) -> Result<T, crate::ModelError> {
    if !secret.is_empty() {
        let value = serde_json::to_value(&response)
            .map_err(|_| crate::ModelError::Provider("invalid provider response".into()))?;
        check_response(&value, secret)?;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_every_declared_credential_encoding() {
        let secret = "key-\"/\n+?=é";
        let encodings = credential_encodings(secret).unwrap();
        assert!(encodings.len() >= 10);
        for encoded in encodings.iter() {
            let value = serde_json::json!({"content": format!("prefix {encoded} suffix")});
            assert!(check_response(&value, secret).is_err(), "{encoded}");
        }
        assert!(check_response(&serde_json::json!("ordinary provider answer"), secret).is_ok());
    }
    #[test]
    fn credential_echoes_are_refused_in_nested_fields_keys_and_numbers() {
        for value in [
            serde_json::json!({"vectors": [[123456789]]}),
            serde_json::json!({"nested": ["prefix123456789suffix"]}),
            serde_json::json!({"123456789": "safe"}),
        ] {
            assert!(check_response(&value, "123456789").is_err());
            assert!(check_response(&value, "").is_ok());
        }
    }
    #[test]
    fn normalized_numeric_output_cannot_echo_credentials() {
        let raw: serde_json::Value = serde_json::from_str("1.234e8").unwrap();
        assert!(check_response(&raw, "123400000").is_ok());
        let normalized: f32 = serde_json::from_value(raw).unwrap();
        assert!(checked_response(vec![normalized], "123400000").is_err());
    }
    #[test]
    fn invalid_embedding_error_is_sanitized_as_provider_failure() {
        let error = safe_error(crate::ModelError::Provider(
            "private embedding detail".into(),
        ));
        assert!(
            matches!(error, crate::ModelError::Provider(message) if message == "credential-bearing provider failure")
        );
    }
    #[test]
    fn secret_clones_are_owned_zeroizing_containers() {
        let mut secret = SecretValue::new(String::from("synthetic"));
        let clone = secret.clone();
        secret.zeroize();
        assert!(secret.is_empty());
        assert_eq!(clone.as_str(), "synthetic");
    }
}
