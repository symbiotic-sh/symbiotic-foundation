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

/// Opaque Foundation-owned credential guard for adapter composition.
/// It can be forwarded or cloned, but exposes neither the secret nor a policy
/// override. Only Foundation constructs it; every result uses the same boundary.
/// ```compile_fail
/// use symbiotic_model::{OpenAiCompatibleChatProvider, ModelProvider};
/// let provider = OpenAiCompatibleChatProvider::new("op", "model", "http://localhost", "key");
/// println!("{:?}", provider.credential_boundary().unwrap());
/// ```
/// ```compile_fail
/// use symbiotic_model::{OpenAiCompatibleChatProvider, ModelProvider};
/// let provider = OpenAiCompatibleChatProvider::new("op", "model", "http://localhost", "key");
/// println!("{}", provider.credential_boundary().unwrap().secret());
/// ```
#[derive(Clone)]
pub struct CredentialBoundary {
    key: SecretValue<String>,
}

impl CredentialBoundary {
    pub(crate) fn new(key: SecretValue<String>) -> Self {
        Self { key }
    }

    pub(crate) fn secret(&self) -> &str {
        self.key.as_str()
    }
}

fn numeric_float_spellings(value: f64) -> SecretValue<Vec<String>> {
    let mut spellings = SecretValue::new(vec![value.to_string()]);
    if let Ok(value) = serde_json::to_string(&value) {
        spellings.push(value);
    }
    let value = value as f32;
    if value.is_finite() {
        spellings.push(value.to_string());
        if let Ok(value) = serde_json::to_string(&value) {
            spellings.push(value);
        }
    }
    spellings
}

fn numeric_spellings(number: &serde_json::Number) -> SecretValue<Vec<String>> {
    let mut spellings = SecretValue::new(vec![number.to_string()]);
    if let Some(value) = number.as_f64() {
        spellings.append(&mut numeric_float_spellings(value));
    }
    spellings
}

/// The finite credential encoding set, including numeric re-spellings.
fn credential_encodings(secret: &str) -> Result<SecretValue<Vec<String>>, crate::ModelError> {
    let mut encodings = SecretValue::new(vec![secret.to_owned()]);
    // Parse borrowed text directly into a primitive; JSON deserialization can
    // retain credential text in an arbitrary-precision Number or error scratch.
    if let Ok(value) = secret.trim().parse::<f64>()
        && value.is_finite()
    {
        encodings.append(&mut numeric_float_spellings(value));
    }
    let escaped = SecretValue::new(serde_json::to_string(secret).map_err(|_| {
        crate::ModelError::Provider(symbiotic_core::DiagnosticCode::InvalidCredentialEncoding)
    })?);
    encodings.push(escaped[1..escaped.len() - 1].to_owned());
    for all in [false, true] {
        for upper in [false, true] {
            let mut encoded = SecretValue::new(String::new());
            for byte in secret.bytes() {
                if !all && (byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)) {
                    encoded.push(char::from(byte));
                } else {
                    let digits = if upper {
                        b"0123456789ABCDEF"
                    } else {
                        b"0123456789abcdef"
                    };
                    encoded.push('%');
                    encoded.push(char::from(digits[usize::from(byte >> 4)]));
                    encoded.push(char::from(digits[usize::from(byte & 15)]));
                }
            }
            encodings.push(std::mem::take(&mut *encoded));
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
/// Used only by the complete adapter-result boundary.
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
            serde_json::Value::Number(number) => numeric_spellings(number)
                .iter()
                .any(|text| contains_text(text, encodings)),
            _ => false,
        }
    }
    if secret.is_empty() {
        return Ok(());
    }
    let encodings = credential_encodings(secret)?;
    let wire = SecretValue::new(serde_json::to_string(value).map_err(|_| {
        crate::ModelError::Provider(symbiotic_core::DiagnosticCode::InvalidProviderResponse)
    })?);
    if contains(value, &encodings) || contains_text(&wire, &encodings) {
        return Err(crate::ModelError::Provider(
            symbiotic_core::DiagnosticCode::CredentialBearingProviderResponseRefused,
        ));
    }
    Ok(())
}

/// Type erasure for dynamic/composed adapters. Policy is still enforced only
/// by `credential_boundary` using the credential owner's opaque guard.
pub(crate) fn composed_result<T: serde::Serialize + serde::de::DeserializeOwned>(
    provider: &dyn crate::ModelProvider,
    result: Result<T, crate::ModelError>,
) -> Result<T, crate::ModelError> {
    let Some(boundary) = provider.credential_boundary() else {
        if provider.credential_fingerprint().is_some()
            || !matches!(
                provider.descriptor().auth_mode,
                crate::ProviderAuthMode::None
            )
        {
            return Err(crate::ModelError::Provider(
                symbiotic_core::DiagnosticCode::CredentialResultBoundaryIsUnavailable,
            ));
        }
        return result;
    };
    let result = result.and_then(|response| {
        serde_json::to_value(response).map_err(|_| {
            crate::ModelError::Provider(symbiotic_core::DiagnosticCode::InvalidAdapterResponse)
        })
    });
    let value = credential_boundary(result, boundary)?;
    // Decode only Foundation's own typed serialization after the boundary.
    serde_json::from_value(value).map_err(|_| {
        crate::ModelError::Provider(symbiotic_core::DiagnosticCode::InvalidAdapterResponse)
    })
}

/// Responses crossing the credential boundary must surrender raw provider JSON.
pub(crate) trait CredentialResponse: serde::Serialize {
    fn discard_raw(&mut self);
}

// The erased representation used by object-safe composed adapters. It follows
// the same inspection and raw-disposal path as concrete responses.
impl CredentialResponse for serde_json::Value {
    fn discard_raw(&mut self) {
        if let Some(object) = self.as_object_mut() {
            object.remove("raw_provider_response");
        }
    }
}

macro_rules! credential_response {
    ($($response:ty),+ $(,)?) => {$(
        impl CredentialResponse for $response {
            fn discard_raw(&mut self) {
                self.raw_provider_response = None;
            }
        }
    )+};
}
credential_response!(
    crate::ChatResponse,
    crate::EmbeddingResponse,
    crate::RerankResponse,
    crate::ClassifyResponse
);

/// The sole credential boundary for a complete adapter result, after HTTP,
/// typed decoding and answer validation, and before runtime bookkeeping.
/// Inspect raw JSON and the final typed value together; never export raw JSON
/// or provider-controlled error text from a credential-bearing call.
pub(crate) fn credential_boundary<T: CredentialResponse>(
    result: Result<T, crate::ModelError>,
    boundary: &CredentialBoundary,
) -> Result<T, crate::ModelError> {
    let secret = boundary.secret();
    if secret.is_empty() {
        return result;
    }
    let mut response = result?;
    let value = serde_json::to_value(&response).map_err(|_| {
        crate::ModelError::Provider(symbiotic_core::DiagnosticCode::InvalidResponse)
    })?;
    check_response(&value, secret)?;
    response.discard_raw();
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
        assert!(check_response(&raw, "123400000").is_err());
        let normalized: f32 = serde_json::from_value(raw).unwrap();
        assert!(check_response(&serde_json::json!([normalized]), "123400000").is_err());
    }
    #[test]
    fn regression_numeric_scratch_uses_zeroizing_storage() {
        let number = serde_json::Number::from(123400000);
        let mut scratch: SecretValue<Vec<String>> = numeric_spellings(&number);
        assert!(scratch.iter().any(|value| value == "123400000"));
        scratch.zeroize();
        assert!(scratch.is_empty());
        for secret in ["123400000", "1.234e8", "0.123456789", "-123400000"] {
            let encodings = credential_encodings(secret).unwrap();
            let normalized: f32 = serde_json::from_str(secret).unwrap();
            assert!(check_response(&serde_json::json!([normalized]), secret).is_err());
            assert!(encodings.iter().any(|value| value == secret));
        }
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
