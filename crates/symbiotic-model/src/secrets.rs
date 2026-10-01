//! One non-Debug, non-serializable zeroizing container for provider secrets.
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_clones_are_owned_zeroizing_containers() {
        let mut secret = SecretValue::new(String::from("synthetic"));
        let clone = secret.clone();
        secret.zeroize();
        assert!(secret.is_empty());
        assert_eq!(clone.as_str(), "synthetic");
    }
}
