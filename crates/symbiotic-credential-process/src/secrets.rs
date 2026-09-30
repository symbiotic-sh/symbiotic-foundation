//! Local secret resolution. No secret type implements Debug or Serialize.
use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Read, path::PathBuf};
use symbiotic_egress::EgressError;
use zeroize::Zeroizing;

/// Configured backend; references carry locations, never secret values.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretSource {
    /// Exact owner-only file, opened without following its final symlink.
    OwnerOnlyFile { path: PathBuf },
    /// Existing macOS generic password; no shell invocation or environment fallback.
    MacosKeychain { service: String, account: String },
}

/// Secret with the finite v1 encoding set precomputed for output rejection.
pub(crate) struct Secret {
    value: Zeroizing<String>,
    encodings: Zeroizing<Vec<String>>,
}

impl Secret {
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    pub(crate) fn contains(&self, bytes: &[u8]) -> bool {
        self.encodings.iter().any(|value| {
            bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes())
        })
    }

    pub(crate) fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, EgressError> {
        let value = Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| EgressError::CredentialUnavailable)?
                .to_owned(),
        );
        if value.is_empty() {
            return Err(EgressError::CredentialUnavailable);
        }
        let mut encodings = Zeroizing::new(vec![value.to_string()]);
        let escaped = Zeroizing::new(
            serde_json::to_string(value.as_str())
                .map_err(|_| EgressError::CredentialUnavailable)?,
        );
        encodings.push(escaped[1..escaped.len() - 1].to_owned());
        for all in [false, true] {
            for upper in [false, true] {
                let mut encoded = String::new();
                for byte in value.bytes() {
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
            encodings.push(engine.encode(value.as_bytes()));
        }
        Ok(Self { value, encodings })
    }
}

impl SecretSource {
    /// Load bounded bytes, refusing insecure files and unsupported platforms.
    pub fn load(&self, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, EgressError> {
        if max_bytes == 0 {
            return Err(EgressError::CredentialUnavailable);
        }
        let bytes = match self {
            Self::OwnerOnlyFile { path } => read_private_file(path, max_bytes)?,
            Self::MacosKeychain { service, account } => keychain(service, account)?,
        };
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(EgressError::CredentialUnavailable);
        }
        Ok(bytes)
    }
}

pub(crate) fn read_private_file(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, EgressError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| EgressError::CredentialUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| EgressError::CredentialUnavailable)?;
        // SAFETY: geteuid has no preconditions and does not access memory.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() > max_bytes as u64
        {
            return Err(EgressError::CredentialUnavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| EgressError::CredentialUnavailable)?;
        if bytes.len() > max_bytes {
            return Err(EgressError::CredentialUnavailable);
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_bytes);
        Err(EgressError::CredentialUnavailable)
    }
}

#[cfg(target_os = "macos")]
fn keychain(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>, EgressError> {
    security_framework::passwords::get_generic_password(service, account)
        .map(Zeroizing::new)
        .map_err(|_| EgressError::CredentialUnavailable)
}
#[cfg(not(target_os = "macos"))]
fn keychain(_: &str, _: &str) -> Result<Zeroizing<Vec<u8>>, EgressError> {
    Err(EgressError::CredentialUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_every_declared_credential_encoding() {
        let secret = Secret::from_bytes(Zeroizing::new(b"key-\"/\n+?=\xc3\xa9".to_vec())).unwrap();
        assert!(secret.encodings.len() >= 10);
        for encoded in secret.encodings.iter() {
            assert!(secret.contains(format!("prefix {encoded} suffix").as_bytes()));
        }
        assert!(!secret.contains(b"ordinary provider answer"));
    }
    #[cfg(unix)]
    #[test]
    fn file_backend_refuses_public_files_symlinks_and_oversize() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "synthetic-secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&path, 100).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            &*read_private_file(&path, 100).unwrap(),
            b"synthetic-secret"
        );
        assert!(read_private_file(&path, 2).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private_file(&link, 100).is_err());
    }
}
