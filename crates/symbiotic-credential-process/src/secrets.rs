//! Local secret resolution. No secret type implements Debug or Serialize.
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Read, path::PathBuf};
use symbiotic_ai_runtime::model::SecretValue;
use symbiotic_egress::EgressError;

/// Configured backend; references carry locations, never secret values.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretSource {
    /// Keyless provider. Must never be used for an admission MAC key.
    None,
    /// Exact owner-only file, opened without following its final symlink.
    OwnerOnlyFile { path: PathBuf },
}

/// Owned credential; the shared model HTTP boundary rejects output echoes.
pub(crate) struct Secret {
    value: SecretValue<String>,
}

impl Secret {
    pub(crate) fn keyless() -> Self {
        Self {
            value: SecretValue::new(String::new()),
        }
    }
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    pub(crate) fn from_bytes(bytes: SecretValue<Vec<u8>>) -> Result<Self, EgressError> {
        let value = SecretValue::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| EgressError::CredentialUnavailable)?
                .to_owned(),
        );
        if value.is_empty() {
            return Err(EgressError::CredentialUnavailable);
        }
        Ok(Self { value })
    }
}

impl SecretSource {
    /// Load bounded bytes, refusing insecure files and unsupported platforms.
    pub fn load(&self, max_bytes: usize) -> Result<SecretValue<Vec<u8>>, EgressError> {
        if max_bytes == 0 {
            return Err(EgressError::CredentialUnavailable);
        }
        let bytes = match self {
            Self::None => return Err(EgressError::CredentialUnavailable),
            Self::OwnerOnlyFile { path } => read_private_file(path, max_bytes)?,
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
) -> Result<SecretValue<Vec<u8>>, EgressError> {
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
        let mut bytes = SecretValue::new(Vec::new());
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

#[cfg(test)]
mod tests {
    use super::*;
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
