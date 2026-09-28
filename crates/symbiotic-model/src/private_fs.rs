//! Directories and files that only the current user can reach.
//!
//! The runtime keeps cached responses and queue state on disk. They can
//! hold private text, so every component the runtime creates or owns is
//! owner-only (`0700` directories, `0600` files). None may be a symlink or
//! belong to another user. On non-Unix platforms the checks are skipped.
//!
//! Public because `symbiotic-ai-runtime` composes it; hosts should not
//! need it.

use std::io;
use std::path::Path;

fn refuse(path: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} {why}", path.display()),
    )
}

/// Refuse `path` unless it is a directory owned by the current user, not a
/// symlink, and closed to group and others.
pub fn check_private_dir(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    check_owned(path, &meta)?;
    if !meta.is_dir() {
        return Err(refuse(path, "is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(refuse(
                path,
                "is open to group or others; make it owner-only (chmod 700)",
            ));
        }
    }
    Ok(())
}

/// Create `path` owner-only, with missing parents also owner-only, or check
/// an existing one with [`check_private_dir`].
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => check_private_dir(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            create_dirs(path)?;
            check_private_dir(path)
        }
        Err(err) => Err(err),
    }
}

/// Create or adopt `path`, a directory inside a private one this runtime
/// owns. A missing directory is created `0700`. An existing one must be the
/// user's own directory and not a symlink; wider permissions left by
/// earlier versions are tightened to `0700`.
pub fn ensure_owned_dir(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            check_owned(path, &meta)?;
            if !meta.is_dir() {
                return Err(refuse(path, "is not a directory"));
            }
            tighten(path, &meta, 0o700)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => create_dirs(path),
        Err(err) => Err(err),
    }
}

/// Adopt an existing file this runtime owns: refuse a symlink or another
/// user's file, and tighten wider permissions to `0600`.
pub fn ensure_owned_file(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    check_owned(path, &meta)?;
    if !meta.is_file() {
        return Err(refuse(path, "is not a regular file"));
    }
    tighten(path, &meta, 0o600)
}

/// Adopt a tree this runtime wrote: every directory and file under `root`
/// (and `root` itself) passes [`ensure_owned_dir`] or
/// [`ensure_owned_file`]. A symlink anywhere in it is refused, not followed.
pub fn ensure_owned_tree(root: &Path) -> io::Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        ensure_owned_dir(&dir)?;
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                pending.push(path);
            } else {
                ensure_owned_file(&path)?;
            }
        }
    }
    Ok(())
}

/// Create `path` as a new, empty `0600` file if it does not exist yet, else
/// adopt it with [`ensure_owned_file`].
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => ensure_owned_file(path),
        Err(err) => Err(err),
    }
}

/// Write `bytes` to `path` as a `0600` file, through a new temporary file in
/// the same directory and a rename, so readers never see a partial file.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp.{}", symbiotic_core::QueueItemId::new().0));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&tmp)
        .and_then(|mut file| file.write_all(bytes))
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

fn create_dirs(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[cfg(unix)]
fn check_owned(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if meta.file_type().is_symlink() {
        return Err(refuse(
            path,
            "is a symlink; the runtime does not follow them",
        ));
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(refuse(path, "is owned by another user"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owned(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    if meta.file_type().is_symlink() {
        return Err(refuse(
            path,
            "is a symlink; the runtime does not follow them",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn tighten(path: &Path, meta: &std::fs::Metadata, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten(_path: &Path, _meta: &std::fs::Metadata, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn private_dirs_are_created_owner_only_and_open_ones_refused() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        ensure_private_dir(&nested).unwrap();
        assert_eq!(mode(&dir.path().join("a")), 0o700);
        assert_eq!(mode(&nested), 0o700);

        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = ensure_private_dir(&nested).unwrap_err();
        assert!(err.to_string().contains("group or others"), "{err}");

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("a"), &link).unwrap();
        assert!(
            ensure_private_dir(&link)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn owned_trees_are_tightened_and_symlinks_inside_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::set_permissions(root.join("sub"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(root.join("sub/file"), b"x").unwrap();
        std::fs::set_permissions(
            root.join("sub/file"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        ensure_owned_tree(&root).unwrap();
        assert_eq!(mode(&root.join("sub")), 0o700);
        assert_eq!(mode(&root.join("sub/file")), 0o600);

        std::os::unix::fs::symlink(dir.path(), root.join("sub/escape")).unwrap();
        assert!(
            ensure_owned_tree(&root)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn private_files_are_written_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entry.json");
        write_private_file(&path, b"{}").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        let created = dir.path().join("queue.sqlite");
        ensure_private_file(&created).unwrap();
        assert_eq!(mode(&created), 0o600);
    }
}
