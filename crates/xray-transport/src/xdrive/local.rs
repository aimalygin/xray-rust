//! The `local` service: objects as files under a folder both ends reach,
//! as Xray-core v26.10.31's `local.go` keeps them.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;

use super::storage::{Entry, Storage, StorageError};

/// Files this prefix starts are being written; nobody lists or reads them.
const TEMP_PREFIX: &str = ".xdrive-tmp-";

#[derive(Debug)]
pub(crate) struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    /// `newLocalStorage`: the folder must be named, and is made with its
    /// parents, readable by this user only, when it is not there.
    pub(crate) async fn open(root: &str) -> Result<Self, StorageError> {
        if root.is_empty() {
            return Err(StorageError::Failed(r#"empty "remoteFolder""#.to_owned()));
        }
        let root = PathBuf::from(root);
        let made = root.clone();
        blocking(move || {
            create_dirs(&made).map_err(|error| failed("failed to create remote folder", error))
        })
        .await?;
        Ok(Self { root })
    }

    #[cfg(test)]
    pub(super) fn resolve_for_test(&self, name: &str) -> Result<PathBuf, StorageError> {
        self.resolve(name)
    }

    /// `resolve`: the file of an object, which is never the folder itself
    /// nor anything outside it, and never a temporary file.
    fn resolve(&self, name: &str) -> Result<PathBuf, StorageError> {
        let clean = clean_rooted(name);
        if clean.is_empty() {
            return Err(StorageError::Failed(format!("invalid object name: {name}")));
        }
        if clean
            .last()
            .is_some_and(|base| base.starts_with(TEMP_PREFIX))
        {
            return Err(StorageError::Failed(format!(
                "reserved object name: {name}"
            )));
        }
        Ok(clean
            .iter()
            .fold(self.root.clone(), |path, part| path.join(part)))
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError> {
        let full = self.resolve(name)?;
        let name = name.to_owned();
        blocking(move || put_file(&full, &data, &name)).await
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let full = self.resolve(name)?;
        let name = name.to_owned();
        blocking(move || match fs::read(&full) {
            Ok(data) => Ok(Bytes::from(data)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(StorageError::NotFound),
            Err(error) => Err(failed(&format!("failed to read {name}"), error)),
        })
        .await
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let full = self.resolve(name)?;
        let name = name.to_owned();
        blocking(move || {
            remove_all(&full).map_err(|error| failed(&format!("failed to delete {name}"), error))
        })
        .await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Entry>, StorageError> {
        let full = self.resolve(prefix)?;
        let prefix = prefix.to_owned();
        blocking(move || {
            let entries = match fs::read_dir(&full) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(error) => return Err(failed(&format!("failed to list {prefix}"), error)),
            };
            let mut names = Vec::new();
            for entry in entries {
                let entry =
                    entry.map_err(|error| failed(&format!("failed to list {prefix}"), error))?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with(TEMP_PREFIX) {
                    names.push(name);
                }
            }
            // os.ReadDir sorts by name.
            names.sort_unstable();
            Ok(names.into_iter().map(Entry::named).collect())
        })
        .await
    }
}

/// `Put`: write a temporary file beside the object, then rename it into
/// place, so a reader never sees half an object.
fn put_file(full: &Path, data: &[u8], name: &str) -> Result<(), StorageError> {
    let dir = full.parent().unwrap_or_else(|| Path::new("."));
    create_dirs(dir)
        .map_err(|error| failed(&format!("failed to create folder {}", dir.display()), error))?;
    let (tmp_path, mut tmp) = create_temp(dir).map_err(|error| {
        failed(
            &format!("failed to create temp file in {}", dir.display()),
            error,
        )
    })?;
    let result = (|| {
        tmp.write_all(data)
            .map_err(|error| failed(&format!("failed to write {name}"), error))?;
        drop(tmp);
        fs::rename(&tmp_path, full)
            .map_err(|error| failed(&format!("failed to commit {name}"), error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// `os.CreateTemp(dir, ".xdrive-tmp-*")`: a new file with a random number
/// in its name, readable by this user only.
fn create_temp(dir: &Path) -> io::Result<(PathBuf, fs::File)> {
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..10_000 {
        let path = dir.join(format!("{TEMP_PREFIX}{}", rand::random::<u32>()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

/// `os.MkdirAll(dir, 0o700)`.
fn create_dirs(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// `os.RemoveAll`: a file, or a folder with all it holds; a link is
/// removed, not followed; nothing there is fine.
fn remove_all(path: &Path) -> io::Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) => Err(error),
    };
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// The parts of Go's `path.Clean("/" + name)`: no empty or `.` part, and a
/// `..` takes the part before it away, never going above the root.
fn clean_rooted(name: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts
}

fn failed(context: &str, error: io::Error) -> StorageError {
    StorageError::Failed(format!("{context}: {error}"))
}

/// Runs a file operation off the runtime's threads.
async fn blocking<T, F>(operation: F) -> Result<T, StorageError>
where
    F: FnOnce() -> Result<T, StorageError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| StorageError::Failed(format!("file operation stopped: {error}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_clean_as_go_cleans_them() {
        assert_eq!(clean_rooted("sessions/1-ab"), ["sessions", "1-ab"]);
        assert_eq!(clean_rooted("a//b/./c/"), ["a", "b", "c"]);
        assert_eq!(clean_rooted("../../etc/passwd"), ["etc", "passwd"]);
        assert_eq!(clean_rooted("a/../../b"), ["b"]);
        assert!(clean_rooted("").is_empty());
        assert!(clean_rooted("/").is_empty());
        assert!(clean_rooted("a/..").is_empty());
    }

    #[tokio::test]
    async fn objects_round_trip_and_stay_inside_the_folder() {
        let dir = std::env::temp_dir().join(format!(
            "xdrive-local-{}",
            super::super::names::new_session_id()
        ));
        let storage = LocalStorage::open(dir.to_str().unwrap()).await.unwrap();
        storage
            .put("streams/s/c2s/000000000.seg", Bytes::from_static(b"one"))
            .await
            .unwrap();
        storage
            .put("streams/s/c2s/000000001.end", Bytes::new())
            .await
            .unwrap();
        assert_eq!(
            storage.get("streams/s/c2s/000000000.seg").await.unwrap(),
            Bytes::from_static(b"one")
        );
        assert_eq!(
            storage.list("streams/s/c2s").await.unwrap(),
            [Entry::named("000000000.seg"), Entry::named("000000001.end")]
        );
        assert_eq!(
            storage.list("streams/s").await.unwrap(),
            [Entry::named("c2s")]
        );
        assert_eq!(storage.list("streams/none").await.unwrap(), []);
        assert_eq!(
            storage.get("streams/s/c2s/9.seg").await,
            Err(StorageError::NotFound)
        );
        // A name cannot climb out of the folder.
        storage
            .put("../../escape", Bytes::from_static(b"x"))
            .await
            .unwrap();
        assert!(dir.join("escape").exists());
        assert!(storage.get("/").await.is_err());
        assert!(storage.put("a/.xdrive-tmp-1", Bytes::new()).await.is_err());
        // Temporary files are never listed.
        fs::write(dir.join("streams/s/c2s/.xdrive-tmp-9"), b"partial").unwrap();
        assert_eq!(storage.list("streams/s/c2s").await.unwrap().len(), 2);
        storage.delete("streams/s").await.unwrap();
        storage.delete("streams/s").await.unwrap();
        assert_eq!(storage.list("streams").await.unwrap(), []);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn an_empty_folder_is_refused() {
        assert_eq!(
            LocalStorage::open("").await.unwrap_err(),
            StorageError::Failed(r#"empty "remoteFolder""#.to_owned())
        );
    }
}
