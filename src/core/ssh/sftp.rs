//! SFTP, for `scp` and `sftp`. Paths mean what they mean on this machine; on
//! Windows, clients see `/C:/Users/name` in the usual SFTP convention.
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const MAX_READ: u32 = 256 * 1024;
const MAX_OPEN_HANDLES: usize = 256;
const DIR_BATCH: usize = 128;

enum Open {
    File(tokio::fs::File),
    Dir(Vec<File>),
}

pub struct SftpSession {
    handles: HashMap<String, Open>,
    next_handle: u64,
    home: PathBuf,
}

impl SftpSession {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_handle: 0,
            home: dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
        }
    }

    fn add(&mut self, open: Open) -> Result<String, StatusCode> {
        if self.handles.len() >= MAX_OPEN_HANDLES {
            return Err(StatusCode::Failure);
        }
        self.next_handle += 1;
        let handle = self.next_handle.to_string();
        self.handles.insert(handle.clone(), open);
        Ok(handle)
    }

    /// Relative paths start from the home directory, as they do under sshd.
    fn local(&self, remote: &str) -> PathBuf {
        let path = PathBuf::from(from_wire(remote));
        if path.is_absolute() {
            path
        } else {
            self.home.join(path)
        }
    }
}

fn from_wire(remote: &str) -> String {
    if cfg!(windows) {
        // `/C:/x` is `C:/x`.
        let bytes = remote.as_bytes();
        if bytes.len() >= 3
            && bytes[0] == b'/'
            && bytes[1].is_ascii_alphabetic()
            && bytes[2] == b':'
        {
            return remote[1..].to_owned();
        }
    }
    remote.to_owned()
}

fn to_wire(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        let text = text
            .strip_prefix(r"\\?\")
            .unwrap_or(&text)
            .replace('\\', "/");
        return if text.starts_with('/') {
            text
        } else {
            format!("/{text}")
        };
    }
    text.into_owned()
}

/// Removes `.` and `..` without touching the disk, for paths that do not exist
/// yet, such as the destination of an upload.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn status_code(error: std::io::Error) -> StatusCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_owned(),
        language_tag: "en-US".to_owned(),
    }
}

#[cfg(unix)]
async fn apply_mode(path: &Path, attrs: &FileAttributes) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = attrs.permissions {
        let permissions = std::fs::Permissions::from_mode(mode & 0o7777);
        tokio::fs::set_permissions(path, permissions).await?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn apply_mode(_path: &Path, _attrs: &FileAttributes) -> std::io::Result<()> {
    Ok(())
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.local(&filename);
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut options = tokio::fs::OpenOptions::from(std::fs::OpenOptions::from(pflags));
        #[cfg(unix)]
        if let Some(mode) = attrs.permissions {
            options.mode(mode & 0o7777);
        }
        #[cfg(not(unix))]
        let _ = &attrs;
        let file = options.open(&path).await.map_err(status_code)?;
        let handle = self.add(Open::File(file))?;
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        match self.handles.remove(&handle) {
            Some(Open::File(mut file)) => {
                file.flush().await.map_err(status_code)?;
                Ok(ok(id))
            }
            Some(Open::Dir(_)) => Ok(ok(id)),
            None => Err(StatusCode::Failure),
        }
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(Open::File(file)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(status_code)?;
        let mut data = vec![0u8; len.min(MAX_READ) as usize];
        let n = file.read(&mut data).await.map_err(status_code)?;
        if n == 0 && !data.is_empty() {
            return Err(StatusCode::Eof);
        }
        data.truncate(n);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(Open::File(file)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(status_code)?;
        file.write_all(&data).await.map_err(status_code)?;
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = tokio::fs::metadata(self.local(&path))
            .await
            .map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = tokio::fs::symlink_metadata(self.local(&path))
            .await
            .map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(file)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let meta = file.metadata().await.map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&meta),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        apply_mode(&self.local(&path), &attrs)
            .await
            .map_err(status_code)?;
        Ok(ok(id))
    }

    // Accepted so `scp -p` and friends do not fail outright; only the mode set
    // at open time and by setstat is honoured.
    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut dir = tokio::fs::read_dir(self.local(&path))
            .await
            .map_err(status_code)?;
        let mut files = Vec::new();
        while let Some(entry) = dir.next_entry().await.map_err(status_code)? {
            if let Ok(meta) = entry.metadata().await {
                let name = entry.file_name().to_string_lossy().into_owned();
                files.push(File::new(name, FileAttributes::from(&meta)));
            }
        }
        let handle = self.add(Open::Dir(files))?;
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir(files)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        if files.is_empty() {
            return Err(StatusCode::Eof);
        }
        let start = files.len().saturating_sub(DIR_BATCH);
        Ok(Name {
            id,
            files: files.split_off(start),
        })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(self.local(&filename))
            .await
            .map_err(status_code)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.local(&path);
        tokio::fs::create_dir(&path).await.map_err(status_code)?;
        apply_mode(&path, &attrs).await.map_err(status_code)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_dir(self.local(&path))
            .await
            .map_err(status_code)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let local = self.local(&path);
        let resolved = tokio::fs::canonicalize(&local)
            .await
            .unwrap_or_else(|_| normalize(&local));
        Ok(Name {
            id,
            files: vec![File::dummy(to_wire(&resolved))],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        tokio::fs::rename(self.local(&oldpath), self.local(&newpath))
            .await
            .map_err(status_code)?;
        Ok(ok(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handles_dots_without_escaping_the_root() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/../x")), PathBuf::from("/x"));
    }
}
