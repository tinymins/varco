//! Client programs shipped in the server package, so someone who reaches the console
//! can get a client even when the website is out of reach. Open to anyone who can
//! reach the port: the login page lists them, and they hold nothing secret.
use super::{ApiError, ApiResult, Console};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::path::{Path as FilePath, PathBuf};
use std::sync::Arc;
use tokio_util::io::ReaderStream;

const SITE: &str = "https://lab.vmins.com/varco/";

/// The only names ever served, so a request can never name a path of its own.
const CLIENTS: [(&str, &str, &str); 8] = [
    ("varco-windows-x64.exe", "Windows", "x64"),
    ("varco-windows-arm64.exe", "Windows", "ARM64"),
    ("varco-macos-arm64.zip", "macOS", "Apple 芯片"),
    ("varco-macos-x64.zip", "macOS", "Intel"),
    ("varco-linux-gui-x64", "Linux 桌面", "x64"),
    ("varco-linux-gui-arm64", "Linux 桌面", "ARM64"),
    ("varco-linux-x64", "Linux 无界面", "x64"),
    ("varco-linux-arm64", "Linux 无界面", "ARM64"),
];

/// Beside the program when run from the unpacked package, and under `share` once
/// installed as /usr/local/bin/varco.
pub(super) fn default_dirs() -> Vec<PathBuf> {
    let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(FilePath::to_path_buf))
    else {
        return Vec::new();
    };
    vec![
        exe_dir.join("clients"),
        exe_dir.join("../share/varco/clients"),
    ]
}

async fn find(dirs: &[PathBuf], file: &str) -> Option<(PathBuf, u64)> {
    for dir in dirs {
        let path = dir.join(file);
        if let Ok(metadata) = tokio::fs::metadata(&path).await {
            if metadata.is_file() {
                return Some((path, metadata.len()));
            }
        }
    }
    None
}

#[derive(Serialize)]
pub struct Client {
    file: &'static str,
    platform: &'static str,
    arch: &'static str,
    size: u64,
}

#[derive(Serialize)]
pub struct Catalog {
    site: &'static str,
    version: &'static str,
    clients: Vec<Client>,
}

pub async fn catalog(State(console): State<Arc<Console>>) -> Json<Catalog> {
    let mut clients = Vec::new();
    for (file, platform, arch) in CLIENTS {
        if let Some((_, size)) = find(&console.client_dirs, file).await {
            clients.push(Client {
                file,
                platform,
                arch,
                size,
            });
        }
    }
    Json(Catalog {
        site: SITE,
        version: env!("CARGO_PKG_VERSION"),
        clients,
    })
}

/// Streamed: these run to tens of megabytes and anyone may ask for them at once.
pub async fn download(
    State(console): State<Arc<Console>>,
    Path(file): Path<String>,
) -> ApiResult<Response> {
    let not_found = || ApiError::new(StatusCode::NOT_FOUND, "没有这个文件");
    let (name, _, _) = CLIENTS
        .iter()
        .find(|(name, _, _)| *name == file)
        .ok_or_else(not_found)?;
    let (path, size) = find(&console.client_dirs, name)
        .await
        .ok_or_else(not_found)?;
    let opened = tokio::fs::File::open(path).await.map_err(|_| not_found())?;
    Ok((
        [
            (CONTENT_TYPE, "application/octet-stream".to_owned()),
            (CONTENT_LENGTH, size.to_string()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        Body::from_stream(ReaderStream::new(opened)),
    )
        .into_response())
}
