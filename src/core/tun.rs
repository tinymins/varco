//! The real virtual NIC. Only the interface address is configured, which gives
//! the mesh subnet route and nothing else: no default route, no DNS.
use super::engine::{Device, DeviceFactory, NetInfo};
use super::error::FailReason;
use std::io;

pub struct TunFactory;

pub struct TunDevice(tun_rs::AsyncDevice);

impl Device for TunDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf).await
    }
}

impl DeviceFactory for TunFactory {
    type Device = TunDevice;

    fn create(&self, net: &NetInfo) -> Result<TunDevice, FailReason> {
        let builder = tun_rs::DeviceBuilder::new()
            .ipv4(net.ip, net.prefix, None)
            .mtu(net.mtu);
        #[cfg(windows)]
        let builder = {
            let path = wintun::extract().map_err(|e| FailReason::DeviceFailed(e.to_string()))?;
            builder.description("varco").wintun_file(path)
        };
        builder.build_async().map(TunDevice).map_err(|error| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                FailReason::NoPrivilege
            } else {
                FailReason::DeviceFailed(error.to_string())
            }
        })
    }
}

/// The signed DLL travels inside the executable, keeping distribution to one file.
#[cfg(windows)]
mod wintun {
    use sha2::{Digest, Sha256};
    use std::io;

    #[cfg(target_arch = "x86_64")]
    const DLL: &[u8] = include_bytes!("../../vendor/wintun/amd64/wintun.dll");
    #[cfg(target_arch = "aarch64")]
    const DLL: &[u8] = include_bytes!("../../vendor/wintun/arm64/wintun.dll");

    pub fn extract() -> io::Result<String> {
        let tag: String = Sha256::digest(DLL)
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        // Under the per-user temp directory, which other standard users cannot
        // write to. The content hash is rechecked so a stale or altered copy
        // is replaced rather than loaded into this elevated process.
        let dir = std::env::temp_dir().join(format!("varco-{tag}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("wintun.dll");
        let intact = std::fs::read(&path).is_ok_and(|existing| existing == DLL);
        if !intact {
            std::fs::write(&path, DLL)?;
        }
        path.into_os_string()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "temp path is not valid UTF-8"))
    }
}
