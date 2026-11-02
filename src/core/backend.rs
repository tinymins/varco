//! One way for front ends to start a connection, wherever the NIC ends up living:
//! in this process when it has the rights, otherwise in an elevated helper.
use super::engine::{self, Counters, DeviceFactory, Status};
use super::netstack::NetstackFactory;
use super::ssh::ListenSource;
use super::tun::TunFactory;
use crate::credential::Credential;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::watch;

pub struct Connection {
    pub status: watch::Receiver<Status>,
    pub counters: Arc<Counters>,
    pub stop: watch::Sender<bool>,
    pub ssh_source: ListenSource,
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

pub fn start_in_process(runtime: &Handle, credential: Credential) -> Connection {
    spawn_engine(runtime, credential, TunFactory, ListenSource::Os)
}

/// Joins without a virtual NIC, so no rights are needed and the system's network
/// configuration is never touched. The only service offered is the SSH server.
pub fn start_ssh_only(runtime: &Handle, credential: Credential) -> Connection {
    let (factory, endpoint) = NetstackFactory::new();
    spawn_engine(runtime, credential, factory, ListenSource::Mesh(endpoint))
}

fn spawn_engine(
    runtime: &Handle,
    credential: Credential,
    factory: impl DeviceFactory,
    ssh_source: ListenSource,
) -> Connection {
    let (status_tx, status) = watch::channel(Status::default());
    let (stop, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    runtime.spawn(engine::run(
        credential,
        hostname(),
        factory,
        status_tx,
        counters.clone(),
        stop_rx,
    ));
    Connection {
        status,
        counters,
        stop,
        ssh_source,
    }
}

/// Used by the GUI, which on Unix runs as the ordinary user.
pub fn start(runtime: &Handle, credential: Credential) -> Connection {
    #[cfg(unix)]
    if !super::helper::is_root() {
        return super::helper::start_elevated(runtime, credential);
    }
    start_in_process(runtime, credential)
}
