//! One way for front ends to start a connection, wherever the NIC ends up living:
//! in this process when it has the rights, otherwise in an elevated helper.
use super::engine::{self, Counters, DeviceFactory, Status};
use super::netstack::NetstackFactory;
use super::ssh::{ListenSource, SshService};
use super::tun::TunFactory;
use crate::credential::Credential;
use russh::keys::{PrivateKey, PublicKey};
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::watch;

pub struct Connection {
    pub status: watch::Receiver<Status>,
    pub counters: Arc<Counters>,
    pub stop: watch::Sender<bool>,
    pub(crate) ssh: SshHost,
}

/// Where the SSH server runs: next to the connection, wherever that is.
pub(crate) enum SshHost {
    InProcess(ListenSource),
    #[cfg(unix)]
    Helper(super::helper::SshLink),
}

impl Connection {
    /// Follows the mesh address until stopped.
    pub fn start_ssh(
        &self,
        runtime: &Handle,
        allowed: PublicKey,
        host_key: PrivateKey,
    ) -> SshService {
        match &self.ssh {
            SshHost::InProcess(source) => SshService::start(
                runtime,
                allowed,
                host_key,
                self.status.clone(),
                source.clone(),
            ),
            #[cfg(unix)]
            SshHost::Helper(link) => link.start(allowed, &host_key),
        }
    }
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

pub fn start_in_process(runtime: &Handle, credential: Credential) -> Connection {
    spawn_engine(runtime, credential, TunFactory)
}

/// Joins without a virtual NIC, so no rights are needed and the system's network
/// configuration is never touched. The only service offered is the SSH server.
pub fn start_ssh_only(runtime: &Handle, credential: Credential) -> Connection {
    spawn_engine(runtime, credential, NetstackFactory::new().0)
}

fn spawn_engine(
    runtime: &Handle,
    credential: Credential,
    factory: impl DeviceFactory,
) -> Connection {
    let (status_tx, status) = watch::channel(Status::default());
    let (stop, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let ssh = SshHost::InProcess(factory.ssh_source());
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
        ssh,
    }
}

/// Used by the GUI, which on Unix runs as the ordinary user: the connection and
/// the SSH server then live in an elevated helper, so remote shells are root.
pub fn start(runtime: &Handle, credential: Credential, ssh_only: bool) -> Connection {
    #[cfg(unix)]
    if !super::helper::is_root() {
        return super::helper::start_elevated(runtime, credential, ssh_only);
    }
    if ssh_only {
        start_ssh_only(runtime, credential)
    } else {
        start_in_process(runtime, credential)
    }
}
