//! The window. Holds no connection logic: it starts a backend and shows its state.
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use varco::core::backend::{self, Connection};
use varco::core::engine::{Phase, Status};
use varco::core::error::FailReason;
use varco::core::ssh::{self, store, SshService, SshState};
use varco::credential::Credential;

slint::include_modules!();

const REFRESH: Duration = Duration::from_millis(500);
const SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

const GREEN: slint::Color = slint::Color::from_rgb_u8(0x1a, 0x7f, 0x37);
const RED: slint::Color = slint::Color::from_rgb_u8(0xb4, 0x23, 0x18);
const AMBER: slint::Color = slint::Color::from_rgb_u8(0xb5, 0x47, 0x08);

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn traffic_line(total: u64, previous: u64, elapsed: Duration) -> SharedString {
    let per_second = total.saturating_sub(previous) as f64 / elapsed.as_secs_f64().max(0.001);
    format!(
        "{}   {}/s",
        format_bytes(total),
        format_bytes(per_second as u64)
    )
    .into()
}

/// Reflects the key field. A key that fails here cannot be switched on.
fn show_key_validity(app: &App, text: &str) {
    match store::parse_public_key(text) {
        Ok(_) => {
            app.set_ssh_key_valid(true);
            app.set_ssh_key_error(SharedString::new());
        }
        Err(error) => {
            app.set_ssh_key_valid(false);
            // An empty field is the normal starting point, not a mistake.
            let show = error != store::KeyError::Empty;
            app.set_ssh_key_error(if show {
                error.to_string().into()
            } else {
                SharedString::new()
            });
        }
    }
}

fn login_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_owned())
}

fn show_ssh(app: &App, service: &SshService) {
    let state = service.state.borrow().clone();
    match state {
        SshState::Off | SshState::Starting => {
            app.set_ssh_status("启动中…".into());
            app.set_ssh_status_color(AMBER);
            app.set_ssh_command(SharedString::new());
        }
        SshState::Listening { ip, connections } => {
            app.set_ssh_status(format!("● 已开启 · {connections} 个连接").into());
            app.set_ssh_status_color(GREEN);
            let command = format!("ssh -p {} {}@{ip}", ssh::PORT, login_name());
            app.set_ssh_command(command.into());
        }
        SshState::Error(message) => {
            app.set_ssh_status(message.into());
            app.set_ssh_status_color(RED);
            app.set_ssh_command(SharedString::new());
        }
    }
}

fn turn_ssh_off(app: &App, runtime: &Handle, slot: &mut Option<SshService>) {
    if let Some(service) = slot.take() {
        runtime.spawn(service.stop());
    }
    app.set_ssh_on(false);
    app.set_ssh_status(SharedString::new());
    app.set_ssh_command(SharedString::new());
    app.set_ssh_fingerprint(SharedString::new());
}

struct Session {
    connection: Connection,
    last_tx: u64,
    last_rx: u64,
    last_tick: Instant,
}

fn show_status(app: &App, status: &Status) {
    match &status.phase {
        Phase::Connected => {
            app.set_status_text("已连接".into());
            app.set_status_color(GREEN);
        }
        Phase::Reconnecting {
            attempt,
            retry_in_secs,
            last_error,
        } => {
            let text =
                format!("重连中（第 {attempt} 次，约 {retry_in_secs} 秒后重试）：{last_error}");
            app.set_status_text(text.into());
            app.set_status_color(AMBER);
        }
        _ => {}
    }
    if let Some(net) = &status.net {
        app.set_network(net.network.as_str().into());
        app.set_ip(net.ip.to_string().into());
        app.set_cidr(net.cidr().to_string().into());
        let rows: Vec<MemberRow> = status
            .members
            .iter()
            .map(|m| MemberRow {
                hostname: m.hostname.as_str().into(),
                ip: m.ip.to_string().into(),
                is_self: m.ip == net.ip,
            })
            .collect();
        app.set_members(ModelRc::new(VecModel::from(rows)));
    }
    app.set_latency(match status.rtt_ms {
        Some(ms) => format!("{ms} ms").into(),
        None => "—".into(),
    });
}

fn tick(app: &App, slot: &mut Option<Session>) {
    let Some(session) = slot.as_mut() else {
        return;
    };
    let status = session.connection.status.borrow().clone();
    let elapsed = session.last_tick.elapsed();
    let counters = &session.connection.counters;
    let (tx, rx) = (
        counters.tx_bytes.load(Ordering::Relaxed),
        counters.rx_bytes.load(Ordering::Relaxed),
    );
    app.set_upload(traffic_line(tx, session.last_tx, elapsed));
    app.set_download(traffic_line(rx, session.last_rx, elapsed));
    session.last_tx = tx;
    session.last_rx = rx;
    session.last_tick = Instant::now();

    match &status.phase {
        Phase::Connecting => {}
        Phase::Connected | Phase::Reconnecting { .. } => {
            app.set_busy(false);
            app.set_joined(true);
            show_status(app, &status);
        }
        Phase::Failed(reason) => {
            app.set_error_text(reason.to_string().into());
            app.set_busy(false);
            app.set_joined(false);
            *slot = None;
        }
        Phase::Stopped => {
            app.set_busy(false);
            app.set_joined(false);
            *slot = None;
        }
    }
}

/// `Err` means no window could be created, and the caller falls back to the CLI.
pub fn run(runtime: Handle) -> Result<(), slint::PlatformError> {
    // The software renderer is used everywhere: it needs no GPU, so remote
    // desktops and bare virtual machines behave the same as anything else.
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .select()?;

    let app = App::new()?;
    let session: Rc<RefCell<Option<Session>>> = Rc::default();

    let weak = app.as_weak();
    let confirm_session = session.clone();
    let confirm_runtime = runtime.clone();
    app.on_confirm(move |code| {
        let Some(app) = weak.upgrade() else {
            return;
        };
        let mut slot = confirm_session.borrow_mut();
        if slot.is_some() {
            return;
        }
        app.set_error_text(SharedString::new());
        let credential = match Credential::parse(&code) {
            Ok(credential) => credential,
            Err(_) => {
                app.set_error_text(FailReason::BadCredential.to_string().into());
                return;
            }
        };
        app.set_busy(true);
        let connection = if app.get_ssh_only() {
            backend::start_ssh_only(&confirm_runtime, credential)
        } else {
            backend::start(&confirm_runtime, credential)
        };
        *slot = Some(Session {
            connection,
            last_tx: 0,
            last_rx: 0,
            last_tick: Instant::now(),
        });
    });

    let disconnect_session = session.clone();
    app.on_disconnect(move || {
        if let Some(active) = disconnect_session.borrow().as_ref() {
            let _ = active.connection.stop.send(true);
        }
    });

    // The key is remembered; whether the server was on deliberately is not.
    if let Some(key) = store::Store::open_default()
        .ok()
        .and_then(|s| s.load_authorized_key())
    {
        show_key_validity(&app, &key);
        app.set_ssh_pubkey(key.into());
    }
    app.set_ssh_admin(ssh::shell_is_admin());
    let ssh_service: Rc<RefCell<Option<SshService>>> = Rc::default();

    let weak = app.as_weak();
    app.on_ssh_pubkey_edited(move |text| {
        if let Some(app) = weak.upgrade() {
            show_key_validity(&app, &text);
        }
    });

    let weak = app.as_weak();
    let toggle_session = session.clone();
    let toggle_service = ssh_service.clone();
    let toggle_runtime = runtime.clone();
    app.on_ssh_toggled(move |on| {
        let Some(app) = weak.upgrade() else {
            return;
        };
        let mut service = toggle_service.borrow_mut();
        if !on {
            turn_ssh_off(&app, &toggle_runtime, &mut service);
            return;
        }
        let session = toggle_session.borrow();
        let Some(active) = session.as_ref() else {
            app.set_ssh_on(false);
            return;
        };
        let key = app.get_ssh_pubkey();
        let saved = store::Store::open_default().and_then(|s| s.save_authorized_key(&key));
        let prepared = saved.and_then(|()| ssh::prepare(&key));
        match prepared {
            Ok((allowed, host_key)) => {
                let started = SshService::start(
                    &toggle_runtime,
                    allowed,
                    host_key,
                    active.connection.status.clone(),
                    active.connection.ssh_source.clone(),
                );
                app.set_ssh_fingerprint(started.host_fingerprint.as_str().into());
                show_ssh(&app, &started);
                *service = Some(started);
            }
            Err(error) => {
                app.set_ssh_on(false);
                app.set_ssh_key_error(error.to_string().into());
            }
        }
    });

    let weak = app.as_weak();
    let tick_session = session.clone();
    let tick_service = ssh_service.clone();
    let tick_runtime = runtime.clone();
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, REFRESH, move || {
        if let Some(app) = weak.upgrade() {
            tick(&app, &mut tick_session.borrow_mut());
            let mut service = tick_service.borrow_mut();
            // Leaving the network takes the server with it.
            if tick_session.borrow().is_none() {
                turn_ssh_off(&app, &tick_runtime, &mut service);
            } else if let Some(service) = service.as_ref() {
                show_ssh(&app, service);
            }
        }
    });

    app.run()?;

    // Sessions end first, while the network they run over still exists.
    if let Some(service) = ssh_service.borrow_mut().take() {
        runtime.block_on(async {
            let _ = tokio::time::timeout(SHUTDOWN_WAIT, service.stop()).await;
        });
    }
    // Closing the window disconnects. Waiting lets the NIC go away cleanly.
    if let Some(mut active) = session.borrow_mut().take() {
        let _ = active.connection.stop.send(true);
        runtime.block_on(async {
            let finished = active
                .connection
                .status
                .wait_for(|s| matches!(s.phase, Phase::Stopped | Phase::Failed(_)));
            let _ = tokio::time::timeout(SHUTDOWN_WAIT, finished).await;
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_human_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(8 * 1024 * 1024), "8.0 MB");
    }
}
