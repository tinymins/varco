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
use varco::credential::Credential;

slint::include_modules!();

const REFRESH: Duration = Duration::from_millis(500);
const SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

const GREEN: slint::Color = slint::Color::from_rgb_u8(0x1a, 0x7f, 0x37);
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
        *slot = Some(Session {
            connection: backend::start(&confirm_runtime, credential),
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

    let weak = app.as_weak();
    let tick_session = session.clone();
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, REFRESH, move || {
        if let Some(app) = weak.upgrade() {
            tick(&app, &mut tick_session.borrow_mut());
        }
    });

    app.run()?;

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
