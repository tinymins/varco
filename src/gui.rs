//! The window. Holds no connection logic: it starts a backend and shows its state.
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use varco::core::backend::{self, Connection};
use varco::core::engine::{Phase, Status};
use varco::core::ssh::{self, store, SshService, SshState};
use varco::credential::compose;
use varco::launch::Launch;

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

fn show_ssh(app: &App, service: &SshService) {
    let state = service.state.borrow().clone();
    match state {
        SshState::Off | SshState::Starting => {
            app.set_ssh_status("启动中…".into());
            app.set_ssh_status_color(AMBER);
            app.set_ssh_command(SharedString::new());
        }
        SshState::Listening {
            ip,
            connections,
            user,
        } => {
            app.set_ssh_status(format!("● 已开启 · {connections} 个连接").into());
            app.set_ssh_status_color(GREEN);
            app.set_ssh_admin(ssh::shell_is_admin(&user));
            let command = format!("ssh -p {} {user}@{ip}", ssh::PORT);
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
    app.set_ssh_configured_key(SharedString::new());
}

struct Session {
    connection: Connection,
    /// The key this connection was started with: used, and never remembered.
    package_key: Option<String>,
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

/// A Code that also hands over control looks like any other, so the window says
/// so before it is confirmed.
fn show_code_effect(app: &App, settings: &Launch, ticked_for_key: &Cell<bool>, code: &str) {
    let credential = settings.credential(code).ok();
    let key = credential
        .as_ref()
        .and_then(|credential| settings.granted_key(credential))
        .and_then(|key| store::parse_public_key(&key).ok());
    app.set_code_grant(match &key {
        Some(key) => store::fingerprint(key).into(),
        None => SharedString::new(),
    });
    if settings.ssh_only_explicit {
        return;
    }
    let wanted = credential
        .as_ref()
        .is_some_and(|credential| settings.ssh_only_for(credential));
    if wanted && !app.get_ssh_only() {
        app.set_ssh_only(true);
        ticked_for_key.set(true);
    } else if !wanted && ticked_for_key.replace(false) {
        app.set_ssh_only(false);
    }
}

fn show_compose_result(app: &App) {
    let code = app.get_compose_code();
    let key = app.get_compose_key();
    app.set_copied(false);
    if code.trim().is_empty() || key.trim().is_empty() {
        app.set_compose_result(SharedString::new());
        app.set_compose_info(SharedString::new());
        app.set_compose_error(SharedString::new());
        return;
    }
    match compose(&code, &key) {
        Ok(composed) => {
            let replaced = if composed.replaced_key {
                "，已替换原公钥"
            } else {
                ""
            };
            app.set_compose_result(composed.code.into());
            app.set_compose_info(
                format!(
                    "服务端 {} · 公钥 {}{replaced}",
                    composed.server, composed.key_fingerprint
                )
                .into(),
            );
            app.set_compose_error(SharedString::new());
        }
        Err(error) => {
            app.set_compose_result(SharedString::new());
            app.set_compose_info(SharedString::new());
            app.set_compose_error(error.to_string().into());
        }
    }
}

/// Where most people's key already is. Only a file that holds a valid public key
/// is offered, and nothing else in that folder is touched.
fn default_public_key() -> Option<String> {
    let path = dirs::home_dir()?.join(".ssh").join("id_ed25519.pub");
    let text = std::fs::read_to_string(path).ok()?;
    store::parse_public_key(&text).ok()?;
    Some(text.trim().to_owned())
}

/// Whether the key in the field came with the package rather than from this window.
fn is_configured_key(configured: Option<&str>, key: &str) -> bool {
    configured.is_some_and(|configured| configured.trim() == key.trim())
}

/// A key that came with the package is only used, never remembered, so deleting
/// the package's settings really does end its access.
fn start_ssh(
    app: &App,
    runtime: &Handle,
    connection: &Connection,
    configured: Option<&str>,
) -> Option<SshService> {
    let key = app.get_ssh_pubkey();
    let from_package = is_configured_key(configured, &key);
    let saved = if from_package {
        Ok(())
    } else {
        store::Store::open_default().and_then(|s| s.save_authorized_key(&key))
    };
    match saved.and_then(|()| ssh::prepare(&key)) {
        Ok((allowed, host_key)) => {
            let shown_key = from_package.then(|| store::fingerprint(&allowed));
            let started = connection.start_ssh(runtime, allowed, host_key);
            app.set_ssh_on(true);
            app.set_ssh_fingerprint(started.host_fingerprint.as_str().into());
            app.set_ssh_configured_key(shown_key.unwrap_or_default().into());
            show_ssh(app, &started);
            Some(started)
        }
        Err(error) => {
            app.set_ssh_on(false);
            app.set_ssh_key_error(error.to_string().into());
            None
        }
    }
}

/// Windows can discard what a window showed, for example around a locked session,
/// and asks for it back with `WM_PAINT`. Slint's software renderer then presents only
/// what it knows has changed, usually nothing, and the rest stays empty.
#[cfg(windows)]
mod os_repaint {
    use super::App;
    use slint::winit_030::winit::{
        event_loop::EventLoop, platform::windows::EventLoopBuilderExtWindows,
    };
    use slint::winit_030::EventLoopBuilder;
    use slint::BackendSelector;
    use std::{cell::RefCell, ptr, rc::Rc};
    use windows_sys::Win32::Graphics::Gdi::GetUpdateRect;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MSG, WM_PAINT};

    /// The returned slot receives the window once it exists.
    pub fn install(selector: BackendSelector) -> (BackendSelector, Rc<RefCell<slint::Weak<App>>>) {
        let target: Rc<RefCell<slint::Weak<App>>> = Rc::default();
        let hook_target = target.clone();
        let mut event_loop: EventLoopBuilder = EventLoop::with_user_event();
        event_loop.with_msg_hook(move |message| {
            // SAFETY: winit passes a valid MSG, alive for the duration of this call.
            let message = unsafe { &*message.cast::<MSG>() };
            // Slint's own redraw requests carry no update region, so this cannot feed itself.
            let lost_pixels = message.message == WM_PAINT
                && unsafe { GetUpdateRect(message.hwnd, ptr::null_mut(), 0) } != 0;
            if lost_pixels {
                if let Some(app) = hook_target.borrow().upgrade() {
                    app.set_repaint_phase(!app.get_repaint_phase());
                }
            }
            false
        });
        // An opaque window shows an unpainted area as black, never the desktop behind it.
        let selector = selector
            .with_winit_event_loop_builder(event_loop)
            .with_winit_window_attributes_hook(|attributes| attributes.with_transparent(false));
        (selector, target)
    }
}

/// `Err` means no window could be created, and the caller falls back to the CLI.
pub fn run(runtime: Handle, launch: &Launch) -> Result<(), slint::PlatformError> {
    // The software renderer is used everywhere: it needs no GPU, so remote
    // desktops and bare virtual machines behave the same as anything else.
    let selector = slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into());
    #[cfg(windows)]
    let (selector, repaint_target) = os_repaint::install(selector);
    selector.select()?;

    let app = App::new()?;
    #[cfg(windows)]
    {
        *repaint_target.borrow_mut() = app.as_weak();
    }
    let session: Rc<RefCell<Option<Session>>> = Rc::default();
    let ssh_service: Rc<RefCell<Option<SshService>>> = Rc::default();
    let settings = Rc::new(Launch {
        problem: None,
        ..launch.clone()
    });
    let ticked_for_key = Rc::new(Cell::new(false));

    let weak = app.as_weak();
    let edit_settings = settings.clone();
    let edit_ticked = ticked_for_key.clone();
    app.on_code_edited(move |code| {
        if let Some(app) = weak.upgrade() {
            show_code_effect(&app, &edit_settings, &edit_ticked, &code);
        }
    });

    let weak = app.as_weak();
    app.on_compose_opened(move || {
        let Some(app) = weak.upgrade() else {
            return;
        };
        if app.get_compose_code().is_empty() {
            app.set_compose_code(app.get_code());
        }
        if app.get_compose_key().is_empty() {
            let key = store::Store::open_default()
                .ok()
                .and_then(|s| s.load_authorized_key())
                .or_else(default_public_key);
            app.set_compose_key(key.unwrap_or_default().into());
        }
        show_compose_result(&app);
    });

    let weak = app.as_weak();
    app.on_compose_edited(move || {
        if let Some(app) = weak.upgrade() {
            show_compose_result(&app);
        }
    });

    let weak = app.as_weak();
    let confirm_session = session.clone();
    let confirm_service = ssh_service.clone();
    let confirm_runtime = runtime.clone();
    let confirm_settings = settings.clone();
    app.on_confirm(move |code| {
        let Some(app) = weak.upgrade() else {
            return;
        };
        let mut slot = confirm_session.borrow_mut();
        if slot.is_some() {
            return;
        }
        app.set_error_text(SharedString::new());
        let credential = match confirm_settings.credential(&code) {
            Ok(credential) => credential,
            Err(message) => {
                app.set_error_text(message.into());
                return;
            }
        };
        let package_key = confirm_settings.granted_key(&credential);
        app.set_busy(true);
        let connection = backend::start(&confirm_runtime, credential, app.get_ssh_only());
        // Also on a retry: the server stops with every connection that fails.
        if let Some(key) = &package_key {
            show_key_validity(&app, key);
            app.set_ssh_pubkey(key.as_str().into());
            *confirm_service.borrow_mut() =
                start_ssh(&app, &confirm_runtime, &connection, Some(key));
        }
        *slot = Some(Session {
            connection,
            package_key,
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
    if let Some(key) = &settings.ssh_pubkey {
        show_key_validity(&app, key);
        app.set_ssh_pubkey(key.as_str().into());
    }
    app.set_ssh_only(settings.ssh_only);
    // What SSH runs as unless elevation is refused; once it listens, the
    // account it actually runs as decides.
    app.set_ssh_admin(true);

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
        *service = start_ssh(
            &app,
            &toggle_runtime,
            &active.connection,
            active.package_key.as_deref(),
        );
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

    // Everything above is wired up, so this behaves exactly like a person clicking.
    if let Some(code) = &settings.code {
        app.set_code(code.as_str().into());
        show_code_effect(&app, &settings, &ticked_for_key, code);
    }
    let key_is_usable = settings
        .ssh_pubkey
        .as_deref()
        .is_none_or(|key| store::parse_public_key(key).is_ok());
    if let Some(problem) = &launch.problem {
        app.set_error_text(problem.as_str().into());
    } else if !key_is_usable {
        app.set_error_text("启动配置里的 SSH 公钥无效".into());
    } else if let Some(code) = &settings.code {
        app.invoke_confirm(code.as_str().into());
    }

    // Closing the window only hides it: the connection carries on until the
    // tray's quit.
    let tray = Tray::new()?;
    let weak = app.as_weak();
    tray.on_show_window(move || {
        if let Some(app) = weak.upgrade() {
            let _ = app.show();
        }
    });
    tray.on_quit(|| {
        let _ = slint::quit_event_loop();
    });
    app.window()
        .on_close_requested(|| slint::CloseRequestResponse::HideWindow);
    app.show()?;
    tray.show()?;
    slint::run_event_loop_until_quit()?;

    // Sessions end first, while the network they run over still exists.
    if let Some(service) = ssh_service.borrow_mut().take() {
        runtime.block_on(async {
            let _ = tokio::time::timeout(SHUTDOWN_WAIT, service.stop()).await;
        });
    }
    // Quitting disconnects. Waiting lets the NIC go away cleanly.
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

    /// Renders the real window the way the winit backend does on Windows: into a
    /// buffer it reuses, presenting only the region the renderer returns.
    #[test]
    fn flipping_the_repaint_phase_redraws_the_whole_window() {
        use slint::platform::software_renderer::{
            MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType,
        };
        use slint::platform::{Platform, WindowAdapter};
        use slint::PhysicalSize;

        struct TestPlatform(Rc<MinimalSoftwareWindow>);
        impl Platform for TestPlatform {
            fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
                Ok(self.0.clone())
            }
        }

        const WIDTH: usize = 400;
        const HEIGHT: usize = 560;
        let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
        slint::platform::set_platform(Box::new(TestPlatform(window.clone()))).unwrap();
        let app = App::new().unwrap();
        window.set_size(PhysicalSize::new(WIDTH as u32, HEIGHT as u32));
        app.show().unwrap();

        let mut pixels = vec![PremultipliedRgbaColor::default(); WIDTH * HEIGHT];
        let mut painted = |window: &MinimalSoftwareWindow| {
            let mut area = 0;
            window.draw_if_needed(|renderer| {
                let region = renderer.render(&mut pixels, WIDTH);
                area = region
                    .iter()
                    .map(|(_, size)| size.width as usize * size.height as usize)
                    .sum();
            });
            area
        };

        assert_eq!(painted(&window), WIDTH * HEIGHT, "the first frame");
        // What the OS gets when it asks for a repaint without this fix.
        window.request_redraw();
        assert_eq!(
            painted(&window),
            0,
            "nothing changed, so nothing is presented"
        );

        app.set_repaint_phase(true);
        assert_eq!(
            painted(&window),
            WIDTH * HEIGHT,
            "the whole window comes back"
        );
    }
}
