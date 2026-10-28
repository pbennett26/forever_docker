mod api;
mod config;
// macOS: only the entropy is used (see macos.rs); the rest is kept for its tests
#[cfg_attr(target_os = "macos", allow(dead_code))]
mod dpapi;
mod game;
mod i18n;
#[cfg(target_os = "macos")]
mod macos;
// macOS: no external memory patch (see macos.rs); kept for its tests
#[cfg_attr(target_os = "macos", allow(dead_code))]
mod patcher;
mod system;

use config::{Session, Settings};
use i18n::{t, tf};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
#[cfg(not(target_os = "macos"))]
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

#[cfg(windows)]
pub use system::admin_setup;

struct AppState {
    settings: Mutex<Settings>,
    playing: AtomicBool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    settings: Settings,
    email: Option<String>,
    platform: &'static str,
    version: &'static str,
    locales: &'static [&'static str],
    runners: Vec<(String, String)>,
    game_found: bool,
    game_version: Option<String>,
    playing: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GameEvent {
    kind: &'static str,
    message: String,
}

fn emit(app: &AppHandle, kind: &'static str, message: impl Into<String>) {
    let _ = app.emit("game", GameEvent { kind, message: message.into() });
}

fn runners() -> Vec<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        let mut r = system::list_protons();
        r.push((t("wine_system").into(), "wine".into()));
        r
    }
    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

#[tauri::command]
fn get_state(state: State<AppState>) -> Snapshot {
    let settings = state.settings.lock().unwrap().clone();
    Snapshot {
        game_found: settings.game_found(),
        game_version: config::installed_version(std::path::Path::new(&settings.game_dir)),
        email: Session::load().map(|s| s.email),
        platform: if cfg!(windows) { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" },
        version: env!("CARGO_PKG_VERSION"),
        locales: config::LOCALES,
        runners: runners(),
        playing: state.playing.load(Ordering::SeqCst),
        settings,
    }
}

#[tauri::command]
fn save_settings(state: State<AppState>, settings: Settings) -> Result<(), String> {
    let mut settings = settings;
    if settings.server.portal.is_empty() {
        settings.server = Default::default();
    }
    settings.save().map_err(|e| e.to_string())?;
    *state.settings.lock().unwrap() = settings;
    Ok(())
}

/// Language of the messages sent by the Rust side (the UI resolves "system language" itself).
#[tauri::command]
fn set_language(language: String) {
    i18n::set(&language);
}

/// Language installed with the client in that folder (to preselect it).
#[tauri::command]
fn detect_locale(game_dir: String) -> Option<String> {
    config::installed_locale(std::path::Path::new(&game_dir))
}

#[tauri::command]
async fn login(state: State<'_, AppState>, email: String, password: String) -> Result<String, String> {
    let server = state.settings.lock().unwrap().server.clone();
    let api = api::Api::new(&server).await?;
    let ticket = api.login(email.trim(), &password).await?;
    let token = api.remember(&ticket).await?;
    let check = api.launcher_login(&token.token).await?;
    Session { email: check.email.clone(), token: token.token, expires: token.expires }
        .save()
        .map_err(|e| tf("session_save", &[&e]))?;
    Ok(check.email.to_lowercase())
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(s) = Session::load() {
        let server = state.settings.lock().unwrap().server.clone();
        if let Ok(api) = api::Api::new(&server).await {
            api.forget(&s.token).await;
        }
    }
    Session::clear();
    Ok(())
}

#[derive(Serialize)]
struct Status {
    online: bool,
    login: bool,
}

#[tauri::command]
async fn server_status(state: State<'_, AppState>) -> Result<Status, String> {
    let s = state.settings.lock().unwrap().server.clone();
    let (world, bnet) = tokio::join!(api::port_open(&s.address, s.world_port), api::port_open(&s.address, s.bnet_port));
    Ok(Status { online: world, login: bnet })
}

#[tauri::command]
async fn news(state: State<'_, AppState>) -> Result<Vec<api::NewsItem>, String> {
    let website = state.settings.lock().unwrap().server.website.clone();
    if website.is_empty() {
        return Ok(Vec::new());
    }
    api::news(&website).await
}

#[tauri::command]
async fn checks(state: State<'_, AppState>) -> Result<system::Checks, String> {
    let settings = state.settings.lock().unwrap().clone();
    tokio::task::spawn_blocking(move || system::check(&settings)).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn repair(state: State<'_, AppState>) -> Result<system::Checks, String> {
    let settings = state.settings.lock().unwrap().clone();
    tokio::task::spawn_blocking(move || {
        system::repair(&settings)?;
        Ok(system::check(&settings))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn play(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if state.playing.swap(true, Ordering::SeqCst) {
        return Err(t("already_running").into());
    }
    let settings = state.settings.lock().unwrap().clone();
    let result = start(&app, settings).await;
    if result.is_err() {
        state.playing.store(false, Ordering::SeqCst);
    }
    result
}

async fn start(app: &AppHandle, settings: Settings) -> Result<(), String> {
    if !settings.game_found() {
        return Err(t("game_not_found").into());
    }
    let session = Session::load().ok_or(t("login_first"))?;
    emit(app, "step", t("step_connecting"));
    let api = api::Api::new(&settings.server).await?;
    let login = match api.launcher_login(&session.token).await {
        Err(e) if e == "expired" => {
            Session::clear();
            return Err(t("session_expired").into());
        }
        other => other?,
    };

    emit(app, "step", t("step_preparing"));
    let s = settings.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        game::write_wtf(&s)?;
        #[cfg(target_os = "linux")]
        system::install_ca_in_prefix(&s)?;
        let account = login.game_accounts.first().map(|a| a.name.clone()).unwrap_or_else(|| "WoW1".into());
        let portal = format!("{}:{}", s.server.portal, s.server.bnet_port);
        #[cfg(not(target_os = "macos"))]
        game::write_launch_options(&s, &portal, &login.login_ticket, &account)?;
        #[cfg(target_os = "macos")]
        macos::write_launch_options(&portal, &login.login_ticket, &account)?;
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())??;
    launch(app, settings).await
}

/// macOS: re-signed copy of the game with keypatch.dylib, followed through the library's log.
#[cfg(target_os = "macos")]
async fn launch(app: &AppHandle, settings: Settings) -> Result<(), String> {
    let (a, s) = (app.clone(), settings.clone());
    let copy = tokio::task::spawn_blocking(move || macos::prepare_copy(&s, |m| emit(&a, "step", m)))
        .await
        .map_err(|e| e.to_string())??;
    emit(app, "step", t("step_launching"));
    let (child, log) = macos::spawn(&settings, &copy)?;
    let app = app.clone();
    std::thread::spawn(move || {
        emit(&app, "running", t("running"));
        match macos::watch(child, &log, |kind, m| emit(&app, kind, m)) {
            Ok(()) => emit(&app, "closed", t("closed")),
            Err(e) => emit(&app, "error", e),
        }
        app.state::<AppState>().playing.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// Windows, Linux: the game is started, then the patcher writes the key into its memory.
#[cfg(not(target_os = "macos"))]
async fn launch(app: &AppHandle, settings: Settings) -> Result<(), String> {
    emit(app, "step", t("step_launching"));
    let patcher = patcher::Patcher::new(&settings.server.public_key, settings.server.region_group)?;
    let mut child = game::spawn(&settings)?;
    let app = app.clone();
    std::thread::spawn(move || {
        // reap the started process (on Linux it is umu-run / gamescope, which may exit early)
        let child_pid = child.id();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        let first = wait_for_client(child_pid);
        match first {
            Some(mem) => {
                emit(&app, "running", t("running"));
                patcher.watch(
                    Box::new(mem),
                    |cur| {
                        let other = patcher::find_client()?;
                        let better = !cur.alive() || other.rss() > (current_rss(cur) * 2).max(50 * 1024);
                        (other_pid(&other) != cur.pid() && better).then(|| Box::new(other) as Box<dyn patcher::Memory>)
                    },
                    |ev| match ev {
                        patcher::Event::Log(m) => emit(&app, "log", m),
                        patcher::Event::Ready => emit(&app, "ready", t("ready")),
                        patcher::Event::Closed => {}
                    },
                );
                emit(&app, "closed", t("closed"));
            }
            None => emit(&app, "error", t("not_started")),
        }
        app.state::<AppState>().playing.store(false, Ordering::SeqCst);
    });
    Ok(())
}

use tauri::Manager;

#[cfg(not(target_os = "macos"))]
fn other_pid(m: &patcher::ProcessMemory) -> u32 {
    use patcher::Memory;
    m.pid()
}

#[cfg(not(target_os = "macos"))]
fn current_rss(m: &dyn patcher::Memory) -> u64 {
    patcher::ProcessMemory::open(m.pid()).map(|p| p.rss()).unwrap_or(0)
}

#[cfg(not(target_os = "macos"))]
fn wait_for_client(_child_pid: u32) -> Option<patcher::ProcessMemory> {
    // Always select the actual WowB.exe process. Do not assume the process
    // returned by Command::spawn is the process whose memory contains the key store.
    for _ in 0..180 {
        if let Some(m) = patcher::find_client() {
            return Some(m);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState { settings: Mutex::new(Settings::load()), playing: AtomicBool::new(false) })
        .invoke_handler(tauri::generate_handler![
            get_state, save_settings, set_language, detect_locale, login, logout, server_status, news, checks, repair, play
        ])
        .run(tauri::generate_context!())
        .expect("error while running Forever Launcher");
}
