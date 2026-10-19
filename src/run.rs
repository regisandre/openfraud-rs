//! `openfraud serve`: opens the engine on its database, starts the API and
//! the admin listeners, and runs the background work: the outbox (webhooks,
//! alerts, module actions), alert digests, list downloads and retention.

use crate::config::Config;
use crate::engine::Engine;
use crate::event::now;
use crate::keys::{KeySet, LiveKeys, State};
use crate::outbox::{Workers, run_outbox};
use crate::server::{App, admin_router, api_router};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How often the outbox is read.
const OUTBOX_EVERY: Duration = Duration::from_secs(2);
/// How often digests, lists and retention are looked at.
const MAINTENANCE_EVERY: u64 = 60;

/// Watches the configuration file: an edit made by hand is applied
/// without a restart, and a broken edit is reported once while the running
/// configuration stays.
pub struct Watch {
    path: PathBuf,
    seen: Option<std::time::SystemTime>,
}

impl Watch {
    pub fn new(path: &std::path::Path) -> Watch {
        Watch {
            path: path.to_path_buf(),
            seen: std::fs::metadata(path).and_then(|m| m.modified()).ok(),
        }
    }

    /// `None` when the file did not change since the last call; otherwise
    /// whether the new text was applied, or its problems.
    pub fn check(&mut self, engine: &Engine) -> Option<std::result::Result<(), Vec<String>>> {
        let modified = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok()?;
        if self.seen == Some(modified) {
            return None;
        }
        self.seen = Some(modified);
        let config = match Config::load(&self.path) {
            Ok(c) => c,
            Err(e) => return Some(Err(vec![format!("{e:#}")])),
        };
        // The admin editor and a promotion write the file after applying
        // it: nothing new to apply then.
        if toml::to_string(&config).ok() == toml::to_string(&engine.config()).ok() {
            return Some(Ok(()));
        }
        Some(engine.reload(config))
    }
}

fn workers(app: &App, secret: &str) -> Workers {
    let mut workers = Workers::new(secret);
    let config = app.engine.assembled();
    workers
        .handlers
        .insert("alert".into(), Box::new(crate::alerts::Alerts::new(&config, secret)));
    if let Some(stripe) = &app.modules.stripe {
        workers.handlers.insert("stripe".into(), Box::new(stripe.clone()));
    }
    if let Some(ai) = &app.modules.ai {
        workers
            .handlers
            .insert("ai_summary".into(), Box::new(crate::ai::Summaries(ai.clone())));
    }
    workers
}

fn fetch(url: &str) -> Result<String> {
    let site = crate::webhook::origin(url);
    let mut response = crate::webhook::download_agent(30_000)
        .get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("{site}: {}", e.to_string().replace(url, "<url>")))?;
    let status = response.status().as_u16();
    if status != 200 {
        anyhow::bail!("{site} answered {status}");
    }
    Ok(response.body_mut().with_config().limit(50 << 20).read_to_string()?)
}

/// Opens everything and serves until Ctrl-C or SIGTERM.
pub async fn serve(config_path: PathBuf, config: Config) -> Result<()> {
    let state_path = config.resolve(&config.server.state_file);
    let mut state = State::load(&state_path)?;
    let mut changed = state.ensure_secrets();
    if state.admin_token_sha256.is_none() {
        let token = state.rotate_admin_token();
        changed = true;
        // Printed once, on the first start: the state keeps a digest only.
        eprintln!("\nadmin token (shown once, keep it): {token}\n");
    }
    if changed {
        state.save(&state_path)?;
    }
    let key = state.pseudonym_key().context("the state file has no pseudonym key")?;
    let secret = state.webhook_secret.clone().unwrap_or_default();
    let external = KeySet::external(config.server.api_keys_file.as_deref().map(|p| config.resolve(p)).as_deref())?;
    let keys = LiveKeys::load(external, &state_path)?;
    let database = config.resolve(&config.server.database);
    let engine = Engine::open(config.clone(), key, Some(&database))?;

    let mut app = App::new(engine, keys, config_path, secret.clone());
    if config.stripe.enabled {
        app.modules.stripe = Some(Arc::new(crate::stripe::StripeModule::from_env(&config.stripe)?));
    }
    if config.ai.enabled {
        app.modules.ai = Some(Arc::new(crate::ai::Assistant::from_env(&config.ai)));
    }
    let app = Arc::new(app);

    let wal = database.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if let Err(e) = crate::store::Store::checkpoint(&wal) {
                tracing::warn!(error = %e, "checkpoint failed");
            }
        }
    });

    // Background work, on a blocking thread: the engine and the HTTP calls
    // of deliveries are synchronous.
    let background = app.clone();
    let mut watch = Watch::new(&app.config_path);
    std::thread::spawn(move || {
        let mut last_maintenance = 0;
        let mut last_lists = 0;
        loop {
            let t = now();
            let w = workers(&background, &secret);
            for line in run_outbox(&background.engine, &w, t, 100) {
                tracing::debug!("{line}");
            }
            match watch.check(&background.engine) {
                Some(Ok(())) => tracing::info!("configuration file read again"),
                Some(Err(problems)) => {
                    let problems = problems.join("; ");
                    tracing::warn!("the edited configuration is not valid, the running one stays: {problems}")
                }
                None => {}
            }
            if t.saturating_sub(last_maintenance) >= MAINTENANCE_EVERY {
                last_maintenance = t;
                crate::alerts::flush_digests(&background.engine, t);
                if let Err(e) = background.engine.maintain(t) {
                    tracing::warn!(error = %e, "maintenance failed");
                }
                let hours = background.engine.assembled().server.lists_refresh_hours;
                if hours > 0 && t.saturating_sub(last_lists) >= 600 {
                    last_lists = t;
                    for line in background.engine.refresh_lists(hours * 3_600, &fetch) {
                        tracing::info!("list {line}");
                    }
                }
            }
            std::thread::sleep(OUTBOX_EVERY);
        }
    });

    let api_listener = tokio::net::TcpListener::bind(&config.server.bind)
        .await
        .with_context(|| format!("binding {}", config.server.bind))?;
    tracing::info!("API on http://{}", config.server.bind);
    let api = axum::serve(api_listener, api_router(app.clone())).with_graceful_shutdown(shutdown());
    if config.admin.enabled {
        let admin_listener = tokio::net::TcpListener::bind(&config.admin.bind)
            .await
            .with_context(|| format!("binding {}", config.admin.bind))?;
        tracing::info!("admin interface on http://{}", config.admin.bind);
        let admin = axum::serve(admin_listener, admin_router(app)).with_graceful_shutdown(shutdown());
        let (a, b) = tokio::join!(api, admin);
        a?;
        b?;
    } else {
        api.await?;
    }
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}
