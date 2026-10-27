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

/// One pass of the checkpoint thread: a passive checkpoint that never
/// blocks, then, once the log has grown past its limit, a truncation by the
/// engine itself between two decisions.
pub fn checkpoint(engine: &Engine, database: &std::path::Path) -> Result<()> {
    if crate::store::Store::checkpoint(database)? {
        engine.truncate_log()?;
    }
    Ok(())
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
    Ok(String::from_utf8(crate::webhook::download(url, 30_000, 50 << 20)?)?)
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    crate::webhook::download(url, 120_000, 200 << 20)
}

/// Loads, refreshes or drops the network table as `[networks]` asks.
/// A file of your own is loaded again when it is replaced.
fn refresh_networks(
    engine: &Engine,
    cache: &std::path::Path,
    loaded: &mut Option<(bool, Option<PathBuf>, Option<crate::networks::Version>)>,
) {
    let config = engine.assembled();
    let file = config.networks.file.as_ref().map(|f| config.resolve(f));
    let version = file.as_deref().and_then(crate::networks::version);
    let wanted = (config.networks.enabled, file, version);
    let stale = std::fs::metadata(cache)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_none_or(|d| d.as_secs() >= config.server.lists_refresh_hours.max(1) * 3_600);
    let due = loaded.as_ref() != Some(&wanted) || (wanted.0 && wanted.1.is_none() && stale && config.server.fetch_lists);
    if !due {
        return;
    }
    let settings = crate::config::Networks {
        file: wanted.1.clone(),
        ..config.networks.clone()
    };
    match crate::networks::load(
        &settings,
        cache,
        config.server.fetch_lists,
        config.server.lists_refresh_hours.max(1),
        &fetch_bytes,
    ) {
        Ok(table) => {
            if let Some(t) = &table {
                tracing::info!("network table: {} ranges", t.len());
            }
            engine.set_networks(table.map(Arc::new));
            *loaded = Some(wanted);
        }
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "network table not loaded");
            *loaded = Some(wanted);
        }
    }
}

/// Opens everything and serves until Ctrl-C or SIGTERM.
pub async fn serve(config_path: PathBuf, config: Config) -> Result<()> {
    let state_path = config.resolve(&config.server.state_file);
    let mut state = State::load(&state_path)?;
    let mut changed = state.ensure_secrets();
    // A host that receives the webhooks of many instances gives their secret.
    if let Some(secret) = std::env::var("OPENFRAUD_WEBHOOK_SECRET").ok().filter(|s| !s.is_empty()) {
        changed |= state.pin_webhook_secret(&secret)?;
    }
    // A host that runs many instances gives the token; otherwise it is made once and printed.
    let pinned = std::env::var("OPENFRAUD_ADMIN_TOKEN").ok().filter(|t| !t.is_empty());
    if let Some(token) = &pinned {
        changed |= state.pin_admin_token(token)?;
    } else if state.admin_token_sha256.is_none() {
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
    if let Some(token) = &pinned {
        app.pin_admin_token(token)?;
    }
    if config.stripe.enabled {
        app.modules.stripe = Some(Arc::new(crate::stripe::StripeModule::from_env(&config.stripe)?));
    }
    if config.ai.enabled {
        app.modules.ai = Some(Arc::new(crate::ai::Assistant::from_env(&config.ai)));
    }
    let app = Arc::new(app);
    // The DNS check of email domains, when asked for: the engine calls it at
    // most once a day per domain.
    let mail = app.engine.clone();
    std::thread::spawn(move || {
        let mut on = None;
        loop {
            let email = mail.assembled().email;
            if on != Some(email.mx_check) {
                on = Some(email.mx_check);
                let check: Option<crate::engine::MailCheck> = email.mx_check.then(|| {
                    let (resolver, timeout) = (email.resolver.clone(), email.timeout_ms);
                    Arc::new(move |domain: &str| crate::signals::mx_lookup(domain, &resolver, timeout)) as crate::engine::MailCheck
                });
                mail.set_mail_check(check);
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });

    let networks_cache = database.with_file_name("openfraud-networks.tsv.gz");
    let wal = database.clone();
    let writer = app.engine.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if let Err(e) = checkpoint(&writer, &wal) {
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
        let mut networks = None;
        refresh_networks(&background.engine, &networks_cache, &mut networks);
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
                refresh_networks(&background.engine, &networks_cache, &mut networks);
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
