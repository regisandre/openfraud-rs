//! Alerts to people: a quarantine, a case, the safety brake. The engine
//! queues one outbox row per notifier whose minimum severity the alert
//! reaches; [`Alerts`] delivers it, or keeps it for the notifier's digest.
//! [`flush_digests`] turns a digest period's alerts into one message.
//! Critical alerts never wait for a digest.
//!
//! Notifiers: a signed webhook (Standard Webhooks, like the decisions), a
//! Slack incoming webhook, the Telegram Bot API, and email over SMTP.

use crate::config::{AlertKind, AlertSpec, Config, Severity};
use crate::engine::Engine;
use crate::event::format_time;
use crate::outbox::Handler;
use crate::webhook::{Delivery, agent, deliver};
use crate::window::parse_duration;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const TIMEOUT_MS: u64 = 10_000;

/// One alert for one notifier, as the outbox keeps it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub notifier: usize,
    pub severity: Severity,
    pub title: String,
    pub text: String,
    pub at: u64,
    /// A digest: send now, whatever the notifier's digest period.
    #[serde(default)]
    pub digest: bool,
}

/// The rows to queue for an alert: one per notifier that wants it.
pub fn rows(config: &Config, severity: Severity, title: &str, text: &str, at: u64) -> Vec<Alert> {
    config
        .alerts
        .iter()
        .enumerate()
        .filter(|(_, spec)| severity >= spec.min_severity)
        .map(|(notifier, _)| Alert {
            notifier,
            severity,
            title: title.to_owned(),
            text: text.to_owned(),
            at,
            digest: false,
        })
        .collect()
}

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

fn digest_key(notifier: usize) -> String {
    format!("alert_digest:{notifier}")
}

pub struct Alerts {
    specs: Vec<AlertSpec>,
    webhook_secret: String,
}

impl Alerts {
    pub fn new(config: &Config, webhook_secret: &str) -> Self {
        Alerts {
            specs: config.alerts.clone(),
            webhook_secret: webhook_secret.to_owned(),
        }
    }

    fn send(&self, spec: &AlertSpec, alert: &Alert) -> Delivery {
        let result = match spec.kind {
            AlertKind::Webhook => {
                let body = json!({"type": "alert", "timestamp": format_time(alert.at), "data": alert}).to_string();
                let url = spec.url.as_deref().unwrap_or_default();
                return deliver(
                    url,
                    &self.webhook_secret,
                    &format!("alert_{}_{}", alert.notifier, alert.at),
                    alert.at,
                    &body,
                    TIMEOUT_MS,
                );
            }
            AlertKind::Slack => {
                let text = format!("*{}* ({})\n{}", alert.title, severity_word(alert.severity), alert.text);
                post_json(spec.url.as_deref().unwrap_or_default(), &json!({ "text": text }))
            }
            AlertKind::Telegram => telegram(spec, alert),
            AlertKind::Email => email(spec, alert),
        };
        match result {
            Ok(()) => Delivery::Done,
            Err(e) => Delivery::Retry(format!("{e:#}")),
        }
    }
}

fn post_json(url: &str, body: &Value) -> Result<()> {
    let response = agent(TIMEOUT_MS).post(url).send_json(body).map_err(|e| anyhow!("{url}: {e}"))?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(anyhow!("{url} answered {status}"))
    }
}

fn env_secret(name: Option<&str>, what: &str) -> Result<String> {
    let name = name.with_context(|| format!("no {what} variable is configured"))?;
    std::env::var(name).with_context(|| format!("the environment variable {name} ({what}) is not set"))
}

fn telegram(spec: &AlertSpec, alert: &Alert) -> Result<()> {
    let token = env_secret(spec.bot_token_env.as_deref(), "Telegram bot token")?;
    let base = spec.api_base.as_deref().unwrap_or("https://api.telegram.org");
    let text = format!("{} ({})\n{}", alert.title, severity_word(alert.severity), alert.text);
    let body = json!({"chat_id": spec.chat_id, "text": text, "disable_web_page_preview": true});
    post_json(&format!("{}/bot{token}/sendMessage", base.trim_end_matches('/')), &body)
}

fn email(spec: &AlertSpec, alert: &Alert) -> Result<()> {
    use lettre::message::Mailbox;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let host = spec.smtp_host.as_deref().context("no smtp_host")?;
    let from: Mailbox = spec
        .from
        .as_deref()
        .context("no from address")?
        .parse()
        .context("the from address")?;
    let mut message = Message::builder()
        .from(from)
        .subject(format!("[openfraud] {}: {}", severity_word(alert.severity), alert.title));
    for to in &spec.to {
        message = message.to(to.parse().with_context(|| format!("the address {to}"))?);
    }
    let message = message.body(format!("{}\n\n{}\n", alert.text, format_time(alert.at)))?;
    let builder = match spec.smtp_tls.as_deref().unwrap_or("starttls") {
        "none" => SmtpTransport::builder_dangerous(host),
        "tls" => SmtpTransport::relay(host)?,
        _ => SmtpTransport::starttls_relay(host)?,
    };
    let mut builder = builder.timeout(Some(std::time::Duration::from_millis(TIMEOUT_MS)));
    if let Some(port) = spec.smtp_port {
        builder = builder.port(port);
    }
    if spec.username_env.is_some() {
        let user = env_secret(spec.username_env.as_deref(), "SMTP user")?;
        let password = env_secret(spec.password_env.as_deref(), "SMTP password")?;
        builder = builder.credentials(Credentials::new(user, password));
    }
    builder.build().send(&message).map(|_| ()).map_err(|e| anyhow!("SMTP {host}: {e}"))
}

impl Handler for Alerts {
    fn handle(&self, engine: &Engine, payload: &str) -> Delivery {
        let Ok(alert) = serde_json::from_str::<Alert>(payload) else {
            return Delivery::Gone;
        };
        let Some(spec) = self.specs.get(alert.notifier) else {
            // The configuration changed since: no such notifier now.
            return Delivery::Gone;
        };
        if spec.digest.is_some() && !alert.digest && alert.severity < Severity::Critical {
            let kept = engine.with_store(|s| {
                let key = digest_key(alert.notifier);
                let mut held = s.get_kv(&key)?.unwrap_or_else(|| json!({"items": []}));
                if let Some(items) = held["items"].as_array_mut() {
                    items.push(serde_json::to_value(&alert)?);
                }
                s.put_kv(&key, &held)
            });
            return match kept {
                Ok(()) => Delivery::Done,
                Err(e) => Delivery::Retry(format!("{e:#}")),
            };
        }
        self.send(spec, &alert)
    }
}

/// For every notifier with a digest whose period is over, queues one alert
/// gathering what was kept. Call it from the maintenance loop.
pub fn flush_digests(engine: &Engine, now: u64) {
    let config = engine.assembled();
    for (notifier, spec) in config.alerts.iter().enumerate() {
        let Some(period) = spec.digest.as_deref().and_then(|d| parse_duration(d).ok()) else {
            continue;
        };
        let result = engine.with_store(|s| {
            let key = digest_key(notifier);
            let mut held = s.get_kv(&key)?.unwrap_or_else(|| json!({"items": []}));
            let items: Vec<Alert> = serde_json::from_value(held["items"].clone()).unwrap_or_default();
            let Some(first) = items.iter().map(|a| a.at).min() else {
                return Ok(());
            };
            let since = held["flushed_at"].as_u64().unwrap_or(first).max(first);
            if now.saturating_sub(since) < period {
                return Ok(());
            }
            let worst = items.iter().map(|a| a.severity).max().unwrap_or_default();
            let text = items
                .iter()
                .map(|a| format!("- {} {}: {}", format_time(a.at), a.title, a.text))
                .collect::<Vec<_>>()
                .join("\n");
            let digest = Alert {
                notifier,
                severity: worst,
                title: format!("{} alerts", items.len()),
                text,
                at: now,
                digest: true,
            };
            s.outbox_push("alert", &serde_json::to_string(&digest)?, now)?;
            held = json!({"items": [], "flushed_at": now});
            s.put_kv(&key, &held)
        });
        if let Err(e) = result {
            tracing::warn!(notifier, error = %e, "cannot flush an alert digest");
        }
    }
}
