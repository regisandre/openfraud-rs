//! The outbox worker. A decision writes what it asks to deliver as outbox
//! rows in its own transaction; this worker delivers them, outside the
//! engine's lock, and records the result: delivered, retried later with
//! backoff, or given up after the last attempt.
//!
//! Kinds: `webhook` (to the application, signed), and one per module:
//! `alert` (a notifier), `stripe` (the `stripe.*` actions), `ai_summary`
//! (a case summary). A kind without a handler is given up at once, and
//! says so.

use crate::engine::Engine;
use crate::webhook::{Delivery, deliver, retry_delay};
use std::collections::HashMap;

/// Attempts for module actions; webhooks use `[webhooks] max_attempts`.
pub const MODULE_ATTEMPTS: u32 = 8;

/// Carries out one outbox row of a module.
pub trait Handler: Send + Sync {
    fn handle(&self, engine: &Engine, payload: &str) -> Delivery;
}

impl<T: Handler> Handler for std::sync::Arc<T> {
    fn handle(&self, engine: &Engine, payload: &str) -> Delivery {
        (**self).handle(engine, payload)
    }
}

pub struct Workers {
    pub webhook_secret: String,
    pub handlers: HashMap<String, Box<dyn Handler>>,
}

impl Workers {
    pub fn new(webhook_secret: &str) -> Self {
        Workers {
            webhook_secret: webhook_secret.to_owned(),
            handlers: HashMap::new(),
        }
    }
}

/// Delivers what is due at `now`, at most `limit` rows. One line per row.
pub fn run_outbox(engine: &Engine, workers: &Workers, now: u64, limit: usize) -> Vec<String> {
    let due = match engine.with_store(|s| s.outbox_due(now, limit)) {
        Ok(due) => due,
        Err(e) => return vec![format!("cannot read the outbox: {e:#}")],
    };
    if due.is_empty() {
        return Vec::new();
    }
    let hooks = engine.config().webhooks;
    let mut report = Vec::new();
    for item in due {
        let (result, max) = match item.kind.as_str() {
            "webhook" => match &hooks {
                Some(h) => (
                    deliver(
                        &h.url,
                        &workers.webhook_secret,
                        &format!("msg_{}", item.id),
                        now,
                        &item.payload,
                        h.timeout_ms,
                    ),
                    h.max_attempts.max(1),
                ),
                None => (Delivery::Gone, 1),
            },
            kind => match workers.handlers.get(kind) {
                Some(handler) => (handler.handle(engine, &item.payload), MODULE_ATTEMPTS),
                None => (Delivery::Retry(format!("no handler for `{kind}`: is its module enabled?")), 1),
            },
        };
        let attempt = item.attempts + 1;
        let (status, next_at, error, word) = match &result {
            Delivery::Done => ("done", now, None, "done".to_owned()),
            Delivery::Gone => (
                "failed",
                now,
                Some("the receiver answered 410 Gone".to_owned()),
                "failed: gone".to_owned(),
            ),
            Delivery::Retry(e) if attempt >= max => ("failed", now, Some(e.clone()), format!("failed after {attempt} attempts: {e}")),
            Delivery::Retry(e) => {
                let delay = retry_delay(item.attempts);
                ("pending", now + delay, Some(e.clone()), format!("retry in {delay}s: {e}"))
            }
        };
        if let Err(e) = engine.with_store(|s| s.outbox_result(item.id, status, next_at, error.as_deref())) {
            report.push(format!("outbox {}: cannot record the result: {e:#}", item.id));
            continue;
        }
        if status == "failed" {
            tracing::warn!(id = item.id, kind = %item.kind, "{word}");
        }
        report.push(format!("outbox {} {}: {word}", item.id, item.kind));
    }
    report
}
