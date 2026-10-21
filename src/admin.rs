//! The admin interface: three static files embedded in the binary, and the
//! endpoints behind the admin token that they call.

use crate::config::{Config, Mode};
use crate::event::now;
use crate::files::write_atomic;
use crate::keys::State;
use crate::replay::replay;
use crate::server::{ApiError, Shared};
use crate::store::SubjectKind;
use axum::Json;
use axum::extract::{Path, State as Extract};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};

const INDEX: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");

/// `OPENFRAUD_UI_DIR` serves the interface from disk, to edit it without
/// rebuilding.
fn asset(name: &str, embedded: &'static str) -> String {
    match std::env::var("OPENFRAUD_UI_DIR") {
        Ok(dir) => std::fs::read_to_string(std::path::Path::new(&dir).join(name)).unwrap_or_else(|_| embedded.to_owned()),
        Err(_) => embedded.to_owned(),
    }
}

fn secured(mut response: Response, content_type: &'static str) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            .parse()
            .unwrap(),
    );
    response
}

pub async fn index() -> Response {
    secured(Html(asset("index.html", INDEX)).into_response(), "text/html; charset=utf-8")
}

pub async fn app_js() -> Response {
    secured(asset("app.js", APP_JS).into_response(), "text/javascript; charset=utf-8")
}

pub async fn app_css() -> Response {
    secured(asset("app.css", APP_CSS).into_response(), "text/css; charset=utf-8")
}

type Answer = Result<Json<Value>, ApiError>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(ApiError::internal)
}

/// The memory the process holds in RAM, from `VmRSS` in `/proc/self/status`:
/// the figure to size a container's limit on. `None` off Linux.
fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix("VmRSS:"))?;
    let kib: u64 = line.trim().trim_end_matches("kB").trim().parse().ok()?;
    Some(kib * 1024)
}

pub async fn overview(Extract(app): Extract<Shared>) -> Answer {
    let engine = app.engine.clone();
    let config = engine.assembled();
    let t = now();
    let stats = blocking(move || {
        engine.with_store(|s| {
            let week = 7 * 86_400;
            let this = s.type_counts(t.saturating_sub(week), t + 1)?;
            let before = s.type_counts(t.saturating_sub(2 * week), t.saturating_sub(week))?;
            let n = |m: &std::collections::BTreeMap<String, u64>, k: &str| m.get(k).copied().unwrap_or(0);
            let (database, wal) = s.file_sizes();
            Ok(json!({
                "signups_7d": n(&this, "account.created"), "signups_prev_7d": n(&before, "account.created"),
                "logins_7d": n(&this, "session.login"), "logins_prev_7d": n(&before, "session.login"),
                "failed_logins_7d": n(&this, "session.login_failed"), "failed_logins_prev_7d": n(&before, "session.login_failed"),
                "challenges_7d": {
                    "requested": n(&this, "challenge.requested"), "succeeded": n(&this, "challenge.succeeded"), "failed": n(&this, "challenge.failed"),
                },
                "top_rules_7d": s.top_rules(t.saturating_sub(week), 10)?.into_iter().map(|(r, c)| json!({"rule": r, "count": c})).collect::<Vec<_>>(),
                "top_signals_7d": s.top_signals(t.saturating_sub(week), 10)?.into_iter().map(|(g, c)| json!({"signal": g, "count": c})).collect::<Vec<_>>(),
                "storage": {"database_bytes": database, "wal_bytes": wal, "resident_bytes": resident_bytes()},
                "events": s.event_count()?,
                "decisions_24h": s.decision_counts(t.saturating_sub(86_400))?,
                "decisions_7d": s.decision_counts(t.saturating_sub(7 * 86_400))?,
                "actors": s.subject_counts(SubjectKind::Actor)?,
                "tenants": s.subject_counts(SubjectKind::Tenant)?,
                "open_cases": s.cases(true, 1_000, 0)?.len(),
                "outbox": s.outbox_recent(200)?.iter().fold(json!({"pending": 0, "failed": 0, "done": 0}), |mut acc, i| {
                    if let Some(n) = acc.get_mut(i.status.as_str()) {
                        *n = json!(n.as_u64().unwrap_or(0) + 1);
                    }
                    acc
                }),
            }))
        })
    })
    .await??;
    let workflows: Vec<Value> = config
        .workflows
        .iter()
        .map(|(name, w)| {
            json!({
                "name": name, "origin": config.origins.get(name), "description": w.description, "events": w.events, "enabled": w.enabled, "mode": w.mode,
                "step_up_at": w.step_up_at, "review_at": w.review_at, "hold_at": w.hold_at, "block_at": w.block_at, "quarantine_at": w.quarantine_at,
                "max_decision": w.max_decision,
                "rules": w.rules.iter().map(|r| json!({"id": r.id, "when": r.when, "score": r.score, "decision": r.decision, "reason": r.reason, "mode": r.mode.unwrap_or(w.mode), "target": r.target, "enabled": r.enabled})).collect::<Vec<_>>(),
            })
        })
        .collect();
    let counters: Vec<Value> = config
        .counters
        .iter()
        .map(|(name, c)| json!({"name": name, "events": c.events, "by": c.by, "distinct": c.distinct, "sum": c.sum, "window": c.window, "description": c.description}))
        .collect();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "stats": stats,
        "packs": config.packs,
        "brake": app.engine.brake(),
        "workflows": workflows,
        "counters": counters,
        "modules": {"ai": config.ai.enabled, "stripe": config.stripe.enabled, "webhooks": config.webhooks.as_ref().map(|w| w.url.clone()), "alerts": config.alerts.len()},
    })))
}

/// Every rule: where it comes from, the mode asked for, whether it may act,
/// and how it did over 30 days: hits, and precision and recall against the
/// people's labels.
pub async fn get_rules(Extract(app): Extract<Shared>) -> Answer {
    let engine = app.engine.clone();
    let config = engine.assembled();
    let approvals = engine.approvals();
    let since = now().saturating_sub(30 * 86_400);
    let (hits, labels) = blocking(move || engine.with_store(|s| Ok((s.rule_hits(since)?, s.labels()?)))).await??;
    let labels: HashMap<String, String> = labels.into_iter().collect();
    let all_fraud = labels.values().filter(|l| *l == "fraud").count() as u64;
    let mut per_rule: HashMap<String, (u64, BTreeSet<String>)> = HashMap::new();
    for (rule, _, actor) in hits {
        let e = per_rule.entry(rule).or_default();
        e.0 += 1;
        if let Some(a) = actor {
            e.1.insert(a);
        }
    }
    let mut rules = Vec::new();
    for (name, w) in &config.workflows {
        for r in &w.rules {
            let (fired, actors) = per_rule.get(&r.id).cloned().unwrap_or_default();
            let count = |label: &str| actors.iter().filter(|a| labels.get(*a).is_some_and(|l| l == label)).count() as u64;
            let (fraud, legit, fp) = (count("fraud"), count("legit"), count("false_positive"));
            let labelled = fraud + legit + fp;
            rules.push(json!({
                "id": r.id, "workflow": name, "origin": config.origins.get(name), "mode": r.mode.unwrap_or(w.mode),
                "reason": r.reason, "decision": r.decision, "score": r.score, "actions": r.actions,
                "may_act": approvals.get(&r.id).copied().unwrap_or(false), "enabled": r.enabled && w.enabled,
                "fired_30d": fired, "actors_30d": actors.len(), "fraud": fraud, "legit": legit, "false_positive": fp,
                "precision": (labelled > 0).then(|| fraud as f64 / labelled as f64),
                "recall": (all_fraud > 0).then(|| fraud as f64 / all_fraud as f64),
            }));
        }
    }
    Ok(Json(json!({ "rules": rules })))
}

#[derive(Deserialize)]
pub struct HitsQuery {
    days: Option<u64>,
    limit: Option<usize>,
}

/// The accounts a rule fired on, shadow hits included, the latest first, each
/// with its timeline as the AI assistant reads it: for a person, or a model,
/// to judge whether the rule is right before it acts. At most 20 accounts
/// over at most 366 days; 10 over 30 by default.
pub async fn get_rule_hits(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<HitsQuery>,
) -> Answer {
    let days = query.days.unwrap_or(30);
    let limit = query.limit.unwrap_or(10);
    if !(1..=366).contains(&days) || !(1..=20).contains(&limit) {
        return Err(ApiError::bad_request("`days` is 1 to 366 and `limit` 1 to 20"));
    }
    let config = app.engine.assembled();
    let Some(rule) = config.workflows.values().flat_map(|w| w.rules.iter()).find(|r| r.id == id).cloned() else {
        return Err(ApiError::not_found(format!("there is no rule `{id}`")));
    };
    let engine = app.engine.clone();
    let since = now().saturating_sub(days * 86_400);
    let accounts = blocking(move || -> anyhow::Result<Vec<Value>> {
        let (actors, labels) = engine.with_store(|s| Ok((s.rule_hit_actors(&id, since, limit)?, s.labels()?)))?;
        let labels: HashMap<String, String> = labels.into_iter().collect();
        actors
            .into_iter()
            .map(|actor| {
                let events = crate::ai::timeline(&engine, SubjectKind::Actor, &actor)?;
                Ok(json!({"label": labels.get(&actor), "actor": actor, "events": events}))
            })
            .collect()
    })
    .await??;
    Ok(Json(
        json!({"rule": rule.id, "reason": rule.reason, "decision": rule.decision, "days": days, "accounts": accounts}),
    ))
}

async fn explore(app: Shared, body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>, grouped: bool) -> Answer {
    let bytes = body.map_err(|e| ApiError::bad_request(e.body_text()))?;
    let query: crate::explore::Query =
        serde_json::from_slice(&bytes).map_err(|e| ApiError::bad_request(format!("the body is not the expected JSON: {e}")))?;
    let Ok(_one) = app.queries.try_lock() else {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "one event query at a time: try again when the running one ends",
        ));
    };
    let engine = app.engine.clone();
    let at = now();
    let answer = blocking(move || {
        engine.with_store(|s| {
            s.read(|conn| {
                if grouped {
                    crate::explore::group(conn, &query, at)
                } else {
                    crate::explore::query(conn, &query, at)
                }
            })
        })
    })
    .await?
    .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    Ok(Json(answer))
}

/// Filters stored events: how many match, and the newest records.
pub async fn post_events_query(
    Extract(app): Extract<Shared>,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Answer {
    explore(app, body, false).await
}

/// Groups stored events by up to three fields.
pub async fn post_events_group(
    Extract(app): Extract<Shared>,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Answer {
    explore(app, body, true).await
}

/// Moves a rule from shadow to act: replays the last `[safety] replay_days`
/// with the rule acting, refuses when the history is shorter, records the
/// report as the approval, and writes `[overrides.<id>] mode = "act"` to
/// the configuration file.
pub async fn post_promote(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let _guard = app.edits.lock().await;
    let text = std::fs::read_to_string(&app.config_path).map_err(|e| ApiError::internal(format!("cannot read the configuration: {e}")))?;
    let base = app.config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    let mut candidate = Config::parse(&text, &base).map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let assembled = candidate.assemble().map_err(|p| ApiError::bad_request(p.join("; ")))?;
    if !assembled.workflows.values().any(|w| w.rules.iter().any(|r| r.id == id)) {
        return Err(ApiError::not_found(format!("there is no rule `{id}`")));
    }
    candidate.overrides.entry(id.clone()).or_default().mode = Some(Mode::Act);
    let days = assembled.safety.replay_days;
    let at = now();
    let since = at.saturating_sub(days * 86_400);
    let engine = app.engine.clone();
    let replayed = candidate.clone();
    let (report, first) = blocking(move || -> anyhow::Result<_> {
        let first = engine.with_store(|s| s.first_event_at())?;
        Ok((replay(&engine, replayed, since)?, first))
    })
    .await??;
    // The history must reach back to the start of the window.
    let covered = first.map(|from| at.saturating_sub(from) / 86_400).unwrap_or(0).min(days);
    if covered + 1 < days {
        return Err(ApiError::bad_request(format!(
            "the replay covers {covered} days of history; a rule acts only after a {days}-day replay. Keep it in shadow, or set [safety] require_replay = false at your own risk"
        )));
    }
    let summary = json!({
        "days": days, "events": report.events, "changed": report.changed_total, "before": report.before, "after": report.after,
        "rule": report.rules.iter().find(|r| r.id == id),
    });
    let written = Config::parse(&text, &base).ok().and_then(|c| c.overrides.get(&id).cloned());
    let new_text = if written.as_ref().is_some_and(|o| o.mode == Some(Mode::Act)) {
        // Already asked to act by hand: only the approval was missing.
        text.clone()
    } else if written.is_some() {
        return Err(ApiError::bad_request(format!(
            "[overrides.{id}] is already in the configuration: add `mode = \"act\"` to it by hand, then promote again"
        )));
    } else {
        format!("{}\n[overrides.{id}]\nmode = \"act\"\n", text.trim_end())
    };
    let config = Config::parse(&new_text, &base).map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let engine = app.engine.clone();
    let (rule, by) = (id.clone(), "admin".to_owned());
    let approval = summary.clone();
    blocking(move || -> anyhow::Result<()> {
        engine.reload(config).map_err(|p| anyhow::anyhow!(p.join("; ")))?;
        engine.approve(&rule, &approval, &by)
    })
    .await??;
    write_atomic(&app.config_path, new_text.as_bytes(), false)?;
    Ok(Json(json!({ "promoted": id, "report": summary })))
}

pub async fn get_brake(Extract(app): Extract<Shared>) -> Answer {
    let s = app.engine.assembled().safety;
    Ok(Json(
        json!({ "brake": app.engine.brake(), "max_auto_per_hour": s.max_auto_per_hour, "baseline_multiple": s.baseline_multiple, "min_per_hour": s.min_per_hour }),
    ))
}

pub async fn post_brake_release(Extract(app): Extract<Shared>) -> Answer {
    let engine = app.engine.clone();
    blocking(move || engine.release_brake("admin")).await??;
    Ok(Json(json!({ "released": true })))
}

pub async fn get_config(Extract(app): Extract<Shared>) -> Answer {
    let text = std::fs::read_to_string(&app.config_path).map_err(|e| ApiError::internal(format!("cannot read the configuration: {e}")))?;
    Ok(Json(json!({"text": text, "path": app.config_path.display().to_string()})))
}

pub async fn get_keys(Extract(app): Extract<Shared>) -> Answer {
    let state = State::load(&app.state_path)?;
    let keys: Vec<Value> = state
        .api_keys
        .iter()
        .map(|k| json!({"id": k.id, "name": k.name, "prefix": k.prefix, "created": k.created, "scope": k.scope}))
        .collect();
    Ok(Json(json!({"keys": keys, "webhook_secret_set": state.webhook_secret.is_some()})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewKey {
    name: String,
    #[serde(default)]
    scope: crate::keys::Scope,
}

pub async fn post_key(Extract(app): Extract<Shared>, Json(body): Json<NewKey>) -> Answer {
    let _guard = app.edits.lock().await;
    let mut state = State::load(&app.state_path)?;
    let key = state
        .add_key_with(&body.name, body.scope)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    state.save(&app.state_path)?;
    let _ = app
        .engine
        .with_store(|s| s.audit(now(), "admin", "key_created", &body.name, body.scope.as_str()));
    Ok(Json(json!({"key": key, "note": "shown once: copy it now"})))
}

pub async fn delete_key(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let _guard = app.edits.lock().await;
    let mut state = State::load(&app.state_path)?;
    if !state.revoke(&id) {
        return Err(ApiError::not_found(format!("there is no key {id}")));
    }
    state.save(&app.state_path)?;
    let _ = app.engine.with_store(|s| s.audit(now(), "admin", "key_revoked", &id, ""));
    Ok(Json(json!({"revoked": id})))
}

/// A new admin token; the current page keeps working with it only.
pub async fn rotate_token(Extract(app): Extract<Shared>) -> Answer {
    if app.admin_token_pinned() {
        return Err(ApiError::conflict(
            "the admin token is given by OPENFRAUD_ADMIN_TOKEN: change it there and restart",
        ));
    }
    let _guard = app.edits.lock().await;
    let token = app.rotate_admin_token()?;
    let _ = app.engine.with_store(|s| s.audit(now(), "admin", "admin_token_rotated", "", ""));
    Ok(Json(json!({"token": token})))
}

pub async fn get_audit(Extract(app): Extract<Shared>) -> Answer {
    let engine = app.engine.clone();
    let log = blocking(move || engine.with_store(|s| s.audit_log(200))).await??;
    Ok(Json(json!({"audit": log})))
}

pub async fn get_outbox(Extract(app): Extract<Shared>) -> Answer {
    let engine = app.engine.clone();
    let items = blocking(move || engine.with_store(|s| s.outbox_recent(100))).await??;
    let items: Vec<Value> = items
        .into_iter()
        .map(|i| {
            let kind = serde_json::from_str::<Value>(&i.payload).ok().and_then(|p| p["type"].as_str().or(p["action"].as_str()).map(str::to_owned));
            json!({"id": i.id, "kind": i.kind, "what": kind, "status": i.status, "attempts": i.attempts, "next_at": i.next_at, "last_error": i.last_error, "created_at": i.created_at})
        })
        .collect();
    Ok(Json(json!({"outbox": items})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBody {
    /// The candidate configuration; the running one when absent.
    #[serde(default)]
    text: Option<String>,
    #[serde(default = "thirty")]
    days: u64,
}

fn thirty() -> u64 {
    30
}

pub async fn post_replay(Extract(app): Extract<Shared>, Json(body): Json<ReplayBody>) -> Answer {
    let base = app.config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    let candidate = match &body.text {
        Some(text) => Config::parse(text, &base).map_err(|e| ApiError::bad_request(format!("{e:#}")))?,
        None => app.engine.config(),
    };
    if let Err(problems) = candidate.compile() {
        return Err(ApiError::bad_request(problems.join("; ")));
    }
    let engine = app.engine.clone();
    let since = now().saturating_sub(body.days.min(366) * 86_400);
    let report = blocking(move || replay(&engine, candidate, since)).await??;
    Ok(Json(serde_json::to_value(report).map_err(ApiError::internal)?))
}

pub async fn post_summary(Extract(app): Extract<Shared>, Path(id): Path<i64>) -> Answer {
    let Some(ai) = app.modules.ai.clone() else {
        return Err(ApiError::bad_request("the AI assistant is off: set [ai] enabled = true"));
    };
    let engine = app.engine.clone();
    let summary = blocking(move || ai.summarize_case(&engine, id))
        .await?
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    Ok(Json(json!({"summary": summary})))
}

pub async fn post_suggest(Extract(app): Extract<Shared>) -> Answer {
    let Some(ai) = app.modules.ai.clone() else {
        return Err(ApiError::bad_request("the AI assistant is off: set [ai] enabled = true"));
    };
    let engine = app.engine.clone();
    let suggestions = blocking(move || ai.suggest_rules(&engine))
        .await?
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    Ok(Json(json!({"suggestions": suggestions})))
}
