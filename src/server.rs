//! The HTTP API and the admin interface.
//!
//! Two listeners: the API (`[server] bind`), for the application, behind an
//! API key; the admin interface (`[admin] bind`), for people, behind the
//! admin token. Every refusal has the same envelope:
//! `{"error": {"type": "...", "message": "..."}}`.

use crate::config::{Config, Mode, Status};
use crate::engine::{Engine, Label, Options, Outcome, ProcessError};
use crate::event::{RawEvent, now};
use crate::files::write_atomic;
use crate::keys::{LiveAdmin, LiveKeys, Scope, State};
use crate::store::SubjectKind;
use anyhow::Result;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State as Extract};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const MAX_BATCH: usize = 100;

/// What both listeners share.
pub struct App {
    pub engine: Arc<Engine>,
    keys: Mutex<LiveKeys>,
    admin: Mutex<LiveAdmin>,
    pub config_path: PathBuf,
    pub state_path: PathBuf,
    pub webhook_secret: String,
    /// Serializes configuration edits.
    pub edits: tokio::sync::Mutex<()>,
    /// Module routes and admin actions plugged in at start.
    pub modules: Modules,
    /// The admin token was given by the host (`OPENFRAUD_ADMIN_TOKEN`): the
    /// interface may not replace it, or the next start would undo it.
    pinned_admin: std::sync::atomic::AtomicBool,
}

/// Optional modules the server calls into.
#[derive(Default)]
pub struct Modules {
    pub ai: Option<Arc<crate::ai::Assistant>>,
    pub stripe: Option<Arc<crate::stripe::StripeModule>>,
}

pub type Shared = Arc<App>;

impl App {
    pub fn new(engine: Engine, keys: LiveKeys, config_path: PathBuf, webhook_secret: String) -> App {
        let state_path = keys.state_path().to_path_buf();
        App {
            engine: Arc::new(engine),
            keys: Mutex::new(keys),
            admin: Mutex::new(LiveAdmin::load(&state_path)),
            config_path,
            state_path,
            webhook_secret,
            edits: tokio::sync::Mutex::new(()),
            modules: Modules::default(),
            pinned_admin: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Makes `token` the admin token, given by the host, and keeps the
    /// interface from replacing it.
    pub fn pin_admin_token(&self, token: &str) -> Result<()> {
        let mut state = State::load(&self.state_path)?;
        if state.pin_admin_token(token)? {
            state.save(&self.state_path)?;
        }
        self.admin.lock().unwrap_or_else(|e| e.into_inner()).reload();
        self.pinned_admin.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Whether the host gave the admin token.
    pub fn admin_token_pinned(&self) -> bool {
        self.pinned_admin.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A new admin token, saved as a digest. The old one stops working.
    pub fn rotate_admin_token(&self) -> Result<String> {
        let mut state = State::load(&self.state_path)?;
        let token = state.rotate_admin_token();
        state.save(&self.state_path)?;
        self.admin.lock().unwrap_or_else(|e| e.into_inner()).reload();
        Ok(token)
    }

    fn require_key(&self, presented: Option<&str>) -> Result<Scope, ApiError> {
        if self.engine.config().server.allow_unauthenticated {
            return Ok(Scope::Full);
        }
        let mut live = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        match presented.and_then(|key| live.current().scope_of(key)) {
            Some(scope) => Ok(scope),
            None => Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "a valid API key is required: `Authorization: Bearer <key>` or `X-Api-Key: <key>`",
            )),
        }
    }

    fn require_admin(&self, presented: Option<&str>) -> Result<(), ApiError> {
        let mut admin = self.admin.lock().unwrap_or_else(|e| e.into_inner());
        match presented {
            Some(token) if admin.is_admin(token) => Ok(()),
            _ => Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "the admin token is required",
            )),
        }
    }
}

// ------------------------------------------------------------------ errors

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    kind: &'static str,
    message: String,
    problems: Option<Vec<String>>,
}

impl ApiError {
    pub fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            kind,
            message: message.into(),
            problems: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "request failed");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "openfraud could not answer: see its log",
        )
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        if e.downcast_ref::<crate::engine::AlreadyAppealed>().is_some() {
            return ApiError::new(StatusCode::CONFLICT, "conflict", format!("{e:#}"));
        }
        if let Some(rule) = e.downcast_ref::<crate::engine::UnknownRule>() {
            return if rule.builtin {
                ApiError::bad_request(rule.message.clone())
            } else {
                ApiError::not_found(rule.message.clone())
            };
        }
        ApiError::internal(format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut error = json!({"type": self.kind, "message": self.message});
        if let Some(problems) = self.problems {
            error["problems"] = json!(problems);
        }
        (self.status, Json(json!({ "error": error }))).into_response()
    }
}

type Answer = Result<Json<Value>, ApiError>;

fn presented(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(token) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer "))
    {
        return Some(token.trim().to_owned());
    }
    headers.get("x-api-key").and_then(|v| v.to_str().ok()).map(|v| v.trim().to_owned())
}

/// A JSON body: the content type, the size and the syntax checked, with
/// the reason in the envelope.
fn json_body<T: DeserializeOwned>(app: &App, headers: &HeaderMap, body: Result<Bytes, BytesRejection>) -> Result<T, ApiError> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media",
            "send the body as JSON with `Content-Type: application/json`",
        ));
    }
    let bytes = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            let limit = app.engine.config().server.max_body_bytes;
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                format!("the request body is larger than {limit} bytes"),
            )
        } else {
            ApiError::bad_request(rejection.body_text())
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|e| ApiError::bad_request(format!("the body is not the expected JSON: {e}")))
}

fn process_error(e: ProcessError) -> ApiError {
    match e {
        ProcessError::Invalid(m) => ApiError::new(StatusCode::BAD_REQUEST, "invalid_event", m),
        ProcessError::Internal(e) => ApiError::internal(format!("{e:#}")),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(ApiError::internal)
}

// ------------------------------------------------------------------ routes

/// The API listener's routes.
pub fn api_router(app: Shared) -> Router {
    let limit = app.engine.config().server.max_body_bytes;
    let mut v1 = shared_routes()
        .route_layer(middleware::from_fn_with_state(app.clone(), api_auth_full))
        .route("/v1/decide", post(post_decide))
        .route("/v1/events", post(post_event))
        .route("/v1/events/batch", post(post_batch))
        .route("/v1/cases/{id}/appeal", post(post_appeal))
        .route("/v1/statements/{id}", get(get_statement))
        .route_layer(middleware::from_fn_with_state(app.clone(), api_auth));
    if let Some(stripe) = &app.modules.stripe {
        v1 = v1.merge(stripe.routes());
    }
    Router::new()
        .route("/health", get(health))
        .merge(v1)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(limit))
        .with_state(app)
}

/// Reading and acting on accounts, tenants, cases and lists: on both
/// listeners.
fn shared_routes() -> Router<Shared> {
    Router::new()
        .route("/v1/actors/{id}", get(get_actor))
        .route("/v1/actors/{id}/cluster", get(get_cluster))
        .route("/v1/actors/{id}/label", post(post_label))
        .route("/v1/actors/{id}/status", post(post_actor_status))
        .route("/v1/actors/{id}/snoozes", post(post_snooze))
        .route("/v1/actors/{id}/snoozes/{rule}", delete(delete_snooze))
        .route("/v1/tenants/{id}", get(get_tenant))
        .route("/v1/tenants/{id}/status", post(post_tenant_status))
        .route("/v1/cases", get(get_cases))
        .route("/v1/cases/{id}", get(get_case))
        .route("/v1/cases/{id}/resolve", post(post_resolve))
        .route("/v1/subjects/{id}/export", get(get_export))
        .route("/v1/subjects/{id}", delete(delete_subject))
        .route("/v1/lists", get(get_lists))
        .route(
            "/v1/lists/{name}/items",
            get(get_list_items).post(post_list_items).delete(delete_list_item),
        )
}

/// The admin listener's routes.
pub fn admin_router(app: Shared) -> Router {
    let api = Router::new()
        .route("/admin/api/overview", get(crate::admin::overview))
        .route("/admin/api/config", get(crate::admin::get_config).put(put_config))
        .route("/admin/api/test", post(admin_test))
        .route("/admin/api/keys", get(crate::admin::get_keys).post(crate::admin::post_key))
        .route("/admin/api/keys/{id}", delete(crate::admin::delete_key))
        .route("/admin/api/audit", get(crate::admin::get_audit))
        .route("/admin/api/outbox", get(crate::admin::get_outbox))
        .route("/admin/api/replay", post(crate::admin::post_replay))
        .route("/admin/api/rules", get(crate::admin::get_rules))
        .route("/admin/api/rules/{id}/promote", post(crate::admin::post_promote))
        .route("/admin/api/brake", get(crate::admin::get_brake))
        .route("/admin/api/brake/release", post(crate::admin::post_brake_release))
        .route("/admin/api/cases/{id}/summary", post(crate::admin::post_summary))
        .route("/admin/api/ai/suggest", post(crate::admin::post_suggest))
        .route("/admin/api/session", get(|| async { Json(json!({"ok": true})) }))
        .route("/admin/api/rotate", put(crate::admin::rotate_token))
        .merge(shared_routes().layer(axum::Extension(Actor("admin".into()))))
        .route_layer(middleware::from_fn_with_state(app.clone(), admin_auth));
    Router::new()
        .route("/", get(crate::admin::index))
        .route("/app.js", get(crate::admin::app_js))
        .route("/app.css", get(crate::admin::app_css))
        .merge(api)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(app)
}

/// Who acts, for the audit log.
#[derive(Clone)]
pub struct Actor(pub String);

async fn api_auth(Extract(app): Extract<Shared>, req: Request, next: Next) -> Response {
    authorize(&app, req, next, Scope::Events).await
}

/// For the routes that act on accounts, cases, lists and personal data.
async fn api_auth_full(Extract(app): Extract<Shared>, req: Request, next: Next) -> Response {
    authorize(&app, req, next, Scope::Full).await
}

async fn authorize(app: &App, mut req: Request, next: Next, needed: Scope) -> Response {
    match app.require_key(presented(req.headers()).as_deref()) {
        Err(e) => return e.into_response(),
        Ok(Scope::Events) if needed == Scope::Full => {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "this API key may only send events: acting on accounts, cases, lists and personal data needs a full key",
            )
            .into_response();
        }
        Ok(_) => {}
    }
    if req.extensions().get::<Actor>().is_none() {
        req.extensions_mut().insert(Actor("api".into()));
    }
    next.run(req).await
}

async fn admin_auth(Extract(app): Extract<Shared>, mut req: Request, next: Next) -> Response {
    if let Err(e) = app.require_admin(presented(req.headers()).as_deref()) {
        return e.into_response();
    }
    req.extensions_mut().insert(Actor("admin".into()));
    next.run(req).await
}

fn actor(req_actor: Option<axum::Extension<Actor>>) -> String {
    req_actor.map(|a| a.0.0).unwrap_or_else(|| "api".into())
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such route")
}

async fn health(Extract(app): Extract<Shared>) -> Json<Value> {
    let config = app.engine.assembled();
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "packs": config.packs,
        "workflows": config.workflows.len(),
        "brake": app.engine.brake().engaged,
        "modules": {"ai": config.ai.enabled, "stripe": config.stripe.enabled},
    }))
}

#[derive(Deserialize, Default)]
struct EventQuery {
    #[serde(default)]
    dry_run: bool,
}

/// The answer to `/v1/decide`: what the application acts on.
pub fn decide_view(o: &Outcome) -> Value {
    let reasons = |shadow: bool| -> Vec<Value> {
        o.rules
            .iter()
            .filter(|r| (r.mode == Mode::Shadow) == shadow)
            .map(|r| json!({"rule": r.id, "workflow": r.workflow, "score": r.score, "reason": r.reason, "mode": r.mode, "pending_approval": r.pending}))
            .collect()
    };
    json!({
        "event_id": o.event_id,
        "decision": o.decision,
        "score": o.score,
        "reasons": reasons(false),
        "actions": o.actions,
        "case_id": o.case_id,
        "tenant_case_id": o.tenant_case_id,
        "statement_id": o.statement_id,
        "hold_until": o.hold_until,
        "retry_after": o.retry_after,
        "snoozed": o.snoozed,
        "shadow": {"decision": o.shadow_decision, "reasons": reasons(true)},
        "protected": o.protected,
        "brake": o.brake,
        "duplicate": o.duplicate,
        "dry_run": o.dry_run,
        "took_us": o.took_us,
    })
}

async fn post_decide(
    Extract(app): Extract<Shared>,
    Query(q): Query<EventQuery>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let mut raw: RawEvent = json_body(&app, &headers, body)?;
    if let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        let key = key.trim();
        if key.is_empty() || key.len() > 200 {
            return Err(ApiError::bad_request("the Idempotency-Key header is 1 to 200 characters"));
        }
        raw.id = Some(key.to_owned());
    }
    let engine = app.engine.clone();
    let outcome = blocking(move || {
        engine.process(
            raw,
            Options {
                dry_run: q.dry_run,
                now: None,
            },
        )
    })
    .await?
    .map_err(process_error)?;
    Ok(Json(decide_view(&outcome)))
}

async fn post_event(
    Extract(app): Extract<Shared>,
    Query(q): Query<EventQuery>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let raw: RawEvent = json_body(&app, &headers, body)?;
    let engine = app.engine.clone();
    let outcome = blocking(move || {
        engine.process(
            raw,
            Options {
                dry_run: q.dry_run,
                now: None,
            },
        )
    })
    .await?
    .map_err(process_error)?;
    Ok(Json(
        json!({"event_id": outcome.event_id, "accepted": true, "duplicate": outcome.duplicate, "decision": outcome.decision}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    events: Vec<Value>,
}

async fn post_batch(
    Extract(app): Extract<Shared>,
    Query(q): Query<EventQuery>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let batch: Batch = json_body(&app, &headers, body)?;
    if batch.events.len() > MAX_BATCH {
        return Err(ApiError::bad_request(format!("a batch holds at most {MAX_BATCH} events")));
    }
    let engine = app.engine.clone();
    let results = blocking(move || {
        batch
            .events
            .into_iter()
            .map(|value| {
                let result = serde_json::from_value::<RawEvent>(value)
                    .map_err(|e| format!("not an event: {e}"))
                    .and_then(|raw| {
                        engine
                            .process(
                                raw,
                                Options {
                                    dry_run: q.dry_run,
                                    now: None,
                                },
                            )
                            .map_err(|e| e.to_string())
                    });
                match result {
                    Ok(o) => json!({"event_id": o.event_id, "accepted": true, "duplicate": o.duplicate, "decision": o.decision}),
                    Err(message) => json!({"accepted": false, "error": message}),
                }
            })
            .collect::<Vec<_>>()
    })
    .await?;
    Ok(Json(json!({ "results": results })))
}

fn recent(events: Vec<(crate::event::Event, Outcome)>) -> Vec<Value> {
    events
        .into_iter()
        .map(|(e, o)| {
            json!({
                "event_id": e.id, "type": e.kind, "at": e.at, "actor": e.actor, "tenant": e.tenant, "decision": o.decision, "score": o.score, "case_id": o.case_id, "statement_id": o.statement_id,
                "rules": o.rules.iter().map(|r| json!({"id": r.id, "mode": r.mode, "score": r.score})).collect::<Vec<_>>(),
            })
        })
        .collect()
}

async fn get_actor(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let wanted = id.clone();
    let engine = app.engine.clone();
    let view = blocking(move || -> Result<Option<Value>> {
        let Some(actor) = engine.subject(SubjectKind::Actor, &id)? else {
            return Ok(None);
        };
        let links: Vec<Value> = engine
            .user_links(&id)?
            .into_iter()
            .map(|(kind, users, flagged)| json!({"kind": kind, "shared_with": users, "flagged": flagged}))
            .collect();
        let open_case = engine.with_store(|s| s.open_case_of(SubjectKind::Actor, &id))?;
        let snoozes = engine.snoozes(&id)?;
        Ok(Some(json!({
            "actor": actor, "recent": recent(engine.subject_events(SubjectKind::Actor, &id, 50)?), "links": links,
            "open_case": open_case, "snoozes": snoozes,
        })))
    })
    .await??;
    view.map(Json)
        .ok_or_else(|| ApiError::not_found(format!("there is no account `{wanted}`")))
}

async fn get_cluster(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let engine = app.engine.clone();
    let cluster = blocking(move || engine.cluster(&id)).await??;
    Ok(Json(json!({ "cluster": cluster })))
}

async fn get_tenant(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let wanted = id.clone();
    let engine = app.engine.clone();
    let view = blocking(move || -> Result<Option<Value>> {
        let Some(tenant) = engine.subject(SubjectKind::Tenant, &id)? else {
            return Ok(None);
        };
        let open_case = engine.with_store(|s| s.open_case_of(SubjectKind::Tenant, &id))?;
        Ok(Some(
            json!({"tenant": tenant, "recent": recent(engine.subject_events(SubjectKind::Tenant, &id, 50)?), "open_case": open_case}),
        ))
    })
    .await??;
    view.map(Json)
        .ok_or_else(|| ApiError::not_found(format!("there is no tenant `{wanted}`")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelBody {
    label: String,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnoozeBody {
    rule: String,
    #[serde(rename = "for")]
    period: String,
    #[serde(default)]
    note: String,
}

/// A snooze period: a duration of at most 366 days.
fn snooze_period(text: &str) -> Result<u64, ApiError> {
    crate::window::parse_duration(text).map_err(|e| ApiError::bad_request(format!("the snooze period: {e}")))
}

async fn post_snooze(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let b: SnoozeBody = json_body(&app, &headers, body)?;
    let until = crate::event::now().saturating_add(snooze_period(&b.period)?);
    let engine = app.engine.clone();
    let by = actor(who);
    let snoozes = blocking(move || {
        engine.snooze(&id, &b.rule, until, &by, &b.note)?;
        engine.snoozes(&id)
    })
    .await??;
    Ok(Json(json!({ "snoozes": snoozes })))
}

async fn delete_snooze(
    Extract(app): Extract<Shared>,
    Path((id, rule)): Path<(String, String)>,
    who: Option<axum::Extension<Actor>>,
) -> Answer {
    let engine = app.engine.clone();
    let by = actor(who);
    let lifted = blocking(move || engine.unsnooze(&id, &rule, &by)).await??;
    Ok(Json(json!({ "lifted": lifted })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveBody {
    label: String,
    #[serde(default)]
    note: String,
    /// With `legit` or `false_positive`: snooze the case's rules for its
    /// account for this long.
    #[serde(default)]
    snooze: Option<String>,
}

fn parse_label(text: &str) -> Result<Label, ApiError> {
    Label::parse(text).ok_or_else(|| ApiError::bad_request(format!("`{text}` is not a label: use fraud, legit or false_positive")))
}

async fn post_label(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let b: LabelBody = json_body(&app, &headers, body)?;
    let label = parse_label(&b.label)?;
    let engine = app.engine.clone();
    let by = actor(who);
    let actor = blocking(move || engine.label(&id, label, &by, &b.note)).await??;
    Ok(Json(json!({ "actor": actor })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusBody {
    status: String,
    #[serde(default)]
    trust: Option<u8>,
    #[serde(default)]
    note: String,
}

async fn set_status(
    app: Shared,
    kind: SubjectKind,
    id: String,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let b: StatusBody = json_body(&app, &headers, body)?;
    let status = Status::parse(&b.status).ok_or_else(|| {
        ApiError::bad_request(format!(
            "`{}` is not a status: use normal, review, quarantined or trusted",
            b.status
        ))
    })?;
    let engine = app.engine.clone();
    let by = actor(who);
    let subject = blocking(move || engine.set_status(kind, &id, status, b.trust, &by, &b.note)).await??;
    Ok(Json(json!({ kind.as_str(): subject })))
}

async fn post_actor_status(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    set_status(app, SubjectKind::Actor, id, who, headers, body).await
}

async fn post_tenant_status(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    set_status(app, SubjectKind::Tenant, id, who, headers, body).await
}

#[derive(Deserialize)]
struct CasesQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

async fn get_cases(Extract(app): Extract<Shared>, Query(q): Query<CasesQuery>) -> Answer {
    let open = match q.status.as_deref() {
        None | Some("open") => true,
        Some("all") => false,
        Some(other) => return Err(ApiError::bad_request(format!("`{other}` is not a case status: use open or all"))),
    };
    let engine = app.engine.clone();
    let cases = blocking(move || engine.cases(open, q.limit.unwrap_or(50).min(500), q.offset.unwrap_or(0))).await??;
    Ok(Json(json!({ "cases": cases })))
}

fn case_id(id: &str) -> Result<i64, ApiError> {
    id.parse().map_err(|_| ApiError::not_found(format!("there is no case {id}")))
}

async fn existing_case(app: &Shared, id: &str) -> Result<i64, ApiError> {
    let n = case_id(id)?;
    let engine = app.engine.clone();
    match blocking(move || engine.case(n)).await?? {
        Some(_) => Ok(n),
        None => Err(ApiError::not_found(format!("there is no case {id}"))),
    }
}

async fn get_case(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let n = case_id(&id)?;
    let engine = app.engine.clone();
    let case = blocking(move || engine.case(n)).await??;
    let case = case.ok_or_else(|| ApiError::not_found(format!("there is no case {id}")))?;
    Ok(Json(json!({ "case": case })))
}

async fn post_resolve(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let b: ResolveBody = json_body(&app, &headers, body)?;
    let label = parse_label(&b.label)?;
    let until = match &b.snooze {
        None => None,
        Some(_) if label == Label::Fraud => {
            return Err(ApiError::bad_request(
                "a snooze goes with a legit or false_positive verdict, not with fraud",
            ));
        }
        Some(period) => Some(crate::event::now().saturating_add(snooze_period(period)?)),
    };
    let n = existing_case(&app, &id).await?;
    let engine = app.engine.clone();
    let by = actor(who);
    let (subject, snoozed) = blocking(move || -> Result<(Value, Vec<String>)> {
        let case = engine.case(n)?;
        let subject = engine.resolve_case(n, label, &by, &b.note)?;
        let mut snoozed = Vec::new();
        if let (Some(until), Some(case)) = (until, case)
            && case.subject_kind == SubjectKind::Actor
        {
            for rule in &case.reasons {
                match engine.snooze(&case.subject_id, rule, until, &by, &b.note) {
                    Ok(()) => snoozed.push(rule.clone()),
                    // A rule removed since the case opened has nothing to silence.
                    Err(e) if e.downcast_ref::<crate::engine::UnknownRule>().is_some() => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok((serde_json::to_value(subject)?, snoozed))
    })
    .await??;
    Ok(Json(json!({ "subject": subject, "snoozed": snoozed })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppealBody {
    message: String,
}

async fn post_appeal(
    Extract(app): Extract<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let b: AppealBody = json_body(&app, &headers, body)?;
    let n = existing_case(&app, &id).await?;
    let engine = app.engine.clone();
    let case = blocking(move || engine.appeal(n, &b.message)).await??;
    Ok(Json(json!({ "case": case })))
}

async fn get_statement(Extract(app): Extract<Shared>, Path(id): Path<String>) -> Answer {
    let wanted = id.clone();
    let engine = app.engine.clone();
    let statement = blocking(move || engine.statement(&id)).await??;
    statement
        .map(|s| Json(json!({ "statement": s })))
        .ok_or_else(|| ApiError::not_found(format!("there is no statement `{wanted}`")))
}

async fn get_export(Extract(app): Extract<Shared>, Path(id): Path<String>, who: Option<axum::Extension<Actor>>) -> Answer {
    let engine = app.engine.clone();
    let by = actor(who);
    let export = blocking(move || -> Result<Value> {
        let export = engine.export(&id)?;
        engine.with_store(|s| s.audit(now(), &by, "export", &id, ""))?;
        Ok(export)
    })
    .await??;
    Ok(Json(export))
}

async fn delete_subject(Extract(app): Extract<Shared>, Path(id): Path<String>, who: Option<axum::Extension<Actor>>) -> Answer {
    let engine = app.engine.clone();
    let by = actor(who);
    let erased = blocking(move || engine.erase(&id, &by)).await??;
    Ok(Json(json!({ "erased": erased })))
}

async fn get_lists(Extract(app): Extract<Shared>) -> Json<Value> {
    let lists: Vec<Value> = app
        .engine
        .lists()
        .into_iter()
        .map(|(name, kind, items, description, url)| json!({"name": name, "kind": kind, "items": items, "description": description, "url": url}))
        .collect();
    Json(json!({ "lists": lists }))
}

fn known_list(app: &App, name: &str) -> Result<(), ApiError> {
    if app.engine.lists().iter().any(|l| l.0 == name) {
        Ok(())
    } else {
        Err(ApiError::not_found(format!("there is no list `{name}`")))
    }
}

async fn get_list_items(Extract(app): Extract<Shared>, Path(name): Path<String>) -> Answer {
    known_list(&app, &name)?;
    let engine = app.engine.clone();
    let items = blocking(move || engine.list_items(&name)).await??;
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemsBody {
    items: Vec<String>,
    #[serde(default)]
    note: String,
}

async fn post_list_items(
    Extract(app): Extract<Shared>,
    Path(name): Path<String>,
    who: Option<axum::Extension<Actor>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Answer {
    let b: ItemsBody = json_body(&app, &headers, body)?;
    known_list(&app, &name)?;
    if b.items.len() > 10_000 {
        return Err(ApiError::bad_request("at most 10,000 items at once"));
    }
    let engine = app.engine.clone();
    let by = actor(who);
    let added = blocking(move || -> Result<Result<u64, String>> {
        let mut added = 0;
        for item in &b.items {
            match engine.add_list_item(&name, item, &by, &b.note) {
                Ok(true) => added += 1,
                Ok(false) => {}
                Err(e) => return Ok(Err(format!("{e:#}"))),
            }
        }
        Ok(Ok(added))
    })
    .await??
    .map_err(ApiError::bad_request)?;
    Ok(Json(json!({ "added": added })))
}

#[derive(Deserialize)]
struct ItemQuery {
    item: String,
}

async fn delete_list_item(
    Extract(app): Extract<Shared>,
    Path(name): Path<String>,
    Query(q): Query<ItemQuery>,
    who: Option<axum::Extension<Actor>>,
) -> Answer {
    known_list(&app, &name)?;
    let engine = app.engine.clone();
    let by = actor(who);
    let removed = blocking(move || engine.remove_list_item(&name, &q.item, &by)).await??;
    Ok(Json(json!({ "removed": removed })))
}

// ------------------------------------------------------------------ admin

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigBody {
    text: String,
}

/// Replaces the configuration file after checking it, and applies it.
async fn put_config(Extract(app): Extract<Shared>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> Answer {
    let b: ConfigBody = json_body(&app, &headers, body)?;
    let _guard = app.edits.lock().await;
    let base = app.config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    let config = Config::parse(&b.text, &base).map_err(|e| {
        let mut err = ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", "the configuration is not valid");
        err.problems = Some(vec![format!("{e:#}")]);
        err
    })?;
    let engine = app.engine.clone();
    let reloaded = blocking(move || engine.reload(config)).await?;
    if let Err(problems) = reloaded {
        let mut err = ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", "the configuration is not valid");
        err.problems = Some(problems);
        return Err(err);
    }
    write_atomic(&app.config_path, b.text.as_bytes(), false).map_err(ApiError::from)?;
    let _ = app
        .engine
        .with_store(|s| s.audit(now(), "admin", "config_saved", &app.config_path.display().to_string(), ""));
    Ok(Json(json!({"saved": true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestBody {
    event: RawEvent,
}

/// The playground: decides an event without storing anything.
async fn admin_test(Extract(app): Extract<Shared>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> Answer {
    let b: TestBody = json_body(&app, &headers, body)?;
    let engine = app.engine.clone();
    let outcome = blocking(move || engine.process(b.event, Options { dry_run: true, now: None }))
        .await?
        .map_err(process_error)?;
    let mut view = serde_json::to_value(&outcome).map_err(ApiError::internal)?;
    view["answer"] = decide_view(&outcome);
    Ok(Json(view))
}

/// Counts for the overview, by name.
pub fn counts(map: BTreeMap<String, u64>) -> Value {
    json!(map)
}
