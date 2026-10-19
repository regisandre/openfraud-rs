//! The Stripe module, off by default (`[stripe] enabled = true`).
//!
//! In: Stripe sends its webhooks to `POST /v1/stripe/webhook`. The
//! `Stripe-Signature` header is checked (HMAC-SHA256 of `t.body` under the
//! endpoint secret, five minutes of tolerance), and the objects openfraud
//! uses become events: a card attached, a trial or a subscription, a payment
//! that failed or succeeded, a paid invoice, a dispute, an early fraud
//! warning. The Stripe event id is the event id, so Stripe's retries count
//! once. The account is the object's `metadata.<user_metadata_key>`, or the
//! account a Stripe customer was linked to by an earlier event.
//!
//! Out: with `actions = true` and an API key, the `stripe.*` actions are
//! carried out from the outbox: `stripe.cancel_subscriptions` (a trial or an
//! unpaid subscription ends now, without an invoice; a paying one at the end
//! of its period, so a mistake can be undone), `stripe.block_cards` (the
//! account's card fingerprints go to a Radar value list) and
//! `stripe.detach_payment_methods`.

use crate::config::Stripe;
use crate::engine::{Engine, Options};
use crate::event::{RawEvent, now};
use crate::outbox::Handler;
use crate::server::{ApiError, Shared};
use crate::webhook::{Delivery, agent};
use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::State as Extract;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const TOLERANCE_SECS: u64 = 300;
/// The external id system for Stripe customers.
pub const CUSTOMER: &str = "stripe_customer";

/// Checks a `Stripe-Signature` header: `t=<unix>,v1=<hex>[,v1=...][,v0=...]`.
pub fn verify_signature(secret: &str, header: &str, body: &[u8], now: u64) -> Result<()> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", t)) => timestamp = t.parse::<u64>().ok(),
            Some(("v1", sig)) => signatures.push(sig.to_owned()),
            _ => {}
        }
    }
    let Some(t) = timestamp else {
        bail!("the Stripe-Signature header has no timestamp")
    };
    if t.abs_diff(now) > TOLERANCE_SECS {
        bail!("the Stripe-Signature timestamp is more than {TOLERANCE_SECS} seconds away");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes a key of any length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    if signatures.iter().any(|s| bool::from(s.as_bytes().ct_eq(expected.as_bytes()))) {
        Ok(())
    } else {
        bail!("no Stripe signature matches")
    }
}

/// A Stripe event as openfraud reads it.
pub struct Mapped {
    pub event: RawEvent,
    /// The Stripe customer, to link to the account.
    pub customer: Option<String>,
    /// A payment method whose card details the event lacks (a trial).
    pub fetch_payment_method: Option<String>,
    /// A charge whose account the event lacks (a dispute, a fraud warning).
    pub fetch_charge: Option<String>,
}

fn text(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}

/// Card details as attributes.
fn card_attrs(card: &Value, attrs: &mut Map<String, Value>) {
    for (from, to) in [
        ("fingerprint", "card_fingerprint"),
        ("country", "card_country"),
        ("funding", "card_funding"),
        ("brand", "card_brand"),
    ] {
        if let Some(v) = text(&card[from]) {
            attrs.insert(to.into(), json!(v));
        }
    }
    if let Some(v) = text(&card["checks"]["cvc_check"]) {
        attrs.insert("cvc_check".into(), json!(v));
    }
    if let Some(v) = text(&card["checks"]["address_postal_code_check"]) {
        attrs.insert("address_check".into(), json!(v));
    }
    if card.get("wallet").is_some_and(|w| !w.is_null()) {
        attrs.insert("wallet".into(), json!(true));
    }
}

/// Turns a Stripe event into an openfraud event, or `None` for the types
/// openfraud does not use. `lookup` finds the account of a Stripe customer.
pub fn map_event(stripe: &Value, user_key: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Option<Mapped> {
    let object = &stripe["data"]["object"];
    let customer = text(&object["customer"]);
    let user = text(&object["metadata"][user_key]).or_else(|| customer.as_deref().and_then(lookup));
    let mut attrs = Map::new();
    if let Some(c) = &customer {
        attrs.insert("stripe_customer".into(), json!(c));
    }
    let mut fetch_payment_method = None;
    let mut fetch_charge = None;
    let kind = match stripe["type"].as_str()? {
        "payment_method.attached" => {
            card_attrs(&object["card"], &mut attrs);
            if let Some(email) = text(&object["billing_details"]["email"]) {
                attrs.insert("billing_email".into(), json!(email));
            }
            "payment.method_added"
        }
        "customer.subscription.created" => {
            let price = &object["items"]["data"][0]["price"];
            if let Some(plan) = text(&price["lookup_key"]).or_else(|| text(&price["id"])) {
                attrs.insert("plan".into(), json!(plan));
            }
            if let Some(status) = text(&object["status"]) {
                attrs.insert("subscription_status".into(), json!(status));
            }
            fetch_payment_method = text(&object["default_payment_method"]);
            if object["status"] == "trialing" {
                "subscription.trial_started"
            } else {
                "subscription.created"
            }
        }
        t @ ("charge.failed" | "charge.succeeded") => {
            card_attrs(&object["payment_method_details"]["card"], &mut attrs);
            for key in ["amount", "currency"] {
                if !object[key].is_null() {
                    attrs.insert(key.into(), object[key].clone());
                }
            }
            if let Some(code) = text(&object["outcome"]["reason"]).or_else(|| text(&object["failure_code"])) {
                attrs.insert("decline_code".into(), json!(code));
            }
            if let Some(risk) = text(&object["outcome"]["risk_level"]) {
                attrs.insert("risk_level".into(), json!(risk));
            }
            if let Some(email) = text(&object["billing_details"]["email"]) {
                attrs.insert("billing_email".into(), json!(email));
            }
            if t == "charge.failed" {
                "payment.failed"
            } else {
                "payment.succeeded"
            }
        }
        "invoice.paid" => {
            let paid = object["amount_paid"].as_i64().unwrap_or(0);
            if paid <= 0 {
                return None;
            }
            attrs.insert("amount".into(), json!(paid));
            if let Some(c) = text(&object["currency"]) {
                attrs.insert("currency".into(), json!(c));
            }
            "subscription.invoice_paid"
        }
        "charge.dispute.created" => {
            for (from, to) in [("amount", "amount"), ("reason", "dispute_reason"), ("currency", "currency")] {
                if !object[from].is_null() {
                    attrs.insert(to.into(), object[from].clone());
                }
            }
            fetch_charge = text(&object["charge"]);
            "payment.disputed"
        }
        "radar.early_fraud_warning.created" => {
            if let Some(t) = text(&object["fraud_type"]) {
                attrs.insert("fraud_type".into(), json!(t));
            }
            fetch_charge = text(&object["charge"]);
            "payment.fraud_warning"
        }
        _ => return None,
    };
    if let Some(charge) = &fetch_charge {
        attrs.insert("stripe_charge".into(), json!(charge));
    }
    Some(Mapped {
        event: RawEvent {
            id: text(&stripe["id"]),
            kind: Some(kind.to_owned()),
            at: stripe.get("created").cloned(),
            actor_id: user,
            attrs: Some(Value::Object(attrs)),
            ..RawEvent::default()
        },
        customer,
        fetch_payment_method,
        fetch_charge,
    })
}

fn form(pairs: &[(&str, &str)]) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub struct StripeModule {
    cfg: Stripe,
    webhook_secret: String,
    api_key: Option<String>,
}

impl StripeModule {
    pub fn new(cfg: &Stripe, webhook_secret: String, api_key: Option<String>) -> Self {
        StripeModule {
            cfg: cfg.clone(),
            webhook_secret,
            api_key: api_key.filter(|k| !k.trim().is_empty()),
        }
    }

    /// The secrets from the environment variables the configuration names.
    pub fn from_env(cfg: &Stripe) -> Result<Self> {
        let secret = std::env::var(&cfg.webhook_secret_env)
            .with_context(|| format!("the Stripe module needs the webhook secret in {}", cfg.webhook_secret_env))?;
        // A blank secret would let anyone sign a Stripe event.
        if secret.trim().is_empty() {
            anyhow::bail!("the webhook secret in {} is empty", cfg.webhook_secret_env);
        }
        Ok(StripeModule::new(cfg, secret, std::env::var(&cfg.api_key_env).ok()))
    }

    pub fn routes(&self) -> Router<Shared> {
        Router::new().route("/v1/stripe/webhook", post(webhook))
    }

    /// One Stripe API call; the parsed answer, or why it failed.
    fn call(&self, method: &str, path: &str, body: &str) -> Result<Value> {
        let key = self.api_key.as_deref().context("the Stripe module has no API key")?;
        let url = format!("{}{}", self.cfg.api_base.trim_end_matches('/'), path);
        let agent = agent(20_000);
        let auth = format!("Bearer {key}");
        let result = match method {
            "GET" => agent.get(&url).header("authorization", &auth).call(),
            "DELETE" => agent.delete(&url).header("authorization", &auth).call(),
            _ => agent
                .post(&url)
                .header("authorization", &auth)
                .header("content-type", "application/x-www-form-urlencoded")
                .send(body),
        };
        let mut response = result.with_context(|| format!("cannot reach Stripe at {url}"))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(4 << 20)
            .read_to_string()
            .unwrap_or_default();
        if !(200..300).contains(&status) {
            let short: String = text.chars().take(300).collect();
            bail!("Stripe answered {status} to {method} {path}: {short}");
        }
        serde_json::from_str(&text).with_context(|| format!("Stripe did not answer JSON to {method} {path}"))
    }

    fn cards(&self, customer: &str) -> Result<Vec<Value>> {
        let list = self.call("GET", &format!("/v1/customers/{customer}/payment_methods?type=card&limit=100"), "")?;
        Ok(list["data"].as_array().cloned().unwrap_or_default())
    }

    fn run(&self, action: &str, customer: &str) -> Result<()> {
        match action {
            "stripe.cancel_subscriptions" => {
                let subs = self.call("GET", &format!("/v1/subscriptions?customer={customer}&status=all&limit=100"), "")?;
                for sub in subs["data"].as_array().cloned().unwrap_or_default() {
                    let id = sub["id"].as_str().unwrap_or_default();
                    match sub["status"].as_str().unwrap_or_default() {
                        "trialing" | "incomplete" | "past_due" | "unpaid" => {
                            self.call("DELETE", &format!("/v1/subscriptions/{id}?invoice_now=false&prorate=false"), "")?;
                        }
                        "active" if sub["cancel_at_period_end"] != json!(true) => {
                            self.call(
                                "POST",
                                &format!("/v1/subscriptions/{id}"),
                                &form(&[("cancel_at_period_end", "true")]),
                            )?;
                        }
                        _ => {}
                    }
                }
            }
            "stripe.block_cards" => {
                let list = self
                    .cfg
                    .radar_value_list
                    .as_deref()
                    .context("stripe.block_cards needs `radar_value_list`")?;
                for card in self.cards(customer)? {
                    if let Some(fp) = card["card"]["fingerprint"].as_str() {
                        self.call("POST", "/v1/radar/value_list_items", &form(&[("value_list", list), ("value", fp)]))?;
                    }
                }
            }
            "stripe.detach_payment_methods" => {
                for card in self.cards(customer)? {
                    if let Some(id) = card["id"].as_str() {
                        self.call("POST", &format!("/v1/payment_methods/{id}/detach"), "")?;
                    }
                }
            }
            other => bail!("`{other}` is not a Stripe action"),
        }
        Ok(())
    }
}

impl Handler for StripeModule {
    fn handle(&self, engine: &Engine, payload: &str) -> Delivery {
        let payload: Value = serde_json::from_str(payload).unwrap_or_default();
        let (Some(action), Some(user)) = (payload["action"].as_str(), payload["user"].as_str()) else {
            return Delivery::Gone;
        };
        if !matches!(
            action,
            "stripe.cancel_subscriptions" | "stripe.block_cards" | "stripe.detach_payment_methods"
        ) {
            tracing::warn!(action, "not a Stripe action: nothing done");
            return Delivery::Gone;
        }
        let customers = match engine.with_store(|s| s.externals_of_user(CUSTOMER, user)) {
            Ok(c) => c,
            Err(e) => return Delivery::Retry(format!("{e:#}")),
        };
        for customer in customers {
            if let Err(e) = self.run(action, &customer) {
                return Delivery::Retry(format!("{e:#}"));
            }
        }
        let _ = engine.with_store(|s| s.audit(now(), "stripe", action, user, ""));
        Delivery::Done
    }
}

async fn webhook(Extract(app): Extract<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    let Some(module) = app.modules.stripe.clone() else {
        return Err(ApiError::not_found("the Stripe module is off"));
    };
    let header = headers.get("stripe-signature").and_then(|v| v.to_str().ok()).unwrap_or_default();
    verify_signature(&module.webhook_secret, header, &body, now()).map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let stripe: Value = serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(format!("not a Stripe event: {e}")))?;
    let engine = app.engine.clone();
    let user_key = module.cfg.user_metadata_key.clone();
    let answer = tokio::task::spawn_blocking(move || -> Result<Value> {
        let lookup = |customer: &str| engine.with_store(|s| s.user_of_external(CUSTOMER, customer)).ok().flatten();
        let Some(mut mapped) = map_event(&stripe, &user_key, &lookup) else {
            return Ok(json!({"received": true, "ignored": true}));
        };
        // What the event lacks, fetched from Stripe when an API key is set.
        if module.api_key.is_some() {
            if let Some(pm) = mapped.fetch_payment_method.take() {
                match module.call("GET", &format!("/v1/payment_methods/{pm}"), "") {
                    Ok(method) => {
                        if let Some(Value::Object(attrs)) = mapped.event.attrs.as_mut() {
                            card_attrs(&method["card"], attrs);
                        }
                    }
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "cannot fetch the trial's card"),
                }
            }
            if mapped.event.actor_id.is_none()
                && let Some(charge) = mapped.fetch_charge.take()
            {
                match module.call("GET", &format!("/v1/charges/{charge}"), "") {
                    Ok(ch) => {
                        let customer = text(&ch["customer"]);
                        mapped.event.actor_id = text(&ch["metadata"][user_key.as_str()]).or_else(|| customer.as_deref().and_then(lookup));
                        if mapped.customer.is_none() {
                            mapped.customer = customer;
                        }
                        if let Some(Value::Object(attrs)) = mapped.event.attrs.as_mut() {
                            card_attrs(&ch["payment_method_details"]["card"], attrs);
                        }
                    }
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "cannot fetch the charge"),
                }
            }
        }
        if let (Some(customer), Some(user)) = (&mapped.customer, &mapped.event.actor_id) {
            engine.with_store(|s| s.put_external(CUSTOMER, customer, user, now()))?;
        }
        let outcome = engine
            .process(mapped.event, Options::default())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(serde_json::to_value(outcome)?)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::from)?;
    Ok(Json(answer))
}
