//! The Stripe module: Stripe webhooks in (signature checked, objects turned
//! into openfraud events), and the stripe.* actions out, as Stripe API calls.
#![allow(clippy::type_complexity)]

mod support;

use axum::body::{Body, to_bytes};
use axum::http::Request;
use hmac::{Hmac, Mac};
use openfraud::config::{Config, Stripe};
use openfraud::engine::{Engine, Options};
use openfraud::keys::{KeySet, LiveKeys};
use openfraud::outbox::Handler;
use openfraud::server::{App, api_router};
use openfraud::stripe::{StripeModule, map_event, verify_signature};
use openfraud::webhook::Delivery;
use serde_json::{Value, json};
use sha2::Sha256;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceExt;

const SECRET: &str = "whsec_test_secret";

fn stripe_sig(secret: &str, t: u64, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.{body}").as_bytes());
    let hex: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("t={t},v1={hex}")
}

#[test]
fn a_stripe_signature_is_checked_like_stripe_does() {
    let body = r#"{"id":"evt_1"}"#;
    let good = stripe_sig(SECRET, 1_000, body);
    // (case, header, body, now, accepted)
    let cases: Vec<(&str, String, &str, u64, bool)> = vec![
        ("as sent", good.clone(), body, 1_010, true),
        ("with an old v0 too", format!("{good},v0=abcd"), body, 1_010, true),
        (
            "a second v1 matches",
            format!("t=1000,v1=00ff,{}", good.split(',').nth(1).unwrap()),
            body,
            1_010,
            true,
        ),
        ("a changed body", good.clone(), r#"{"id":"evt_2"}"#, 1_010, false),
        ("another secret", stripe_sig("whsec_other", 1_000, body), body, 1_010, false),
        ("older than five minutes", good.clone(), body, 1_301, false),
        ("no timestamp", good.split(',').nth(1).unwrap().to_owned(), body, 1_010, false),
        ("empty", String::new(), body, 1_010, false),
    ];
    let mut failures = Vec::new();
    for (case, header, body, now, want) in cases {
        if verify_signature(SECRET, &header, body.as_bytes(), now).is_ok() != want {
            failures.push(format!("{case}: want {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_stripe_object_becomes_an_openfraud_event() {
    let pm = json!({"id": "evt_pm", "type": "payment_method.attached", "created": 1_000, "data": {"object": {
        "id": "pm_1", "object": "payment_method", "customer": "cus_1", "metadata": {"user_id": "u1"},
        "billing_details": {"email": "Payer@Outlook.com", "name": "Someone Else"},
        "card": {"fingerprint": "fp_abc", "country": "MA", "funding": "debit", "brand": "visa",
                 "checks": {"cvc_check": "pass", "address_postal_code_check": "unavailable"}, "wallet": null}
    }}});
    let sub = json!({"id": "evt_sub", "type": "customer.subscription.created", "created": 2_000, "data": {"object": {
        "id": "sub_1", "object": "subscription", "customer": "cus_1", "status": "trialing", "metadata": {},
        "items": {"data": [{"price": {"id": "price_1", "lookup_key": "studio_monthly"}}]}
    }}});
    let charge = json!({"id": "evt_ch", "type": "charge.failed", "created": 3_000, "data": {"object": {
        "id": "ch_1", "object": "charge", "customer": null, "amount": 100, "currency": "eur", "metadata": {},
        "failure_code": "card_declined", "outcome": {"risk_level": "elevated", "reason": null},
        "payment_method_details": {"card": {"fingerprint": "fp_t", "country": "US", "funding": "prepaid", "checks": {"cvc_check": "fail"}}}
    }}});
    let paid_zero = json!({"id": "evt_inv0", "type": "invoice.paid", "created": 4_000, "data": {"object": {"object": "invoice", "customer": "cus_1", "amount_paid": 0, "currency": "eur"}}});
    let paid = json!({"id": "evt_inv", "type": "invoice.paid", "created": 5_000, "data": {"object": {"object": "invoice", "customer": "cus_1", "amount_paid": 2900, "currency": "eur"}}});
    let efw = json!({"id": "evt_efw", "type": "radar.early_fraud_warning.created", "created": 6_000, "data": {"object": {"object": "radar.early_fraud_warning", "charge": "ch_9", "fraud_type": "made_with_stolen_card"}}});
    let other = json!({"id": "evt_x", "type": "product.created", "created": 1, "data": {"object": {}}});
    let lookup = |customer: &str| (customer == "cus_1").then(|| "u1".to_owned());
    // (case, Stripe event, openfraud type or None when ignored, user, attributes that must be there)
    let cases: Vec<(&str, Value, Option<&str>, Option<&str>, Value)> = vec![
        (
            "a card attached",
            pm,
            Some("payment.method_added"),
            Some("u1"),
            json!({"card_fingerprint": "fp_abc", "card_country": "MA", "card_funding": "debit", "cvc_check": "pass", "billing_email": "Payer@Outlook.com", "stripe_customer": "cus_1"}),
        ),
        (
            "a trial",
            sub,
            Some("subscription.trial_started"),
            Some("u1"),
            json!({"plan": "studio_monthly", "stripe_customer": "cus_1"}),
        ),
        (
            "a declined guest payment",
            charge,
            Some("payment.failed"),
            None,
            json!({"amount": 100, "card_fingerprint": "fp_t", "card_funding": "prepaid", "cvc_check": "fail", "decline_code": "card_declined", "risk_level": "elevated"}),
        ),
        ("a zero invoice is not a payment", paid_zero, None, None, json!({})),
        (
            "a paid invoice",
            paid,
            Some("subscription.invoice_paid"),
            Some("u1"),
            json!({"amount": 2900, "currency": "eur"}),
        ),
        (
            "an early fraud warning",
            efw,
            Some("payment.fraud_warning"),
            None,
            json!({"fraud_type": "made_with_stolen_card", "stripe_charge": "ch_9"}),
        ),
        ("an event openfraud does not use", other, None, None, json!({})),
    ];
    let mut failures = Vec::new();
    for (case, stripe_event, kind, user, attrs) in cases {
        let mapped = map_event(&stripe_event, "user_id", &lookup);
        match (mapped, kind) {
            (None, None) => {}
            (None, Some(k)) => failures.push(format!("{case}: ignored, want {k}")),
            (Some(m), None) => failures.push(format!("{case}: mapped to {:?}, want ignored", m.event.kind)),
            (Some(m), Some(k)) => {
                if m.event.kind.as_deref() != Some(k) || m.event.actor_id.as_deref() != user {
                    failures.push(format!("{case}: {:?} for {:?}", m.event.kind, m.event.actor_id));
                }
                if m.event.id.as_deref() != stripe_event["id"].as_str() {
                    failures.push(format!("{case}: the Stripe event id is the idempotency key"));
                }
                let got = m.event.attrs.clone().unwrap_or_default();
                for (k, v) in attrs.as_object().unwrap() {
                    if &got[k] != v {
                        failures.push(format!("{case}: attrs.{k} = {}, want {v}", got[k]));
                    }
                }
                if got.to_string().contains("Someone Else") {
                    failures.push(format!("{case}: the cardholder name is copied"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn module(api: &str, actions: bool) -> StripeModule {
    let cfg = Stripe {
        enabled: true,
        actions,
        api_base: api.to_owned(),
        radar_value_list: Some("rsl_1".into()),
        ..Stripe::default()
    };
    StripeModule::new(&cfg, SECRET.into(), Some("sk_test_123".into()))
}

#[tokio::test]
async fn a_signed_stripe_webhook_is_decided_and_links_the_customer() {
    let dir = std::env::temp_dir().join(format!("openfraud-stripe-{}", openfraud::event::random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config::parse("[stripe]\nenabled = true\n", Path::new(".")).unwrap();
    let engine = Engine::open(config, b"stripe-test-key-stripe-test-key!".to_vec(), None).unwrap();
    let keys = LiveKeys::load(KeySet::default(), &dir.join("state.toml")).unwrap();
    let mut app = App::new(engine, keys, dir.join("openfraud.toml"), "whsec_AAAA".into());
    // The trial's card is fetched from Stripe.
    let (api, rx) = support::serve(vec![(
        200,
        json!({"id": "pm_9", "customer": "cus_1", "card": {"fingerprint": "fp_9", "country": "BE", "funding": "credit"}}).to_string(),
    )]);
    app.modules.stripe = Some(Arc::new(module(&api, false)));
    let router = api_router(Arc::new(app));

    let post = |body: String, sig: String| {
        let router = router.clone();
        async move {
            let req = Request::post("/v1/stripe/webhook")
                .header("stripe-signature", sig)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let res = router.oneshot(req).await.unwrap();
            let status = res.status().as_u16();
            let v: Value = serde_json::from_slice(&to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap_or(Value::Null);
            (status, v)
        }
    };
    let now = openfraud::event::now();
    let pm = json!({"id": "evt_1", "type": "payment_method.attached", "created": now, "data": {"object": {"id": "pm_1", "customer": "cus_1", "metadata": {"user_id": "u1"}, "card": {"fingerprint": "fp_1", "country": "BE", "funding": "credit"}}}}).to_string();
    let (status, _) = post(pm.clone(), "t=1,v1=00".into()).await;
    assert_eq!(status, 400, "a bad signature is refused");
    let (status, v) = post(pm.clone(), stripe_sig(SECRET, now, &pm)).await;
    assert_eq!((status, v["decision"].as_str()), (200, Some("allow")), "{v}");

    let sub = json!({"id": "evt_2", "type": "customer.subscription.created", "created": now, "data": {"object": {"id": "sub_1", "customer": "cus_1", "status": "trialing", "default_payment_method": "pm_9", "metadata": {}, "items": {"data": []}}}}).to_string();
    let (status, v) = post(sub.clone(), stripe_sig(SECRET, now, &sub)).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["type"], "subscription.trial_started");
    assert_eq!(
        v["actor"]["id"], "u1",
        "the customer was linked to its actor by the first event: {v}"
    );
    let fetched = rx.recv().unwrap();
    assert_eq!(
        (fetched.method.as_str(), fetched.path.as_str()),
        ("GET", "/v1/payment_methods/pm_9")
    );
    assert_eq!(fetched.header("authorization"), "Bearer sk_test_123");

    let ignored = json!({"id": "evt_3", "type": "product.created", "created": now, "data": {"object": {}}}).to_string();
    let (status, v) = post(ignored.clone(), stripe_sig(SECRET, now, &ignored)).await;
    assert_eq!((status, v["ignored"].as_bool()), (200, Some(true)));
}

#[test]
fn a_stripe_action_makes_the_calls_it_promises() {
    let engine = Engine::open(
        Config::parse("[stripe]\nenabled = true\nactions = true\n", Path::new(".")).unwrap(),
        b"stripe-test-key-stripe-test-key!".to_vec(),
        None,
    )
    .unwrap();
    engine.with_store(|s| s.put_external("stripe_customer", "cus_1", "u1", 1)).unwrap();
    let subs = json!({"data": [
        {"id": "sub_trial", "status": "trialing"},
        {"id": "sub_paid", "status": "active"},
        {"id": "sub_old", "status": "canceled"}
    ], "has_more": false});
    let cards = json!({"data": [{"id": "pm_1", "card": {"fingerprint": "fp_1"}}, {"id": "pm_2", "card": {"fingerprint": "fp_2"}}], "has_more": false});
    let ok = json!({"id": "x"}).to_string();
    // (action, responses, expected calls as (method, path, form body))
    let cases: Vec<(&str, Vec<(u16, String)>, Vec<(&str, &str, &str)>)> = vec![
        (
            "stripe.cancel_subscriptions",
            vec![(200, subs.to_string()), (200, ok.clone()), (200, ok.clone())],
            vec![
                ("GET", "/v1/subscriptions?customer=cus_1&status=all&limit=100", ""),
                ("DELETE", "/v1/subscriptions/sub_trial?invoice_now=false&prorate=false", ""),
                ("POST", "/v1/subscriptions/sub_paid", "cancel_at_period_end=true"),
            ],
        ),
        (
            "stripe.block_cards",
            vec![(200, cards.to_string()), (200, ok.clone()), (200, ok.clone())],
            vec![
                ("GET", "/v1/customers/cus_1/payment_methods?type=card&limit=100", ""),
                ("POST", "/v1/radar/value_list_items", "value_list=rsl_1&value=fp_1"),
                ("POST", "/v1/radar/value_list_items", "value_list=rsl_1&value=fp_2"),
            ],
        ),
        (
            "stripe.detach_payment_methods",
            vec![(200, cards.to_string()), (200, ok.clone()), (200, ok.clone())],
            vec![
                ("GET", "/v1/customers/cus_1/payment_methods?type=card&limit=100", ""),
                ("POST", "/v1/payment_methods/pm_1/detach", ""),
                ("POST", "/v1/payment_methods/pm_2/detach", ""),
            ],
        ),
    ];
    let mut failures = Vec::new();
    for (action, responses, calls) in cases {
        let (api, rx) = support::serve(responses);
        let result = module(&api, true).handle(&engine, &json!({"action": action, "user": "u1"}).to_string());
        if result != Delivery::Done {
            failures.push(format!("{action}: {result:?}"));
        }
        for (method, path, form) in calls {
            let got = rx.recv_timeout(std::time::Duration::from_secs(2));
            match got {
                Ok(r) if r.method == method && r.path == path && r.body == form && r.header("authorization") == "Bearer sk_test_123" => {}
                Ok(r) => failures.push(format!(
                    "{action}: got {} {} {:?}, want {method} {path} {form:?}",
                    r.method, r.path, r.body
                )),
                Err(_) => failures.push(format!("{action}: {method} {path} was never called")),
            }
        }
    }
    let unknown_user =
        module("http://127.0.0.1:9", true).handle(&engine, &json!({"action": "stripe.block_cards", "user": "nobody"}).to_string());
    assert_eq!(
        unknown_user,
        Delivery::Done,
        "an account without a Stripe customer has nothing to do"
    );
    let (api, _rx) = support::serve(vec![(500, json!({"error": {"message": "boom"}}).to_string())]);
    let failed = module(&api, true).handle(&engine, &json!({"action": "stripe.cancel_subscriptions", "user": "u1"}).to_string());
    assert!(matches!(failed, Delivery::Retry(_)), "a Stripe error is retried: {failed:?}");
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_trial_gets_the_card_country_rule_from_the_last_country_seen() {
    // Stripe events carry no request country: the account's last one is used.
    let config = Config::parse("packs = [\"free-tier-and-trial\"]", Path::new(".")).unwrap();
    let engine = Engine::open(config, b"stripe-test-key-stripe-test-key!".to_vec(), None).unwrap();
    let ev = |v: Value| serde_json::from_value(v).unwrap();
    engine
        .process(
            ev(json!({"type": "account.created", "actor_id": "u1", "country": "BE", "at": 1_000})),
            Options::default(),
        )
        .unwrap();
    let out = engine
        .process(ev(json!({"type": "subscription.trial_started", "actor_id": "u1", "at": 90_000, "attrs": {"card_fingerprint": "fp", "card_country": "MA"}})), Options::default())
        .unwrap();
    assert!(out.rules.iter().any(|r| r.id == "trial_card_country"), "{:?}", out.rules);
}

#[test]
fn the_stripe_module_refuses_a_missing_or_blank_webhook_secret() {
    // (case, value of the variable, accepted)
    let cases: Vec<(&str, Option<&str>, bool)> = vec![
        ("unset", None, false),
        ("empty", Some(""), false),
        ("blank", Some("   "), false),
        ("set", Some("whsec_abc123"), true),
    ];
    let mut failures = Vec::new();
    for (i, (case, value, want)) in cases.into_iter().enumerate() {
        let var = format!("OPENFRAUD_TEST_STRIPE_SECRET_{}_{i}", std::process::id());
        // SAFETY: each case uses its own variable, read only by this test.
        unsafe {
            match value {
                Some(v) => std::env::set_var(&var, v),
                None => std::env::remove_var(&var),
            }
        }
        let cfg = Stripe {
            enabled: true,
            webhook_secret_env: var,
            ..Stripe::default()
        };
        if StripeModule::from_env(&cfg).is_ok() != want {
            failures.push(format!("{case}: want accepted={want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
