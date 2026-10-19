//! Rule conditions, written in CEL (the Common Expression Language).
//!
//! A condition is compiled once, when the configuration loads, and checked
//! there: its syntax, the counters and lists it names, and the variables it
//! reads. It is then evaluated against the [`Facts`] of each event through a
//! [`Scope`], built once per event and shared by every rule. CEL cannot loop
//! without bound or reach the system: a condition only reads the facts.
//!
//! Variables: `event` (the normalized event), `actor` (alias `user`: the
//! account that acts), `tenant` (the workspace acted on), `counters`, `links`
//! (accounts sharing an identifier, and `links.cluster`), `session` (account
//! takeover signals), `related` (other accounts the event names) and `now`.
//! Functions besides the CEL standard library: `in_list(name, value)`,
//! `mentions(name, text)` (the text contains an item of the list, in any
//! case), `list_size(name)`, `share_in_list(name, addresses)`,
//! `provider(address)`, `providers(list)`, `freemail_share(list)`,
//! `alike(list, address)`, `domain(address)`, `since(event_type)` (seconds
//! since the first such event, -1 if never) and `since_last(event_type)`.

use crate::lists::List;
use crate::signals;
use cel::{Context, Env, Program, Value};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, LazyLock, RwLock};

pub const MAX_SOURCE_LEN: usize = 2_000;
pub const VARIABLES: [&str; 9] = ["event", "actor", "user", "tenant", "counters", "links", "session", "related", "now"];
/// What a counter's `when` may read: the event alone.
pub const EVENT_VARIABLES: [&str; 2] = ["event", "now"];

pub type Lists = Arc<RwLock<HashMap<String, List>>>;

static ENV: LazyLock<Arc<Env>> = LazyLock::new(|| Arc::new(Env::stdlib()));
static COUNTER_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bcounters\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*"([^"]*)"\s*\])"#).unwrap());
static LIST_FN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\b(in_list|mentions|list_size|share_in_list)\s*\(\s*([^,)]*)"#).unwrap());
static IP_LIST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""([^"]*)"\s+in\s+event\.ip_lists"#).unwrap());
static LOOP_VAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\s*(?:all|exists|exists_one|map|filter)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,").unwrap());

/// The names a condition may refer to.
#[derive(Debug, Clone, Default)]
pub struct Known {
    pub counters: BTreeSet<String>,
    pub lists: BTreeSet<String>,
}

/// What rules see for one event.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub event: serde_json::Value,
    pub actor: serde_json::Value,
    pub tenant: serde_json::Value,
    pub counters: serde_json::Value,
    pub links: serde_json::Value,
    pub session: serde_json::Value,
    pub related: serde_json::Value,
    /// The first and the last time the actor sent each event type, before
    /// this event.
    pub firsts: BTreeMap<String, u64>,
    pub lasts: BTreeMap<String, u64>,
    pub at: u64,
}

/// The facts of one event, ready for every rule to read.
pub struct Scope {
    ctx: Context<'static, 'static>,
}

fn strings(list: &[Value]) -> Vec<String> {
    list.iter()
        .filter_map(|v| match v {
            Value::String(s) => Some(s.to_string()),
            _ => None,
        })
        .collect()
}

fn seconds_since(times: &BTreeMap<String, u64>, kind: &str, at: u64) -> i64 {
    match times.get(kind) {
        Some(t) => at as i64 - *t as i64,
        None => -1,
    }
}

/// A JSON value as CEL sees it. Every whole number is a signed integer, so
/// `counters.x * 20` and `event.attrs.count - 1` mix with literals: CEL has
/// no arithmetic between `int` and `uint`.
fn cel_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => Value::Int(i),
            (None, Some(u)) => Value::UInt(u),
            _ => Value::Float(n.as_f64().unwrap_or(0.0)),
        },
        serde_json::Value::String(s) => Value::String(Arc::new(s.clone())),
        serde_json::Value::Array(items) => Value::List(Arc::new(items.iter().map(cel_value).collect())),
        serde_json::Value::Object(map) => {
            let map: HashMap<cel::objects::Key, Value> = map
                .iter()
                .map(|(k, v)| (cel::objects::Key::String(Arc::new(k.clone())), cel_value(v)))
                .collect();
            Value::Map(cel::objects::Map { map: Arc::new(map) })
        }
    }
}

impl Scope {
    pub fn new(facts: &Facts, lists: Lists) -> Self {
        let mut ctx = Context::with_env(ENV.clone());
        // Adding a variable or a function to a fresh root context cannot
        // fail except on a name the standard library already uses.
        ctx.add_variable_from_value("event", cel_value(&facts.event));
        ctx.add_variable_from_value("actor", cel_value(&facts.actor));
        ctx.add_variable_from_value("user", cel_value(&facts.actor));
        ctx.add_variable_from_value("tenant", cel_value(&facts.tenant));
        ctx.add_variable_from_value("counters", cel_value(&facts.counters));
        ctx.add_variable_from_value("links", cel_value(&facts.links));
        ctx.add_variable_from_value("session", cel_value(&facts.session));
        ctx.add_variable_from_value("related", cel_value(&facts.related));
        let _ = ctx.add_variable("now", facts.at as i64);
        let l = lists.clone();
        let _ = ctx.add_function("in_list", move |name: Arc<String>, value: Arc<String>| -> bool {
            let lists = l.read().unwrap_or_else(|e| e.into_inner());
            lists.get(name.as_str()).is_some_and(|l| l.contains(&value))
        });
        let l = lists.clone();
        let _ = ctx.add_function("mentions", move |name: Arc<String>, text: Arc<String>| -> bool {
            let lists = l.read().unwrap_or_else(|e| e.into_inner());
            let text = text.to_lowercase();
            lists
                .get(name.as_str())
                .is_some_and(|l| l.items().any(|item| !item.is_empty() && text.contains(&item.to_lowercase())))
        });
        let l = lists.clone();
        let _ = ctx.add_function("list_size", move |name: Arc<String>| -> i64 {
            let lists = l.read().unwrap_or_else(|e| e.into_inner());
            lists.get(name.as_str()).map(|l| l.len() as i64).unwrap_or(0)
        });
        let l = lists;
        let _ = ctx.add_function("share_in_list", move |name: Arc<String>, items: Arc<Vec<Value>>| -> f64 {
            let items = strings(&items);
            if items.is_empty() {
                return 0.0;
            }
            let lists = l.read().unwrap_or_else(|e| e.into_inner());
            let Some(list) = lists.get(name.as_str()) else { return 0.0 };
            items.iter().filter(|i| list.contains(i)).count() as f64 / items.len() as f64
        });
        let _ = ctx.add_function("provider", |a: Arc<String>| -> String { signals::provider(&a).to_owned() });
        let _ = ctx.add_function("domain", |a: Arc<String>| -> String {
            a.rsplit('@').next().unwrap_or_default().to_owned()
        });
        let _ = ctx.add_function("providers", |l: Arc<Vec<Value>>| -> i64 { signals::providers(&strings(&l)) });
        let _ = ctx.add_function("freemail_share", |l: Arc<Vec<Value>>| -> f64 {
            signals::freemail_share(&strings(&l))
        });
        let _ = ctx.add_function("alike", |l: Arc<Vec<Value>>, owner: Arc<String>| -> i64 {
            signals::alike(&strings(&l), &owner)
        });
        let (firsts, at) = (facts.firsts.clone(), facts.at);
        let _ = ctx.add_function("since", move |kind: Arc<String>| -> i64 { seconds_since(&firsts, &kind, at) });
        let lasts = facts.lasts.clone();
        let _ = ctx.add_function("since_last", move |kind: Arc<String>| -> i64 { seconds_since(&lasts, &kind, at) });
        Scope { ctx }
    }

    /// The facts of an event alone, for counter filters.
    pub fn event_only(event: serde_json::Value, at: u64) -> Self {
        let facts = Facts {
            event,
            at,
            ..Facts::default()
        };
        Scope::new(&facts, Arc::new(RwLock::new(HashMap::new())))
    }
}

/// A compiled condition.
#[derive(Debug)]
pub struct Expr {
    source: String,
    program: Program,
}

impl Expr {
    pub fn compile(source: &str, known: &Known) -> Result<Expr, String> {
        Expr::compile_with(source, known, &VARIABLES)
    }

    /// A condition that reads only `event` and `now`.
    pub fn compile_event_only(source: &str, known: &Known) -> Result<Expr, String> {
        Expr::compile_with(source, known, &EVENT_VARIABLES)
    }

    fn compile_with(source: &str, known: &Known, variables: &[&str]) -> Result<Expr, String> {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            return Err("the condition is empty".into());
        }
        if source.chars().count() > MAX_SOURCE_LEN {
            return Err(format!("the condition is longer than {MAX_SOURCE_LEN} characters"));
        }
        let program = catch_unwind(AssertUnwindSafe(|| ENV.compile(trimmed)))
            .map_err(|_| "the condition could not be read".to_owned())?
            .map_err(|e| e.to_string())?;

        let mut problems = Vec::new();
        for cap in COUNTER_REF.captures_iter(trimmed) {
            let name = cap.get(1).or(cap.get(2)).map(|m| m.as_str()).unwrap_or_default();
            if !known.counters.contains(name) {
                problems.push(format!("there is no counter `{name}`"));
            }
        }
        for cap in LIST_FN.captures_iter(trimmed) {
            let (function, arg) = (&cap[1], cap[2].trim());
            match arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
                Some(name) if known.lists.contains(name) => {}
                Some(name) => problems.push(format!("there is no list `{name}`")),
                None => problems.push(format!(
                    "{function}() takes the list name as a literal text, such as {function}(\"disposable\", ...), not `{arg}`"
                )),
            }
        }
        for cap in IP_LIST.captures_iter(trimmed) {
            if !known.lists.contains(&cap[1]) {
                problems.push(format!("there is no list `{}`", &cap[1]));
            }
        }
        let loop_vars: BTreeSet<&str> = LOOP_VAR
            .captures_iter(trimmed)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str())
            .collect();
        for var in program.references().variables() {
            if !variables.contains(&var) && !loop_vars.contains(var) {
                problems.push(format!("there is no variable `{var}`: use {}", variables.join(", ")));
            }
        }
        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        Ok(Expr {
            source: trimmed.to_owned(),
            program,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// True or false, or why the condition could not be decided (a missing
    /// attribute, a value of the wrong type).
    pub fn eval(&self, scope: &Scope) -> Result<bool, String> {
        let result = catch_unwind(AssertUnwindSafe(|| self.program.execute(&scope.ctx)))
            .map_err(|_| "the condition stopped with an internal error".to_owned())?;
        match result {
            Ok(Value::Bool(b)) => Ok(b),
            Ok(other) => Err(format!("the condition gave {other:?}, not true or false")),
            Err(e) => Err(format!("{e:?}")),
        }
    }
}
