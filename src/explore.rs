//! Exploring stored events from the admin interface: filters, groups and
//! the fields both may name.
//!
//! Only what is stored is queryable: pseudonyms, never a raw email or IP
//! address. A field is one of a fixed set, or `attrs.<name>`,
//! `traits.<name>` and the dotted fields of the agent, the device and the
//! email shape, each segment lowercase letters, digits and `_`: the SQL is
//! built from those names alone, and every value is a bound parameter.

use anyhow::{Result, bail};
use rusqlite::types::Value as Sql;
use rusqlite::{Connection, params_from_iter};
use serde::Deserialize;
use serde_json::{Value, json};

/// The longest window a query may read, and the most rows it returns.
pub const MAX_DAYS: u64 = 366;
pub const MAX_ROWS: usize = 1_000;
pub const MAX_GROUPS: usize = 200;

/// The top-level fields of a stored event.
const BODY_FIELDS: [&str; 14] = [
    "country",
    "ip_country",
    "ip_asn",
    "ip_org",
    "email_domain",
    "email_registered_domain",
    "email_reachable",
    "device",
    "language",
    "device_token",
    "phone_code",
    "phone_prefix",
    "ip_prefix",
    "owner",
];

/// Fields under a fixed prefix: `agent.os`, `email_shape.generated` ...
const NESTED: [&str; 6] = ["attrs", "traits", "agent", "device_info", "email_shape", "subject"];

pub const OPS: [&str; 9] = ["eq", "neq", "in", "nin", "exists", "contains", "starts_with", "ends_with", "range"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub field: String,
    pub op: String,
    #[serde(default)]
    pub value: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// Unix seconds; a day ago when absent.
    #[serde(default)]
    pub from: Option<u64>,
    /// Unix seconds; now when absent.
    #[serde(default)]
    pub to: Option<u64>,
    /// All of these.
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// And all of one of these groups.
    #[serde(default)]
    pub any: Vec<Vec<Filter>>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// For a group: the fields to group by, and the columns to compute.
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub columns: Vec<Column>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Column {
    /// `count`, `count_distinct`, `sum`, `avg`, `min`, `max`.
    pub op: String,
    #[serde(default)]
    pub field: Option<String>,
}

/// The fields a query may name, for the schema.
pub fn schema() -> Value {
    let mut fields: Vec<String> = ["type", "actor", "tenant", "at", "decision", "score", "rules", "signals"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    fields.extend(BODY_FIELDS.iter().map(|s| s.to_string()));
    fields.extend(NESTED.iter().map(|n| format!("{n}.<name>")));
    json!({
        "fields": fields,
        "ops": OPS,
        "columns": ["count", "count_distinct", "sum", "avg", "min", "max"],
        "notes": "rules and signals take `contains`; times are Unix seconds; at most 366 days and 1,000 rows",
    })
}

fn segment(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The SQL expression of a field, or why it is refused.
fn field_sql(field: &str) -> Result<String> {
    Ok(match field {
        "type" => "events.type".into(),
        "actor" => "events.actor".into(),
        "tenant" => "events.tenant".into(),
        "at" => "events.at".into(),
        "decision" => "json_extract(events.outcome, '$.decision')".into(),
        "score" => "json_extract(events.outcome, '$.score')".into(),
        f if BODY_FIELDS.contains(&f) => format!("json_extract(events.body, '$.{f}')"),
        f => match f.split_once('.') {
            Some((prefix, rest)) if NESTED.contains(&prefix) && rest.split('.').all(segment) && rest.split('.').count() <= 3 => {
                format!("json_extract(events.body, '$.{prefix}.{rest}')")
            }
            _ => bail!("`{field}` is not a field: see /admin/api/events/schema"),
        },
    })
}

fn sql_value(v: &Value) -> Result<Sql> {
    Ok(match v {
        Value::String(s) => Sql::Text(s.clone()),
        Value::Bool(b) => Sql::Integer(i64::from(*b)),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Sql::Integer(i),
            None => Sql::Real(n.as_f64().unwrap_or(0.0)),
        },
        _ => bail!("a filter value is a text, a number or a boolean"),
    })
}

/// One filter as SQL, its parameters pushed.
fn filter_sql(f: &Filter, params: &mut Vec<Sql>) -> Result<String> {
    if !OPS.contains(&f.op.as_str()) {
        bail!("`{}` is not an op: use {}", f.op, OPS.join(", "));
    }
    // A rule that fired, or a signal of the answer.
    if f.field == "rules" || f.field == "signals" {
        if f.op != "contains" {
            bail!("`{}` takes the op `contains`", f.field);
        }
        params.push(sql_value(&f.value)?);
        return Ok(if f.field == "rules" {
            "EXISTS (SELECT 1 FROM rule_hits h WHERE h.event_id = events.id AND h.rule = ?)".into()
        } else {
            "EXISTS (SELECT 1 FROM json_each(events.outcome, '$.signals') s WHERE s.key = ?)".into()
        });
    }
    let x = field_sql(&f.field)?;
    let one = |params: &mut Vec<Sql>| -> Result<()> {
        params.push(sql_value(&f.value)?);
        Ok(())
    };
    Ok(match f.op.as_str() {
        "eq" => {
            one(params)?;
            format!("{x} = ?")
        }
        "neq" => {
            one(params)?;
            format!("({x} IS NULL OR {x} != ?)")
        }
        "exists" => format!("{x} IS NOT NULL"),
        "contains" | "starts_with" | "ends_with" => {
            let Value::String(s) = &f.value else {
                bail!("`{}` takes a text", f.op);
            };
            let escaped = s.replace('!', "!!").replace('%', "!%").replace('_', "!_");
            params.push(Sql::Text(match f.op.as_str() {
                "contains" => format!("%{escaped}%"),
                "starts_with" => format!("{escaped}%"),
                _ => format!("%{escaped}"),
            }));
            format!("{x} LIKE ? ESCAPE '!'")
        }
        "in" | "nin" => {
            let Value::Array(items) = &f.value else {
                bail!("`{}` takes a list", f.op);
            };
            if items.is_empty() || items.len() > 100 {
                bail!("`{}` takes 1 to 100 values", f.op);
            }
            for item in items {
                params.push(sql_value(item)?);
            }
            let marks = vec!["?"; items.len()].join(", ");
            if f.op == "in" {
                format!("{x} IN ({marks})")
            } else {
                format!("({x} IS NULL OR {x} NOT IN ({marks}))")
            }
        }
        _ => {
            // range: {gte, gt, lte, lt}
            let Value::Object(bounds) = &f.value else {
                bail!("`range` takes an object such as {{\"gte\": 10, \"lte\": 20}}");
            };
            let mut parts = Vec::new();
            for (key, sign) in [("gte", ">="), ("gt", ">"), ("lte", "<="), ("lt", "<")] {
                if let Some(v) = bounds.get(key) {
                    params.push(sql_value(v)?);
                    parts.push(format!("{x} {sign} ?"));
                }
            }
            if parts.is_empty() {
                bail!("`range` needs gte, gt, lte or lt");
            }
            format!("({})", parts.join(" AND "))
        }
    })
}

/// The WHERE clause of a query, its parameters, and the window.
fn where_sql(q: &Query, now: u64) -> Result<(String, Vec<Sql>)> {
    let to = q.to.unwrap_or(now);
    let from = q.from.unwrap_or(to.saturating_sub(86_400));
    if from > to || to - from > MAX_DAYS * 86_400 {
        bail!("the window is `from` to `to`, at most {MAX_DAYS} days");
    }
    if q.filters.len() + q.any.iter().map(Vec::len).sum::<usize>() > 50 {
        bail!("at most 50 filters");
    }
    let mut params = vec![Sql::Integer(from as i64), Sql::Integer(to as i64)];
    let mut clauses = vec!["events.at >= ? AND events.at <= ?".to_owned()];
    for f in &q.filters {
        clauses.push(filter_sql(f, &mut params)?);
    }
    if !q.any.is_empty() {
        let mut groups = Vec::new();
        for group in &q.any {
            let parts: Vec<String> = group.iter().map(|f| filter_sql(f, &mut params)).collect::<Result<_>>()?;
            groups.push(if parts.is_empty() {
                "1".to_owned()
            } else {
                format!("({})", parts.join(" AND "))
            });
        }
        clauses.push(format!("({})", groups.join(" OR ")));
    }
    Ok((clauses.join(" AND "), params))
}

fn json_of(v: rusqlite::types::ValueRef<'_>) -> Value {
    match v {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(i) => json!(i),
        rusqlite::types::ValueRef::Real(f) => json!(f),
        rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
        rusqlite::types::ValueRef::Blob(_) => Value::Null,
    }
}

/// The events a query matches: how many, and the newest records.
pub fn query(conn: &Connection, q: &Query, now: u64) -> Result<Value> {
    let (clause, params) = where_sql(q, now)?;
    let count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {clause}"),
        params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let limit = q.limit.unwrap_or(100).min(MAX_ROWS);
    let mut stmt = conn.prepare(&format!(
        "SELECT events.id, events.at, events.type, events.actor, events.tenant,
                json_extract(events.outcome, '$.decision'), json_extract(events.outcome, '$.score'),
                json_extract(events.outcome, '$.signals'), events.body
         FROM events WHERE {clause} ORDER BY events.at DESC, events.rowid DESC LIMIT {limit}"
    ))?;
    let mut rows = stmt.query(params_from_iter(params.iter()))?;
    let mut events = Vec::new();
    while let Some(r) = rows.next()? {
        let signals: Value = r
            .get::<_, Option<String>>(7)?
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.as_object().map(|m| json!(m.keys().collect::<Vec<_>>())))
            .unwrap_or(json!([]));
        let body: Value = serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default();
        events.push(json!({
            "event_id": r.get::<_, String>(0)?, "at": r.get::<_, i64>(1)?, "type": r.get::<_, String>(2)?,
            "actor": r.get::<_, Option<String>>(3)?, "tenant": r.get::<_, Option<String>>(4)?,
            "decision": r.get::<_, Option<String>>(5)?, "score": r.get::<_, Option<i64>>(6)?,
            "signals": signals, "event": body,
        }));
    }
    Ok(json!({"count": count, "events": events}))
}

/// The events a query matches, grouped: one row per value of the
/// `group_by` fields, with the columns asked for (a count by default).
pub fn group(conn: &Connection, q: &Query, now: u64) -> Result<Value> {
    if q.group_by.is_empty() || q.group_by.len() > 3 {
        bail!("`group_by` names 1 to 3 fields");
    }
    let (clause, params) = where_sql(q, now)?;
    let keys: Vec<String> = q.group_by.iter().map(|f| field_sql(f)).collect::<Result<_>>()?;
    let default = [Column {
        op: "count".into(),
        field: None,
    }];
    let columns = if q.columns.is_empty() { &default[..] } else { &q.columns[..] };
    if columns.len() > 6 {
        bail!("at most 6 columns");
    }
    let mut exprs = Vec::new();
    for c in columns {
        let field = || -> Result<String> {
            match &c.field {
                Some(f) => field_sql(f),
                None => bail!("the column `{}` needs a `field`", c.op),
            }
        };
        exprs.push(match c.op.as_str() {
            "count" => "COUNT(*)".to_owned(),
            "count_distinct" => format!("COUNT(DISTINCT {})", field()?),
            "sum" => format!("TOTAL({})", field()?),
            "avg" => format!("AVG({})", field()?),
            "min" => format!("MIN({})", field()?),
            "max" => format!("MAX({})", field()?),
            other => bail!("`{other}` is not a column: use count, count_distinct, sum, avg, min, max"),
        });
    }
    let groups = (1..=keys.len()).map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT {}, {} FROM events WHERE {clause} GROUP BY {groups} ORDER BY {} DESC LIMIT {MAX_GROUPS}",
        keys.join(", "),
        exprs.join(", "),
        keys.len() + 1
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(params.iter()))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let key_values: Vec<Value> = (0..keys.len())
            .map(|i| r.get_ref(i).map(json_of))
            .collect::<rusqlite::Result<_>>()?;
        let values: Vec<Value> = (0..exprs.len())
            .map(|i| {
                r.get_ref(keys.len() + i).map(|v| match json_of(v) {
                    // A sum of whole numbers reads as one.
                    Value::Number(n) if n.as_f64().is_some_and(|f| f.fract() == 0.0 && f.abs() < 9e15) => {
                        json!(n.as_f64().unwrap_or(0.0) as i64)
                    }
                    other => other,
                })
            })
            .collect::<rusqlite::Result<_>>()?;
        out.push(json!({"keys": key_values, "values": values}));
    }
    Ok(json!({"groups": out}))
}
