//! Storage, in one SQLite file: events with their outcomes, subjects
//! (actors and tenants), links and clusters of accounts, cases, statements
//! of reasons, rule approvals, list items added at run time, downloaded
//! lists, the outbox, and the audit log.
//!
//! One connection, used under the engine's lock: SQLite in WAL mode with
//! `synchronous = NORMAL` commits an event in tens of microseconds.

use crate::config::Status;
use crate::event::Event;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    type TEXT NOT NULL,
    actor TEXT,
    tenant TEXT,
    body TEXT NOT NULL,
    outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events (at);
CREATE INDEX IF NOT EXISTS events_actor ON events (actor, at);
CREATE INDEX IF NOT EXISTS events_tenant ON events (tenant, at);

-- The rules each event fired, one row per rule: what the rule review reads
-- without opening every stored outcome.
CREATE TABLE IF NOT EXISTS rule_hits (
    event_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    rule TEXT NOT NULL,
    mode TEXT NOT NULL,
    actor TEXT
);
CREATE INDEX IF NOT EXISTS rule_hits_rule ON rule_hits (rule, at);
CREATE INDEX IF NOT EXISTS rule_hits_at ON rule_hits (at);
CREATE INDEX IF NOT EXISTS rule_hits_actor ON rule_hits (actor);
CREATE INDEX IF NOT EXISTS rule_hits_event ON rule_hits (event_id);

CREATE TABLE IF NOT EXISTS subjects (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    created_at INTEGER,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    status TEXT NOT NULL,
    trust INTEGER NOT NULL,
    max_score INTEGER NOT NULL,
    label TEXT,
    firsts TEXT NOT NULL,
    note TEXT,
    updated_at INTEGER NOT NULL,
    country TEXT,
    country_at INTEGER,
    countries TEXT NOT NULL,
    owner TEXT,
    lasts TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS subjects_status ON subjects (kind, status);

-- An actor refused one event type until a time: the `throttle:<duration>` action.
CREATE TABLE IF NOT EXISTS throttles (
    actor TEXT NOT NULL,
    kind TEXT NOT NULL,
    until INTEGER NOT NULL,
    PRIMARY KEY (actor, kind)
);

-- A rule silenced for one actor until a time, after a false positive.
CREATE TABLE IF NOT EXISTS snoozes (
    actor TEXT NOT NULL,
    rule TEXT NOT NULL,
    until INTEGER NOT NULL,
    by_whom TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (actor, rule)
);

-- What an actor was seen with that is not an identifier linking accounts:
-- the network operators (`asn`) it connected through.
CREATE TABLE IF NOT EXISTS seen (
    actor TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    first_at INTEGER NOT NULL,
    last_at INTEGER NOT NULL,
    PRIMARY KEY (actor, kind, value)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS links (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    actor TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (kind, value, actor)
);
CREATE INDEX IF NOT EXISTS links_actor ON links (actor);
-- Recent holders of an identifier, without reading the old ones.
CREATE INDEX IF NOT EXISTS links_recent ON links (kind, value, last_seen);

CREATE TABLE IF NOT EXISTS clusters (
    actor TEXT PRIMARY KEY,
    root TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS clusters_root ON clusters (root);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    status TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    resolved_at INTEGER,
    decision TEXT NOT NULL,
    score INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    events TEXT NOT NULL,
    label TEXT,
    note TEXT,
    resolved_by TEXT,
    summary TEXT,
    appeal TEXT,
    appealed_at INTEGER
);
CREATE INDEX IF NOT EXISTS cases_status ON cases (status, updated_at);
CREATE INDEX IF NOT EXISTS cases_subject ON cases (subject_kind, subject_id);

CREATE TABLE IF NOT EXISTS statements (
    id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS statements_subject ON statements (subject_kind, subject_id);

CREATE TABLE IF NOT EXISTS approvals (
    rule TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    approved_at INTEGER NOT NULL,
    approved_by TEXT NOT NULL,
    report TEXT NOT NULL,
    PRIMARY KEY (rule, fingerprint)
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS list_items (
    list TEXT NOT NULL,
    item TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    note TEXT,
    PRIMARY KEY (list, item)
);

-- Accounts labelled fraud, by the registered domain of their addresses:
-- two on one domain put it on the list `fraud_email_domains`.
CREATE TABLE IF NOT EXISTS fraud_domains (
    domain TEXT NOT NULL,
    actor TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (domain, actor)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS list_cache (
    list TEXT PRIMARY KEY,
    fetched_at INTEGER NOT NULL,
    body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (status, next_at);

CREATE TABLE IF NOT EXISTS external_ids (
    system TEXT NOT NULL,
    external TEXT NOT NULL,
    actor TEXT NOT NULL,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (system, external)
);
CREATE INDEX IF NOT EXISTS external_ids_actor ON external_ids (system, actor);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT
);
"#;

/// An actor (an account that acts) or a tenant (a workspace, team,
/// organisation or store acted on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Actor,
    Tenant,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::Actor => "actor",
            SubjectKind::Tenant => "tenant",
        }
    }

    pub fn parse(text: &str) -> Option<SubjectKind> {
        match text {
            "actor" => Some(SubjectKind::Actor),
            "tenant" => Some(SubjectKind::Tenant),
            _ => None,
        }
    }
}

/// An item added to a list at run time, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct ListEntryRow {
    pub item: String,
    pub added_at: u64,
    pub expires_at: Option<u64>,
    pub archived_at: Option<u64>,
    pub by: String,
    pub note: String,
}

/// A rule silenced for one actor.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snooze {
    pub rule: String,
    pub until: u64,
    pub by: String,
    pub note: String,
    pub created_at: u64,
}

/// What openfraud remembers about an actor or a tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    pub kind: SubjectKind,
    pub id: String,
    /// When the account was created: its first `account.created` event.
    pub created_at: Option<u64>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub status: Status,
    pub trust: u8,
    pub max_score: i64,
    /// `fraud`, `legit` or `false_positive`, set by a person.
    pub label: Option<String>,
    /// The first time the subject had each event type.
    pub firsts: BTreeMap<String, u64>,
    pub note: Option<String>,
    pub updated_at: u64,
    /// The last request country seen, and when.
    pub country: Option<String>,
    pub country_at: Option<u64>,
    /// Every country seen, with the last time.
    pub countries: BTreeMap<String, u64>,
    /// For a tenant: its owner.
    pub owner: Option<String>,
    /// The last time the subject had each event type.
    pub lasts: BTreeMap<String, u64>,
    /// What the application says the account is (`plan`, `seats` ...).
    #[serde(default)]
    pub traits: BTreeMap<String, Value>,
}

impl Subject {
    pub fn new(kind: SubjectKind, id: &str, at: u64) -> Self {
        Subject {
            kind,
            id: id.to_owned(),
            created_at: None,
            first_seen: at,
            last_seen: at,
            status: Status::Normal,
            trust: 0,
            max_score: 0,
            label: None,
            firsts: BTreeMap::new(),
            note: None,
            updated_at: at,
            country: None,
            country_at: None,
            countries: BTreeMap::new(),
            owner: None,
            lasts: BTreeMap::new(),
            traits: BTreeMap::new(),
        }
    }

    /// Quarantined, or labelled fraud by a person.
    pub fn flagged(&self) -> bool {
        self.status == Status::Quarantined || self.label.as_deref() == Some("fraud")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Case {
    pub id: i64,
    pub subject_kind: SubjectKind,
    pub subject_id: String,
    /// `open`, `appealed` or `resolved`.
    pub status: String,
    pub opened_at: u64,
    pub updated_at: u64,
    pub resolved_at: Option<u64>,
    pub decision: String,
    pub score: i64,
    pub reasons: Vec<String>,
    pub events: Vec<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    pub resolved_by: Option<String>,
    pub summary: Option<String>,
    pub appeal: Option<String>,
    pub appealed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboxItem {
    pub id: i64,
    pub kind: String,
    pub payload: String,
    pub attempts: u32,
    pub next_at: u64,
    pub status: String,
    pub last_error: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: Option<String>,
}

pub struct Store {
    conn: Connection,
    /// The write-ahead log beside a database file; none in memory.
    wal: Option<std::path::PathBuf>,
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

fn from_json<T: for<'de> Deserialize<'de> + Default>(text: &str) -> T {
    serde_json::from_str(text).unwrap_or_default()
}

const SUBJECT_COLUMNS: &str = "kind, id, created_at, first_seen, last_seen, status, trust, max_score, label, firsts, note, updated_at, country, country_at, countries, owner, lasts, traits";

fn subject_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Subject> {
    Ok(Subject {
        kind: SubjectKind::parse(&r.get::<_, String>(0)?).unwrap_or(SubjectKind::Actor),
        id: r.get(1)?,
        created_at: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
        first_seen: r.get::<_, i64>(3)? as u64,
        last_seen: r.get::<_, i64>(4)? as u64,
        status: Status::parse(&r.get::<_, String>(5)?).unwrap_or_default(),
        trust: r.get::<_, i64>(6)?.clamp(0, 255) as u8,
        max_score: r.get(7)?,
        label: r.get(8)?,
        firsts: from_json(&r.get::<_, String>(9)?),
        note: r.get(10)?,
        updated_at: r.get::<_, i64>(11)? as u64,
        country: r.get(12)?,
        country_at: r.get::<_, Option<i64>>(13)?.map(|v| v as u64),
        countries: from_json(&r.get::<_, String>(14)?),
        owner: r.get(15)?,
        lasts: from_json(&r.get::<_, String>(16)?),
        traits: from_json(&r.get::<_, String>(17)?),
    })
}

const CASE_COLUMNS: &str = "id, subject_kind, subject_id, status, opened_at, updated_at, resolved_at, decision, score, reasons, events, label, note, resolved_by, summary, appeal, appealed_at";

fn case_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Case> {
    Ok(Case {
        id: r.get(0)?,
        subject_kind: SubjectKind::parse(&r.get::<_, String>(1)?).unwrap_or(SubjectKind::Actor),
        subject_id: r.get(2)?,
        status: r.get(3)?,
        opened_at: r.get::<_, i64>(4)? as u64,
        updated_at: r.get::<_, i64>(5)? as u64,
        resolved_at: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
        decision: r.get(7)?,
        score: r.get(8)?,
        reasons: from_json(&r.get::<_, String>(9)?),
        events: from_json(&r.get::<_, String>(10)?),
        label: r.get(11)?,
        note: r.get(12)?,
        resolved_by: r.get(13)?,
        summary: r.get(14)?,
        appeal: r.get(15)?,
        appealed_at: r.get::<_, Option<i64>>(16)?.map(|v| v as u64),
    })
}

fn outbox_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxItem> {
    Ok(OutboxItem {
        id: r.get(0)?,
        kind: r.get(1)?,
        payload: r.get(2)?,
        attempts: r.get::<_, i64>(3)? as u32,
        next_at: r.get::<_, i64>(4)? as u64,
        status: r.get(5)?,
        last_error: r.get(6)?,
        created_at: r.get::<_, i64>(7)? as u64,
    })
}

/// The size the write-ahead log is cut back to once a checkpoint has
/// copied it into the database.
pub const WAL_LIMIT: u64 = 64 << 20;

/// Past this size the engine cuts the log back itself, after a decision,
/// without waiting for the checkpoint thread.
pub const WAL_HARD_LIMIT: u64 = WAL_LIMIT + WAL_LIMIT / 2;

impl Store {
    /// The database at `path`, or a private in-memory one.
    pub fn open(path: Option<&Path>) -> Result<Store> {
        let conn = match path {
            Some(p) => Connection::open(p).with_context(|| format!("cannot open the database {}", p.display()))?,
            None => Connection::open_in_memory()?,
        };
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;
             PRAGMA cache_size = -65536; PRAGMA temp_store = MEMORY; PRAGMA journal_size_limit = 67108864;",
        )?;
        conn.execute_batch(SCHEMA).context("cannot create the database tables")?;
        // Columns added after the first release: a database made before gets them.
        for (table, column, kind) in [
            ("list_items", "expires_at", "INTEGER"),
            ("list_items", "archived_at", "INTEGER"),
            ("list_items", "by_whom", "TEXT"),
            ("subjects", "traits", "TEXT NOT NULL DEFAULT '{}'"),
        ] {
            let present: bool = conn
                .prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"))?
                .query_row([column], |_| Ok(()))
                .optional()?
                .is_some();
            if !present {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind};"))?;
            }
        }
        // A database from before the `rule_hits` table: fill it once from the
        // stored outcomes.
        let filled: bool = conn
            .query_row("SELECT 1 FROM kv WHERE key = 'rule_hits_filled'", [], |_| Ok(()))
            .optional()?
            .is_some();
        if !filled {
            conn.execute_batch(
                "INSERT INTO rule_hits (event_id, at, rule, mode, actor)
                   SELECT events.id, events.at, COALESCE(json_extract(r.value, '$.rule'), json_extract(r.value, '$.id')),
                          COALESCE(json_extract(r.value, '$.mode'), 'act'), events.actor
                   FROM events, json_each(events.outcome, '$.rules') AS r;
                 INSERT INTO kv (key, value) VALUES ('rule_hits_filled', 'true');",
            )
            .context("cannot index the rules of the stored events")?;
        }
        if path.is_some() {
            // A checkpoint copies the log into the database and syncs it: tens
            // of milliseconds. The engine's connection never does it, so no
            // decision waits on one; `checkpoint` runs from another thread.
            conn.execute_batch("PRAGMA wal_autocheckpoint = 0;")?;
        }
        let wal = path.map(|p| {
            let mut wal = p.as_os_str().to_owned();
            wal.push("-wal");
            std::path::PathBuf::from(wal)
        });
        Ok(Store { conn, wal })
    }

    /// Copies the write-ahead log into the database file, on a connection of
    /// its own, without blocking the engine (SQLite's passive checkpoint).
    /// Under steady writes a passive checkpoint never catches up, so the log
    /// would grow without end: true when it has passed [`WAL_LIMIT`] and the
    /// engine should cut it back with [`Store::truncate_log`].
    pub fn checkpoint(path: &Path) -> Result<bool> {
        // Past the limit, no passive round first: on a slow disk one takes
        // seconds, and the log keeps growing meanwhile.
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        if std::fs::metadata(&wal).is_ok_and(|m| m.len() > WAL_LIMIT) {
            return Ok(true);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA busy_timeout = 1000;")?;
        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        Ok(false)
    }

    /// Whether the log has grown past its hard limit: the checkpoint thread
    /// lags (a slow disk), so the engine must cut it back itself.
    pub fn wal_overflowing(&self) -> bool {
        self.wal
            .as_ref()
            .is_some_and(|w| std::fs::metadata(w).is_ok_and(|m| m.len() > WAL_HARD_LIMIT))
    }

    /// Copies what is left of the log and cuts the file to zero, on the
    /// engine's own connection: between two decisions, with no other writer
    /// to wait for.
    pub fn truncate_log(&self) -> Result<()> {
        self.conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    /// Runs a read of its own on the connection: the admin's queries.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        f(&self.conn)
    }

    /// Events per type in `[from, to)`.
    pub fn type_counts(&self, from: u64, to: u64) -> Result<BTreeMap<String, u64>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT type, COUNT(*) FROM events WHERE at >= ?1 AND at < ?2 GROUP BY type")?;
        let rows = stmt.query_map(params![from as i64, to as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (kind, n) = row?;
            out.insert(kind, n as u64);
        }
        Ok(out)
    }

    /// The rules that fired most since `since`, acting or in shadow.
    pub fn top_rules(&self, since: u64, limit: usize) -> Result<Vec<(String, u64)>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT rule, COUNT(*) AS n FROM rule_hits WHERE at >= ?1 GROUP BY rule ORDER BY n DESC, rule LIMIT ?2")?;
        let rows = stmt.query_map(params![since as i64, limit as i64], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The signals seen most since `since`.
    pub fn top_signals(&self, since: u64, limit: usize) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT s.key, COUNT(*) AS n FROM events, json_each(events.outcome, '$.signals') AS s
             WHERE events.at >= ?1 GROUP BY s.key ORDER BY n DESC, s.key LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since as i64, limit as i64], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The values an actor was seen with for one identifier kind: (value,
    /// first seen, last seen).
    pub fn links_detail(&self, actor: &str, kind: &str) -> Result<Vec<(String, u64, u64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT value, first_seen, last_seen FROM links WHERE actor = ?1 AND kind = ?2 ORDER BY last_seen DESC LIMIT 100",
        )?;
        let rows = stmt.query_map(params![actor, kind], |r| {
            Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The lists with an active item that is the actor, alone or first in a pair.
    pub fn lists_holding(&self, actor: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT DISTINCT list FROM list_items WHERE archived_at IS NULL
               AND (item = ?1 OR item LIKE ?2 || char(31) || '%' ESCAPE '!') ORDER BY list",
        )?;
        let escaped = actor.replace('!', "!!").replace('%', "!%").replace('_', "!_");
        let rows = stmt.query_map(params![actor, escaped], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Runs `f` in one transaction: everything or nothing.
    pub fn atomically<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        // Immediate: the write lock is taken first, so a checkpoint running
        // meanwhile makes it wait (busy_timeout) instead of failing.
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let out = f(self)?;
        tx.commit()?;
        Ok(out)
    }

    // ------------------------------------------------------------ events

    pub fn outcome_of(&self, event_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT outcome FROM events WHERE id = ?1")?
            .query_row([event_id], |r| r.get(0))
            .optional()?)
    }

    /// Stores an event, its outcome, and one row per rule it fired: (rule,
    /// mode).
    pub fn insert_event(&self, event: &Event, outcome: &str, rules: &[(&str, &str)]) -> Result<()> {
        let inserted = self
            .conn
            .prepare_cached(
                "INSERT OR IGNORE INTO events (id, at, type, actor, tenant, body, outcome) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?
            .execute(params![
                event.id,
                event.at as i64,
                event.kind,
                event.actor,
                event.tenant,
                json(event),
                outcome
            ])?;
        if inserted > 0 {
            let mut stmt = self
                .conn
                .prepare_cached("INSERT INTO rule_hits (event_id, at, rule, mode, actor) VALUES (?1, ?2, ?3, ?4, ?5)")?;
            for (rule, mode) in rules {
                stmt.execute(params![event.id, event.at as i64, rule, mode, event.actor])?;
            }
        }
        Ok(())
    }

    /// Events from `since` on, oldest first, with their outcomes.
    pub fn events_since(&self, since: u64, mut f: impl FnMut(Event, String) -> Result<()>) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT body, outcome FROM events WHERE at >= ?1 ORDER BY at, rowid")?;
        let mut rows = stmt.query([since as i64])?;
        while let Some(row) = rows.next()? {
            let body: String = row.get(0)?;
            let outcome: String = row.get(1)?;
            if let Ok(event) = serde_json::from_str::<Event>(&body) {
                f(event, outcome)?;
            }
        }
        Ok(())
    }

    /// The latest events of a subject, newest first.
    pub fn subject_events(&self, kind: SubjectKind, id: &str, limit: usize) -> Result<Vec<(Event, String)>> {
        let sql = match kind {
            SubjectKind::Actor => "SELECT body, outcome FROM events WHERE actor = ?1 ORDER BY at DESC, rowid DESC LIMIT ?2",
            SubjectKind::Tenant => "SELECT body, outcome FROM events WHERE tenant = ?1 ORDER BY at DESC, rowid DESC LIMIT ?2",
        };
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params![id, limit as i64], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (body, outcome) = row?;
            if let Ok(event) = serde_json::from_str(&body) {
                out.push((event, outcome));
            }
        }
        Ok(out)
    }

    /// The time of the oldest event kept.
    pub fn first_event_at(&self) -> Result<Option<u64>> {
        Ok(self
            .conn
            .query_row("SELECT MIN(at) FROM events", [], |r| r.get::<_, Option<i64>>(0))?
            .map(|v| v as u64))
    }

    pub fn event_count(&self) -> Result<u64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))? as u64)
    }

    /// Decisions per kind since `since`.
    pub fn decision_counts(&self, since: u64) -> Result<BTreeMap<String, u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json_extract(outcome, '$.decision'), COUNT(*) FROM events WHERE at >= ?1 GROUP BY 1")?;
        let rows = stmt.query_map([since as i64], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (decision, n) = row?;
            out.insert(decision.unwrap_or_default(), n as u64);
        }
        Ok(out)
    }

    /// For each rule fired since `since`: (mode, actor) pairs, once per
    /// event. For precision, recall and the overview.
    pub fn rule_hits(&self, since: u64) -> Result<Vec<(String, String, Option<String>)>> {
        let mut stmt = self.conn.prepare("SELECT rule, mode, actor FROM rule_hits WHERE at >= ?1")?;
        let rows = stmt.query_map([since as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The accounts a rule fired on since `since`, in shadow or acting, the
    /// one it fired on last first: at most `limit`.
    pub fn rule_hit_actors(&self, rule: &str, since: u64, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT actor FROM rule_hits WHERE rule = ?2 AND at >= ?1 AND actor IS NOT NULL
             GROUP BY actor ORDER BY MAX(at) DESC, MAX(rowid) DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(rusqlite::params![since as i64, rule, limit as i64], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Automatic restrictions (hold, block, quarantine in act mode) since
    /// `since`, as event times: for the safety brake's baseline.
    pub fn restriction_times(&self, since: u64) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT at FROM events WHERE at >= ?1 AND json_extract(outcome, '$.decision') IN ('hold', 'block', 'quarantine')
             AND COALESCE(json_extract(outcome, '$.brake'), 0) = 0 AND COALESCE(json_extract(outcome, '$.repeat'), 0) = 0 ORDER BY at",
        )?;
        let rows = stmt.query_map([since as i64], |r| r.get::<_, i64>(0).map(|v| v as u64))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ---------------------------------------------------------- subjects

    pub fn subject(&self, kind: SubjectKind, id: &str) -> Result<Option<Subject>> {
        Ok(self
            .conn
            .prepare_cached(&format!("SELECT {SUBJECT_COLUMNS} FROM subjects WHERE kind = ?1 AND id = ?2"))?
            .query_row(params![kind.as_str(), id], subject_from_row)
            .optional()?)
    }

    /// Until when the actor is refused this event type, if it is.
    pub fn throttled_until(&self, actor: &str, kind: &str, at: u64) -> Result<Option<u64>> {
        let until: Option<i64> = self
            .conn
            .prepare_cached("SELECT until FROM throttles WHERE actor = ?1 AND kind = ?2")?
            .query_row(params![actor, kind], |r| r.get(0))
            .optional()?;
        Ok(until.map(|u| u as u64).filter(|u| *u > at))
    }

    /// Refuses the actor this event type until `until`; a longer throttle wins.
    pub fn throttle(&self, actor: &str, kind: &str, until: u64) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO throttles (actor, kind, until) VALUES (?1, ?2, ?3)
                 ON CONFLICT (actor, kind) DO UPDATE SET until = MAX(until, ?3)",
            )?
            .execute(params![actor, kind, until as i64])?;
        Ok(())
    }

    /// Silences a rule for an actor until `until`, replacing an earlier snooze.
    pub fn snooze(&self, actor: &str, rule: &str, until: u64, by: &str, note: &str, at: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO snoozes (actor, rule, until, by_whom, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (actor, rule) DO UPDATE SET until = ?3, by_whom = ?4, note = ?5, created_at = ?6",
            params![actor, rule, until as i64, by, note, at as i64],
        )?;
        Ok(())
    }

    pub fn unsnooze(&self, actor: &str, rule: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM snoozes WHERE actor = ?1 AND rule = ?2", [actor, rule])?
            > 0)
    }

    /// The actor's snoozes, running or not yet purged.
    pub fn snoozes_of(&self, actor: &str) -> Result<Vec<Snooze>> {
        let mut stmt = self
            .conn
            .prepare("SELECT rule, until, by_whom, note, created_at FROM snoozes WHERE actor = ?1 ORDER BY rule")?;
        let rows = stmt.query_map([actor], |r| {
            Ok(Snooze {
                rule: r.get(0)?,
                until: r.get::<_, i64>(1)? as u64,
                by: r.get(2)?,
                note: r.get(3)?,
                created_at: r.get::<_, i64>(4)? as u64,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The rules silenced for the actor at `at`.
    pub fn snoozed_rules(&self, actor: &str, at: u64) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT rule FROM snoozes WHERE actor = ?1 AND until > ?2")?;
        let rows = stmt.query_map(params![actor, at as i64], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Deletes the snoozes that have ended.
    pub fn purge_snoozes(&self, now: u64) -> Result<u64> {
        Ok(self.conn.execute("DELETE FROM snoozes WHERE until <= ?1", [now as i64])? as u64)
    }

    /// How many values of a kind the actor was seen with.
    pub fn seen_count(&self, actor: &str, kind: &str) -> Result<u64> {
        let n: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM seen WHERE actor = ?1 AND kind = ?2")?
            .query_row(params![actor, kind], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn has_seen(&self, actor: &str, kind: &str, value: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM seen WHERE actor = ?1 AND kind = ?2 AND value = ?3")?
            .query_row(params![actor, kind, value], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn mark_seen(&self, actor: &str, kind: &str, value: &str, at: u64) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO seen (actor, kind, value, first_at, last_at) VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT (actor, kind, value) DO UPDATE SET last_at = MAX(last_at, ?4)",
            )?
            .execute(params![actor, kind, value, at as i64])?;
        Ok(())
    }

    /// Everything the actor was seen with, for an export.
    pub fn seen_of(&self, actor: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, value FROM seen WHERE actor = ?1 ORDER BY kind, value")?;
        let rows = stmt.query_map([actor], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Deletes the throttles that have ended: they keep nothing worth an account id.
    pub fn purge_throttles(&self, now: u64) -> Result<u64> {
        Ok(self.conn.execute("DELETE FROM throttles WHERE until <= ?1", [now as i64])? as u64)
    }

    /// Lifts every throttle of an actor: a release.
    pub fn clear_throttles(&self, actor: &str) -> Result<()> {
        self.conn.execute("DELETE FROM throttles WHERE actor = ?1", [actor])?;
        Ok(())
    }

    pub fn put_subject(&self, s: &Subject) -> Result<()> {
        self.conn
            .prepare_cached(&format!(
                "INSERT INTO subjects ({SUBJECT_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                 ON CONFLICT (kind, id) DO UPDATE SET created_at = ?3, first_seen = ?4, last_seen = ?5, status = ?6, trust = ?7,
                   max_score = ?8, label = ?9, firsts = ?10, note = ?11, updated_at = ?12, country = ?13, country_at = ?14,
                   countries = ?15, owner = ?16, lasts = ?17, traits = ?18"
            ))?
            .execute(params![
                s.kind.as_str(),
                s.id,
                s.created_at.map(|v| v as i64),
                s.first_seen as i64,
                s.last_seen as i64,
                s.status.as_str(),
                s.trust as i64,
                s.max_score,
                s.label,
                json(&s.firsts),
                s.note,
                s.updated_at as i64,
                s.country,
                s.country_at.map(|v| v as i64),
                json(&s.countries),
                s.owner,
                json(&s.lasts),
                json(&s.traits)
            ])?;
        Ok(())
    }

    pub fn subject_counts(&self, kind: SubjectKind) -> Result<BTreeMap<String, u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT status, COUNT(*) FROM subjects WHERE kind = ?1 GROUP BY status")?;
        let rows = stmt.query_map([kind.as_str()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (status, n) = row?;
            out.insert(status, n as u64);
        }
        Ok(out)
    }

    /// Labelled actors: (id, label).
    pub fn labels(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, label FROM subjects WHERE kind = 'actor' AND label IS NOT NULL ORDER BY updated_at DESC")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ------------------------------------------------------------- links

    /// Other actors seen with this identifier (since `since`), and how many
    /// are flagged. Counts stop at 1,000.
    pub fn link_counts(&self, kind: &str, value: &str, except: Option<&str>, since: u64) -> Result<(u64, u64)> {
        let (users, flagged): (i64, i64) = self
            .conn
            .prepare_cached(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN s.status = 'quarantined' OR s.label = 'fraud' THEN 1 ELSE 0 END), 0)
                 FROM (SELECT actor FROM links WHERE kind = ?1 AND value = ?2 AND actor != ?3 AND last_seen >= ?4 LIMIT 1000) l
                 LEFT JOIN subjects s ON s.kind = 'actor' AND s.id = l.actor",
            )?
            .query_row(params![kind, value, except.unwrap_or(""), since as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        Ok((users as u64, flagged as u64))
    }

    /// The other actors seen with an identifier since `since`, at most `limit`.
    pub fn link_actors(&self, kind: &str, value: &str, except: &str, since: u64, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT actor FROM links WHERE kind = ?1 AND value = ?2 AND actor != ?3 AND last_seen >= ?4 LIMIT ?5")?;
        let rows = stmt.query_map(params![kind, value, except, since as i64, limit as i64], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn add_links(&self, actor: &str, ids: &BTreeMap<String, String>, at: u64) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO links (kind, value, actor, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT (kind, value, actor) DO UPDATE SET last_seen = MAX(last_seen, ?4)",
        )?;
        for (kind, value) in ids {
            stmt.execute(params![kind, value, actor, at as i64])?;
        }
        Ok(())
    }

    /// Whether the actor was seen with this identifier before.
    pub fn has_link(&self, actor: &str, kind: &str, value: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM links WHERE kind = ?1 AND value = ?2 AND actor = ?3")?
            .query_row(params![kind, value, actor], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// The actor seen last with an identifier.
    pub fn last_holder(&self, kind: &str, value: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT actor FROM links WHERE kind = ?1 AND value = ?2 ORDER BY last_seen DESC, actor LIMIT 1")?
            .query_row(params![kind, value], |r| r.get(0))
            .optional()?)
    }

    /// Records an account labelled fraud under a registered domain; returns
    /// how many such accounts the domain has.
    pub fn fraud_domain(&self, domain: &str, actor: &str, at: u64) -> Result<u64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO fraud_domains (domain, actor, at) VALUES (?1, ?2, ?3)",
            params![domain, actor, at as i64],
        )?;
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM fraud_domains WHERE domain = ?1", [domain], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// The identifiers of an actor: (kind, value).
    pub fn links_of(&self, actor: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, value FROM links WHERE actor = ?1 ORDER BY kind, value")?;
        let rows = stmt.query_map([actor], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ---------------------------------------------------------- clusters

    pub fn cluster_root(&self, actor: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT root FROM clusters WHERE actor = ?1")?
            .query_row([actor], |r| r.get(0))
            .optional()?)
    }

    pub fn cluster_members(&self, root: &str, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT actor FROM clusters WHERE root = ?1 ORDER BY actor LIMIT ?2")?;
        let rows = stmt.query_map(params![root, limit as i64], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Members of a cluster: the index alone, no join.
    pub fn cluster_size(&self, root: &str) -> Result<u64> {
        let n: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM clusters WHERE root = ?1")?
            .query_row([root], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Size, flagged members, and members labelled fraud and legit.
    pub fn cluster_stats(&self, root: &str) -> Result<(u64, u64, u64, u64)> {
        let row: (i64, i64, i64, i64) = self
            .conn
            .prepare_cached(
                "SELECT COUNT(*),
                   COALESCE(SUM(CASE WHEN s.status = 'quarantined' OR s.label = 'fraud' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN s.label = 'fraud' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN s.label IN ('legit', 'false_positive') THEN 1 ELSE 0 END), 0)
                 FROM clusters c LEFT JOIN subjects s ON s.kind = 'actor' AND s.id = c.actor WHERE c.root = ?1",
            )?
            .query_row([root], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok((row.0 as u64, row.1 as u64, row.2 as u64, row.3 as u64))
    }

    /// Puts `actor` in a cluster of its own if it has none.
    pub fn ensure_cluster(&self, actor: &str) -> Result<String> {
        if let Some(root) = self.cluster_root(actor)? {
            return Ok(root);
        }
        self.conn.execute("INSERT INTO clusters (actor, root) VALUES (?1, ?1)", [actor])?;
        Ok(actor.to_owned())
    }

    /// Joins two clusters: the smaller takes the root of the larger.
    pub fn union_clusters(&self, a: &str, b: &str) -> Result<String> {
        let (ra, rb) = (self.ensure_cluster(a)?, self.ensure_cluster(b)?);
        if ra == rb {
            return Ok(ra);
        }
        let size = |root: &str| -> Result<i64> {
            Ok(self
                .conn
                .query_row("SELECT COUNT(*) FROM clusters WHERE root = ?1", [root], |r| r.get(0))?)
        };
        let (keep, merge) = if size(&ra)? >= size(&rb)? { (ra, rb) } else { (rb, ra) };
        self.conn
            .execute("UPDATE clusters SET root = ?1 WHERE root = ?2", params![keep, merge])?;
        Ok(keep)
    }

    // ------------------------------------------------------------- cases

    pub fn open_case_of(&self, kind: SubjectKind, id: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT id FROM cases WHERE subject_kind = ?1 AND subject_id = ?2 AND status != 'resolved' ORDER BY id DESC LIMIT 1",
            )?
            .query_row(params![kind.as_str(), id], |r| r.get(0))
            .optional()?)
    }

    /// Adds the event to the subject's open case, or opens one. Returns the
    /// case id and whether it is new.
    #[allow(clippy::too_many_arguments)]
    pub fn record_case(
        &self,
        kind: SubjectKind,
        id: &str,
        at: u64,
        decision: &str,
        score: i64,
        reasons: &[String],
        event_id: &str,
    ) -> Result<(i64, bool)> {
        if let Some(case_id) = self.open_case_of(kind, id)? {
            let case = self.case(case_id)?.context("the open case disappeared")?;
            let mut all = case.reasons.clone();
            for r in reasons {
                if !all.contains(r) {
                    all.push(r.clone());
                }
            }
            let mut events = case.events.clone();
            if !events.iter().any(|e| e == event_id) {
                events.push(event_id.to_owned());
            }
            let rank = |d: &str| crate::config::Decision::parse(d).map(|d| d as u8).unwrap_or(0);
            let decision = if rank(decision) > rank(&case.decision) {
                decision
            } else {
                case.decision.as_str()
            };
            self.conn.execute(
                "UPDATE cases SET updated_at = ?2, decision = ?3, score = MAX(score, ?4), reasons = ?5, events = ?6 WHERE id = ?1",
                params![case_id, at as i64, decision, score, json(&all), json(&events)],
            )?;
            return Ok((case_id, false));
        }
        self.conn.execute(
            "INSERT INTO cases (subject_kind, subject_id, status, opened_at, updated_at, decision, score, reasons, events)
             VALUES (?1, ?2, 'open', ?3, ?3, ?4, ?5, ?6, ?7)",
            params![kind.as_str(), id, at as i64, decision, score, json(&reasons), json(&[event_id])],
        )?;
        Ok((self.conn.last_insert_rowid(), true))
    }

    pub fn case(&self, id: i64) -> Result<Option<Case>> {
        Ok(self
            .conn
            .prepare_cached(&format!("SELECT {CASE_COLUMNS} FROM cases WHERE id = ?1"))?
            .query_row([id], case_from_row)
            .optional()?)
    }

    /// Cases, newest activity first; open and appealed ones only, or all.
    pub fn cases(&self, open_only: bool, limit: usize, offset: usize) -> Result<Vec<Case>> {
        let filter = if open_only { "WHERE status != 'resolved'" } else { "" };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {CASE_COLUMNS} FROM cases {filter} ORDER BY updated_at DESC, id DESC LIMIT ?1 OFFSET ?2"
        ))?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], case_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn subject_cases(&self, kind: SubjectKind, id: &str) -> Result<Vec<Case>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {CASE_COLUMNS} FROM cases WHERE subject_kind = ?1 AND subject_id = ?2 ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![kind.as_str(), id], case_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn resolve_case(&self, id: i64, label: &str, note: &str, actor: &str, at: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE cases SET status = 'resolved', resolved_at = ?2, updated_at = ?2, label = ?3, note = ?4, resolved_by = ?5 WHERE id = ?1",
            params![id, at as i64, label, note, actor],
        )?;
        Ok(())
    }

    pub fn appeal_case(&self, id: i64, message: &str, at: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE cases SET status = 'appealed', appeal = ?2, appealed_at = ?3, updated_at = ?3 WHERE id = ?1",
            params![id, message, at as i64],
        )?;
        Ok(())
    }

    pub fn set_case_summary(&self, id: i64, summary: &str) -> Result<()> {
        self.conn
            .execute("UPDATE cases SET summary = ?2 WHERE id = ?1", params![id, summary])?;
        Ok(())
    }

    // -------------------------------------------------------- statements

    pub fn put_statement(&self, id: &str, kind: SubjectKind, subject: &str, at: u64, body: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO statements (id, subject_kind, subject_id, created_at, body) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, kind.as_str(), subject, at as i64, body.to_string()],
        )?;
        Ok(())
    }

    pub fn statement(&self, id: &str) -> Result<Option<Value>> {
        Ok(self
            .conn
            .query_row("SELECT body FROM statements WHERE id = ?1", [id], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn subject_statements(&self, kind: SubjectKind, id: &str) -> Result<Vec<Value>> {
        let mut stmt = self
            .conn
            .prepare("SELECT body FROM statements WHERE subject_kind = ?1 AND subject_id = ?2 ORDER BY created_at")?;
        let rows = stmt.query_map(params![kind.as_str(), id], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).filter_map(|b| serde_json::from_str(&b).ok()).collect())
    }

    // --------------------------------------------------------- approvals

    pub fn approval(&self, rule: &str, fingerprint: &str) -> Result<Option<Value>> {
        Ok(self
            .conn
            .query_row(
                "SELECT report FROM approvals WHERE rule = ?1 AND fingerprint = ?2",
                params![rule, fingerprint],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn approvals(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT rule, fingerprint FROM approvals")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn put_approval(&self, rule: &str, fingerprint: &str, at: u64, by: &str, report: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO approvals (rule, fingerprint, approved_at, approved_by, report) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![rule, fingerprint, at as i64, by, report.to_string()],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- kv

    pub fn get_kv(&self, key: &str) -> Result<Option<Value>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn put_kv(&self, key: &str, value: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2",
            params![key, value.to_string()],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------- lists

    /// The items added at run time and not archived: (list, item, end).
    pub fn list_items(&self) -> Result<Vec<(String, String, Option<u64>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT list, item, expires_at FROM list_items WHERE archived_at IS NULL ORDER BY list, item")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<i64>>(2)?.map(|v| v as u64))))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn add_list_item(&self, list: &str, item: &str, note: &str, at: u64) -> Result<bool> {
        self.put_list_item(list, item, note, "api", at, None)
    }

    /// Adds an item, or gives an archived one back, until `expires_at`.
    /// An item already there gets the new end. True when the item was not
    /// active before.
    pub fn put_list_item(&self, list: &str, item: &str, note: &str, by: &str, at: u64, expires_at: Option<u64>) -> Result<bool> {
        let before: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT archived_at FROM list_items WHERE list = ?1 AND item = ?2",
                params![list, item],
                |r| r.get(0),
            )
            .optional()?;
        match before {
            None => {
                self.conn.execute(
                    "INSERT INTO list_items (list, item, added_at, note, expires_at, archived_at, by_whom) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                    params![list, item, at as i64, note, expires_at.map(|v| v as i64), by],
                )?;
                Ok(true)
            }
            Some(archived) => {
                self.conn.execute(
                    "UPDATE list_items SET expires_at = ?3, archived_at = NULL,
                       added_at = CASE WHEN archived_at IS NULL THEN added_at ELSE ?4 END,
                       note = CASE WHEN ?5 = '' THEN note ELSE ?5 END,
                       by_whom = CASE WHEN archived_at IS NULL THEN by_whom ELSE ?6 END
                     WHERE list = ?1 AND item = ?2",
                    params![list, item, expires_at.map(|v| v as i64), at as i64, note, by],
                )?;
                Ok(archived.is_some())
            }
        }
    }

    /// Archives an active item at `at`: it stops matching and stays on record.
    pub fn archive_list_item(&self, list: &str, item: &str, at: u64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE list_items SET archived_at = ?3 WHERE list = ?1 AND item = ?2 AND archived_at IS NULL",
            params![list, item, at as i64],
        )? > 0)
    }

    /// Gives an archived item back, until `expires_at`.
    pub fn unarchive_list_item(&self, list: &str, item: &str, expires_at: Option<u64>) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE list_items SET archived_at = NULL, expires_at = ?3 WHERE list = ?1 AND item = ?2 AND archived_at IS NOT NULL",
            params![list, item, expires_at.map(|v| v as i64)],
        )? > 0)
    }

    /// The active items whose end is at or before `now`: (list, item, end).
    pub fn ended_list_items(&self, now: u64) -> Result<Vec<(String, String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT list, item, expires_at FROM list_items WHERE archived_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?1",
        )?;
        let rows = stmt.query_map([now as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u64)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The items of a list added at run time, archived ones too when asked.
    pub fn list_entries(&self, list: &str, archived: bool) -> Result<Vec<ListEntryRow>> {
        let filter = if archived { "" } else { "AND archived_at IS NULL" };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT item, added_at, expires_at, archived_at, COALESCE(by_whom, 'api'), COALESCE(note, '')
             FROM list_items WHERE list = ?1 {filter} ORDER BY added_at, item"
        ))?;
        let rows = stmt.query_map([list], |r| {
            Ok(ListEntryRow {
                item: r.get(0)?,
                added_at: r.get::<_, i64>(1)? as u64,
                expires_at: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                archived_at: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                by: r.get(4)?,
                note: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn remove_list_item(&self, list: &str, item: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM list_items WHERE list = ?1 AND item = ?2", params![list, item])?
            > 0)
    }

    pub fn list_cache(&self, list: &str) -> Result<Option<(u64, String)>> {
        Ok(self
            .conn
            .query_row("SELECT fetched_at, body FROM list_cache WHERE list = ?1", [list], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
            })
            .optional()?)
    }

    pub fn put_list_cache(&self, list: &str, at: u64, body: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO list_cache (list, fetched_at, body) VALUES (?1, ?2, ?3) ON CONFLICT (list) DO UPDATE SET fetched_at = ?2, body = ?3",
            params![list, at as i64, body],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------ outbox

    pub fn outbox_push(&self, kind: &str, payload: &str, at: u64) -> Result<i64> {
        self.conn
            .prepare_cached("INSERT INTO outbox (kind, payload, next_at, created_at) VALUES (?1, ?2, ?3, ?3)")?
            .execute(params![kind, payload, at as i64])?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn outbox_due(&self, now: u64, limit: usize) -> Result<Vec<OutboxItem>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, kind, payload, attempts, next_at, status, last_error, created_at FROM outbox
             WHERE status = 'pending' AND next_at <= ?1 ORDER BY next_at, id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now as i64, limit as i64], outbox_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn outbox_recent(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, payload, attempts, next_at, status, last_error, created_at FROM outbox ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], outbox_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Marks an item delivered, failed for good, or to retry at `next_at`.
    pub fn outbox_result(&self, id: i64, status: &str, next_at: u64, error: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET status = ?2, attempts = attempts + 1, next_at = ?3, last_error = ?4 WHERE id = ?1",
            params![id, status, next_at as i64, error],
        )?;
        Ok(())
    }

    // ------------------------------------------------------- external ids

    /// Links an id of another system (a Stripe customer) to an actor.
    pub fn put_external(&self, system: &str, external: &str, actor: &str, at: u64) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO external_ids (system, external, actor, seen_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (system, external) DO UPDATE SET actor = ?3, seen_at = ?4",
            )?
            .execute(params![system, external, actor, at as i64])?;
        Ok(())
    }

    pub fn user_of_external(&self, system: &str, external: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT actor FROM external_ids WHERE system = ?1 AND external = ?2")?
            .query_row(params![system, external], |r| r.get(0))
            .optional()?)
    }

    pub fn externals_of_user(&self, system: &str, actor: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT external FROM external_ids WHERE system = ?1 AND actor = ?2 ORDER BY external")?;
        let rows = stmt.query_map(params![system, actor], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ------------------------------------------------------------- audit

    pub fn audit(&self, at: u64, actor: &str, action: &str, target: &str, detail: &str) -> Result<()> {
        self.conn
            .prepare_cached("INSERT INTO audit (at, actor, action, target, detail) VALUES (?1, ?2, ?3, ?4, ?5)")?
            .execute(params![at as i64, actor, action, target, detail])?;
        Ok(())
    }

    pub fn audit_log(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT at, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok(AuditEntry {
                at: r.get::<_, i64>(0)? as u64,
                actor: r.get(1)?,
                action: r.get(2)?,
                target: r.get(3)?,
                detail: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn audit_of(&self, target: &str) -> Result<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT at, actor, action, target, detail FROM audit WHERE target = ?1 ORDER BY id")?;
        let rows = stmt.query_map([target], |r| {
            Ok(AuditEntry {
                at: r.get::<_, i64>(0)? as u64,
                actor: r.get(1)?,
                action: r.get(2)?,
                target: r.get(3)?,
                detail: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ------------------------------------------------- export and erasure

    /// Deletes every record about an actor except the audit log entries
    /// (which hold the people's acts). Returns the rows deleted.
    pub fn erase_actor(&self, id: &str) -> Result<u64> {
        let mut n = 0;
        n += self.conn.execute("DELETE FROM events WHERE actor = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM rule_hits WHERE actor = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM fraud_domains WHERE actor = ?1", [id])? as u64;
        // List items that are the account, alone or in a pair.
        n += self.conn.execute(
            "DELETE FROM list_items WHERE item = ?1 OR item LIKE ?2 || char(31) || '%' ESCAPE '!' OR item LIKE '%' || char(31) || ?2 ESCAPE '!'",
            params![id, id.replace('!', "!!").replace('%', "!%").replace('_', "!_")],
        )? as u64;
        n += self.conn.execute("DELETE FROM subjects WHERE kind = 'actor' AND id = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM links WHERE actor = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM throttles WHERE actor = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM seen WHERE actor = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM snoozes WHERE actor = ?1", [id])? as u64;
        // A workspace the actor owned stays, without the name of its owner.
        n += self
            .conn
            .execute("UPDATE subjects SET owner = NULL WHERE kind = 'tenant' AND owner = ?1", [id])? as u64;
        // Webhooks and alerts about the actor, sent or not: none goes out after the erasure.
        n += self.conn.execute(
            "DELETE FROM outbox WHERE EXISTS (SELECT 1 FROM json_tree(outbox.payload) WHERE type = 'text' AND atom = ?1)",
            [id],
        )? as u64;
        n += self.conn.execute("DELETE FROM clusters WHERE actor = ?1", [id])? as u64;
        // The erased actor may have been its cluster's root: give it another.
        let heir: Option<String> = self
            .conn
            .query_row("SELECT MIN(actor) FROM clusters WHERE root = ?1", [id], |r| r.get(0))
            .optional()?
            .flatten();
        if let Some(heir) = heir {
            self.conn
                .execute("UPDATE clusters SET root = ?1 WHERE root = ?2", params![heir, id])?;
        }
        n += self
            .conn
            .execute("DELETE FROM cases WHERE subject_kind = 'actor' AND subject_id = ?1", [id])? as u64;
        n += self
            .conn
            .execute("DELETE FROM statements WHERE subject_kind = 'actor' AND subject_id = ?1", [id])? as u64;
        n += self.conn.execute("DELETE FROM external_ids WHERE actor = ?1", [id])? as u64;
        Ok(n)
    }

    // --------------------------------------------------------- retention

    /// Deletes events, delivered outbox items and the links of unflagged
    /// actors older than `before`. Flagged actors keep their links, so a
    /// returning offender is still recognized.
    pub fn purge(&self, before: u64) -> Result<u64> {
        let b = before as i64;
        let mut n = self.conn.execute("DELETE FROM events WHERE at < ?1", [b])? as u64;
        self.conn.execute("DELETE FROM rule_hits WHERE at < ?1", [b])?;
        n += self
            .conn
            .execute("DELETE FROM outbox WHERE status != 'pending' AND created_at < ?1", [b])? as u64;
        n += self.conn.execute(
            "DELETE FROM links WHERE last_seen < ?1 AND actor NOT IN
               (SELECT id FROM subjects WHERE kind = 'actor' AND (status = 'quarantined' OR label = 'fraud'))",
            [b],
        )? as u64;
        n += self.conn.execute("DELETE FROM seen WHERE last_at < ?1", [b])? as u64;
        // Accounts and tenants inactive since `before`, unless restricted,
        // labelled or with a case open: those are kept to recognize a return
        // and to answer an appeal.
        self.conn.execute(
            "CREATE TEMP TABLE IF NOT EXISTS gone (kind TEXT NOT NULL, id TEXT NOT NULL);
             ",
            [],
        )?;
        self.conn.execute("DELETE FROM temp.gone", [])?;
        self.conn.execute(
            "INSERT INTO temp.gone SELECT kind, id FROM subjects s WHERE last_seen < ?1 AND status != 'quarantined'
               AND label IS NULL
               AND NOT EXISTS (SELECT 1 FROM cases c WHERE c.subject_kind = s.kind AND c.subject_id = s.id AND c.status != 'resolved')",
            [b],
        )?;
        n += self
            .conn
            .execute("DELETE FROM subjects WHERE (kind, id) IN (SELECT kind, id FROM temp.gone)", [])? as u64;
        n += self.conn.execute(
            "DELETE FROM cases WHERE (subject_kind, subject_id) IN (SELECT kind, id FROM temp.gone)",
            [],
        )? as u64;
        n += self.conn.execute(
            "DELETE FROM statements WHERE (subject_kind, subject_id) IN (SELECT kind, id FROM temp.gone)",
            [],
        )? as u64;
        n += self.conn.execute(
            "DELETE FROM links WHERE actor IN (SELECT id FROM temp.gone WHERE kind = 'actor')",
            [],
        )? as u64;
        n += self.conn.execute(
            "DELETE FROM clusters WHERE actor IN (SELECT id FROM temp.gone WHERE kind = 'actor')",
            [],
        )? as u64;
        // A cluster whose root was forgotten takes its smallest member as root.
        self.conn.execute(
            "UPDATE clusters SET root = (SELECT MIN(c2.actor) FROM clusters c2 WHERE c2.root = clusters.root)
             WHERE root NOT IN (SELECT actor FROM clusters)",
            [],
        )?;
        Ok(n)
    }

    /// After an erasure: the audit rows about the actor `id` name `marker`
    /// instead, and lose their free text, which may hold personal data. Rows
    /// whose target is a rule, a list, a key or a tenant of the same name stay.
    /// Runs before the actor's cases are deleted: an appeal row is matched to
    /// its case. `resolve_*` rows are written for tenants only.
    pub fn anonymize_audit(&self, id: &str, marker: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE audit SET target = ?2, detail = NULL WHERE target = ?1 AND (
                action LIKE 'label!_%' ESCAPE '!' OR action LIKE 'stripe.%' OR action = 'export'
                OR (action = 'set_status' AND detail LIKE 'actor %')
                OR (action = 'appeal' AND EXISTS (SELECT 1 FROM cases c
                    WHERE c.subject_kind = 'actor' AND c.subject_id = ?1 AND audit.detail = 'case ' || c.id)))",
            params![id, marker],
        )?;
        Ok(())
    }
}
