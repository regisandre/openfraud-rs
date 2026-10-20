"use strict";
/* openfraud admin interface. Vanilla JS, no build step. Server data is only
   ever put in the page with textContent, never innerHTML. */

const TOKEN_KEY = "openfraud.token";
const $app = document.getElementById("app");
const $toast = document.getElementById("toast");

// ------------------------------------------------------------------ DOM

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "style") Object.assign(node.style, value);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "value") node.value = value;
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, value);
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children) {
    if (child === undefined || child === null || child === false) continue;
    if (Array.isArray(child)) append(node, child);
    else if (child instanceof Node) node.appendChild(child);
    else node.appendChild(document.createTextNode(String(child)));
  }
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

const link = (href, text, cls) => el("a", { href, class: cls, text });
const code = (text) => el("code", { text: String(text) });
const muted = (text) => el("span", { class: "muted", text });

function pill(text, kind) {
  const value = text === undefined || text === null || text === "" ? "-" : String(text);
  return el("span", { class: "pill " + (kind || "p-" + value.replace(/[^a-z_]/gi, "").toLowerCase()), text: value });
}

function pre(value) {
  return el("pre", { class: "json", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) });
}

function when(seconds) {
  if (seconds === null || seconds === undefined) return "-";
  const d = new Date(seconds * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const percent = (x) => (x === null || x === undefined ? "-" : (x * 100).toFixed(0) + "%");
const num = (n) => (n === null || n === undefined ? "-" : Number(n).toLocaleString("en-US"));

function table(columns, rows, empty) {
  if (!rows.length) return el("p", { class: "empty", text: empty || "Nothing to show." });
  const head = el("tr", {}, columns.map((c) => el("th", { text: c.title, class: c.num ? "num" : "" })));
  const body = rows.map((row) =>
    el(
      "tr",
      row.__href ? { class: "click", onclick: () => (location.hash = row.__href) } : {},
      columns.map((c) => {
        const v = c.render ? c.render(row) : row[c.key];
        return el("td", { class: (c.num ? "num " : "") + (c.wrap ? "wrap" : "") }, v === undefined || v === null || v === "" ? muted("-") : v);
      })
    )
  );
  return el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, body)));
}

function card(title, ...body) {
  return el("section", { class: "card" }, title ? el("h2", { text: title }) : null, body);
}

function field(label, control, hint) {
  return el("label", { class: "field" }, el("span", { class: "label", text: label }), control, hint ? el("span", { class: "hint", text: hint }) : null);
}

function button(text, onclick, kind) {
  const b = el("button", { type: "button", class: "btn " + (kind || ""), text });
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await onclick();
    } catch (e) {
      /* already shown in the toast */
    } finally {
      b.disabled = false;
    }
  });
  return b;
}

function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    dl.appendChild(el("dt", { text: k }));
    dl.appendChild(el("dd", {}, v === undefined || v === null || v === "" ? muted("-") : v));
  }
  return dl;
}

function stats(pairs) {
  return el(
    "div",
    { class: "stats" },
    pairs.map(([label, value, sub]) =>
      el("div", { class: "stat" }, el("div", { class: "stat-value", text: value }), el("div", { class: "stat-label", text: label }), sub ? el("div", { class: "stat-sub", text: sub }) : null)
    )
  );
}

function counts(map) {
  const entries = Object.entries(map || {});
  if (!entries.length) return el("p", { class: "empty", text: "No data." });
  return el("div", { class: "chips" }, entries.map(([k, v]) => el("span", { class: "chip" }, pill(k || "unknown"), el("b", { text: num(v) }))));
}

// ------------------------------------------------------------------ toast

let toastTimer = null;

function showToast(kind, message, problems) {
  clear($toast);
  $toast.className = "show " + kind;
  $toast.appendChild(el("div", { class: "toast-message", text: message }));
  if (problems && problems.length) $toast.appendChild(el("ul", {}, problems.map((p) => el("li", { text: String(p) }))));
  $toast.appendChild(el("button", { type: "button", class: "toast-close", "aria-label": "Dismiss", text: "x", onclick: hideToast }));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, kind === "error" ? 12000 : 4000);
}

function hideToast() {
  $toast.className = "";
  clear($toast);
}

const ok = (message) => showToast("ok", message);

// ------------------------------------------------------------------ API

class ApiError extends Error {
  constructor(status, body) {
    const e = body && body.error;
    super((e && e.message) || "Request failed (" + status + ")");
    this.status = status;
    this.problems = (e && e.problems) || [];
  }
}

const getToken = () => sessionStorage.getItem(TOKEN_KEY) || "";

async function request(method, path, body, opts) {
  const headers = { Authorization: "Bearer " + getToken() };
  const init = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch (e) {
    showToast("error", "The server cannot be reached.");
    throw e;
  }
  let data = null;
  const text = await response.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = null;
    }
  }
  if (response.status === 401) {
    sessionStorage.removeItem(TOKEN_KEY);
    route();
    const err = new ApiError(401, data);
    if (!(opts && opts.quiet)) showToast("error", err.message);
    throw err;
  }
  if (!response.ok) {
    const err = new ApiError(response.status, data);
    if (!(opts && opts.quiet)) showToast("error", err.message, err.problems);
    throw err;
  }
  return data;
}

const api = {
  get: (path, opts) => request("GET", path, undefined, opts),
  post: (path, body, opts) => request("POST", path, body === undefined ? {} : body, opts),
  put: (path, body, opts) => request("PUT", path, body === undefined ? {} : body, opts),
  del: (path, opts) => request("DELETE", path, undefined, opts),
};

// Posts that take no body: sent without a content type or body.
async function postEmpty(path) {
  return request("POST", path, undefined);
}

const enc = encodeURIComponent;

// ------------------------------------------------------------------ login

function loginView() {
  clear($app);
  const input = el("input", { type: "password", id: "token", autocomplete: "current-password", placeholder: "Admin token", required: true, autofocus: true });
  const form = el(
    "form",
    { class: "login card" },
    el("h1", { text: "openfraud" }),
    el("p", { class: "muted", text: "Enter the admin token printed at first start." }),
    field("Admin token", input),
    el("button", { type: "submit", class: "btn primary", text: "Sign in" })
  );
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    sessionStorage.setItem(TOKEN_KEY, input.value.trim());
    try {
      await request("GET", "/admin/api/session", undefined, { quiet: true });
      hideToast();
      route();
    } catch (e) {
      sessionStorage.removeItem(TOKEN_KEY);
      showToast("error", e.status === 401 ? "That token is not valid." : e.message);
    }
  });
  $app.appendChild(el("div", { class: "login-wrap" }, form));
  input.focus();
}

function logout() {
  sessionStorage.removeItem(TOKEN_KEY);
  hideToast();
  route();
}

// ------------------------------------------------------------------ shell

const NAV = [
  ["overview", "Overview"],
  ["cases", "Cases"],
  ["actors", "Actors"],
  ["rules", "Rules"],
  ["playground", "Playground"],
  ["replay", "Replay"],
  ["lists", "Lists"],
  ["config", "Config"],
  ["keys", "Keys"],
  ["audit", "Audit"],
  ["outbox", "Outbox"],
];

let current = 0;

function shell(section) {
  clear($app);
  const nav = el(
    "nav",
    { class: "nav" },
    NAV.map(([id, title]) => link("#/" + id, title, id === section ? "active" : ""))
  );
  const header = el(
    "header",
    { class: "top" },
    el("a", { class: "brand", href: "#/overview", text: "openfraud" }),
    nav,
    el("button", { type: "button", class: "btn small", text: "Log out", onclick: logout })
  );
  const main = el("main", { class: "main" });
  $app.appendChild(header);
  $app.appendChild(main);
  return main;
}

function route() {
  const id = ++current;
  hideToast();
  if (!getToken()) return loginView();
  const parts = location.hash.replace(/^#\/?/, "").split("?")[0].split("/").map(decodeURIComponent);
  const section = parts[0] || "overview";
  const view = VIEWS[section] || VIEWS.overview;
  const main = shell(VIEWS[section] ? section : "overview");
  main.appendChild(el("p", { class: "boot", text: "Loading..." }));
  const done = (node) => {
    if (id !== current) return;
    clear(main);
    if (node) main.appendChild(node);
  };
  view(parts.slice(1), done, () => id === current).catch((e) => {
    if (id !== current || e.status === 401) return;
    clear(main);
    main.appendChild(el("p", { class: "empty", text: "Could not load this page: " + e.message }));
  });
}

function reload() {
  route();
}

function title(text, ...actions) {
  return el("div", { class: "page-title" }, el("h1", { text }), el("div", { class: "actions" }, actions));
}

// ------------------------------------------------------------------ overview

async function overviewView(_args, done) {
  const o = await api.get("/admin/api/overview");
  const s = o.stats;
  const page = el("div", {}, title("Overview", muted("v" + o.version), button("Refresh", reload, "small")));

  if (o.brake && o.brake.engaged) {
    page.appendChild(
      el(
        "div",
        { class: "banner danger" },
        el("div", {}, el("b", { text: "Safety brake engaged. " }), "Restrictions are turned into reviews. ", o.brake.reason || "", " ", muted("Since " + when(o.brake.since))),
        button(
          "Release brake",
          async () => {
            await postEmpty("/admin/api/brake/release");
            ok("Brake released.");
            reload();
          },
          "danger"
        )
      )
    );
  } else {
    page.appendChild(el("div", { class: "banner good" }, "Safety brake is off. Automatic restrictions are within limits."));
  }

  page.appendChild(
    stats([
      ["Events", num(s.events)],
      ["Open cases", num(s.open_cases)],
      ["Actors", num(sum(s.actors))],
      ["Tenants", num(sum(s.tenants))],
      ["Outbox pending", num(s.outbox.pending), num(s.outbox.failed) + " failed"],
    ])
  );
  page.appendChild(
    el(
      "div",
      { class: "grid two" },
      card("Decisions, last 24 hours", counts(s.decisions_24h)),
      card("Decisions, last 7 days", counts(s.decisions_7d)),
      card("Actors by status", counts(s.actors)),
      card("Tenants by status", counts(s.tenants))
    )
  );

  const mods = o.modules || {};
  page.appendChild(
    card(
      "Packs and modules",
      kv([
        ["Packs", (o.packs || []).length ? (o.packs || []).map((p) => pill(p, "p-neutral")) : null],
        ["AI assistant", pill(mods.ai ? "on" : "off", mods.ai ? "p-allow" : "p-neutral")],
        ["Stripe", pill(mods.stripe ? "on" : "off", mods.stripe ? "p-allow" : "p-neutral")],
        ["Webhook", mods.webhooks ? code(mods.webhooks) : null],
        ["Alerts configured", String(mods.alerts)],
      ])
    )
  );

  const wf = (o.workflows || []).map((w) =>
    el(
      "details",
      { class: "workflow" },
      el("summary", {}, el("b", { text: w.name }), " ", pill(w.mode), " ", w.enabled ? null : pill("disabled", "p-neutral"), " ", muted((w.origin || "") + " | " + (w.rules || []).length + " rules")),
      w.description ? el("p", { class: "muted", text: w.description }) : null,
      kv([
        ["Events", (w.events || []).join(", ")],
        ["Bands", bands(w)],
        ["Max decision", w.max_decision],
      ]),
      table(
        [
          { title: "Rule", render: (r) => code(r.id) },
          { title: "Mode", render: (r) => pill(r.mode) },
          { title: "Score", key: "score", num: true },
          { title: "Decision", render: (r) => (r.decision ? pill(r.decision) : null) },
          { title: "When", render: (r) => code(r.when), wrap: true },
          { title: "Reason", key: "reason", wrap: true },
          { title: "On", render: (r) => (r.enabled === false ? pill("off", "p-neutral") : null) },
        ],
        w.rules || []
      )
    )
  );
  page.appendChild(card("Workflows", wf.length ? wf : el("p", { class: "empty", text: "No workflows." })));

  page.appendChild(
    card(
      "Counters",
      table(
        [
          { title: "Name", render: (c) => code(c.name) },
          { title: "Events", render: (c) => (c.events || []).join(", "), wrap: true },
          { title: "By", key: "by" },
          { title: "Distinct", key: "distinct" },
          { title: "Sum", key: "sum" },
          { title: "Window", key: "window" },
          { title: "Description", key: "description", wrap: true },
        ],
        o.counters || []
      )
    )
  );
  done(page);
}

function sum(map) {
  return Object.values(map || {}).reduce((a, b) => a + Number(b || 0), 0);
}

function bands(w) {
  const pairs = [
    ["step_up", w.step_up_at],
    ["review", w.review_at],
    ["hold", w.hold_at],
    ["block", w.block_at],
    ["quarantine", w.quarantine_at],
  ].filter(([, v]) => v !== null && v !== undefined);
  return pairs.length ? pairs.map(([k, v]) => k + " " + v).join(" | ") : null;
}

// ------------------------------------------------------------------ cases

const PAGE = 50;

async function casesView(args, done) {
  if (args[0]) return caseDetail(args[0], done);
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const status = params.get("status") === "all" ? "all" : "open";
  const offset = Math.max(0, parseInt(params.get("offset") || "0", 10) || 0);
  const data = await api.get(`/v1/cases?status=${status}&limit=${PAGE}&offset=${offset}`);
  const cases = data.cases || [];
  const select = el("select", {}, el("option", { value: "open", text: "Open and appealed" }), el("option", { value: "all", text: "All cases" }));
  select.value = status;
  select.addEventListener("change", () => (location.hash = `#/cases?status=${select.value}`));
  const rows = cases.map((c) => Object.assign({ __href: "#/cases/" + c.id }, c));
  const pager = el(
    "div",
    { class: "pager" },
    offset > 0 ? link(`#/cases?status=${status}&offset=${Math.max(0, offset - PAGE)}`, "Previous") : null,
    cases.length === PAGE ? link(`#/cases?status=${status}&offset=${offset + PAGE}`, "Next") : null
  );
  done(
    el(
      "div",
      {},
      title("Cases", field("Show", select)),
      card(
        null,
        table(
          [
            { title: "#", key: "id" },
            { title: "Subject", render: (c) => el("span", {}, pill(c.subject_kind, "p-neutral"), " ", code(c.subject_id)) },
            { title: "Status", render: (c) => pill(c.status) },
            { title: "Decision", render: (c) => pill(c.decision) },
            { title: "Score", key: "score", num: true },
            { title: "Reasons", render: (c) => (c.reasons || []).join("; "), wrap: true },
            { title: "Label", render: (c) => (c.label ? pill(c.label) : null) },
            { title: "Opened", render: (c) => when(c.opened_at) },
          ],
          rows,
          status === "open" ? "No open cases." : "No cases."
        ),
        pager
      )
    )
  );
}

async function caseDetail(id, done) {
  const { case: c } = await api.get("/v1/cases/" + enc(id));
  const subjectPath = c.subject_kind === "tenant" ? "tenants" : "actors";
  let recent = [];
  try {
    const s = await api.get(`/v1/${subjectPath}/${enc(c.subject_id)}`, { quiet: true });
    recent = s.recent || [];
  } catch (e) {
    if (e.status === 401) return;
  }
  const resolved = c.status === "resolved";
  const note = el("textarea", { rows: 3, placeholder: "Note (optional)" });
  const snooze = el(
    "select",
    {},
    el("option", { value: "", text: "Do not snooze" }),
    el("option", { value: "7d", text: "7 days" }),
    el("option", { value: "30d", text: "30 days" }),
    el("option", { value: "90d", text: "90 days" })
  );
  const resolve = (label) => async () => {
    const body = { label, note: note.value };
    if (snooze.value && label !== "fraud" && c.subject_kind === "actor") body.snooze = snooze.value;
    const r = await api.post(`/v1/cases/${enc(c.id)}/resolve`, body);
    const quiet = (r.snoozed || []).length ? ` Snoozed for this account: ${r.snoozed.join(", ")}.` : "";
    ok(`Case ${c.id} resolved as ${label}.${quiet}`);
    reload();
  };
  const summaryBox = el("div", {}, c.summary ? el("p", { class: "text-block", text: c.summary }) : el("p", { class: "muted", text: "No summary yet." }));
  const stmtInput = el("input", { type: "text", placeholder: "Statement id" });
  const stmtOut = el("div", {});

  const page = el(
    "div",
    {},
    title(`Case ${c.id}`, link("#/cases", "Back to cases")),
    el(
      "div",
      { class: "grid two" },
      card(
        "Summary",
        kv([
          ["Subject", el("span", {}, pill(c.subject_kind, "p-neutral"), " ", link(`#/${subjectPath}/${enc(c.subject_id)}`, c.subject_id))],
          ["Status", pill(c.status)],
          ["Decision", pill(c.decision)],
          ["Score", String(c.score)],
          ["Opened", when(c.opened_at)],
          ["Updated", when(c.updated_at)],
          ["Resolved", c.resolved_at ? when(c.resolved_at) + (c.resolved_by ? " by " + c.resolved_by : "") : null],
          ["Label", c.label ? pill(c.label) : null],
          ["Note", c.note],
        ])
      ),
      card(
        "Reasons",
        (c.reasons || []).length ? el("ul", { class: "plain" }, c.reasons.map((r) => el("li", { text: r }))) : el("p", { class: "empty", text: "No reasons recorded." })
      )
    )
  );

  if (c.appeal) {
    page.appendChild(card("Appeal", el("p", { class: "muted", text: "Sent " + when(c.appealed_at) }), el("blockquote", { class: "text-block", text: c.appeal })));
  }

  page.appendChild(
    card(
      "Resolve",
      resolved ? el("p", { class: "muted", text: "This case is resolved. Resolving again overwrites the label." }) : null,
      field("Note", note),
      c.subject_kind === "actor" ? field("Snooze the case's rules for this account (legit or false positive)", snooze) : null,
      el(
        "div",
        { class: "btn-row" },
        button("Fraud", resolve("fraud"), "danger"),
        button("Legit", resolve("legit"), "good"),
        button("False positive", resolve("false_positive"))
      )
    )
  );

  const summaryButton = button("Generate AI summary", async () => {
    const r = await postEmpty(`/admin/api/cases/${enc(c.id)}/summary`);
    clear(summaryBox);
    summaryBox.appendChild(el("p", { class: "text-block", text: r.summary }));
  });
  page.appendChild(card("AI summary", summaryBox, summaryButton));

  page.appendChild(
    card(
      `Timeline of ${c.subject_kind} ${c.subject_id}`,
      table(
        [
          { title: "When", render: (e) => when(e.at) },
          { title: "Event", render: (e) => el("span", {}, e.event_id && (c.events || []).includes(e.event_id) ? "* " : "", e.type) },
          { title: "Decision", render: (e) => pill(e.decision) },
          { title: "Score", key: "score", num: true },
          { title: "Rules", render: (e) => (e.rules || []).map((r) => r.id + (r.mode === "shadow" ? " (shadow)" : "")).join(", "), wrap: true },
        ],
        recent,
        "No recent events."
      ),
      el("p", { class: "hint", text: "* marks an event that is part of this case." })
    )
  );

  page.appendChild(
    card(
      "Case events",
      (c.events || []).length ? el("ul", { class: "plain mono" }, c.events.map((e) => el("li", { text: e }))) : el("p", { class: "empty", text: "No events attached." })
    )
  );

  const lookup = async () => {
    if (!stmtInput.value.trim()) return;
    const r = await api.get("/v1/statements/" + enc(stmtInput.value.trim()));
    clear(stmtOut);
    stmtOut.appendChild(pre(r.statement));
  };
  page.appendChild(
    card(
      "Statement of reasons",
      el("p", { class: "hint", text: "Statement ids are returned with a decision (statement_id)." }),
      el("div", { class: "inline" }, stmtInput, button("Open", lookup, "small")),
      stmtOut
    )
  );
  done(page);
}

// ------------------------------------------------------------------ actors and tenants

async function actorsView(args, done) {
  const kindSel = el("select", {}, el("option", { value: "actors", text: "Actor" }), el("option", { value: "tenants", text: "Tenant" }));
  const input = el("input", { type: "text", placeholder: "Account id", autocapitalize: "off", spellcheck: "false" });
  const form = el("form", { class: "inline" }, kindSel, input, el("button", { type: "submit", class: "btn primary", text: "Look up" }));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (input.value.trim()) location.hash = `#/${kindSel.value}/${enc(input.value.trim())}`;
  });
  const page = el("div", {}, title("Actors"), card("Look up an account", form));
  if (!args[0]) return done(page);
  input.value = args[0];
  await subjectCard(page, "actors", args[0]);
  done(page);
}

async function tenantsView(args, done) {
  const page = el("div", {}, title("Tenant"));
  if (!args[0]) {
    location.hash = "#/actors";
    return;
  }
  await subjectCard(page, "tenants", args[0]);
  done(page);
}

async function subjectCard(page, plural, id) {
  const isActor = plural === "actors";
  let data;
  try {
    data = await api.get(`/v1/${plural}/${enc(id)}`);
  } catch (e) {
    if (e.status === 404) {
      page.appendChild(card(null, el("p", { class: "empty", text: e.message }), link("#/actors", "Back to lookup")));
      return;
    }
    throw e;
  }
  const s = isActor ? data.actor : data.tenant;
  const note = el("textarea", { rows: 2, placeholder: "Note (optional)" });
  const act = (fn) => async () => {
    await fn();
    reload();
  };

  page.appendChild(
    card(
      (isActor ? "Actor " : "Tenant ") + s.id,
      kv([
        ["Status", pill(s.status)],
        ["Trust", String(s.trust)],
        ["Label", s.label ? pill(s.label) : null],
        ["Max score", String(s.max_score)],
        ["Created", s.created_at ? when(s.created_at) : null],
        ["First seen", when(s.first_seen)],
        ["Last seen", when(s.last_seen)],
        ["Country", s.country],
        ["Countries", Object.keys(s.countries || {}).join(", ")],
        ["Owner", s.owner],
        ["Note", s.note],
        ["Open case", data.open_case ? link("#/cases/" + data.open_case.id, "Case " + data.open_case.id) : null],
      ])
    )
  );

  // Actions.
  const statusSel = el("select", {}, ["normal", "review", "quarantined", "trusted"].map((v) => el("option", { value: v, text: v })));
  statusSel.value = s.status;
  const trust = el("input", { type: "number", min: 0, max: 100, placeholder: "Trust 0-100" });
  const actions = [
    field("Note", note),
    el(
      "div",
      { class: "inline" },
      field("Status", statusSel),
      field("Trust", trust),
      button(
        "Set status",
        act(async () => {
          const body = { status: statusSel.value, note: note.value };
          if (trust.value !== "") body.trust = Number(trust.value);
          await api.post(`/v1/${plural}/${enc(id)}/status`, body);
          ok("Status updated.");
        })
      )
    ),
  ];
  if (isActor) {
    const label = (l) =>
      act(async () => {
        await api.post(`/v1/actors/${enc(id)}/label`, { label: l, note: note.value });
        ok(`Labelled ${l}.`);
      });
    actions.push(
      el("div", { class: "btn-row" }, el("span", { class: "label", text: "Label" }), button("Fraud", label("fraud"), "danger"), button("Legit", label("legit"), "good"), button("False positive", label("false_positive")))
    );
  }
  page.appendChild(card("Actions", actions));

  if (isActor) {
    page.appendChild(
      card(
        "Linked identifiers",
        table(
          [
            { title: "Kind", render: (l) => pill(l.kind, "p-neutral") },
            { title: "Other accounts sharing it", render: (l) => sharedWith(l.shared_with), num: true },
            { title: "Flagged", render: (l) => (l.flagged ? pill("flagged", "p-quarantine") : null) },
          ],
          data.links || [],
          "No identifier is shared with another account."
        )
      )
    );
  }

  page.appendChild(
    card(
      "Recent decisions",
      table(
        [
          { title: "When", render: (e) => when(e.at) },
          { title: "Event", key: "type" },
          { title: "Decision", render: (e) => pill(e.decision) },
          { title: "Score", key: "score", num: true },
          { title: "Rules", render: (e) => (e.rules || []).map((r) => r.id + (r.mode === "shadow" ? " (shadow)" : "")).join(", "), wrap: true },
        ],
        data.recent || [],
        "No events yet."
      )
    )
  );

  if (isActor) {
    const box = el("div", {}, el("p", { class: "boot", text: "Loading cluster..." }));
    page.appendChild(card("Cluster", box));
    api
      .get(`/v1/actors/${enc(id)}/cluster`, { quiet: true })
      .then((r) => renderCluster(box, r.cluster, id))
      .catch((e) => {
        clear(box);
        box.appendChild(el("p", { class: "empty", text: e.message }));
      });

    const exportBtn = button("Export data (JSON)", async () => {
      const r = await api.get(`/v1/subjects/${enc(id)}/export`);
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = el("a", { href: url, download: `openfraud-${id}.json` });
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    });
    const eraseBtn = button(
      "Erase all data",
      async () => {
        if (!confirm(`Erase everything about ${id}? This cannot be undone.`)) return;
        if (!confirm(`Second confirmation: permanently erase ${id}.`)) return;
        const r = await api.del(`/v1/subjects/${enc(id)}`);
        ok(`Erased ${r.erased} records.`);
        location.hash = "#/actors";
      },
      "danger"
    );
    page.appendChild(card("Privacy", el("p", { class: "hint", text: "Export is the access request; erase is irreversible." }), el("div", { class: "btn-row" }, exportBtn, eraseBtn)));
  }
}

function sharedWith(v) {
  if (!Array.isArray(v)) return v === undefined || v === null ? null : String(v);
  const out = [];
  v.forEach((u, i) => {
    if (i) out.push(", ");
    out.push(link("#/actors/" + enc(u), u));
  });
  return out;
}

function renderCluster(box, cl, id) {
  clear(box);
  if (!cl || !cl.root) {
    box.appendChild(el("p", { class: "empty", text: "This account is not linked to any other account." }));
    return;
  }
  box.appendChild(
    stats([
      ["Members", num(cl.size)],
      ["Flagged", num(cl.flagged)],
      ["Fraud", num(cl.fraud)],
      ["Legit", num(cl.legit)],
    ])
  );
  box.appendChild(el("h3", { text: "Joined by" }));
  box.appendChild(
    table(
      [
        { title: "Identifier kind", render: (j) => pill(j.kind, "p-neutral") },
        { title: "Shared values", key: "shared_values", num: true },
      ],
      cl.joined_by || [],
      "No shared identifiers."
    )
  );
  box.appendChild(el("h3", { text: "Members" }));
  box.appendChild(
    table(
      [
        { title: "Account", render: (m) => el("span", {}, link("#/actors/" + enc(m.id), m.id), m.id === id ? muted(" (this one)") : null) },
        { title: "Status", render: (m) => pill(m.status) },
        { title: "Label", render: (m) => (m.label ? pill(m.label) : null) },
        { title: "Trust", key: "trust", num: true },
      ],
      cl.members || []
    )
  );
}

// ------------------------------------------------------------------ rules

// The last promotion's report, shown once the table is drawn again.
let lastPromotion = null;

async function rulesView(_args, done) {
  const { rules } = await api.get("/admin/api/rules");
  const report = el("div", {});
  if (lastPromotion) {
    report.appendChild(card(`Promotion report for ${lastPromotion.promoted}`, promotionReport(lastPromotion.report)));
    lastPromotion = null;
  }
  const page = el(
    "div",
    {},
    title("Rules", muted("Last 30 days. Precision and recall use the labels people set.")),
    card(
      null,
      table(
        [
          { title: "Rule", render: (r) => code(r.id) },
          { title: "Workflow", render: (r) => el("span", {}, r.workflow, " ", muted(r.origin || "")) },
          { title: "Mode", render: (r) => pill(r.mode) },
          { title: "May act", render: (r) => pill(r.may_act ? "yes" : "no", r.may_act ? "p-allow" : "p-neutral") },
          { title: "On", render: (r) => (r.enabled ? "yes" : pill("off", "p-neutral")) },
          { title: "Fired", key: "fired_30d", num: true },
          { title: "Actors", key: "actors_30d", num: true },
          { title: "Fraud", key: "fraud", num: true },
          { title: "Legit", key: "legit", num: true },
          { title: "FP", key: "false_positive", num: true },
          { title: "Precision", render: (r) => percent(r.precision), num: true },
          { title: "Recall", render: (r) => percent(r.recall), num: true },
          {
            title: "",
            render: (r) =>
              r.may_act
                ? null
                : button(
                    "Promote",
                    async () => {
                      if (!confirm(`Promote ${r.id} to act? It will start restricting accounts.`)) return;
                      const res = await postEmpty(`/admin/api/rules/${enc(r.id)}/promote`);
                      ok(`${res.promoted} promoted.`);
                      lastPromotion = res;
                      await rulesView(_args, done);
                    },
                    "small"
                  ),
          },
        ],
        rules,
        "No rules."
      )
    ),
    report
  );
  done(page);
}

function promotionReport(r) {
  const out = [kv([["Days replayed", String(r.days)], ["Events", num(r.events)], ["Decisions changed", num(r.changed)]])];
  out.push(el("div", { class: "grid two" }, el("div", {}, el("h3", { text: "Before" }), counts(r.before)), el("div", {}, el("h3", { text: "After" }), counts(r.after))));
  if (r.rule) out.push(el("h3", { text: "Rule" }), ruleStatsTable([r.rule]));
  return out;
}

function ruleStatsTable(rules) {
  return table(
    [
      { title: "Rule", render: (r) => code(r.id) },
      { title: "Mode", render: (r) => pill(r.mode) },
      { title: "Fired", key: "fired", num: true },
      { title: "Accounts", key: "users", num: true },
      { title: "Fraud", key: "fraud", num: true },
      { title: "Legit", key: "legit", num: true },
      { title: "FP", key: "false_positive", num: true },
      { title: "Precision", render: (r) => percent(r.precision), num: true },
      { title: "Recall", render: (r) => percent(r.recall), num: true },
    ],
    rules,
    "No rule fired."
  );
}

// ------------------------------------------------------------------ playground

const SAMPLE_EVENT = {
  type: "message.contacts_imported",
  actor_id: "u1",
  email: "a@gmail.com",
  attrs: { recipients: ["x@gmail.com", "y@yahoo.com", "z@outlook.com"] },
};

async function playgroundView(_args, done) {
  const text = el("textarea", { rows: 14, class: "code", spellcheck: "false" });
  text.value = JSON.stringify(SAMPLE_EVENT, null, 2);
  const out = el("div", {});
  const run = async () => {
    let event;
    try {
      event = JSON.parse(text.value);
    } catch (e) {
      showToast("error", "The event is not valid JSON: " + e.message);
      return;
    }
    const r = await api.post("/admin/api/test", { event });
    clear(out);
    out.appendChild(playgroundResult(r));
  };
  done(
    el(
      "div",
      {},
      title("Playground"),
      card("Event", el("p", { class: "hint", text: "A dry run: nothing is stored and no action is sent." }), text, el("div", { class: "btn-row" }, button("Decide", run, "primary"))),
      out
    )
  );
}

function reasonRows(list) {
  return table(
    [
      { title: "Rule", render: (r) => code(r.rule || r.id) },
      { title: "Workflow", key: "workflow" },
      { title: "Mode", render: (r) => pill(r.mode) },
      { title: "Score", key: "score", num: true },
      { title: "Reason", key: "reason", wrap: true },
      { title: "", render: (r) => (r.pending_approval || r.pending ? pill("pending approval", "p-neutral") : null) },
    ],
    list || [],
    "None."
  );
}

function playgroundResult(r) {
  const a = r.answer || {};
  const shadow = a.shadow || {};
  const box = el(
    "div",
    {},
    card(
      "Result",
      el(
        "div",
        { class: "verdict" },
        el("div", {}, el("div", { class: "label", text: "Decision" }), pill(r.decision)),
        el("div", {}, el("div", { class: "label", text: "Would be (with shadow rules)" }), pill(r.shadow_decision)),
        el("div", {}, el("div", { class: "label", text: "Score" }), el("b", { text: String(r.score) })),
        el("div", {}, el("div", { class: "label", text: "Took" }), el("b", { text: (r.took_us || 0) + " us" }))
      ),
      kv([
        ["Workflows", (r.workflows || []).join(", ")],
        ["Protected", r.protected ? "yes (trusted actor: restriction turned into a hold)" : null],
        ["Brake", r.brake ? "yes" : null],
        ["Hold until", r.hold_until ? when(r.hold_until) : null],
      ])
    ),
    card("Reasons (acting rules)", reasonRows(a.reasons)),
    card("Shadow reasons", reasonRows(shadow.reasons)),
    card(
      "Actions",
      table(
        [
          { title: "Action", key: "action" },
          { title: "Target", key: "target" },
          { title: "Id", render: (x) => code(x.id) },
        ],
        a.actions || [],
        "No action."
      )
    )
  );
  if ((r.errors || []).length) {
    box.appendChild(
      card(
        "Rules that could not be decided",
        table(
          [
            { title: "Rule", render: (x) => code(x.rule) },
            { title: "Workflow", key: "workflow" },
            { title: "Error", key: "error", wrap: true },
          ],
          r.errors
        )
      )
    );
  }
  box.appendChild(el("details", { class: "card" }, el("summary", { text: "Raw outcome" }), pre(r)));
  return box;
}

// ------------------------------------------------------------------ replay

async function replayView(_args, done) {
  const cfg = await api.get("/admin/api/config");
  const text = el("textarea", { rows: 18, class: "code", spellcheck: "false" });
  text.value = cfg.text;
  const days = el("input", { type: "number", min: 1, max: 366, value: 30 });
  const out = el("div", {});
  const run = (candidate) => async () => {
    const body = { days: Number(days.value) || 30 };
    if (candidate) body.text = text.value;
    const r = await api.post("/admin/api/replay", body);
    clear(out);
    out.appendChild(replayResult(r));
  };
  done(
    el(
      "div",
      {},
      title("Replay"),
      card(
        "Candidate configuration",
        el("p", { class: "hint", text: "Replays stored events through the candidate and shows which decisions would change. Nothing is saved." }),
        text,
        el("div", { class: "inline" }, field("Days", days), button("Replay candidate", run(true), "primary"), button("Replay running config", run(false)))
      ),
      out
    )
  );
}

function replayResult(r) {
  return el(
    "div",
    {},
    card(
      "Replay result",
      kv([
        ["Events", num(r.events)],
        ["Period", r.from ? when(r.from) + " to " + when(r.to) : null],
        ["Decisions changed", num(r.changed_total)],
      ]),
      el("div", { class: "grid two" }, el("div", {}, el("h3", { text: "Before" }), counts(r.before)), el("div", {}, el("h3", { text: "After" }), counts(r.after)))
    ),
    card("Rules", ruleStatsTable(r.rules || [])),
    card(
      `Changed decisions (${(r.changed || []).length} of ${num(r.changed_total)})`,
      table(
        [
          { title: "Event", render: (c) => code(c.event_id) },
          { title: "Type", key: "type" },
          { title: "Actor", render: (c) => (c.actor ? link("#/actors/" + enc(c.actor), c.actor) : null) },
          { title: "Before", render: (c) => pill(c.before) },
          { title: "After", render: (c) => pill(c.after) },
          { title: "Rules", render: (c) => (c.rules || []).join(", "), wrap: true },
        ],
        r.changed || [],
        "No decision would change."
      )
    )
  );
}

// ------------------------------------------------------------------ lists

async function listsView(args, done) {
  const { lists } = await api.get("/v1/lists");
  const page = el(
    "div",
    {},
    title("Lists"),
    card(
      null,
      table(
        [
          { title: "Name", render: (l) => code(l.name) },
          { title: "Kind", render: (l) => pill(l.kind, "p-neutral") },
          { title: "Items", key: "items", num: true },
          { title: "Description", key: "description", wrap: true },
          { title: "Source", render: (l) => (l.url ? code(l.url) : null), wrap: true },
        ].concat([{ title: "", render: (l) => link("#/lists/" + enc(l.name), "Edit") }]),
        lists,
        "No lists."
      )
    )
  );
  if (args[0]) {
    const name = args[0];
    const box = el("div", {});
    const input = el("textarea", { rows: 3, placeholder: "One item per line" });
    const note = el("input", { type: "text", placeholder: "Note (optional)" });
    const render = async () => {
      const r = await api.get(`/v1/lists/${enc(name)}/items`);
      clear(box);
      box.appendChild(
        table(
          [
            { title: "Item", render: (i) => code(i.item) },
            {
              title: "",
              render: (i) =>
                button(
                  "Remove",
                  async () => {
                    await api.del(`/v1/lists/${enc(name)}/items?item=${enc(i.item)}`);
                    ok("Removed.");
                    await render();
                  },
                  "small danger"
                ),
            },
          ],
          (r.items || []).map((item) => ({ item })),
          "No item was added at run time."
        )
      );
    };
    await render();
    page.appendChild(
      card(
        `List ${name}`,
        el("p", { class: "hint", text: "Items added here, on top of the ones the configuration or its source provides." }),
        box,
        field("Add items", input),
        field("Note", note),
        button(
          "Add",
          async () => {
            const items = input.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
            if (!items.length) return;
            const r = await api.post(`/v1/lists/${enc(name)}/items`, { items, note: note.value });
            ok(`${r.added} added.`);
            input.value = "";
            await render();
          },
          "primary"
        )
      )
    );
  }
  done(page);
}

// ------------------------------------------------------------------ config

async function configView(_args, done) {
  const cfg = await api.get("/admin/api/config");
  const text = el("textarea", { rows: 28, class: "code", spellcheck: "false" });
  text.value = cfg.text;
  const problems = el("div", {});
  const save = async () => {
    clear(problems);
    try {
      await api.put("/admin/api/config", { text: text.value }, { quiet: true });
      ok("Configuration saved and applied.");
    } catch (e) {
      if (e.status === 401) return;
      showToast("error", e.message, e.problems);
      problems.appendChild(el("div", { class: "banner danger" }, el("b", { text: e.message }), el("ul", {}, e.problems.map((p) => el("li", { class: "mono", text: p })))));
      throw e;
    }
  };
  done(
    el(
      "div",
      {},
      title("Config", code(cfg.path)),
      card(null, problems, text, el("div", { class: "btn-row" }, button("Save and apply", save, "primary"), button("Reset", () => (text.value = cfg.text))))
    )
  );
}

// ------------------------------------------------------------------ keys

async function keysView(_args, done) {
  const data = await api.get("/admin/api/keys");
  const shown = el("div", {});
  const name = el("input", { type: "text", placeholder: "Key name, e.g. backend" });
  const scope = el(
    "select",
    {},
    el("option", { value: "full", text: "Full: events, accounts, cases, lists, data" }),
    el("option", { value: "events", text: "Events only: decide and track" })
  );
  const create = async () => {
    if (!name.value.trim()) return;
    const r = await api.post("/admin/api/keys", { name: name.value.trim(), scope: scope.value });
    clear(shown);
    shown.appendChild(
      el("div", { class: "banner good stack" }, el("b", { text: "New API key (shown once, copy it now)" }), el("code", { class: "secret", text: r.key }), muted(r.note || ""))
    );
    name.value = "";
    const fresh = await api.get("/admin/api/keys");
    listBox(fresh);
  };
  const list = el("div", {});
  const listBox = (d) => {
    clear(list);
    list.appendChild(
      table(
        [
          { title: "Id", render: (k) => code(k.id) },
          { title: "Name", key: "name" },
          { title: "Prefix", render: (k) => code(k.prefix) },
          { title: "Scope", key: "scope" },
          { title: "Created", render: (k) => when(k.created) },
          {
            title: "",
            render: (k) =>
              button(
                "Revoke",
                async () => {
                  if (!confirm(`Revoke key ${k.name}? Applications using it stop working.`)) return;
                  await api.del("/admin/api/keys/" + enc(k.id));
                  ok("Key revoked.");
                  listBox(await api.get("/admin/api/keys"));
                },
                "small danger"
              ),
          },
        ],
        d.keys || [],
        "No API keys."
      )
    );
  };
  listBox(data);
  const rotated = el("div", {});
  const rotate = async () => {
    if (!confirm("Rotate the admin token? The old one stops working at once.")) return;
    const r = await api.put("/admin/api/rotate");
    sessionStorage.setItem(TOKEN_KEY, r.token);
    clear(rotated);
    rotated.appendChild(el("div", { class: "banner good stack" }, el("b", { text: "New admin token (shown once, copy it now)" }), el("code", { class: "secret", text: r.token }), muted("This session already uses it.")));
  };
  done(
    el(
      "div",
      {},
      title("Keys"),
      card("API keys", el("p", { class: "hint", text: "Webhook secret: " + (data.webhook_secret_set ? "set" : "not set") }), shown, list, el("div", { class: "inline" }, name, scope, button("Create key", create, "primary"))),
      card("Admin token", el("p", { class: "hint", text: "Rotating signs out everyone else." }), rotated, button("Rotate admin token", rotate, "danger"))
    )
  );
}

// ------------------------------------------------------------------ audit, outbox

async function auditView(_args, done) {
  const { audit } = await api.get("/admin/api/audit");
  done(
    el(
      "div",
      {},
      title("Audit", muted("Last 200 entries"), button("Refresh", reload, "small")),
      card(
        null,
        table(
          [
            { title: "When", render: (a) => when(a.at) },
            { title: "Who", key: "actor" },
            { title: "Action", render: (a) => pill(a.action, "p-neutral") },
            { title: "Target", render: (a) => code(a.target), wrap: true },
            { title: "Detail", key: "detail", wrap: true },
          ],
          audit || [],
          "The audit log is empty."
        )
      )
    )
  );
}

async function outboxView(_args, done) {
  const { outbox } = await api.get("/admin/api/outbox");
  done(
    el(
      "div",
      {},
      title("Outbox", muted("Last 100 items"), button("Refresh", reload, "small")),
      card(
        null,
        table(
          [
            { title: "#", key: "id" },
            { title: "Kind", key: "kind" },
            { title: "What", key: "what" },
            { title: "Status", render: (i) => pill(i.status, i.status === "failed" ? "p-quarantine" : i.status === "done" ? "p-allow" : "p-review") },
            { title: "Attempts", key: "attempts", num: true },
            { title: "Next try", render: (i) => (i.status === "pending" ? when(i.next_at) : null) },
            { title: "Last error", key: "last_error", wrap: true },
            { title: "Created", render: (i) => when(i.created_at) },
          ],
          outbox || [],
          "The outbox is empty."
        )
      )
    )
  );
}

// ------------------------------------------------------------------ start

const VIEWS = {
  overview: overviewView,
  cases: casesView,
  actors: actorsView,
  tenants: tenantsView,
  rules: rulesView,
  playground: playgroundView,
  replay: replayView,
  lists: listsView,
  config: configView,
  keys: keysView,
  audit: auditView,
  outbox: outboxView,
};

window.addEventListener("hashchange", route);
route();
