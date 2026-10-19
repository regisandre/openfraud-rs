> Status: shipped in 0.1, optional and off by default; matches src/ai.rs
> Last checked: 2026-10-19

# The AI assistant

An optional helper for the people who review cases. It writes case summaries
and suggests rules. **It never decides anything**: no decision, status or
action depends on a model. It is off by default and makes no outbound call
unless enabled.

## Configuration

```toml
[ai]
enabled = true
base_url = "https://api.openai.com/v1"   # default; any OpenAI-compatible endpoint
model = "gpt-5-mini"                      # default
api_key_env = "OPENFRAUD_AI_API_KEY"      # default; the variable may be unset for a local model
summarize_cases = true                    # default
timeout_secs = 60                         # default
max_output_tokens = 800                   # default
```

| Key | Meaning |
|---|---|
| `enabled` | turns the module on (default false) |
| `base_url` | the root of a chat completions API (`<base_url>/chat/completions`): a hosted provider, or a local Ollama or vLLM. Must start with `http://` or `https://` |
| `model` | the model name sent to the API |
| `api_key_env` | the environment variable holding the key, sent as a bearer token. If it is unset or empty, no key is sent (a local model) |
| `summarize_cases` | write a summary for every new case |
| `timeout_secs` | per request |
| `max_output_tokens` | sent as `max_completion_tokens` |

The key is never in the configuration file.

## Case summaries

When a case is opened and `summarize_cases` is on, a job is queued and a
summary of three to six sentences is written onto the case: what the account
did in order, which rules fired and why it matters, and what the reviewer
should check. A failed job is retried a few times. You can also request one
for any case from the admin interface (`POST /admin/api/cases/{id}/summary`).
The summary is stored on the case (`summary`) and shown to reviewers; it is
not part of the statement of reasons shown to users.

What the model sees: the case (decision, score, rule ids), the account's
status, trust and top score, and its 30 latest events (type, seconds since
the first, **pseudonymized** email, IP network prefix, IP lists, country,
plain attributes shortened to 200 characters, decision, score, rules).

## Rule suggestions

`POST /admin/api/ai/suggest` (the Suggest button): the model reads the
workflows, counters and list names of the running configuration and up to 20
timelines of accounts people labelled `fraud` and 20 labelled `legit`, and
proposes at most five rules (ten are taken at most) that would catch the
fraud without hitting the legit accounts.

Each suggestion is compiled against the running configuration and comes back as

```json
{"workflow": "msg_sending", "id": "ai_free_domain_burst", "when": "...", "score": 40,
 "reason": "...", "valid": true, "problem": null,
 "toml": "[[workflows.msg_sending.rules]]\nid = ...\nmode = \"shadow\"\n"}
```

`valid` is false, with a `problem`, if the workflow does not exist, the id is
invalid or already used, the score is zero or outside -100 to 100, the reason
is empty, or the condition does not compile (an unknown counter or list, a
bad function). The TOML block is **always shadow mode, with no forced
decision and no actions**. A person pastes it into the configuration, checks
it with `openfraud validate`, watches it in shadow, and promotes it after a
replay like any other rule ([safety.md](safety.md)). Nothing is written to the
configuration for you.

## Prompt injection

Users write some of what the model reads: a page title, a username, a
campaign subject. That text could say "ignore your instructions". The
protections:

- user data reaches the model only inside a `<data> ... </data>` block, and
  the instructions say that block is untrusted and must not be followed (a
  suspicious instruction in it should be reported, not obeyed). A literal
  `</data>` or `<data>` in the data is escaped so it cannot close the block;
- the block is cut at 60,000 characters, texts at 200, lists at 20 items;
- the model has no tools and its output is only text (a summary) or a JSON
  object (suggestions), which is validated as above; at worst a manipulated
  summary misleads a reviewer, which is why it is labelled a summary and the
  reviewer sees the events and the rules beside it;
- no decision path reads the model's output.

## Privacy

Only normalized events leave openfraud: email addresses appear as
pseudonyms, IP addresses as network prefixes, devices as hashes. Plain
attributes are sent as stored, so anything personal you put in `attrs` (a
title, a username) goes to the endpoint too. If that is a problem, point
`base_url` at a model you run yourself, or leave the assistant off. Treat a
hosted provider as a processor in your records of processing.
