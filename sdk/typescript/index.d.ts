export type DecisionValue = "allow" | "step_up" | "review" | "hold" | "block" | "quarantine";

export interface OpenFraudEvent {
  id?: string;
  type: string;
  /** RFC 3339 or Unix seconds */
  at?: string | number;
  actor_id?: string;
  /** When the actor's account was created, for accounts older than openfraud: RFC 3339 or Unix seconds */
  actor_created_at?: string | number;
  tenant_id?: string;
  owner_id?: string;
  email?: string;
  phone?: string;
  ip?: string;
  device?: string;
  /** The end user's User-Agent header, not your server's: read into facts, never stored */
  user_agent?: string;
  /** The end user's Accept-Language header, or a language tag such as fr-BE */
  language?: string;
  country?: string;
  /** The token of the browser script (sdk/device deviceToken()), as the page sent it */
  device_token?: string;
  /** "client" for an event a page or an app reports on its own: its actor, tenant and owner are ignored */
  reported_by?: "server" | "client";
  subject?: { type: string; id: string };
  attrs?: Record<string, unknown>;
  /** What the account is, kept on it from event to event: texts, numbers, booleans */
  traits?: Record<string, string | number | boolean>;
}

export interface Reason {
  rule: string;
  workflow: string;
  score: number;
  reason: string;
  mode: string;
}

export interface Action {
  action: string;
  target: "actor" | "tenant";
  id: string;
}

export interface Decision {
  event_id: string;
  decision: DecisionValue;
  score: number;
  reasons: Reason[];
  actions: Action[];
  case_id?: number | null;
  statement_id?: string | null;
  /** Unix seconds, for a hold with a length */
  hold_until?: number | null;
  /** seconds before the actor may try this action again, when throttled */
  retry_after?: number | null;
  /** rules that would have fired but are snoozed for this account */
  snoozed?: string[];
  /** what the facts show and the signals of the rules that fired: {"new_device": {}} */
  signals?: Record<string, Record<string, unknown>>;
  /** 0 to 1, from the rules that fired: a summary of the rules, not a model */
  scores?: { account_takeover: number; account_abuse: number; bot: number };
  /** the lists the event changed */
  lists?: Array<{ list: string; action: "add" | "remove" }>;
  /** an allow rule with stop = true that ended the other workflows */
  stopped_by?: string | null;
  /** before sign-in: the account the event's email address belongs to */
  matched_actor?: string | null;
  shadow?: { decision: DecisionValue; reasons: Reason[] };
  brake?: boolean;
  duplicate?: boolean;
  took_us?: number;
  /** true when the SDK made this decision because the server was unreachable */
  failover?: boolean;
  error?: string;
}

export interface TrackResult {
  event_id?: string;
  accepted: boolean;
  duplicate?: boolean;
  error?: string;
}

export interface BatchResult {
  accepted?: boolean;
  results?: Array<{ event_id?: string; accepted?: boolean; error?: string }>;
  error?: string;
}

export interface ClientOptions {
  baseUrl: string;
  apiKey: string;
  /** default 300 */
  timeoutMs?: number;
  /** default 2 */
  retries?: number;
  /** backoff bases per retry in ms, default [50, 150] */
  backoffMs?: number[];
}

export class OpenFraudError extends Error {
  status: number;
  type: string;
}

export class WebhookError extends Error {}

export class Client {
  constructor(options: ClientOptions);
  decide(event: OpenFraudEvent, options?: { idempotencyKey?: string; failClosed?: boolean }): Promise<Decision>;
  track(event: OpenFraudEvent): Promise<TrackResult>;
  trackBatch(events: OpenFraudEvent[]): Promise<BatchResult>;
}

/** Returns the parsed body, throws WebhookError when the signature or timestamp is bad. */
export function verifyWebhook(
  secret: string,
  headers: Record<string, string> | Headers,
  rawBody: string,
  options?: { toleranceSec?: number; now?: number },
): Promise<any>;
