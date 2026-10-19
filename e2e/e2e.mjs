import { readFileSync } from "node:fs";
import { Client, verifyWebhook } from "../sdk/typescript/src/index.js";

const [, , key, secret, hookFile] = process.argv;
const of = new Client({ baseUrl: "http://127.0.0.1:18092", apiKey: key });
const probe = { type: "message.test_requested", actor_id: "ts_probe", email: "ts.probe@gmail.com", attrs: { recipients: ["a1@gmail.com", "b1@yahoo.com", "c1@outlook.com", "d1@icloud.com"] } };
const d = await of.decide(probe);
if (d.decision !== "quarantine" || d.failover) throw new Error("decide: " + JSON.stringify(d));
const t = await of.track({ type: "account.created", actor_id: "ts_other" });
if (!t.accepted) throw new Error("track: " + JSON.stringify(t));
await new Promise((r) => setTimeout(r, 4000));
const hook = JSON.parse(readFileSync(hookFile, "utf8"));
const ev = await verifyWebhook(secret, hook.headers, hook.body);
if (ev.type !== "decision.quarantine") throw new Error("webhook: " + JSON.stringify(ev));
const down = new Client({ baseUrl: "http://127.0.0.1:1", apiKey: key });
const f = await down.decide(probe);
if (f.decision !== "allow" || !f.failover) throw new Error("fail open: " + JSON.stringify(f));
console.log("typescript ok");
