#!/usr/bin/env bash
# End to end: the server, a webhook receiver, and each SDK against them,
# then a hand edit of the configuration applied by the running server.
# Needs a built binary (cargo build), Node 18+, Python 3.9+ and Go.
set -u
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:/c/Program Files/Go/bin:$PATH"
BIN=${BIN:-../target/debug/openfraud}
PY=$(command -v python3 || command -v python)
rm -f e2e.db* state.toml hook.json server.log
trap 'mv -f openfraud.toml.bak openfraud.toml 2>/dev/null; kill $SRV $RECV 2>/dev/null' EXIT
"$PY" receiver.py hook.json &
RECV=$!
KEY=$("$BIN" -c openfraud.toml key add e2e 2>/dev/null)
"$BIN" -c openfraud.toml serve > server.log 2>&1 &
SRV=$!
for i in $(seq 30); do curl -sf http://127.0.0.1:18092/health > /dev/null && break; sleep 1; done
SECRET=$(grep webhook_secret state.toml | sed 's/.*= *"\(.*\)"/\1/')
fail=0
node e2e.mjs "$KEY" "$SECRET" hook.json || fail=1
"$PY" e2e.py "$KEY" "$SECRET" hook.json || fail=1
(cd goclient && go run . "$KEY" "$SECRET" ../hook.json) || fail=1

# A hand edit of the configuration is applied by the running server.
cp openfraud.toml openfraud.toml.bak
printf '\n[lists.blocked_actors]\nkind = "value"\nitems = ["edited_out"]\n' >> openfraud.toml
for i in $(seq 15); do
  d=$(curl -s -H "authorization: Bearer $KEY" -H "content-type: application/json" -d '{"type":"account.created","actor_id":"edited_out"}' http://127.0.0.1:18092/v1/decide)
  echo "$d" | grep -q '"decision":"block"' && break; sleep 1
done
echo "$d" | grep -q '"decision":"block"' && echo "reload ok" || { echo "reload FAILED: $d"; fail=1; }
printf '\n[workflows.broken]\nevents = ["not a type"]\n' >> openfraud.toml
sleep 4
grep -q "not valid, the running one stays" server.log && echo "broken edit reported ok" || { echo "broken edit NOT reported"; fail=1; }
curl -sf http://127.0.0.1:18092/health > /dev/null && echo "still serving ok" || { echo "server died"; fail=1; }
mv openfraud.toml.bak openfraud.toml

exit $fail
