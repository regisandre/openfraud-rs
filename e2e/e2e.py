import json
import sys
import time

sys.path.insert(0, "../sdk/python")
from openfraud import Client, verify_webhook  # noqa: E402

key, secret, hook_file = sys.argv[1:4]
of = Client("http://127.0.0.1:18092", key)
probe = {"type": "message.test_requested", "actor_id": "py_probe", "email": "py.probe@gmail.com",
         "attrs": {"recipients": ["a2@gmail.com", "b2@yahoo.com", "c2@outlook.com", "d2@icloud.com"]}}
d = of.decide(probe)
assert d["decision"] == "quarantine" and not d.get("failover"), d
t = of.track({"type": "account.created", "actor_id": "py_other"})
assert t["accepted"], t
time.sleep(4)
hook = json.load(open(hook_file))
ev = verify_webhook(secret, hook["headers"], hook["body"])
assert ev["type"] == "decision.quarantine", ev
f = Client("http://127.0.0.1:1", key).decide(probe)
assert f["decision"] == "allow" and f["failover"], f
print("python ok")
