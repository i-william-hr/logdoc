#!/usr/bin/env python3
"""One-time setup for logdoc: create the llmproxy key and write this
project's .env. Run as root (it reads two 0600 env files it does not own):

    sudo python3 [REDACTED:server-path]            # create/ensure
    sudo python3 [REDACTED:server-path] --rotate   # new secret
    sudo python3 [REDACTED:server-path] --setmodel groq llama-3.3-70b-versatile

What it does:
  1. Reads LLMPROXY_GATE_SECRET from [REDACTED:server-path]
  2. Finds or creates the client key labeled "logdoc" via the admin API on
     the loopback socket (POST /api/keys). The plaintext secret is returned
     exactly once by llmproxy — here or on --rotate; it is never printed in
     full, only written to [REDACTED:server-path] (0600, logdoc:logdoc).
  3. Copies the Telegram bot/chat credentials from [REDACTED:server-path]
     (the same bot/chat wmon alerts and the daily digest use) into
     LOGDOC_TG_BOT_TOKEN / LOGDOC_TG_CHAT_ID.

llmproxy routes by key: the key's pinned provider+model decide the backend,
so logdoc's backend is changed from the llm.inbox.li admin UI or with
--setmodel — never by editing provider keys here. llmproxy itself is not
restarted or otherwise touched; keys are runtime data.
"""

import argparse
import json
import os
import pwd
import sys
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE, ".env")
LLMPROXY_ENV = "[REDACTED:server-path]"
STATUS_ENV = "[REDACTED:server-path]"
PROXY_BASE = "http://127.0.0.1:[REDACTED:loopback-port]"

KEY_LABEL = "logdoc"
DEFAULT_PROVIDER = "nvidia"
DEFAULT_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"


def read_env(path):
    vals = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                vals.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass
    return vals


def api(method, path, gate, body=None):
    req = urllib.request.Request(
        PROXY_BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-Llmproxy-Gate": gate, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode() or "{}")
        except ValueError:
            return exc.code, {}
    except urllib.error.URLError as exc:
        raise SystemExit("provision: cannot reach llmproxy at %s: %s"
                         % (PROXY_BASE, exc))


def find_key(gate):
    status, data = api("GET", "/api/state", gate)
    if status != 200:
        raise SystemExit("provision: GET /api/state -> %s (%s)"
                         % (status, data.get("error", "?")))
    for key in data.get("keys", []):
        if key.get("label") == KEY_LABEL:
            return key
    return None


def ensure_key(gate, provider, model):
    """Create the key if missing. Returns (key_row_or_None, secret_or_None):
    the secret only exists on the create/rotate path."""
    key = find_key(gate)
    if key:
        return key, None
    status, data = api("POST", "/api/keys", gate, {
        "label": KEY_LABEL,
        "provider": provider,
        "model": model,
        "note": "logdoc — journal/nginx error analysis from logdoc-check.timer",
    })
    if status == 409:  # raced; re-read
        return find_key(gate), None
    if status != 201:
        raise SystemExit("provision: POST /api/keys -> %s (%s)"
                         % (status, data.get("error", "?")))
    return data.get("key"), data.get("secret")


def write_env(secret=None, base_url=None):
    """Merge into .env, preserving anything already there. The key secret is
    only rewritten when this run actually obtained one."""
    cur = read_env(ENV_PATH)
    status_env = read_env(STATUS_ENV)
    updates = {
        "LOGDOC_LLM_BASE_URL": base_url or cur.get("LOGDOC_LLM_BASE_URL") or PROXY_BASE,
        "LOGDOC_TG_BOT_TOKEN": status_env.get("STATUS_TG_BOT_TOKEN",
                                              cur.get("LOGDOC_TG_BOT_TOKEN", "")),
        "LOGDOC_TG_CHAT_ID": status_env.get("STATUS_TG_CHAT_ID",
                                            cur.get("LOGDOC_TG_CHAT_ID", "")),
    }
    if secret:
        updates["LOGDOC_LLM_KEY"] = secret
    elif not cur.get("LOGDOC_LLM_KEY"):
        print("provision: WARNING: key exists but its secret is unknown and "
              ".env has no LOGDOC_LLM_KEY — run `sudo python3 provision.py "
              "--rotate` to mint a fresh one.", file=sys.stderr)
    lines = ["# written by provision.py — secrets, do not commit"]
    for k in sorted(set(cur) | set(updates)):
        v = updates.get(k, cur.get(k, ""))
        if v == "":
            continue
        lines.append("%s=%s" % (k, v))
    tmp = ENV_PATH + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    try:
        pw = pwd.getpwnam("logdoc")
        os.chown(tmp, pw.pw_uid, pw.pw_gid)
    except KeyError:
        print("provision: WARNING: no 'logdoc' user — leaving .env root-owned",
              file=sys.stderr)
    os.replace(tmp, ENV_PATH)


def main():
    ap = argparse.ArgumentParser(description="create the logdoc llmproxy key and .env")
    ap.add_argument("--rotate", action="store_true",
                    help="mint a fresh secret for the existing key")
    ap.add_argument("--setmodel", nargs=2, metavar=("PROVIDER", "MODEL"),
                    help="retarget the key's backend (e.g. nvidia nvidia/nemotron-3.5-lightning-30b-a3b)")
    args = ap.parse_args()

    gate = read_env(LLMPROXY_ENV).get("LLMPROXY_GATE_SECRET", "")
    if not gate:
        raise SystemExit("provision: LLMPROXY_GATE_SECRET not found in %s" % LLMPROXY_ENV)

    provider, model = DEFAULT_PROVIDER, DEFAULT_MODEL
    if args.setmodel:
        provider, model = args.setmodel

    key, secret = ensure_key(gate, provider, model)
    if key is None:
        raise SystemExit("provision: could not find or create the key")

    if args.setmodel:
        status, data = api("PATCH", "/api/keys/%s" % key["id"], gate,
                           {"provider": provider, "model": model})
        if status != 200:
            raise SystemExit("provision: PATCH /api/keys -> %s (%s)"
                             % (status, data.get("error", "?")))
        key = data.get("key", key)

    if args.rotate:
        status, data = api("POST", "/api/keys/%s/rotate" % key["id"], gate)
        if status != 200 or "secret" not in data:
            raise SystemExit("provision: rotate -> %s (%s)"
                             % (status, data.get("error", "?")))
        secret = data["secret"]

    write_env(secret=secret)

    print("provision: key id=%s label=%s provider=%s model=%s enabled=%s"
          % (key["id"], key["label"], key["provider"], key["model"],
             key.get("enabled")))
    print("provision: secret: %s..." % ((secret or read_env(ENV_PATH).get("LOGDOC_LLM_KEY", ""))[:11] or "(unchanged/unknown)"))
    if secret:
        print("provision: fresh secret written to %s (0600)" % ENV_PATH)
    print("provision: .env updated — TG credentials copied from %s" % STATUS_ENV)
    return 0


if __name__ == "__main__":
    sys.exit(main())
