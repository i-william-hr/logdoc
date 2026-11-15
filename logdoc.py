#!/usr/bin/env python3
"""logdoc — watch journald + nginx errors, explain crashes via llmproxy.

A stdlib-only sweeper meant to run every 5 minutes from logdoc-check.timer.
Each sweep it reads everything that is new since its last cursor per watched
unit (all units under [REDACTED:server-path], plus the kernel, plus
/var/log/nginx/error.log), matches ERROR/FATAL-class lines, and for each
error fingerprint not seen within the cooldown window it sends the last 50
lines of context through llmproxy (http://127.0.0.1:[REDACTED:loopback-port]). The reply —
WHAT BROKE / LIKELY CAUSE / FIX — is appended to data/analyses.jsonl,
rewritten into data/digest.json (read by status/report.py for the daily
digest) and pushed to the same Telegram chat wmon alerts to.

The llmproxy key in .env pins the provider+model (the request "model" field
is ignored by llmproxy); retarget the backend from the llm.inbox.li admin UI
or with `sudo python3 provision.py --setmodel <provider> <model>`.

Exit nonzero only when a Telegram alert for a new analysis failed, so the
timer unit shows failed — same contract as status/report.py.
"""

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
CURSORS = os.path.join(DATA, "cursors")
STATE_PATH = os.path.join(DATA, "state.json")
ANALYSES_PATH = os.path.join(DATA, "analyses.jsonl")
DIGEST_PATH = os.path.join(DATA, "digest.json")

# journalctl prints this hint on stderr when the caller lacks journal access;
# if it ever shows up the group membership (systemd-journal/adm) broke.
JOURNAL_HINT = "not seeing messages"

SYS_PROMPT = (
    "You are logdoc, an ops assistant for a Debian web server. You receive the "
    "last 50 log lines from one systemd unit (or the kernel, or nginx) that "
    "just logged an error. Reply with exactly three short sections and "
    "nothing else:\n"
    "WHAT BROKE: one line.\n"
    "LIKELY CAUSE: 1-2 lines.\n"
    "FIX: one concrete shell command or config change (write 'unknown' only "
    "if the logs genuinely do not say)."
)


def _env(path):
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


ENV = _env(os.path.join(BASE, ".env"))


def cfg_get(name, default):
    """Secrets and overridables come from .env first, config.json second."""
    env = os.environ.get("LOGDOC_" + name.upper(), ENV.get("LOGDOC_" + name.upper(), ""))
    return env or default


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def unit_list(cfg):
    """All custom services. Auto-glob keeps new services watched without
    config edits; the static list is the fallback if the glob comes up empty.
    Exclude units listed in cfg["exclude_units"] or matching cfg["exclude_patterns"]."""
    if cfg.get("auto_units", True):
        try:
            units = sorted(os.path.basename(p)
                           for p in glob.glob("[REDACTED:server-path]*.service"))
            if units:
                # Filter out excluded units
                exclude_units = set(cfg.get("exclude_units", []))
                exclude_patterns = [re.compile(p) for p in cfg.get("exclude_patterns", [])]
                filtered = []
                for unit in units:
                    if unit in exclude_units:
                        continue
                    if any(p.search(unit) for p in exclude_patterns):
                        continue
                    filtered.append(unit)
                return filtered
        except OSError:
            pass
    return [u for u in (cfg["units"] or []) 
            if u not in cfg.get("exclude_units", []) and not
            any(re.search(p, u) for p in cfg.get("exclude_patterns", []))]


# --------------------------------------------------------------- redaction ---

REDACT_RES = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{8,}"), "sk-REDACTED"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer REDACTED"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"), "gh-REDACTED"),
    (re.compile(r"xox[bpars]-[A-Za-z0-9\-]{8,}"), "xox-REDACTED"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA-REDACTED"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_\-]?key|token)\b(['\"]?\s*[:=]\s*)(['\"]?)\S+"),
     r"\1\2\3REDACTED"),
]


def backup_state(unit, cfg):
    """Create a pre-fix backup for quick rollback."""
    timestamp = now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(DATA, "backups", f"{unit}_{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)
    
    backup_data = {
        "unit": unit,
        "timestamp": iso(now()),
        "systemd_status": None,
        "config_files": [],
        "log_state": None
    }
    
    # Backup systemd status
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=10
        )
        backup_data["systemd_status"] = proc.stdout.strip()
    except Exception:
        pass
    
    # Backup config files if they exist
    config_paths = cfg.get("backup_configs", [])
    for config_path in config_paths:
        full_path = config_path.format(unit=unit) if "{unit}" in config_path else config_path
        if os.path.exists(full_path):
            backup_path = os.path.join(backup_dir, os.path.basename(full_path))
            try:
                import shutil
                shutil.copy2(full_path, backup_path)
                backup_data["config_files"].append(full_path)
            except Exception:
                pass
    
    # Save backup file
    backup_file = os.path.join(DATA, "backups", f"{unit}_{timestamp}.json")
    with open(backup_file, "w") as f:
        json.dump(backup_data, f, indent=2)
    
    return backup_dir


def redact(text):
    for rx, repl in REDACT_RES:
        text = rx.sub(repl, text)
    return text


# ------------------------------------------------------------------ journal ---

def journal_lines(selector, cursor_path, window_min):
    """New journal entries since the stored cursor for one source.

    Returns (lines, new_cursor, warnings). new_cursor is None when nothing
    was read — the stored cursor must then be left alone. systemd 259 refuses
    --cursor together with --since, so the --since window is only used when no
    cursor exists yet (first run) or the stored one went stale (journal
    vacuum/rotation, which journalctl reports as 'Failed to seek to cursor'
    with exit code 0 and empty output).
    """
    base = ["journalctl", *selector, "--no-pager", "-o", "short-iso",
            "--quiet", "--show-cursor"]
    saved = None
    try:
        with open(cursor_path) as fh:
            saved = fh.read().strip()
    except OSError:
        pass

    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return None

    proc = run(base + (["--cursor=" + saved] if saved else ["--since=-%dmin" % window_min]))
    if proc is None:
        return None, None, ["journalctl failed to run for %s" % (selector,)]
    if "Failed to seek to cursor" in proc.stderr:
        proc = run(base + ["--since=-%dmin" % window_min])
        if proc is None:
            return None, None, ["journalctl failed to run for %s" % (selector,)]

    warnings = []
    if JOURNAL_HINT in proc.stderr:
        warnings.append("journalctl hints the caller lacks journal access — "
                        "is the service user still in systemd-journal/adm?")
    if proc.returncode != 0 and not proc.stdout.strip():
        warnings.append("journalctl rc=%d: %s" % (proc.returncode, proc.stderr.strip()[:200]))
        return None, None, warnings

    lines, new_cursor = [], None
    for line in proc.stdout.splitlines():
        if line.startswith("-- cursor: "):
            new_cursor = line[len("-- cursor: "):].strip()
        elif line.strip() and line.strip() != "-- No entries --":
            lines.append(line)
    return lines, new_cursor, warnings


def journal_context(selector, n_lines):
    """The last n_lines of a source, regardless of cursors — the LLM's window."""
    cmd = ["journalctl", *selector, "--no-pager", "-o", "short-iso",
           "--quiet", "-n", str(n_lines)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return "(journalctl failed)"
    return proc.stdout or "(no log lines)"


# -------------------------------------------------------------------- nginx ---

def nginx_lines(cfg, off_state):
    """New lines from the nginx error log since the stored byte offset.

    Returns (lines, new_state, warnings). On first sight of a huge log only
    the last nginx_max_bytes are read (and a possibly-split first line is
    dropped); rotation (inode change) and truncation (size < offset) reset.
    """
    path = cfg["nginx_error_log"]
    try:
        st = os.stat(path)
    except OSError as exc:
        return None, off_state, ["stat %s: %s" % (path, exc)]
    off = off_state.get("offset", 0)
    if off_state.get("inode") is not None and st.st_ino != off_state["inode"]:
        off = 0  # rotated
    if st.st_size < off:
        off = 0  # truncated
    if st.st_size == off:
        return [], off_state, []
    start = off
    capped = False
    if st.st_size - start > cfg["nginx_max_bytes"]:
        start = st.st_size - cfg["nginx_max_bytes"]
        capped = True
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            blob = fh.read(st.st_size - start)
    except OSError as exc:
        return None, off_state, ["read %s: %s" % (path, exc)]
    lines = [l for l in blob.decode("utf-8", "replace").splitlines() if l.strip()]
    if capped and lines:
        lines = lines[1:]
    return lines, {"offset": st.st_size, "inode": st.st_ino}, []


# ---------------------------------------------------------------- detection ---

def fingerprint(unit, error_line):
    """A stable id for an error kind: unit + message with timestamps, pids,
    paths-unique numbers and addresses normalised away, so a crash loop is
    one fingerprint and the cooldown can do its job."""
    msg = error_line
    m = re.match(r"^\S+\s+\S+\s+([^:\s]+)(?:\[\d+\])?:\s?(.*)$", msg)
    if m:
        msg = m.group(2)
    msg = msg.lower()
    msg = re.sub(r"\d+", "#", msg)
    msg = re.sub(r"\s+", " ", msg).strip()[:200]
    return hashlib.sha1((unit + "\x00" + msg).encode()).hexdigest()[:16]


def detect(unit, lines, err_re, ignore_res):
    """Yield (error_line, fingerprint) for lines matching the error regex
    and none of the ignore regexes."""
    out = []
    seen = set()
    for line in lines:
        if not err_re.search(line):
            continue
        if any(rx.search(line) for rx in ignore_res):
            continue
        fp = fingerprint(unit, line)
        if fp not in seen:
            seen.add(fp)
            out.append((line, fp))
    return out


# -------------------------------------------------------------------- state ---

def load_state():
    try:
        with open(STATE_PATH) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    state.setdefault("fps", {})
    state.setdefault("nginx", {})
    state.setdefault("day", "")
    state.setdefault("llm_calls_today", 0)
    state.setdefault("alerts_today", 0)
    return state


def save_state(state):
    os.makedirs(DATA, exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_PATH)


def reset_daily(state):
    today = now().strftime("%Y-%m-%d")
    if state["day"] != today:
        state["day"] = today
        state["llm_calls_today"] = 0
        state["alerts_today"] = 0


def prune_fps(state, days):
    cutoff = now() - dt.timedelta(days=days)
    for fp in [k for k, v in state["fps"].items()
               if _parse_iso(v.get("last_seen")) < cutoff]:
        del state["fps"][fp]


def _parse_iso(s):
    try:
        return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------- LLM ---

def llm_analyze(unit, error_line, context, timeout=90):
    """One chat completion through llmproxy. The 'model' field is a label —
    llmproxy routes by the key, so the backend is changed at the key."""
    key = cfg_get("llm_key", "")
    base = cfg_get("llm_base_url", "http://127.0.0.1:[REDACTED:loopback-port]").rstrip("/")
    if not key:
        raise RuntimeError("LOGDOC_LLM_KEY not set — run provision.py")
    body = {
        "model": "logdoc",
        "temperature": 0.2,
        "max_tokens": 400,
        "messages": [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content":
                "Source: %s\nError line: %s\n\nLast log lines:\n%s"
                % (unit, error_line, context)},
        ],
    }
    req = urllib.request.Request(
        base + "/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + key,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    # Handle different LLM response formats
    # Cohere and other providers may return the content in different places
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    content = message.get("content", "")
    if not content and "text" in choice:
        # Some providers use a "text" field instead of "content"
        content = choice["text"]
    return content.strip()


# ---------------------------------------------------------------- Telegram ---

def tg_send(text):
    token = cfg_get("tg_bot_token", "")
    chat = cfg_get("tg_chat_id", "")
    if not token or not chat:
        print("logdoc: LOGDOC_TG_BOT_TOKEN/LOGDOC_TG_CHAT_ID not set",
              file=sys.stderr)
        return False
    ok = True
    chunks, cur = [], ""
    for line in text.splitlines(keepends=True):
        if len(cur) + len(line) > 3800:
            chunks.append(cur)
            cur = ""
        cur += line
    chunks.append(cur)
    for chunk in chunks:
        url = "https://api.telegram.org/bot%s/sendMessage" % token
        data = urllib.parse.urlencode({"chat_id": chat, "text": chunk}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data),
                                        timeout=15) as resp:
                ok = resp.status == 200 and ok
        except Exception as exc:  # noqa: BLE001
            print("logdoc: telegram send failed: %s" % exc, file=sys.stderr)
            ok = False
    return ok


# ------------------------------------------------------------------ storage ---

def record_analysis(entry, dry):
    """Append to analyses.jsonl and rewrite digest.json (0644 so the status
    user's report.py can read it; everything else in data/ stays 0600)."""
    if not dry:
        os.makedirs(DATA, exist_ok=True)
        with open(ANALYSES_PATH, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        rewrite_digest()
    print("logdoc: [%s] %s" % (entry["unit"], entry["error_line"][:160]))
    if entry.get("analysis"):
        for line in entry["analysis"].splitlines():
            print("  " + line)


def rewrite_digest():
    cutoff = now() - dt.timedelta(hours=24)
    entries = []
    try:
        with open(ANALYSES_PATH) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if _parse_iso(e.get("ts")) >= cutoff:
                    entries.append(e)
    except FileNotFoundError:
        pass
    entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
    digest = {"generated_at": iso(now()), "window_hours": 24, "analyses": entries}
    tmp = DIGEST_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(digest, fh, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, DIGEST_PATH)


# -------------------------------------------------------------------- sweep ---

def build_context(lines, cfg):
    red = []
    total = 0
    for line in lines[-cfg["context_lines"]:]:
        rl = redact(line)[:cfg["context_line_chars"]]
        red.append(rl)
        total += len(rl) + 1
        if total >= cfg["context_total_chars"]:
            break
    return "\n".join(red)


def process_candidates(source, candidates, state, cfg, dry):
    """Dedup against the fingerprint store, analyse what is new or past its
    cooldown, alert, record. Returns True when every alert send succeeded."""
    all_sent = True
    cooldown = dt.timedelta(hours=cfg["cooldown_hours"])
    for error_line, fp in candidates:
        rec = state["fps"].get(fp)
        if rec:
            rec["last_seen"] = iso(now())
            rec["count"] += 1
            if rec.get("last_analysis") and _parse_iso(rec["last_analysis"]) > now() - cooldown:
                continue  # still cooling down; the count bump is all it gets
        else:
            rec = {"unit": source, "error_line": redact(error_line)[:300],
                   "first_seen": iso(now()), "last_seen": iso(now()),
                   "count": 1, "last_analysis": None, "analysis": None}
            state["fps"][fp] = rec

        entry = {"ts": iso(now()), "unit": source, "fingerprint": fp,
                 "count": rec["count"], "error_line": rec["error_line"],
                 "analysis": None, "status": "ok"}

        if state["llm_calls_today"] >= cfg["max_llm_calls_per_day"]:
            entry["status"] = "capped"
            entry["analysis"] = "(daily LLM cap reached — raw error line only)"
            rec["last_analysis"] = entry["ts"]
            rec["analysis"] = entry["analysis"]
            record_analysis(entry, dry)
            continue

        # context: the LLM's window over the whole source, not just this line
        if source == "kernel":
            context = build_context(journal_context(["-k"], cfg["context_lines"]), cfg)
        elif source.startswith("nginx"):
            try:
                with open(cfg["nginx_error_log"], "rb") as fh:
                    fh.seek(0, 2)
                    size = fh.tell()
                    fh.seek(max(0, size - cfg["context_total_chars"]))
                    context = build_context(
                        fh.read(cfg["context_total_chars"]).decode("utf-8", "replace").splitlines(),
                        cfg)
            except OSError:
                context = "(unreadable)"
        else:
            context = build_context(journal_context(["-u", source],
                                                    cfg["context_lines"]), cfg)

        state["llm_calls_today"] += 1
        try:
            entry["analysis"] = llm_analyze(source, rec["error_line"], context)
        except Exception as exc:  # noqa: BLE001
            entry["status"] = "llm_error"
            entry["analysis"] = None
            entry["error_detail"] = str(exc)[:300]
            print("logdoc: llmproxy call failed for %s: %s" % (source, exc),
                  file=sys.stderr)
        rec["last_analysis"] = entry["ts"]
        rec["analysis"] = entry["analysis"]

        if entry["status"] == "ok":
            if state["alerts_today"] < cfg["max_alerts_per_day"]:
                state["alerts_today"] += 1
                alert = "🩺 logdoc — %s\n%s\n———\n%s" % (
                    source, rec["error_line"][:300], entry["analysis"])
                if not dry and not tg_send(alert):
                    all_sent = False
        record_analysis(entry, dry)
    return all_sent


def _cursor_path(name):
    safe = re.sub(r"[^A-Za-z0-9_.@\-]", "_", name)
    return os.path.join(CURSORS, safe + ".cursor")


def sweep(cfg, dry, units_override):
    state = load_state()
    reset_daily(state)
    prune_fps(state, cfg["fps_prune_days"])
    os.makedirs(CURSORS, exist_ok=True)
    err_re = re.compile(cfg["journal_error_re"])
    ng_re = re.compile(cfg["nginx_error_re"])
    ignore_res = [re.compile(rx) for rx in cfg["ignore_res"]]
    all_sent = True
    warnings = []
    analyzed = 0

    sources = [("journal", u) for u in (units_override or unit_list(cfg))]
    sources.append(("journal", "kernel"))

    for kind, name in sources:
        selector = ["-k"] if name == "kernel" else ["-u", name]
        label = "kernel" if name == "kernel" else name
        lines, new_cursor, w = journal_lines(selector, _cursor_path(label),
                                             cfg["window_min"])
        warnings += ["%s: %s" % (label, x) for x in w]
        if lines is None:
            continue
        cands = detect(label, lines, err_re, ignore_res)
        if cands:
            if not process_candidates(label, cands, state, cfg, dry):
                all_sent = False
            analyzed += len(cands)
        if new_cursor and not dry:
            with open(_cursor_path(label), "w") as fh:
                fh.write(new_cursor)

    # nginx error log
    ng_lines, ng_state, w = nginx_lines(cfg, state["nginx"])
    warnings += ["nginx: %s" % x for x in w]
    if ng_lines:
        cands = detect("nginx:error.log", ng_lines, ng_re, ignore_res)
        if cands:
            if not process_candidates("nginx:error.log", cands, state, cfg, dry):
                all_sent = False
            analyzed += len(cands)
    if ng_state != state["nginx"] and not dry:
        state["nginx"] = ng_state

    if not dry:
        save_state(state)

    for w in warnings:
        print("logdoc: warning: %s" % w, file=sys.stderr)
    print("logdoc: sweep done — %d new error kinds, llm calls today %d/%d"
          % (analyzed, state["llm_calls_today"], cfg["max_llm_calls_per_day"]))
    return 0 if all_sent else 1


# --------------------------------------------------------------------- test ---

def self_test(cfg, dry):
    """Full analyse→record→alert path against a synthetic error, without
    touching the journal. Unique per run so the cooldown never blocks it."""
    stamp = now().strftime("%H:%M:%S")
    unit = "logdoc-selftest"
    error_line = ("FATAL: logdoc self-test failure at %s — synthetic drill, "
                  "no action needed" % stamp)
    context = build_context([
        "2026-11-05T%s+00:00 negev logdoc-selftest[1]: Starting self-test" % stamp,
        "2026-11-05T%s+00:00 negev logdoc-selftest[1]: Traceback (most recent call last):" % stamp,
        "  File \"[REDACTED:server-path]\", line 1, in <module> self_test()",
        "Exception: simulated crash for pipeline verification",
        "2026-11-05T%s+00:00 negev logdoc-selftest[1]: %s" % (stamp, error_line),
    ], cfg)
    state = load_state()
    reset_daily(state)
    entry = {"ts": iso(now()), "unit": unit, "fingerprint": fingerprint(unit, error_line),
             "count": 1, "error_line": error_line, "analysis": None, "status": "ok"}
    state["llm_calls_today"] += 1
    try:
        entry["analysis"] = llm_analyze(unit, error_line, context)
    except Exception as exc:  # noqa: BLE001
        entry["status"] = "llm_error"
        entry["error_detail"] = str(exc)[:300]
        print("logdoc: llmproxy call failed: %s" % exc, file=sys.stderr)
    if entry["status"] == "ok" and not dry:
        state["alerts_today"] += 1
    record_analysis(entry, dry)
    if not dry:
        save_state(state)
    return 0 if entry["status"] == "ok" else 1


def main(argv):
    ap = argparse.ArgumentParser(description="logdoc — log error analysis via llmproxy")
    ap.add_argument("--sweep", action="store_true", help="one sweep (what the timer runs)")
    ap.add_argument("--test", action="store_true",
                    help="synthetic error through the full analyse/record/alert path")
    ap.add_argument("--dry-run", action="store_true",
                    help="print instead of writing state or sending")
    ap.add_argument("--units", default="",
                    help="comma-separated unit override (e.g. for a live test unit)")
    args = ap.parse_args(argv)
    cfg = load_config()
    if args.test:
        return self_test(cfg, args.dry_run)
    return sweep(cfg, args.dry_run,
                 [u for u in args.units.split(",") if u] or None)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
