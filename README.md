# logdoc

Automated log analysis. Watches every systemd unit under
`[REDACTED:server-path]` (auto-globbed, so new services are picked up
automatically), the kernel ring buffer and `/var/log/nginx/error.log` for
ERROR/FATAL-class lines, and for each new error kind sends the last 50 lines
of context through [llmproxy](../llmproxy). The reply — what broke, likely
cause, and the fix command — goes to Telegram in real time and into the 11:00
daily digest produced by `status/report.py`.

```
┌─ logdoc-check.timer (5 min) ──► logdoc.py --sweep
│                                  │ journalctl --cursor per unit + kernel
│                                  │ tail /var/log/nginx/error.log by offset
│                                  ▼
│                            match ERROR/FATAL regex, fingerprint, dedup
│                                  │ new kind (or cooldown expired)
│                                  ▼
│                            POST /v1/chat/completions → llmproxy
│                                  │ (key "logdoc" pins provider+model)
│                                  ▼
│                        data/analyses.jsonl + data/digest.json (0644)
│                                  │                    │
│                                  ▼                    ▼
│                        Telegram alert      status/report.py reads it
└──────────────────────────────────────────────────────────────────────────┘
```

## Layout

- `logdoc.py` — the sweeper. `--sweep` (timer), `--test` (synthetic error
  through the full path), `--dry-run`, `--units u1,u2` (override the unit
  list, e.g. for a live test unit).
- `provision.py` — one-time setup run as root: creates the `logdoc` key in
  llmproxy (`provider: nvidia, model: nvidia/nemotron-3.5-lightning-30b-a3b`
  by default), copies the Telegram credentials from `../status/.env`, and
  writes this project's `0600 .env`. Also `--rotate` (new secret) and
  `--setmodel <provider> <model>` (retarget the key's backend).
- `config.json` — regexes, cooldowns, caps. `auto_units` globs
  `[REDACTED:server-path]*.service` each sweep.
- `data/` — runtime state only (gitignored): per-unit journal cursors,
  `state.json` (fingerprints, offsets, daily counters), `analyses.jsonl`,
  `digest.json` (0644 — read by the `status` user for the daily digest).

## Installation

Python 3 standard library only — no venv, no pip.

```bash
git clone <repo-url> logdoc
cd logdoc

sudo python3 provision.py     # one-time: creates the "logdoc" key in llmproxy,
                              # copies Telegram credentials, writes 0600 .env
chmod 600 .env
```

## Running

```bash
python3 logdoc.py --sweep        # one sweep (what the timer runs)
python3 logdoc.py --test         # synthetic error through the full path
python3 logdoc.py --dry-run      # match + fingerprint, no LLM/Telegram side effects
```

Example systemd pair — the service does one sweep and exits; the timer drives
it:

```ini
[Unit]
Description=logdoc sweep
[Service]
User=logdoc
WorkingDirectory=/opt/logdoc
ExecStart=/usr/bin/python3 /opt/logdoc/logdoc.py --sweep

[Timer]
[Install]
```

```ini
[Unit]
Description=logdoc sweep timer
[Timer]
OnCalendar=*:0/5
[Install]
WantedBy=timers.target
```

## Operational notes

- The llmproxy key routes by key: to point logdoc at a different backend,
  change the key's model in the llm.inbox.li admin UI or run
  `sudo python3 provision.py --setmodel <provider> <model>`. No logdoc
  restart needed — the next sweep picks it up.
- Dedup: an error kind is fingerprinted by unit + normalised message, so a
  crash loop produces one analysis per `cooldown_hours` (6) and a rising
  count. Daily caps: 20 LLM calls, 15 Telegram alerts (config.json).
- Log excerpts are redacted (`sk-…`, `Bearer …`, `password=…`, common token
  shapes) before they leave the box toward the upstream provider.
- If llmproxy is unreachable, the raw error is still recorded (status
  `llm_error`) and lands in the digest without an explanation.
- The unit runs as user `logdoc`, member of `systemd-journal` (journal read)
  and `adm` (nginx log read). If journal output suddenly looks restricted,
  check those groups.

## License

MIT — see [LICENSE](LICENSE).
