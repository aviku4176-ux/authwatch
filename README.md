# AuthWatch v2

IDS-style brute-force / credential-stuffing detector for systems you
administer. Pure Python stdlib — no dependencies. Reads SSH, PAM, Dovecot,
Postfix, web access logs, and SIEM-style JSON events; flags suspicious
patterns with sliding-window rules; emits human-readable, JSON-lines, or CEF
(SIEM) alerts; optional syslog/webhook delivery and ban commands.

## Quick start

```bash
# One-shot analysis
python authwatch.py --logfile /var/log/auth.log

# Live monitoring
python authwatch.py --logfile /var/log/auth.log --tail

# Pipe a stream
tail -F /var/log/auth.log | python authwatch.py --format ssh

# Nginx/Apache access log
python authwatch.py --logfile /var/log/nginx/access.log --format http

# SIEM-style JSON events -> CEF
python authwatch.py --logfile events.jsonl --format json --cef

# With config file
python authwatch.py --config authwatch.ini --logfile /var/log/auth.log
```

## Log sources

| Format | Example lines |
| --- | --- |
| `ssh` | `sshd` Failed password / Invalid user / Accepted / max-auth lockout |
| `pam` | `pam_unix(...)` authentication failure with rhost/user |
| `dovecot` | POP3/IMAP auth failed with rip= |
| `postfix` | SMTP SASL authentication failed with unknown[ip] |
| `http` | Apache/Nginx combined log; 401/403 login paths, 404 recon |
| `json` | JSONL with ts, src_ip, user, kind, service, status |

Auto-detects per line with `--format auto` (default).

## Rules (defaults)

| Rule | Trigger | Severity |
| --- | --- | --- |
| `ssh_bruteforce` | >=5 failed SSH logins per IP in 300s | high |
| `auth_bruteforce` | same, for non-SSH auth services (PAM, Dovecot, Postfix) | high |
| `auth_bruteforce_escalated` | >=3x the fail threshold (sustained attack) | critical |
| `credential_stuffing` | >=10 denied auth requests per IP | high |
| `username_spray` | >=5 distinct usernames from one IP | medium |
| `password_spray` | one username seen from >=5 IPs | high |
| `focused_account_attack` | >=3 failures on a `--focus-users` account | high |
| `success_after_bruteforce` | >=3 failures then success from same IP | critical |
| `persistent_attacker` | >=6 detection windows touched (slow, low-and-slow) | high |
| `multi_vector_attack` | same IP attacking >=2 services | critical |
| `scanner_recon` | >=30 404s per IP (path enumeration) | medium |
| `account_lockout` | max-auth lockout event | critical |
| `denylisted_ip` | any event from a denylisted IP/CIDR | critical |

All thresholds/window configurable. One alert per rule per IP per window
bucket prevents floods.

## Allow / deny / focus

```bash
python authwatch.py --logfile auth.log \
  --allowlist 10.0.0.0/8,192.168.0.0/16,127.0.0.1 \
  --denylist 203.0.113.0/24 \
  --focus-users admin,root
```

## Output and delivery

- Default human-readable; `--json` JSON-lines; `--cef` CEF.
- `--alert-file FILE` appends JSON-lines alerts.
- `--syslog-host HOST [--syslog-port 514]` UDP-syslog to a SIEM collector.
- `--webhook-url URL` POSTs JSON alerts (e.g. Slack/Teams bridge).

## Bans and state

```bash
# Dry-run ban commands
python authwatch.py --logfile /var/log/auth.log \
  --ban-cmd "iptables -A INPUT -s {ip} -j DROP"

# Execute them (template supports {ip} and {user})
python authwatch.py --logfile /var/log/auth.log \
  --ban-cmd "iptables -A INPUT -s {ip} -j DROP" --ban

# Persist per-IP attacker state across restarts
python authwatch.py --logfile /var/log/auth.log \
  --state-file /var/lib/authwatch/state.json
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Notes

- Run only on systems you own or administer.
- Pairs with `sweepclean` (IR scanner) for cleanup workflows.