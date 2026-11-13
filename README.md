# auth-log-hunter

Every internet-facing SSH server is under constant attack. The question that matters is not "how many failed logins" but "did any of them work". auth-log-hunter reads OpenSSH auth logs and separates noise from brute force, password spraying and, most importantly, a successful login after repeated failures from the same address.

**Live demo:** https://jvch0512.github.io/auth-log-hunter/ (a report on a synthetic log)

Perl 5, core modules only, offline.

## Use

```bash
perl bin/auth-log-hunter /var/log/auth.log --year 2026
perl bin/auth-log-hunter auth.log --year 2026 --json
perl bin/auth-log-hunter auth.log --year 2026 --html > report.html
perl bin/auth-log-hunter auth.log --year 2026 --window 3600 --min-failures 20 --fail-on-find
```

Syslog timestamps carry no year, so pass `--year`. See [examples/auth.log](examples/auth.log) and [docs/sample-output.txt](docs/sample-output.txt).

## What it flags

| Kind | Meaning | Severity |
|---|---|---|
| success-after-failures | a login was accepted from an address that had failed repeatedly: treat as a probable compromise | critical |
| brute-force | many failures against few accounts inside the window | medium |
| password-spraying | many distinct usernames, few attempts each, including users that do not exist | medium |

Two or three typos followed by a success are normal and are ignored.

## Limits

- Reads OpenSSH `sshd` lines in syslog format. systemd journal exports (`journalctl -t sshd`) work if saved in the same format. Other services are out of scope.
- It sees addresses, not people: NAT, proxies and shared egress IPs merge users. Geolocation and reputation are deliberately not included, to stay offline.
- A key-based login from an attacker who already holds a key will not show failures. Combine with host and key inventory.

## Where it fits

Incident response triage, MDR and SOC playbooks, hardening reviews ("is anything already inside?"), and a quick-win deliverable in a security assessment.

## Tests

```bash
prove -l t   # 19 checks
```

MIT.
