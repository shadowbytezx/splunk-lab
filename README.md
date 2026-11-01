# SSH Brute-Force and Privilege Escalation Detection with Splunk

A beginner SOC project: using Splunk Enterprise to collect Linux authentication logs, detect SSH brute-force attacks and privilege escalation, build alerts and a dashboard, and document the investigation.

## Objectives

- Ingest Linux authentication logs (`/var/log/auth.log`) into Splunk
- Establish a baseline of normal login and sudo activity
- Simulate a manual and an automated (Hydra) SSH brute-force attack
- Simulate a privilege-escalation attack (new user added to `sudo`)
- Build SPL detections, scheduled alerts, and a monitoring dashboard
- Document both incidents and map them to MITRE ATT&CK

## Lab Environment

| Component | Details |
|---|---|
| Log source / Splunk server | Ubuntu VM, hostname `attacker` |
| SIEM | Splunk Enterprise |
| Log file | `/var/log/auth.log` |
| Sourcetype | `linux_secure` |
| Index | `main` |
| Attack tools | OpenSSH client (manual), THC-Hydra (automated) |

## 1. Data Ingestion

Added `/var/log/auth.log` as a monitored file via **Add Data → Monitor → Files & Directories**, sourcetype `linux_secure`, host `attacker`.

![Data ingested](screenshots/01-data-ingested.png)

**Result:** 160 events indexed.

### Issue encountered: "Path is not readable"

Splunk couldn't read the file because it's owned by `syslog:adm` (mode `640`) and Splunk runs as the `splunk` user.

![Permission error](screenshots/02-permission-error.png)

**Fix:**
```bash
sudo usermod -aG adm splunk
sudo -u splunk /opt/splunk/bin/splunk restart
```
Adding `splunk` to the `adm` group grants read access without loosening file permissions. A restart is required because running processes don't pick up new group membership automatically.

## 2. Baseline: Normal Activity

```spl
index=main sourcetype=linux_secure | stats count by process
```

![Events by process](screenshots/03-events-by-process.png)

| Process | Events | Meaning |
|---|---|---|
| sudo | 85 | Commands run with elevated privileges |
| systemd-logind | 26 | Login session tracking |
| useradd | 17 | Account creation |
| sshd | 16 | SSH server activity |
| login | 4 | Console logins |
| systemd | 4 | Service/session activity |
| groupadd | 3 | Group creation |
| CRON | 2 | Scheduled jobs |
| usermod | 2 | Account modification |
| passwd | 1 | Password change |

### SSH baseline (before any attack)

```spl
index=main sourcetype=linux_secure process=sshd | sort _time | table _time, _raw
```

![SSH baseline](screenshots/04-ssh-baseline.png)

Before any attack was simulated: 3 successful password logins (all from the same source), 4 sshd startups, 1 host-key rejection on first connection, 0 failed logins. This is the normal pattern — anything outside it is worth investigating.

## 3. Attack Simulations

> All attacks were run only against my own lab VM.

- Manual failed SSH logins against a nonexistent user (`wronguser`) and a valid user (`attacker`)
- Automated brute-force attack using Hydra against the `attacker` account
- New local account created and added to the `sudo` group

Full timeline and evidence for both attacks: **[INCIDENT_REPORT.md](INCIDENT_REPORT.md)**

## 4. Detections

### 4.1 SSH brute force (burst detection)

Groups failed logins into 10-second windows to separate automated bursts from manual attempts, and correctly handles syslog's "message repeated N times" line collapsing:

```spl
index=main sourcetype=linux_secure process=sshd "Failed password"
| rex "message repeated (?<repeat>\d+) times"
| eval attempts=coalesce(tonumber(repeat), 1)
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bin _time span=10s
| stats sum(attempts) as failed_attempts by _time, src_ip
| where failed_attempts > 5
```

![Brute force burst detection](screenshots/05-bruteforce-burst.png)

Result: one 10-second window with 10 failed attempts from a single source — the Hydra run. The manual test never exceeded 1-2 failures per window, so it doesn't trigger this rule, by design.

### 4.2 Privilege escalation (user added to sudo)

```spl
index=main sourcetype=linux_secure process=usermod "'sudo'"
```

![Privilege escalation detection](screenshots/08-privesc-detection.png)

Result: two log lines recording `testuser` being added to the `sudo` group and the shadow `sudo` group.

## 5. Alerts

| Alert | Condition | Schedule |
|---|---|---|
| SSH Brute Force - Burst Detection | More than 5 failed logins from one IP in a 10-second window | Every 5 minutes (`*/5 * * * *`) |
| Privilege Escalation - User Added to Sudo Group | Any `usermod ... sudo` event | Every 5 minutes (`*/5 * * * *`) |

The brute-force alert fired on schedule:

![Alert triggered](screenshots/06-alert-triggered.png)

## 6. Dashboard

**Linux Auth Monitoring** — 4 panels:

![Dashboard](screenshots/07-dashboard-full.png)

1. **Failed vs Successful Logins Over Time** — line chart, both attack spikes clearly visible against a flat baseline

   ![Panel 1](screenshots/dashboard-panel1-logins.png)

2. **Top Source IPs - Failed Logins** — bar chart, 32 total failed attempts from the test source

   ![Panel 2](screenshots/dashboard-panel2-topips.png)

3. **Sudo Command Audit** — table of every privileged command run on the box

   ![Panel 3](screenshots/dashboard-panel3-sudoaudit.png)

4. **Privilege Escalation - Sudo Group Changes** — table of `sudo` group membership changes

   (see screenshot 08-privesc-detection.png above)

## 7. Incident Reports

Full write-ups with timelines, evidence, analysis, and recommended response: **[INCIDENT_REPORT.md](INCIDENT_REPORT.md)**

## 8. MITRE ATT&CK Mapping

| Detection | Technique |
|---|---|
| SSH brute force (burst) | T1110.001 Brute Force: Password Guessing |
| Valid account login attempts | T1078 Valid Accounts |
| Account created | T1136.001 Create Account: Local Account |
| Added to sudo group | T1098.003 / T1548.003 Account Manipulation / Abuse Elevation Control Mechanism: Sudo and Sudo Caching |

## Lessons Learned

- Splunk needs OS-level read access to log files; a permissions problem only surfaces as "Path is not readable," with no further detail
- syslog collapses repeated identical lines ("message repeated N times"), which detection logic has to account for or it will undercount attacks
- Automated attacks (Hydra) have a distinct timing signature — many failures in under a second — that manual attempts don't, which is what the burst-detection window is built to catch
- Establishing a baseline before simulating attacks makes anomalies easy to recognize
- Everything run with `sudo`, including routine setup commands, appears in the audit log

## Tools

Splunk Enterprise, Ubuntu (VirtualBox), OpenSSH, THC-Hydra
