Incident Report
Incident 1: SSH Brute-Force Attack
Field	Details
Date/Time	November 1, 2026, 05:12-05:24 AM (local)
Source	127.0.0.1 (localhost, simulated attacker)
Target	SSH service on host attacker, accounts wronguser (nonexistent) and attacker (valid)
Detected by	Splunk alert: SSH Brute Force - Burst Detection
Severity	High

Timeline

05:12-05:14 - Manual brute-force simulation: 12 failed SSH login attempts (9 against the nonexistent wronguser, 3 against the valid attacker account), roughly 10-60 seconds apart.
05:23:40 - Automated brute-force attack launched with Hydra against the attacker account: 10 failed login attempts within a single 10-second window, from 10 parallel connections (distinct source ports).
05:35:01 UTC - Scheduled Splunk alert fired, flagging the burst of failed logins from 127.0.0.1.
No successful login resulted from either attack; the real password was never guessed by the wordlist used.

Evidence

index=main sourcetype=linux_secure process=sshd "Failed password" - 32 total failed attempts from one source IP over the test window.
Burst-detection query grouping failures into 10-second windows: one window with 10 failed attempts from 127.0.0.1.
Triggered Alerts: entry at 05:35:01 UTC for SSH Brute Force - Burst Detection.
Dashboard panel “Failed vs Successful Logins Over Time” showing two distinct failure spikes against a flat baseline.

Analysis
The manual test produced a slow, irregular pattern of failures, typical of a human or a simple script. The Hydra run produced a dense burst in under a second, a timing signature that distinguishes automated tooling from manual attempts and is what the burst-detection search was built to catch. Neither attack achieved a successful login, so this incident reflects detection working as intended rather than a successful compromise.

Recommended Response

Block the source IP at the firewall after repeated failures.
Disable SSH password authentication in favor of key-based login.
Install fail2ban to automatically block an IP after a threshold of failures.
Reduce or eliminate the time a brute-force tool has by rate-limiting new connections (sshd MaxStartups).
Incident 2: Unauthorized Privilege Escalation (Simulated)
Field	Details
Date/Time	November 1, 2026, 06:30-06:31 AM (local)
Account	testuser
Action	New local account created, then added to the sudo group
Detected by	Splunk search / alert: Privilege Escalation - User Added to Sudo Group
Severity	High

Timeline

06:30:32 - Account testuser created (useradd).
06:30:41 - A duplicate useradd attempt for the same username failed and rolled back, confirmed as expected behavior, not account tampering.
06:31:25 - testuser added to both the sudo group and the shadow sudo group via usermod -aG sudo.

Evidence

index=main sourcetype=linux_secure process=usermod "'sudo'" - two log lines recording the group addition.
Verified against live system state with id testuser and groups testuser, confirming testuser is a real member of sudo (not just a log entry).

Analysis
An account gaining sudo membership is one of the clearest signs of privilege escalation, since it converts a standard account into one capable of full administrative control. In a real incident, this step typically follows an initial compromise (such as a successful brute-force login) and precedes further malicious activity. Correlating this detection with Incident 1 is a natural next step for a SOC analyst: did the same account that escalated also appear in failed-login activity shortly before?

Recommended Response

Alert immediately on any sudo/wheel group modification, especially outside change-management windows.
Require approval workflows for group changes on privileged groups.
Regularly audit sudo group membership against an expected baseline.
MITRE ATT&CK Mapping
Detection	Technique
SSH brute force (burst)	T1110.001 Brute Force: Password Guessing
Valid account login attempts	T1078 Valid Accounts
Account created	T1136.001 Create Account: Local Account
Added to sudo group	T1098.003 / T1548.003 Account Manipulation / Abuse Elevation Control Mechanism: Sudo and Sudo Caching
