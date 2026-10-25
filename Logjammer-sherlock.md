# Logjammer — HTB Sherlock Write-up

**Difficulty:** Easy  
**Focus:** Windows Event Log analysis

The logs show earlier activity tied to `CyberJunkie`, but for this write-up I am focusing on the twelve Sherlock questions and the activity on **27 March 2023**. The login identified below should not be treated as the account’s first-ever activity.

## Summary

In this Sherlock, I investigated activity associated with `CyberJunkie` on `DESKTOP-887GK2L`. The relevant events show an interactive login, a SharpHound detection and quarantine, a new outbound firewall rule, an audit-policy change, and a scheduled task. PowerShell also recorded a command to hash the task’s script, followed by an event showing that the firewall log channel was cleared.

I worked through the five event-log files individually, using the username, SID, and timestamps to find the records needed for each question.

## Tools and approach

The evidence consisted of:

- `Security.evtx`
- `System.evtx`
- `Windows Firewall-Firewall.evtx`
- `Windows Defender-Operational.evtx`
- `Powershell-Operational.evtx`

I used `evtx_dump.py`, which uses `python-evtx`, to convert the files to XML:

```bash
python3 evtx_dump.py Security.evtx > Security.xml
```

I repeated this for the other files, then used `awk` to select events and `grep` to inspect fields.

Setting `RS='</Event>'` makes `awk` work on event-sized records instead of individual lines. This lets me match an Event ID and a username or SID within the same event.

The timestamps copied into my notes use `+00:00` or `Z`, so all times below are **UTC**. The fields shown are summaries from my notes, not complete raw XML records.

## Q1. When did CyberJunkie successfully log in?

**Answer:** `27/03/2023 14:37:09 UTC`

I started with `Security.xml` and searched for Event ID **4624**, which records a successful logon, with `CyberJunkie` as the target username.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>4624</ &&
  /<Data Name="TargetUserName">CyberJunkie</
  {print $0 "</Event>"}
' Security.xml
```

After sorting the matching timestamps and inspecting the relevant record, I noted:

```text
TimeCreated: 2023-03-27 14:37:09.879890+00:00
TargetUserName: CyberJunkie
TargetUserSid: S-1-5-21-3393683511-3463148672-371912004-1001
LogonType: 2
```

`LogonType=2` means an **interactive logon**. I kept the SID to use in the next searches.

This answers the question, but earlier activity in the other logs means it is not evidence of the account’s first-ever login.

## Q2–3. What firewall rule was added, and what was its direction?

**Rule name:** `Metasploit C2 Bypass`  
**Direction:** `Outbound`

In `Windows Firewall-Firewall.xml`, I searched for Event ID **2004**, which records a rule addition. I matched `ModifyingUser` against CyberJunkie’s SID and narrowed the search to 27 March.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>2004</ &&
  /<Data Name="ModifyingUser">S-1-5-21-3393683511-3463148672-371912004-1001</ &&
  /<TimeCreated SystemTime="2023-03-27[ T]/
  {print $0 "</Event>"}
' 'Windows Firewall-Firewall.xml'
```

The relevant fields were:

```text
TimeCreated: 2023-03-27 14:44:43.415701+00:00
RuleName: Metasploit C2 Bypass
Direction: 2
```

Microsoft’s firewall direction enumeration identifies `2` as **Outbound**.

The name is suspicious, but the rule alone does not prove that a C2 connection happened.

## Q4. Which audit-policy subcategory changed?

**Answer:** `Other Object Access Events`

I returned to `Security.xml` and searched for Event ID **4719**, which records audit-policy changes.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>4719</
  {print $0 "</Event>"}
' Security.xml
```

The record contained:

```text
TimeCreated: 2023-03-27 14:50:03.721834+00:00
SubjectUserName: DESKTOP-887GK2L$
SubjectLogonId: 0x00000000000003e7
SubcategoryGuid: {0CCE9227-69AE-11D9-BED3-505054503030}
AuditPolicyChanges: %%8449
```

Looking up the GUID identifies **Other Object Access Events**, which includes scheduled-task and COM+ auditing.

`%%8449` means **Success added**. Success auditing was enabled, not disabled. The event records the machine account and SYSTEM logon session rather than directly naming CyberJunkie as the subject.

## Q5–7. What task was created, what file did it reference, and what were its arguments?

**Task:** `HTB-AUTOMATION`  
**File:** `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1`  
**Arguments:** `-A cyberjunkie@hackthebox.eu`

Scheduled-task creation is recorded by Security Event ID **4698**. I filtered for that event and CyberJunkie’s SID.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>4698</ &&
  /<Data Name="SubjectUserSid">S-1-5-21-3393683511-3463148672-371912004-1001</
  {print $0 "</Event>"}
' Security.xml
```

The event gave me all three answers:

```text
TimeCreated: 2023-03-27 14:51:21.481720+00:00
TaskName: \HTB-AUTOMATION
Command: C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1
Arguments: -A cyberjunkie@hackthebox.eu
```

The command and arguments are inside the embedded task XML.

This shows that the task was registered. It does not show that it ran or explain what the script does with the argument.

## Q8–10. What did Defender detect, where was it, and what action did it take?

**Tool:** `SharpHound`  
**Archive path:** `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`  
**Action:** `Quarantine`

In `Windows Defender-Operational.xml`, I searched for:

- **1116:** threat detection.
- **1117:** action taken against the threat.

I used the host and username to match `Detection User`.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>111[67]</ &&
  index($0, "<Data Name=\"Detection User\">DESKTOP-887GK2L\\CyberJunkie</") &&
  /<TimeCreated SystemTime="2023-03-27[ T]/
  {print $0 "</Event>"}
' 'Windows Defender-Operational.xml'
```

My notes contain two closely spaced detection events with these threat names:

```text
HackTool:MSIL/SharpHound.B
HackTool:MSIL/SharpHound!MSR
```

The relevant detection details were:

```text
Detection Time: 2023-03-27T14:42:34.272Z
Detection User: DESKTOP-887GK2L\CyberJunkie
Severity Name: High
Source Name: Downloads and attachments
Archive path: C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip
```

At **14:42:48 UTC**, Event 1117 recorded:

```text
Action Name: Quarantine
```

The detection and action records share the detection time. They show Defender identifying the threat and recording quarantine, but do not establish whether SharpHound had executed.

## Q11. What PowerShell command was recorded?

**Answer:**

```powershell
Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1
```

I searched `Powershell-Operational.xml` for Event ID **4104**, which records script-block content, using CyberJunkie’s SID and the exercise date.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>4104</ &&
  /<Security UserID="S-1-5-21-3393683511-3463148672-371912004-1001"/ &&
  /<TimeCreated SystemTime="2023-03-27[ T]/
  {print $0 "</Event>"}
' 'Powershell-Operational.xml'
```

The relevant record contained:

```text
TimeCreated: 2023-03-27 14:58:33.364769+00:00
ScriptBlockText: Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1
ScriptBlockId: b4fcf72f-abdc-4a84-923f-8e06a758000b
```

This command calculates a file hash; it does **not** execute the script. The record does not include the resulting hash or establish that the command completed successfully.

## Q12. Which event log was cleared?

**Answer:** `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`

I searched `System.xml` for Event ID **104** and CyberJunkie’s SID.

```bash
awk -v RS='</Event>' '
  /<EventID[^>]*>104</ &&
  /<Security UserID="S-1-5-21-3393683511-3463148672-371912004-1001"/
  {print $0 "</Event>"}
' System.xml
```

My notes record **15 matching clear events**, including earlier activity. After reviewing their timestamps, the relevant event at **2023-03-27 15:01:56.515837 UTC** identified the firewall channel.

There are two different channel fields to distinguish:

```text
System/Channel:
System

UserData/LogFileCleared/Channel:
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
```

The first says where the clear notification was recorded. The second says which log channel was cleared.

This shows a channel-clear action, not necessarily deletion of the EVTX file itself.

## A note on log coverage

The earlier clear events are why I avoided calling the Question 1 login the start of all activity. 

The firewall export contains the rule-creation event even though System later records that channel being cleared. Different export times could explain this, for example, if the firewall log was copied before the clear and System afterward. I cannot confirm that from my notes alone.

## Lessons learned

- **Keep the event together.** Matching the Event ID and account within the same record made the searches easier to trust.
- **Use the SID to follow an account across logs.** The username found the login; the SID helped with the firewall rule, task, PowerShell activity, and clears.
- **Look up unfamiliar values.** `Direction=2`, the audit GUID, and `%%8449` needed decoding before I could explain them correctly.
- **Check clears before saying “first.”** The earliest login selected from one file does not necessarily mark the beginning of activity.
- **Separate registration, detection, and execution.** Creating a task, detecting an archive, and hashing a script each show something different.

