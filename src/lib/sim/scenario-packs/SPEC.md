# Scenario authoring spec

Every rule here exists because an audit found the opposite in shipped content.
Follow it literally.

## Type contract

```ts
import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildXScenario(scenarioId = "<slug>-2026"): ScenarioBundle {
  const B = new Date("2026-..-..T..:..:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const events: TelemetryEvent[] = [ /* ... */ ];
  const iocs: IOC[] = [ /* ... */ ];
  const killchain = [{ ts: T(0), phase: "...", action: "..." }];
  const questions: ScenarioQuestion[] = [ /* ... */ ];
  return {
    scenario_id: scenarioId, title, threat_actor, attack_kind,
    narrative, learning_objectives,
    alerts: eventsToAlerts(events, scenarioId),   // imported from ../scenarios
    events, iocs, killchain, questions,
  };
}
```

`TelemetryEvent` fields: `id, ts, source, vendor, event_type, hostname?, user_email?,
src_ip?, dst_ip?, dst_port?, protocol?, severity, mitre_technique?, description,
process?{name,pid,parent_name,parent_pid,cmdline,user,integrity}, file?{path,name,sha256,size},
network?{url,domain,bytes_in,bytes_out}, raw{}`.

`severity`: `critical | high | medium | low | informational`.
`event_type` must be one of the `EventType` union in `types.ts` — check before using.
`IOC.type`: `ip | domain | url | sha256 | md5 | email | user | host`.

## Hard rules

### 1. The privilege chain must be provable
Never have an actor do something the timeline has not earned. Concretely:
- Dumping LSASS / opening a process with `PROCESS_ALL_ACCESS` needs `integrity: "high"`
  or SYSTEM. If a chain starts at `medium`, you MUST show the escalation as its own event.
- Writing to `ADMIN$` / `C$`, creating a service, or installing PsExec needs local admin
  **on the target**. Show the group membership or the admin logon.
- Creating API tokens, changing Conditional Access, or granting roles needs an admin role.
  Show the role.
- A container escape needs `privileged: true` / `hostPID: true`. Show the securityContext.
- Cloud API calls need a principal with that permission. Show the policy or the assumed role.
- A child process cannot run at higher integrity than its parent without an elevation event.

Ask for every event: *"what in an earlier event makes this possible?"* If nothing, add it.

### 2. Raw logs contain observations, never conclusions
A `raw` block is what the product actually wrote to disk. It must not contain:
- `*.Description` sub-fields explaining the event in prose
- flags naming the technique — `pass_the_hash: true`, `hash_mismatch: true`,
  `threat.category: "PossibleDNSTunnel"`
- anything with the words *indicates*, *suspicious*, *consistent with*, *crackable*,
  *lateral movement*, *unusual*

If you want the student to know it, put it in the event `description` (the platform's
own voice) — not in the evidence.

### 3. No analytics in raw fields
A sensor records one action. Derived aggregates belong in the `description` or an
explicit correlation/SIEM event, never in a device log:
- BAD in a Sysmon/EDR record: `beacon.interval_seconds`, `baseline.files_per_day`,
  `files.encryption_rate_per_sec`, `vss.copies_deleted`, `AccessCount: 312`,
  `loginFailureCount: 47`, `BaselineDeviationFactor: 650`, `estimated_bytes_exfiltrated`
- Vendors that write one record per action (CloudTrail, O365 UAL, Okta) must not carry
  counts. Emit a representative record; put the total in a separate correlation alert.

### 4. Invented mechanics are forbidden
No `ml.score: 74` / `av.quarantine_threshold: 80` — no EDR exposes a 0-100 score with a
numeric threshold in its logs. Use real outcome fields (`action_result`,
`quarantine.status`, `policy.name`, `RemediationAction`).
Use real field names for the declared vendor. If unsure, use fewer fields, not invented ones.

### 5. Facts must be correct
- RID 500 is the **built-in Administrator**. Named accounts get their own RID (1100+).
- NTLM network logon: `LogonProcessName: "NtLmSsp"`, `AuthenticationPackageName: "NTLM"`.
  Interactive console is LogonType 2 (`User32`); network is 3; RDP is 10; service is 5.
- A logon from another host over the network can never be LogonType 2.
- Event IDs: 4624 logon, 4625 failed, 4672 special privileges, 4688 process, 4768 TGT,
  4769 TGS, 4662 object access, 1102 log cleared.
- Kerberoasting = **4769 TGS** for an account **with an SPN**, RC4 `0x17` → T1558.003.
  A 4768 TGT with a stolen hash is overpass-the-hash → T1550.002. They are not the same.
- AS-REP roasting = pre-auth disabled (`PreAuthType: "0"`, UAC bit 4194304) → T1558.004.
- Base32 max entropy is 5.0 bits/char; base64 is 6.0. Do not exceed.
- A DNS name is ≤255 bytes, a label ≤63 — cap per-query exfil accordingly.
- Check the weekday of your base date before writing "on a Tuesday".
- Windows concepts (integrity levels, DLLs, Authenticode) do not apply to Linux hosts.
- One SHA256 = one file. Never reuse a hash across different files or as a process image
  hash for a signed system binary.
- Verify arithmetic: counts, rates, durations and byte totals must agree across events.

### 6. Chronology
Declare events in the order they happen. If a tool intercepts traffic, the tool starts
first. A process referenced as a parent must have its own creation event.

### 7. IOC hygiene
`tags` are evidence labels, not answers. `["c2", "external"]` yes; `["llmnr-poisoning",
"asrep-roasting-tool"]` no. Only use `type: "sha256"` for actual files — not API tokens,
Kerberos hashes or cloud credentials.

### 8. Questions
- 4–5 questions. **Every `learning_objectives` entry must be assessed by one.**
- All options within a question must be **similar length**. The correct answer being 3×
  longer than every distractor lets students score without reading.
- Distractors must be plausible and wrong for a *reason a student could articulate*.
- No deprecated ATT&CK IDs anywhere, including distractors (T1076, T1086, T1064, T1035).
- The `explanation` should teach why the wrong answers are wrong, not just restate the right one.
- Include at least one question that requires correlating **two** events.

### 9. Benign scenarios
If the scenario's correct verdict is *not malicious*, set `attack_kind: "false_positive"`.
The grader keys the expected verdict off this exact string. A benign scenario must still
look genuinely alarming — the lesson is the discriminating evidence, which must be present
and findable, not absent.

## Realism sources
Use real vendor field names. Windows → `winlog.event_data.*` + `event.code`.
Sysmon → `winlog.provider_name: "Microsoft-Windows-Sysmon"`, Event 1/3/11/13/22.
CrowdStrike → `crowdstrike.*` / `cs.*`. MDE → `DeviceProcessEvents` columns
(`DeviceName`, `ActionType`, `ProcessCommandLine`, `InitiatingProcessFileName`).
O365 → `data.office365.*` with real `Operation` values. Okta → `data.okta.*` /
`eventType`. AWS → `aws.cloudtrail.*` (one record per API call).
PAN-OS → `pan.*`. FortiGate → `data.*`. Linux → auditd / sshd syslog fields.

Vendor strings must already exist in `scripts/vendor-normalization-map.json`, or CI fails.
