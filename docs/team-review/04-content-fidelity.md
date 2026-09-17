# Team-SOC Feed — Content Fidelity & Coherence Review (04)

**Scope:** the shared live-feed the Team-SOC multiplayer exercise reuses from the
single-player engine. The feed payloads come from `companyProfiles.ts` (attack
chains) + `benignEvents.ts` (noise), are normalized in `liveFeed`/`enrichSnapshot`
(`src/app/(app)/team/[id]/page.tsx`) and re-enriched by `enrichEvent`
(`src/app/(app)/dashboard/useLiveEvents.ts`). **Reference incident for the dummy
run:** an admin sign-in to a Domain Controller (`SRV-NXC-DC01`, user `it.admin`)
escalated to Tier-2. Company under test: **NexaCorp**.

**Mode:** REPORT ONLY — no files were edited. Fixes below are precise and ready to apply.

---

## Ranked issues

### 1. HIGH — Split IT-admin identity breaks cross-source entity continuity
- **Files:** `src/app/(app)/dashboard/benignEvents.ts` (AD events use `it-admin`,
  EDR decoys use `it.admin`), `src/lib/sim/companyProfiles.ts` (all 7 admin refs `it-admin`).
- **Offending values:** AD / Windows-Security events use `it-admin@nexacorp.com`
  and `NEXACORP\it-admin` (`b_pwd_04/05/06`, `b_ad_08`, `b_itv_01`, `b_itv_02`;
  67× `it-admin` in benignEvents). Endpoint / EDR false-positive decoys use
  `it.admin@nexacorp.com` / process `user: "it.admin"` (`b_fp_001/003/004/008` …;
  37× `it.admin`). The reference incident (and every dotted user in the estate —
  `c.thornton`, `m.edwards`, `m.torres`) uses the **dotted** form.
- **Why it matters (team drill):** T1 escalates the `it.admin` cert-decode decoy
  (`b_fp_001`); T2 pivots to the DC and finds only `it-admin`, which reads as a
  *different principal*, corrupting scope/attribution. The reference "`it.admin`
  on `SRV-NXC-DC01`" has **no** authored counterpart — every authored DC-admin
  event is `it-admin`. One human admin must be one identity across sources.
- **Correct:** normalize to `it.admin@nexacorp.com` / `NEXACORP\it.admin` /
  `SamAccountName it.admin` everywhere (match the estate's dotted convention and
  the endpoint identity). Global replace `it-admin` → `it.admin` across
  `benignEvents.ts` and `companyProfiles.ts` (both `user_email`, `user.name`,
  `SubjectUserName`, `actor.name`, and prose). Severity: **HIGH** (coherence /
  pedagogically wrong — teaches that a hyphen vs dot is a "different user").

### 2. HIGH — Palo Alto event carries a non-canonical + triple field convention
- **File:** `src/lib/sim/companyProfiles.ts` `nx_d4` (chain D IDS block), plus the
  shared PAN enrichment in `enrichEvent` (`useLiveEvents.ts` ~L684-691).
- **Offending fields:** authored raw uses `pan.threat_id`, `pan.threat_name`,
  `pan.action`, `pan.severity`, `pan.rule`, `pan.app`. `enrichEvent` then *adds*
  `panw.panos.type`, `panw.panos.action`, `panw.panos.source.zone`,
  `panw.panos.destination.zone`, `panw.panos.ruleset`. The field registry's real
  convention is a **third** form: `panw.threatid`, `panw.rule`, `panw.subtype`,
  `panw.category`.
- **Correct (pick one — the registry `panw.*`):** `panw.threatid` (=`40001`),
  `panw.rule` (=`OUTSIDE-IN-BLOCK`), `panw.subtype` (=`vulnerability`),
  `event.action`=`reset-both`, `network.transport`=`tcp`. `pan.threat_id` /
  `pan.threat_name` / `pan.app` are not real PAN-OS/Elastic field names; the
  `panw.panos.*` enrichment adds yet another schema. A T2 opening this log sees up
  to three naming schemes for one firewall event. Severity: **HIGH** (field
  fidelity — mis-vendored/invented + inconsistent). Note: the validator passes
  because `pan.` is an allowlisted *prefix*; only manual review catches this.

### 3. MED — New-InboxRule mislabeled `AzureActiveDirectory` workload
- **Files:** `src/lib/sim/companyProfiles.ts` `nx_a3` (relies on enrichment);
  `enrichEvent` o365 branch (`useLiveEvents.ts` ~L652-663).
- **Offending value:** `nx_a3` is `event_type: "account_modify"` with
  `data.office365.Operation: "New-InboxRule"` and no authored `Workload`.
  `enrichEvent` classifies `account_modify` as `isAzureAD` → sets
  `data.office365.Workload = "AzureActiveDirectory"`, `RecordType = "15"`.
  New-InboxRule is an **Exchange** operation. `nx_b4` (the *same* operation)
  hard-codes `Workload: "Exchange"` — so the two forwarding-rule events in the
  same company disagree on workload.
- **Correct:** `Workload: "Exchange"`, `RecordType: "1"` (ExchangeAdmin). Either
  set it explicitly on `nx_a3`, or make `enrichEvent` route inbox-rule / mailbox
  operations to Exchange. Severity: **MED** (coherence + fidelity).

### 4. MED — 4625 auth-failure aggregate rendered as a single Windows record
- **File:** `src/lib/sim/companyProfiles.ts` `nx_d1`, `nx_d2`.
- **Offending shape:** one `event.code: 4625` record whose description asserts
  "61 network logon failures … across 14 usernames" / "22 accounts, one attempt
  per account". A single 4625 = one failed logon for one `TargetUserName`. No
  `TargetUserName`, no `winlog.computer_name`, and no count field are present.
- **Correct:** either (a) model this as a SIEM correlation/analytic alert
  (`source: "siem"`, a rule name + `event.count`/`distinct_accounts`), or
  (b) keep it a raw 4625 but add `winlog.event_data.TargetUserName`,
  `winlog.computer_name: "SRV-NXC-DC01"`, and drop the aggregate count from a
  per-record log. Severity: **MED** (fidelity/completeness — the "one 4625 = many
  failures" shape is subtly wrong and a T2 quoting it as raw evidence is quoting a
  record that can't exist).

### 5. MED — `enrichEvent` sets `WorkstationName` to the target DC on network logons
- **File:** `enrichEvent` (`useLiveEvents.ts` ~L552-554), triggered on
  `nx_d1`/`nx_d2` (and any DC-hosted `auth_failure`).
- **Offending logic:** `if (event.hostname) WorkstationName = event.hostname`
  → `WorkstationName = "SRV-NXC-DC01"`. In a Type-3 (network) 4625, `WorkstationName`
  is the **source** workstation, and the DC is the `ComputerName`
  (`winlog.computer_name`). Stamping the target DC as the originating workstation
  is wrong and, for a TOR-sourced spray, misleads the analyst about origin.
- **Correct:** only set `WorkstationName` for interactive/local logons, or when a
  distinct source host is known; for network logons from an external IP leave it
  `-` (or the client NetBIOS name) and instead ensure `winlog.computer_name` =
  the DC. Severity: **MED** (shared enrichment → hits the exact reference incident).

### 6. LOW — `data.office365.Parameters` as a flat delimited string
- **File:** `src/lib/sim/companyProfiles.ts` `nx_a3`, `nx_b4`.
- **Offending value:** `"ForwardTo=…; SubjectContainsWords=wire,transfer,payment"`
  as one string. Real O365 UAL `Parameters` is an **array of `{Name, Value}`**
  objects (e.g. `[{"Name":"ForwardTo","Value":"…"},{"Name":"SubjectContainsWords","Value":"wire,transfer,payment"}]`).
- **Correct:** emit the array form (or accept as a deliberate SIEM-flattened
  simplification, but then apply it consistently). Severity: **LOW** (format).

### 7. LOW — Redundant EventID keys on the lockout record
- **File:** `src/lib/sim/companyProfiles.ts` `nx_d3`.
- **Offending value:** carries both `"event.code": "4740"` and
  `"winlog.event_id": "4740"`. The platform standard elsewhere is `event.code`
  only; duplicating the ID in two keys is non-standard.
- **Correct:** keep `event.code` (or `winlog.event_id`), not both. Severity: **LOW**.

### 8. LOW — `enrichEvent` overwrites the authored lockout `SubjectUserName`
- **File:** `enrichEvent` (`useLiveEvents.ts` ~L575-585) vs `nx_d3`.
- **Offending logic:** the `account_lockout` branch assigns
  `SubjectUserName = "SYSTEM"` **without** an "already-set" guard, silently
  replacing the authored `"SRV-NXC-DC01$"` (while leaving `SubjectUserSid`
  `S-1-5-18`). Rendered value ≠ authored value. (Both are defensible for a 4740,
  but the un-guarded overwrite is a latent divergence and inconsistent with every
  other branch, which guards on the key.) Severity: **LOW** (guard the assignment).

---

## What's strong

- **The escalation-report content path is sound.** `escalate()` snapshots the
  *full original* `feed.event` payload (`page.tsx` ~L762-769) carrying
  `hostname` / `user_email` / `src_ip` / `raw`; T2 re-enriches via
  `enrichSnapshot` (~L651-663), which preserves every field and only fills
  defaults for missing `id/ts/source/event_type/severity`. Nothing T2 needs is
  dropped or relabeled, and `DetailPanel` renders the same raw a single-player
  analyst would see. The Shared-Case scope derivation resolves `hostname` /
  `user_email` / `mitre_technique` / `severity` from the escalated event
  correctly.
- **Signal-to-noise is realistic for a drill.** Rule level is derived purely from
  severity for attack *and* noise (`calculateRuleLevel`), and genuine high-severity
  benign decoys (IT-admin certutil/PsExec/encoded-PowerShell FPs) sit in the pool,
  so the attack can't be isolated by "filter level ≥ 8" alone — the team must read
  logs. Per-source ingestion jitter spreads one incident across minutes.
- **NexaCorp chains A–D are otherwise vendor-accurate and causally coherent:**
  phishing→sign-in→inbox-rule→Key Vault exfil (A); CEO BEC with SPF/DKIM/DMARC pass
  and a hidden move-to-RSS rule (B); insider SharePoint→USB→file-share→personal
  Gmail with DLP audit-only (C); TOR spray→wrong-password (accounts exist)→lockout
  →PAN reset (D) — chronology and MITRE mapping are correct.
- **EDR vendor normalization** (`instantiateStory` / `reshapeEdrRaw`) correctly
  reshapes CrowdStrike-authored chains into the target company's EDR schema, so the
  team feed doesn't leak the attack via a foreign `crowdstrike.*` namespace.

---

## Suggested fix order
1 (identity) → 2 (PAN schema) → 3 (Exchange workload) → 5 (WorkstationName) →
4 (4625 aggregate) → 6/7/8 (low-risk cleanups). Re-run `npm run validate:logs`,
`validate:feed`, and `tsc --noEmit` after edits.
