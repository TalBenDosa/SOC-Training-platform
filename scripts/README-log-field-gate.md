# Vendor log-field CI gate

## Why

Every `raw: { ... }` block in the content data is a claim: *"this is what &lt;vendor&gt; actually emits."*
Five independent expert reviews found that claim false often enough to be the platform's largest
credibility risk — `crowdstrike.Confidence`, `s1.extensionAdded`, and `RequestorName` (on Event 4769)
do not exist in the named products, and in several cases a **graded answer depended on one**.

A student who memorises a field that isn't real arrives at their first Falcon or Sentinel console
and discovers the course lied to them.

## Usage

```bash
npm run validate:logs            # report + exit 1 on NEW violations   (runs in CI)
npm run validate:logs:baseline   # re-baseline after a cleanup pass
npm run validate:logs:vendors    # list declared vendors with no registry entry
node scripts/validate-log-fields.mjs --json   # machine-readable
```

`LOG_FIELD_REGISTRY=/path/to.json` points the gate at an alternate registry (used when iterating
on the registry itself).

## How it works

1. Parses the real **TypeScript AST** (not regex) across `src/data`, `src/lib/sim`,
   `src/app/(app)/dashboard` — currently **78 files, 1,070 raw blocks, 13,665 fields**.
2. For each `raw` block, resolves the sibling `vendor:` string through an alias table
   (exact match, then longest-containment fallback, so `FortiGate 100F` → `fortigate`).
3. Checks each field against `log-field-registry.json` — `commonFields`, the vendor's
   `exactFields`, and its `prefixes`.
4. Violations already present when the baseline was taken are ignored; **new ones fail the build**.

Proven not to be a no-op: a fixture declaring `vendor: "Check Point NGFW"` with an invented
`TotallyInventedThreatScore` field produces `FAIL` / exit 1; removing it returns `PASS` / exit 0.

## Current state — read this before trusting a PASS

The gate's **harness is correct**; its **registry coverage is not yet good enough to enforce
broadly**. Baseline: **2,920 accepted violations** (8,030 field occurrences).

That baseline is **not** an accuracy claim. It contains both genuine defects (`RequestorName`,
`FailureCount`, `AlertThreshold`, `FailuresPerMinute` …) and a large number of **false positives**
from registry gaps. Do not read a baselined field as "verified".

### Root cause of the gap

The 15 field-reference documents the registry was generated from are written in **abstract
ECS-style taxonomy** (`account.name`, `destination.ip`, `alert.category`) — a map of what fields
exist *conceptually*. The codebase uses **vendor-native naming** (`winlog.event_data.TargetUserName`,
`DeviceName`, `ActionType`, `okta.event_type`). Two different vocabularies, so the registry
cannot recognise legitimate fields.

Measured recognition rate per vendor (fields recognised / total, vendors with ≥40 fields):

| Coverage | Vendors |
|---|---|
| 50–71% | crowdstrike-falcon (inflated by the `crowdstrike.` prefix), aws-waf, fortigate, cloudflare-waf, microsoft-purview-dlp |
| 25–49% | azure-ad, microsoft-365, palo-alto-ngfw, check-point-ngfw, microsoft-defender-office365, cisco-firepower, microsoft-active-directory, sentinelone, aws-cloudtrail |
| < 25% | sysmon, microsoft-defender-endpoint, kubernetes-audit, azure-monitor, cisco-anyconnect, microsoft-sentinel, okta, corelight-zeek, microsoft-graph-security (0%) |

**No vendor exceeds 71%.** Enforcing without a baseline today produces ~8,000 false positives.

### Known-weak registry entries

Four vendors have **no backing reference document** — their `exactFields` were borrowed from the
closest generic category set, so real logs for them will fail:
`Zscaler`, `Corelight (Zeek)`, `Google Workspace Audit`, `GitHub Audit Log`.
Weakly backed: `Microsoft Defender for Office 365`, `Cisco AnyConnect`.

## Vendor normalisation — DONE

The corpus used **117 distinct `vendor:` strings for 59 real products**. Because the gate keys
off `vendor`, most events resolved to nothing and went unvalidated. Two codemods fixed this:

```bash
npm run normalize:vendors          # dry run   (CI runs this — exits 1 on any unmapped string)
npm run normalize:vendors:write    # apply
npm run backfill:vendors           # infer `vendor` for blocks that declare none
```

- `scripts/vendor-normalization-map.json` — controlled vocabulary, **117 → 59**. Canonical names
  are human-readable because `vendor` is shown in the raw-log view. The map is *self-closed*
  (every canonical value is also a key), so the codemod is idempotent.
- Five ambiguous strings were resolved **by inspecting the raw fields, not the label** —
  e.g. `"Sysmon + DNS Server"` is pure Sysmon (`provider_name: Microsoft-Windows-Sysmon`, no DNS
  Server log present), and `"AbuseIPDB / SIEM Correlation"` is really the Wazuh decoder schema.
  These are recorded in the map's `ambiguousResolvedByInspection` block.
- `backfill-missing-vendors.mjs` filled 15 blocks whose raw fields identify a product
  unambiguously, and **deliberately left the rest alone**.

**Result: 971 of 1,070 raw blocks (91%) are now attributable to a schema**, up from a small
fraction. Unresolved vendor *names* dropped from 116 to 12.

CI now runs `normalize:vendors`, which exits 1 on any `vendor:` string missing from the map —
so new content cannot reintroduce the drift.

## Remaining blind spots

- **30 raw blocks still have no `vendor`, and cannot be given one.** They use generic normalised
  field names (`action`, `protocol`, `src_ip`, `dst_port`) and are **not modelled on any real
  product**. Labelling them would fabricate a schema claim — the exact defect this gate exists to
  catch. They need rewriting against a real vendor schema. This is content work, not tooling work.
- **12 vendors have no registry entry** (63 blocks): `Linux auditd` (34 — the big one),
  `Windows DNS Server`, `Windows TerminalServices`, `Windows DHCP Server`, `Squid Proxy`,
  `Proofpoint`, `Infoblox DNS`, `AWS CloudWatch`, `AWS Cost Anomaly Detection`, `Wazuh`,
  `ServiceNow ITSM`, `Epiq EMR Audit Log`. Reported, not validated.
- **`source` is not a usable fallback.** It is a category enum (`edr`, `ad`, `firewall`) —
  `"edr"` could be CrowdStrike, SentinelOne or MDE with completely different schemas.
- Some generators compute `vendor` at runtime
  (`vendor: world.meta.emailStack === "gsuite" ? … : …`), so static analysis sees `<computed>`
  and treats the block as attributed but unvalidatable.

## To make this gate authoritative

1. **Normalise `vendor`** across the corpus to a controlled list; add `vendor` to the 50 blocks
   that lack one. This is the prerequisite for everything else.
2. **Rebuild the registry from vendor-native documentation** — Winlogbeat `winlog.*`, MDE Advanced
   Hunting column names, Okta System Log, PAN-OS, AWS CloudTrail — rather than from the ECS
   taxonomy docs. Cite a source per vendor.
3. Re-baseline. The baseline should **shrink** on every pass; never grow it.
4. Consider failing on vendorless blocks once step 1 is done.

Until then the gate delivers one real thing: **new content cannot introduce an invented field
for a vendor the registry does cover.** That is worth having on day one, but it is not yet a
guarantee that existing logs are accurate.
