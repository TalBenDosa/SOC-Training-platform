# Brief: writing a native source module

Repo root: `C:\Users\Talma\OneDrive\שולחן העבודה\claude-work\SOC-qa-fixes` (Next.js + TypeScript, vitest).
Goal: every log the SOC-training platform shows must be in its source's NATIVE format (Tal's rule:
no schema mixing), and detection **use cases** must be writable on those logs.

## Read first
- `docs/log-schemas/README.md` and the card(s) for your sources — the single source of truth for
  field names, nesting, value types and native timestamp formats. Do not use a field a card does not
  document; avoid fields marked UNVERIFIED unless unavoidable (then say so in a code comment).
- `src/lib/logs/native/types.ts` (the contract), `paths.ts`, `validate.ts`, `engine.ts`, `ctx.ts`,
  `testing/corpus.ts`. Do NOT edit these shared files — if the contract needs a change, put it in your
  final report instead.
- `src/lib/sim/types.ts` (TelemetryEvent — the vendor-neutral input).

## Deliverable per source `<id>` (one of the SourceId values)
`src/lib/logs/native/sources/<id>.ts` exporting `const source: NativeSource` (named export `source`)
and `export function kindOf(record: Record<string, unknown>): string | null` (classifies a native
record — used to validate card samples), plus `src/lib/logs/native/sources/<id>.test.ts`.

1. **schema** — kinds you support (cover every event kind your card documents that the platform's
   stories need), with `required` (always present in real records) and `optional` (everything else
   documented), `openPrefixes` only for genuinely free-form sub-objects (e.g. CloudTrail
   `requestParameters`/`responseElements`/`additionalEventData`, Okta `debugContext.debugData`).
   `telemetrySources` = the TelemetryEvent.source values of your category; `vendorMatch` = vendor
   substrings that natively belong to you.
2. **fromTelemetry(ev, ctx)** — build the native record from the TelemetryEvent's structured fields
   (hostname, user/user_email, src/dst ip+port, process{}, file{}, network{}, dns{}, authentication{},
   cloud{}, geo{}, registry{}, severity, mitre_technique, description, event_type) AND from the legacy
   `ev.raw` map (inspect the corpus for your sources: legacy keys like `aws.cloudtrail.eventName`,
   `data.srcip`, `okta.client.ipAddress`, `crowdstrike.CommandLine`, `winlog.event_data.*` hold values
   you must carry over). Rules:
   - Evidence values must survive verbatim: user, host, IPs, ports, command line, hashes, file paths,
     domains, URLs, API/operation names, event ids. A student quotes them in reports.
   - Fill the remaining native fields with realistic, DETERMINISTIC values from `ctx` (ctx.hex /
     ctx.uuid / ctx.int seeded with `ev.id + purpose`; tenant ids from ctx.tenant). Never Math.random,
     never Date.now. Stable per-entity ids (same user → same principalId/accessKeyId/actor.id; same host
     → same aid/agent uuid) must be seeded from the entity (e.g. `${ctx.companyId}:${email}`), not the
     event, so a story correlates across events.
   - Native value types and timestamp formats exactly as the card shows (strings vs numbers, ms vs ns,
     "Z" or not).
   - Text-native sources: `record` = flat object with the vendor's keys; also set `rawLine` (the wire
     line rebuilt from the same values).
   - Category-wide rendering: your module must render events of its category authored for ANOTHER
     vendor too (a CrowdStrike-authored process event rendered as SentinelOne; a Palo Alto-authored
     connection rendered as FortiGate). Return null only when your product truly has no such record
     (e.g. Sophos has no per-event DNS stream) — never fake one.
   - `timeMs` = Date.parse(ev.ts).
3. **useCases** — 4–10 per source (more for rich sources), real SOC detections expressed with the
   engine's `Condition`/`threshold` over YOUR native field paths: e.g. password spray (distinct users
   per IP in 10 min), impossible travel inputs, StopLogging/DeleteTrail, public bucket policy,
   encoded PowerShell from Office parent, LSASS access, new admin role, inbox forwarding to external,
   C2 to newly-registered domain category, RC4 Kerberos service tickets, VPN login from new country…
   Each with `id` = `<id>.<slug>`, title, severity, MITRE ids, a student-facing `description`, a
   `logic` string written the way an analyst would write it for that product (SPL/KQL/LogScale/EQL
   style — label which), and `falsePositives`.

## Tests (`<id>.test.ts`) — must all pass with `npx vitest run src/lib/logs/native/sources/<id>.test.ts`
- Every card sample whose `kindOf()` is a supported kind validates with **zero** violations
  (`validateNative`). Report (in a test comment) any card sample you had to skip and why.
- Every corpus event of your category (`corpusFor(source.schema.telemetrySources)`) → `fromTelemetry`
  returns a NativeLog that validates with zero violations, OR null for a documented reason. Assert
  coverage: ≥ 95 % non-null for events whose vendor natively belongs to you; for cross-vendor events
  assert a sensible floor and print the count.
- Evidence preservation: for converted events, every present evidence value (hostname, user email or
  sAMAccountName, src_ip, dst_ip, process.cmdline, process/file sha256, dns.query, network.domain/url,
  cloud.api_call) appears somewhere in the record (deep string search) when your source has that
  concept. Assert it.
- Determinism: converting the same event twice gives deep-equal output.
- Use cases: each fires (runUseCase) on at least one log built from card samples or converted
  attack-story events (origin "story"), and high/critical use cases fire on < 2 % of converted
  benign/company noise events. Print per-use-case hit counts.

## Rules
- Write only your own files under `src/lib/logs/native/sources/`. No git. Do not touch other files.
- The path contains Hebrew: after writing, `ls` the sources folder with Bash to confirm the files are
  really there (rewrite if missing). Run `npx tsc --noEmit -p .` restricted check: at least make sure
  your files compile (`npx tsc --noEmit -p . 2>&1 | grep native/sources/<id>` must be empty).
- Final report: per source — kinds supported, corpus coverage (native / cross-vendor), use cases
  (count + ids), anything skipped or contract changes you need.
