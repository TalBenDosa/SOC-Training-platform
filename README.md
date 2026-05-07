# HACK THE SOC

Enterprise-grade SOC analyst training platform. Learn to triage, hunt, investigate,
and detect — against a synthetic enterprise that breathes like the real thing.

> Inspired by **CrowdStrike Falcon · Microsoft Sentinel · Splunk · Elastic Security · IBM QRadar · Wazuh.**
> All telemetry is synthetic. Not a replacement for production SOC tooling.

---

## What's inside

- **SOC Dashboard** — live alert feed, KPIs, top hosts/users, MITRE coverage, source breakdown.
- **Alerts / SIEM** — vendor-accurate alerts (CrowdStrike CRWD-, Sentinel MDE-, Palo Alto PAN-, Okta, AWS), filterable queue with drilldown.
- **Investigations** — timelines, IOC linkage, killchain, analyst notes, AI suggestions.
- **Threat Hunting** — KQL / SPL / Sigma editor, hypothesis-driven hunts.
- **Detection Engineering Lab** — author Sigma, validate, deploy, track TP/FP.
- **Attack Scenarios** — end-to-end simulations (phishing → cloud exfil, BEC mailbox rule, more).
- **MITRE ATT&CK Heatmap** — coverage view across tactics & techniques.
- **Learning Paths** — SOC Analyst, Threat Hunter, IR, Detection Engineer, Purple Team.
- **Gamification** — XP, levels, ranks, badges, streaks, global leaderboard.
- **AI Co-Analyst** — Claude-powered, grounded in your scenario context.
- **Admin Panel** — users, content, platform settings, audit log.
- **IOC Database** — every extracted indicator across runs, searchable.
- **Live Telemetry** — raw EDR / Sysmon / FW / DNS / O365 / Okta / CloudTrail event stream.

## Stack

- **Frontend**: Next.js 14 (App Router) · React 18 · TypeScript · TailwindCSS · Lucide · framer-motion · recharts
- **Backend**: Next.js Route Handlers · Supabase (Postgres + Auth + RLS)
- **AI**: Claude (Anthropic SDK) with prompt caching on the system prompt + scenario context
- **Realism layer**: deterministic seeded RNG generates vendor-accurate alerts and process trees from MITRE ATT&CK techniques

## Repo layout

```
src/
  app/
    page.tsx                       Landing
    login/                         Auth
    (app)/                         Authenticated app shell
      dashboard/                   SOC dashboard
      alerts/[id]/                 Alert queue + detail
      investigations/[id]/         IR workspace + timeline
      hunts/                       Threat hunting
      detections/                  Detection engineering lab
      scenarios/[slug]/            Attack simulations
      mitre/                       ATT&CK heatmap
      telemetry/                   Live event stream
      learn/                       Learning paths
      leaderboard/                 Global leaderboard
      iocs/                        IOC database
      playbooks/                   IR playbooks
      admin/                       Admin panel
      ai/                          AI Co-Analyst chat
    api/
      alerts/    scenarios/    telemetry/    mitre/
      ai/        leaderboard/   health/
  components/
    Logo.tsx
    nav/{Sidebar, Topbar}.tsx
    ui/{Button, Card, Badge, Input}.tsx
  lib/
    mitre/attack.ts                Curated ATT&CK tactics & techniques
    sim/
      rng.ts                       Mulberry32 seeded PRNG
      identities.ts                Synthetic enterprise (Cryotech)
      iocs.ts                      Domains, IPs, hashes, URLs
      generators.ts                Per-source telemetry generators
      scenarios.ts                 End-to-end attack stories
      types.ts
    supabase/{client,server}.ts
    utils.ts
supabase/
  migrations/0001_init.sql         Full schema with RLS
  seeds/0001_content.sql           Paths, scenarios, badges
scripts/seed.ts
```

## Getting started

```bash
# 1) Install
npm install

# 2) Configure env
cp .env.example .env.local
# Fill in:
#   NEXT_PUBLIC_SUPABASE_URL
#   NEXT_PUBLIC_SUPABASE_ANON_KEY
#   SUPABASE_SERVICE_ROLE_KEY  (server only)
#   ANTHROPIC_API_KEY          (optional — AI co-analyst)

# 3) Apply schema
psql "$DATABASE_URL" -f supabase/migrations/0001_init.sql
psql "$DATABASE_URL" -f supabase/seeds/0001_content.sql
# or:  npm run seed

# 4) Run
npm run dev
# open http://localhost:3000
```

## Database schema (highlights)

- `profiles` — analyst identity, XP, level, rank, streak (auto-managed by trigger)
- `learning_paths` / `modules` / `lessons` / `lesson_progress`
- `scenarios` / `scenario_runs` — attack simulations and per-user runs
- `alerts` — SIEM-style alerts with source, vendor, severity, MITRE mapping, entities, raw JSON
- `telemetry_events` — normalized events from EDR / Sysmon / FW / DNS / O365 / Okta / CloudTrail
- `investigations` / `investigation_notes` — IR workflow with verdict, timeline, IOCs
- `hunts` — saved threat hunting queries with findings
- `detections` — Sigma/KQL/SPL rules with TP/FP tracking
- `badges` / `user_badges` / `xp_events` — gamification
- `ai_conversations` / `ai_messages` — AI co-analyst transcripts
- `audit_log` — admin actions

Full row-level security: every analyst sees only their own runs, alerts, telemetry, investigations, and hunts.

## How realism works

Each scenario in `src/lib/sim/scenarios.ts` calls per-source generators in
`src/lib/sim/generators.ts` to produce coherent, MITRE-mapped telemetry:

- **EDR / Sysmon** — process tree (parent → child), command line, SHA256, integrity level, Sysmon Event IDs (1, 10, 11, 13)
- **Firewall** — src/dst, ports, protocol, action, rule name, bytes in/out
- **DNS** — query name, type, rcode, response size (tunneling = high-entropy + TXT)
- **Active Directory** — 4624/4625/4768 with logon types and failure reasons
- **Okta** — system log entries with client geo, MFA result, user agent
- **AWS CloudTrail** — eventName, eventSource, requestParameters, additionalEventData
- **Microsoft 365 UAL** — sender/recipient, SPF/DKIM/DMARC, attachment hash, inbox rule operations

The output of `eventsToAlerts()` mirrors the look of CrowdStrike Falcon, Microsoft
Defender, and Splunk Enterprise Security alert objects — same shape, fake values.

## Roadmap

- More scenarios: ransomware, OAuth consent phishing, supply chain compromise, insider data theft
- Real-time replay (clock-driven event playback)
- Sigma → KQL/SPL backend conversion in-app
- Team mode (war-room collaboration on a shared investigation)
- LLM grading of free-text answers (already wired for the API)
- Read-only "executive dashboard" mode for management demos

## License

Internal use. All synthetic content is for training only.
