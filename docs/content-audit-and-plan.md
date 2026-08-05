# Content Audit & Improvement Plan — HACK THE SOC

**Date:** 2026-08-05 · **Method:** 5 parallel expert audits (content credibility, pedagogy, engagement/visuals, reports mechanism, image-support tech) + a hands-on SOC-analyst log-analysis pass over the platform's real telemetry. Read-only audits; fixes applied separately (§4).

---

## 0. Verdict

The platform is **genuinely production-grade — content credibility 8/10**, with real MITRE-mapped telemetry, authentic vendor field names, and a **mastery-gated Rooms system** that is exemplary. The gaps are **not** content quality — they are (a) a handful of point factual errors, (b) two real scoring bugs in the reports mechanism, and (c) a structural disconnect: the excellent Rooms system's mastery gating does **not** carry into the three "exit" surfaces (Learning-Path nav, Scenarios, live Dashboard), and the built-in visual/diagram capability is dramatically **under-used**.

---

## 1. Current state (inventory)

- **Rooms:** ~62–85 rooms across 26 batches, 14 categories, beginner→advanced. ~850+ tasks: 362 reading, 288 question, 108 log_analysis, 78 flag, 42 analyst_choice, 35 matching, 27 ordering, 14 query_fill. Real mastery gating (65% threshold, prereq-depth recommender).
- **Learning Path:** TWO systems — a flat curated library (~115 lessons) shown at `/learn`, AND a fully-built 5-track career path (`LESSON_PATHS`, soc-analyst→purple-team) at `/learn/[slug]` that **nothing links to**.
- **AI-generated lessons:** 5 tracks, generated on-demand by Claude.
- **Scenarios:** ~27–30, beginner→expert (incl. AiTM token theft, ESXi ransomware, DCSync→Golden Ticket).
- **Visuals:** Mermaid fully works (`mermaid ^11.16.0`, rendered client-side in rooms via a `diagram` field and in lessons via `codeExample` keyword-sniff). 34 diagrams exist and all parse.

**Log-analysis validation (hands-on):** I triaged the AiTM scenario end-to-end as an analyst — the discriminating evidence (one `sessionId` on two Entra sign-ins, two IPs/ASNs/browsers, MFA "satisfied by claim in token", `isInteractive:false`) is *findable, not narrated*, with a proper benign look-alike for contrast. This is how real telemetry reads. Endpoint content (Sysmon EID 10, `GrantedAccess 0x1FFFFF`, `dbghelp.dll` call trace) is equally authentic.

---

## 2. Findings by dimension

### Content credibility — 8/10
Point errors found (all verified against the room's own correct statements):
| Loc | Error | Severity |
|---|---|---|
| `rooms-batch-03.ts:120` | `0x12 = AES-128, 0x18 = AES-256` — wrong; correct is `0x11 = AES-128, 0x12 = AES-256` (contradicted the same room's line 51) | factual |
| `rooms-batch-13-r3.ts:81` | "The US military's Mandiant team" — Mandiant was a private firm | factual |
| `rooms-batch-07.ts:319` | `crowdstrike.AlertType: "ProcessRollup2"` — `ProcessRollup2` is a value of `event_simpleName`, not a field called AlertType | field-name |
| `rooms-batch-24.ts:919` | `web-attacks-practice` didn't require its theory room `web-application-security` | prereq gap |
| `rooms-batch-17-r3.ts:78-79` | `cert_age_hours_at_connection` / `destination_hosts_seen_before_today` are pre-computed conclusions (spec forbids derived analytics) — **BUT** the whole task is built around them, with a benign contrast. Spec-vs-design tension; needs a content decision, not a mechanical delete. | design |
| `playbookLessons.ts`, `rooms-batch-08.ts:769` | Teaches NIST SP 800-61 **Rev 2**; Rev 3 (2025) + CSF 2.0 superseded it | currency |
| `rooms-batch-19.ts` | Header declares 4 rooms; export ships 2. **T1114.002** (Remote Email Collection) and **T1098.005** (Device Registration) still lack a dedicated room | coverage |

No NICE Framework (PR-CDA-001) mapping exists, though the content covers most of its KSAs — a missed documentation opportunity.

### Pedagogy — Rooms excellent; exits ungated
- **🔴 Learning-Path nav is a flat catalog, not a path.** `/learn` renders the flat library with only difficulty filter; the real 5-track `LESSON_PATHS` has **zero links to it** anywhere in the UI. A beginner clicking "Learning Path" lands on an intermediate lesson with no scaffolding.
- **🔴 Scenarios & Dashboard have no mastery gate.** Every scenario (incl. expert ESXi ransomware, DCSync→Golden Ticket) is launchable from day 1 — the 65% readiness gate that governs Rooms is absent at the exact learning→practice transition.
- **🔴 5 of 6 "bridge" rooms are unwired.** `log-entry-anatomy`, `malware-types`, `timestamps-and-timelines`, `encoding-encryption-hashing`, `security-products-behaviour` were written to close knowledge gaps but are not listed as prerequisites of the rooms that assume them (only `identity-basics` was wired).
- **🟡** difficulty tags occasionally understate prereq depth; `CONTENT-SPEC.md` describes a historical "42/82 techniques" gap as current.
- **🟢 Strengths to preserve:** systematic task-type variety (≤2 readings in a row), genuine recognition→recall→transfer spaced repetition around Event IDs/Kerberos.

### Engagement / visuals — capability under-used
- Mermaid renders but is **0%** in AI lessons (the generator prompt never asked for diagrams) and **~10%** in rooms despite `CONTENT-SPEC` mandating it for structural content.
- A `SectionImage` component pulls from the **Unsplash Source API (deprecated 2022)** — fragile, generic, may vanish silently.
- **No markdown-table support** in either lesson renderer → SLA/field-comparison tables are stuck as ASCII inside code blocks.

### Reports mechanism — two real bugs (fixed)
- **Verdict scoring bug:** client sent `"tp"/"fp"`, server compared `"malicious"/"benign"` → the 25-pt correct-verdict tier was **unreachable** and `verdictCorrect` always false.
- **`findings` dropped:** the Findings tab was collected in the UI but excluded from the POST body → a whole graded input was dead.
- **Gaps (not yet fixed):** the analyst's written report text is **never persisted** (only score/XP/time) — no "review past reports," no instructor visibility; rubrics are word-count/keyword proxies (gameable); fabrication-detection exists only in the dashboard flow, not the scenario grader.

### Images — the definitive answer
Raster/SVG images are **not currently supported** (no field, no `<img>` renderer), but the **CSP already permits them** (`img-src 'self' data: blob: https:`) — the only blocker is a missing content-model field + renderer. **Recommendation: do NOT AI-generate raster images for technical diagrams** (they garble exact labels — port numbers, field names — and invent wrong topologies; the codebase already documents this rationale and it's correct). Instead: lean on the **already-working Mermaid**, add markdown tables, generate SVG diagrams in code, and reserve real images for non-technical "hero" module art stored locally in `/public`.

---

## 3. Prioritized improvement plan

### ✅ Tier 0 — done this pass (safe, verified, tsc-clean)
1. Fixed AES value (`rooms-batch-03.ts:120`).
2. Fixed "US military's Mandiant" (`rooms-batch-13-r3.ts:81`).
3. Fixed CrowdStrike field name → `event_simpleName` (`rooms-batch-07.ts:319`).
4. Wired `web-attacks-practice` → `web-application-security` prerequisite.
5. Fixed verdict scoring bug + wired `findings` into grading (reports mechanism).
6. Taught the AI-lesson generator to emit Mermaid diagrams for structural topics (0%→ expected 2-3/lesson; zero frontend change — renderer already supports it).

### 🥇 Tier 1 — highest ROI, small changes (recommend next)
7. **Expose `LESSON_PATHS` in the nav** — make `/learn` show the 5 career tracks (link to `/learn/[slug]`), with the flat library clearly labeled as a reference library. *(pedagogy 🔴 A)*
8. **Wire the 5 unwired bridge rooms** as prerequisites of the rooms that assume them. *(pedagogy 🔴 C — data-only)*
9. **Add soft readiness signals on Scenarios** — `recommendedRoomIds` per scenario + a "you haven't finished X yet" badge (soft, not a hard lock — preserves self-paced freedom). *(pedagogy 🔴 B)*
10. **Convert existing ASCII-art diagrams to real Mermaid** (e.g. the SOC-loop in `pathLessons-a.ts`) — content already written, syntax conversion only.
11. **Add markdown-table support** to both lesson renderers; convert SLA/field-comparison tables out of code blocks.
12. **Remove/replace the deprecated Unsplash `SectionImage`.**

### 🥈 Tier 2 — medium effort, high value
13. **Persist the analyst's written report** (text + rubric breakdown) to `scenario_history` so students can review past reports and instructors get visibility (big win for a *training* platform, ties into B2B org-admin console).
14. **Port fabrication-detection** from the dashboard grader into the scenario grader.
15. **Add a lesson `image?`/`heroImage?` field** (local `/public` assets) + `<img>` renderer for non-technical module art; add explicit `diagram?` to `LessonPage` for parity with rooms.
16. **Generalize an "AnatomyViewer"** (from the existing email-header click-to-reveal) for lessons — interactive JWT/HTTP/Kerberos-ticket anatomy.
17. **Write the two missing rooms** — T1114.002 (Remote Email Collection) and T1098.005 (Device Registration).
18. **Refresh NIST content to SP 800-61 Rev 3 / CSF 2.0.**

### 🥉 Tier 3 — polish / positioning
19. Formal **NICE PR-CDA-001** competency mapping (tag lessons/rooms to KSAs).
20. A **diagram-coverage lint** that fails structural topics lacking a `diagram` (enforces existing `CONTENT-SPEC` guidance).
21. Refresh `CONTENT-SPEC.md` (drop the stale "42/82 techniques" framing).
22. Systematic MITRE-coverage diff script (scenario/companyProfile techniques vs taught rooms) to quantify remaining gaps.

---

## 4. What changed in this pass

Files edited (tsc-clean, diagram gate PASS):
- `src/data/rooms-batch-03.ts`, `rooms-batch-13-r3.ts`, `rooms-batch-07.ts`, `rooms-batch-24.ts` — content fixes.
- `src/app/(app)/scenarios/[slug]/ScenarioClient.tsx`, `src/app/api/scenarios/[slug]/grade/route.ts` — report scoring bugs.
- `src/app/api/lessons/[slug]/route.ts` — Mermaid diagram guidance for the AI generator.
