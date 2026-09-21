# Team-SOC — Exercise Content Audit (2026-09-21)

What the Team-SOC exercise actually throws at trainees: how many events, what types, how
much variety/repetition, which attacks, coverage, and cadence — judged against the goal of
effective ("positive") training. Measured directly from the data (`attackStories.ts`,
`companyProfiles.ts`, `benignEvents.ts`) and the feed builder (`buildTimeline.ts`).

## How the feed is built (context)
Per session, `buildTeamTimeline(company, difficulty, seed)` interleaves **1 attack story
(easy) or 2 concurrent stories (medium/hard)** into **30 / 42 / 55 benign "noise" events**,
one event every **~4–9 s**, deterministic per `(company, difficulty, seed)`. Story selection
is filtered by company SIEM sources and by complexity tier, and de-dupes recent picks.
Complexity → difficulty: **easy = foundation only · medium = foundation + core · hard =
advanced only.** Plus 5 scripted MSEL injects (3× mgmt-pressure, 1 vishing ticket, 1
announcement) on medium/hard.

## 1. How many practice events?
- **66 attack stories** (18 foundation · 24 core · 24 advanced), **avg 8 events each**
  (range 4–22) → **~530 authored attack log-events**.
- **Benign/noise pools:** a 415-event generic pool + per-company pools (RocketStack 64,
  MedCore 82, GlobalLogis 46, QuantumBank 34; NexaCorp uses the 415 generic pool).
- **Per session the trainee sees ~38 (easy) / ~58 (medium) / ~71 (hard) events**, of which
  ~8–16 are the attack and the rest are noise.

## 2. Event types & variety — **strong**
- **33 distinct `event_type`s**: auth_success/failure, process_create, process_access,
  net_connection, dns_query, http_request, cloud_api_call, av_detection, edr_alert,
  registry_set, service_install, scheduled-task, file_create/modify, dlp_block,
  email_received/sent/blocked, mfa_challenge, vpn_login/failed, privilege_escalation,
  role_assignment, account_create/modify/lockout, group_modify, linux_execve, db_query,
  sharepoint_access, ids_signature/blocked, net_blocked…
- **24 distinct vendors** across EDR (CrowdStrike, SentinelOne, Sophos, Sysmon), identity
  (Okta, Entra ID, M365), network/edge (Palo Alto, FortiGate, Check Point, Cisco, Zscaler,
  Infoblox), cloud (AWS CloudTrail/CloudWatch, Azure), Windows Security, Linux auditd,
  CyberArk, GitHub, Google Workspace, Epiq EMR.
- **Verdict:** excellent surface variety — a trainee reads many log shapes from real tools,
  not one vendor's format on repeat.

## 3. Repetition — **low overall, one weak spot**
Deterministic per seed (good — an AAR can replay it), and cross-session picks de-dupe recent
stories. Candidate-story pool per company × difficulty (higher = less repetition):

| Company | easy | medium | hard |
|---|---|---|---|
| NexaCorp | 16 | 25 | 11 |
| RocketStack | 16 | 21 | **8** |
| MedCore | 16 | 24 | 11 |
| GlobalLogis | 16 | 24 | 12 |
| QuantumBank | 14 | 19 | **4** |

- **Easy/medium: plenty of variety** (14–25 candidates) — repetition is a non-issue.
- **Hard is thin at two companies** — **QuantumBank hard = only 4** candidate stories (and
  a session pulls 2), RocketStack hard = 8. A class running hard repeatedly at QuantumBank
  will see the same handful of incidents. **This is the main repetition finding.**

## 4. Attack types — **broad and well-labelled**
The 66 stories span the whole intrusion lifecycle:
- **Initial access:** phishing (attachment/link/macro/ISO), drive-by / fake-update, USB,
  SEO-poisoned & cracked/trojanized installers, ClickFix, tech-support scam, edge-appliance
  pre-auth RCE, SQLi→web-shell, exposed RDP/SSH/VPN.
- **Identity/cred:** password spray, credential stuffing, MFA fatigue, AiTM token theft,
  help-desk MFA-reset social engineering, Kerberoasting, AS-REP roasting, NTLM relay,
  DCSync→Golden Ticket, infostealer cookie theft.
- **Cloud:** OAuth consent/app persistence, impossible travel, key-vault/secrets exfil,
  container escape, K8s pod escape→metadata, cloud crypto-mining, S3/GitHub exfil.
- **Impact/exfil:** ransomware (LockBit-style, ESXi hypervisor, EMR), exfil-first extortion,
  insider bulk theft, DNS tunneling C2, coinminers, rogue trading, market manipulation.
- **LOLBins / defense evasion:** certutil→regsvr32, scheduled-task persistence, clipboard
  clipper, supply-chain vendor update, malicious npm package.

## 5. Coverage — **comprehensive** (with honest edges)
- **120 unique MITRE ATT&CK technique IDs** (77 base techniques) across essentially **all
  enterprise tactics** — Initial Access, Execution, Persistence, Priv-Esc, Defense Evasion,
  Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact, plus
  some Recon (T1595) and Resource-Development (T1608). This is best-in-class breadth for a
  training platform.
- **Edges, not gaps:**
  - **Hard-tier coverage per company is uneven** — because hard = *advanced-only* filtered by
    company sources, some companies expose few advanced stories (QuantumBank 4, RocketStack 8).
    A trainee doing "hard" at QuantumBank sees a narrow slice of the advanced catalogue.
  - **NexaCorp has no company-specific benign pool** (0 events → falls back to the 415 generic
    pool). Works, but its noise is less "NexaCorp-flavoured" than the other tenants'.

## 6. Frequency / pacing — **dense, but the shift is SHORT vs the promise**
- Cadence is realistic: **one event every ~4 s (hard) / ~5.5 s (medium) / ~7 s (easy)** plus
  up to 3.5 s jitter, attacks hidden in the noise.
- **But the feed only STREAMS for ~5.5–7 minutes**, then goes quiet:
  - easy ≈ 38 events × ~8.7 s ≈ **~5.5 min**
  - medium ≈ 58 events × ~7.2 s ≈ **~7 min**
  - hard ≈ 71 events × ~5.75 s ≈ **~7 min**
- The lobby briefing promises a **"~30–45 min"** shift. So after ~7 minutes no new telemetry
  arrives; the room only stays busy if analysts are still working the backlog. **This is the
  single most impactful content finding** for "positive training": the exercise ends (as a
  live feed) far sooner than advertised, and a real shift's sustained-vigilance rhythm isn't
  exercised.

## Verdict & recommendations
**Overall the content is a genuine strength** — 66 attacks, 120 techniques, 33 event types,
24 vendors, realistic noise-to-signal, deterministic replay. Variety and coverage are strong;
it will train real recognition breadth. Three fixes would make it clearly "positive":

1. **[High] Match feed length to the shift.** Either raise the benign pool per difficulty
   (~3–4×, e.g. medium 42→150) or lengthen the cadence, so the feed streams across the full
   30–45 min — or set the briefing to the real ~7–10 min. Today the promise and the pacing
   disagree.
2. **[Medium] Deepen hard-tier variety where it's thin** — add 4–6 advanced stories that fit
   QuantumBank (banking/fraud) and RocketStack (cloud/SaaS) so "hard" there isn't a 4–8 story
   loop. (Alternatively, let hard also draw from `core` when a company's advanced pool < N.)
3. **[Low] Give NexaCorp its own benign pool** for tenant-flavoured noise (cosmetic; the
   generic 415-pool already works).

No repetition problem on easy/medium; coverage and type/vendor variety need no work.
