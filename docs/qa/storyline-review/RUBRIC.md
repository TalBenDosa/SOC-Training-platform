# Storyline review — rubric (read-only review, NO code changes)

You are a senior SOC / DFIR practitioner (10+ years, Tier-3 / IR lead) reviewing attack storylines of a SOC-analyst
training platform. Each storyline is a sequence of security logs that the trainee team sees in a live feed (mixed with
benign noise) and must detect, triage, escalate and investigate end to end.

Data: one JSON file per storyline in
`C:\Users\Talma\AppData\Local\Temp\claude\C--Users-Talma-OneDrive--------------claude-work\74dc0fed-7ea9-4146-84e8-618168851ee1\scratchpad\stories\<id>.json`
Each file: id, title, complexity (foundation=easy, core=medium, advanced=hard), companies, mitre, events[]. Each event has
the authored fields (source, vendor, event_type, severity, host, user, IPs, mitre, expected_verdict, is_baseline,
fp_explanation, description, process/file/network, raw) and `native` = the record exactly as the platform renders it in
the product's native schema (`product`, `record`, `rawLine`) — or null when the event renders from `raw` (legacy view).
Trainees see: the one-line description, the native record (or raw), and can pivot by host/user/IP/hash.
Note: at runtime the story is re-homed onto the session's organization (names/hosts/IPs/products swapped) — judge the
content, not the demo company names.

The product owner's requirements (Tal):
1. Every storyline must be a WELL-KNOWN, RECOGNISED cyber incident type that a real SOC meets (documented TTPs, real
   campaigns / DFIR-report patterns, MITRE ATT&CK) — not an exotic or invented scenario.
2. NO cryptocurrency-related incidents at all (cryptomining / cryptojacking / coinminers / wallet clippers / crypto theft
   / crypto payouts as the incident). Flag every storyline where crypto is the incident or a central element. (A ransom
   note that asks for Bitcoin inside a ransomware story is NOT the incident — note it, don't flag it as crypto-themed.)
3. An analyst must be able to DETECT it and INVESTIGATE IT END TO END from the logs present: an initial alert/anomaly a
   SOC would really get → pivots (host↔IP↔user↔hash↔domain) that actually connect in the data → root cause / initial
   access → scope / impact → enough evidence to choose containment. Missing links = finding.
4. Every log must be RELIABLE evidence of the attack: the product really emits that event type; field names/values are
   realistic for that product; the log itself (record/raw), not only the description, carries the evidence; no
   contradictions (time order, host/IP/user/hash mismatches, impossible values); descriptions are neutral facts and do
   not state the conclusion ("malicious", "attacker", "exfiltration" …) on attack rows.

For EACH storyline produce:
- **Verdict**: KEEP (sound) / FIX (keep after listed fixes) / REPLACE (concept is fine but execution too weak — rewrite) /
  REMOVE (crypto-themed, not a recognised SOC incident, or not investigable).
- **Recognised incident** 1–5 + the real-world anchor (ATT&CK technique ids, known campaign/actor/DFIR pattern).
- **Crypto**: yes/no (+ where).
- **Detectable** 1–5: what would really fire first (product + detection name/type) — is that alert present in the logs?
- **End-to-end** 1–5: the investigation path through the event ids, and the missing links.
- **Log reliability** 1–5: concrete problems with event id + field (wrong field for vendor, impossible value, contradiction,
  conclusion leaked in description, evidence only in prose, render-error / null native where a native card should exist).
- **Fixes**: concrete, minimal, actionable (event id → what to change / add / remove).

Be specific and evidence-based (cite event ids and field names). Don't pad; skip praise. Do NOT edit any repository file.

## Output
Write your full report to
`C:\Users\Talma\AppData\Local\Temp\claude\C--Users-Talma-OneDrive--------------claude-work\74dc0fed-7ea9-4146-84e8-618168851ee1\scratchpad\review\batch-<N>.md`
as: a summary table (id | verdict | recognised | crypto | detect | e2e | logs | one-line reason), then one section per
storyline with the bullets above. Your final message: the summary table only, plus your 3 most important cross-cutting
observations.
