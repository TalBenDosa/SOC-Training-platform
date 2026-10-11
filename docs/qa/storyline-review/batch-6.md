# Storyline review: batch 6 (AI-themed storylines)

Reviewer stance: Tier-3 / IR lead. Every event was read in full, including `raw` and `native`. Nothing in the repository was modified.

## Summary

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|---|---|---|---|---|---|---|---|
| ai-shadow-chat-upload | FIX | 4 | no | 4 | 3 | 3 | Real DLP-block opener, but the xlsx-to-CSV bypass works the wrong way round. The Sanctioned/Unsanctioned flag and the prompt text appear only in raw, not in the native card. |
| ai-chat-harvest-extension | FIX | 4 | no | 2 | 4 | 3 | The extension ID and the byte sizes give clean pivots, but nothing fires an alert. The DNS row is labelled Infoblox while its native record is Windows DNS on DC01. |
| ai-svg-invoice-lure | FIX | 5 | no | 4 | 4 | 3 | Strong VEC-plus-SVG chain. The native email card lacks the attachment hash and the originating IP. IsFirstContact contradicts itself. The second recipient's scope is never followed up. |
| ai-helpdesk-voice-reset | FIX | 5 | no | 4 | 4 | 3 | Scattered Spider help-desk pattern. The ticket is resolved before the reset happens. The key work-notes are empty in the native record. Raw and native IDs disagree. |
| ai-claude-enterprise-departure | FIX | 3 | no | 3 | 3 | 3 | The data never leaves the corporate tenant. The device story contradicts itself (unmanaged Edge vs Endpoint DLP on corporate WS-SALES-1876 with Chrome). All AI, HR and DLP rows have null native. |
| ai-copilot-oversharing-probe | FIX | 3 | no | 4 | 3 | 3 | The UEBA alert at 13:36 cites a download that happens at 13:41. No evidence shows why a Marketing user can read HR, IT and Finance files. Copilot rows have null native. |
| ai-claude-shared-secret | REPLACE | 3 | no | 2 | 2 | 3 | No alert, no proof the artifact holds secrets, no record of the sharing scope or of anyone viewing it, and no use of the secrets afterwards. |
| ai-claude-compliance-key-harvest | FIX | 4 | no | 4 | 3 | 2 | The IP allow-list should have blocked the attacker's admin actions it later deletes. Okta native records contradict the anomaly. The new key ID is missing from api_key_created. |
| ai-aoai-support-bot-jailbreak | FIX | 3 | no | 5 | 3 | 3 | An external caller IP in the AOAI logs means someone is calling the endpoint directly, i.e. key exposure, and the story ignores it. The recon alert covers a window with no logs. |
| ai-aoai-key-capacity-abuse | FIX | 5 | no* | 5 | 4 | 3 | Storm-2139 Azure OpenAI key abuse, well built. The volume alert starts before gpt-4o-2 existed. Subscription IDs disagree inside the native records. |
| ai-gemini-drive-sweep | FIX | 4 | no | 3 | 3 | 3 | Okta native records contradict the story (Tel Aviv geo, all behaviours NEGATIVE). No alert. Gemini rows carry no doc IDs, so the "sweep" cannot be pivoted to files. |
| ai-bedrock-key-abuse | FIX (merge) | 5 | no | 5 | 4 | 4 | Accurate Sysdig LLMjacking sequence. Entitlement and logging changes happen in us-east-1 but the abuse runs in eu-central-1. Near-duplicate of ai-llmjacking-bedrock. |
| ai-agentic-intrusion-tempo | KEEP | 5 | no | 5 | 4 | 4 | Capital One-style SSRF → IMDSv1 → off-instance credentials chain. The access key links every step. Only minor realism nits. |
| ai-copilot-indirect-injection | FIX | 4 | no | 2 | 4 | 3 | EchoLeak (CVE-2025-32711) modelled correctly. Nothing triggers the response. The injected text, which is the root cause, exists only in prose. |
| ai-llmjacking-bedrock | KEEP | 5 | no | 5 | 4 | 4 | Best in the batch: FP control with a change ticket, invocation-log content, GuardDuty and Cost Anomaly evidence. Small native mismatches. Overlaps ai-bedrock-key-abuse. |

\* The Defender for Cloud alert "Suspected wallet attack" means denial-of-wallet (cost exhaustion). It is not crypto.

**Crypto:** none of the 15 storylines is crypto-themed.

---

## ai-shadow-chat-upload

- **Verdict:** FIX
- **Recognised: 4.** Shadow-AI data leakage (the Samsung/ChatGPT pattern, 2023). T1567 Exfiltration Over Web Service; ATLAS AML.T0048 is in the descriptions only.
- **Crypto:** no.
- **Detectable: 4.** The first thing that fires is Zscaler's DLP block "Block PII to GenAI (Files)" at aishd4. That row is present.
- **End-to-end: 3.**
  - Path: aishd4 (block) → aishd3 (session marked Unsanctioned) → aishd5 (CSV re-save) → aishd6 (allowed upload) → aishd7 (prompt) → aishd8 (delete). The pivots are host, user and file name.
  - Missing: where the xlsx came from. aishd2 claims "exported from a browser session" but native `FileOriginUrl`/`FileOriginIP` are null and there is no CRM or SaaS export record.
  - Missing: any personal-account evidence, such as an OpenAI login or an account ID.
- **Log reliability: 3.**
  - **Logic flaw (aishd6):** DLP "returned nothing for the CSV". A plaintext CSV with 1,204 email addresses would trip the same dictionary more easily than a compressed xlsx, so this teaches a wrong lesson.
  - **Key evidence missing from native (aishd1, aishd3, aishd6):** `zscaler.app_status` (Sanctioned/Unsanctioned) and `zscaler.prompt_req` exist only in raw. The NSS native record has neither, so the native cards for aishd1 and aishd3 are effectively identical. The uploaded file name (`upload_filename`) is also missing from native in aishd4 and aishd6.
  - **Vendor/product mismatch:** aishd2, aishd5 and aishd8 are authored as CrowdStrike FileWritten but render as MDE DeviceFileEvents. PIDs disagree between raw and native (6204/13624; 7284/18540; parent 3844/8104).
  - **Conclusion leaks in descriptions:** aishd3 "which means this session is not signed in to the company workspace"; aishd7 "Customer records have now been disclosed to a public model service… (ATLAS AML.T0048)".
  - **Weak MITRE mapping (aishd8):** a user deleting a file from Downloads via explorer.exe is tagged T1070.004.
- **Fixes:**
  - aishd6: make the bypass realistic. Options: a password-protected zip (native `unscannabletype: Encrypted`), the upload going through a file type the DLP rule does not cover, or pasting rows into the prompt in small chunks. Show the DLP gap in the log fields.
  - aishd1, aishd3, aishd4, aishd6, aishd7: put the app-status and prompt evidence into the native NSS record. Add the uploaded file name to native.
  - aishd2: populate `FileOriginUrl` with the CRM export URL, or add a CRM/SharePoint export audit row.
  - aishd3, aishd7: neutralise the descriptions.
  - aishd8: drop T1070.004 or downgrade the row to context. Align the native PIDs with raw.

## ai-chat-harvest-extension

- **Verdict:** FIX
- **Recognised: 4.**
  - Malicious browser-extension update harvesting AI chats: Urban VPN / Koi Security 2025; the Cyberhaven extension compromise, Dec 2024.
  - ATT&CK: T1176 Browser Extensions, T1041.
- **Crypto:** no.
- **Detectable: 2.**
  - Nothing fires. Every row is an allowed proxy or DNS record; aiext7 and aiext9 are "high" only because they were authored that way.
  - A real SOC would find this through threat intel on the domain, a browser-extension inventory or risk score (MDE TVM browser extensions, Falcon Exposure Management) or a hunt. None of those is present.
- **End-to-end: 4.**
  - Path: aiext2 (crx download) → aiext3 (Extensions\<id>\5.5.0_0) → aiext4 (DNS) → aiext5, aiext7, aiext9 (POSTs carrying `ext=<same id>`). The byte sizes match prompt plus answer from aiext6 and aiext8. This is a good chain.
  - Missing: the extension name and its new permissions. The link between the ID and "SurfGuard VPN" rests only on the domain name.
  - Missing: fleet scope (other hosts with the same extension ID).
- **Log reliability: 3.**
  - **DNS row (aiext4):** the vendor is Infoblox and the description says "internal Infoblox resolver ns-01", but native is Microsoft-Windows-DNSServer EventID 257 on DC01.nexacorp.com. The geo "Bucharest hosting range" appears only in prose.
  - **CRX download (aiext2):** native `contenttype: text/html` should be `application/x-chrome-extension`.
  - **Prompt text missing from native (aiext6, aiext8):** `prompt_req` (the evidence of what leaked) is raw-only.
  - **Vendor/product mismatch (aiext3):** CrowdStrike is authored but native is MDE; PID 7132 vs 17164.
  - **Conclusion leak (aiext7):** "Conversation content is being copied to a domain that belongs to the extension vendor… (ATLAS AML.T0048)".
- **Fixes:**
  - Add an opening detection: a TI or newly-observed-domain alert on stats.surfguard-vpn.com, or a browser-extension inventory or risk-change record showing the name, version 5.5.0 and new host permissions (`<all_urls>`, chatgpt.com).
  - aiext4: make the native record Infoblox, or change the vendor and description to Windows DNS on DC01.
  - Put prompt evidence into native for aiext6 and aiext8.
  - Optionally add a second host with the same extension ID to give the trainee scoping work.

## ai-svg-invoice-lure

- **Verdict:** FIX
- **Recognised: 5.**
  - Compromised-supplier (VEC) email with an SVG attachment leading to a Turnstile-gated credential page (Tycoon2FA / Mamba2FA style). The 2024–25 SVG phishing surge; Microsoft's Sept-2025 report on LLM-obfuscated SVG.
  - ATT&CK: T1566.001, T1204.002.
- **Crypto:** no.
- **Detectable: 4.**
  - Real triggers are present: the MDO ZAP post-delivery alert (aisvg11) and a correct-password sign-in from a new country followed by an MFA failure (aisvg10).
  - aisvg10 has `riskLevelDuringSignIn: none`. An "unfamiliar sign-in properties" risk would be realistic and would give an earlier alert.
- **End-to-end: 4.**
  - Path: aisvg2/aisvg3 (InternetMessageId) → aisvg4 (same SHA-256 in INetCache) → aisvg5 (Edge opens the SVG) → aisvg6/aisvg8/aisvg9 (NRD domain, 45.142.214.77) → aisvg10 (Entra sign-in from the same IP, password correct).
  - Missing: p.whitfield (aisvg3) is never followed (no open, click or ZAP row), and the other hidden Bcc recipients are not scoped.
  - Missing: any evidence linking the SVG to the URL. A detonation or URL-extraction record would show it; currently only timing connects them.
- **Log reliability: 3.**
  - **Key pivots missing from native (aisvg2, aisvg3):** native EmailEvents has no attachment name or hash, and no originating IP (the Lagos `x-originating-ip` exists only in raw). The hash pivot to aisvg4 therefore exists only in raw.
  - **IsFirstContact contradiction (aisvg2):** aisvg2 has `IsFirstContact: 1` from a sender who mailed the same recipient the day before (aisvg1: 0).
  - **Missing referer (aisvg7):** `refererURL: None`, yet the description's point is "requested by the page on the NRD". `contenttype: text/html` for api.js is also wrong.
  - **Entra ID mismatch (aisvg10):** native `userId` 71a6e17d… vs raw 6b2f9d40…; native `sessionId` empty.
  - **Vendor/product mismatch (aisvg4, aisvg5):** CrowdStrike is authored but native is MDE; PIDs 5148/15536 and 9236/2164.
  - **Leaks:** aisvg2 "LLM produces at no cost (ATLAS AML.T0052.000)" is speculation with no body in the log. aisvg10 "The password is disclosed". aisvg11 "after the credentials were submitted".
- **Fixes:**
  - Add EmailAttachmentInfo rows (file name, SHA256) for aisvg2 and aisvg3, or render them in native.
  - Set `IsFirstContact: 0` on aisvg2.
  - aisvg7: set `refererURL` to the docview URL.
  - Add a ZAP row for p.whitfield, plus her EDR or proxy activity (or its absence).
  - Drop the LLM claim from aisvg2. Neutralise the descriptions of aisvg10 and aisvg11.
  - Consider T1566.002 / T1598.003 instead of T1056 for aisvg9.

## ai-helpdesk-voice-reset

- **Verdict:** FIX
- **Recognised: 5.**
  - Help-desk social engineering for an MFA reset: Scattered Spider / MGM 2023, CISA AA23-320A. The voice-clone layer is plausible and acknowledged as "suspected".
  - ATT&CK: T1656, T1556.006, T1098.005, T1114.003.
- **Crypto:** no.
- **Detectable: 4.**
  - Real triggers: "Suspicious inbox forwarding rule" (MDO / Defender for Cloud Apps) on aihvr10, and a SIEM rule for an MFA method wipe followed by re-registration from a new IP (aihvr6 → aihvr8). The raw events are present; no alert record is.
- **End-to-end: 4.**
  - Path: aihvr2 (ticket) → aihvr3 (the real user active on the office laptop during the "lockout"; an excellent clue) → aihvr5/aihvr6 (admin reset and wipe) → aihvr7/aihvr8/aihvr9 (Romanian IP registers Authenticator and signs in) → aihvr10 (forwarding rule; the session matches by IP) → aihvr11 (confirmation).
  - Missing: impact of the forwarding rule (no message trace or MailItemsAccessed rows).
  - Missing: the forced change of the temporary password at first sign-in (a "Change password" audit row from 80.94.95.118).
  - Missing: a telephony or CDR record for the inbound caller number.
- **Log reliability: 3.**
  - **Timing contradiction (aihvr4 vs aihvr5/aihvr6):** the ticket is resolved at 08:46:52 with close notes saying the reset is done, but the reset happens at 08:47:58 and the method wipe at 08:48:31.
  - **Key evidence empty in native (aihvr4, aihvr11):** native `work_notes: ""` while raw holds the decisive notes ("call-back not performed", "suspected synthetic voice"). aihvr4 native also lacks `u_identity_verification`.
  - **Raw/native ID mismatches:** Entra userId 4b7d1e92 vs e9f788cf. Initiator j.oduya c9e21f57 vs 604bd4b8. Tenant 6d1f9a3e in raw audit and UAL vs 74155343 in native. aihvr10 native lacks `SessionId`.
  - **CA status contradiction (aihvr7):** native `conditionalAccessStatus: notApplied` alongside a policy with `result: success`.
  - **Event typing (aihvr2, aihvr4, aihvr11):** `event_type: policy_modification` for ServiceNow tickets.
  - **Leak (aihvr11):** the description restates the conclusion and adds ATLAS tags.
- **Fixes:**
  - Order the events as reset → wipe → resolve (move aihvr4 after aihvr6), or edit the close notes.
  - Copy work_notes and u_identity_verification into the native ServiceNow records.
  - Add a "Change password" row from 80.94.95.118 after aihvr7.
  - Add a MessageTrace or MailItemsAccessed row showing forwarded messages.
  - Unify the user and tenant IDs between raw and native. Fix the CA status on aihvr7.

## ai-claude-enterprise-departure

- **Verdict:** FIX
- **Recognised: 3.**
  - Departing-employee data theft is extremely common (the Purview IRM "Data theft by departing users" template). T1213.002, T1567.
  - Here, though, the "exfil" goes to the company's own sanctioned Claude tenant. The story admits this in aicld7 ("the upload alone is not a leak").
- **Crypto:** no.
- **Detectable: 3.**
  - The realistic trigger is a Purview IRM alert (HR resignation + downloads), or an Endpoint DLP alert.
  - aicld8 is audit-only, so it would not normally raise an alert.
- **End-to-end: 3.**
  - Path: aicld1 (HR) → aicld3/aicld4 (SharePoint downloads) → aicld5–aicld11 (Claude uploads; file names match) → aicld12 (chat).
  - Missing: any step that moves data out of company control, such as personal email, USB, a share or export of the project, or access to Claude from a personal device. Without it, scope, impact and containment are just HR policy.
  - Missing: the source of Pricing_Model_Discounts_2026.xlsx and Pipeline_Q4_Forecast_Detail.xlsx (aicld10, aicld11).
- **Log reliability: 3.**
  - **Device contradiction:**
    - aicld3/aicld4: SharePoint downloads with `IsManagedDevice: false` and an Edge UA.
    - aicld5–aicld11: Claude activity uses a Chrome UA.
    - aicld8: Purview Endpoint DLP says chrome.exe on corporate WS-SALES-1876 from C:\Users\a.kaplan\Downloads.
    - These describe two different devices.
  - **Null native:** Workday (aicld1), every Claude row and the Purview DLP row (aicld8) have `native: null`.
  - **Wrong record type (aicld8):** Endpoint DLP is shaped as `DlpRuleMatch` / Workload Endpoint. Endpoint DLP audit uses RecordType DLPEndpoint with operations such as FileUploadedToCloud.
  - **Wrong geo (aicld3/aicld4):** native `GeoLocation: "NAM"` for a UK tenant and home IP.
  - **Tenant ID mismatch:** 6d1f9a3e vs 74155343.
  - **Editorialising (aicld7, aicld11, aicld12):** "the risk is a leaver consolidating…", "by an employee who resigned that morning", and investigation instructions inside the description.
- **Fixes:**
  - Pick one device. Either a corporate laptop at home (then SharePoint `IsManagedDevice: true` and a consistent browser), or a personal device (then drop aicld8 and use Defender for Cloud Apps session control).
  - Add a real egress step. Options: a Claude project export or share to an external account; mail to a personal address; a USB copy on WS-SALES-1876; or Claude accessed from an unmanaged device after the project was built.
  - Give Workday, Claude and Purview native cards.

## ai-copilot-oversharing-probe

- **Verdict:** FIX
- **Recognised: 3.**
  - Copilot oversharing and permission sprawl is a well-documented M365 risk (Microsoft's oversharing guidance; Purview DSPM for AI "risky AI usage"). As a SOC incident it is newer.
  - ATT&CK: T1213.002, T1552.001.
- **Crypto:** no.
- **Detectable: 4.** Sentinel UEBA (aicop8) is present. A Purview DSPM-for-AI / IRM "Risky AI usage (jailbreak)" alert would be the more natural trigger.
- **End-to-end: 3.**
  - Path: aicop2–aicop7 (CopilotInteraction on the same ThreadId, labelled resources) → aicop5/aicop9 (direct SharePoint access and download).
  - Missing root cause: Copilot only returns what the user can already open, so the real finding is that s.patel has access to HR-Compensation and the IT and Finance libraries. No row shows why (an "Everyone except external users" grant, a sharing link, group membership).
  - Missing: sign-in context to rule out account compromise.
- **Log reliability: 3.**
  - **Time contradiction (aicop8):** UEBA at 13:36:00 cites "a direct SharePoint open and download", but the download is aicop9 at 13:41.
  - **Null native:** all CopilotInteraction rows (aicop1–4, aicop6, aicop7) have `native: null`, even though the m365 native product is used for the SharePoint rows.
  - **Library evidence only in prose:** AccessedResources lack `SiteUrl`, so "HR library", "IT" and "Finance" rest on GUID label IDs plus prose.
  - **Field shapes (aicop8):** UEBA mixes ECS with flat `FirstTimeUserPerformedAction`. Real BehaviorAnalytics nests these under `ActivityInsights` and carries `InvestigationPriority`.
  - **Speculation (aicop4):** "The prompt was apparently reworded".
  - **Editorialising (aicop3, aicop6):** "retrieved for a marketing user", "the kind of documents that hold credentials".
- **Fixes:**
  - Move aicop8 after aicop9, or remove "download" from its text.
  - Add `SiteUrl` to each AccessedResource.
  - Add the permission root cause, e.g. a SharePoint SharingSet / AddedToGroup audit row or a site-permission record showing HR-Compensation shared with Everyone.
  - Render the Copilot rows natively.

## ai-claude-shared-secret

- **Verdict:** REPLACE
- **Recognised: 3.** Secrets exposed through a SaaS share or publish (the public Postman workspaces and public gist leak pattern). T1552.001. The AI-artifact variant is plausible but thin.
- **Crypto:** no.
- **Detectable: 2.** Nothing fires. A realistic opener would be a SIEM rule on `claude_file_uploaded` with `filename=*.env` followed by `claude_artifact_published`, or a secret-scanning hit on the published artifact.
- **End-to-end: 2.**
  - Path: aicas3 (prod-deploy.env uploaded) → aicas5 (artifact created; no `claude_chat_id`) → aicas6 (sharing changed; no new value) → aicas7 (published).
  - Missing: proof the artifact contains the secrets, the scope of the share (org or public), any viewer or access record, and any use of the leaked payments-service credentials.
  - Without these the analyst cannot tell a leak from a developer publishing a harmless script.
- **Log reliability: 3.**
  - `hostname: LAP-DEV-12` on SaaS audit records that carry no host field.
  - Baseline claim only in prose: "first sharing change… in 90 days" (aicas6).
  - Enrichment only in prose: "matches the… payments service" (aicas3).
  - Null native on every row.
- **Fixes (rewrite):**
  - Link the artifact to the chat and project: add `claude_chat_id` and `claude_project_id` on aicas5.
  - Show the sharing scope in aicas6.
  - Add a detection, e.g. a secret scanner or DLP hit on the published artifact URL, or a GitHub/GitGuardian-style public-exposure alert.
  - Add downstream misuse, e.g. a CloudTrail or payment-API call using the leaked key from an external IP.
  - Add a containment row (unpublish, key rotation).

## ai-claude-compliance-key-harvest

- **Verdict:** FIX
- **Recognised: 4.**
  - IdP account takeover → SaaS admin mints an API key → bulk data pull. This is the UNC5537/Snowflake and Salesloft-Drift style of SaaS token and data theft.
  - ATT&CK: T1078.004, T1098.001, T1530.
- **Crypto:** no.
- **Detectable: 4.** Okta ThreatInsight `threatSuspected: true` (aicak1), plus high-signal admin events (aicak4 IP restriction deleted, aicak5 first new API key).
- **End-to-end: 3.**
  - Path: aicak1/aicak2 (Okta from M247) → aicak3 (Claude SSO from the same IP) → aicak4/aicak5 → aicak6/aicak7 (new key used from 5.188.206.18, Moscow) → aicak8 (org export).
  - Missing initial access: how the password and the push approval were obtained (no AiTM, phishing or MFA-fatigue rows). The title says "hijacked owner session", but the logs show a fresh password + push login.
  - Missing impact: no record of the export download.
- **Log reliability: 2.**
  - **Logic contradiction (aicak4):** the allow-list "limited Claude Enterprise access to RocketStack's office and VPN ranges", so the M247 sign-in (aicak3) and the admin action (aicak4) should have been refused before the restriction was deleted.
  - **aicak1 native:**
    - `behaviors` all NEGATIVE (New Geo-Location, New Country, New IP = NEGATIVE) and `risk {level=LOW}`, contradicting "never seen this network or country".
    - `credentialType: null`, `authenticationStep: 0`.
    - `actor.id` differs from raw.
  - **aicak2 native:** geo Tel Aviv, ISP hot-net, `isProxy: false` for the same M247 IP; raw `isProxy` is false as well. `externalSessionId` differs from aicak1 (102ya4b6k vs 102z4349h).
  - **Okta event order (aicak1/aicak2):** `user.session.start` is logged before `user.authentication.auth_via_mfa`. Okta logs session start after the MFA step.
  - **Missing key ID (aicak5):** `api_key_created` does not carry the new key's ID, so the link to apikey_01m9NG575… in aicak6 exists only in prose.
  - **Count only in prose (aicak7):** the "1,184 activities" figure is not backed by an aggregated alert row.
- **Fixes:**
  - aicak4: scope the restriction differently (e.g. it applied only to API keys), or remove the allow-list claim.
  - aicak1/aicak2: set behaviours to POSITIVE for New Country/IP/Device and risk MEDIUM or HIGH. Use the M247/Amsterdam geo and `isProxy: true` on both. Use the same externalSessionId. Order MFA first, session start second.
  - aicak5: add the created key's ID.
  - Add an initial-access row, e.g. preceding Okta push denials (MFA fatigue) or an AiTM proxy sign-in.
  - Add a SIEM aggregate for the API burst.

## ai-aoai-support-bot-jailbreak

- **Verdict:** FIX
- **Recognised: 3.**
  - Prompt-injection and jailbreak attempts on a public chatbot (OWASP LLM01). The Defender for Cloud AI alerts used are real.
  - `mitre: []`: there is no ATT&CK anchor; it is a blocked, no-impact triage case.
- **Crypto:** no.
- **Detectable: 5.** Defender for Cloud "A Jailbreak attempt… was blocked by… Prompt Shields" (aiasb3, aiasb6) and "(Preview) LLM Reconnaissance Attempt Detected" (aiasb5) are present.
- **End-to-end: 3.**
  - Path: aiasb3 (alert, IP 193.29.13.77) → aiasb2/aiasb4/aiasb7 (AOAI 400s from masked 193.29.13.***).
  - **Unaddressed finding:** the support app calls AOAI from its App Service egress (aiasb1, 20.73.41.***). If AOAI logs an external `caller_ip_address`, that client is calling the AOAI endpoint directly with a valid key. That means key or endpoint exposure, which is a bigger incident than the jailbreak, and the story never addresses it.
  - Missing: app or WAF logs, a user or session ID, and whether anything leaked during the 09:11–09:14 recon.
- **Log reliability: 3.**
  - **Recon window has no logs (aiasb5):** the alert covers 09:11:48–09:17 "prompts since 09:11", but no request from this caller exists before 09:14:03, and aiasb7 says no 200s were seen.
  - **Subscription mismatch:** native alert IDs use subscription 6520fe69… while the resource is 7d3e1b90….
  - **Null native:** AOAI rows are native null.
- **Fixes:** choose one model and make the logs consistent.
  - Model A (via the app): AOAI rows show the app egress. Defender for Cloud gets the end-user IP via the user security context (`extendedProperties` "End user IP"). Add App Gateway/WAF or app logs carrying the attacker IP.
  - Model B (direct API): reframe as key exposure and add how the key leaked.
  - Either way, add the 09:11–09:14 recon requests.
  - Fix the subscription ID.

## ai-aoai-key-capacity-abuse

- **Verdict:** FIX
- **Recognised: 5.**
  - Stolen Azure OpenAI keys used for resale or abuse: Storm-2139 / Microsoft DCU's "Azure Abuse Enterprise" case, 2025; LLMjacking.
  - ATT&CK: T1078.004, T1552, T1496.004.
- **Crypto:** no. "Wallet attack" means denial-of-wallet; consider renaming in the UI to avoid confusion.
- **Detectable: 5.** Entra Identity Protection medium risk (aiakc1), plus Defender for Cloud "Access from suspicious IP" (aiakc4) and "Suspected wallet attack - volume anomaly" (aiakc7).
- **End-to-end: 4.**
  - Path: aiakc1 (risky sign-in, 185.196.8.140) → aiakc2 (LISTKEYS from the same IP) → aiakc3/aiakc4 (key auth from 162.55.84.19) → aiakc5 (new deployment from the same portal IP) → aiakc6 → aiakc8 (business impact, 429s).
  - Missing initial access: how t.harris's password and push were obtained.
  - Missing: cost and billing evidence.
- **Log reliability: 3.**
  - **Timing contradiction (aiakc7):** the alert is scoped to deployment gpt-4o-2 with `startTimeUtc` 21:58:51, but gpt-4o-2 was created at 22:37 (aiakc5).
  - **Subscription mismatch:** native Activity Log `hierarchy` and Defender for Cloud alert IDs use subscription 6520fe69… while the resource is 7d3e1b90….
  - **Claims only in prose:** aiakc5 "No change request… exists"; aiakc8 "token quota is exhausted". TPM limits are per minute; next-morning 429s imply quota was reallocated to gpt-4o-2 or abuse is ongoing, and neither is shown.
- **Fixes:**
  - aiakc7: scope it to the resource, or start it at ≥22:37.
  - Unify the subscription IDs.
  - Show the capacity reallocation (deployment `sku.capacity` in aiakc5) or ongoing abuse at 08:12.
  - Add the initial-access vector.

## ai-gemini-drive-sweep

- **Verdict:** FIX
- **Recognised: 4.**
  - Account takeover from a commercial VPN → SaaS collection → external share to a personal Gmail. The Gemini-as-recon twist is novel but plausible.
  - ATT&CK: T1078.004, T1530, T1537 (T1567 would fit the share better).
- **Crypto:** no.
- **Detectable: 3.**
  - No alert row. Okta native says `threatSuspected: false`, and Google login has `is_suspicious: false`.
  - The realistic opener is a Google Workspace alert-center / DLP "external sharing of sensitive file" alert on aigds10, or an Okta new-country alert.
- **End-to-end: 3.**
  - Path: aigds1/aigds2 → aigds3 (SAML login, same IP) → aigds4–aigds6 and aigds9 (Gemini) → aigds7/aigds8 (downloads) → aigds10 (share to sa.docs.backup@gmail.com).
  - Missing: Gemini rows carry no doc_id, so the sweep cannot be tied to specific files.
  - Missing: how the credentials and push approval were obtained.
  - Missing: whether this is ATO or the user travelling. The Gmail name suggests the user's own backup; there is no evidence either way.
- **Log reliability: 3.**
  - **aigds1 native:** behaviours all NEGATIVE, risk LOW, `threatSuspected: false`, contradicting "never signed in from this network or country".
  - **aigds2 native:** geo Tel Aviv, ISP hot-net, `isProxy: false` for the Datacamp IP. `externalSessionId` differs (10214aikdj vs 10214ki62i). Session start is logged before MFA.
  - **Raw/native ID mismatches:** `customerId` C03k8q2vz vs C03f5715b; `profileId` differs.
  - **Count only in prose (aigds6):** "14 Gemini events".
- **Fixes:**
  - Fix the Okta template exactly as for compliance-key-harvest.
  - Add a Workspace alert-center or DLP row for the external share.
  - Add a Drive `view` or `access` event per summarised file, or doc context on the Gemini rows if the source supports it.
  - Unify the customer and profile IDs.

## ai-bedrock-key-abuse

- **Verdict:** FIX (or merge with ai-llmjacking-bedrock)
- **Recognised: 5.**
  - Sysdig's LLMjacking sequence, reproduced faithfully: GetModelInvocationLoggingConfiguration → a deliberately invalid `max_tokens_to_sample` probe → PutUseCaseForModelAccess → PutFoundationModelEntitlement → DeleteModelInvocationLoggingConfiguration → streaming inference.
  - ATT&CK: T1552.001, T1078.004, T1562.008, T1496.004.
- **Crypto:** no.
- **Detectable: 5.** GitHub secret-scanning alert (aibk3) and GuardDuty findings (aibk10, aibk11).
- **End-to-end: 4.**
  - Path: aibk1 (over-privileged inline policy = root cause of the blast radius) → aibk2 (baseline: VPC endpoint, private IP) → aibk3 (key leaked) → aibk4–aibk9 (same AKIA from 62.210.71.148) → aibk12 (containment). Excellent pivoting on the access key.
  - Missing: the commit author or push event (who leaked the key).
  - Missing: cost evidence.
- **Log reliability: 4.**
  - **Region inconsistency:** the entitlement (aibk7) and the logging deletion (aibk8) are in us-east-1, but the abuse (aibk9) is in eu-central-1. Model access and invocation logging are per region, so the deletion does not blind eu-central-1 and the us-east-1 entitlement does not enable eu-central-1. The aibk8 description ("requests in that region…") makes the gap explicit.
  - **Native card missing:** the GitHub secret-scanning row (aibk3) has null native.
  - **Unverified finding types:** check that `DefenseEvasion:IAMUser/BedrockLoggingDisabled` and `Impact:IAMUser/AnomalousModelInvocation` exist in GuardDuty's published list. If not, use the documented AnomalousBehavior family.
  - **Duplicate:** near-duplicate of ai-llmjacking-bedrock (same TTP chain, same GitHub root cause, same CI-user premise).
- **Fixes:**
  - Run the abuse in us-east-1, or add PutFoundationModelEntitlement and logging reads/deletes in eu-central-1.
  - Add a GitHub push or audit row naming the committer.
  - Verify the GuardDuty types.
  - Merge with ai-llmjacking-bedrock or clearly differentiate the two (e.g. make this one the "fast containment" variant and drop the overlapping steps).

## ai-agentic-intrusion-tempo

- **Verdict:** KEEP
- **Recognised: 5.**
  - SSRF → IMDSv1 → instance-role credentials used off-instance → Secrets Manager → S3. The Capital One 2019 pattern; MITRE campaign C0062-style tempo.
  - ATT&CK: T1190, T1552.005, T1555.006, T1530.
- **Crypto:** no.
- **Detectable: 5.**
  - GuardDuty `InstanceCredentialExfiltration.OutsideAWS` (aiag11) is present.
  - The decoy-key trip (aiag9) is a strong canary signal. No canary alert row is present; the CloudTrail AccessDenied record is.
- **End-to-end: 4.**
  - Path: aiag2/aiag3 (spec, then endpoint at machine tempo) → aiag4/aiag5 (SSRF to 169.254.169.254, role name) → aiag6–aiag8 (ASIA key identical to the instance's own at aiag1, now from 159.89.212.66) → aiag9 (decoy) → aiag10 (412 MB) → aiag11 → aiag12 (revocation).
  - Missing: use of the stolen prod/customer-api/db-reader secret (no RDS or DB audit), which leaves the DB scope open.
- **Log reliability: 4.**
  - **WAF realism (aiag4):** with AWSManagedRulesCommonRuleSet deployed, `EC2MetaDataSSRF_QUERYARGUMENTS` would match. Showing it in `nonTerminatingMatchingRules` (COUNT mode) is more realistic than "managed rule groups did not match".
  - **Native card missing:** WAF rows render from flattened raw (`native: null`).
  - **Editorial descriptions (aiag8, aiag9):** "collection without judgement", "without deciding". They are acceptable as teaching but lean toward conclusions.
- **Fixes (optional):**
  - aiag4: add the CRS rule in COUNT mode.
  - Add a canary-token alert row right after aiag9.
  - Add a DB login from 159.89.212.66 using db-reader, or its absence (e.g. a security-group deny).
  - Give WAF a native card.

## ai-copilot-indirect-injection

- **Verdict:** FIX
- **Recognised: 4.**
  - EchoLeak, CVE-2025-32711 (Aim Security, June 2025): zero-click M365 Copilot exfiltration via injected email text and an image URL fetched through the Teams `urlp` proxy. The mechanics are modelled accurately.
  - ATT&CK fit is loose (T1566, T1567).
- **Crypto:** no.
- **Detectable: 2.**
  - Nothing fires. XPIADetected and JailbreakDetected are false, MDO delivered the mail, and Zscaler allowed the traffic.
  - aicp10 shows an admin remediation, but no row shows what triggered it (a user report, a hunt, a DLP hit).
- **End-to-end: 4.**
  - Path: aicp2–aicp4 (three emails from brightline-procurement.com) → aicp6/aicp8 (Copilot reads them plus a labelled file) → aicp7/aicp9 (urlp request carrying base64 data to the sender's domain, within seconds) → aicp10.
  - The decoded payloads ("Q3 payroll total: 4,820,113", "Q3 board deck: revenue 41.2") verify correctly.
  - Missing: other recipients and other users' Copilot sessions (scope is only asserted in aicp10).
- **Log reliability: 3.**
  - **Root cause only in prose (aicp2):** the injection itself ("In Threat Explorer's body preview one paragraph is written as instructions to an AI assistant") is not in any field.
  - **aicp10 native contradiction:** a manual soft delete carries `ThreatTypes: Phish` and `DetectionMethods: Advanced filter`, although the message had no detection.
  - **Egress IP inconsistency:** Copilot `ClientIP` 212.150.61.20 vs Zscaler `clientpublicIP` 192.0.2.150 for the same office egress. Other nexacorp stories use 82.132.31.8.
  - **Null native:** Copilot rows are native null.
  - **ATLAS tags:** ATLAS IDs appear in most descriptions.
- **Fixes:**
  - Add the trigger before aicp10, e.g. a user-reported-phish submission with the body snippet, a Zscaler DLP or custom rule on base64 in urlp `url=` parameters, or a Purview alert.
  - Put the injected paragraph in a field (submission or Threat Explorer preview record).
  - Remove the Phish/Advanced-filter values from aicp10.
  - Align the office egress IP across rows.

## ai-llmjacking-bedrock

- **Verdict:** KEEP
- **Recognised: 5.**
  - Sysdig LLMjacking: GetFoundationModelAvailability, the ValidationException probe, PutUseCaseForModelAccess, CreateFoundationModelAgreement, entitlement, a role-play jailbreak in the prompt, logging deletion, multi-region inference.
  - ATT&CK: T1552.001, T1078.004, T1562.008, T1496.004.
- **Crypto:** no.
- **Detectable: 5.** GitHub secret-scanning (lj_04), GuardDuty (lj_16, lj_17) and AWS Cost Anomaly Detection (lj_18).
- **End-to-end: 4.**
  - Path: lj_01 (AmazonBedrockFullAccess on the CI user = blast radius) → lj_02/lj_03 (approved change and legitimate entitlement as the FP control; excellent) → lj_04 (leak) → lj_05–lj_15 (same AKIA; second IP 178.62.204.77 in us-west-2) → lj_12 (invocation-log content, same requestId as lj_11) → lj_18 (dollar impact).
  - Missing: the committer.
  - Missing: a containment row (key deactivation).
- **Log reliability: 4.**
  - **GuardDuty native mismatches (lj_16, lj_17):** `principalId` AIDAB731C7782564A77BA does not match CloudTrail's AIDAXQ7PL2MD4RVN8HJTB. `geoLocation` is 0/0 in native vs real coordinates in raw. City is "Amsterdam (DigitalOcean)".
  - **Unverified finding types:** check that `Impact:IAMUser/CostHarvesting` and `DefenseEvasion:IAMUser/BedrockLoggingDisabled` exist in GuardDuty's documented list.
  - **Invocation-log timestamp (lj_12):** 01:24:20 vs CloudTrail eventTime 01:23:02 for the same requestId. A small gap, but both are request time.
  - **Region access:** model access was enabled only in us-east-1, but the invocations run in us-west-2 and us-east-2. Cross-region inference profiles also need access in the source region.
  - **Null native:** lj_04 (GitHub), lj_12 (CloudWatch) and lj_18 (Cost Anomaly) have null native.
- **Fixes:**
  - Align the GuardDuty native principalId and geo with raw.
  - Verify the finding types.
  - Add an UpdateAccessKey (Inactive) containment row and a GitHub push/audit row.
  - Either add entitlements in the other regions or note cross-region profile behaviour.
  - Merge with or differentiate from ai-bedrock-key-abuse.

---

## Cross-cutting observations

1. **Raw and native disagree almost everywhere, and the decisive evidence often lives only in raw or prose.**
   - Vendor/product mismatch: CrowdStrike is authored but renders as MDE, with different PIDs.
   - Identifier mismatches between raw and native:
     - Entra userId and initiator ID.
     - UAL OrganizationId 6d1f9a3e vs 74155343.
     - GWS customerId and profileId.
     - Azure subscription 7d3e1b90 vs 6520fe69 in alert IDs.
     - Okta actor.id.
     - GuardDuty principalId and geo.
   - Fields the native card drops: Zscaler `app_status` and `prompt_req`, ServiceNow `work_notes`, MDO attachment hash and originating IP, Copilot SiteUrl.
   - Null native on whole source families: Claude Compliance API, Copilot, Workday, Purview DLP, AOAI, WAF, GitHub, CloudWatch.
   - Trainees who read the native card are missing exactly the fields the investigation hinges on.
2. **The shared Okta template contradicts the stories that use it** (compliance-key-harvest, gemini-drive-sweep).
   - `user.authentication.auth_via_mfa` native always renders Tel Aviv / hot-net / `isProxy: false`, whatever the source IP.
   - `user.session.start` native always has every behaviour NEGATIVE and risk LOW.
   - Session start is logged before MFA, and externalSessionId differs between the two events.
   - Separately, several ATO stories (compliance-key, gemini, aoai-key) have no initial-access evidence: a fresh password plus an approved push from a VPN, with no phishing, AiTM or fatigue rows. The "root cause" step of the investigation is therefore missing.
3. **Several stories have no realistic first alert, and some concepts are duplicated or carried by prose.**
   - No alert in chat-harvest-extension, claude-shared-secret, copilot-indirect-injection or gemini-drive-sweep. The trainee is steered only by authored severity, not by a detection a SOC would actually receive.
   - ai-bedrock-key-abuse and ai-llmjacking-bedrock are the same incident; merge or differentiate them.
   - Many descriptions still state conclusions or ATLAS IDs ("disclosed", "being copied to…", "password is disclosed", "LLM-written").
   - Logic flaws to correct:
     - shadow-chat: the CSV bypass of DLP works the wrong way round.
     - compliance-key: the IP allow-list should have blocked the admin who deletes it.
     - aoai-jailbreak: an external caller IP implies a leaked key, which the story ignores.
     - copilot-oversharing and aoai-key-capacity: alerts reference events that have not happened yet.
