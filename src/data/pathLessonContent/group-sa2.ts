import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content — group "sa2". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_sa2: Record<string, AuthoredPathLesson> = {
  "soc-analyst--containment-basics": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/containment-basics/containment-basics.mp4",
          "caption": "Explainer, Containment Basics · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/containment-basics/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/containment-basics/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/containment-basics/es.vtt" }
          ]
        },
        "title": "Containment is not eradication",
        "body": "When an alert turns out to be a real attack, the natural instinct is to \"fix it\" immediately: kill the malicious process, delete the file, wipe the machine. Skilled analysts resist that instinct. **Containment** is the deliberate act of stopping an incident from getting worse (cutting off an attacker's access, movement, or communication) while preserving the evidence and the system state needed to fully understand and remove the threat afterward. Containment answers \"how do I stop the bleeding right now?\" **Eradication** (removing the malware, closing the vulnerability) and **recovery** (restoring normal service) come after, once the scope is understood.\n\nA useful analogy: a hospital that discovers a patient has a contagious infection does not immediately start surgery. It first moves the patient to an isolation ward, containment, so the infection cannot spread to other patients, and only then runs tests and treats the underlying cause. Acting in the wrong order (treating before isolating) risks the infection spreading further while you are distracted.\n\n### Where containment sits in incident response\n\nNIST Special Publication 800-61 is the U.S. government's foundational guidance on incident handling. **Revision 2** (2012) described a four-phase lifecycle that most SOC teams still use as shorthand: Preparation; Detection and Analysis; Containment, Eradication, and Recovery; and Post-Incident Activity. **Revision 3** (published April 2025) retired that rigid phase model and instead maps incident response activities onto the six functions of the NIST Cybersecurity Framework (CSF) 2.0 (Govern, Identify, Protect, Detect, Respond, and Recover) with containment actions living inside the **Respond** function. Either way you learn it, the principle is identical: contain before you clean up.\n\nAn **IOC**, or Indicator of Compromise, is any observable artifact (an IP address, file hash, domain name, registry key, or command line) that suggests malicious activity occurred. Containment decisions are built around IOCs: you isolate the host that showed the IOC, disable the account tied to it, and block the network indicators associated with it. The rest of this lesson walks through the three containment actions a Tier-1/Tier-2 analyst is most often trusted to execute directly: isolating a host, disabling an account, and blocking an IOC at the network edge.",
        "codeExample": "flowchart TD\n    A[Alert confirmed as True Positive] --> B{Is the threat still active?}\n    B -- Yes --> C[CONTAIN: isolate host / disable account / block IOC]\n    B -- No --> D[Skip to scoping]\n    C --> E[ERADICATE: remove malware, patch, reset creds]\n    E --> F[RECOVER: restore service, monitor]\n    F --> G[POST-INCIDENT: lessons learned]",
        "keyPoints": [
          "Containment stops an incident from spreading; eradication removes the cause; recovery restores service: they happen in that order.",
          "NIST SP 800-61r2's 4-phase lifecycle: Preparation, Detection and Analysis, Containment/Eradication/Recovery, Post-Incident Activity.",
          "NIST SP 800-61r3 (April 2025) maps IR work to the six CSF 2.0 functions instead; containment lives in the Respond function.",
          "An IOC (Indicator of Compromise) is any observable artifact (IP, hash, domain, command line) that drives a containment decision."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Isolating a host",
        "body": "**Host isolation** (also called network containment or network quarantine) cuts a compromised endpoint off from the rest of the network while keeping it powered on and, critically, keeping your monitoring tool connected to it. This is the single most common containment action a SOC analyst performs, because it stops lateral movement and data exfiltration immediately without destroying evidence the way powering off a machine would (powering off loses volatile memory, which can hold decryption keys, injected malware, and active network connections).\n\nAn **EDR** (Endpoint Detection and Response) agent is software installed on a laptop or server that continuously records process, file, registry, and network activity and can also take response actions remotely. Isolation is a built-in EDR response action:\n\n- **CrowdStrike Falcon** calls this **Network Contain**. From the Falcon console you select the host and choose \"Network Contain\"; Falcon deliberately preserves the agent's own connection to the CrowdStrike cloud, so an analyst can keep running live queries and pulling files from the machine even while it is cut off from everything else.\n- **Microsoft Defender for Endpoint** calls the equivalent action **Isolate device**. Full isolation blocks all network communication except to Defender's own cloud service. A variant called **Selective Isolation** additionally allows Outlook, Microsoft Teams, and Skype for Business traffic through, so a user under investigation can still be reached for questions without giving an attacker a fully open host.\n\n### Why isolate instead of shutting down\n\nShutting a machine down destroys RAM contents (volatile memory), any encrypted malware that only exists unpacked in memory, and active network sockets: all valuable forensic evidence. Network isolation keeps the machine running and keeps your EDR agent talking to it, so an analyst or a forensic responder can still pull a memory image, list running processes, or collect files after the isolation is in place. The trade-off: isolation does not stop what the malware does *locally* on the host (a ransomware encryption routine already running will continue), it only stops it from spreading over the network or communicating with an attacker's infrastructure.",
        "codeExample": "# Example: CrowdStrike Falcon host_contain automation call (conceptual)\nPOST /devices/entities/devices-actions/v2?action_name=contain\n{\n  \"ids\": [\"a1b2c3d4e5f60000000000000000001\"]\n}\n# Example: Microsoft Defender for Endpoint isolate machine API\nPOST https://api.securitycenter.microsoft.com/api/machines/{id}/isolate\n{\n  \"Comment\": \"Isolating host after confirmed T1486 ransomware precursor activity\",\n  \"IsolationType\": \"Full\"\n}",
        "keyPoints": [
          "Host isolation (network containment/quarantine) cuts network access while keeping the EDR agent connected for continued investigation.",
          "CrowdStrike Falcon calls it Network Contain; Microsoft Defender for Endpoint calls it Isolate device, with an optional Selective Isolation mode for Outlook/Teams/Skype for Business.",
          "Isolating preserves volatile evidence (memory, active connections) that a hard shutdown would destroy.",
          "Isolation stops network spread and C2 (command-and-control) traffic, but does not stop local malicious activity already running on the host."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Disabling and resetting compromised accounts",
        "body": "When the evidence points to a stolen or misused set of credentials rather than (or in addition to) a compromised endpoint, the containment action shifts from the host to the identity. Two related but different actions matter here, and analysts should understand why they are not interchangeable.\n\n**Disabling the account** (in Active Directory, the PowerShell cmdlet is Disable-ADAccount) immediately blocks any new sign-in with that account. Windows logs this as **Event ID 4725, \"A user account was disabled\"** on the domain controller's Security log. Disabling is fast, reversible, and does not require the legitimate user to do anything.\n\n**Resetting the password** (Event ID 4724, \"An attempt was made to reset an account's password\") changes the credential, but it has an important gap: it does **not** invalidate sessions or tokens the attacker may have already obtained. A signed-in web session, an OAuth refresh token, or an active Kerberos ticket can all continue to work even after the password changes, because those artifacts were issued *before* the reset and are not automatically checked against the new password. This is why, in cloud identity platforms like Azure AD / Entra ID, containment playbooks explicitly call for **revoking sessions and refresh tokens** (for example, via Revoke-AzureADUserAllRefreshToken) in addition to, not instead of, a password reset.\n\n### Putting it together\n\nA thorough identity-side containment response for a confirmed compromised account looks like this: disable the account (or at minimum force sign-out everywhere), revoke active sessions and tokens, reset the password to a new value the attacker never possessed, and only then re-enable the account once eradication is complete. Disabling first prevents the attacker from beating you to a re-authentication while you are still working the reset. Skipping straight to \"just reset the password\" is one of the most common containment mistakes new analysts make, because it feels complete but leaves live sessions untouched.",
        "codeExample": "# Disable a compromised on-prem AD account\nDisable-ADAccount -Identity jsmith\n\n# Force sign-out of all active sessions and refresh tokens in Entra ID\nRevoke-AzureADUserAllRefreshToken -ObjectId \"jsmith@nexacorp.example\"\n\n# KQL: confirm the disable landed by finding Event ID 4725\nSecurityEvent\n| where EventID == 4725\n| where TargetAccount has \"jsmith\"\n| project TimeGenerated, Computer, TargetAccount, SubjectAccount",
        "keyPoints": [
          "Disable-ADAccount blocks new sign-ins immediately and logs Windows Event ID 4725 (a user account was disabled).",
          "A password reset alone (Event ID 4724) does not invalidate already-issued sessions, tokens, or Kerberos tickets.",
          "Cloud identity containment must explicitly revoke sessions/refresh tokens (e.g. Revoke-AzureADUserAllRefreshToken), not just change the password.",
          "Full identity containment order: disable/force sign-out, revoke sessions and tokens, reset password, re-enable only after eradication."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Blocking indicators at the network edge",
        "body": "The third core containment lever is blocking the **IOCs** (Indicators of Compromise) themselves (the IP addresses, domains, and file hashes tied to the attack) so that even a host you have not yet found cannot reach the attacker's infrastructure, and a file you have not yet removed cannot re-execute.\n\n### Where blocks get applied\n\n- **Firewall / proxy block lists**: adding an attacker IP or domain to a deny rule stops any host on the network from establishing that connection, which is valuable when you suspect other machines may be compromised but have not confirmed which ones.\n- **DNS sinkholing**: redirecting a malicious domain to a non-routable or monitored address at the internal DNS resolver level. This has a useful side effect. Any host that still tries to resolve the sinkholed domain after the block is a strong signal that it is still infected, giving you a free detection mechanism.\n- **EDR-level hash and IOC blocking**: both CrowdStrike Falcon (via its IOC management feature) and Microsoft Defender for Endpoint (via custom indicators) allow you to add a file hash, IP, or domain to a block list that is enforced directly on every managed endpoint, independent of the network path.\n\n### Short-lived vs. long-lived blocks\n\nNot every block should be permanent. A block on a throwaway phishing domain that will be abandoned by the attacker within days provides diminishing value the longer it sits in a firewall rule set, and stale rules accumulate as technical debt that later analysts have to untangle. A best practice is to record *why* a block exists and *when* it should be reviewed, so temporary containment measures do not silently become permanent, undocumented policy. Contrast this with a hash for a known commodity malware family. That block often stays in place indefinitely because the same hash may reappear in unrelated future incidents.\n\nBlocking IOCs is deliberately the weakest containment measure on its own: attackers rotate infrastructure quickly, so it should always be paired with host isolation and identity containment rather than relied on alone.",
        "codeExample": "# Example firewall deny rule (conceptual, vendor-neutral syntax)\ndeny ip any host 203.0.113.45 log\ndeny dns-query domain secure-login-update.example log\n\n# Microsoft Defender for Endpoint custom indicator (block a hash)\nPOST https://api.securitycenter.microsoft.com/api/indicators\n{\n  \"indicatorValue\": \"8f14e45fceea167a5a36dedd4bea2543\",\n  \"indicatorType\": \"FileSha256\",\n  \"action\": \"Block\",\n  \"title\": \"Confirmed malicious dropper hash - INC-2044\"\n}",
        "keyPoints": [
          "Blocking IOCs (IPs, domains, hashes) at the firewall, DNS resolver, or EDR level stops known-bad infrastructure from being reached even before every affected host is found.",
          "DNS sinkholing a malicious domain gives a bonus detection: any host still resolving it afterward is likely still infected.",
          "Blocks should be documented with a reason and review date: attacker infrastructure rotates, and stale rules become technical debt.",
          "IOC blocking is the weakest containment layer alone and should always be paired with host isolation and identity containment."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Short-term vs. long-term containment strategy",
        "body": "SANS, a well-known information security training organization, popularized a six-stage incident handling model often abbreviated **PICERL**: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned. Within the Containment stage, PICERL draws a distinction that is easy to skip past but genuinely changes what an analyst should do first.\n\n### Short-term containment\n\nThe immediate action taken to stop active damage: the network isolation, account disable, or IOC block covered in the previous three pages. Short-term containment is fast and reversible, and its goal is simply \"stop it from getting worse right now\" while investigation continues in parallel.\n\n### Long-term containment\n\nA more deliberate, often temporary fix applied while a permanent remediation is prepared, for example, moving a compromised server behind a stricter firewall segment and applying a vendor's temporary mitigation for a vulnerability while waiting for an official patch, rather than leaving the box fully isolated (and therefore unusable) for the weeks it might take to schedule a full rebuild. Long-term containment tries to balance \"keep the business running\" against \"keep the attacker out,\" which short-term containment does not need to worry about.\n\n### The forensic backup step\n\nBetween short-term containment and eradication, PICERL calls out an easily-missed step: take a forensic image or system backup of the affected host **before** eradication begins. Once you wipe a machine or delete the malware, you lose the ability to answer questions that come up later (how did the malware persist, what else did it touch), and you lose material a legal or regulatory process might require. A backup taken post-containment but pre-eradication preserves that evidence cheaply, while the short-term containment measure (isolation) keeps the live host safe to leave running for a little longer if the backup takes time.\n\n### Why order matters\n\nDoing eradication before containment (e.g., deleting a malicious file while the host is still connected to the network) risks the attacker simply re-deploying through the same open access. Doing containment without ever getting to eradication leaves a permanently isolated, unusable machine. The sequence (contain, preserve evidence, eradicate, recover) protects both the investigation and the business.",
        "codeExample": "flowchart LR\n    A[Short-term containment\\nisolate / disable / block] --> B[Forensic backup\\nbefore any cleanup]\n    B --> C[Eradication\\nremove malware, patch, reset creds]\n    C --> D[Recovery\\nrestore service, monitor]\n    D --> E[Long-term fix\\napplied if short-term isolation\\nwas only a stopgap]",
        "keyPoints": [
          "SANS PICERL: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.",
          "Short-term containment stops active damage immediately (isolate/disable/block); long-term containment is a deliberate interim fix while a permanent remediation is scheduled.",
          "Take a forensic image or backup of the host after short-term containment but before eradication, so cleanup does not destroy evidence.",
          "Skipping the containment-before-eradication order risks the attacker re-establishing access through a path that was never closed."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Containment mistakes that hurt an investigation",
        "body": "Containment actions are powerful and fast to execute, which is exactly why they are also easy to get wrong. A few recurring mistakes cost real investigations their most valuable evidence or, in the opposite direction, cost the business unnecessary downtime.\n\n### Killing the process too early\n\nTerminating a malicious process the moment it is spotted feels productive, but it destroys the process's memory space, which may be the only place a fileless payload or an in-memory decryption key ever existed. Whenever practical, capture a memory dump or at least record the running process's details (command line, parent process, loaded modules) before killing it.\n\n### Isolating before you understand scope\n\nIf an attacker is actively communicating with a command-and-control (**C2**) server, isolating the very first compromised host you find can tip them off that they have been discovered, causing them to accelerate destructive actions (like triggering ransomware early) on other hosts you have not yet identified. In active, multi-host intrusions, this is sometimes deliberately weighed against a short delay to map scope first: a judgment call that should involve a Tier-2/Tier-3 analyst or IR lead, not a Tier-1 analyst acting alone.\n\n### Not documenting the action\n\nA containment action that is not logged (who did it, when, why, what evidence supported it) breaks the **chain of custody** (the documented trail proving evidence was handled properly) and makes it hard for the next analyst on shift, or a later legal/regulatory review, to reconstruct what happened. Every containment action belongs in the incident ticket with a timestamp and justification, even when it felt \"obvious\" at the time.\n\n### Over-containment\n\nIsolating a shared production server (a domain controller, a database used by dozens of applications) without warning the business can cause an outage far more costly than the original alert. Containment decisions on shared, high-impact infrastructure should involve IT operations and, where relevant, business stakeholders before execution, not as an afterthought after the outage ticket comes in.",
        "codeExample": "# Minimum containment log entry template for the incident ticket\nAction: Network-isolated host WKS-4471 (CrowdStrike Falcon Network Contain)\nTimestamp: 2026-09-28T14:32:00Z\nPerformed by: analyst.t1@nexacorp.example\nJustification: Confirmed rundll32 LSASS memory access (T1003.001) at 14:28Z,\n  consistent with active credential theft. Escalated to T2 per playbook IR-07.\nEvidence preserved before action: process command line + parent PID captured\n  via EDR console at 14:29Z (see attached screenshot INC-2044-01.png).",
        "keyPoints": [
          "Capture process details or a memory dump before killing a malicious process, since termination destroys in-memory evidence.",
          "Isolating too early in a multi-host intrusion can tip off an attacker and trigger accelerated destructive actions elsewhere.",
          "Undocumented containment actions break the chain of custody and hinder later analysts, legal, or regulatory review.",
          "Containment on shared or high-impact infrastructure needs coordination with IT/business stakeholders to avoid a self-inflicted outage."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Worked example: a ransomware precursor at NexaCorp",
        "body": "Put the pieces together with a single scenario. NexaCorp's EDR fires an alert on workstation WKS-4471: a process named rundll32.exe, spawned by an Office document, is accessing lsass.exe's memory with the access mask 0x1FFFFF, a strong indicator of credential dumping (covered in more detail in the lesson on mapping alerts to ATT&CK). Ten minutes later, the SIEM shows the same user account, jsmith, successfully authenticating to two other workstations it has never touched before.\n\n### Step through the containment decision\n\n1. **Scope first, briefly.** Before isolating WKS-4471, a quick pivot on the jsmith account shows exactly two other hosts touched, not fifty. This is small enough to contain all three hosts roughly at once rather than alerting the attacker by isolating just one and waiting.\n2. **Contain the hosts.** Network-isolate WKS-4471 and the two newly-touched workstations using the EDR's containment action, preserving live connectivity for the investigation team.\n3. **Contain the identity.** Disable the jsmith account (Event ID 4725 will confirm it), and revoke any active cloud sessions/tokens if jsmith also has cloud access, since the credential may have been reused there too.\n4. **Block the IOC.** If the initial Office document phoned home to a delivery domain, add that domain to the DNS sinkhole and the EDR's block list, so any other host that received the same phishing email cannot connect out.\n5. **Preserve evidence, then eradicate.** Take a forensic image of WKS-4471 (the patient zero host) before removing the dropper and resetting jsmith's password.\n6. **Document everything** in the incident ticket, including the ATT&CK technique IDs involved (T1003.001 Credential Access, T1078 Valid Accounts if the stolen credential was reused for lateral movement).\n\nThis sequence (scope, contain host, contain identity, block IOC, preserve, eradicate) is the pattern this lesson has been building toward, applied end to end.",
        "codeExample": "flowchart TD\n    A[EDR alert: rundll32 accessing lsass.exe\\nGrantedAccess 0x1FFFFF on WKS-4471] --> B[Pivot on account jsmith:\\n2 other hosts touched]\n    B --> C[Network-isolate all 3 hosts]\n    C --> D[Disable jsmith + revoke cloud sessions]\n    D --> E[Sinkhole/block delivery domain]\n    E --> F[Forensic image of WKS-4471]\n    F --> G[Eradicate dropper, reset credentials]\n    G --> H[Document in ticket with ATT&CK IDs]",
        "keyPoints": [
          "A brief scoping pivot before isolating can reveal whether you are dealing with one host or several, changing how you sequence containment.",
          "Host containment and identity containment usually need to happen together when a credential-theft technique is involved.",
          "IOC blocking (the delivery domain) protects hosts you have not yet identified as affected.",
          "A forensic image taken before eradication preserves the evidence trail for later review."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Verifying containment and handing off",
        "body": "Taking a containment action is not the end of the job: an analyst must confirm it actually worked and hand off cleanly to whoever picks up eradication and recovery.\n\n### Verifying the action succeeded\n\nEvery containment tool can fail silently: an isolation command can be issued while the endpoint is offline and only apply once it reconnects; a firewall block can be misconfigured; an account disable can be undone automatically by a sync job pulling from an authoritative HR system. Always confirm:\n\n- The EDR console shows the host's status as **Contained/Isolated**, not just \"action requested.\"\n- A follow-up query (for example, the KQL query for Event ID 4725 shown earlier) confirms the account disable actually logged.\n- A test connection attempt (or absence of new traffic in the logs) confirms the IOC block is enforced.\n\n### Deciding whether to escalate\n\nTier-1 analysts are generally authorized to take fast, reversible containment actions (isolating a single host, disabling a single account, blocking a single IOC) under a documented playbook. Escalation to Tier-2/Tier-3 or a formal incident response lead becomes appropriate when: multiple hosts or a shared/critical system are involved, the action is not easily reversible, business stakeholders need to be looped in, or the scope is still unclear enough that a scoping decision (like the one in the worked example) carries real risk either way. When in doubt, contain what is safe to contain immediately and escalate the broader decision rather than waiting.\n\n### Handoff content\n\nA clean handoff to the incident response or Tier-2 team includes: what was contained and when, what evidence was preserved beforehand, what verification was performed, and what remains open (eradication, recovery, root-cause). This is the same information that later feeds the verdict and closing documentation covered in the lesson on verdict workflows. Containment done well makes every later step of the incident faster.",
        "codeExample": "# Post-containment verification checklist (paste into ticket)\n[ ] EDR console confirms host state = Contained (not just \"requested\")\n[ ] KQL/SIEM query confirms Event ID 4725 (account disabled) logged\n[ ] IOC block confirmed enforced (test query shows no new traffic to indicator)\n[ ] Evidence preserved (process detail / memory image / forensic backup) BEFORE any cleanup\n[ ] Escalation decision documented: contained-and-closed vs. escalated-to-T2 (reason: ____)",
        "keyPoints": [
          "Always verify a containment action actually applied: isolation, disable, and block commands can fail silently.",
          "Tier-1 analysts typically handle fast, reversible, single-host/single-account containment under playbook; multi-host or hard-to-reverse actions merit escalation.",
          "A complete handoff states what was contained, what evidence was preserved, what was verified, and what remains open.",
          "Solid containment documentation is the foundation the later verdict and closing report will build on."
        ]
      }
    ],
    "quiz": [
      {
        "question": "An analyst confirms a workstation is compromised and wants to stop the attacker's access without losing volatile evidence like running processes and memory. Which action best fits this goal?",
        "options": [
          {
            "label": "Shut the machine down immediately to stop all activity",
            "value": "a"
          },
          {
            "label": "Network-isolate the host while leaving the EDR agent connected",
            "value": "b"
          },
          {
            "label": "Delete the suspicious file and let the host keep running normally",
            "value": "c"
          },
          {
            "label": "Reset the logged-on user's password and take no other action",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Network isolation (CrowdStrike's Network Contain or Microsoft Defender for Endpoint's Isolate device) cuts the host off from the rest of the network while keeping the EDR agent's own connection alive, so evidence like memory and process state stays intact for investigation. Shutting the machine down destroys volatile memory, deleting the file alone does not stop network spread, and a password reset does not address the endpoint at all."
      },
      {
        "question": "Why is resetting a compromised user's password alone often insufficient as a containment action?",
        "options": [
          {
            "label": "Password resets are logged with the wrong event ID and go unnoticed",
            "value": "a"
          },
          {
            "label": "Active sessions and tokens issued before the reset can still be valid afterward",
            "value": "b"
          },
          {
            "label": "Password resets require the user to be physically present",
            "value": "c"
          },
          {
            "label": "Active Directory blocks password resets during an active incident",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A password reset changes the credential going forward, but sessions, OAuth refresh tokens, or Kerberos tickets issued before the reset were not tied to a live password check and can keep working. Containment playbooks pair a reset with explicitly revoking sessions/tokens (e.g. Revoke-AzureADUserAllRefreshToken). The other options are not accurate reasons."
      },
      {
        "question": "During a confirmed incident, in what order should containment, evidence preservation, and eradication generally happen?",
        "options": [
          {
            "label": "Eradicate first, then contain, then preserve evidence",
            "value": "a"
          },
          {
            "label": "Contain first, preserve evidence, then eradicate",
            "value": "b"
          },
          {
            "label": "Preserve evidence first, then eradicate, then contain",
            "value": "c"
          },
          {
            "label": "All three should always happen at exactly the same moment",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The standard sequence is to contain the threat first (stop it from spreading), take a forensic image or backup before any cleanup, and only then eradicate. Eradicating before containing risks the attacker simply re-establishing access through a path that is still open, and eradicating before preserving evidence destroys material needed for later analysis."
      },
      {
        "question": "A SOC finds a malicious domain used by a phishing campaign and redirects internal DNS lookups for it to a monitored address instead of blocking it outright at the firewall. What extra benefit does this technique (DNS sinkholing) provide over a simple firewall block?",
        "options": [
          {
            "label": "It permanently removes the domain from the internet",
            "value": "a"
          },
          {
            "label": "It reveals which hosts are still trying to resolve the domain, flagging likely-infected machines",
            "value": "b"
          },
          {
            "label": "It automatically disables the account of any user who clicked the phishing link",
            "value": "c"
          },
          {
            "label": "It is the only method that works against encrypted HTTPS traffic",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Sinkholing redirects DNS resolution to a monitored destination, so any host that still queries the malicious domain after the sinkhole is in place is very likely still infected, giving the SOC a bonus detection mechanism for finding hosts it hasn't identified yet. It does not remove the domain from the internet, does not touch account state, and is not specific to HTTPS."
      },
      {
        "question": "A Tier-1 analyst notices a confirmed malicious process running on a shared production database server used by many business applications. What is the most appropriate next step?",
        "options": [
          {
            "label": "Immediately isolate the server without notifying anyone, since speed matters most",
            "value": "a"
          },
          {
            "label": "Ignore the finding since production servers should never be touched",
            "value": "b"
          },
          {
            "label": "Coordinate with IT operations/business stakeholders before containing, given the shared, high-impact nature of the system",
            "value": "c"
          },
          {
            "label": "Wait until the next shift to avoid making any decision",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Containment on shared, high-impact infrastructure can cause a costly outage if done without coordination, so best practice is to loop in IT operations and relevant business stakeholders before acting, or escalate the decision to Tier-2/IR leadership. Acting alone without warning risks over-containment; ignoring the finding or delaying to the next shift both leave an active threat unaddressed."
      }
    ]
  },
  "soc-analyst--tactics-and-techniques": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/tactics-and-techniques/tactics-and-techniques.mp4",
          "caption": "Explainer, MITRE ATT&CK: Tactics & Techniques · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/tactics-and-techniques/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/tactics-and-techniques/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/tactics-and-techniques/es.vtt" }
          ]
        },
        "title": "A shared language for attacker behavior",
        "body": "Before a common framework existed, two SOC analysts describing the same intrusion might use completely different words: \"they hacked in through email,\" \"there was a malware infection,\" \"the attacker moved around the network.\" None of those phrases are wrong, but none of them are precise enough to compare across incidents, build detections from, or hand off cleanly between shifts. **MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) solves that problem. It is a free, globally-used knowledge base, maintained by the MITRE Corporation, that catalogs real-world adversary behavior observed in actual intrusions and organizes it into a consistent structure.\n\nThink of ATT&CK as a shared vocabulary: the way a standardized medical coding system (like ICD-10 for diagnoses) lets any two hospitals describe the same condition the same way, ATT&CK lets any two SOC analysts, anywhere in the world, describe \"the attacker used a scheduled task to persist\" using the exact same identifier, no matter which product or vendor's alert generated the observation.\n\n### The three matrix domains\n\nATT&CK is organized into separate matrices for different environments, because the behaviors that matter differ by platform:\n\n| Domain | Covers |\n|---|---|\n| **Enterprise** | Windows, macOS, Linux, cloud (Azure AD, AWS, GCP, SaaS), network, containers, the matrix a SOC analyst uses day to day |\n| **Mobile** | Android and iOS-specific adversary behavior |\n| **ICS** | Industrial Control Systems. Behaviors specific to operational technology environments like SCADA |\n\nThis lesson, and the rest of this module, focuses on the **Enterprise matrix**, since that is what nearly every SOC alert and SIEM detection maps against. The Enterprise matrix is built from two connected layers: **tactics**, which describe an attacker's *goal* at a given moment, and **techniques** (with **sub-techniques**), which describe *how* that goal is achieved. The next two pages cover each layer in depth.",
        "codeExample": "flowchart LR\n    A[\"Raw alert text:<br/>suspicious PowerShell activity\"] --> B[\"ATT&CK mapping:<br/>TA0002 Execution\"]\n    B --> C[\"Technique:<br/>T1059 Command and Scripting Interpreter\"]\n    C --> D[\"Sub-technique:<br/>T1059.001 PowerShell\"]",
        "keyPoints": [
          "MITRE ATT&CK is a free knowledge base of real-world adversary behavior, maintained by the MITRE Corporation.",
          "It gives SOC analysts a shared, precise vocabulary instead of vague descriptions like 'they hacked in.'",
          "ATT&CK has three matrix domains: Enterprise, Mobile, and ICS (Industrial Control Systems); this lesson focuses on Enterprise.",
          "The Enterprise matrix is built from tactics (the attacker's goal) and techniques/sub-techniques (how the goal is achieved)."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Tactics: the attacker's 'why'",
        "body": "A **tactic** answers the question \"what was the attacker trying to accomplish at this step?\" Tactics are the columns of the Enterprise matrix, and each one has a stable ID prefixed **TA**. As of the current Enterprise matrix (ATT&CK v19, April 2026), there are **15 tactics**:\n\n| ID | Tactic | Attacker's goal |\n|---|---|---|\n| TA0043 | Reconnaissance | Gather information to plan future operations |\n| TA0042 | Resource Development | Establish resources (infrastructure, accounts, malware) to support operations |\n| TA0001 | Initial Access | Get an initial foothold into the network |\n| TA0002 | Execution | Run malicious code |\n| TA0003 | Persistence | Maintain access across restarts, credential changes, etc. |\n| TA0004 | Privilege Escalation | Gain higher-level permissions |\n| TA0005 | Stealth | Avoid detection by hiding or blending in |\n| TA0112 | Defense Impairment | Disable or degrade security tools, logging, and other defenses |\n| TA0006 | Credential Access | Steal account names and passwords |\n| TA0007 | Discovery | Learn about the environment |\n| TA0008 | Lateral Movement | Move through the environment to other systems |\n| TA0009 | Collection | Gather data of interest |\n| TA0011 | Command and Control (C2) | Communicate with compromised systems |\n| TA0010 | Exfiltration | Steal data out of the network |\n| TA0040 | Impact | Manipulate, interrupt, or destroy systems and data |\n\nUntil ATT&CK v18 there were 14 tactics: Stealth and Defense Impairment were a single tactic, Defense Evasion (TA0005). v19 split it because hiding from defenders and breaking the defenses are different goals, and the second is a much louder act. Stealth kept the TA0005 ID; Defense Impairment is new. Older reports and some vendor consoles still show \"Defense Evasion\", so expect to translate.\n\n### Left-to-right is a guide, not a rule\n\nThe matrix orders tactics roughly in the sequence a typical intrusion progresses (reconnaissance and initial access on the left, impact on the right) which is genuinely useful for building intuition. But ATT&CK explicitly does not require attackers to move through tactics in strict order, and it is common for an intrusion to revisit an earlier tactic multiple times (an attacker might use Discovery, then Lateral Movement, then Discovery again on the new host, then Credential Access, then Lateral Movement again). Treat the tactic ordering as a mental map of \"what phase is this activity most consistent with,\" not a checklist an attacker is obligated to follow in sequence.",
        "codeExample": "# Fifteen Enterprise tactic IDs (ATT&CK v19), in matrix order\nTA0043 Reconnaissance        TA0042 Resource Development\nTA0001 Initial Access        TA0002 Execution\nTA0003 Persistence           TA0004 Privilege Escalation\nTA0005 Stealth               TA0112 Defense Impairment\nTA0006 Credential Access     TA0007 Discovery\nTA0008 Lateral Movement      TA0009 Collection\nTA0011 Command and Control   TA0010 Exfiltration\nTA0040 Impact",
        "keyPoints": [
          "A tactic describes the attacker's goal at a given step (the 'why'); tactics have stable IDs prefixed TA.",
          "The Enterprise matrix has 15 tactics (v19), from TA0043 Reconnaissance through TA0040 Impact; v19 split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112).",
          "The left-to-right ordering roughly follows a typical intrusion's progression but is not a required sequence.",
          "Real intrusions frequently revisit earlier tactics (e.g. Discovery again after Lateral Movement to a new host)."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Techniques and sub-techniques: the attacker's 'how'",
        "body": "If a tactic is the goal, a **technique** is the specific method used to achieve it, and it carries a stable ID prefixed **T** (for example, T1059). Many techniques are further broken down into **sub-techniques**, written with a dot suffix (T1059.001), which describe a more specific implementation of the parent technique.\n\n### Worked example: T1059 Command and Scripting Interpreter\n\nT1059 covers an attacker abusing a command or scripting interpreter to execute code, a very broad behavior on its own. Its sub-techniques narrow that down to the specific interpreter abused:\n\n- **T1059.001. PowerShell**: using Windows PowerShell to run commands or scripts, often with the -EncodedCommand flag to obfuscate the payload\n- **T1059.003. Windows Command Shell**: using cmd.exe\n- **T1059.005, Visual Basic**: using VBA macros or VBScript, commonly seen in malicious Office document attachments\n\nWhen you can identify the specific interpreter involved, mapping to the sub-technique (T1059.001) is more precise and more useful than stopping at the parent technique (T1059) alone. It tells the next analyst exactly what to look for.\n\n### One technique, multiple tactics\n\nA single technique can map to more than one tactic, because the same attacker action can serve more than one goal simultaneously. **T1053 Scheduled Task/Job** is a clear example: creating a scheduled task can be used to *execute* code right now (Execution), to make sure that code *keeps running* after a reboot (Persistence), and (if the task runs with SYSTEM privileges) to *escalate* the attacker's access level (Privilege Escalation). ATT&CK's own technique page for T1053 lists all three tactics, and a good mapping should acknowledge whichever ones actually apply to the observed behavior rather than arbitrarily picking just one.\n\n### Procedures: how real groups actually did it\n\nBelow techniques sit **procedures**, the specific, real-world implementation used by a named threat actor or malware family, documented on ATT&CK's Groups and Software pages. For example, the technique T1003.001 (OS Credential Dumping: LSASS Memory) has documented procedure examples showing specific APT groups using the tool Mimikatz to perform exactly that technique. Procedures are the most concrete layer: tactic (why) → technique/sub-technique (how, generically) → procedure (how, specifically, by whom).",
        "codeExample": "# T1053 Scheduled Task/Job, one technique, three tactics\nTactic: TA0002 Execution (the task runs code now)\nTactic: TA0003 Persistence (the task re-runs after reboot/logon)\nTactic: TA0004 Privilege Escalation (if the task runs as SYSTEM)\n\n# T1059 sub-techniques (a sample)\nT1059.001 PowerShell\nT1059.003 Windows Command Shell\nT1059.005 Visual Basic",
        "keyPoints": [
          "A technique (prefixed T) is the specific method used to achieve a tactic's goal; sub-techniques (T1059.001) narrow it further.",
          "T1059 Command and Scripting Interpreter breaks into sub-techniques like T1059.001 PowerShell and T1059.005 Visual Basic.",
          "A single technique can map to multiple tactics at once: T1053 Scheduled Task/Job maps to Execution, Persistence, and Privilege Escalation.",
          "Procedures document how a specific real-world group or malware family implemented a technique, adding concrete detail beneath it."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Reading the matrix and the Navigator",
        "body": "The Enterprise ATT&CK matrix, viewed on MITRE's website, is a large table: each column is a tactic, and the technique names listed under that column are techniques associated with that tactic. Clicking any technique opens its dedicated page, which lists its ID, a full description, associated sub-techniques, detection guidance, mitigation guidance, and documented procedure examples from real intrusions.\n\n### ATT&CK Navigator\n\nReading the raw matrix is useful for learning, but SOC teams typically work with **ATT&CK Navigator**, a free web-based tool (also self-hostable) that lets you build and visualize \"layers\" on top of the matrix. A layer is essentially a colored overlay: you might build a layer showing every technique a specific ransomware group has been observed using, or a layer showing which techniques your organization currently has detection coverage for (this second use case, building coverage heatmaps, is the subject of a later lesson in this module).\n\n### Groups and Software pages\n\nAlongside the matrix, ATT&CK maintains two other catalogs that a SOC analyst will run into constantly during threat intelligence work:\n\n- **Groups**, each with a **G**-prefixed ID (for example, G0016 for APT29), documenting a named threat actor and every technique ATT&CK has evidence they have used.\n- **Software**, each with an **S**-prefixed ID, documenting a specific tool or malware family (commodity tools like Mimikatz and Cobalt Strike, or malware families) and the techniques it implements.\n\nA threat intelligence report that says \"this activity is consistent with G0016\" is really saying \"cross-reference this group's technique list on ATT&CK, and expect the sub-techniques documented there.\" Learning to navigate between the matrix, technique pages, and group/software pages is a core research skill, not a one-time thing to memorize, even experienced analysts look techniques up constantly rather than relying on memory for exact IDs.",
        "codeExample": "# ATT&CK Navigator layer (conceptual JSON structure)\n{\n  \"name\": \"NexaCorp - Ransomware Precursor Group Coverage\",\n  \"domain\": \"enterprise-attack\",\n  \"techniques\": [\n    { \"techniqueID\": \"T1003.001\", \"color\": \"#31a354\", \"comment\": \"Detected via Sysmon EID 10\" },\n    { \"techniqueID\": \"T1059.001\", \"color\": \"#e6550d\", \"comment\": \"No PowerShell script block logging yet\" },\n    { \"techniqueID\": \"T1053.005\", \"color\": \"#31a354\", \"comment\": \"Detected via scheduled task creation alert\" }\n  ]\n}",
        "keyPoints": [
          "The Enterprise matrix's columns are tactics; the techniques listed under each column belong to that tactic.",
          "ATT&CK Navigator is a free tool for building color-coded 'layers' over the matrix, such as a group's known techniques or an org's detection coverage.",
          "Groups (G-prefixed IDs, e.g. G0016 APT29) and Software (S-prefixed IDs) document real threat actors and tools and the techniques they use.",
          "Analysts routinely look up technique/group IDs rather than memorizing them, knowing how to navigate the framework matters more than rote recall."
        ]
      },
      {
        "pageNumber": 5,
        "title": "How SOC analysts use ATT&CK day to day",
        "body": "Learning the theory of tactics and techniques only pays off once it becomes part of daily triage work. A few concrete ways ATT&CK shows up on the job:\n\n### Tagging alerts and tickets with technique IDs\n\nMany EDR and SIEM platforms already tag their own detections with technique IDs, for example, CrowdStrike Falcon detections include Tactic and Technique fields, and Microsoft Defender's alerts list associated MITRE technique IDs. Even when a platform does not auto-tag an alert, an analyst adding the relevant technique ID to the incident ticket (as introduced in the containment-basics lesson's worked example) turns a one-off note into structured, searchable data: six months later, someone can query \"how many incidents this quarter involved T1566.001\" and get a real answer.\n\n### Reading and writing threat intelligence\n\nVendor and government threat reports (CISA advisories, vendor blog write-ups) routinely cite technique IDs directly in their text: \"the actor gained initial access via T1566.002 (Spearphishing Link) and established persistence via T1547.001 (Registry Run Keys).\" Being fluent in ATT&CK IDs means an analyst can read that sentence and immediately know what log sources and behaviors to go hunt for, without having to look up what each phrase means from scratch every time.\n\n### Consistent handoffs across shifts and tiers\n\nWhen a Tier-1 analyst escalates to Tier-2 with \"Technique T1003.001 detected via rundll32/lsass access, escalating for scope assessment,\" the receiving analyst instantly knows the technical nature of the finding, its tactic (Credential Access), and can look up detection/mitigation guidance on the technique's ATT&CK page if needed, no matter which analyst wrote the escalation or which shift they were on.\n\nThe next lesson in this module, Mapping alerts to ATT&CK, turns this theory into a practiced skill: given a real EDR or SIEM alert, working through the reasoning to land on the correct technique ID.",
        "codeExample": "# Example escalation note using ATT&CK IDs for precision\nINC-2044: Escalating WKS-4471 to Tier-2.\nTechnique: T1003.001 (OS Credential Dumping: LSASS Memory) - Credential Access\nEvidence: rundll32.exe accessed lsass.exe, GrantedAccess=0x1FFFFF, 14:28Z\nRelated: T1078 (Valid Accounts) suspected - jsmith authenticated to 2 new hosts\n  within 10 minutes of the credential access event.",
        "keyPoints": [
          "Many EDR/SIEM platforms auto-tag detections with ATT&CK technique IDs; analysts should add them manually when a platform does not.",
          "Threat intelligence reports cite technique IDs directly, so fluency in ATT&CK lets an analyst act on a report immediately.",
          "Technique IDs in tickets create structured, queryable data for later metrics (e.g. how many incidents involved a given technique).",
          "ATT&CK IDs make cross-shift and cross-tier handoffs precise regardless of who wrote the original note."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Common misconceptions about ATT&CK",
        "body": "A few misunderstandings come up often enough among new analysts that they are worth addressing directly.\n\n### \"ATT&CK is a strict kill chain\"\n\nATT&CK is frequently compared to the Lockheed Martin Cyber Kill Chain, an earlier and more rigid seven-stage model of an intrusion (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives). ATT&CK's tactics are broader and more numerous (15 vs. 7), and critically, ATT&CK does not assume attackers move through them in strict linear order. As covered on page 2, an intrusion can revisit Discovery or Credential Access multiple times. Treating the matrix as a mandatory sequence leads analysts to expect a \"next step\" that may never come, or to miss activity that occurs \"out of order.\"\n\n### \"Every alert must map cleanly to exactly one technique\"\n\nReal alerts are often ambiguous, especially early in an investigation with limited evidence. Forcing a confident technique mapping onto a vague signal (a slightly unusual login time, for instance) produces false precision that misleads whoever reads the ticket next. It is entirely appropriate to record an alert as \"Suspicious Activity. Insufficient evidence for a specific technique mapping yet\" and revisit the mapping once more evidence is gathered, rather than guessing.\n\n### \"Techniques are the same as detection signatures\"\n\nA technique describes a *behavior* (e.g., \"abusing PowerShell to execute code\"), not a specific signature, file hash, or exact command line. The same technique, T1059.001, can be carried out in thousands of different, superficially unrelated ways. This is precisely why ATT&CK is valuable for behavioral, not purely signature-based, detection thinking: a rule built around the *behavior* pattern (PowerShell launched with obfuscation flags from an unusual parent process) catches many variations that a single-hash signature never would.\n\n### \"ATT&CK covers every possible attacker action\"\n\nATT&CK is a living, community-curated knowledge base built from observed, documented intrusions. It grows and gets revised regularly as new techniques are documented, but it is not, and does not claim to be, an exhaustive theoretical list of every conceivable technique. New sub-techniques and even occasionally new tactics get added as adversary tradecraft evolves and gets documented.",
        "codeExample": "flowchart TD\n    A[\"Alert: unusual login time for jsmith\"] --> B{\"Enough evidence for\\na specific technique?\"}\n    B -- No --> C[\"Record as 'Suspicious Activity'\\nno technique ID forced yet\"]\n    B -- Yes, credential reuse confirmed --> D[\"Map to T1078\\nValid Accounts\"]",
        "keyPoints": [
          "ATT&CK is broader (15 tactics) and non-linear compared to the older, seven-stage Lockheed Martin Cyber Kill Chain.",
          "Not every alert needs, or should be forced into, a confident single technique mapping; ambiguous evidence can stay unmapped until clarified.",
          "A technique describes a behavior pattern, not a specific signature or hash, which is why ATT&CK supports behavioral detection thinking.",
          "ATT&CK is a living, evolving knowledge base of observed intrusions, not an exhaustive theoretical catalog of every possible attack."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Worked example: from raw alert to tactic and technique",
        "body": "Bring the whole chain together with one alert, reasoned through step by step. NexaCorp's EDR generates this raw detection: \"Process created: powershell.exe -enc <base64 string>, parent process: WINWORD.EXE, on host WKS-2210, user rjones.\"\n\n### Step 1: What actually happened, technically?\n\nStrip away interpretation and describe the observable fact: a Microsoft Word process spawned PowerShell with the -EncodedCommand flag (abbreviated -enc), which runs a base64-encoded script, a common technique to hide the true command from casual inspection or simple string-matching defenses, since the readable command only appears after decoding.\n\n### Step 2: What was the attacker likely trying to accomplish?\n\nA Word document spawning PowerShell is not something a normal document does on its own. Word does not need to launch a scripting interpreter to display text or run a macro's built-in functions. This pattern strongly suggests a malicious macro embedded in the document ran and used PowerShell to execute a second-stage payload. The attacker's goal at this specific step is to **run code** on the victim machine. That goal is the tactic **TA0002 Execution**.\n\n### Step 3: Which technique/sub-technique matches the specific method?\n\nThe specific method is abusing a scripting interpreter (that is **T1059 Command and Scripting Interpreter**) and the specific interpreter is PowerShell, giving the precise sub-technique **T1059.001 PowerShell**.\n\n### Step 4: Is there a related technique worth noting?\n\nThe fact that the payload arrived via a Word document at all is itself worth a separate note: if this document arrived by email, the delivery mechanism is a different tactic entirely. **TA0001 Initial Access**, specifically **T1566.001 Phishing: Spearphishing Attachment**, since gaining the initial foothold and executing code once inside are two different goals achieved by two different steps of the same intrusion, each deserving its own technique ID in the ticket.\n\n### The final mapping\n\nTicket note: \"T1566.001 (Spearphishing Attachment, Initial Access) delivered a malicious macro; T1059.001 (PowerShell, Execution) executed the second-stage payload.\" Two technique IDs, two tactics, one coherent story, exactly the kind of mapping the next lesson will practice on more alerts.",
        "codeExample": "flowchart LR\n    A[\"Phishing email with Word attachment\"] -->|\"T1566.001\\nInitial Access\"| B[\"Malicious macro runs\"]\n    B -->|\"T1059.001\\nExecution\"| C[\"powershell.exe -enc <base64>\\nspawned by WINWORD.EXE\"]",
        "keyPoints": [
          "Reasoning from raw alert to technique ID: describe the observable fact, infer the attacker's goal (tactic), then match the specific method (technique/sub-technique).",
          "A Word process spawning PowerShell is a strong behavioral indicator of a malicious macro, mapping to T1059.001 (Execution).",
          "The delivery mechanism (phishing attachment) and the execution step are separate techniques under separate tactics, both worth recording.",
          "A good ticket note states both the technique ID and the tactic it falls under, not just one or the other."
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the core purpose of the MITRE ATT&CK framework for a SOC team?",
        "options": [
          {
            "label": "It provides a shared, precise vocabulary for describing observed adversary behavior",
            "value": "a"
          },
          {
            "label": "It automatically blocks every technique it documents across all connected endpoints",
            "value": "b"
          },
          {
            "label": "It replaces the need to operate a SIEM or EDR platform in the environment",
            "value": "c"
          },
          {
            "label": "It is a mandatory licensing requirement for purchasing any EDR product",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "ATT&CK is a knowledge base that standardizes how adversary behavior is described, so any two analysts can refer to the same activity with the same technique ID rather than vague, inconsistent language. It does not block anything itself, does not replace SIEM/EDR tooling, and is not a licensing requirement. It is a free reference framework."
      },
      {
        "question": "How many tactics does the current MITRE ATT&CK Enterprise matrix define, and what does a tactic represent?",
        "options": [
          {
            "label": "7 tactics, each representing a specific malware family",
            "value": "a"
          },
          {
            "label": "15 tactics, each representing the attacker's goal at a given step",
            "value": "b"
          },
          {
            "label": "10 tactics, each representing a specific tool or piece of software",
            "value": "c"
          },
          {
            "label": "15 tactics, each representing a named threat actor group",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The Enterprise matrix defines 15 tactics as of ATT&CK v19 (from TA0043 Reconnaissance through TA0040 Impact, after Defense Evasion was split into Stealth and Defense Impairment), each describing the attacker's goal at that step, such as Initial Access or Credential Access. Malware families and tools are documented separately as Software; threat actors are documented separately as Groups."
      },
      {
        "question": "The technique T1053 Scheduled Task/Job is documented as mapping to Execution, Persistence, and Privilege Escalation all at once. What does this illustrate about the relationship between techniques and tactics?",
        "options": [
          {
            "label": "A single technique can serve more than one tactic depending on how it is used",
            "value": "a"
          },
          {
            "label": "This is a documentation error that ATT&CK plans to fix",
            "value": "b"
          },
          {
            "label": "Sub-techniques always cancel out their parent technique's tactic",
            "value": "c"
          },
          {
            "label": "Scheduled tasks are no longer considered a valid ATT&CK technique",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "A single technique's real-world use can accomplish more than one goal at the same time, creating a scheduled task can execute code now, survive a reboot, and (if run as SYSTEM) escalate privileges, so ATT&CK legitimately lists all applicable tactics for that technique. This is intentional, not an error, and has nothing to do with sub-technique cancellation."
      },
      {
        "question": "An analyst sees a very ambiguous alert with minimal evidence and is unsure which specific technique it represents. What does this lesson recommend?",
        "options": [
          {
            "label": "Guess the most common technique to keep the ticket moving",
            "value": "a"
          },
          {
            "label": "Leave the alert completely unlabeled and undocumented",
            "value": "b"
          },
          {
            "label": "Record it as suspicious activity without forcing a specific technique mapping until more evidence is gathered",
            "value": "c"
          },
          {
            "label": "Close the alert as a false positive automatically since it cannot be mapped",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Forcing a confident technique mapping onto ambiguous, limited evidence produces false precision that can mislead later reviewers. The recommended approach is to note the activity as suspicious without a forced specific mapping, and revisit once more evidence is available, not guess, ignore, or auto-close it."
      },
      {
        "question": "A Word document spawns powershell.exe with the -EncodedCommand flag. What is the most accurate way to describe this using ATT&CK terminology?",
        "options": [
          {
            "label": "T1566.001 (Phishing) is the only applicable technique for this activity",
            "value": "a"
          },
          {
            "label": "T1059.001 (PowerShell), under the Execution tactic, describes the scripting interpreter abuse observed",
            "value": "b"
          },
          {
            "label": "T1053.005 (Scheduled Task) describes this activity because it involves automation",
            "value": "c"
          },
          {
            "label": "This activity cannot be mapped to ATT&CK because PowerShell is a legitimate Windows tool",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The observed behavior (a scripting interpreter (PowerShell) being abused to run code) matches T1059.001 under the Execution tactic. T1566.001 would only apply to the separate delivery step if the document arrived via phishing email; T1053.005 concerns scheduled tasks, not this activity; and ATT&CK maps legitimate tools when they are abused maliciously, which is exactly what living-off-the-land technique tracking is for."
      }
    ]
  },
  "soc-analyst--mapping-alerts-to-attack": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/mapping-alerts-to-attack/mapping-alerts-to-attack.mp4",
          "caption": "Explainer, Mapping Alerts to ATT&CK · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/mapping-alerts-to-attack/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/mapping-alerts-to-attack/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/mapping-alerts-to-attack/es.vtt" }
          ]
        },
        "title": "Why mapping is a practiced skill, not a lookup",
        "body": "The previous lesson covered what tactics, techniques, and sub-techniques are. This lesson is about the harder, more practical skill: given a real, messy alert from an EDR (Endpoint Detection and Response) console or a SIEM (Security Information and Event Management, a platform that aggregates and correlates logs from across an environment), reasoning your way to the correct technique ID rather than looking one up from a list.\n\n### Why this matters operationally\n\nConsistent mapping across a SOC team produces real, usable metrics: which techniques appear most often in your environment, which ones your detections catch well versus poorly (the subject of the next lesson, Coverage thinking), and which techniques a given threat actor group tends to use against your industry. None of that is possible if every analyst maps loosely or skips the step, because the underlying data becomes inconsistent and unusable. Mapping also makes handoffs faster: a Tier-2 analyst picking up an escalation with \"T1003.001 detected\" already knows the tactic (Credential Access), can pull up the technique's ATT&CK page for detection/mitigation guidance, and does not have to re-derive what happened from scratch.\n\n### A three-step method\n\nEvery worked example in this lesson follows the same repeatable process:\n\n1. **Identify the observable behavior**, strip the alert down to what actually, technically happened (a specific process launched, a specific access pattern, a specific network pattern), separate from any interpretation.\n2. **Ask what goal that behavior serves**: this identifies the tactic.\n3. **Match the specific method to a technique or sub-technique**, using the specificity of the evidence to decide how far down the sub-technique tree you can confidently go.\n\nThe next several pages apply this method to four realistic alert types a Tier-1/Tier-2 analyst encounters regularly: credential dumping, phishing-to-execution, scheduled task persistence, and command-and-control beaconing.",
        "codeExample": "flowchart TD\n    A[Raw alert] --> B[\"Step 1: What actually happened,\\ntechnically?\"]\n    B --> C[\"Step 2: What goal does that\\nbehavior serve? (tactic)\"]\n    C --> D[\"Step 3: Which technique/\\nsub-technique matches the method?\"]\n    D --> E[Document technique ID + tactic in ticket]",
        "keyPoints": [
          "Mapping alerts to ATT&CK is a reasoning skill applied to real, messy evidence, not a lookup exercise.",
          "Consistent mapping across a team enables usable metrics and faster, clearer handoffs between analysts and tiers.",
          "The three-step method: identify the observable behavior, infer the tactic (goal), then match the specific technique/sub-technique.",
          "This lesson applies that method to four realistic alert types: credential dumping, phishing-to-execution, scheduled tasks, and C2 beaconing."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Worked alert 1: LSASS memory access",
        "body": "**The alert.** A CrowdStrike Falcon detection fires: \"Process rundll32.exe (PID 5544) accessed the memory of a process named lsass.exe. GrantedAccess: 0x1FFFFF.\" No file was written, no network connection accompanied it.\n\n### Step 1: the observable behavior\n\n**LSASS** stands for Local Security Authority Subsystem Service, a core Windows process responsible for enforcing security policy and validating logins, which as a side effect holds credential material (password hashes, Kerberos tickets) in its memory for currently or recently logged-on users. rundll32.exe, a legitimate Windows utility normally used to run functions inside DLL files, is opening a memory handle into lsass.exe with the access right 0x1FFFFF: a very broad access mask (essentially \"full access\") that a normal DLL-loading operation has no reason to request. This is the classic fingerprint of a credential-dumping tool reading LSASS's memory to extract stored credentials, often performed by a legitimate-looking process (rundll32.exe invoking comsvcs.dll's MiniDump export is one well-documented, \"living off the land\" way to do this without dropping a separate hacking tool to disk).\n\n### Step 2: the goal\n\nThe attacker is trying to steal account credentials directly from memory. That goal is the tactic **TA0006 Credential Access**.\n\n### Step 3: the technique\n\nThe parent technique is **T1003 OS Credential Dumping**; the specific target (LSASS process memory, as opposed to the SAM registry hive or NTDS.dit) narrows it to the sub-technique **T1003.001 OS Credential Dumping: LSASS Memory**.\n\n### A Sigma rule for this exact pattern\n\nSigma is a vendor-neutral, YAML-based rule format for describing detection logic once and converting it to any SIEM's native query language. A rule for this exact behavior watches Sysmon Event ID 10 (ProcessAccess) for a broad GrantedAccess value targeting lsass.exe:",
        "codeExample": "title: Suspicious Access to LSASS Memory\nid: 4a5f2b6e-79a0-4d7b-9e5b-1c2d3e4f5a6b\nstatus: experimental\nlogsource:\n  category: process_access\n  product: windows\ndetection:\n  selection:\n    TargetImage|endswith: '\\\\lsass.exe'\n    GrantedAccess:\n      - '0x1010'\n      - '0x1410'\n      - '0x1F0FFF'\n      - '0x1FFFFF'\n  condition: selection\nlevel: high\ntags:\n  - attack.credential_access\n  - attack.t1003.001",
        "keyPoints": [
          "LSASS (Local Security Authority Subsystem Service) holds credential material in memory; opening a broad-access handle to it is a classic credential-dumping fingerprint.",
          "rundll32.exe accessing lsass.exe with GrantedAccess 0x1FFFFF maps to T1003.001 OS Credential Dumping: LSASS Memory.",
          "The tactic is TA0006 Credential Access: the attacker's goal is to steal account credentials.",
          "Sigma is a vendor-neutral YAML detection format; rules can tag technique IDs directly (attack.t1003.001) for consistent mapping."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Worked alert 2: document macro to PowerShell",
        "body": "**The alert.** A SIEM correlation rule fires on process-creation telemetry: \"powershell.exe launched with command line containing -EncodedCommand, parent process WINWORD.EXE, on host WKS-2210.\" An email gateway log shows the document, invoice_Q3.docm, was delivered as an email attachment to the user twelve minutes earlier from an external sender.\n\n### Step 1: the observable behavior\n\nTwo separate, chained behaviors are visible here: (1) a document with a macro-enabled extension (.docm) arrived via email from outside the organization, and (2) opening that document caused Microsoft Word to spawn PowerShell with an encoded (base64) command, something a normal document, even one using built-in Word features, has no legitimate reason to do.\n\n### Step 2 and 3: two technique IDs for two steps\n\nBecause two distinct attacker goals are represented, this alert produces **two** technique mappings rather than one, and correctly documenting a multi-stage alert this way (rather than collapsing it into a single ID) is itself a mapping skill:\n\n- **Delivery**: an external email delivering a malicious attachment is **T1566.001 Phishing: Spearphishing Attachment**, under the tactic **TA0001 Initial Access**.\n- **Execution**: Word spawning PowerShell to run a hidden payload is **T1059.001 PowerShell**, a sub-technique of **T1059 Command and Scripting Interpreter**, under the tactic **TA0002 Execution**.\n\n### Why not stop at just one ID\n\nRecording only \"T1566.001\" would miss that code actually ran on the host, a materially more serious fact than delivery alone. Recording only \"T1059.001\" would miss how the attacker got in, which matters for both the immediate response (has this sender/domain sent attachments to other users?) and for longer-term detection engineering (do we need better attachment-macro filtering at the gateway?). Chained alerts like this are common and the right practice is to record every distinct technique the evidence supports, in the order the intrusion actually progressed.",
        "codeExample": "# KQL: correlate the macro-execution chain in Microsoft Defender Advanced Hunting\nDeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| where ProcessCommandLine has \"-EncodedCommand\" or ProcessCommandLine has \"-enc\"\n| where InitiatingProcessFileName =~ \"winword.exe\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine,\n          InitiatingProcessFileName, InitiatingProcessCommandLine",
        "keyPoints": [
          "A single alert can represent more than one distinct attacker action, each deserving its own technique ID.",
          "External email delivering a malicious attachment maps to T1566.001 Phishing: Spearphishing Attachment (Initial Access).",
          "Word spawning PowerShell with an encoded command maps to T1059.001 PowerShell (Execution).",
          "Recording only one ID for a multi-stage alert loses either the delivery context or the execution severity: document each stage."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Worked alert 3: a new scheduled task",
        "body": "**The alert.** Windows event telemetry shows a new scheduled task was registered: \"Task 'WindowsUpdateHelper' created, action runs C:\\Users\\Public\\svc.ps1 at user logon, created by account svc_backup on host SRV-DB01.\" The account svc_backup normally only runs a nightly backup job and has never created a scheduled task before.\n\n### Step 1: the observable behavior\n\nA scheduled task (a native Windows feature for running a program automatically on a schedule or trigger) was created to run a PowerShell script every time any user logs on, by an account with no history of doing so, on a database server, naming itself to look like a legitimate Windows update process (a naming choice meant to blend in and discourage scrutiny).\n\n### Step 2: the goal(s)\n\nAsk what this accomplishes, and more than one answer is correct simultaneously: it ensures the script keeps running across reboots and logoffs (**Persistence**), and depending on what account context the task runs under, it may also serve to execute code with different privileges than the account that created it (**Privilege Escalation**, if the task is configured to run as SYSTEM or another higher-privileged account). Task creation itself is also, technically, an **Execution** action the moment the task is registered or first triggered.\n\n### Step 3: the technique\n\nThe technique is **T1053 Scheduled Task/Job**, and the specific mechanism (Windows Task Scheduler, as opposed to a Linux cron job or a macOS launch agent) narrows it to the sub-technique **T1053.005 Scheduled Task**. As introduced in the previous lesson, this technique legitimately maps to all three tactics (**TA0002 Execution**, **TA0003 Persistence**, and **TA0004 Privilege Escalation**) and a complete mapping should note which of those actually apply based on the specific evidence (here: persistence is clearly the primary intent, given the logon trigger and disguised name; privilege escalation only applies if the task's run-as account is confirmed to be more privileged than svc_backup).\n\n### A note on the deceptive naming\n\nNaming a malicious task to resemble a legitimate one (\"WindowsUpdateHelper\") is itself worth flagging separately as a stealth behavior pattern, even though ATT&CK does not have a single dedicated technique purely for \"misleading names\". It is usually noted as context supporting T1036 Masquerading if other masquerading indicators (like a mismatched file location or signature) are also present.",
        "codeExample": "# SPL (Splunk): hunt for scheduled tasks created by atypical accounts\nindex=windows EventCode=4698\n| eval task_name=mvindex(TaskName, 0)\n| stats count by Account_Name, task_name, Computer\n| where count < 3\n| sort Account_Name",
        "keyPoints": [
          "T1053.005 Scheduled Task is the sub-technique for Windows Task Scheduler abuse, under the parent T1053 Scheduled Task/Job.",
          "This technique can legitimately map to Execution, Persistence, and Privilege Escalation at once. Determine which apply from the specific evidence.",
          "A logon-triggered task created by an account with no history of doing so is a strong persistence indicator.",
          "Windows Event ID 4698 logs scheduled task creation and is a key log source for hunting this technique."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Worked alert 4: outbound beaconing traffic",
        "body": "**The alert.** A network detection tool flags: \"Host WKS-7788 makes an outbound HTTPS connection to 203.0.113.77 (rare domain: portal-cdn-sync.example) every 60 seconds, +/- 2 seconds jitter, with a consistent small payload size (approximately 300 bytes per request).\"\n\n### Step 1: the observable behavior\n\nThe connection pattern itself is the evidence: a fixed, short interval with minimal jitter and a consistently small, similarly-sized payload is a textbook signature of **beaconing**. Malware \"checking in\" with a remote command-and-control server at a regular interval to ask for instructions, as opposed to normal human or application-driven web traffic, which tends to be irregular and variably sized. The destination domain being rare (i.e., almost no other traffic in the environment has ever gone there) and using generic, deliberately unremarkable naming (\"portal-cdn-sync\") adds further suspicion, since attackers often pick domain names designed to blend in with legitimate cloud/CDN traffic on casual inspection.\n\n### Step 2: the goal\n\nThe attacker's goal is ongoing communication with the compromised host to issue commands or retrieve results. That is the tactic **TA0011 Command and Control**.\n\n### Step 3: the technique\n\nSince the traffic uses a standard web protocol (HTTPS) rather than something more exotic (DNS tunneling, ICMP tunneling, or a custom raw protocol), the technique is **T1071 Application Layer Protocol**, narrowed to the sub-technique **T1071.001 Web Protocols**. Command-and-control traffic disguised as ordinary web browsing.\n\n### A follow-up question, not a follow-up guess\n\nAt this point an analyst should resist the temptation to also assume a specific follow-on technique (like exfiltration) without evidence for it. The correct move is to ask: has any larger data transfer occurred on this connection recently (which would support **T1041 Exfiltration Over C2 Channel**), and has a larger payload ever been *downloaded* over it (which would support **T1105 Ingress Tool Transfer**, a second-stage payload being pulled down)? Only map those additional techniques if the corresponding evidence (a data-volume spike, a large inbound transfer) actually appears in the traffic logs.",
        "codeExample": "# KQL: detect beaconing candidates by connection interval consistency\nDeviceNetworkEvents\n| where RemoteUrl == \"portal-cdn-sync.example\" or RemoteIP == \"203.0.113.77\"\n| sort by Timestamp asc\n| serialize\n| extend PrevTime = prev(Timestamp)\n| extend IntervalSeconds = datetime_diff('second', Timestamp, PrevTime)\n| project Timestamp, DeviceName, RemoteIP, IntervalSeconds, RemotePort",
        "keyPoints": [
          "Beaconing (regular-interval, low-jitter, similarly-sized outbound connections) is a behavioral fingerprint of command-and-control check-ins.",
          "This pattern over HTTPS maps to T1071.001 Web Protocols under the tactic TA0011 Command and Control.",
          "A rare destination domain with deliberately generic naming adds corroborating suspicion but is not itself the technique.",
          "Only map follow-on techniques like T1041 Exfiltration or T1105 Ingress Tool Transfer when the specific supporting evidence (data volume, large downloads) is actually present."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Common mapping pitfalls",
        "body": "Having worked through four realistic alerts, it is worth naming the mistakes that repeatedly show up when analysts are new to this skill.\n\n### Over-mapping generic alerts\n\nNot every PowerShell execution is malicious. PowerShell is a legitimate, heavily used administrative tool, and IT staff run it constantly for entirely benign reasons. Tagging every single PowerShell process-creation event with T1059.001 regardless of context (parent process, command-line content, signing status, user) produces noisy, low-value data and trains a team to ignore technique tags altogether. Map a technique when the *behavior pattern* is actually suspicious (unusual parent process, encoding/obfuscation, unusual account), not merely because the tool involved happens to have a technique ID.\n\n### Ignoring multi-tactic techniques\n\nAs seen with T1053 Scheduled Task/Job, some techniques legitimately span multiple tactics. Picking only one out of habit (always defaulting to \"Execution\" for anything that runs code, for instance) loses information that a Tier-2 analyst or a coverage-heatmap exercise later needs.\n\n### Forcing a mapping without sufficient evidence\n\nCovered in the previous lesson but worth repeating here with a concrete example: an alert reading only \"unusual login time for user jsmith, 3:14 AM\" does not, by itself, support a specific technique mapping. It might become **T1078 Valid Accounts** if a stolen-credential indicator later confirms account compromise, or it might resolve as a legitimate benign explanation (a different time zone, an on-call shift). Recording it as \"Suspicious Activity (pending further evidence\" until enough is known is the correct, professional choice) not a failure to complete the task.\n\n### Confusing the technique with the tool\n\nT1003.001 describes the behavior of dumping LSASS memory, not the specific tool used to do it. Mimikatz, procdump, or a custom in-house dumper number as documented \"procedures\" under the technique, but the technique ID itself stays the same regardless of which tool performed the behavior. Do not create a new mapping every time a different tool is involved in the same underlying behavior.",
        "codeExample": "flowchart TD\n    A[\"PowerShell process observed\"] --> B{\"Unusual parent process,\\nencoding, or account context?\"}\n    B -- No, routine admin script --> C[\"Do not tag T1059.001\\n(benign administrative use)\"]\n    B -- Yes, suspicious pattern --> D[\"Tag T1059.001, Execution\\ndocument the specific indicators\"]",
        "keyPoints": [
          "Do not tag every instance of a legitimate tool (like PowerShell) with a technique ID; map based on the suspicious behavior pattern, not tool presence alone.",
          "Multi-tactic techniques (like T1053) should list every tactic the evidence actually supports, not just a default single choice.",
          "Weak or ambiguous evidence should stay unmapped ('Suspicious Activity') rather than be forced into a specific technique.",
          "A technique ID describes a behavior, not a tool. Different tools implementing the same behavior still map to the same technique ID."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Documenting the mapping where it counts",
        "body": "A correct mapping that only exists in an analyst's head, or buried in free-text prose no one else reads, provides almost none of the operational value this lesson opened with. Mapping needs to land in a place the rest of the SOC's tooling and process can actually use.\n\n### Where technique IDs belong\n\n- **The incident ticket's dedicated field or tag**, if the ticketing/SOAR (Security Orchestration, Automation, and Response) platform supports one: most modern platforms have a technique-ID field precisely so this data is queryable later.\n- **The alert/incident record in the SIEM or EDR itself**, where supported. Many platforms allow custom tags or fields; using the field the ECS (Elastic Common Schema) convention calls threat.technique.id and threat.technique.name keeps the value structured and consistent with how many SIEM/EDR export formats already represent this information natively.\n- **The escalation note**, in plain language plus the ID, so the receiving analyst does not have to decode shorthand.\n\n### A complete documentation example\n\nPulling together every worked alert from this lesson, a properly documented multi-technique incident note looks like this: a clear one-line summary per technique, the tactic, and the specific evidence that supports the mapping, not just the ID by itself, since a bare ID with no supporting evidence is nearly as unhelpful to the next reader as no mapping at all.\n\n### Closing the loop with the previous lesson\n\nRecall that the containment-basics lesson's worked example referenced T1003.001 and T1078 directly inside the escalation note. That is not a coincidence. It demonstrates the entire point of this skill: mapping is not an academic exercise performed after the fact, it happens *during* triage and directly shapes what containment and escalation decisions get made and how clearly they get communicated to the next person in the chain.",
        "codeExample": "# Complete mapping documentation for a multi-stage incident\nINC-2051 | Host: WKS-2210 | User: rjones\n\n1. T1566.001 (Spearphishing Attachment) - Initial Access\n   Evidence: invoice_Q3.docm delivered via email from external sender, 09:14Z\n\n2. T1059.001 (PowerShell) - Execution\n   Evidence: powershell.exe -enc <base64>, parent WINWORD.EXE, 09:26Z\n\n3. T1003.001 (LSASS Memory) - Credential Access\n   Evidence: rundll32.exe accessed lsass.exe, GrantedAccess 0x1FFFFF, 09:41Z\n\n4. T1078 (Valid Accounts) - suspected, pending confirmation\n   Evidence: rjones credential used to authenticate to SRV-DB01, 09:52Z\n   (10 min after LSASS access - timing consistent with credential reuse)",
        "keyPoints": [
          "Technique mappings need to be recorded in structured, queryable fields (ticket/SOAR fields, SIEM tags like threat.technique.id), not just in an analyst's head or free text.",
          "A good documentation entry pairs each technique ID with its tactic and the specific evidence supporting it.",
          "Multi-stage incidents should list every distinct technique in the order the intrusion progressed.",
          "Mapping happens during triage and directly informs the containment and escalation decisions covered in earlier and later lessons."
        ]
      }
    ],
    "quiz": [
      {
        "question": "An EDR alert shows rundll32.exe accessing lsass.exe's memory with GrantedAccess 0x1FFFFF. What technique and tactic does this map to?",
        "options": [
          {
            "label": "T1059.001 PowerShell, under Execution",
            "value": "a"
          },
          {
            "label": "T1003.001 OS Credential Dumping: LSASS Memory, under Credential Access",
            "value": "b"
          },
          {
            "label": "T1071.001 Web Protocols, under Command and Control",
            "value": "c"
          },
          {
            "label": "T1053.005 Scheduled Task, under Persistence",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A broad-access memory handle into lsass.exe, which stores credential material, is the classic fingerprint of credential dumping, mapping to T1003.001 under the Credential Access tactic. The other options describe unrelated behaviors (scripting interpreter abuse, C2 beaconing, and scheduled task creation) not present in this alert."
      },
      {
        "question": "A malicious document delivered by email causes Word to spawn PowerShell with an encoded command. Why should this alert be mapped to two technique IDs instead of one?",
        "options": [
          {
            "label": "ATT&CK's rules require every multi-stage alert to carry at least two separate technique IDs",
            "value": "a"
          },
          {
            "label": "The delivery (phishing attachment) and the execution (PowerShell abuse) are two distinct attacker actions, each with its own technique",
            "value": "b"
          },
          {
            "label": "One ID belongs to the analyst who first found the alert, the other to whoever eventually closes the ticket",
            "value": "c"
          },
          {
            "label": "Every sub-technique used in an alert must also list its parent technique as a second, separate ID",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The email delivery (T1566.001, Initial Access) and the PowerShell execution (T1059.001, Execution) represent two separate steps of the intrusion with two separate goals, so both deserve documentation. There is no ATT&CK rule requiring exactly two IDs, this has nothing to do with which analyst is involved, and sub-techniques do not require separately listing their parent."
      },
      {
        "question": "A scheduled task is created by an account that has never done so before, set to run a script at every user logon. Which statement about mapping this correctly is most accurate?",
        "options": [
          {
            "label": "It can only be mapped to the Execution tactic, since a task technically executes code",
            "value": "a"
          },
          {
            "label": "It should be mapped to Persistence, and also Execution and/or Privilege Escalation if the evidence supports those tactics too",
            "value": "b"
          },
          {
            "label": "It cannot be mapped to any technique because Task Scheduler is a legitimate Windows feature",
            "value": "c"
          },
          {
            "label": "It must be mapped to T1078 Valid Accounts since an account created it",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "T1053.005 Scheduled Task legitimately maps to Persistence, Execution, and Privilege Escalation depending on the specific evidence. Here the logon trigger strongly suggests Persistence, and Privilege Escalation would also apply if the task's run-as account is more privileged than the creating account. Legitimate features can still be abused and mapped when the behavior pattern is suspicious, and T1078 concerns credential reuse, not task creation itself."
      },
      {
        "question": "A host makes an outbound HTTPS connection to a rarely-seen domain every 60 seconds with a small, consistent payload size. What should an analyst do about mapping a follow-on technique like data exfiltration?",
        "options": [
          {
            "label": "Automatically add T1041 Exfiltration Over C2 Channel, since any confirmed beaconing pattern always leads to data exfiltration eventually",
            "value": "a"
          },
          {
            "label": "Map only the beaconing itself to T1071.001, adding exfiltration or tool-transfer techniques only once matching evidence like a data-volume spike actually appears",
            "value": "b"
          },
          {
            "label": "Skip mapping this alert entirely, since encrypted HTTPS connection metadata cannot be meaningfully analyzed for patterns",
            "value": "c"
          },
          {
            "label": "Treat the destination domain as safe and close the alert, since the connection uses HTTPS encryption throughout",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The regular, low-jitter connection pattern itself maps to T1071.001 (Command and Control), but follow-on techniques like T1041 Exfiltration or T1105 Ingress Tool Transfer should only be added when their specific supporting evidence (a data-volume spike, a large inbound transfer) is actually observed, not assumed automatically. HTTPS traffic is fully analyzable via connection metadata even without decrypting content, and encryption says nothing about the destination's legitimacy."
      },
      {
        "question": "Why is tagging every single PowerShell process-creation event in an environment with T1059.001 considered a mapping mistake?",
        "options": [
          {
            "label": "T1059.001 only applies to PowerShell versions older than version 5.0 of the interpreter",
            "value": "a"
          },
          {
            "label": "PowerShell is used constantly for legitimate administrative work, so blanket tagging produces noisy, low-value data instead of flagging genuinely suspicious behavior patterns",
            "value": "b"
          },
          {
            "label": "Any PowerShell activity observed anywhere should always be mapped to T1053 Scheduled Task instead",
            "value": "c"
          },
          {
            "label": "Technique IDs can only ever be applied to alerts generated directly by an EDR tool, never by a SIEM correlation rule",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Because PowerShell is heavily used for legitimate administration, mapping every instance regardless of context floods the data with noise and trains the team to ignore technique tags. The mapping should be reserved for genuinely suspicious patterns (unusual parent process, encoding, unusual account). PowerShell version has no bearing on the technique ID, T1053 concerns scheduled tasks, and technique mapping applies to any alert source, not just EDR."
      }
    ]
  },
  "soc-analyst--coverage-thinking": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/coverage-thinking/coverage-thinking.mp4",
          "caption": "Explainer, Coverage Thinking · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/coverage-thinking/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/coverage-thinking/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/coverage-thinking/es.vtt" }
          ]
        },
        "title": "What 'coverage' actually means",
        "body": "After learning to map individual alerts to ATT&CK technique IDs, a natural next question emerges: across the *entire* ATT&CK matrix, which techniques could my organization actually detect if an attacker used them, and which would sail through unnoticed? That question is what \"coverage thinking\" is about, and it turns individual alert-mapping skill into a strategic view of an entire detection program.\n\n### Coverage is not one thing. It is three layers\n\nA common mistake is treating coverage as a single yes/no property per technique. In practice it breaks into three distinct layers, and a gap can exist at any one of them even if the others are fine:\n\n| Layer | Question it answers |\n|---|---|\n| **Visibility** | Do we even collect the log source that would show this technique happening? |\n| **Detection** | If we have the log source, do we have a rule or alert that would actually fire on it? |\n| **Response** | If a detection fires, can an analyst act on it fast enough to matter? |\n\nA concrete illustration: an organization might collect Sysmon Event ID 10 (Process Access) data across every endpoint (visibility exists), but never wrote a rule watching for LSASS access patterns (no detection despite having the data), or the opposite, a well-tuned detection rule exists but nobody is staffed to review its alerts overnight (detection exists, response is the gap). Coverage thinking asks all three questions for every technique that matters to an organization's threat model, not just whether an alert once fired.\n\n### Why this matters for a SOC analyst, not just a manager\n\nIt is tempting to think of coverage analysis as purely a detection-engineering or SOC-manager responsibility. In practice, front-line analysts are often the first to notice a gap, during an investigation, realizing \"we have no way to see what that PowerShell command actually contained\" is a coverage observation, and knowing how to escalate it (covered later in this lesson) turns a one-off frustration into a permanent improvement for the whole team.",
        "codeExample": "flowchart TD\n    A[\"Technique: T1003.001 LSASS Memory\"] --> B{\"Visibility:\\ndo we collect Sysmon EID 10?\"}\n    B -- No --> C[GAP: blind to this technique]\n    B -- Yes --> D{\"Detection:\\ndo we have a rule for it?\"}\n    D -- No --> E[GAP: data exists but unused]\n    D -- Yes --> F{\"Response:\\ncan an analyst act on the alert?\"}\n    F -- No --> G[GAP: alert fires into a void]\n    F -- Yes --> H[Covered]",
        "keyPoints": [
          "Coverage breaks into three layers: visibility (do we collect the data), detection (do we have a rule for it), response (can we act on it).",
          "A gap can exist at any single layer even if the others are fine, collecting data with no rule, or a rule with no staffed response, are both gaps.",
          "Coverage thinking extends the earlier alert-mapping skill from a single incident to the entire ATT&CK matrix.",
          "Front-line analysts often spot coverage gaps first, during real investigations, before any formal review catches them."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Building an ATT&CK heatmap",
        "body": "The most common way to visualize coverage across the whole matrix is a **heatmap**: the ATT&CK matrix with each technique cell colored according to how well-covered it is. Building and reading these heatmaps is done with **ATT&CK Navigator**, the same free MITRE tool introduced in the tactics-and-techniques lesson for viewing group and software technique lists.\n\n### A small worked heatmap\n\nImagine NexaCorp's SOC reviews five techniques relevant to a recent threat intelligence report about a ransomware group active in their industry:\n\n| Technique | Visibility | Detection | Coverage status |\n|---|---|---|---|\n| T1566.001 Spearphishing Attachment | Email gateway logs collected | Attachment-scanning rule active | Covered |\n| T1059.001 PowerShell | Sysmon EID 1 collected | No rule for encoded/obfuscated commands | Partial |\n| T1003.001 LSASS Memory | No ProcessAccess (Sysmon EID 10) collected | N/A: no data to detect on | Not covered |\n| T1053.005 Scheduled Task | Event ID 4698 collected | Rule flags tasks by atypical accounts | Covered |\n| T1071.001 Web Protocols (C2) | NetFlow/proxy logs collected | No beaconing-interval detection logic | Partial |\n\nColoring this in Navigator (green for covered, yellow for partial, red for not covered) turns a table into an at-a-glance picture: two solid gaps here are LSASS memory access (no data at all) and encoded PowerShell commands / beaconing detection (data exists but no rule uses it yet).\n\n### Why a heatmap beats a simple checklist\n\nA plain checklist (\"do we detect ransomware: yes/no\") hides exactly which specific behaviors within a broad threat category are and are not covered. A heatmap forces the analysis down to the technique level, where actionable gaps like \"we have the log source but nobody wrote the rule\" become visible and specific enough to actually fix, as opposed to a vague, unfixable statement like \"we need better ransomware detection.\"",
        "codeExample": "# ATT&CK Navigator layer (conceptual), NexaCorp coverage review\n{\n \"name\": \"NexaCorp Coverage vs Ransomware Group Report\",\n \"domain\": \"enterprise-attack\",\n \"techniques\": [\n { \"techniqueID\": \"T1566.001\", \"color\": \"#31a354\", \"comment\": \"Covered: gateway + attachment rule\" },\n { \"techniqueID\": \"T1059.001\", \"color\": \"#fed976\", \"comment\": \"Partial: EID 1 collected, no encoding rule\" },\n { \"techniqueID\": \"T1003.001\", \"color\": \"#de2d26\", \"comment\": \"Not covered: EID 10 not collected\" },\n { \"techniqueID\": \"T1053.005\", \"color\": \"#31a354\", \"comment\": \"Covered: EID 4698 + atypical-account rule\" },\n { \"techniqueID\": \"T1071.001\", \"color\": \"#fed976\", \"comment\": \"Partial: netflow collected, no beacon logic\" }\n ]\n}",
        "keyPoints": [
          "ATT&CK Navigator builds color-coded heatmaps (covered/partial/not-covered) directly over the matrix.",
          "A heatmap at the technique level exposes specific, fixable gaps rather than a vague overall judgment.",
          "The same technique can be 'partial' because the log source exists but no rule uses it: visibility without detection.",
          "Reviewing coverage against a specific threat actor's known technique list (from a threat intel report) is a common, high-value exercise."
        ]
      },
      {
        "pageNumber": 3,
        "title": "DeTT&CT: a structured methodology for scoring coverage",
        "body": "Building a heatmap by hand, as in the previous page, works for a handful of techniques reviewed after a specific report. For an ongoing, organization-wide coverage program, teams commonly use **DeTT&CT** (Detect Tactics, Techniques & Combat Threats), an open-source methodology and toolset originally created by Rabobank's Cyber Defence Centre. DeTT&CT adds structure that ad-hoc heatmaps lack.\n\n### The core idea: score data sources, not just techniques\n\nInstead of jumping straight to \"is this technique covered,\" DeTT&CT starts one layer earlier: it has an analyst inventory and score the **quality of each data source** the organization collects (for example: Windows process creation logs, DNS logs, cloud audit logs), evaluating dimensions like completeness (is it collected from every relevant host, or only some?), timeliness (how much delay before the data is queryable?), consistency (is the field structure the same across every source of that log type?), and retention (how long is it kept?).\n\n### From data source quality to technique visibility\n\nEach ATT&CK technique is associated with one or more data sources that could reveal it. DeTT&CT propagates the data-source quality score into a **visibility score** for every technique that depends on that source: a technique that relies on a data source with poor quality (say, inconsistent field names across different log forwarders) inherits a correspondingly weaker visibility score, even before anyone asks whether a detection rule exists.\n\n### Then, and only then, detection scoring\n\nSeparately from visibility, DeTT&CT scores whether an actual **detection** (rule, alert, or analytic) exists for each technique. Keeping visibility and detection as two separate, deliberately distinct scores (rather than collapsing them into one number) is DeTT&CT's key contribution: it lets a team see the difference between \"we cannot see this happening\" (a visibility/log-source problem to fix with logging changes) and \"we can see it, but nobody built a detection\" (a detection-engineering backlog item), which require entirely different remediation work.\n\n### The output\n\nLike a manual heatmap, DeTT&CT ultimately produces layers that load into ATT&CK Navigator, but built from a documented, repeatable, and comparable-over-time scoring methodology rather than a one-off manual review.",
        "codeExample": "flowchart LR\n    A[\"Inventory data sources\\n(process logs, DNS, cloud audit)\"] --> B[\"Score data source quality\\n(completeness, timeliness,\\nconsistency, retention)\"]\n    B --> C[\"Propagate to per-technique\\nvisibility score\"]\n    C --> D[\"Separately score detection\\ncoverage per technique\"]\n    D --> E[\"Export as ATT&CK Navigator\\nlayers for review\"]",
        "keyPoints": [
          "DeTT&CT (Detect Tactics, Techniques & Combat Threats) is an open-source methodology, originating at Rabobank's Cyber Defence Centre, for structured coverage scoring.",
          "It starts by scoring the quality of underlying data sources (completeness, timeliness, consistency, retention), not techniques directly.",
          "Data source quality propagates into a per-technique visibility score, kept deliberately separate from a per-technique detection score.",
          "Separating visibility from detection distinguishes 'we can't see this' (a logging problem) from 'we see it but have no rule' (a detection-engineering problem)."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Prioritizing which gaps to close first",
        "body": "A complete coverage review of the full ATT&CK Enterprise matrix will almost always surface more gaps than a SOC has the staffing or budget to close immediately. Coverage thinking is as much about **prioritization** as it is about measurement.\n\n### Threat-informed defense\n\nThe Center for Threat-Informed Defense and MITRE both promote the idea of prioritizing coverage work based on techniques *actually used against organizations like yours*, rather than trying to cover the entire matrix evenly. Sources for this prioritization include:\n\n- **Threat intelligence reports** naming groups or campaigns relevant to your industry or region, cross-referenced against ATT&CK's Groups pages for their documented technique lists.\n- **Published \"most common techniques\" analyses**, which periodically identify which techniques appear disproportionately often across real incident data.\n- **Your own incident history**. Techniques that have shown up in your own past incidents (even ones that were eventually caught) are, by definition, ones your specific environment is exposed to.\n\n### Weighing prevalence against blast radius and current gap size\n\nNot every prevalent technique deserves equal urgency. A useful mental model weighs three factors together: how often the technique is actually used against organizations like yours (prevalence), how much damage an unnoticed instance could cause (blast radius. Credential theft and ransomware-precursor techniques tend to rank high here), and how big the current gap is (a technique with zero visibility is a more urgent fix than one that already has partial coverage). A rare but catastrophic technique with zero visibility might reasonably outrank a common but low-impact technique that already has partial detection.\n\n### A living process, not a one-time project\n\nBecause adversary tradecraft and an organization's own environment both change constantly (new log sources come online, cloud services get adopted, old rules stop matching after a software update), coverage review is a recurring process (commonly done on a quarterly cadence) rather than a project with a defined end date. Treating it as a one-time exercise is itself a common and costly mistake.",
        "codeExample": "# Simple prioritization scoring model (conceptual)\npriority_score = prevalence_weight * blast_radius_weight * (1 - current_coverage_score)\n\n# Example: two candidate gaps\nT1003.001 LSASS Memory:     prevalence=High, blast_radius=High, coverage=0.0  -> priority: urgent\nT1560.001 Archive via Utility: prevalence=Low, blast_radius=Medium, coverage=0.4 -> priority: lower",
        "keyPoints": [
          "Threat-informed defense prioritizes coverage work using real threat intelligence (relevant groups, common-technique analyses, your own incident history) rather than trying to cover everything evenly.",
          "Prioritize using prevalence, blast radius (potential damage), and the size of the current gap together, not any single factor alone.",
          "A rare but catastrophic, zero-visibility technique can outrank a common but low-impact, partially-covered one.",
          "Coverage review is a recurring process (commonly quarterly), not a one-time project, since both adversary tradecraft and the environment keep changing."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Log source gaps behind specific technique blind spots",
        "body": "Many coverage gaps trace back to a missing or under-configured log source rather than a missing detection rule, which is exactly why DeTT&CT insists on scoring data sources separately from detections. A few concrete, common examples worth knowing by heart:\n\n### No PowerShell script block logging\n\nWindows Event ID 4104 (PowerShell script block logging) records the actual decoded content of a script block that ran. This is what would let an analyst see through an obfuscated or base64-encoded command and read what it was really going to do. Without it enabled, an organization can still see *that* PowerShell ran (via process-creation logging) but is blind to *what the script actually contained*, which severely limits confident mapping and investigation of T1059.001.\n\n### No DNS query logging\n\nWithout visibility into which internal hosts resolved which domain names, an organization is largely blind to DNS-based command-and-control and DNS tunneling (T1071.004), and loses the ability to run the \"who still resolves this sinkholed domain\" detection technique described in the containment-basics lesson.\n\n### No process-access telemetry\n\nAs referenced throughout this module, Sysmon Event ID 10 (or an EDR's equivalent process-access telemetry) is what makes T1003.001 LSASS-memory detection possible at all. Many organizations running only Windows' default Security log auditing (without Sysmon or a comparable EDR sensor) simply have no data source capable of showing this technique, no matter how good their detection rules are elsewhere.\n\n### The pattern across all three examples\n\nEach case shows a technique that can be **fully invisible** not because attackers are especially sophisticated, but because a specific, well-known log source was never turned on. Recognizing \"we have no log source that could show this at all\" versus \"we have the log source but no rule\" is exactly the visibility/detection split DeTT&CT formalizes, and it is often the cheaper, faster fix of the two, since enabling an existing logging feature is usually less work than developing and tuning a brand-new detection rule from scratch.",
        "codeExample": "# Enable PowerShell Script Block Logging via Group Policy registry path\n# (conceptual. Set via GPO, not run directly on a single host)\nHKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\n EnableScriptBlockLogging = 1\n\n# KQL: confirm Event ID 4104 is actually arriving before assuming coverage exists\nSecurityEvent\n| where TimeGenerated > ago(7d)\n| where EventID == 4104\n| summarize EventCount = count()\n| where EventCount == 0",
        "keyPoints": [
          "Missing PowerShell script block logging (Event ID 4104) blinds an organization to the actual decoded content of obfuscated scripts.",
          "Missing DNS query logging blinds an organization to DNS-based C2 and tunneling (T1071.004) and removes the sinkhole-detection technique.",
          "Missing process-access telemetry (Sysmon Event ID 10 or an EDR equivalent) makes T1003.001 LSASS detection impossible regardless of rule quality.",
          "Enabling an existing log source is often a cheaper, faster fix than building a new detection rule from scratch."
        ]
      },
      {
        "pageNumber": 6,
        "title": "From gap to detection-engineering ticket",
        "body": "Spotting a gap during an investigation is only useful if it turns into a concrete, actionable request rather than a passing observation lost in a closed ticket's history. A well-formed escalation from a front-line analyst to a detection-engineering function should answer four questions clearly.\n\n### The four questions a good gap report answers\n\n1. **What happened that revealed the gap?** A specific incident or near-miss, briefly described, grounds the request in a real scenario rather than a hypothetical.\n2. **What would have caught it, specifically?** Name the exact log source or field that was missing, or the exact rule logic that would have flagged the behavior sooner. Vague requests like \"we need better detection\" are far less actionable than \"we need Event ID 4104 enabled on domain controllers.\"\n3. **Which technique(s) does this close coverage on?** Tying the request to a technique ID connects it to the broader heatmap and prioritization work covered earlier in this lesson.\n4. **How urgent is it, and why?** Reference prevalence/blast-radius reasoning if relevant: a gap discovered during an active, real intrusion generally deserves faster turnaround than one found during a routine tabletop review.\n\n### Why this belongs to every analyst, not just detection engineers\n\nA detection engineering team, however skilled, cannot manufacture gap reports out of nothing. They depend on front-line analysts noticing, during real triage work, where the available evidence fell short of what was needed. A SOC culture where analysts treat \"I wish we had X\" as a private frustration rather than a formal, tracked request quietly wastes the single richest source of information a coverage program has: real incidents that actually happened.\n\n### Closing the loop\n\nWell-run programs track gap reports to resolution and, ideally, re-test the specific technique in the heatmap once the fix (new log source, new rule) ships, turning coverage thinking into a measurable, continuously-improving cycle rather than a one-time snapshot.",
        "codeExample": "# Detection-engineering gap report template\nIncident reference: INC-2051\nTechnique(s) affected: T1003.001 (LSASS Memory), T1059.001 (PowerShell - encoded)\nGap identified: No Sysmon Event ID 10 on SRV-DB01; no PowerShell 4104 logging\n  anywhere in the SRV-* server OU.\nSpecific fix requested: Enable Sysmon ProcessAccess for lsass.exe on all\n  servers; enable PowerShell Script Block Logging via existing domain GPO.\nUrgency: High - gap directly prevented earlier detection during a confirmed\n  intrusion (INC-2051), not a hypothetical scenario.",
        "keyPoints": [
          "A well-formed gap report answers: what happened, what specifically would have caught it, which technique it closes coverage on, and how urgent it is.",
          "Naming the exact missing log source or rule logic is far more actionable than a vague request for 'better detection.'",
          "Front-line analysts are the primary source of real gap reports, since they encounter real evidence shortfalls during actual triage.",
          "Mature programs track gap reports to resolution and re-test the affected technique's heatmap status once a fix ships."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Good enough coverage in a resource-constrained SOC",
        "body": "Every SOC operates with finite analyst time, finite log-storage budget, and finite detection-engineering capacity. Full, deep coverage of all 15 tactics and every technique and sub-technique in the Enterprise matrix is not a realistic goal for almost any real organization, and treating \"100% coverage\" as the target leads to either paralysis or superficial, low-quality coverage spread too thin to be useful anywhere.\n\n### Layered defense reduces reliance on any single detection\n\nCoverage thinking pairs naturally with **defense in depth**: the principle that no single control needs to catch everything, because multiple independent layers each catch a portion of what gets past the others. MITRE's own **D3FEND** framework (a complementary knowledge base of defensive countermeasures, mapped to the offensive techniques they counter) is useful here: even where a detection gap exists for a specific technique, a preventive or hardening control from D3FEND (for example, restricting which accounts can access LSASS memory in the first place, reducing the technique's viability regardless of whether it gets detected) can reduce the practical risk of that gap without requiring a perfect detection rule.\n\n### Depth over breadth for your specific threat model\n\nGiven limited resources, a SOC generally gets more real security value from deep, well-tuned coverage of the roughly 15-25 techniques most relevant to its actual threat model (informed by the prioritization approach from earlier in this lesson) than from shallow, unreliable coverage spread across the entire matrix. A rule that reliably catches T1003.001 with low false-positive noise is worth more in practice than ten superficial, high-noise rules across ten low-priority techniques that analysts learn to ignore.\n\n### Communicating gaps honestly, upward and sideways\n\nPart of \"good enough\" coverage is being honest (in status reports, coverage reviews, and incident retrospectives) about which known gaps remain open and why (budget, staffing, or genuinely lower priority), rather than letting a heatmap imply more confidence than the underlying detections actually warrant. A documented, deliberately-accepted gap is a far healthier state than an undocumented one nobody remembers exists until an incident exposes it.",
        "codeExample": "flowchart TD\n    A[\"Full ATT&CK Enterprise matrix\\n~200+ techniques\"] --> B[\"Prioritize by threat model\\n(prevalence x blast radius x gap size)\"]\n    B --> C[\"~15-25 highest-priority techniques\"]\n    C --> D[\"Deep, well-tuned detection\\n+ D3FEND hardening controls\\nfor these\"]\n    D --> E[\"Document remaining gaps\\nhonestly for future review\"]",
        "keyPoints": [
          "Full coverage of the entire ATT&CK matrix is not realistic for most organizations; treating 100% as the goal leads to shallow, low-quality coverage.",
          "MITRE D3FEND is a complementary knowledge base of defensive countermeasures that can reduce risk from a technique even without a perfect detection.",
          "Deep, well-tuned coverage of a prioritized, threat-relevant subset of techniques generally provides more real value than shallow coverage everywhere.",
          "Honestly documenting known, deliberately-accepted gaps is healthier than an undocumented blind spot nobody remembers exists."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A SOC collects Sysmon Event ID 10 data on every endpoint, but has never written a rule to alert on suspicious LSASS memory access patterns. Which coverage layer is missing?",
        "options": [
          {
            "label": "Visibility: the log source itself is missing",
            "value": "a"
          },
          {
            "label": "Detection: the data exists but no rule uses it",
            "value": "b"
          },
          {
            "label": "Response: analysts cannot act on the alert fast enough",
            "value": "c"
          },
          {
            "label": "All three layers are missing",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Visibility exists because the Sysmon Event ID 10 data is being collected. The gap is at the detection layer: no rule or analytic has been built to actually alert on suspicious patterns within that data. Response is a separate concern about acting on alerts once they fire, which is not what's described here."
      },
      {
        "question": "What is the key methodological contribution of DeTT&CT compared to a manually built ATT&CK heatmap?",
        "options": [
          {
            "label": "It automatically writes and deploys finished detection rules for every technique in the matrix",
            "value": "a"
          },
          {
            "label": "It scores data source quality first, then separately scores visibility and detection, rather than collapsing coverage into one number",
            "value": "b"
          },
          {
            "label": "It fully replaces the need to ever load a layer into ATT&CK Navigator again",
            "value": "c"
          },
          {
            "label": "It is designed to only score coverage for cloud environments, not on-premises networks",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "DeTT&CT's key contribution is a structured methodology that scores the quality of underlying data sources, propagates that into a per-technique visibility score, and scores detection separately, distinguishing 'we can't see this' from 'we see it but have no rule.' It does not write rules automatically, still exports to ATT&CK Navigator rather than replacing it, and applies to any environment, not just cloud."
      },
      {
        "question": "When prioritizing which coverage gaps to close first, which combination of factors does this lesson recommend weighing together?",
        "options": [
          {
            "label": "Only how recently the technique was first published or updated on the ATT&CK website",
            "value": "a"
          },
          {
            "label": "Prevalence against organizations like yours, potential blast radius, and the size of the current coverage gap",
            "value": "b"
          },
          {
            "label": "Only the alphabetical ordering of the technique's ID within the matrix",
            "value": "c"
          },
          {
            "label": "Only whether the technique happens to have a short, memorable name",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Threat-informed prioritization weighs how often a technique is actually used against similar organizations, how much damage it could cause if missed, and how large the current gap already is: together, not any single factor alone. Publication date, alphabetical order, and naming have no bearing on prioritization."
      },
      {
        "question": "An organization has process-creation logging but no PowerShell script block logging (Event ID 4104) enabled anywhere. What specific limitation does this create?",
        "options": [
          {
            "label": "The organization loses all ability to see that a PowerShell process ever ran on any host",
            "value": "a"
          },
          {
            "label": "The organization can see that PowerShell ran, but cannot see the decoded content of obfuscated or encoded script blocks",
            "value": "b"
          },
          {
            "label": "The organization becomes fully blind to every form of command-and-control traffic across the network",
            "value": "c"
          },
          {
            "label": "The organization loses the ability to detect any newly created scheduled tasks",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Process-creation logging still shows that powershell.exe ran, including its command line, but without Event ID 4104 the actual decoded content of an encoded or obfuscated script block is invisible, limiting confident investigation of T1059.001. It does not affect visibility into C2 traffic or scheduled tasks, which rely on different log sources entirely."
      },
      {
        "question": "Given limited SOC resources, what does this lesson recommend over trying to achieve full coverage of the entire ATT&CK Enterprise matrix?",
        "options": [
          {
            "label": "Abandon coverage analysis entirely, since achieving full coverage is genuinely impossible for any real organization",
            "value": "a"
          },
          {
            "label": "Focus deep, well-tuned detection and D3FEND hardening on a prioritized subset of techniques most relevant to the organization's actual threat model",
            "value": "b"
          },
          {
            "label": "Spread an equal, shallow amount of effort evenly across every single technique listed in the matrix",
            "value": "c"
          },
          {
            "label": "Postpone thinking about coverage at all until after an incident has already occurred and been resolved",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson recommends prioritizing depth over breadth: strong, well-tuned coverage (plus complementary D3FEND hardening controls) on the techniques most relevant to your actual threat model provides more real value than shallow, low-quality coverage spread across the entire matrix. Ignoring coverage analysis, spreading effort evenly and thinly, or only reacting after an incident are all explicitly discouraged approaches."
      }
    ]
  },
  "soc-analyst--building-timelines": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why a timeline is the core deliverable",
        "body": "Every investigation, no matter how it starts, eventually has to answer one question clearly: what happened, in what order? A **timeline**: a chronological sequence of events pulled from every relevant log source, lined up against a single, consistent clock. Is how an analyst turns a pile of disconnected log entries into an actual story that a Tier-2 analyst, an incident response lead, or a compliance auditor can read and understand.\n\n### An analogy: assembling security camera footage\n\nPicture a large building with a security camera at every entrance, each camera running on its own internal clock, some slightly fast, some slightly slow. If a security guard wants to know how an intruder actually moved through the building, watching each camera's footage separately, on its own uncorrected clock, would be nearly useless: the guard needs every camera's footage placed on one shared timeline before the sequence of events becomes clear. A SOC investigation faces the exact same problem, except the \"cameras\" are a Windows Security event log, an EDR's process telemetry, a firewall's connection log, and a cloud platform's audit log. Four different systems, four different native timestamp formats, and (without correction) four different clocks.\n\n### What this lesson builds toward\n\nThis lesson covers the mechanics of building a trustworthy timeline: normalizing time across sources so events actually line up correctly, understanding which log sources contribute which kind of event, using the right tools for small versus large-scale timelines, handling gaps in the evidence honestly, and presenting the finished timeline clearly in an incident report. The following lesson, Pivoting on entities, builds directly on this one. Once a rough timeline exists, pivoting is how an analyst fills in the gaps and extends the story to other hosts, users, and infrastructure.",
        "codeExample": "flowchart LR\n    A[Windows Security log\\nlocal time or UTC?] --> E[Normalize to UTC]\n    B[EDR telemetry\\nusually UTC] --> E\n    C[Firewall log\\ndevice-local time] --> E\n    D[Cloud audit log\\nISO 8601 UTC] --> E\n    E --> F[Single chronological\\ntimeline]",
        "keyPoints": [
          "A timeline is a chronological sequence of events from multiple log sources, normalized to one consistent clock.",
          "Without time normalization, events from different systems cannot be reliably compared or ordered.",
          "This lesson covers normalization, source characteristics, tooling, gap-handling, and presentation.",
          "The next lesson, Pivoting on entities, extends a rough timeline by following entities (host, user, IP) across data sources."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Time normalization: getting every source onto one clock",
        "body": "The single most common way a timeline goes subtly wrong is a time-normalization mistake: two events that actually happened seconds apart appear hours apart (or vice versa) purely because of a timestamp handling error, leading an analyst to draw a completely wrong conclusion about cause and effect.\n\n### UTC as the standard\n\n**UTC** (Coordinated Universal Time) is the time standard that does not shift with daylight saving time or local time zones, which is exactly why it is the standard an investigation should normalize every timestamp to. Local time is convenient for a human reading a single log on their own machine, but becomes actively misleading the moment logs from different time zones (a branch office server, a cloud region, an analyst's own laptop) need to be compared side by side.\n\n### NTP drift\n\n**NTP** (Network Time Protocol) is the protocol most systems use to keep their internal clocks synchronized to a reference time source. When NTP is misconfigured or a device has been offline from its time source for a while, its clock can **drift**, meaning its own recorded \"UTC\" timestamp is itself wrong by seconds, minutes, or in poorly-maintained environments, occasionally much more. A rigorous timeline notes when a source's clock reliability is uncertain, and where possible, cross-checks suspect timestamps against another source that recorded the same real-world event (for example, a firewall's connection log and an EDR's network-connection telemetry should show the same connection within a second or two of each other if both clocks are accurate).\n\n### Timestamp formats you will actually encounter\n\n- **ISO 8601** (for example, 2026-09-28T14:32:00Z): the \"Z\" suffix explicitly denotes UTC; this is the cleanest, least ambiguous format and what most modern cloud and SIEM platforms use natively.\n- **Epoch / Unix time**, a single integer counting seconds (or milliseconds) since January 1, 1970 UTC; unambiguous but not human-readable without conversion, common in raw API responses and some log formats.\n- **Local timestamps with no time zone marker**, the most dangerous format, since the reader has no way to know which zone it represents without separately knowing the device's configuration; always confirm the source device's configured time zone before treating such a timestamp as UTC.",
        "codeExample": "# Converting a local timestamp to UTC (example, Israel Standard Time, UTC+3 in DST)\nLocal logged time: 2026-09-28 17:32:00 (device configured for Asia/Jerusalem)\nUTC equivalent:    2026-09-28T14:32:00Z\n\n# KQL: force explicit UTC handling when correlating across tables\nSecurityEvent\n| extend TimeUTC = TimeGenerated  // Sentinel stores TimeGenerated in UTC already\n| join kind=inner (\n    DeviceNetworkEvents\n    | extend TimeUTC = Timestamp   // Defender Advanced Hunting timestamps are UTC\n  ) on $left.TimeUTC == $right.TimeUTC",
        "keyPoints": [
          "Normalize every timestamp to UTC (Coordinated Universal Time) before building a cross-source timeline.",
          "NTP (Network Time Protocol) keeps device clocks synchronized; drift from misconfigured or long-offline NTP can silently skew a source's timestamps.",
          "ISO 8601 (with a 'Z' suffix) and epoch/Unix time are unambiguous formats; a local timestamp with no time zone marker is the most dangerous to trust blindly.",
          "Cross-check suspect timestamps against a second source that recorded the same real-world event, when clock reliability is uncertain."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Know your sources: what each one actually contributes",
        "body": "Building a timeline efficiently means knowing, before you start pulling data, what each log source is good at recording and at what level of time precision, pulling from the wrong source, or expecting precision a source cannot provide, wastes investigation time.\n\n### Windows Event Log\n\nLocal Windows Security events (Security.evtx) record the exact SystemTime attribute of the event at the moment it was generated, in UTC by default on modern Windows systems, giving second-level precision. This is the primary source for authentication (Event ID 4624/4625 logon success/failure), account changes (4725, 4724. Covered in the containment-basics lesson), and scheduled task creation (4698, covered in the mapping-alerts lesson).\n\n### EDR telemetry\n\nEDR (Endpoint Detection and Response) platforms like CrowdStrike Falcon and Microsoft Defender for Endpoint typically record process, file, and network events with their own Timestamp field, already normalized to UTC by the vendor's backend regardless of the endpoint's local clock setting: one of the practical advantages of cloud-centralized EDR logging over reading raw local event logs directly off each endpoint.\n\n### Firewall and proxy logs\n\nThese typically log in the device's own configured local time zone unless explicitly set to UTC, and often only to one-second precision. Usable for correlating with other one-second-precision sources, but not fine enough to establish sub-second ordering between two nearly-simultaneous events.\n\n### Cloud audit logs\n\nMicrosoft 365's Unified Audit Log records a CreationTime field, and AWS CloudTrail records an eventTime field. Both in ISO 8601 UTC by convention, making them straightforward to normalize, but worth remembering that cloud audit logs can have their own ingestion delay (the event may not appear in the log for several minutes after it actually happened), which matters when deciding how wide a time window to search when pivoting from an on-premises event to a cloud one.\n\n### The practical takeaway\n\nBefore building a timeline, briefly note each source's native format, precision, and typical delay. This five-minute step prevents the much larger cost of misinterpreting an ordering later.",
        "codeExample": "# Quick source reference table (paste into investigation notes)\nSource                    | Native format        | Precision | Typical delay\nWindows Security log      | UTC (SystemTime)      | ~1 sec    | near-real-time\nEDR (Falcon / Defender)   | UTC (vendor-normalized)| ~1 sec    | seconds\nFirewall / proxy          | device-local time      | ~1 sec    | near-real-time\nO365 Unified Audit Log    | UTC (CreationTime)     | ~1 sec    | up to ~30 min\nAWS CloudTrail            | UTC (eventTime)        | ~1 sec    | minutes (varies by event)",
        "keyPoints": [
          "Windows Event Log records SystemTime in UTC by default on modern systems, at roughly one-second precision.",
          "EDR platforms usually normalize timestamps to UTC in their cloud backend regardless of endpoint local clock settings.",
          "Firewall/proxy logs commonly use device-local time unless explicitly configured otherwise: verify before assuming UTC.",
          "Cloud audit logs (O365 Unified Audit Log CreationTime, AWS CloudTrail eventTime) use ISO 8601 UTC but can have meaningful ingestion delay."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Tools for building a timeline",
        "body": "For a small, focused investigation, a manual approach is often the fastest and clearest: export the relevant events from each source, normalize their timestamps, and assemble them in a spreadsheet or a SIEM's own timeline visualization, sorted chronologically. Both Splunk and Microsoft Sentinel have built-in timeline/investigation-graph views designed exactly for this, pulling correlated events from multiple indexed sources onto one visual timeline without leaving the platform.\n\n### When manual assembly stops scaling\n\nFor larger, more complex investigations. Many hosts, a long time window, or forensic disk/memory images that need to be included alongside live logs. Purpose-built timeline tools become worthwhile:\n\n- **log2timeline / Plaso**: an open-source forensic timeline tool (Plaso stands for \"Plaso Langar Að Safna Öllu,\" Icelandic for \"Plaso wants to gather everything\") that parses dozens of different forensic artifact formats (Windows Registry hives, browser history, file system metadata, event logs, and many more) and normalizes them all into one combined, sortable timeline. Colloquially called a \"super timeline\" because of how many different artifact types feed into a single output.\n- **Timesketch**: an open-source, collaborative timeline analysis platform (developed by Google) that ingests Plaso's output (or other structured timeline data) and lets multiple analysts jointly filter, annotate, and search a very large timeline through a web interface, rather than scrolling through a massive flat file or spreadsheet alone.\n\n### Choosing the right tool for the job\n\nA quick rule of thumb: if the investigation fits comfortably in a SIEM's native query/timeline view and involves live telemetry from systems still online, stay in the SIEM. It is faster and requires no extra tooling. Reach for Plaso/Timesketch specifically when forensic artifacts (disk images, memory dumps, browser artifacts) need to be combined with live log data into one master timeline, or when the scale of the investigation (many hosts, a long time window) makes a manual spreadsheet unmanageable.",
        "codeExample": "# log2timeline / Plaso: basic usage pattern (conceptual)\nlog2timeline.py timeline.plaso /evidence/WKS-4471_disk_image.E01\npsort.py -o l2tcsv -w timeline.csv timeline.plaso\n\n# Result: a single CSV with normalized UTC timestamps across every parsed\n# artifact type (registry, event log, browser history, file system, etc.),\n# ready to import into Timesketch or filter directly.",
        "keyPoints": [
          "Splunk and Microsoft Sentinel both have built-in timeline/investigation views suitable for smaller, focused investigations using live telemetry.",
          "Plaso (log2timeline) is an open-source forensic tool that parses many artifact types into one normalized 'super timeline.'",
          "Timesketch, developed by Google, is a collaborative web platform for filtering and annotating large timelines, often fed by Plaso's output.",
          "Stay in the SIEM for live-telemetry investigations that fit its native view; reach for Plaso/Timesketch when forensic artifacts and scale demand it."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Handling gaps honestly",
        "body": "No timeline is ever perfectly complete. Log retention limits mean older events roll off before anyone asks for them; a host might not have had an EDR agent installed until partway through the period under investigation; a log source might have simply failed silently for a stretch of time. How an analyst handles these gaps says a lot about the quality and trustworthiness of the resulting investigation.\n\n### Mark the gap explicitly\n\nThe correct approach is to state a gap directly in the timeline itself, rather than silently skipping from one known event to the next as if nothing happened in between: \"No EDR telemetry available for WKS-4471 between 2026-09-14 and 2026-09-21 (agent was not yet deployed to this host).\" This single sentence tells the next reader exactly what is and is not known, and prevents someone from mistakenly assuming \"no events logged\" means \"nothing happened\" during that window.\n\n### Inference is allowed. Assertion of the unproven is not\n\nIt is entirely reasonable to use surrounding evidence to form a *hypothesis* about what likely happened during a gap, for example, if a host shows a malicious file present both before and after a logging gap, it is reasonable to infer the file was likely present throughout, even without direct evidence for every day in between. The critical discipline is labeling this correctly as an inference (\"likely present based on surrounding evidence\") rather than writing it into the timeline as a confirmed, logged fact. Conflating inference with confirmed fact is one of the more serious credibility risks in an investigation report, particularly if the findings are later used in a legal, regulatory, or insurance context.\n\n### Gaps as their own finding\n\nA gap is sometimes itself an important finding rather than just an inconvenience: a log source that stopped recording exactly when an attacker likely gained privileged access is a pattern worth flagging on its own (some attackers deliberately disable or tamper with logging, which ATT&CK v19 files under the Defense Impairment tactic as T1685 Disable or Modify Tools, formerly T1562 Impair Defenses), rather than treated as an unrelated coincidence.",
        "codeExample": "# Example timeline entry format that handles a gap correctly\n2026-09-14 09:02:14Z | EDR       | File dropper.exe created on WKS-4471\n2026-09-14 to 2026-09-21 | [GAP]  | No EDR telemetry - agent not yet deployed\n                                     to this host during this window\n2026-09-21 08:47:03Z | EDR       | dropper.exe executed on WKS-4471\n                                     (inference: likely present and dormant\n                                     throughout the gap; not directly observed)",
        "keyPoints": [
          "Explicitly mark gaps in a timeline ('no telemetry available for X to Y, because Z') rather than silently skipping over them.",
          "Reasonable inference from surrounding evidence is allowed, but must be clearly labeled as inference, not written as a confirmed fact.",
          "Conflating inference with confirmed fact is a serious credibility risk, especially in reports used for legal or regulatory purposes.",
          "A logging gap that coincides suspiciously with likely attacker activity can itself be a finding (possible T1685 Disable or Modify Tools, Defense Impairment), not just a data limitation."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Presenting the timeline in an incident report",
        "body": "A technically accurate timeline that is hard to read fails at its actual job, which is helping someone else (a Tier-2 analyst, an IR lead, a manager, sometimes an external auditor) understand and act on what happened. A few presentation practices consistently make timelines clearer.\n\n### A consistent table format\n\nPresenting the timeline as a table with consistent columns. Timestamp (UTC), source, event description, and (where relevant) the related ATT&CK technique ID. Lets a reader scan quickly instead of parsing paragraphs of prose for each entry. Pulling in technique IDs here directly reuses the mapping skill taught earlier in this Learning Path (in the MITRE ATT&CK module), giving the timeline both a \"what happened when\" and a \"why it mattered\" dimension in the same view.\n\n### Relative time deltas show speed and urgency\n\nAlongside absolute UTC timestamps, adding a relative delta from the first event (T+0, T+5m, T+14m) helps a reader immediately grasp how fast an intrusion actually moved: the difference between an attacker who took days to move from initial access to credential theft versus one who did it in fourteen minutes is operationally significant (a fast-moving intrusion likely warrants faster escalation and broader initial containment), and that speed is much more obvious from \"T+14m\" than from two absolute timestamps a reader has to mentally subtract.\n\n### Keep interpretation separate from raw fact, but include both\n\nA strong report includes the raw factual sequence (what the logs actually show) and a short interpretive summary (what this sequence means for the investigation), but keeps them visually distinct, for example, factual entries in the timeline table, with a short narrative paragraph above or below it. This mirrors the inference-versus-fact discipline from the previous page: a reader should always be able to tell which parts are directly observed and which are the analyst's reasoned interpretation.\n\n### Leading with the headline, not burying it\n\nEspecially for a busy reader (a manager skimming ten incident summaries in one sitting), leading the report with a one-paragraph summary of what happened and its current status, with the detailed timeline available immediately below for anyone who wants to verify the details, respects the reader's time without sacrificing rigor for those who need the full picture.",
        "codeExample": "| Time (UTC)          | T+     | Source   | Event                                  | Technique  |\n|---------------------|--------|----------|------------------------------------------|------------|\n| 2026-09-28T09:14:02Z | T+0   | Email GW | invoice_Q3.docm delivered from external  | T1566.001  |\n| 2026-09-28T09:26:41Z | T+13m | EDR      | powershell.exe -enc spawned by WINWORD  | T1059.001  |\n| 2026-09-28T09:41:09Z | T+27m | EDR      | rundll32.exe accessed lsass.exe memory  | T1003.001  |\n| 2026-09-28T09:52:37Z | T+39m | AD/DC    | rjones credential used on SRV-DB01      | T1078      |",
        "keyPoints": [
          "Present timelines as consistent tables (timestamp, source, event, related technique ID) rather than dense prose.",
          "Relative time deltas (T+0, T+13m) make the speed of an intrusion immediately visible in a way absolute timestamps alone do not.",
          "Keep raw factual entries visually separate from interpretive analysis, mirroring the inference-versus-fact discipline covered earlier.",
          "Lead a report with a short headline summary, with the detailed timeline available immediately below for verification."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Worked example: a phishing-to-lateral-movement timeline",
        "body": "Bring the full lesson together by walking through building one short timeline from raw log excerpts, applying the normalization, source-awareness, and presentation practices covered so far.\n\n### The raw evidence, as pulled from three different sources\n\n- Email gateway (native local time zone, UTC+3): \"09-28 12:14:02, invoice_Q3.docm delivered to rjones@nexacorp.example from external sender.\"\n- EDR console (already UTC): \"2026-09-28T09:26:41Z, powershell.exe (-enc ...) spawned by WINWORD.EXE on WKS-2210.\"\n- EDR console (already UTC): \"2026-09-28T09:41:09Z, rundll32.exe accessed lsass.exe memory, GrantedAccess 0x1FFFFF, on WKS-2210.\"\n- Active Directory domain controller Security log (UTC by default): \"2026-09-28T09:52:37Z, Event ID 4624 (logon success), Account: rjones, Logon Type: 3 (network), Source Workstation: WKS-2210, Target: SRV-DB01.\"\n\n### Step 1: normalize\n\nThe email gateway's timestamp is in local UTC+3 time; converting 09-28 12:14:02 local to UTC gives 2026-09-28T09:14:02Z. The other three sources are already UTC and require no conversion, but this should still be explicitly confirmed, not assumed, per the practice from page 3.\n\n### Step 2: sort and assemble\n\nOnce every timestamp is in UTC, sorting is mechanical: the four events fall in the exact order they were pulled above, spanning just 38 minutes from delivery to lateral movement, a fast-moving intrusion by the standard set on the previous page, which by itself is a signal worth calling out in the report's headline summary.\n\n### Step 3: annotate with technique IDs and present\n\nThe finished table from the previous page is exactly this timeline, fully normalized, with relative deltas and technique IDs attached, turning four disconnected, differently-formatted log lines from three separate systems into one clear, 38-minute story that any reader, technical or not, can follow from first delivery to confirmed lateral movement.",
        "codeExample": "sequenceDiagram\n    participant Attacker\n    participant Email as Email Gateway\n    participant WKS as WKS-2210\n    participant DC as Domain Controller\n    Attacker->>Email: invoice_Q3.docm (09:14:02Z)\n    Email->>WKS: Delivered to rjones\n    WKS->>WKS: powershell.exe -enc (09:26:41Z)\n    WKS->>WKS: rundll32 accesses lsass.exe (09:41:09Z)\n    WKS->>DC: rjones logon to SRV-DB01 (09:52:37Z)",
        "keyPoints": [
          "Normalizing a local-time source (email gateway, UTC+3) to UTC is a required step before it can be sorted alongside already-UTC sources.",
          "Even sources believed to already be UTC should be explicitly confirmed, not assumed, during normalization.",
          "Once normalized, sorting events chronologically is mechanical and reveals the true pace of the intrusion (38 minutes, in this example).",
          "The finished timeline combines normalized timestamps, relative deltas, and technique IDs into one coherent, readable narrative."
        ]
      }
    ],
    "quiz": [
      {
        "question": "Why must timestamps from different log sources be normalized to a single time standard before building a timeline?",
        "options": [
          {
            "label": "Because most SIEM platforms are technically unable to ingest events recorded in local time at all",
            "value": "a"
          },
          {
            "label": "Because without normalization, events from different sources cannot be reliably compared or correctly ordered",
            "value": "b"
          },
          {
            "label": "Because timestamps recorded in UTC consume noticeably less log storage space over time",
            "value": "c"
          },
          {
            "label": "Because only timestamps recorded in UTC are ever considered admissible in legal proceedings",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Log sources often record time in different formats or local time zones; without converting them all to one standard (UTC), an analyst cannot reliably tell which event actually happened first, leading to incorrect conclusions about cause and effect. SIEMs can ingest local-time data, storage size is unrelated, and legal admissibility depends on many factors beyond timestamp format."
      },
      {
        "question": "A firewall log and an EDR's network-connection telemetry are being compared, and their timestamps differ by several minutes. What is the most likely explanation this lesson describes?",
        "options": [
          {
            "label": "One of the two log sources has deliberately falsified what actually happened",
            "value": "a"
          },
          {
            "label": "NTP (Network Time Protocol) drift on one of the devices has caused its clock to be inaccurate",
            "value": "b"
          },
          {
            "label": "EDR platforms are fundamentally unable to record any network connection events",
            "value": "c"
          },
          {
            "label": "Firewalls never record any connection timestamps in their logs",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "When two sources that should agree closely (both recording the same real-world connection) differ by more than expected, NTP drift on one device's clock (from misconfiguration or extended time offline from its time source) is a common, realistic explanation covered in this lesson. Logs don't 'lie,' and both firewalls and EDR platforms routinely log connection events."
      },
      {
        "question": "An investigation has no EDR telemetry for a host between two dates because the EDR agent was not yet deployed during that window. What is the correct way to represent this in the timeline?",
        "options": [
          {
            "label": "Skip silently from the last known event to the next one as if the gap does not exist",
            "value": "a"
          },
          {
            "label": "Explicitly mark the gap with its date range and the reason it exists",
            "value": "b"
          },
          {
            "label": "Assume nothing happened during the gap and state that as a confirmed fact",
            "value": "c"
          },
          {
            "label": "Delete the investigation since the timeline cannot be completed",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The correct practice is to explicitly state the gap, its date range, and the reason (no agent deployed yet), so the reader knows exactly what is and is not known. Silently skipping the gap or asserting 'nothing happened' as fact both misrepresent the evidence; a data gap does not require abandoning the investigation."
      },
      {
        "question": "For a large-scale investigation combining forensic disk images, memory dumps, and multiple live log sources into one master timeline, which tool combination does this lesson recommend reaching for?",
        "options": [
          {
            "label": "A single spreadsheet built entirely from manually copy-pasted log entries",
            "value": "a"
          },
          {
            "label": "Plaso (log2timeline) to parse artifacts into a super timeline, optionally loaded into Timesketch for collaborative analysis",
            "value": "b"
          },
          {
            "label": "ATT&CK Navigator, since its layers are specifically designed for chronological timeline building",
            "value": "c"
          },
          {
            "label": "DeTT&CT, since its scoring methodology is designed to handle chronological event ordering",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Plaso parses many forensic artifact formats into one normalized 'super timeline,' and Timesketch provides a collaborative web interface for filtering and annotating large timelines built from Plaso's output: the right combination when scale and forensic artifacts exceed what a manual spreadsheet or SIEM view can handle. ATT&CK Navigator is for coverage heatmaps, and DeTT&CT scores detection coverage, not timelines."
      },
      {
        "question": "In a finished incident report, why does this lesson recommend adding relative time deltas (T+0, T+13m, T+27m) alongside absolute UTC timestamps?",
        "options": [
          {
            "label": "Because relative time deltas are an explicit formatting requirement under NIST SP 800-61",
            "value": "a"
          },
          {
            "label": "They make the speed and urgency of an intrusion immediately visible without the reader needing to mentally subtract timestamps",
            "value": "b"
          },
          {
            "label": "Because absolute UTC timestamps are not considered accurate enough for a formal investigation report",
            "value": "c"
          },
          {
            "label": "Because relative deltas remove the earlier need to normalize every timestamp to UTC first",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Relative deltas let a reader instantly see how fast an intrusion progressed (e.g., 38 minutes from delivery to lateral movement) without mentally subtracting absolute timestamps, which is operationally useful for judging urgency. This is a presentation best practice, not a NIST requirement, does not imply absolute timestamps are inaccurate, and does not replace UTC normalization. It is built on top of it."
      }
    ]
  },
  "soc-analyst--pivoting-on-entities": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What an entity is, and why pivoting expands the picture",
        "body": "The previous lesson built a timeline from one host's worth of evidence. But almost every real intrusion touches more than one host, more than one account, and more than one piece of outside infrastructure, and a timeline built from only the first host you happened to look at will systematically understate the true scope of an incident. **Pivoting** is the technique of using one piece of evidence, an **entity**, as the starting point for a new query that reveals other, related evidence you had not yet found.\n\n### Defining the common entity types\n\nAn entity, in this context, is any single, identifiable \"thing\" that shows up across multiple log sources and can be searched on directly:\n\n| Entity type | Example | Typical field |\n|---|---|---|\n| **Host** | WKS-2210 | DeviceName / Computer / host.name |\n| **User / account** | rjones | AccountName / user.name |\n| **IP address** | 203.0.113.45 | RemoteIP / source.ip / destination.ip |\n| **Domain** | portal-cdn-sync.example | RemoteUrl / dns.question.name |\n| **File hash** | SHA256 value | SHA256 / file.hash.sha256 |\n| **Process** | rundll32.exe (specific PID) | ProcessId / process.pid |\n\n### The core pivot pattern\n\nEvery pivot follows the same shape: take an entity value you already know is relevant (because it showed up in a confirmed malicious event), and search *every other log source you have* for that same value, across a reasonable time window. Each hit either confirms the entity's involvement in a wider pattern or surfaces a brand-new host, user, or indicator you had not previously connected to the incident. This lesson works through the five most common pivot directions (host, user, IP, domain, and hash) in the order an investigation typically discovers them, then shows how they chain together into one continuous investigation.",
        "codeExample": "flowchart LR\n    A[Confirmed malicious event\\non Host A] --> B[Pivot: who was\\nlogged on?]\n    B --> C[User account X]\n    C --> D[Pivot: where else\\ndid X log on?]\n    D --> E[Host B, Host C]",
        "keyPoints": [
          "Pivoting uses a known-relevant entity (host, user, IP, domain, hash) as the starting point for a new query across other log sources.",
          "An entity is any identifiable 'thing' that appears consistently across multiple log sources under a searchable field name.",
          "The core pivot pattern: take a confirmed-relevant value, search every other source for it, and evaluate each new hit.",
          "This lesson covers five pivot directions (host, user, IP, domain, hash) and how they chain into one continuous investigation."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Pivoting from a host",
        "body": "The most natural starting pivot, once a single malicious event is confirmed on a specific machine, is to ask: what else happened on that same host, in the surrounding time window? This is usually the very first pivot performed in any investigation, because it is the cheapest to run and often the highest-yield.\n\n### Why a host-scoped pivot comes first\n\nA single alert typically only shows one event out of everything that actually happened on the host: the process that triggered the alert, but not necessarily the process that spawned it, the files it touched, or the network connections it made around the same time. Pulling the full activity timeline for that specific host (using its unique **DeviceId**, or **DeviceName**/hostname, as the pivot key) across a window before and after the alert usually surfaces the surrounding context needed to understand the full attack chain on that one machine, before expanding outward to other machines.\n\n### A concrete query pattern\n\nIn Microsoft Defender Advanced Hunting, DeviceProcessEvents and DeviceNetworkEvents share a common DeviceId field, which is the reliable way to join process activity and network activity for the same host. Hostnames can occasionally be reused or renamed, but the DeviceId stays stable for the lifetime of that specific device's enrollment.\n\n### What to look for once pivoted\n\n- Parent-child process relationships around the confirmed malicious process (what spawned it, what it spawned).\n- Any file creation or modification events in the same window (a dropped payload, a dumped credential file).\n- Any outbound network connections from the host in the same window (potential command-and-control, covered in the mapping-alerts lesson).\n- Any new scheduled tasks, services, or registry persistence created around the same time.\n\nA thorough host pivot often surfaces two or three additional confirmed-malicious events on the very same machine before an analyst even needs to look at a second host, which is exactly why it is the right first pivot to run.",
        "codeExample": "# KQL: full activity window for one host, joined across two Advanced Hunting tables\nlet TargetDevice = \"WKS-2210\";\nlet AlertTime = datetime(2026-09-28T09:41:09Z);\nDeviceProcessEvents\n| where DeviceName == TargetDevice\n| where Timestamp between (AlertTime - 30m .. AlertTime + 30m)\n| union (\n    DeviceNetworkEvents\n    | where DeviceName == TargetDevice\n    | where Timestamp between (AlertTime - 30m .. AlertTime + 30m)\n  )\n| sort by Timestamp asc",
        "keyPoints": [
          "The host pivot is usually the first pivot run: pull all activity on the same machine around the confirmed malicious event's time window.",
          "A stable identifier like DeviceId is more reliable for joining tables than a hostname, which can occasionally be reused or renamed.",
          "Look for parent-child process relationships, file creation, network connections, and new persistence mechanisms in the surrounding window.",
          "A thorough host pivot frequently surfaces additional confirmed-malicious events before an analyst needs to look at a second host."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Pivoting from a user account",
        "body": "Once the host-level picture is clear, the next natural pivot is the account that was logged on when the malicious activity occurred, because if a credential was compromised, the attacker's next move is often to reuse that same credential somewhere else, and finding that reuse quickly can be the difference between a single-host incident and a multi-host breach.\n\n### Finding the logged-on account\n\nMicrosoft Defender Advanced Hunting's DeviceLogonEvents table records which AccountName was logged onto a given device at a given time, letting an analyst confirm exactly which account was active on the host during the malicious activity window identified in the host pivot.\n\n### Pivoting outward from the account\n\nWith the account name in hand, the pivot direction flips: instead of asking \"what else happened on this host,\" the question becomes \"what else did this account do, on any host, in this time window?\" This is precisely the query that would have revealed, in the worked example from the mapping-alerts-to-attack lesson, that the account jsmith authenticated to two additional workstations shortly after the credential-theft event on the first host, the account pivot is what turns a single-host credential-dumping alert into a confirmed multi-host lateral-movement incident.\n\n### Extending into cloud identity\n\nModern environments almost always have a cloud identity component alongside on-premises Active Directory, and a compromised on-premises credential is sometimes also valid for cloud services (this is one of the risks behind hybrid identity setups). Microsoft Sentinel's **SigninLogs** table records Azure AD / Entra ID sign-in activity, including the account name, source IP, location, and application accessed, pivoting the same account name into SigninLogs checks whether the same compromised credential was also used to access cloud resources, which the on-premises Windows event logs alone would never reveal.\n\n### Why this pivot matters so much\n\nCredential-based lateral movement (ATT&CK's T1078 Valid Accounts) is deliberately quiet. It uses a legitimate account doing something that looks, on the surface, like normal authentication, so it will not trigger the same kind of alert a malware detection would. The user pivot is often the *only* way this activity gets found at all.",
        "codeExample": "# KQL: where else did this account authenticate, on-prem and in the cloud?\nlet CompromisedAccount = \"jsmith\";\nlet WindowStart = datetime(2026-09-28T09:41:00Z);\nDeviceLogonEvents\n| where AccountName == CompromisedAccount\n| where Timestamp > WindowStart\n| project Timestamp, DeviceName, LogonType, RemoteIP\n| union (\n    SigninLogs\n    | where UserPrincipalName startswith CompromisedAccount\n    | where TimeGenerated > WindowStart\n    | project Timestamp = TimeGenerated, DeviceName = AppDisplayName,\n              LogonType = \"cloud\", RemoteIP = IPAddress\n  )\n| sort by Timestamp asc",
        "keyPoints": [
          "DeviceLogonEvents identifies which account was logged onto a host during a malicious activity window, confirming which credential to pivot on.",
          "Pivoting the account across all hosts (not just the original one) is how single-host credential theft becomes a confirmed multi-host lateral-movement finding.",
          "SigninLogs in Microsoft Sentinel extends the account pivot into cloud identity (Azure AD / Entra ID), catching compromised-credential reuse against cloud resources.",
          "The user pivot is often the only way to find T1078 Valid Accounts activity, since credential reuse looks like normal authentication on the surface."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Pivoting from an IP address",
        "body": "When the confirmed-malicious evidence is a network connection rather than a process or a logon, the pivot target is a remote IP address, and the question shifts to: what else, across the entire environment, has talked to this same address?\n\n### Finding shared infrastructure\n\nSearching network-connection logs (DeviceNetworkEvents, firewall logs, or proxy logs) for every host that connected to a specific remote IP within a relevant time window can reveal that the \"single infected host\" from the original alert is actually one of several hosts that all reached out to the same command-and-control infrastructure. Evidence of a broader campaign rather than an isolated incident, and a strong signal that the initial delivery mechanism (a phishing campaign, for example) reached more than one victim.\n\n### Enriching the IP before trusting it too much\n\nNot every shared connection to an IP is meaningful: a shared cloud provider's IP range, a widely-used CDN (Content Delivery Network), or a large SaaS platform's shared infrastructure can produce many unrelated hosts connecting to the same address for entirely legitimate reasons, which would make an IP pivot noisy and potentially misleading if taken at face value. Before drawing conclusions from an IP pivot, enrich the IP with external threat intelligence: WHOIS registration data (who registered the address space and when), and passive DNS history (what domain names have historically resolved to this IP) both help distinguish \"dedicated attacker infrastructure\" from \"shared hosting that happens to also serve legitimate traffic.\"\n\n### A caution about pivot breadth\n\nAn IP pivot on a narrow, dedicated attacker IP (a fresh VPS, Virtual Private Server, registered days before the attack, hosting only the malicious domain) will produce a small, high-confidence set of related hosts. An IP pivot on a shared, high-traffic IP will produce a large, low-confidence set that is not actually useful for scoping, recognizing the difference before spending investigation time chasing every hit is an important judgment call, covered further on the \"when to stop pivoting\" page later in this lesson.",
        "codeExample": "# KQL: find every host that connected to a specific suspicious IP\nlet SuspiciousIP = \"203.0.113.45\";\nDeviceNetworkEvents\n| where RemoteIP == SuspiciousIP\n| where Timestamp > ago(30d)\n| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),\n            ConnectionCount = count() by DeviceName\n| sort by ConnectionCount desc",
        "keyPoints": [
          "An IP pivot searches for every host that connected to a specific remote address, potentially revealing a broader campaign beyond the original alert.",
          "Shared infrastructure (CDNs, cloud provider ranges, large SaaS platforms) can make an IP pivot noisy. Many unrelated hosts may share an IP for legitimate reasons.",
          "Enrich a suspicious IP with WHOIS registration data and passive DNS history before treating every connecting host as compromised.",
          "A narrow, dedicated attacker IP yields a small, high-confidence pivot result; a shared high-traffic IP yields a large, low-confidence one."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Pivoting from a domain and from a file hash",
        "body": "The final two pivot directions in this lesson's core set target a malicious domain name and a specific file, and each answers a distinct question the previous three pivots cannot.\n\n### Domain pivot: who else resolved this name?\n\nPivoting on a malicious domain (rather than the IP it currently resolves to) searches DNS query logs across the environment for any host that attempted to resolve that domain name, regardless of which IP address it pointed to at the time. Useful because attacker infrastructure sometimes rotates the IP address behind a domain while keeping the domain name itself constant, meaning a domain pivot can catch victims an IP-only pivot would miss if the domain's DNS record had already changed since the original infection.\n\n### Hash pivot: who else ran this exact file?\n\nA file's **SHA256** hash is a fixed-length value computed from its exact byte content. Any change to the file, even a single byte, produces a completely different hash, which makes a hash match a very high-confidence indicator that two files are byte-for-byte identical (unlike a filename, which is trivial for an attacker to rename). Pivoting on a confirmed-malicious file's SHA256 hash across DeviceFileEvents and DeviceProcessEvents (checking both file-creation events and process-execution events, since the same file might be observed as a dropped file on one host and an executed process on another) answers the question \"which other hosts in the environment have this exact file present or running,\" directly enabling a \"hunt for other victims\" sweep across the whole fleet, not just the hosts already flagged by an alert.\n\n### Why both matter, and why order can vary\n\nA domain pivot tends to be broader and faster to run (DNS logs are usually well-indexed and complete); a hash pivot tends to be the highest-confidence but requires the file to have actually been captured or fingerprinted somewhere first. In practice, whichever indicator becomes available first in an investigation is the one worth pivoting on immediately. There is no fixed requirement to always do domain before hash or vice versa, unlike the host-then-user ordering recommended on earlier pages.",
        "codeExample": "# KQL: domain pivot (catches hosts even if the IP behind the domain rotated)\nDeviceNetworkEvents\n| where RemoteUrl == \"portal-cdn-sync.example\"\n| summarize count() by DeviceName\n\n# KQL: hash pivot across both file-creation and execution telemetry\nlet MaliciousHash = \"8f14e45fceea167a5a36dedd4bea2543c8b7f1a2e9d0f3a5c6b7d8e9f0a1b2c\";\nunion\n  (DeviceFileEvents    | where SHA256 == MaliciousHash),\n  (DeviceProcessEvents | where SHA256 == MaliciousHash)\n| summarize FirstSeen = min(Timestamp) by DeviceName, ActionType",
        "keyPoints": [
          "A domain pivot finds every host that queried a malicious domain, catching victims even if the domain's underlying IP address has since rotated.",
          "SHA256 is a fixed-length fingerprint of a file's exact byte content; a hash match is far more reliable evidence of identity than a filename match.",
          "A hash pivot across both file-creation and process-execution telemetry enables a fleet-wide hunt for other victims of the same file.",
          "Domain and hash pivots have no fixed required order relative to each other. Use whichever indicator is confirmed first."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Chaining pivots into one investigation",
        "body": "Individually, each pivot direction answers one question. Chained together in sequence, they turn a single confirmed alert into a complete, environment-wide picture of an incident's true scope, which is the actual goal of entity-based investigation.\n\n### The full chain, worked through\n\nReturning to the recurring NexaCorp scenario from this module: a host pivot on WKS-2210 confirms the full local attack chain (macro execution, PowerShell, LSASS access). A user pivot on the account active during that activity (rjones) reveals a second host, SRV-DB01, authenticated to shortly afterward, extending the incident from one host to two. A domain pivot on the phishing delivery domain reveals two additional employees received the same malicious attachment, neither of whom had opened it yet, extending the incident from a confirmed compromise to a wider, contained exposure that needs preventive action (blocking, user notification) rather than reactive cleanup. A hash pivot on the dropped payload's SHA256 confirms no other host in the fleet has executed that exact file: a reassuring negative result that helps establish the outer boundary of the incident's scope.\n\n### Why the chain, not just one pivot, defines scope\n\nStopping after only the host and user pivots would have left the incident's true boundary understated, two additional at-risk employees would have gone unnotified, and the phishing domain might not have been blocked as quickly. Each pivot direction covers a blind spot the others cannot: host pivots miss cross-host activity, user pivots miss unopened-but-received phishing, IP/domain pivots miss activity not yet execution-confirmed, and hash pivots miss activity using a different file entirely. A mature investigation runs enough of the chain to be confident the incident's actual boundary has been found, not just the first host that happened to alert.",
        "codeExample": "flowchart TD\n    A[\"Confirmed alert: WKS-2210\\nrundll32 accesses lsass.exe\"] --> B[\"Host pivot:\\nfull local attack chain\"]\n    B --> C[\"User pivot (rjones):\\nSRV-DB01 also authenticated\"]\n    C --> D[\"Domain pivot\\n(delivery domain):\\n2 more recipients found\"]\n    D --> E[\"Hash pivot (payload SHA256):\\nno other execution found\"]\n    E --> F[\"Incident scope established:\\n2 hosts compromised,\\n2 recipients need notification\"]",
        "keyPoints": [
          "Chaining host, user, domain, and hash pivots together builds a complete picture of an incident's true scope, not just its first-found host.",
          "Each pivot direction covers a distinct blind spot the others cannot: cross-host activity, unopened phishing, unresolved infrastructure, or differently-named copies of the same file.",
          "A negative pivot result (no other host executed the same hash) is still valuable. It helps establish the outer boundary of the incident.",
          "Stopping the pivot chain too early risks understating scope and missing preventive actions (like notifying at-risk but not-yet-compromised users)."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Knowing when to stop pivoting",
        "body": "Pivoting is powerful precisely because each result can open a new thread to follow, which also makes it possible to pivot indefinitely without ever reaching a conclusion, especially once a pivot lands on shared or noisy infrastructure (as discussed on the IP-pivot page).\n\n### Diminishing returns as a signal to stop\n\nA pivot chain reaches diminishing returns when successive queries stop surfacing genuinely new, actionable findings. Repeatedly confirming the same small set of hosts and accounts across several different pivot directions is a sign the incident's boundary has likely been found, whereas each new pivot still turning up previously-unseen hosts is a sign the investigation is not yet complete and should continue.\n\n### Time-boxing the investigation\n\nA practical, widely-used discipline is to set an explicit time budget for the scoping phase of an investigation (for example, \"two hours to establish initial scope before escalating with current findings\"), rather than letting pivoting continue indefinitely while the incident goes unaddressed in the meantime. This does not mean stopping the investigation entirely at the time-box boundary. It means escalating with the best current understanding of scope, clearly labeled as provisional, and continuing deeper investigation in parallel with the response actions (containment, from the earlier lesson in this path) that the current findings already justify.\n\n### A defined scope statement, not an open-ended search\n\nThe goal of a pivot chain is to reach a defensible, written scope statement, for example, \"2 hosts confirmed compromised (WKS-2210, SRV-DB01); 2 additional recipients of the phishing email identified as at-risk but not compromised; no other hosts in the fleet found running the identified payload hash as of [timestamp]\", rather than an open-ended, never-quite-finished search. A scope statement with an explicit \"as of\" timestamp is honest about the fact that new evidence could still emerge, without using that possibility as a reason to withhold action on what is already known.",
        "codeExample": "# Scope statement template (paste into incident ticket once pivoting concludes)\nScope as of: 2026-09-28T11:15:00Z\nConfirmed compromised hosts: WKS-2210, SRV-DB01\nAt-risk (received but did not open) recipients: 2 (notified, attachment quarantined)\nHash pivot result: negative - no other host in fleet has executed\n  8f14e45fceea167a5a36dedd4bea2543... as of this timestamp\nPivot chain run: host -> user -> domain -> hash (see linked queries)\nNext step: continue monitoring for new hash/domain hits; scope may expand\n  if new evidence emerges.",
        "keyPoints": [
          "Diminishing returns (successive pivots confirming the same small set rather than surfacing new hosts) is the main signal that an incident's boundary has likely been found.",
          "Time-boxing the scoping phase prevents open-ended pivoting from delaying necessary containment and escalation.",
          "Reaching the time-box does not mean stopping investigation. It means escalating current findings as provisional and continuing in parallel.",
          "A good scope statement includes an explicit 'as of' timestamp, acknowledging that new evidence could still emerge without withholding action on what is already known."
        ]
      }
    ],
    "quiz": [
      {
        "question": "Why is the host pivot typically the first pivot run in an investigation, before pivoting on a user account?",
        "options": [
          {
            "label": "Because SOC playbooks are legally required to perform a host pivot before any other pivot type",
            "value": "a"
          },
          {
            "label": "It is usually the cheapest to run and reveals the full local attack chain around the confirmed event before expanding outward",
            "value": "b"
          },
          {
            "label": "Because a user-account pivot is technically impossible until a host pivot has fully completed",
            "value": "c"
          },
          {
            "label": "Because host pivots always take noticeably longer to run, so starting them early saves time overall",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Pulling the full activity timeline for the affected host is usually the cheapest, highest-yield first step, often surfacing additional confirmed-malicious events on the same machine before an analyst needs to expand to other hosts or accounts. There is no legal requirement or technical dependency forcing this order, and host pivots are not inherently slower."
      },
      {
        "question": "A credential-dumping alert fires on one host. Pivoting on the account that was logged on reveals it authenticated to two additional workstations shortly afterward. What does this illustrate?",
        "options": [
          {
            "label": "The user pivot turned a single-host alert into a confirmed multi-host lateral-movement finding",
            "value": "a"
          },
          {
            "label": "The account must be a false positive since it logged into multiple hosts",
            "value": "b"
          },
          {
            "label": "This is unrelated to the original alert and should be ignored",
            "value": "c"
          },
          {
            "label": "IP pivots are more reliable than user pivots for this scenario",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Pivoting on the compromised account revealed activity (authentication to new hosts) that the original single-host alert never showed, extending the incident's known scope from one host to multiple: exactly the value of the user pivot, especially for quiet, credential-based lateral movement (T1078 Valid Accounts). Multiple logons are not evidence of a false positive, the activity is directly related given the timing, and this scenario does not involve an IP at all."
      },
      {
        "question": "Why can pivoting on a widely-shared IP address (such as a large CDN's shared infrastructure) be misleading if taken at face value?",
        "options": [
          {
            "label": "Shared IP addresses cannot technically be queried through a SIEM's search interface",
            "value": "a"
          },
          {
            "label": "Many unrelated hosts may connect to the same shared IP for entirely legitimate reasons, producing a large, low-confidence result set",
            "value": "b"
          },
          {
            "label": "Shared IP addresses never actually appear in a table like DeviceNetworkEvents",
            "value": "c"
          },
          {
            "label": "IP pivots are only technically capable of matching internal addresses, never external ones",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Shared infrastructure like CDNs or cloud provider ranges can be used by many unrelated hosts for legitimate reasons, so a pivot on such an IP produces a noisy, low-confidence result rather than a clean set of related, compromised hosts. This is why enriching the IP with WHOIS and passive DNS history before drawing conclusions matters. Shared IPs are fully queryable and commonly appear in network telemetry, and IP pivots work on any address, internal or external."
      },
      {
        "question": "What advantage does pivoting on a malicious domain name have over pivoting only on the IP address it currently resolves to?",
        "options": [
          {
            "label": "Domain pivots are always faster to execute than IP pivots",
            "value": "a"
          },
          {
            "label": "A domain pivot can catch victims even if the attacker has since rotated the IP address behind the domain",
            "value": "b"
          },
          {
            "label": "Domains cannot be spoofed, unlike IP addresses",
            "value": "c"
          },
          {
            "label": "DNS logs are more complete than network connection logs in every environment",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Attacker infrastructure sometimes rotates the IP address behind a domain while keeping the domain name constant; pivoting on the domain itself (via DNS query logs) catches hosts that resolved it even after the underlying IP changed, which an IP-only pivot would miss. This has nothing to do with relative speed, domain spoofing resistance, or a blanket claim about DNS log completeness across all environments."
      },
      {
        "question": "An analyst has been pivoting for several hours, and each new query keeps confirming the same two hosts and one account already identified, with no new findings. What does this lesson recommend?",
        "options": [
          {
            "label": "Keep pivoting indefinitely until absolutely certain that no more evidence could ever possibly exist anywhere",
            "value": "a"
          },
          {
            "label": "Treat the repeated confirmations as a sign of diminishing returns, finalize a scope statement with a timestamp, and escalate/act on current findings",
            "value": "b"
          },
          {
            "label": "Discard all findings gathered so far, since the most recent round of queries produced no new results",
            "value": "c"
          },
          {
            "label": "Pause the investigation and wait for a different analyst to take over without recording any findings",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Repeated confirmation of the same small set of entities across multiple pivot directions is the signal of diminishing returns described in this lesson: the right response is to finalize a scope statement (with an explicit 'as of' timestamp) and act on current findings, continuing deeper investigation in parallel rather than pivoting indefinitely. Discarding findings or waiting without documentation both waste the investigation work already done."
      }
    ]
  },
  "soc-analyst--verdict-workflows": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why every alert needs a verdict",
        "body": "Every alert a SOC investigates eventually has to be closed with a **verdict**: a formal classification of what the evidence showed. This might seem like paperwork layered on top of the \"real\" investigative work covered in the rest of this module, but the verdict is actually where an individual investigation's findings become organizational knowledge: it is the single piece of data that determines whether a detection rule gets tuned, whether an account gets scrutinized further, and whether the SOC's own detection-quality metrics look healthy or need attention.\n\n### An analogy: closing a medical chart\n\nA doctor's visit does not end when treatment is decided. It ends when the visit is coded with a diagnosis, because that code is what feeds insurance billing, public health statistics, and the patient's permanent record. An alert works the same way: the investigative work (the triage, the timeline, the pivoting covered in earlier lessons) is like the doctor's exam, and the verdict is the diagnosis code that makes the visit's outcome usable by everyone downstream who was not in the room.\n\n### The four verdict categories this lesson covers\n\nMicrosoft Sentinel's own incident-closing workflow, used here as a concrete, well-documented reference point (the same classification logic applies conceptually across most SIEM/SOAR platforms even where the exact labels differ), defines four classifications an analyst chooses from when closing an incident:\n\n- **True Positive – Suspicious Activity**\n- **Benign Positive – Suspicious but Expected**\n- **False Positive – Incorrect Alert Logic**\n- **Undetermined**\n\nThe next several pages work through each of these in depth. What it means, what workflow it triggers, and the mistake analysts most commonly make in applying it: before closing with what a complete, well-documented closing note looks like in practice.",
        "codeExample": "flowchart TD\n    A[Alert investigated] --> B{Did the described\\nactivity actually happen?}\n    B -- No, alert logic was wrong --> C[False Positive]\n    B -- Yes --> D{Was it malicious?}\n    D -- Yes --> E[True Positive]\n    D -- No, expected/authorized --> F[Benign Positive]\n    B -- Not enough evidence to say --> G[Undetermined]",
        "keyPoints": [
          "A verdict is the formal classification an analyst assigns when closing an alert, and it is what turns an individual investigation into organizational knowledge.",
          "Verdicts feed detection-quality metrics and inform whether a rule gets tuned or an account gets further scrutiny.",
          "This lesson uses Microsoft Sentinel's four incident-closing classifications as a concrete reference: True Positive, Benign Positive, False Positive, Undetermined.",
          "The same underlying classification logic applies conceptually across most SIEM/SOAR platforms even where exact labels differ."
        ]
      },
      {
        "pageNumber": 2,
        "title": "True Positive: confirmed malicious activity",
        "body": "A **True Positive** (labeled in Microsoft Sentinel as \"True Positive – Suspicious Activity\") means the investigation confirmed that the activity described by the alert genuinely happened, and that it was malicious. This is the verdict every worked example throughout this Learning Path has been building toward: the LSASS memory access, the phishing-to-PowerShell chain, the lateral movement to a second host. All of it, once confirmed through investigation, resolves to True Positive.\n\n### What a True Positive verdict triggers\n\nReaching a True Positive verdict is not simply a label applied at the very end, in practice it is usually reached *during* the investigation, well before the ticket is formally closed, and it is what justifies the containment actions covered earlier in this Learning Path (in the containment-basics lesson) happening as soon as the evidence supports them, rather than waiting for a final close-out. By the time an analyst is ready to record the verdict, containment, scoping (via pivoting), and initial escalation have typically already occurred.\n\n### Documentation requirements for a True Positive\n\nA True Positive closing note needs more supporting detail than any other verdict, because it is the record other analysts, IR leads, and sometimes auditors will rely on later: the full list of IOCs (Indicators of Compromise) involved, every host and account confirmed affected (from the pivot chain), the ATT&CK technique IDs mapped, what containment actions were taken and when, and the current eradication/recovery status if not yet fully resolved.\n\n### A common mistake: closing too early\n\nMarking an alert True Positive the moment malicious activity is *first* confirmed, without completing the scoping pivots from the earlier lesson, risks closing the ticket while the true extent of the incident is still unknown, a partial True Positive closure that undercounts affected hosts or accounts produces a false sense of resolution and can leave real exposure unaddressed. The verdict should reflect the investigation's actual, current scope, updated if new pivots later expand it.",
        "codeExample": "# True Positive closing note template\nVerdict: True Positive - Suspicious Activity\nIOCs: SHA256 8f14e45f..., domain portal-cdn-sync.example, IP 203.0.113.45\nTechniques: T1566.001, T1059.001, T1003.001, T1078\nHosts confirmed affected: WKS-2210, SRV-DB01\nContainment actions: network isolation (both hosts), jsmith account disabled,\n  domain sinkholed - all completed 2026-09-28T10:05Z\nStatus: Eradication complete; recovery in progress; monitoring for\n  reappearance of confirmed hash/domain indicators.",
        "keyPoints": [
          "A True Positive verdict confirms both that the alerted activity happened and that it was malicious.",
          "The verdict is typically reached during the investigation, justifying containment actions well before formal ticket closure.",
          "A True Positive closing note requires full IOC lists, confirmed affected hosts/accounts, technique IDs, and containment status.",
          "Closing as True Positive before scoping pivots are complete risks undercounting the incident's true extent."
        ]
      },
      {
        "pageNumber": 3,
        "title": "False Positive: the alert logic itself was wrong",
        "body": "A **False Positive** (\"False Positive – Incorrect Alert Logic\" in Sentinel's terminology) means the alert fired, but the activity it claims to describe either did not actually occur as described, or the detection rule's logic incorrectly flags a category of activity that was never actually risky in the first place. The defining characteristic of a False Positive is that the *rule itself* is wrong, not that the underlying activity turned out to be harmless (that distinction is exactly what separates a False Positive from the next verdict, Benign Positive, on the following page).\n\n### A concrete example\n\nA detection rule intended to catch encoded PowerShell commands (T1059.001) might be written with logic that also happens to match a completely unrelated, common administrative script's normal syntax due to a coding oversight in the rule. Every time that legitimate script runs, the rule fires, even though nothing about the rule's stated intent (catching malicious encoding) was ever actually present. Once identified, this is a textbook False Positive: the rule's logic, not the observed activity, is the problem.\n\n### The correct response: fix the rule, don't just close the ticket\n\nRepeatedly investigating and closing the same False Positive alert, week after week, without ever tuning the underlying detection rule, wastes analyst time on a problem that has already been diagnosed and contributes directly to **alert fatigue**, the well-documented phenomenon where analysts, worn down by a high volume of low-value alerts, start reflexively dismissing new alerts without adequately investigating them, occasionally missing a genuine True Positive buried among the noise as a result. The correct response to a confirmed False Positive is to escalate a fix to whoever owns the detection rule (tightening its logic, adding an exception condition, or in some cases retiring the rule entirely if it cannot be made reliable).\n\n### Documenting a False Positive well\n\nEven though a False Positive requires less evidence documentation than a True Positive, the closing note should still clearly state *why* the rule's logic was wrong and what specific fix is being requested. This is what actually breaks the cycle of repeated, unproductive re-investigation, rather than a bare \"false positive, closing\" note that leaves the next analyst to rediscover the same root cause from scratch.",
        "codeExample": "# False Positive closing note template\nVerdict: False Positive - Incorrect Alert Logic\nAlert: \"Suspicious Encoded PowerShell Command\" (Rule ID: DET-0442)\nRoot cause: Rule regex matches the base64-encoded config blob used by\n  NexaCorp's approved backup script (Backup-DailyJob.ps1), which is not\n  malicious and runs nightly on all servers.\nRequested fix: Add exception for InitiatingProcessFileName == \"Backup-DailyJob.ps1\"\n  AND ProcessCommandLine containing the known backup-script signature string.\nEscalated to: Detection Engineering, ticket DET-ENG-118",
        "keyPoints": [
          "A False Positive means the detection rule's own logic is wrong: the activity it claims to flag never actually matched the rule's real intent.",
          "This differs from a Benign Positive, where the rule correctly fired on real activity that simply was not malicious.",
          "Repeatedly closing the same False Positive without fixing the rule wastes time and contributes to alert fatigue, risking missed True Positives.",
          "A good False Positive closing note states the specific root cause and requested fix, not just the verdict label."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Benign Positive: real activity, correctly detected, not malicious",
        "body": "A **Benign Positive** (\"Benign Positive – Suspicious but Expected\" in Sentinel's terminology) is the verdict most often confused with False Positive, and the distinction matters enough to warrant its own page. In a Benign Positive, the detection rule worked *exactly as designed* (the activity it describes genuinely happened, matching the rule's real intent) but the activity turns out to be legitimate and expected rather than malicious.\n\n### A concrete example\n\nA rule designed to flag privilege escalation on a domain controller correctly fires because an IT administrator genuinely did elevate their own access to deploy an approved, scheduled infrastructure change. The rule's logic is completely correct (privilege escalation genuinely occurred, exactly as the rule is designed to catch) but this specific instance was authorized, planned, and legitimate. Another common example: a rule flagging unusual outbound scanning traffic correctly fires during an authorized, scheduled penetration test.\n\n### Why this distinction changes the fix\n\nBecause the rule's logic is not the problem in a Benign Positive, \"fixing the rule\" (as recommended for a False Positive on the previous page) is the wrong response, doing so would blind the SOC to a *real* instance of the same technique used maliciously in the future, since the rule was working correctly. Instead, the correct response is a narrow, specifically-scoped suppression or allow-list entry (for example: suppress this specific rule for this specific admin account during this specific approved change window, or suppress it only for the specific source IP range used by the approved penetration-testing team). Narrow enough that a genuinely malicious instance of the same technique, from a different account or a different IP, still fires normally.\n\n### The risk of getting this wrong\n\nA Benign Positive suppressed too broadly (for example, exempting an entire admin group permanently instead of one account for one change window) can quietly create a lasting blind spot that an attacker who later compromises any account in that broadly-exempted group could exploit undetected, turning a correctly-working detection into a permanent, unmonitored gap. This is precisely the kind of coverage regression the coverage-thinking lesson, earlier in this Learning Path, warned against creating unintentionally.",
        "codeExample": "# Benign Positive closing note template\nVerdict: Benign Positive - Suspicious but Expected\nAlert: \"Unauthorized Privilege Escalation on Domain Controller\" (Rule ID: DET-0219)\nRoot cause: Genuine privilege escalation confirmed - performed by\n  admin.smith@nexacorp.example during approved change CHG-4471\n  (scheduled infrastructure patch, ticket linked).\nAction: Narrow suppression added for admin.smith during change window\n  2026-09-28T22:00Z to 2026-09-29T02:00Z ONLY. Rule remains fully active\n  for all other accounts and time windows.\nReviewed by: change-approval owner (ticket CHG-4471)",
        "keyPoints": [
          "A Benign Positive means the detection rule fired correctly on real activity that simply turns out to be legitimate and expected, not malicious.",
          "Unlike a False Positive, the rule's logic is not the problem in a Benign Positive, so 'fixing the rule' is the wrong response.",
          "The correct response is a narrowly-scoped suppression (specific account, specific time window) rather than broadly disabling the rule.",
          "An overly broad Benign Positive suppression can create a lasting, unintended blind spot exploitable by a future attacker."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Undetermined: honest uncertainty, and how to handle it",
        "body": "Not every investigation reaches a confident conclusion within the time and evidence available, and **Undetermined** exists specifically for that situation. It is the professionally correct verdict when the evidence genuinely does not support confidently choosing True Positive, False Positive, or Benign Positive, rather than a verdict to avoid using out of a reluctance to admit uncertainty.\n\n### When Undetermined is the right call\n\nA typical scenario: a log source needed to confirm or rule out malicious intent was not retained long enough to still be available (a common consequence of the log-retention limits mentioned in the timelines lesson), or a key piece of context (whether a specific action was authorized) requires confirmation from a business stakeholder who has not yet responded. In both cases, guessing at a verdict to close the ticket faster produces worse organizational knowledge than honestly recording what is and is not known.\n\n### The risk of misusing Undetermined\n\nUndetermined can be misused as an escape hatch to avoid the harder work of a proper investigation, or, more insidiously, as a way to avoid the discomfort of labeling a colleague's or a business unit's activity as suspicious pending clarification. A verdict of Undetermined should always be paired with a specific, documented statement of exactly what evidence is missing and what would resolve the question, not a vague \"insufficient information\" note that gives no path forward for the next analyst.\n\n### Undetermined still requires action\n\nAn alert closed as Undetermined is not the same as a resolved alert, and should not be treated as equivalent to a closed, settled case. Best practice includes: documenting the specific missing evidence, setting a reasonable revisit timeframe or trigger condition (for example, \"revisit if this account exhibits similar activity again within 30 days\"), and, depending on organizational risk tolerance, applying a lightweight precautionary measure (increased monitoring on the account or host in question) even while the verdict itself remains open, rather than treating \"undetermined\" as equivalent to \"no further action needed.\"",
        "codeExample": "# Undetermined closing note template\nVerdict: Undetermined\nAlert: \"Unusual after-hours file access pattern\" - user jsmith, SRV-FILE02\nMissing evidence: Business stakeholder (jsmith's manager) has not yet\n  confirmed whether after-hours access was pre-authorized for a project\n  deadline (per jsmith's own claim, unconfirmed as of ticket close).\nInterim action: Enhanced monitoring flag added on jsmith's account for 30 days.\nRevisit trigger: Re-open immediately if similar access pattern recurs before\n  manager confirmation is received, or automatically in 30 days if unconfirmed.",
        "keyPoints": [
          "Undetermined is the professionally correct verdict when evidence genuinely does not support a confident True/False/Benign Positive call.",
          "Common causes include expired log retention or pending confirmation from a business stakeholder about whether an action was authorized.",
          "Undetermined should never be a vague escape hatch. It must state exactly what evidence is missing and what would resolve the question.",
          "An Undetermined verdict still requires action: a revisit trigger and, where appropriate, interim precautionary monitoring."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Verdicts feed metrics, tuning, and trust in the SOC",
        "body": "Individually, a single verdict closes a single ticket. In aggregate, across hundreds or thousands of tickets over months, verdicts become the raw data behind some of the most important operational metrics a SOC tracks, which is the real payoff for the documentation discipline covered on the previous pages.\n\n### What aggregated verdicts reveal\n\nA detection rule with a consistently high False Positive rate relative to its True Positive rate is a strong, data-backed argument for prioritizing that rule's tuning in the coverage-and-detection-engineering backlog introduced in the coverage-thinking lesson earlier in this Learning Path, without verdict data, that prioritization argument would just be one analyst's impression rather than a defensible metric. Conversely, a rule that reliably produces True Positives with very few False Positives is evidence the detection is well-tuned and should be a template for how similar rules get written.\n\n### Verdict data and analyst trust\n\nA SOC where verdicts are applied inconsistently: one analyst's \"True Positive\" standard is looser than another's, or Undetermined gets used as an escape hatch as warned against on the previous page. Produces metrics that cannot actually be trusted or acted on, undermining the entire point of collecting verdict data in the first place. This is why well-run SOCs invest in calibration: periodic review sessions where analysts discuss recent verdict decisions together, comparing reasoning on ambiguous cases, specifically to keep the team's verdict standards consistent with each other over time.\n\n### The closing loop back to detection engineering\n\nA mature SOC treats verdict data as a continuous feedback loop back into detection engineering, closing the circle first opened in the coverage-thinking lesson: gaps identified during investigation feed engineering tickets; new or tuned rules go live; the resulting alerts get verdicted; the aggregated verdict data confirms (or challenges) whether the tuning actually improved the rule, turning individual case-closing discipline into organization-wide detection improvement over time.",
        "codeExample": "# Simple aggregated verdict metric (conceptual query)\nAlerts\n| where TimeGenerated > ago(90d)\n| summarize TotalAlerts = count(),\n            TruePositives = countif(Verdict == \"True Positive\"),\n            FalsePositives = countif(Verdict == \"False Positive\")\n  by RuleName\n| extend FalsePositiveRate = round(100.0 * FalsePositives / TotalAlerts, 1)\n| where FalsePositiveRate > 80\n| sort by FalsePositiveRate desc\n# Output: rules most urgently needing tuning, ranked by their own verdict history",
        "keyPoints": [
          "Aggregated verdict data reveals which detection rules need tuning (high False Positive rate) and which are working well.",
          "Inconsistent verdict standards across analysts produce untrustworthy metrics, undermining the value of collecting verdict data at all.",
          "Calibration sessions, where analysts compare reasoning on ambiguous cases, help keep verdict standards consistent across the team.",
          "Verdict data closes the feedback loop with detection engineering: gaps become tickets, tickets become rules, rules get verdicted, and the cycle informs the next round of tuning."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Writing a complete closing note",
        "body": "Every verdict discussed in this lesson has come with its own closing-note template, because the note itself (not just the verdict label selected from a dropdown) is what actually carries the investigation's findings forward to anyone who reads the ticket later. A consistently strong closing note, regardless of which of the four verdicts it accompanies, includes the same core elements.\n\n### The universal elements of a good closing note\n\n- **The verdict itself**, stated using the organization's standard classification labels (this lesson used Microsoft Sentinel's four as a concrete reference).\n- **A one-line summary** of what was actually found, written so a reader unfamiliar with the specific alert can understand the outcome without opening the full ticket history.\n- **The supporting evidence**, proportional to the verdict. Extensive for True Positive (IOCs, technique IDs, affected hosts/accounts), root-cause-focused for False Positive, scope-and-authorization-focused for Benign Positive, and explicitly bounded (\"here is exactly what remains unknown\") for Undetermined.\n- **The action taken as a result**. Containment for True Positive, a rule-fix request for False Positive, a narrow suppression for Benign Positive, a revisit trigger for Undetermined.\n- **The reviewer or approver**, where relevant (a change-approval reference for a Benign Positive, a detection-engineering ticket number for a False Positive fix request).\n\n### Bringing the whole module together\n\nThis lesson closes the Investigation module, which began with building timelines and pivoting on entities, and, more broadly, it closes out the entire investigative skill arc this Learning Path has been building since containment basics and MITRE ATT&CK mapping several lessons ago. The verdict is where all of that work becomes visible and useful beyond the single analyst who did it: a well-documented True Positive with technique IDs and a full pivot-derived scope is what makes a coverage-heatmap review meaningful months later; a well-documented False Positive with a specific root cause is what actually gets a noisy rule fixed instead of endlessly re-investigated. The technical skills in this module matter, but the closing note is what makes them count for anyone besides the analyst who wrote it.",
        "codeExample": "# Universal closing note checklist (any verdict)\n[ ] Verdict stated using standard classification labels\n[ ] One-line plain-language summary of the outcome\n[ ] Supporting evidence proportional to the verdict type\n[ ] Specific action taken (containment / rule-fix request / suppression / revisit trigger)\n[ ] Reviewer or approver referenced where relevant\n[ ] Technique ID(s) included if any malicious or suspicious activity was involved",
        "keyPoints": [
          "A strong closing note includes the verdict, a plain-language summary, proportional supporting evidence, the action taken, and any relevant reviewer/approver.",
          "The evidence expected differs by verdict: extensive for True Positive, root-cause-focused for False Positive, authorization-focused for Benign Positive, explicitly-bounded for Undetermined.",
          "The closing note, not just the verdict label, is what carries an investigation's findings forward to future readers.",
          "Verdict documentation is what makes the earlier skills taught across this Learning Path (mapping, coverage thinking, timelines, pivoting) useful beyond the single analyst who performed them."
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the defining characteristic of a True Positive verdict?",
        "options": [
          {
            "label": "The alert fired due to a bug in the detection rule's logic",
            "value": "a"
          },
          {
            "label": "The investigation confirmed the alerted activity genuinely happened and was malicious",
            "value": "b"
          },
          {
            "label": "There is not enough evidence to reach any conclusion",
            "value": "c"
          },
          {
            "label": "The activity happened but was authorized and expected",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A True Positive confirms both that the described activity actually occurred and that it was malicious. A rule-logic bug describes a False Positive, insufficient evidence describes Undetermined, and authorized/expected activity that genuinely occurred describes a Benign Positive."
      },
      {
        "question": "A detection rule intended to catch encoded PowerShell commands also happens to match a completely unrelated legitimate script due to a flaw in its logic, firing every time that script runs even though nothing malicious is present. What verdict and response does this call for?",
        "options": [
          {
            "label": "Benign Positive; add a narrow suppression for this one account",
            "value": "a"
          },
          {
            "label": "False Positive; fix the underlying rule logic rather than just closing the ticket repeatedly",
            "value": "b"
          },
          {
            "label": "True Positive; escalate for containment",
            "value": "c"
          },
          {
            "label": "Undetermined; wait for more evidence before deciding",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Because the rule's own logic is flawed and never actually matched its intended malicious pattern, this is a False Positive, and the correct response is fixing the rule itself, not repeatedly re-investigating and closing the same recurring alert. Benign Positive would apply if the rule correctly detected real activity that was simply authorized; this is not malicious activity requiring containment, and there is no meaningful uncertainty left to justify Undetermined."
      },
      {
        "question": "An IT administrator's genuine, approved privilege escalation correctly triggers a detection rule designed exactly to catch privilege escalation. Why is broadly disabling or exempting the entire admin group from this rule the wrong fix, compared to a narrow suppression?",
        "options": [
          {
            "label": "Broad suppression would create a lasting blind spot that a future attacker compromising any account in that group could exploit undetected",
            "value": "a"
          },
          {
            "label": "Because the rule's underlying logic is actually broken here and needs to be rewritten from scratch",
            "value": "b"
          },
          {
            "label": "Because platforms like Microsoft Sentinel do not support creating any kind of scoped suppression at all",
            "value": "c"
          },
          {
            "label": "Because individual admin accounts can never be scoped or targeted separately within a detection rule",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Since the rule is working correctly (this is a Benign Positive, not a False Positive), broadly exempting the whole admin group would silence the rule even for a genuinely malicious privilege escalation performed through any account in that group later: a narrow, specific suppression (one account, one approved time window) avoids this while still resolving the immediate noise. The rule's logic is not broken here, suppressions are a standard and supported mechanism, and admin accounts can absolutely be scoped precisely in detection rules."
      },
      {
        "question": "An analyst cannot confirm whether a specific after-hours file access was authorized because the responsible manager has not yet responded, and no other evidence resolves the question. What is the correct verdict and required follow-up?",
        "options": [
          {
            "label": "Mark it False Positive and close it, since no malicious intent is proven",
            "value": "a"
          },
          {
            "label": "Mark it Undetermined, documenting exactly what evidence is missing and setting a revisit trigger or interim monitoring",
            "value": "b"
          },
          {
            "label": "Mark it True Positive as a precaution, in case it turns out to be malicious later",
            "value": "c"
          },
          {
            "label": "Leave the alert completely unclosed with no verdict and no documentation",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "When evidence genuinely cannot support a confident True/False/Benign Positive call, Undetermined is correct, but it must be paired with a specific statement of what is missing and a revisit trigger or interim precaution, not left as a vague, actionless note. Marking it False Positive or True Positive without adequate evidence would misrepresent the investigation's actual findings, and leaving it undocumented entirely abandons the required discipline altogether."
      },
      {
        "question": "Why do well-run SOCs hold periodic calibration sessions where analysts discuss recent verdict decisions together?",
        "options": [
          {
            "label": "To assign blame for incorrect past verdicts",
            "value": "a"
          },
          {
            "label": "To keep verdict standards consistent across analysts, since inconsistent verdicts produce untrustworthy aggregated metrics",
            "value": "b"
          },
          {
            "label": "Calibration sessions are required by NIST SP 800-61 for compliance purposes",
            "value": "c"
          },
          {
            "label": "To replace the need for individual investigation skills covered elsewhere in this module",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "If one analyst's threshold for True Positive is looser or stricter than another's, or if Undetermined gets used inconsistently, the resulting aggregated metrics (like a rule's False Positive rate) become unreliable and cannot be confidently acted on. Calibration sessions exist specifically to keep verdict standards consistent across the team. This is about improving shared judgment, not assigning blame, is not a formal NIST requirement, and does not replace the underlying investigative skills: it depends on them."
      }
    ]
  }
};
