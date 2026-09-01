/**
 * Learning Rooms — Batch 36
 *
 * Closes an F-09 external-audit gap: the platform's macOS attack scenarios
 * (macos-stealer-dmg, macos-tcc-pkg) require knowledge that no room taught —
 * DMG/PKG install mechanics, Gatekeeper/notarization/quarantine, Developer ID
 * vs ad-hoc code signing, osascript/AppleScript abuse, the login Keychain and
 * the security command-line tool, TCC.db and privacy-permission manipulation, and the
 * LaunchAgent/LaunchDaemon persistence split. This room is the macOS
 * counterpart to the existing Windows Fundamentals / Linux Fundamentals rooms.
 *
 * Rooms in this batch:
 *  1. macos-security-fundamentals
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — macOS Security Fundamentals
// ===========================================================================

const tccWriteEvent: TelemetryEvent = {
  id: "evt-macf-la1-001",
  ts: "2026-03-11T13:24:09.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "file_modify",
  severity: "critical",
  mitre_technique: "T1548.006",
  mitre_tactic: "Privilege Escalation",
  hostname: "MAC-4471",
  user_email: "l.tavor@nexacorp.com",
  user_title: "Sales Operations Manager",
  process: {
    name: "sqlite3",
    pid: 6120,
    path: "/usr/bin/sqlite3",
    parent_name: "sh",
    parent_pid: 6104,
    cmdline:
      "sqlite3 /Users/l.tavor/Library/Application Support/com.apple.TCC/TCC.db INSERT OR REPLACE INTO access VALUES('kTCCServiceScreenCapture','com.safeclean.util',0,2,4,1,NULL,NULL,NULL,'UNUSED',NULL,0,1);",
    user: "root",
  },
  file: {
    name: "TCC.db",
    path: "/Users/l.tavor/Library/Application Support/com.apple.TCC/TCC.db",
  },
  description:
    "A shell process spawned by the SafeClean Utility installer's postinstall script ran /usr/bin/sqlite3 against the user's own TCC privacy database and inserted a new access row, all while running as root.",
  raw: {
    "crowdstrike.ComputerName": "MAC-4471",
    "crowdstrike.UserName": "root",
    "crowdstrike.FileName": "TCC.db",
    "crowdstrike.FilePath": "/Users/l.tavor/Library/Application Support/com.apple.TCC/",
    "crowdstrike.CommandLine":
      "sqlite3 /Users/l.tavor/Library/Application Support/com.apple.TCC/TCC.db INSERT OR REPLACE INTO access VALUES('kTCCServiceScreenCapture','com.safeclean.util',0,2,4,1,NULL,NULL,NULL,'UNUSED',NULL,0,1);",
    "crowdstrike.ParentProcessName": "sh",
    "crowdstrike.OperationType": "FileWritten",
    "process.name": "sqlite3",
    "process.executable": "/usr/bin/sqlite3",
    "process.parent.name": "sh",
    "process.parent.pid": "6104",
    "process.code_signature.status": "valid",
    "process.code_signature.subject_name": "Software Signing",
    "file.name": "TCC.db",
    "file.path": "/Users/l.tavor/Library/Application Support/com.apple.TCC/TCC.db",
    "host.name": "MAC-4471",
    "host.os.name": "macOS",
    "host.os.version": "14.5",
    "user.name": "root",
    "threat.technique.id": "T1548.006",
    "threat.technique.name": "Abuse Elevation Control Mechanism: TCC Manipulation",
    "threat.tactic.name": "Privilege Escalation",
    "threat.tactic.id": "TA0004",
    "event.outcome": "success",
  },
};

const osascriptChainEvent: TelemetryEvent = {
  id: "evt-macf-la2-001",
  ts: "2026-04-02T09:18:47.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "critical",
  mitre_technique: "T1059.002",
  mitre_tactic: "Execution",
  hostname: "MAC-2298",
  user_email: "d.peretz@nexacorp.com",
  user_title: "Marketing Coordinator",
  process: {
    name: "osascript",
    pid: 7742,
    path: "/usr/bin/osascript",
    parent_name: "BatteryBoost Pro",
    parent_pid: 7710,
    cmdline:
      "osascript -e display dialog \"BatteryBoost Pro needs your password to finish setup.\" default answer \"\" with hidden answer with icon caution buttons {\"OK\"} default button \"OK\"",
    user: "d.peretz",
  },
  description:
    "Four seconds after BatteryBoost Pro launched from a mounted disk image at /Volumes/BatteryBoost Pro, it spawned /usr/bin/osascript running the AppleScript shown in the command line.",
  raw: {
    "crowdstrike.ComputerName": "MAC-2298",
    "crowdstrike.UserName": "d.peretz",
    "crowdstrike.FileName": "osascript",
    "crowdstrike.FilePath": "/usr/bin/",
    "crowdstrike.CommandLine":
      "osascript -e display dialog \"BatteryBoost Pro needs your password to finish setup.\" default answer \"\" with hidden answer with icon caution buttons {\"OK\"} default button \"OK\"",
    "crowdstrike.ParentProcessName": "BatteryBoost Pro",
    "crowdstrike.OperationType": "ProcessRollup2",
    "process.name": "osascript",
    "process.executable": "/usr/bin/osascript",
    "process.parent.name": "BatteryBoost Pro",
    "process.parent.pid": "7710",
    "process.parent.executable": "/Volumes/BatteryBoost Pro/BatteryBoost Pro.app/Contents/MacOS/BatteryBoost Pro",
    "process.parent.code_signature.status": "adhoc",
    "process.parent.code_signature.subject_name": "-",
    "process.code_signature.status": "valid",
    "process.code_signature.subject_name": "Software Signing",
    "host.name": "MAC-2298",
    "host.os.name": "macOS",
    "host.os.version": "14.5",
    "user.name": "d.peretz",
    "threat.technique.id": "T1059.002",
    "threat.technique.name": "Command and Scripting Interpreter: AppleScript",
    "threat.tactic.name": "Execution",
    "threat.tactic.id": "TA0002",
    "event.outcome": "success",
  },
};

const benignNotarizedInstallEvent: TelemetryEvent = {
  id: "evt-macf-ac1-001",
  ts: "2026-02-19T10:02:00.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "informational",
  hostname: "MAC-6610",
  user_email: "r.golan@nexacorp.com",
  user_title: "Product Designer",
  process: {
    name: "Notion",
    pid: 3390,
    path: "/Applications/Notion.app/Contents/MacOS/Notion",
    parent_name: "launchd",
    parent_pid: 1,
    cmdline: "/Applications/Notion.app/Contents/MacOS/Notion",
    user: "r.golan",
  },
  description:
    "Notion.app launched from /Applications after a .pkg install completed. Falcon recorded a valid Developer ID Installer signature, a passed Gatekeeper assessment, and a per-user LaunchAgent registered for the updater.",
  raw: {
    "crowdstrike.ComputerName": "MAC-6610",
    "crowdstrike.UserName": "r.golan",
    "crowdstrike.FileName": "Notion",
    "crowdstrike.FilePath": "/Applications/Notion.app/Contents/MacOS/",
    "crowdstrike.ParentProcessName": "launchd",
    "crowdstrike.OperationType": "ProcessRollup2",
    "process.name": "Notion",
    "process.executable": "/Applications/Notion.app/Contents/MacOS/Notion",
    "process.code_signature.status": "valid",
    "process.code_signature.subject_name": "Developer ID Application: Notion Labs, Inc. (LBQG3xxxxx)",
    "file.signature.trusted": "true",
    "host.name": "MAC-6610",
    "host.os.name": "macOS",
    "host.os.version": "14.5",
    "user.name": "r.golan",
    "event.outcome": "success",
  },
};

const macosSecurityFundamentalsRoom = {
  id: "macos-security-fundamentals",
  title: "macOS Security Fundamentals",
  description:
    "The macOS counterpart to Windows Fundamentals and Linux Fundamentals: how software actually arrives and runs on a Mac (DMG and PKG), how Gatekeeper, notarization and the quarantine attribute decide whether to let it, what Developer ID versus ad-hoc code signing tells an analyst, how osascript and the login Keychain get abused, what the TCC privacy database controls and how a root process can bypass it, and how LaunchAgents and LaunchDaemons persist software across logins and reboots.",
  difficulty: "beginner" as const,
  category: "Threat Detection",
  estimatedMinutes: 60,
  xp: 400,
  icon: "🍎",
  prerequisites: ["intro-cybersecurity", "malware-types"],
  tasks: [
    // ── Reading 1: mental model ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r1",
      heading: "A macOS Mental Model for an Analyst Trained on Windows or Linux",
      content:
        "Every analyst arrives at a first macOS investigation carrying a mental model built for a different operating system, and that mismatch causes real mistakes if it goes unexamined. This room replaces the borrowed model with the real one.\n\n" +
        "**What macOS actually is.** Underneath its interface, macOS is a Unix-based operating system built on a core called XNU (a hybrid of a Mach microkernel and BSD components). That single fact explains a lot of what follows: macOS has Unix-style users, a Unix-style filesystem hierarchy, and Unix-style permissions (owner, group, other; read, write, execute) — the same conceptual family as Linux, not Windows. An analyst who already knows Linux fundamentals is closer to home here than one who only knows Windows.\n\n" +
        "**Where the two models genuinely diverge from Windows.** Windows keeps machine-wide configuration in a single hierarchical database, the Registry, and manages background processes through the Service Control Manager. macOS has neither. There is no registry to query and no services console. Configuration instead lives in property list (plist) files — XML or binary files holding settings for an app or the system — and every background process, user-level or system-level, is started and supervised by exactly one process: launchd, always process ID 1, the very first process the kernel starts at boot. Autostart and persistence on macOS run entirely through launchd and the plist files it reads, a theme this room returns to in depth later.\n\n" +
        "**Where software lives.** A macOS application is not spread across a Program Files folder and assorted registry keys the way a Windows install often is. It is a single .app bundle — really a folder that Finder styles to look like one file — containing the executable, resources, and an Info.plist describing it, conventionally placed in /Applications. That structure matters for an investigation: the actual binary an EDR agent reports on typically sits several folders deep inside the bundle, commonly under a Contents/MacOS/ subfolder, not at the visible .app path itself.\n\n" +
        "**Where a typical user's data lives.** Each user has a home directory under /Users/username, and inside it a Library folder — hidden from Finder by default but very much present — holding Application Support data, cached files, Keychains, and, as this room covers in depth, the privacy-permission database. Almost every artifact a macOS investigation cares about lives somewhere under this per-user Library folder or its system-wide counterpart at /Library.\n\n" +
        "**Why this matters before any technique-hunting begins.** Every reading that follows describes one specific mechanism — how software is verified before it runs, how it is granted trust, how it persists. All of those mechanisms rest on the four ideas introduced here: a Unix-permission foundation, launchd as the sole process supervisor, the .app bundle as the unit of installed software, and the per-user Library folder as home to almost every artifact worth investigating.",
      checkpoint: {
        question: "On macOS, which single process starts and supervises every background process, user-level and system-level alike?",
        options: [
          "The Service Control Manager, exactly as on Windows",
          "launchd, always process ID 1, the first process the kernel starts at boot",
          "systemd, inherited directly from Linux",
          "Finder, since it is the process the user interacts with first",
        ],
        answer: 1,
        explanation:
          "macOS has no Service Control Manager and no systemd. launchd is the one process supervisor for the whole system, always PID 1, reading plist files to know what to start and when.",
      },
    },
    // ── Reading 2: DMG vs PKG ────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r2",
      heading: "DMG and PKG: The Two Doors Software Walks Through",
      content:
        "Software reaches a Mac through one of two container formats almost every time, and the two behave very differently — a distinction worth knowing before anything else in this room.\n\n" +
        "**The disk image (.dmg).** A DMG is a mountable disk-image file. Double-clicking one doesn't install anything by itself — it tells macOS's built-in disk-image handler to mount the image as a new, temporary volume, which shows up under /Volumes with its own drive-letter-like mount point (for example /Volumes/AppName). Inside, the user typically finds a .app bundle and drags it into /Applications, or simply double-clicks it to run it directly from the mounted volume without ever installing it at all. Nothing here requires elevated privilege, and nothing here runs arbitrary scripts on the user's behalf: mounting a DMG only exposes files for the user to look at and, optionally, copy or launch.\n\n" +
        "**The installer package (.pkg).** A PKG is fundamentally different: it is not just a container, it is a set of instructions. Double-clicking a .pkg hands it to /usr/sbin/installer (or the graphical Installer.app that wraps it), which can place files anywhere on the system the package specifies — and, critically, can run preinstall and postinstall shell scripts as part of the install. Those scripts execute with root privilege, because package installation is itself a root-level operation on macOS. A .pkg that only copies an app into /Applications and finishes is unremarkable. A .pkg whose postinstall script does something else entirely — writes into a privacy database, drops a system-level persistence item, resets a service account's credentials — inherits root the same way, and the install log alone will not tell an analyst which kind of postinstall script it just ran; only reading what that script actually did will.\n\n" +
        "**Why this split matters for triage.** A DMG-delivered attack has to get the user to run something themselves after mounting, and whatever runs, runs with the user's own privilege level unless it separately escalates. A PKG-delivered attack can reach root the moment the user clicks through the installer's own prompts — no separate privilege-escalation exploit required, because the operating system hands root to the install process by design. That single difference is why a malicious .pkg is generally more dangerous per click than a malicious app mounted from a DMG: the attacker doesn't have to find a vulnerability to get root, the installer framework gives it to them.\n\n" +
        "**What a SOC analyst checks first, either way.** Regardless of which container delivered it, the two facts that matter before anything else are: what account is the resulting process running as (the user, or root), and what does the code-signing state say about who built it and whether Apple has vouched for it in any way. The next two readings cover exactly those two facts.",
    },
    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "macf-q1",
      question:
        "An analyst is comparing two macOS installs: one delivered as a .dmg where the user drags an app into /Applications, and one delivered as a .pkg with a postinstall script. Why does the .pkg install carry materially higher inherent risk per click, independent of anything the script actually does?",
      options: [
        "Because .pkg files are always larger, and larger files are statistically more likely to be malicious",
        "Because installing a package is itself a root-level operation on macOS, so a .pkg's preinstall/postinstall scripts inherit root privilege by design -- no separate privilege-escalation exploit is required",
        "Because .dmg files cannot contain executable code of any kind, while .pkg files always can",
        "Because Gatekeeper only ever inspects .pkg files and skips .dmg files entirely",
      ],
      answer: 1,
      explanation:
        "Reading 2 covered this directly: package installation is a root-level operation, so a .pkg's install scripts inherit root the moment the user clicks through the installer -- no exploit needed. File size (a) has no bearing on risk. DMGs can absolutely contain executable .app bundles (c), which is exactly what most legitimate DMG installs are. And Gatekeeper evaluates both container types at first launch (d), not just packages.",
      xp: 20,
    },
    // ── Reading 3: Gatekeeper / quarantine / notarization ────────────────────
    {
      type: "reading" as const,
      id: "macf-r3",
      heading: "Gatekeeper, the Quarantine Attribute, and Notarization",
      content:
        "macOS tries to stop a user from unknowingly running malicious downloaded software with three linked mechanisms, and untangling them is essential to reading any macOS EDR event correctly.\n\n" +
        "**The quarantine attribute.** The moment a browser, mail client, or any other app that participates in the convention downloads a file, macOS tags it with an extended file attribute named com.apple.quarantine. This is a marker, not a verdict — it simply records that the file arrived from outside the machine (conceptually similar in purpose, though not in mechanism, to Windows' Mark-of-the-Web). Its presence is what triggers the next mechanism, Gatekeeper, on first launch. Almost anything downloaded — a legitimate app update, a family photo, a malicious binary — carries this attribute; seeing it on a file proves nothing about intent by itself.\n\n" +
        "**Gatekeeper.** When a quarantined app is launched for the first time, Gatekeeper runs an assessment before allowing it to proceed: does the app carry a valid code signature, and if so, whose, and has Apple notarized it. Depending on the outcome, Gatekeeper either lets the app open silently, shows a warning the user can choose to override, or refuses outright. A key detail: Gatekeeper's check happens once, at first launch from that specific location — an app already approved and then re-run doesn't re-trigger the full check the same way.\n\n" +
        "**Notarization.** Notarization is a step beyond simply signing code. A developer submits their signed app to Apple's automated scanning service; Apple checks it for known malware indicators and, if it's clean, issues a ticket that can be stapled to the app or checked online. An app can be validly signed by a real Developer ID and still not be notarized — notarization is a separate, additional step, not an automatic consequence of signing. Gatekeeper treats a Developer-ID-signed-and-notarized app as the strongest, most trusted case; it can silently clear such an app because Apple itself has already screened it.\n\n" +
        "**How these three combine in practice.** A brand-new download carries the quarantine attribute. On first launch, Gatekeeper checks whether it is Developer-ID-signed and notarized: if so, it opens with no friction. If it is signed but not notarized, or ad-hoc signed (the next reading explains what that means), the user typically has to explicitly override a warning to run it — friction the attacker is counting on the victim to click through anyway, particularly when a page has already told them exactly which button to press. What the EDR telemetry an analyst actually sees records is the outcome of this chain: whether the quarantine attribute was present, what the code-signature status came back as, and whether the process launched anyway.",
      diagram:
        "flowchart LR\n" +
        "  A[File downloaded] --> B[com.apple.quarantine attribute set]\n" +
        "  B --> C{First launch: Gatekeeper assessment}\n" +
        "  C -->|Developer ID + notarized| D[Opens with no friction]\n" +
        "  C -->|Signed, not notarized / ad-hoc| E[User must override a warning]\n" +
        "  C -->|Unsigned / known-bad| F[Gatekeeper blocks outright]\n",
      diagramCaption: "Quarantine sets the flag; Gatekeeper reads the signature to decide what happens next",
      checkpoint: {
        question: "A downloaded app is validly signed with a real Developer ID certificate but was never submitted for notarization. What does Gatekeeper do with it?",
        options: [
          "It is treated identically to a Developer-ID-signed AND notarized app, since any valid Developer ID signature is enough on its own",
          "It typically requires the user to explicitly override a warning before it will run, since notarization -- Apple's own malware scan -- is a separate step a valid signature alone does not satisfy",
          "Gatekeeper always blocks it outright with no way for the user to proceed",
          "The com.apple.quarantine attribute is automatically removed the moment a valid Developer ID signature is detected",
        ],
        answer: 1,
        explanation:
          "Notarization is an additional step beyond signing -- Apple's own scan of the submitted app. A validly signed but non-notarized app sits in the middle tier: not silently trusted like a notarized app, not outright blocked like an unsigned one, but requiring the user to override a friction warning.",
      },
    },
    // ── Reading 4: code signing states ───────────────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r4",
      heading: "Code Signing: Developer ID, Ad-Hoc, and Revoked",
      content:
        "The single most useful field in a macOS EDR event is almost always the code-signature status, and it comes in a handful of distinct states an analyst needs to be able to tell apart on sight.\n\n" +
        "**Developer ID signed.** Apple issues Developer ID certificates to registered developers (individuals or companies) who pay for and maintain an Apple Developer Program membership. A binary signed this way carries a subject name identifying the real developer or company — for example, a certificate string naming a specific company and a unique developer identifier. This is the strongest legitimate-software signal available outside the Mac App Store itself, and it's what most reputable commercial and open-source Mac software carries.\n\n" +
        "**Ad-hoc signed.** macOS requires every executable to carry some form of code signature to run at all on modern versions, even one with no real identity behind it. An ad-hoc signature satisfies that technical requirement without asserting who built the software — in EDR telemetry this typically shows up as a code-signature status of ad-hoc with a subject name of a single dash, meaning no identity claim exists at all. Malware distributed outside official channels overwhelmingly falls into this bucket: it is technically signed (macOS requires it), but the signature carries zero attribution and zero of Apple's trust.\n\n" +
        "**Revoked.** Sometimes a real Developer ID certificate does exist behind a signature, but Apple has since revoked it — typically because Apple found it being used to distribute malware and pulled its trust retroactively. A revoked signature is a strong signal in its own right: it means the software once had a real identity attached that Apple has since disowned. It is a materially different, and often more suspicious, state than ad-hoc, because it implies a developer account was compromised or was knowingly used for abuse.\n\n" +
        "**Unsigned.** Rare on modern macOS because the operating system actively resists running completely unsigned code, but it appears occasionally, particularly for scripts or files that were never bundled as a proper signed application at all.\n\n" +
        "**Reading these states together with the parent process.** A signature status is never the whole story on its own. Apple's own system binaries — /usr/bin/osascript, /bin/sh, /usr/bin/security — are validly signed by Apple itself (subject name Software Signing) and will show status valid on every single invocation, malicious or benign. A valid signature on a system binary says nothing about whether what it was told to do is legitimate; it only says Apple built that particular binary. This is exactly why the parent process and the command line matter as much as the signature field itself — a point the next reading builds on directly.",
    },
    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "macf-q2",
      question:
        "An EDR event shows /usr/bin/osascript running with process.code_signature.status = valid and subject_name = Software Signing. A junior analyst concludes this process must be benign because its signature is valid. What is wrong with that reasoning?",
      options: [
        "Nothing is wrong -- a valid Apple signature on a system binary always means the activity is benign",
        "Apple's own system binaries like osascript are validly signed on every invocation, malicious or benign -- the signature says Apple built the binary, not that whatever it was instructed to do is legitimate; the parent process and command line matter just as much",
        "osascript can never be validly signed, so this event must be spoofed or corrupted",
        "A valid signature on a system binary means it is running with root privilege, which is itself the concerning fact",
      ],
      answer: 1,
      explanation:
        "Reading 4 was explicit: osascript is a real Apple-signed binary and will show 'valid' every time it runs, regardless of what it was told to do. The signature attests to who built the binary, not to the intent behind a specific invocation -- which is why the parent process (what launched it) and the command line (what it was told to do) carry the real signal here, not the signature field alone. Options (c) and (d) both invent facts the event doesn't support.",
      xp: 20,
    },
    // ── Log Analysis 1: TCC.db root write ────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "macf-la1",
      heading: "A Root Shell Writes Into the User's Own Privacy Database",
      context:
        "Lior Tavor, a sales operations manager at NexaCorp, installed a utility called SafeClean Utility from a .pkg downloaded from a search-ad result promising to speed up her Mac. The installer ran normally and finished with no visible error. Minutes later, Falcon recorded the event below on her MacBook, MAC-4471.",
      event: tccWriteEvent,
      questions: [
        {
          question:
            "The process running sqlite3 in this event is 'root', and its parent is 'sh'. Given what Reading 2 taught about .pkg installers, where did this root shell most plausibly come from?",
          options: [
            "SafeClean Utility's .pkg installer ran a preinstall or postinstall script, which macOS executes with root privilege as part of the install process itself",
            "Lior must have manually opened Terminal and typed sudo before running this command herself",
            "Falcon's own agent process launched this shell to perform a routine self-check of the privacy database",
            "root shells on macOS only ever come from a remote SSH login, so this indicates an external attacker with network access",
          ],
          answer: 0,
          explanation:
            "Reading 2 covered exactly this mechanism: installing a .pkg is itself a root-level operation, and its preinstall/postinstall scripts inherit that root privilege automatically -- no separate exploit or manual sudo needed. Nothing in the event suggests Lior opened Terminal herself (b), Falcon's agent does not spawn arbitrary shells against the privacy database (c), and SSH is not the only source of a root shell on macOS -- a local install script is a far more common and far better-evidenced one here (d).",
          xp: 25,
        },
        {
          question:
            "The command inserts a row for kTCCServiceScreenCapture keyed to the com.safeclean.util bundle. Based on what TCC controls, what did this operation actually accomplish?",
          options: [
            "It granted the SafeClean Utility app Screen Recording permission by writing the approval directly into the privacy database, without the user ever seeing or clicking a consent prompt",
            "It permanently disabled Screen Recording for every application on the Mac, including legitimate ones",
            "It only logged that Screen Recording had been requested; a separate step is still required before the permission actually takes effect",
            "It reset all of the user's existing TCC permissions back to their default, unconfigured state",
          ],
          answer: 0,
          explanation:
            "TCC.db is where macOS stores exactly this kind of approval -- a row granting a specific bundle identifier a specific protected permission. Normally that row only appears after the user clicks Allow on a system consent prompt. Because this write came from a root process, the row was inserted directly, and the app is now treated as approved for Screen Recording with no prompt ever shown. It disabled nothing globally (b), the row's presence is not a mere log entry pending a further step (c), and nothing here touches any other bundle's existing permissions (d).",
          xp: 25,
        },
        {
          question:
            "Given everything in this event, what is the most important next investigative step?",
          options: [
            "Check whether the com.safeclean.util bundle has been granted any OTHER protected TCC permissions the same way, and whether it has begun using Screen Recording to capture anything",
            "Reset the user's macOS login password immediately, since a TCC.db write implies the password itself has been compromised",
            "Assume the alert is a false positive, since sqlite3 is a legitimate, Apple-signed system tool",
            "Take no further action, since Falcon only logged the file write and did not report the process as blocked",
          ],
          answer: 0,
          explanation:
            "A self-granted permission is a means to an end, not the end itself -- the natural next question is what the app does with that access, and whether it quietly granted itself others (Full Disk Access, Accessibility, Camera/Microphone) the same way. There is no evidence here of a compromised password (b) -- TCC.db and login credentials are unrelated stores. sqlite3 being a legitimate, signed tool (c) is exactly the living-off-the-land pattern Reading 4 warned against reasoning from the tool's own signature. And 'not blocked' (d) describes Falcon's disposition on this one event, not whether the underlying activity needs a response.",
          xp: 30,
        },
      ],
    },
    // ── Reading 5: osascript ─────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r5",
      heading: "osascript and AppleScript: macOS's Living-Off-the-Land Tool",
      content:
        "Every operating system ships legitimate automation tooling that malware can turn against the user, and on macOS the single most abused example is osascript.\n\n" +
        "**What it actually is.** osascript is a real, Apple-signed command-line tool (found at /usr/bin/osascript) that runs AppleScript — Apple's own scripting language for automating tasks and interacting with the operating system and other applications. Legitimate uses are everywhere: an installer showing a progress dialog, a script automating a repetitive Finder task, an IT management tool displaying a message to end users. None of that is inherently suspicious, and that ubiquity is exactly what makes it useful to abuse.\n\n" +
        "**The specific abuse pattern this room focuses on.** AppleScript's display dialog command can render an on-screen prompt, and a with hidden answer option turns the input field into a password-style masked box. A malicious app can spawn osascript with a display dialog command worded to look like a legitimate system or app request — 'needs your password to continue,' 'finish installation,' 'verify your identity' — and capture whatever the user types in cleartext. There is no macOS system password prompt that any third-party app is entitled to trigger on the operating system's behalf; a genuine system password prompt comes from a macOS system process, never from a downloaded app's own child process.\n\n" +
        "**Why the captured password matters so much.** A password typed into a fake dialog like this is very often the user's own macOS login password — the same password that unlocks the login Keychain, covered in the next reading. Capturing it is frequently the necessary first step before a stealer can read anything else of value on the machine, because several of the richest credential stores on macOS are themselves protected behind that same login password.\n\n" +
        "**A second common pattern: do shell script.** AppleScript can also hand off to a shell command directly via do shell script, meaning osascript is sometimes seen as a relay rather than an endpoint — spawning a curl command to send data out, or chaining into another interpreter entirely. Reading the full command line, not just the process name, is what tells these two osascript patterns apart: a display dialog invocation is almost always the phishing step; a do shell script invocation is almost always doing something else with whatever was already captured.\n\n" +
        "**What this means for detection.** Because the binary itself is always validly Apple-signed, no detection rule can rely on osascript's own signature. What actually distinguishes malicious use is the combination this room keeps returning to: an unusual, ad-hoc or unnotarized parent process spawning osascript, with a command line that renders a credential-style prompt or hands off to a shell command — living-off-the-land, macOS-style.",
    },
    // ── Reading 6: Keychain / security ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r6",
      heading: "The Login Keychain and the security Command-Line Tool",
      content:
        "Once a password has been captured — by an osascript prompt, or by any other means — the next stop for a macOS credential-theft chain is almost always the Keychain.\n\n" +
        "**What the Keychain is.** The Keychain is macOS's built-in encrypted credential store: a place where the operating system and applications can save passwords, certificates, secure notes and cryptographic keys, all encrypted at rest. Every user has a login Keychain, stored as a file named login.keychain-db under their own Library/Keychains folder, and — this is the important part — it is unlocked using the same password as the user's macOS login account by default, which is exactly why a phished login password is so valuable to an attacker on this platform specifically.\n\n" +
        "**What actually lives in it.** Applications routinely store their own saved credentials in the Keychain rather than managing their own encryption — this includes, notably, browsers: Chrome on macOS stores an encryption key inside the Keychain (commonly referenced as its Safe Storage key) that it uses to protect the separate saved-password database it keeps in its own profile folder. That single detail matters: reading the Keychain entry sometimes isn't the whole theft on its own, it is the key that unlocks a second store elsewhere.\n\n" +
        "**The security command-line tool.** macOS ships a command-line utility, /usr/bin/security, specifically for interacting with the Keychain from a script or the command line — the same binary a legitimate developer might use to automate a certificate-related task in a build pipeline. A stealer with the unlocked login password can invoke it directly, commonly with an operation like find-generic-password targeting a specific saved-item label (for example, one belonging to a particular browser), to pull exactly the secret it wants without any graphical prompt at all.\n\n" +
        "**Why the command line, not just the process name, is the tell.** Exactly as with osascript, /usr/bin/security is a real, validly Apple-signed binary, used constantly by entirely legitimate software and IT tooling. A detection built only around 'the security binary ran' will drown in noise. What actually matters is the combination: an unusual parent process (particularly one recently launched from a mounted disk image or an ad-hoc-signed app) invoking security against the login Keychain file, especially in the seconds immediately following an osascript password-prompt event on the same host. Sequence, not any single process, is what turns this from routine automation into a credential-theft chain.",
      checkpoint: {
        question: "Why is a phished macOS login password specifically valuable to an attacker, beyond simply letting them log in as the user?",
        options: [
          "It has no special value beyond login access -- the Keychain uses a completely separate, unrelated password",
          "By default, the login password is also what unlocks the user's login Keychain, so capturing it opens the door to every credential stored inside that Keychain as well",
          "It automatically grants root privilege on the machine the moment it is captured",
          "It disables Gatekeeper and code-signing checks system-wide once known",
        ],
        answer: 1,
        explanation:
          "The login Keychain is unlocked with the same password as the macOS login account by default. That's the whole reason a fake osascript password prompt is worth running before reaching for the Keychain -- one captured password unlocks a second, richer store.",
      },
    },
    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "macf-q3",
      question:
        "An ad-hoc-signed app, freshly launched from a mounted disk image, spawns /usr/bin/osascript running a command line containing display dialog and with hidden answer, referencing the app's own name and the word password. What is the most accurate read of this single event?",
      options: [
        "This is almost certainly a phishing prompt built to capture the user's password in cleartext, styled to look like a legitimate request from the app or the system",
        "This is a harmless UI convenience feature, since display dialog is a standard and extremely common AppleScript command used constantly by legitimate installers",
        "This proves the app has already read the user's Keychain, since osascript is the tool used to access it",
        "This event cannot be evaluated at all without first checking whether osascript's own code signature is valid",
      ],
      answer: 0,
      explanation:
        "Reading 5 named this exact pattern: a hidden-answer display dialog worded around 'password' is the classic macOS credential-phishing move, and no legitimate system password prompt is triggered by a third-party app's own child process. Option (b) is the trap the reading specifically warned against -- display dialog is common, but the wording and hidden-answer combination here is not routine UI, it's a credential lure. Option (c) confuses the phishing step with the separate Keychain-read step that typically follows it, not the same event. And (d) is a distraction: osascript's own signature will read as valid every single time, which is precisely why it tells you nothing on its own -- the command line is what carries the signal.",
      xp: 25,
    },
    // ── Reading 7: TCC ────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r7",
      heading: "TCC: Transparency, Consent and Control",
      content:
        "macOS gates access to a specific set of sensitive resources behind a subsystem called TCC — Transparency, Consent and Control — and understanding how it normally works is what makes the earlier log-analysis event fully make sense.\n\n" +
        "**What TCC protects.** A defined list of resources requires explicit, per-app approval before any application, however innocuous it looks, can touch them: Full Disk Access (reading broadly across the filesystem, including other apps' protected data and the user's Documents/Desktop/Downloads by default), Screen Recording, the camera and microphone, Accessibility (controlling other apps via the accessibility APIs), Automation (one app scripting another), and several more. None of these are things a normal app gets automatically just by being installed and signed — each one requires its own separate approval.\n\n" +
        "**How that approval is normally granted.** The first time an app tries to use one of these, macOS shows the user a system consent dialog naming the specific app and the specific permission it's requesting. If the user clicks Allow, macOS records that decision as a row in a database; if they click Deny, or ignore it, no row granting access is written. This is Apple's mechanism for making an invisible category of access (what an app can silently see or control) visible and consent-driven — hence the name.\n\n" +
        "**Where the approvals are stored.** Those decisions live in a SQLite database called TCC.db. There is a per-user copy under that user's own Library/Application Support/com.apple.TCC folder, covering permissions scoped to that user's data, and a separate system-wide copy for machine-level grants. Each row in the database ties a specific service identifier (for example, one for Screen Recording, one for Full Disk Access) to a specific application's bundle identifier, along with the allow/deny decision.\n\n" +
        "**Why a root process bypassing the prompt is such a significant event.** The consent dialog and the database write are meant to always travel together — a user sees the prompt, and only then does a row appear. A process running as root has direct filesystem write access to that same database file, though, and can insert an allow-row itself, exactly the way the earlier log-analysis event did. When that happens, the app ends up looking, from every other part of the system's perspective, exactly as if the user had clicked Allow — even though no prompt was ever shown and no consent was ever actually given. This is precisely why a TCC.db write coming from an unexpected root process, rather than from the normal consent-dialog flow, is one of the highest-confidence privilege-escalation signals available on macOS.\n\n" +
        "**tccutil, for completeness.** Administrators and users can also manage these grants deliberately through a command-line tool called tccutil, most commonly to reset a specific app's permissions back to an unconfigured state. Seeing tccutil used to reset permissions is ordinary administration; seeing sqlite3 or another generic tool write directly into TCC.db from a root shell is not.",
    },
    // ── Reading 8: LaunchAgents vs LaunchDaemons ──────────────────────────────
    {
      type: "reading" as const,
      id: "macf-r8",
      heading: "LaunchAgents vs LaunchDaemons: How macOS Persists Software",
      content:
        "Reading 1 introduced launchd as the single process supervisor for all of macOS. This reading covers the two ways anything registers with it to persist — the direct macOS analogue to a Windows Run key or scheduled task.\n\n" +
        "**The shared mechanism.** Both LaunchAgents and LaunchDaemons are simply plist files describing a program to run and when to run it — at login, at boot, on a schedule, or when watching a particular path for changes. A tool called launchctl is used to register (load) or unregister (unload) one of these plists with launchd. The plist itself typically lives in a predictable, well-known directory; which directory it lives in is what determines everything else about how and when it runs.\n\n" +
        "**LaunchAgents.** A LaunchAgent runs on behalf of a specific logged-in user, with that user's own privilege level — nothing more. A per-user LaunchAgent lives under that user's own ~/Library/LaunchAgents folder and needs no elevated privilege at all to create: any process running as that user can write a plist there. It only starts when that specific user logs in, and it stops when they log out. This is the normal, unremarkable way many legitimate apps register their own background updater or menu-bar helper.\n\n" +
        "**LaunchDaemons.** A LaunchDaemon runs as root and is not tied to any particular user logging in at all. A system LaunchDaemon lives under /Library/LaunchDaemons (there's also a smaller Apple-reserved set under /System/Library/LaunchDaemons), and launchd starts every daemon registered there automatically at boot — before any user has logged in. Critically, writing a new plist into /Library/LaunchDaemons requires root privilege, since that directory is not writable by an ordinary user account. That single fact is what makes finding a new file there so significant: something already had to be running as root to place it — this is a persistence mechanism reached as a consequence of privilege escalation, not a cause of it.\n\n" +
        "**Why the distinction matters operationally.** A LaunchAgent-based foothold disappears the moment that one user is removed or their account is cleaned, and it never runs unless that user is logged in — a narrower blast radius. A LaunchDaemon-based foothold survives a reboot, runs before anyone logs in at all, runs as root regardless of which user (if any) is using the machine, and persists independently of any specific user account. When an investigation finds a LaunchDaemon it cannot account for, the two facts to state plainly in the write-up are: it starts automatically at every future boot until removed, and whatever it does, it does as root.\n\n" +
        "**Confirming what a launch item actually runs.** The plist's Program (or ProgramArguments) key names the executable it starts. That target executable's own code-signature state deserves exactly the same scrutiny as anything else in this room — an ad-hoc-signed or unsigned binary sitting as the Program target of a newly created LaunchDaemon is a strong, specific finding worth stating precisely in an incident write-up.",
      diagram:
        "flowchart TB\n" +
        "  L[launchd -- PID 1, the one process supervisor] --> A[LaunchAgent\\n~/Library/LaunchAgents\\nruns as the logged-in user\\nno root needed to create]\n" +
        "  L --> D[LaunchDaemon\\n/Library/LaunchDaemons\\nruns as root, starts at boot\\nrequires root to create]\n" +
        "  A --> AS[Stops at logout\\nNarrower blast radius]\n" +
        "  D --> DS[Survives reboot, runs before any login\\nRoot-level, system-wide]\n",
      diagramCaption: "Where the plist lives determines who it runs as and when it starts",
      checkpoint: {
        question: "An investigation finds a new plist file in /Library/LaunchDaemons pointing at an ad-hoc-signed binary. What does the LOCATION alone already prove about how it got there?",
        options: [
          "Nothing -- any logged-in user can write into /Library/LaunchDaemons without special privilege",
          "Whatever created it was already running with root privilege, since /Library/LaunchDaemons is not writable by an ordinary user account",
          "It proves the binary itself is definitely malicious, regardless of any other evidence",
          "It proves the item only runs when that specific user is logged in, exactly like a LaunchAgent",
        ],
        answer: 1,
        explanation:
          "Writing into /Library/LaunchDaemons requires root -- ordinary user accounts cannot write there. So finding a new file in that specific directory is itself proof that whatever placed it already had root, before this persistence step happened at all.",
      },
    },
    // ── Question 4 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "macf-q4",
      question:
        "Two persistence items are found on two different Macs during an investigation: Item A is a plist in a specific user's own ~/Library/LaunchAgents folder; Item B is a plist in /Library/LaunchDaemons. Which statement correctly compares their impact?",
      options: [
        "Item B is the more serious finding -- it runs as root, starts automatically at every boot before any user logs in, and its mere existence in that location proves the actor already had root privilege",
        "Item A is more serious, because LaunchAgents are harder to detect than LaunchDaemons",
        "They are functionally identical -- both run as root and both start at boot regardless of any user logging in",
        "Item A is more serious because it persists even after the operating system is reinstalled, while Item B does not",
      ],
      answer: 0,
      explanation:
        "Reading 8 laid out the comparison directly: a LaunchDaemon runs as root, starts before any login, survives reboots regardless of which user is active, and its presence in /Library/LaunchDaemons already proves the actor had root when they placed it -- all of that is absent from a per-user LaunchAgent, which only runs as that one user, only while they're logged in, and requires no elevated privilege to create. Options (b), (c) and (d) all invert or invent facts the reading does not support.",
      xp: 25,
    },
    // ── Log Analysis 2: DMG mount + osascript chain ──────────────────────────
    {
      type: "log_analysis" as const,
      id: "macf-la2",
      heading: "Four Seconds After a Mounted App Launches",
      context:
        "Dana Peretz, a marketing coordinator at NexaCorp, downloaded a free utility called BatteryBoost Pro from a search result and ran it directly from the mounted disk image without moving it into Applications. The event below is what Falcon recorded four seconds after the app launched.",
      event: osascriptChainEvent,
      questions: [
        {
          question:
            "process.parent.code_signature.status for BatteryBoost Pro reads 'adhoc' with subject_name '-'. Based on Reading 4, what does that tell you about this app's provenance?",
          options: [
            "The app carries no real developer identity at all -- it is technically signed because macOS requires it, but the signature makes zero attribution claim and carries none of Apple's trust",
            "The app was built by Apple itself and shipped as part of the operating system",
            "The app's signature was revoked by Apple after being reported for abuse",
            "Ad-hoc signing is simply an older, now-deprecated signing format with no bearing on trust one way or another",
          ],
          answer: 0,
          explanation:
            "Reading 4 covered exactly this state: ad-hoc signing satisfies macOS's technical requirement that every executable be signed, without asserting any real identity -- a subject name of a single dash means no developer or company is named at all. This is the overwhelmingly common state for malware distributed outside official channels. It is not an Apple-built binary (b), not a revoked-then-abused certificate (c, which would show a 'revoked' status, not 'adhoc'), and it is very much still relevant to trust today (d).",
          xp: 25,
        },
        {
          question:
            "The osascript process itself shows code_signature.status 'valid' with subject_name 'Software Signing'. Why doesn't that valid signature make this event benign?",
          options: [
            "Apple's own system binaries like osascript are validly signed on every invocation regardless of intent -- the signal here is the ad-hoc-signed parent and the credential-prompt command line, not osascript's own signature",
            "It does make the event benign -- a valid Apple signature on any process is sufficient on its own to clear it",
            "The 'valid' status must be a logging error, since osascript should never appear in a malicious process chain",
            "A valid signature only applies to the process's first few seconds of execution before it can be considered fully trusted",
          ],
          answer: 0,
          explanation:
            "osascript is a real, Apple-signed binary that will show 'valid' on every single invocation, whatever it was told to do -- Reading 4 named this exact trap. The signal that actually matters here is everything around the signature: an ad-hoc-signed parent process launched minutes earlier from a mounted disk image, spawning osascript with a command line that renders a credential-style prompt. Option (b) is precisely the reasoning error the reading warned against. Nothing supports a logging error (c) -- osascript appears constantly in real malicious chains specifically because it is trusted. And code signatures do not expire within a single execution the way (d) describes.",
          xp: 25,
        },
        {
          question:
            "Putting this event together with what Reading 5 taught about the display dialog and hidden-answer pattern, what should the analyst expect to find if they keep watching this process tree for the next few minutes?",
          options: [
            "A likely follow-on step reading the login Keychain or a browser's saved-credential store, now that a password may have been captured",
            "The process tree should end here -- osascript display dialog events have no meaningful follow-on activity in a real attack chain",
            "A guaranteed ransomware file-encryption event within the same process tree",
            "A new user account being created on the domain controller",
          ],
          answer: 0,
          explanation:
            "Reading 6 built directly on this: once a login password is captured, the next step in a credential-theft chain is very often /usr/bin/security reading the login Keychain, or a direct read of a browser's saved-password database, since the captured password is frequently what unlocks those stores. Nothing here suggests the chain simply stops (b) -- that ignores the entire point of phishing a password. Ransomware (c) and a domain-controller account creation (d) are both unrelated techniques this event gives no evidence for; this platform keeps techniques evidence-based rather than assuming the worst-case unconnected outcome.",
          xp: 30,
        },
      ],
    },
    // ── Analyst Choice: benign notarized pkg install ─────────────────────────
    {
      type: "analyst_choice" as const,
      id: "macf-ac1",
      heading: "Verdict: A .pkg Install Followed by a New LaunchAgent",
      scenario:
        "An automated rule fires on MAC-6610 for a pattern this room has spent several readings teaching you to take seriously: a .pkg installer ran, and a new launchd item was registered immediately afterward. Review the record before deciding how to handle it.",
      event: benignNotarizedInstallEvent,
      correct_verdict: "false_positive",
      explanation:
        "The install shape (a .pkg followed by a new launch item) is real, but every discriminator this room taught points to benign: process.code_signature.status is valid with a genuine Developer ID Application subject naming a real, identifiable company, file.signature.trusted is true, and the description states plainly that the registered item is a per-user LaunchAgent for the app's own updater -- not a system-wide LaunchDaemon. A LaunchAgent created by the app's own installer, under the current user's own privilege, to manage its own future update checks, is exactly the routine pattern Reading 8 described as unremarkable. There is no ad-hoc or revoked signature here, no root-owned script doing anything unusual, and no TCC or Keychain activity anywhere in the record.",
      fp_trap:
        "A .pkg install followed by a new launchd registration is precisely the shape this room has taught you to scrutinize -- installer scripts can run as root, and a LaunchDaemon can persist as root at boot. But real, entirely legitimate commercial software installs this way constantly, registering a per-user LaunchAgent to check for its own updates. Escalating every install-plus-launch-item pattern on shape alone, without checking the signature state and which of the two launchd locations was actually used, trains a team to drown in noise on the one pattern that most needs real scrutiny when it is genuinely malicious.",
      xp: 30,
    },
    // ── Matching: term to definition ─────────────────────────────────────────
    {
      type: "matching" as const,
      id: "macf-m1",
      heading: "Match the macOS Term to What It Actually Does",
      instructions: "Match each macOS security mechanism to the description of what it does.",
      pairs: [
        { id: "gatekeeper", left: "Gatekeeper", right: "Runs an assessment at first launch, checking a quarantined app's signature and notarization status before deciding whether to allow it" },
        { id: "notarization", left: "Notarization", right: "Apple's own automated malware scan of a signed app, which issues a ticket Gatekeeper can trust without further friction" },
        { id: "quarantine", left: "com.apple.quarantine", right: "An extended attribute set on anything downloaded from outside the machine, which is what triggers Gatekeeper's check on first launch" },
        { id: "adhoc", left: "Ad-hoc signature", right: "A signature that satisfies macOS's technical requirement to sign code, but asserts no real developer identity at all" },
        { id: "tcc", left: "TCC.db", right: "The privacy-permission database recording which apps were allowed Full Disk Access, Screen Recording, and other protected resources" },
        { id: "daemon", left: "LaunchDaemon", right: "A launchd item in /Library/LaunchDaemons that runs as root and starts automatically at every boot, before any user logs in" },
        { id: "agent", left: "LaunchAgent", right: "A launchd item in a user's own Library folder that runs only while that specific user is logged in, with their own privilege level" },
      ],
      explanation:
        "Notice how these seven mechanisms chain together across a real intrusion: quarantine flags a download, Gatekeeper checks its signature and notarization state to decide whether to add friction, a root-level install script can bypass user consent by writing straight into TCC.db, and persistence lands either as a narrow per-user LaunchAgent or a much more consequential system-wide root LaunchDaemon.",
      xp: 35,
    },
    // ── Ordering: triage sequence ─────────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "macf-o1",
      heading: "Order the Triage of a Suspicious macOS Process Chain",
      instructions: "Arrange these steps in the order an analyst should actually work them when investigating an unfamiliar macOS process chain.",
      items: [
        { id: "ancestry", text: "Check the full process ancestry -- what launched what, and whether that parent-child relationship makes sense for the app involved" },
        { id: "signature", text: "Check the code-signature status of the binaries involved -- Developer ID, ad-hoc, revoked, or unsigned -- for both the parent and any child processes" },
        { id: "quarantine", text: "Check whether the com.apple.quarantine attribute is present on the originating file, and what Gatekeeper's assessment recorded at first launch" },
        { id: "privilege", text: "Check whether anything in the chain ran as root, and if so, what that root process actually touched -- particularly TCC.db or a LaunchDaemon location" },
        { id: "network", text: "Check for any outbound network activity tied to the same process tree, and where it went" },
        { id: "verdict", text: "Assign a verdict and document the full chain for the incident record" },
      ],
      correct_order: ["ancestry", "signature", "quarantine", "privilege", "network", "verdict"],
      explanation:
        "Start with ancestry, because an unusual parent-child pair -- like an ad-hoc-signed app spawning osascript -- is often the first fact that reframes the whole chain. From there, the signature states of everything involved tell you which parts of the chain carry real identity and which don't, and the quarantine/Gatekeeper history tells you how the file got past (or through) the operating system's own first line of defence. Only once the technical shape is clear does it make sense to check for privilege escalation specifically -- since finding a TCC.db write or a new LaunchDaemon changes the scope of the incident substantially -- and network activity after that. Committing to a verdict comes last, once every layer has actually been checked, which is exactly what separates a correctly-closed benign install (like the Notion case in this room) from a missed intrusion that looked identical on the surface.",
      xp: 35,
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "macf-f1",
      prompt:
        "Look at the Log Analysis finding on MAC-4471 (the TCC.db write). What is the exact value of the crowdstrike.ParentProcessName field in the raw log?",
      answer: "sh",
      hint: "Look inside the raw block of the log analysis event for the field named crowdstrike.ParentProcessName.",
      xp: 20,
    },
    // ── Question 5: synthesis ──────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "macf-q5",
      question:
        "A help-desk ticket describes a Mac where a downloaded utility was run, the user was asked to type their password into an unfamiliar dialog, and shortly afterward the machine's fan spun up while the app was already closed. No new file appeared under /Library/LaunchDaemons. Which of this room's mechanisms most plausibly explains persistence surviving after the app itself was quit, and what should the analyst check first?",
      options: [
        "A LaunchAgent under the user's own ~/Library/LaunchAgents folder -- check there first, since it requires no root privilege to create and would explain activity continuing for that user without a system-wide root daemon being present",
        "It must be a LaunchDaemon that simply hasn't been found yet, so the analyst should assume root compromise regardless of what a search of /Library/LaunchDaemons actually shows",
        "Persistence is impossible without a LaunchDaemon, so the described activity must be an unrelated, coincidental problem with the Mac",
        "The Keychain itself must have been corrupted, which is what is causing the sustained fan activity",
      ],
      answer: 0,
      explanation:
        "Reading 8 covered exactly this middle case: persistence does not require root at all -- a LaunchAgent under the user's own Library folder needs no elevated privilege to create and would fully explain something continuing to run for that user after the original app was quit. Jumping straight to 'it must be a LaunchDaemon we haven't found' (b) ignores the room's own evidence-based approach -- a clean search result is a real finding, not something to override with an assumption. Persistence is not impossible without a LaunchDaemon (c); that is exactly what a LaunchAgent is for. And nothing in this room ties Keychain state to CPU/fan activity (d) -- that combination describes a running process consuming resources, not a credential-store issue.",
      xp: 30,
    },
  ],
};

export const roomsBatch36 = [macosSecurityFundamentalsRoom];
