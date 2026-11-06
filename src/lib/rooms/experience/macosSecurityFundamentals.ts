import type { RoomExperience } from "./types";

// "Operation Orchard" for the "macos-security-fundamentals" room.
// Script: docs/campaign/22-macos-security-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Corva Studios (fictional), not the graded tasks' NexaCorp. Lab data differs
// from the graded tasks: the DMG/PKG console asks what a postinstall script
// fetches, not why packages are riskier (q1); the signing console checks
// third-party apps, never osascript's own signature (q2); the osascript sort
// leaves out hidden-answer password dialogs (q3, la2); the TCC sheet reads a
// user database, not la1's root sqlite3 write (la1, f1); the launchd console
// finds one daemon and asks what its plist says, not how agents and daemons
// compare (q4, q5) or Notion's updater (ac1); and nothing defines mechanisms
// (m1) or orders the triage (o1).
export const MACOS_SECURITY_FUNDAMENTALS: RoomExperience = {
  roomId: "macos-security-fundamentals",
  codename: "Operation Orchard",
  theme: "macos",
  handler: { name: "Mei Tran", role: "macOS Security Engineer, Corva Studios" },
  briefing: [
    "Corva Studios. 180 designers, 180 MacBooks, and an analyst team trained on Windows.",
    "macOS is Unix underneath, with its own gates: quarantine tags, Gatekeeper, signatures, privacy consent, and launchd.",
    "Mei Tran secures the fleet. She'll hand you the same evidence and the same questions she asks of every odd Mac.",
    "Learn where software comes in, what vouches for it, and where it hides to stay.",
  ],
  mission: "Map Windows ideas onto macOS, work out which DMG or PKG dropped a helper, read quarantine, Gatekeeper and code signatures, judge osascript command lines, test your Keychain instincts, read the TCC database, and inspect a launchd plist.",
  estimate: "~65 min",
  look: { primary: "#e2e8f0", secondary: "#60a5fa", warn: "#f43f5e" },
  scene: "orchard",
  layout: "stage",
  story: {
    intro: { title: "Unix With Its Own Gates", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-intro-7fad77b8.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-intro-f4352769.jpg" },
    afterStation: {
      doors: { title: "Who Vouches for It", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch2-2b9895c5.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch2-c30ae9a5.jpg" },
      prompts: { title: "The Password Is the Key", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch3-8811c0c8.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch3-08279469.jpg" },
      persist: { title: "KeepAlive", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-finale-8537a4d4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-finale-2fa5b88c.jpg" },
    },
  },
  stations: [
    {
      id: "model",
      label: "Unix Underneath",
      topic: "macOS for an analyst trained on Windows or Linux",
      tagline: "Translate what you know into macOS terms",
      building: "archive",
      taskIds: ["macf-r1"],
    },
    {
      id: "doors",
      label: "Two Doors In",
      topic: "DMG disk images vs PKG installers and their scripts",
      tagline: "Mount one, unpack the other",
      building: "factory",
      taskIds: ["macf-r2", "macf-q1"],
    },
    {
      id: "gate",
      label: "Who Vouches for It",
      topic: "Quarantine attribute, Gatekeeper, notarization · Developer ID vs ad-hoc vs revoked",
      tagline: "Read the tags and signatures before it runs",
      building: "vault",
      taskIds: ["macf-r3", "macf-r4", "macf-q2"],
    },
    {
      id: "prompts",
      label: "Scripts and Secrets",
      topic: "osascript as a living-off-the-land tool · the login Keychain",
      tagline: "Judge AppleScript one-liners, then test your Keychain instincts",
      building: "lab",
      taskIds: ["macf-r5", "macf-q3", "macf-la2", "macf-r6"],
    },
    {
      id: "tcc",
      label: "The Privacy Gate",
      topic: "TCC: who may record the screen, read every file, or control other apps",
      tagline: "Read the consent database row by row",
      building: "control",
      taskIds: ["macf-r7", "macf-la1", "macf-f1"],
    },
    {
      id: "persist",
      label: "Staying Power",
      topic: "LaunchAgents vs LaunchDaemons · launchctl and plists",
      tagline: "Find what starts on its own, and read its plist",
      building: "ticket",
      taskIds: ["macf-r8", "macf-q4", "macf-ac1", "macf-q5", "macf-m1", "macf-o1"],
      boss: true,
    },
  ],
  personas: {
    "macf-q1": { name: "Mei Tran", role: "macOS Security Engineer", line: "Same app, shipped as a DMG or as a PKG. Why is one riskier per click?" },
    "macf-q2": { name: "Mei Tran", role: "macOS Security Engineer", line: "osascript, signed by Apple. A junior calls it benign. Correct them." },
    "macf-q3": { name: "Mei Tran", role: "macOS Security Engineer", line: "An ad-hoc app spawns osascript with 'display dialog'. Read that one event." },
    "macf-q4": { name: "Mei Tran", role: "macOS Security Engineer", line: "A LaunchAgent on one Mac, a LaunchDaemon on another. Which is worse?" },
    "macf-q5": { name: "Mei Tran", role: "macOS Security Engineer", line: "The app is closed, but something keeps running. Where do you look first?" },
    "macf-ac1": { name: "Mei Tran", role: "macOS Security Engineer", line: "A .pkg install and a new LaunchAgent on a designer's Mac. Verdict?" },
  },
  briefings: {
    // ── Reading 1: the mental model ──
    "macf-r1": [
      {
        kind: "match",
        title: "Translate to macOS",
        prompt: "You know these on Windows. Match each to its macOS counterpart.",
        pairs: [
          { id: "reg", left: "The Registry", right: "Property list (.plist) files", why: "Settings live in plist files (XML or binary), not in one central database." },
          { id: "run", left: "A Run key or scheduled task", right: "A LaunchAgent or LaunchDaemon", why: "launchd starts whatever a plist in those folders tells it to." },
          { id: "scm", left: "services.exe / Service Control Manager", right: "launchd (PID 1)", why: "One supervisor starts and keeps alive almost everything." },
          { id: "motw", left: "Mark-of-the-Web", right: "The com.apple.quarantine attribute", why: "Same purpose (tag downloads), different mechanism (an extended attribute)." },
          { id: "users", left: "C:\\Users\\name", right: "/Users/name", why: "Unix layout: home folders under /Users." },
          { id: "uac", left: "A UAC elevation prompt", right: "An administrator password prompt (sudo / authorization dialog)", why: "Elevation asks for an admin's password, which is exactly why fake password dialogs work." },
        ],
      },
    ],
    // ── Reading 2: DMG and PKG ──
    "macf-r2": [
      {
        kind: "deduce",
        title: "Which Download Dropped It?",
        prompt: "A designer's Mac has a new helper binary under /Library/Application Support that nobody launched. Mei lines up this morning's six downloads. Which one put it there?",
        nameColumn: "Download",
        columns: ["Format", "Signature", "Scripts inside"],
        suspects: [
          { id: "d1", name: "FontPack.dmg", cells: ["Disk image", "Developer ID, notarized", "none, an app and an alias"] },
          { id: "d2", name: "ProofViewer.dmg", cells: ["Disk image", "Ad-hoc", "none, an app only"] },
          { id: "d3", name: "Calibrator.pkg", cells: ["Installer package", "Developer ID, notarized", "postinstall"] },
          { id: "d4", name: "PrinterDrv-4.pkg", cells: ["Installer package", "Developer ID, notarized", "none, payload only"] },
          { id: "d5", name: "TypeSync.pkg", cells: ["Installer package", "Developer ID, notarized", "preinstall and postinstall"] },
          { id: "d6", name: "ColorLink.pkg", cells: ["Installer package", "Unsigned", "postinstall"] },
        ],
        clues: [
          "Opening a disk image only mounts a volume of files. Nothing in a DMG runs until someone launches the app, and the helper appeared during an install.",
          "Expanding each package with pkgutil --expand shows the helper in no payload. Whatever put it there had to run code and fetch it.",
          "Mei read the postinstall scripts of Calibrator and ColorLink: one registers a daemon that is already in its own payload, the other only sets permissions on payload files. Neither makes a network call.",
        ],
        culprit: "d5",
        why: "TypeSync.pkg is signed and notarized, yet its postinstall pulls a second binary from the network; a valid signature says who built the package, not what its script does. The DMGs only expose files, PrinterDrv-4 has no scripts to run, and the unsigned ColorLink and the Calibrator scripts were read and stay inside their own payloads. Expanding a PKG before installing is how you find this.",
      },
    ],
    // ── Readings 3-4: quarantine, Gatekeeper, signatures ──
    "macf-r4": [
      {
        kind: "intercept",
        title: "The Notarization Gate",
        prompt: "Corva's designers launch new apps all morning. You are the gate: Mei reads you the quarantine tag, the Gatekeeper verdict and the signature for each one. Refuse what should not run, allow the rest.",
        protect: "the Corva MacBook fleet",
        blockLabel: "Refuse",
        passLabel: "Allow",
        seconds: 11,
        items: [
          { id: "i1", text: "Meetly.app", sub: "quarantine: Chrome · spctl: accepted, source=Notarized Developer ID", bad: false, why: "Downloaded by a browser, quarantined, notarized by Apple and signed with a Developer ID. Every check passes." },
          { id: "i2", text: "RenderBoost.app", sub: "quarantine: Safari · spctl: rejected, source=Unnotarized Developer ID", bad: true, why: "A valid Developer ID signature, but Apple never notarized it. Gatekeeper refuses it on first launch, and so should you." },
          { id: "i3", text: "TabOrganiser (installed from the Mac App Store)", sub: "spctl: accepted, source=Mac App Store", bad: false, why: "App Store apps are reviewed and signed by Apple. Source=Mac App Store is the strongest voucher on the list." },
          { id: "i4", text: "FontMender (command-line tool from a chat link)", sub: "quarantine: Slack · codesign: Signature=adhoc, TeamIdentifier=not set", bad: true, why: "Ad-hoc satisfies 'must be signed' while naming nobody. With no team behind it, nothing vouches for it." },
          { id: "i5", text: "Pixel Foundry Studio.app", sub: "quarantine: Safari · spctl: rejected, CSSMERR_TP_CERT_REVOKED", bad: true, why: "The Developer ID certificate was revoked, usually after abuse. A signature from a revoked certificate counts for nothing." },
          { id: "i6", text: "Corva Agent update (pushed by the MDM)", sub: "no quarantine attribute · spctl: accepted, source=Notarized Developer ID", bad: false, why: "No quarantine tag, but the MDM installed it, not a download, and it is notarized. A missing tag is only a warning when something else wrote the file." },
          { id: "i7", text: "ArtBridge.pkg", sub: "no quarantine attribute · fetched by curl run from a script in /tmp", bad: true, why: "curl does not set the quarantine tag, so Gatekeeper never checks the file at all. The missing tag is the problem here, because an unknown script fetched it." },
          { id: "i8", text: "Preview.app", sub: "spctl: accepted, source=Apple System", bad: false, why: "Apple's own binary from the signed system volume. Source=Apple System needs no further questions." },
          { id: "i9", text: "ColorPicker Pro.app", sub: "quarantine: Safari · spctl: accepted, source=Notarized Developer ID · codesign --verify: a sealed resource is missing or invalid", bad: true, why: "Notarized when it shipped, but files inside the bundle changed afterwards, which breaks the seal. A good certificate on a modified app is a trojan." },
          { id: "i10", text: "Slidesmith.app", sub: "quarantine: Safari · spctl: accepted, source=Notarized Developer ID · codesign --verify: valid", bad: false, why: "Notarization accepted and the seal verifies. It looks like the others but nothing is missing." },
        ],
        lesson: "Three checks vouch for a Mac app: the quarantine tag says where it came from, spctl says whether Apple accepts it, and codesign says who signed it and whether it was changed. A missing tag is only safe if a trusted installer wrote the file.",
      },
    ],
    // ── Reading 5: osascript ──
    "macf-r5": [
      {
        kind: "sort",
        title: "Admin Tool or Abuse?",
        prompt: "osascript command lines seen across the fleet this week, each with its parent process. Sort them.",
        buckets: [
          { id: "ok", label: "Expected automation" },
          { id: "bad", label: "Investigate" },
        ],
        items: [
          { id: "a", text: "Jamf agent > osascript -e 'display notification \"Restart tonight for updates\" with title \"Corva IT\"'", bucket: "ok", why: "The MDM agent posting a notification: exactly what osascript is for." },
          { id: "b", text: "FontFixer (ad-hoc) > osascript -e 'tell application \"Finder\" to duplicate (POSIX file \"/Users/mei/Library/Keychains/login.keychain-db\") to (POSIX file \"/tmp\")'", bucket: "bad", why: "An unknown, unsigned-identity binary copying the login Keychain file out of its folder." },
          { id: "c", text: "Adobe installer > osascript -e 'tell application \"Adobe Photoshop 2026\" to quit'", bucket: "ok", why: "An installer closing the app it's about to update." },
          { id: "d", text: "curl | sh > osascript -e 'do shell script \"launchctl load /Library/LaunchDaemons/com.sysupdate.helper.plist\" with administrator privileges'", bucket: "bad", why: "A piped download script asking for admin rights to load a daemon." },
          { id: "e", text: "Terminal (user mei, IT staff) > osascript -e 'tell application \"System Events\" to get name of every login item'", bucket: "ok", why: "An admin listing login items while troubleshooting: same tool, legitimate intent, known user." },
        ],
      },
    ],
    // ── Reading 6: the Keychain ──
    "macf-r6": [
      {
        kind: "rush",
        title: "Keychain Calls",
        prompt: "EDR flagged the security tool on a designer's Mac. Mei throws Keychain and credential-theft claims at you. True or false, before the clock runs out.",
        seconds: 60,
        target: 10,
        cards: [
          { id: "k1", text: "The security tool can read Keychain items from a script, with no graphical prompt, once it has the unlocked login password.", answer: true, why: "That is what the tool is for. A run of it that nobody on the team started, with an odd parent, is the alert." },
          { id: "k2", text: "The login Keychain has its own password, separate from the user's login password.", answer: false, why: "By default it opens with the login password. That is why a phished login password unlocks everything stored in it." },
          { id: "k3", text: "A phished macOS login password can also open that user's login Keychain.", answer: true, why: "Same secret, two doors. This is why fake password dialogs are worth an attacker's effort." },
          { id: "k4", text: "A security process whose parent lives in a hidden folder under Application Support is routine.", answer: false, why: "Legitimate tools do not hide in dot folders named like system daemons. The parent process explains the dump." },
          { id: "k5", text: "Tracing a security run to its parent process tells you more than the fact that the tool ran.", answer: true, why: "The parent explains the run: a hidden or ad-hoc parent turns routine automation into a credential-theft chain." },
          { id: "k6", text: "Chrome keeps its saved passwords only in the Keychain, so reading the Keychain entry is always the whole theft.", answer: false, why: "Chrome stores a Safe Storage key in the Keychain that protects a separate password database in its profile folder. The Keychain entry is the key to that second store." },
          { id: "k7", text: "A detection built only on the security binary having run will drown in noise.", answer: true, why: "/usr/bin/security is used constantly by legitimate software and IT tooling. The parent process and the command line are what matter." },
          { id: "k8", text: "/usr/bin/security is validly Apple-signed, so a run of it can be waved through.", answer: false, why: "A valid signature only says who built the binary. A stealer uses the real tool, so judge the parent and the arguments." },
          { id: "k9", text: "The login Keychain is a file named login.keychain-db under the user's own Library/Keychains folder.", answer: true, why: "That file is what a copy command or a security call is aimed at, which is why a copy of it by an unknown binary is a finding." },
          { id: "k10", text: "A security call from an unusual parent seconds after an osascript password prompt is stronger evidence than either event alone.", answer: true, why: "Sequence, not any single process, turns routine automation into a credential-theft chain." },
          { id: "k11", text: "With the login password in hand, find-generic-password can pull one saved item without any graphical prompt.", answer: true, why: "That is why a stealer prefers the command line: no dialog appears for the victim to notice." },
          { id: "k12", text: "osascript showing a notification, started by the Jamf agent, should be escalated.", answer: false, why: "The MDM agent posting a notification is what osascript is for. Judge the parent and the content, not the tool." },
          { id: "k13", text: "osascript raising a password dialog with hidden input, launched by an ad-hoc signed binary, deserves investigation.", answer: true, why: "A binary that names nobody asking for a password is credential harvesting. The tool is Apple's; the intent is not." },
          { id: "k14", text: "Killing the process that dumped the Keychain also revokes the passwords it already read.", answer: false, why: "Whatever was printed has left. Rotate the credentials, because containment of the process does not recall the secrets." },
        ],
        lesson: "The Keychain opens with the login password, so one phished dialog opens everything; trace the dump to its parent process, and judge a security run by its parent and its arguments, not by the tool's signature.",
      },
    ],
    // ── Reading 7: TCC ──
    "macf-r7": [
      {
        kind: "worksheet",
        title: "Read the Consent Database",
        prompt: "Rows from a designer's Mac, from both TCC databases: the per-user one (camera, microphone, automation) and the system one (Accessibility, Full Disk Access). auth_value 2 means allowed, 0 means denied.",
        caption: "select service, client, auth_value, auth_reason from access · user TCC.db (~/Library/...) and system TCC.db (/Library/...)",
        columns: ["database", "service", "client", "auth_value", "auth_reason"],
        rows: [
          ["user", "kTCCServiceMicrophone", "com.microsoft.teams2", "2", "2 (user consent)"],
          ["user", "kTCCServiceCamera", "us.zoom.xos", "2", "2 (user consent)"],
          ["system", "kTCCServiceAccessibility", "com.renderd.agent", "2", "4 (system set)"],
          ["user", "kTCCServiceAppleEvents", "com.apple.Terminal", "0", "2 (user consent)"],
        ],
        questions: [
          { id: "acc", q: "Which client may control other apps through Accessibility?", hint: "kTCCServiceAccessibility.", answer: ["com.renderd.agent", "renderd"], why: "Accessibility lets an app click, type and read other windows: a keylogger's dream." },
          { id: "how", q: "Did a user approve that grant? (yes/no)", hint: "Read its auth_reason.", answer: ["no"], why: "Reason 4 is a system-set entry, not a click in a consent prompt. Grants nobody clicked are what TCC tampering leaves behind." },
          { id: "deny", q: "Which entry was denied?", hint: "auth_value 0.", answer: ["kTCCServiceAppleEvents", "AppleEvents", "com.apple.Terminal", "Terminal"], why: "The user said no to Terminal automating another app. Denials are recorded too." },
        ],
      },
    ],
    // ── Reading 8: launchd persistence ──
    "macf-r8": [
      {
        kind: "spotdiff",
        title: "The Golden Plist",
        prompt: "Mei keeps a golden copy of the fleet agent's LaunchDaemon plist, printed with plutil -p. This MacBook's copy came back from a flagged Mac. Tap every line that was tampered with.",
        goodTitle: "Golden copy (fleet image)",
        suspectTitle: "CORVA-MBP-112 now",
        good: [
          "{",
          "  \"Label\" => \"com.corva.fleet-agent\"",
          "  \"ProgramArguments\" => [",
          "    0 => \"/Library/Corva/Agent/fleet-agent\"",
          "    1 => \"--checkin\"",
          "  ]",
          "  \"RunAtLoad\" => 1",
          "  \"StartInterval\" => 3600",
          "  \"UserName\" => \"root\"",
          "  \"StandardErrorPath\" => \"/var/log/fleet-agent.err\"",
          "  \"KeepAlive\" => 0",
          "}",
        ],
        suspect: [
          "{",
          "  \"Label\" => \"com.apple.mdmclient.helper\"",
          "  \"ProgramArguments\" => [",
          "    0 => \"/Users/Shared/.fleet/fleet-agent\"",
          "    1 => \"--checkin\"",
          "  ]",
          "  \"RunAtLoad\" => 1",
          "  \"StartInterval\" => 1800",
          "  \"UserName\" => \"root\"",
          "  \"StandardErrorPath\" => \"/var/log/fleet-agent-err.log\"",
          "  \"KeepAlive\" => 1",
          "}",
        ],
        diffs: [
          { line: 1, why: "The Label now borrows an Apple-looking name. Attackers name launchd jobs after system components so a glance at the list passes; the label must match what the vendor ships." },
          { line: 3, why: "The program moved to a hidden folder in /Users/Shared, which any user can write. A real vendor installs under /Library, so the daemon now runs whatever sits in a world-writable path, as root." },
          { line: 10, why: "KeepAlive went from 0 to 1, so launchd restarts the process whenever it dies. Killing it does nothing; unload the plist with launchctl bootout, then remove the file and the binary." },
        ],
        decoys: [
          { line: 7, why: "StartInterval moved from hourly to every 30 minutes. A faster check-in is a policy change, and it grants no new access." },
          { line: 9, why: "Only the log file name changed. A different StandardErrorPath is cosmetic and still points inside /var/log." },
        ],
        lesson: "Judge a launchd plist by its Label, the path of its program and its KeepAlive and RunAtLoad keys. A vendor-like name, a binary in a world-writable folder and KeepAlive set to 1 describe persistence.",
      },
    ],
  },
};
