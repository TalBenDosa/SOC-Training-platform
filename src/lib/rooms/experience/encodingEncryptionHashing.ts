import type { RoomExperience } from "./types";

// "Operation Cipher Room" for the "encoding-encryption-hashing" room (rooms-batch-20.ts).
// Script: docs/campaign/08-encoding-encryption-hashing.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Arclight Insurance (fictional). Every hash and encoding in the labs is real
// (computed, not invented). Lab data differs from the graded tasks: the decode
// bench never uses the flag's string or the scheduled-task blob (f1, ac1), the
// avalanche demo uses a payment string, not 'invoice.pdf' (q2), the hash-check
// queue sits after the graded hash alert, and the drill's file record never
// discusses renaming (la1).
export const ENCODING_ENCRYPTION_HASHING: RoomExperience = {
  roomId: "encoding-encryption-hashing",
  codename: "Operation Cipher Room",
  theme: "crypto",
  handler: { name: "Tomas Reyes", role: "Senior Analyst, Arclight Insurance" },
  briefing: [
    "Arclight Insurance. Three words show up in almost every ticket: encoded, encrypted, hashed.",
    "Mix them up and you misjudge how serious a finding is.",
    "Tomas Reyes keeps a bench for exactly this: a decoder, a hash press and a captured TLS session.",
    "Learn what each one can and cannot hide, by running them yourself.",
  ],
  mission: "Use the analyst's bench: decode Base64, hex, URL and PowerShell blobs, hash data and verify downloads, expose shared passwords, judge hash lookups, and read an encrypted beacon without decrypting it.",
  estimate: "~55 min",
  look: { primary: "#a78bfa", secondary: "#38bdf8", warn: "#f43f5e" },
  scene: "cipherlab",
  layout: "stage",
  story: {
    intro: { title: "Three Words", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-intro-8f6bc0b0.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-intro-0ee7220b.jpg" },
    afterStation: {
      decode: { title: "Not a Secret", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch2-4343a07c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch2-1218fcfd.jpg" },
      press: { title: "One Byte, New Hash", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch3-1c285616.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch3-25904254.jpg" },
      tunnel: { title: "Read It Without Breaking It", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-finale-ff58df1a.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-finale-85d0cac3.jpg" },
    },
  },
  stations: [
    {
      id: "jobs",
      label: "Three Jobs",
      topic: "Encoding vs encryption vs hashing: reversible by anyone, with a key, or never",
      tagline: "Sort real situations by which of the three operations they are",
      building: "archive",
      taskIds: ["enc-r1"],
    },
    {
      id: "decode",
      label: "The Decoder Bench",
      topic: "Base64 · hex · URL encoding · PowerShell -EncodedCommand (UTF-16LE)",
      tagline: "Decode what attackers encode, then judge an encoded scheduled task",
      building: "lab",
      taskIds: ["enc-r2", "enc-f1", "enc-q1", "enc-ac1"],
    },
    {
      id: "press",
      label: "The Hash Press",
      topic: "What a hash is · one-way · avalanche effect · collisions · fixed length",
      tagline: "Hash data yourself and watch one character change everything",
      building: "factory",
      taskIds: ["enc-r3", "enc-r4", "enc-q2"],
    },
    {
      id: "work",
      label: "Hashes on Shift",
      topic: "IOC matching · integrity checks · salted password storage · NSRL · a hash's limits",
      tagline: "Verify a download, expose shared passwords, and judge hash lookups",
      building: "control",
      taskIds: ["enc-r5", "enc-o1", "enc-la1", "enc-r6", "enc-m1"],
    },
    {
      id: "tunnel",
      label: "Inside the Tunnel",
      topic: "Symmetric vs asymmetric encryption · TLS · what stays visible without decrypting",
      tagline: "An encrypted connection beacons out. Read it without breaking it",
      building: "vault",
      taskIds: ["enc-r7", "enc-r8", "enc-q3"],
      boss: true,
    },
  ],
  personas: {
    "enc-q1": { name: "Tomas Reyes", role: "Senior Analyst", line: "Our proxy rule looks for the word 'DownloadString'. It still missed this one. Why?" },
    "enc-q2": { name: "Tomas Reyes", role: "Senior Analyst", line: "Two names, one letter apart, and the hashes look nothing alike. What does that tell you?" },
    "enc-q3": { name: "Mei Tanaka", role: "Tier 2 Lead", line: "We can't decrypt it, and you still called it a beacon. What did you actually see?" },
  },
  briefings: {
    // ── Reading 1: three different jobs ──
    "enc-r1": [
      {
        kind: "sort",
        title: "Which Operation?",
        prompt: "Every one of these happens at Arclight every day. Is it encoding (reversible by anyone), encryption (reversible with a key) or hashing (never reversible)?",
        buckets: [
          { id: "enc", label: "Encoding" },
          { id: "cry", label: "Encryption" },
          { id: "hash", label: "Hashing" },
        ],
        items: [
          { id: "csv", text: "A CSV export is turned into Base64 so it fits inside a JSON field", bucket: "enc", why: "A format change for transport. Anyone can turn it back." },
          { id: "bitl", text: "A laptop disk is locked with BitLocker and a recovery key", bucket: "cry", why: "Readable again only with the key: encryption." },
          { id: "sha", text: "An installer is published with its SHA-256 so you can check your copy", bucket: "hash", why: "A fingerprint for identity and integrity, not a secret." },
          { id: "url", text: "A space in a web address travels as %20", bucket: "enc", why: "URL encoding: so the browser doesn't misread the URL." },
          { id: "pwd", text: "A password is stored as a salted SHA-256 value", bucket: "hash", why: "Stored so it can be checked, never read back." },
          { id: "tls", text: "A customer's web session is protected with TLS", bucket: "cry", why: "Only the two ends hold the session key." },
          { id: "enc", text: "Malware launches powershell -enc followed by a long blob", bucket: "enc", why: "Hidden from naive text rules, not from you: one decode reveals it." },
        ],
      },
    ],
    // ── Reading 2: Base64, hex, URL, PowerShell ──
    "enc-r2": [
      {
        kind: "terminal",
        title: "The Decoder Bench",
        prompt: "Four strings pulled from this week's alerts. None of them is secret: decode each one on the bench and read what it really says.",
        shell: "bash",
        host: "tomas@bench:~$",
        commands: [
          { match: "echo\\s+-?n?\\s*['\"]?aHR0cDovLzIwMy4wLjExMy45NS9zdGFnZTIuYmlu['\"]?\\s*\\|\\s*base64\\s+(-d|--decode)", help: "echo '<text>' | base64 -d            decode Base64",
            output: "http://203.0.113.95/stage2.bin" },
          { match: "echo\\s+-?n?\\s*['\"]?77686f616d69202f616c6c['\"]?\\s*\\|\\s*xxd\\s+-r\\s+-p", help: "echo '<hex>' | xxd -r -p              decode hex",
            output: "whoami /all" },
          { match: "python3\\s+-c\\s+.*unquote.*", help: "python3 -c \"import urllib.parse as u; print(u.unquote('<text>'))\"   URL-decode",
            output: "id=1' OR '1'='1" },
          { match: "echo\\s+-?n?\\s*['\"]?QQBkAGQA[A-Za-z0-9+/=]*['\"]?\\s*\\|\\s*base64\\s+(-d|--decode)\\s*\\|\\s*iconv\\s+-f\\s+utf-?16le(\\s+-t\\s+utf-?8)?", help: "echo '<blob>' | base64 -d | iconv -f UTF-16LE -t UTF-8   decode a PowerShell -enc blob",
            output: "Add-MpPreference -ExclusionPath C:\\Users\\Public" },
          { match: "echo\\s+-?n?\\s*['\"]?QQBkAGQA[A-Za-z0-9+/=]*['\"]?\\s*\\|\\s*base64\\s+(-d|--decode)",
            output: "A.d.d.-.M.p.P.r.e.f.e.r.e.n.c.e. .-.E.x.c.l.u.s.i.o.n.P.a.t.h. .C.:.\\.U.s.e.r.s.\\.P.u.b.l.i.c.\n(each dot is a 00 byte: this is UTF-16LE. Pipe it through iconv -f UTF-16LE -t UTF-8)" },
          { match: "cat\\s+strings\\.txt", help: "cat strings.txt                        the four strings",
            output: "1  aHR0cDovLzIwMy4wLjExMy45NS9zdGFnZTIuYmlu\n2  77686f616d69202f616c6c\n3  id%3D1%27%20OR%20%271%27%3D%271\n4  QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAA==" },
        ],
        objectives: [
          { id: "b64", task: "String 1 is Base64. Which URL does it hold?", hint: "echo 'aHR0cDovLzIwMy4wLjExMy45NS9zdGFnZTIuYmlu' | base64 -d", answer: ["http://203.0.113.95/stage2.bin"], why: "A download location for a second stage, hidden from any rule that only matches plain URLs." },
          { id: "hex", task: "String 2 is hex. Which command does it spell?", hint: "echo '77686f616d69202f616c6c' | xxd -r -p", answer: ["whoami /all"], why: "Two hex characters per byte: 77 is 'w', 68 is 'h'. Attackers' first reconnaissance command, written so a keyword search misses it." },
          { id: "url", task: "String 3 is URL-encoded. What does the parameter really say?", hint: "python3 -c \"import urllib.parse as u; print(u.unquote('id%3D1%27%20OR%20%271%27%3D%271'))\"", answer: ["id=1' OR '1'='1", "id=1' or '1'='1"], why: "%27 is a quote, %20 a space: a classic SQL injection test hidden in percent-encoding." },
          { id: "ps", task: "String 4 is a PowerShell -EncodedCommand blob. Which folder does it exclude from Defender?", hint: "echo '<string 4>' | base64 -d | iconv -f UTF-16LE -t UTF-8", answer: ["C:\\Users\\Public", "c:\\users\\public"], why: "Add-MpPreference -ExclusionPath: the attacker tells Defender to stop scanning C:\\Users\\Public before dropping tools there." },
        ],
      },
      {
        kind: "sort",
        title: "Spot the Encoding",
        prompt: "Before you decode, recognise. Which encoding is each string in?",
        buckets: [
          { id: "b64", label: "Base64" },
          { id: "hex", label: "Hex" },
          { id: "url", label: "URL encoding" },
        ],
        items: [
          { id: "a", text: "dXNlcj1hZG1pbg==", bucket: "b64", why: "Mixed case, digits, and = padding, length a multiple of 4." },
          { id: "b", text: "4d5a90000300000004000000", bucket: "hex", why: "Only 0-9 and a-f, two per byte. 4d5a is 'MZ', the start of a Windows executable." },
          { id: "c", text: "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", bucket: "url", why: "%3C and %3E are < and >: a cross-site scripting test." },
          { id: "d", text: "SW52b2tlLUV4cHJlc3Npb24=", bucket: "b64", why: "Base64 again: it decodes to 'Invoke-Expression'." },
          { id: "e", text: "2f6574632f706173737764", bucket: "hex", why: "Hex for '/etc/passwd'." },
          { id: "f", text: "file=..%2F..%2F..%2Fetc%2Fshadow", bucket: "url", why: "%2F is '/': path traversal hidden in percent-encoding." },
        ],
      },
    ],
    // ── Reading 3: what a hash is ──
    "enc-r3": [
      {
        kind: "terminal",
        title: "The Hash Press",
        prompt: "Run real hash functions on the bench. Change one character and see what happens to the output.",
        shell: "bash",
        host: "tomas@bench:~$",
        commands: [
          { match: "echo\\s+-n\\s+['\"]Pay 100 to ACC-4471['\"]\\s*\\|\\s*sha256sum", help: "echo -n 'Pay 100 to ACC-4471' | sha256sum   SHA-256 of a string",
            output: "7bee5b700b44f00aa6887723538af17d5bc08814b4885efd97d1b2c4e0afe380  -" },
          { match: "echo\\s+-n\\s+['\"]Pay 900 to ACC-4471['\"]\\s*\\|\\s*sha256sum", help: "echo -n 'Pay 900 to ACC-4471' | sha256sum   one digit changed",
            output: "8a42b91b2f3f50fa220c305946eed51d3a5e730dec21b17479e066907963edcb  -" },
          { match: "echo\\s+-n\\s+['\"]Pay 100 to ACC-4471['\"]\\s*\\|\\s*md5sum", help: "echo -n 'Pay 100 to ACC-4471' | md5sum      MD5 (legacy)",
            output: "eb6ea0ffc02c0ad3cdc4c51a0310abdc  -" },
          { match: "echo\\s+-n\\s+['\"]Pay 100 to ACC-4471['\"]\\s*\\|\\s*sha1sum", help: "echo -n 'Pay 100 to ACC-4471' | sha1sum     SHA-1 (legacy)",
            output: "656442b54763f3dc538a4144dad6d81f30fa740b  -" },
          { match: "sha256sum\\s+evidence/disk01\\.img", help: "sha256sum evidence/disk01.img         a 4 GB disk image",
            output: "1044dec7206e8d7c9fbb4ae8f766668406d2567fc7fc1a160a9d4700fcf8f8e9  evidence/disk01.img" },
          { match: "ls\\s+-lh?\\s+evidence/?", output: "-rw-r----- 1 tomas soc 4.0G Nov  4 07:58 disk01.img" },
        ],
        objectives: [
          { id: "md5", task: "How many hex characters long is the MD5 output?", hint: "echo -n 'Pay 100 to ACC-4471' | md5sum", answer: ["32"], why: "MD5 is 128 bits, 32 hex characters. Short, fast, and broken for collisions: fine for spotting duplicates, not for trust." },
          { id: "sha1", task: "And the SHA-1 output?", hint: "echo -n 'Pay 100 to ACC-4471' | sha1sum", answer: ["40"], why: "SHA-1 is 160 bits, 40 hex characters. Also broken for collisions." },
          { id: "aval", task: "Change 100 to 900. Do the two SHA-256 outputs start with the same character? (yes or no)", hint: "Hash both strings and compare the first character.", answer: ["no"], why: "7bee5b... versus 8a42b9...: one changed digit, an unrelated output. That is the avalanche effect." },
          { id: "len", task: "Is the 4 GB disk image's SHA-256 longer than the 19-character string's? (yes or no)", hint: "sha256sum evidence/disk01.img", answer: ["no"], why: "Both are 64 hex characters. Fixed length is what makes millions of hashes cheap to store and search." },
        ],
      },
    ],
    "enc-r4": [
      {
        kind: "match",
        title: "Property to Superpower",
        prompt: "Each property of a good hash is the reason for something you rely on. Match them.",
        pairs: [
          { id: "det", left: "Deterministic", right: "The same file gives the same hash on every machine, so a hash is a usable identity", why: "Without it, no hash database would work." },
          { id: "ava", left: "Avalanche effect", right: "A hash can only say 'identical' or 'not identical', never 'close'", why: "One recompile and the old hash is useless." },
          { id: "col", left: "Collision resistance", right: "Nobody can craft a second file with the same hash, so a match can be trusted", why: "Why MD5 and SHA-1 deserve a sceptical read." },
          { id: "fix", left: "Fixed length", right: "A hundred million fingerprints fit in a small, searchable index", why: "The economics of threat intelligence." },
        ],
      },
    ],
    // ── Reading 5: the four jobs of a hash ──
    "enc-r5": [
      {
        kind: "terminal",
        title: "Verify the Download",
        prompt: "IT downloaded the new endpoint agent from three mirrors. The vendor publishes the real SHA-256. Which copy is genuine?",
        shell: "bash",
        host: "tomas@bench:~/downloads$",
        commands: [
          { match: "cat\\s+vendor_sha256\\.txt", help: "cat vendor_sha256.txt                  the vendor's published hash",
            output: "f962cf8e9eabbb97d07caf47c3dd92256ef322c6dfa76a9996c645de035a3089  ArclightAgent-7.2.msi" },
          { match: "sha256sum\\s+(\\*|mirror\\*|.*\\.msi.*)", help: "sha256sum mirror*/ArclightAgent-7.2.msi   hash all three copies",
            output: "ca949ca547cac321d06693f91109ad1fd893e5e4c4ad1eaf71bc453a3d385b89  mirror1/ArclightAgent-7.2.msi\nf962cf8e9eabbb97d07caf47c3dd92256ef322c6dfa76a9996c645de035a3089  mirror2/ArclightAgent-7.2.msi\na62bb5b855a74c9a16069d1a005a51caffca584c57bcd9004a216d06077dee4e  mirror3/ArclightAgent-7.2.msi" },
          { match: "ls(\\s+-l)?", output: "mirror1  mirror2  mirror3  vendor_sha256.txt" },
        ],
        objectives: [
          { id: "good", task: "Which mirror's copy matches the vendor's published hash? (mirror1, mirror2 or mirror3)", hint: "cat vendor_sha256.txt, then sha256sum mirror*/ArclightAgent-7.2.msi", answer: ["mirror2"], why: "Only mirror2 matches all 64 characters. The other two are corrupted or tampered with: do not install them." },
        ],
      },
      {
        kind: "worksheet",
        title: "Who Shares a Password?",
        prompt: "An old database stored plain SHA-256 password hashes. The new one adds a random salt per user. Both tables were exported for an audit.",
        caption: "Password table exports · same four users",
        columns: ["table", "user", "salt", "stored hash (first 16 chars)"],
        rows: [
          ["legacy", "ana", "(none)", "a5c95e887dbf1c0a"],
          ["legacy", "ben", "(none)", "a97dc74ba02c9e70"],
          ["legacy", "chen", "(none)", "3a7ec732573dfbb9"],
          ["legacy", "dee", "(none)", "a5c95e887dbf1c0a"],
          ["salted", "ana", "a91f3c", "b9e42cc3cad10ebd"],
          ["salted", "ben", "c4d711", "818c21b81765ca09"],
          ["salted", "chen", "07aa9e", "893e4e8fe1cd48c5"],
          ["salted", "dee", "5e02bd", "f04431fa668e6389"],
        ],
        questions: [
          { id: "share", q: "In the legacy table, which two users share a password? (two names)", hint: "Look for identical stored hashes.", answer: ["ana and dee", "ana, dee", "ana,dee", "dee and ana", "dee, ana", "ana dee"], why: "Same password, same unsalted hash. Crack one and you have both, and a rainbow table cracks common ones instantly." },
          { id: "salted", q: "In the salted table, can you still tell who shares a password? (yes or no)", hint: "Compare ana's and dee's salted hashes.", answer: ["no"], why: "Each user's random salt changes the input, so identical passwords give unrelated hashes. Rainbow tables become useless." },
        ],
      },
    ],
    // Drill before the graded hash alert: a different file record, decoded.
    "enc-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a File Event",
        prompt: "Your alert is an EDR file-creation record. Tomas walks you through a different one, field by field.",
        source: "Microsoft Defender for Endpoint · DeviceFileEvents · WKS-FIN11",
        fields: [
          { key: "Timestamp", value: "2026-11-04T10:07:41.000Z" },
          { key: "DeviceName", value: "WKS-FIN11" },
          { key: "ActionType", value: "FileCreated", label: "What happened", note: "A new file appeared on disk. Other values include FileModified and FileRenamed." },
          { key: "FileName", value: "PolicyRenewal_2027.scr", label: "What it is called", note: ".scr is a screensaver, which is an executable dressed up as a document." },
          { key: "FolderPath", value: "C:\\Users\\r.lindqvist\\AppData\\Local\\Temp\\Rar$EXa4120\\PolicyRenewal_2027.scr", label: "Where", note: "Rar$EX: extracted from an archive into Temp, the usual route for an attachment opened from a ZIP or RAR." },
          { key: "SHA256", value: "b8b0a64e79e47f3dac1362c1d72092fa63a7b10795facb8deb27ccffebba885c", label: "The fingerprint", note: "The identity you take to threat intelligence. Use SHA256: MD5 and SHA1 are here for older tools." },
          { key: "SHA1", value: "9f1735b19ab93565dbeae477b13d8a52644322d7" },
          { key: "MD5", value: "bbaed3036d63e6ee21b98cf088ccb5c5" },
          { key: "FileSize", value: "1204736" },
          { key: "InitiatingProcessFileName", value: "WinRAR.exe", label: "Who wrote it", note: "The process that created the file: here an archiver, meaning the user extracted it." },
          { key: "InitiatingProcessAccountName", value: "r.lindqvist", label: "As whom", note: "The user whose session it happened in." },
        ],
        summary: "r.lindqvist extracted PolicyRenewal_2027.scr from an archive into Temp at 10:07. Next step: take its SHA256 to threat intelligence, and look at what the file did after it was written.",
      },
    ],
    // ── Reading 6: a hash's limits ──
    "enc-r6": [
      {
        kind: "queue",
        title: "Hash Check Results",
        prompt: "Four hash lookups came back this morning. Decide what each result actually means for the investigation.",
        console: "Threat intelligence · hash lookups",
        actions: [
          { id: "bad", label: "Known bad: contain", tone: "contain" },
          { id: "unknown", label: "Unknown: keep investigating", tone: "escalate" },
          { id: "good", label: "Known good: filter out", tone: "close" },
        ],
        alerts: [
          { id: "emotet", time: "08:12", severity: "High", rule: "invoice_8812.doc.exe", entity: "WKS-ACC04",
            fields: [{ k: "SHA256", v: "b7628ef8…b5e68309" }, { k: "result", v: "Match: 58 of 71 engines" }, { k: "family", v: "Emotet loader" }, { k: "first seen", v: "9 days ago" }],
            context: "An exact match to a catalogued malware sample.", answer: "bad", why: "A hash match is strong evidence: this exact file is known malware. Contain the host." },
          { id: "fresh", time: "08:40", severity: "Medium", rule: "Q4_bonus_plan.exe", entity: "WKS-HR02",
            fields: [{ k: "SHA256", v: "8dbff4b2…3fe5dc7b" }, { k: "result", v: "No match found" }, { k: "signed", v: "No" }, { k: "arrived", v: "Email attachment, 20 minutes ago" }],
            context: "Nobody in the world has catalogued this exact file.", answer: "unknown", why: "'Not found' only means this exact byte sequence is new. A fresh or recompiled payload always looks like this: sandbox it and check behaviour." },
          { id: "nsrl", time: "09:05", severity: "Low", rule: "notepad.exe", entity: "WKS-OPS11",
            fields: [{ k: "path", v: "C:\\Windows\\System32\\notepad.exe" }, { k: "result", v: "NSRL: known Microsoft file" }, { k: "signed", v: "Microsoft Windows" }],
            context: "In the NIST reference set of known legitimate software.", answer: "good", why: "A known-good hash in the right place: filter it out and spend your time on the files nobody has vouched for." },
          { id: "renamed", time: "09:31", severity: "High", rule: "chrome_update.exe", entity: "WKS-MKT07",
            fields: [{ k: "SHA256", v: "0996898c…a6163aff" }, { k: "result", v: "Match: 44 of 71 engines" }, { k: "family", v: "AsyncRAT" }, { k: "path", v: "AppData\\Roaming\\chrome_update.exe" }],
            context: "A browser-sounding name, but the bytes match a remote-access trojan.", answer: "bad", why: "The name is irrelevant: the bytes match AsyncRAT. Contain." },
        ],
      },
    ],
    // ── Reading 7: symmetric, asymmetric, TLS ──
    "enc-r7": [
      {
        kind: "sort",
        title: "One Key or Two?",
        prompt: "Symmetric encryption shares one key; asymmetric uses a public and a private key. Sort each item.",
        buckets: [
          { id: "sym", label: "Symmetric" },
          { id: "asym", label: "Asymmetric" },
        ],
        items: [
          { id: "aes", text: "AES-256 encrypting a database backup", bucket: "sym", why: "One shared key, fast enough for bulk data." },
          { id: "rsa", text: "RSA key pair on a web server's certificate", bucket: "asym", why: "Public key shared, private key kept." },
          { id: "ecc", text: "ECDHE agreeing a session key between strangers", bucket: "asym", why: "Elliptic-curve maths solves key exchange." },
          { id: "chacha", text: "ChaCha20 encrypting traffic on a phone", bucket: "sym", why: "A fast symmetric stream cipher." },
          { id: "ssh", text: "An SSH public key in authorized_keys", bucket: "asym", why: "The public half of a keypair." },
          { id: "bulk", text: "Every request and response after the TLS handshake", bucket: "sym", why: "Bulk data always moves on the fast symmetric key." },
        ],
      },
      {
        kind: "sequence",
        title: "Build a TLS Session",
        prompt: "A browser meets a server for the first time. Put the steps in order.",
        items: [
          { id: "sym", text: "All page data flows encrypted with the shared symmetric key", note: "Fast AES or ChaCha20 for the bulk." },
          { id: "hello", text: "Client Hello: the browser lists its ciphers and names the site (SNI)", note: "Sent before encryption, so the SNI is readable." },
          { id: "cert", text: "The server sends its certificate and public key", note: "Proof of identity, signed by a trusted authority." },
          { id: "kx", text: "Both sides agree a fresh session key with asymmetric key exchange", note: "The key itself never crosses the wire." },
          { id: "verify", text: "The browser checks the certificate's name, dates and issuer", note: "A failed check is the 'not private' warning." },
        ],
        order: ["hello", "cert", "verify", "kx", "sym"],
        doneNote: "Asymmetric to agree a key between strangers, symmetric for the speed. That hybrid is TLS.",
      },
    ],
    // ── Reading 8: what's visible inside TLS ──
    "enc-r8": [
      {
        kind: "pcap",
        title: "The Beacon You Can't Decrypt",
        prompt: "A workstation keeps talking to a domain nobody recognises, over TLS. You cannot decrypt it. Find out how much the metadata alone tells you.",
        capture: "WKS-OPS22_tls.pcapng",
        packets: [
          { no: 1, time: "0.000000", src: "10.60.2.44", dst: "198.51.100.140", proto: "TLSv1.3", len: 583, info: "Client Hello (SNI=sync.cdn-update.example)",
            tree: ["Transport Layer Security", "    Handshake Protocol: Client Hello", "        Extension: server_name name=sync.cdn-update.example", "        JA3: 72a589da586844d7f0818ce684948eea"] },
          { no: 2, time: "0.041220", src: "198.51.100.140", dst: "10.60.2.44", proto: "TLSv1.3", len: 1388, info: "Server Hello, Change Cipher Spec, Application Data",
            tree: ["Transport Layer Security", "    Handshake Protocol: Server Hello", "    (certificate is encrypted in TLS 1.3)"] },
          { no: 3, time: "0.083551", src: "10.60.2.44", dst: "198.51.100.140", proto: "TLSv1.3", len: 517, info: "Application Data",
            tree: ["Transport Layer Security", "    Application Data Protocol: Hypertext Transfer Protocol", "        Encrypted Application Data (len=488)"] },
          { no: 4, time: "12.402113", src: "10.60.2.44", dst: "52.96.165.18", proto: "TLSv1.3", len: 571, info: "Client Hello (SNI=outlook.office365.com)",
            tree: ["Transport Layer Security", "    Handshake Protocol: Client Hello", "        Extension: server_name name=outlook.office365.com", "        JA3: cd08e31494f9531f560d64c695473da9"] },
          { no: 5, time: "60.001084", src: "10.60.2.44", dst: "198.51.100.140", proto: "TLSv1.3", len: 583, info: "Client Hello (SNI=sync.cdn-update.example)",
            tree: ["Transport Layer Security", "    Handshake Protocol: Client Hello", "        Extension: server_name name=sync.cdn-update.example", "        JA3: 72a589da586844d7f0818ce684948eea"] },
          { no: 6, time: "60.084390", src: "10.60.2.44", dst: "198.51.100.140", proto: "TLSv1.3", len: 517, info: "Application Data",
            tree: ["Transport Layer Security", "    Application Data Protocol: Hypertext Transfer Protocol", "        Encrypted Application Data (len=488)"] },
          { no: 7, time: "120.000932", src: "10.60.2.44", dst: "198.51.100.140", proto: "TLSv1.3", len: 583, info: "Client Hello (SNI=sync.cdn-update.example)",
            tree: ["Transport Layer Security", "    Handshake Protocol: Client Hello", "        Extension: server_name name=sync.cdn-update.example", "        JA3: 72a589da586844d7f0818ce684948eea"] },
          { no: 8, time: "120.083117", src: "10.60.2.44", dst: "198.51.100.140", proto: "TLSv1.3", len: 517, info: "Application Data",
            tree: ["Transport Layer Security", "    Application Data Protocol: Hypertext Transfer Protocol", "        Encrypted Application Data (len=488)"] },
        ],
        objectives: [
          { id: "sni", task: "Which hostname does the workstation keep connecting to?", hint: "tls", answer: ["sync.cdn-update.example"], why: "The SNI travels in the clear in the Client Hello. Any network sensor logs it without decrypting anything." },
          { id: "every", task: "How many seconds apart do those connections start?", hint: "ip.addr==198.51.100.140", answer: ["60", "60s", "60 seconds"], why: "0, 60, 120: clockwork. Humans do not browse on a 60-second timer; implants check in exactly like this." },
          { id: "size", task: "Each check-in sends the same Application Data length. How many bytes (the Length column)?", hint: "Filter on the beacon's IP and compare the Application Data rows.", answer: ["517"], why: "Identical sizes every time: the same small 'anything for me?' message. Timing plus size is the beacon signature." },
          { id: "path", task: "Can you read the HTTP path the workstation requested? (yes or no)", hint: "Open an Application Data packet and read its tree.", answer: ["no"], why: "The payload, path, headers and cookies are encrypted. You did not need them: SNI, JA3, timing and size already make the case." },
        ],
      },
    ],
  },
};
