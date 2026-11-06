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
    intro: { title: "Three Words", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-intro-667a3aac.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-intro-5c2991f7.jpg" },
    afterStation: {
      decode: { title: "Not a Secret", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch2-c117a535.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch2-dd9c5473.jpg" },
      press: { title: "One Byte, New Hash", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch3-cb9a3d2e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-ch3-1b2188bb.jpg" },
      tunnel: { title: "Read It Without Breaking It", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-finale-68c58e1b.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/encoding-encryption-hashing/cipher-room-finale-b6cba0fb.jpg" },
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
    "enc-q1": { name: "Tomas Reyes", role: "Senior Analyst", line: "Our detection rule looks for the word 'DownloadString'. It still missed this one. Why?" },
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
          { id: "pwd", text: "A password is stored as a bcrypt hash with its own salt", bucket: "hash", why: "Stored so it can be checked, never read back. bcrypt is a deliberately slow password hash." },
          { id: "tls", text: "A customer's web session is protected with TLS", bucket: "cry", why: "Only the two ends hold the session key." },
          { id: "enc", text: "Malware launches powershell -enc followed by a long blob", bucket: "enc", why: "Hidden from naive text rules, not from you: one decode reveals it." },
        ],
      },
    ],
    // ── Reading 2: Base64, hex, URL, PowerShell ──
    "enc-r2": [
      {
        kind: "codebreak",
        title: "Decode the Token",
        prompt: "Four strings pulled from this week's alerts at Arclight. None of them is secret, only dressed up. Decode each one in your head and type the single word it hides.",
        tries: 6,
        rounds: [
          { id: "b64", clue: "Base64 in a proxy log field: bmV0c3RhdA==  Decode it. Which command does it spell?", answer: "NETSTAT", why: "Base64 is a format, not a lock: bmV0 is 'net', c3Rh is 'sta', dA== is 't'. The == padding at the end is the giveaway. Attackers use it so keyword rules looking for plain command names miss it." },
          { id: "hex", clue: "Hex in an EDR command line: 636572747574696c  Two hex digits make one byte. Which signed Windows tool does it name?", answer: "CERTUTIL", why: "63 is c, 65 is e, 72 is r, 74 is t and so on. Only 0-9 and a-f appear, always in pairs. certutil is a legitimate Windows tool that attackers use to fetch files, so hiding its name defeats a naive text rule." },
          { id: "url", clue: "URL encoding in a web request: %75%6e%69%6f%6e  Each %XX is one character. Which SQL keyword is it?", answer: "UNION", why: "%75 is u, %6e is n, %69 is i, %6f is o. Percent-encoding exists so odd characters survive in a URL, and attackers use it to split a keyword from a signature. Decode before you judge a query string." },
          { id: "ps", clue: "A PowerShell -EncodedCommand blob: aABvAHMAdABuAGEAbQBlAA==  It is Base64 of UTF-16LE, so every letter is followed by a 00 byte. Which command is it?", answer: "HOSTNAME", why: "Plain Base64 decoding gives h.o.s.t.n.a.m.e with a null between every letter. PowerShell reads UTF-16LE, so you must decode as UTF-16LE to get one clean word. That pattern of letters and AA in the blob is the PowerShell fingerprint." },
        ],
        lesson: "Encoding hides nothing from someone who recognises it. Spot the alphabet first (Base64 mixed case and =, hex only 0-9 and a-f, URL with %), then decode, and remember PowerShell blobs are UTF-16LE.",
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
        kind: "spotdiff",
        title: "Which Hash Moved?",
        prompt: "Tomas keeps a SHA-256 manifest for each night's backup. The suspect copy was pulled from the offsite share this morning. Find the lines that mean the data or the manifest itself changed, and ignore what a hash does not care about.",
        goodTitle: "manifest.sha256 (written at the source)",
        suspectTitle: "manifest.sha256 (offsite copy)",
        good: [
          "# Arclight nightly backup 2026-11-04 · written 02:00",
          "7bee5b700b44f00aa6887723538af17d5bc08814b4885efd97d1b2c4e0afe380  payments_batch.csv",
          "f962cf8e9eabbb97d07caf47c3dd92256ef322c6dfa76a9996c645de035a3089  ArclightAgent-7.2.msi",
          "1044dec7206e8d7c9fbb4ae8f766668406d2567fc7fc1a160a9d4700fcf8f8e9  claims_archive.img",
          "b8b0a64e79e47f3dac1362c1d72092fa63a7b10795facb8deb27ccffebba885c  renewals_2027.xlsx",
          "a62bb5b855a74c9a16069d1a005a51caffca584c57bcd9004a216d06077dee4e  policy_docs.zip",
          "ca949ca547cac321d06693f91109ad1fd893e5e4c4ad1eaf71bc453a3d385b89  mailbox_export.pst",
          "# files: 6",
          "# algorithm: sha256 (64 hex characters per line)",
          "# check with: sha256sum -c manifest.sha256",
        ],
        suspect: [
          "# Arclight nightly backup 2026-11-04 · written 02:01",
          "8a42b91b2f3f50fa220c305946eed51d3a5e730dec21b17479e066907963edcb  payments_batch.csv",
          "f962cf8e9eabbb97d07caf47c3dd92256ef322c6dfa76a9996c645de035a3089  ArclightAgent-7.2.msi",
          "1044dec7206e8d7c9fbb4ae8f766668406d2567fc7fc1a160a9d4700fcf8f8e8  claims_archive.img",
          "b8b0a64e79e47f3dac1362c1d72092fa63a7b10795facb8deb27ccffebba885c  renewals_2027.xlsx",
          "a62bb5b855a74c9a16069d1a005a51caffca584c57bcd9004a216d06077dee4e  policy_docs_final.zip",
          "ca949ca547cac321d06693f91109ad1fd893e5e4c4ad1eaf71bc453a3d385b89  mailbox_export.pst",
          "# files: 6",
          "# algorithm: md5 (32 hex characters per line)",
          "# check with: sha256sum -c manifest.sha256",
        ],
        diffs: [
          { line: 1, why: "payments_batch.csv has a completely different hash. A hash only says identical or not identical: this data is not what the manifest was written for, even if the file looks normal. The avalanche effect means a tiny edit gives an unrelated value." },
          { line: 3, why: "The last character is 9 in the source and 8 here. Looking nearly the same is the trap: one character of difference means a different file, because a hash has no sense of closeness. The whole 64 characters must match." },
          { line: 8, why: "The header now claims md5 with 32 hex characters, yet every line is still 64 characters long. A manifest that downgrades the algorithm is a tamper signal: MD5 is broken for collisions, and the label no longer matches the lines." },
        ],
        decoys: [
          { line: 0, why: "A one-minute difference in the written time is a comment. It is not covered by any file hash, so it changes nothing about the data." },
          { line: 5, why: "The hash is identical and only the file name differs. A hash is of the bytes, not the name, so the same bytes under a new name still verify. A rename is worth a question, but it is not a data change." },
        ],
        lesson: "A hash answers only identical or different, never close. Check every character, check that the algorithm and length agree, and remember that a name or a comment lives outside the hash.",
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
        kind: "defuse",
        title: "Pick the Primitive",
        prompt: "Tomas has four jobs on his board this morning, each needing a different tool from the bench. Encoding, encryption or hashing: cut the one that does the job and not just looks like it.",
        device: "Cipher bench · morning queue",
        seconds: 90,
        rounds: [
          {
            id: "mirror",
            state: "IT downloaded the new agent installer from a mirror. The mirror's page shows a SHA-256 beside the download link, and your copy hashes to exactly that value.",
            wires: [
              { id: "trust", label: "Install it: your copy matches the hash on the same page" },
              { id: "channel", label: "Compare against the hash in the vendor's own signed release notes" },
              { id: "again", label: "Download it again from the same mirror and hash that" },
            ],
            cut: "channel",
            hint: "Who controls the page that publishes the hash?",
            why: "Anyone who can swap the installer on a mirror can also swap the hash next to it, so a match on the same page proves nothing. Compare against a hash obtained through a separate trusted channel such as the vendor's signed release notes.",
          },
          {
            id: "passwords",
            state: "The new customer portal needs to store passwords so a login can be checked. The developer proposes AES with a key in the app's config file.",
            wires: [
              { id: "aes", label: "Keep AES: the key is in the config, so it is secure" },
              { id: "salted", label: "A slow, salted one-way hash for each user" },
              { id: "b64", label: "Base64 each password so it is not readable" },
            ],
            cut: "salted",
            hint: "Does the system ever need to read the password back?",
            why: "A login only needs to check a password, never recover it, so a one-way salted hash fits. It must also be slow on purpose: plain SHA-256 is built for speed, so a stolen table of salted SHA-256 values can still be guessed at billions of tries per second on GPUs. Password hashes such as bcrypt, scrypt, Argon2 or PBKDF2 are deliberately costly to compute. With AES the key sits next to the data and every password falls together, and Base64 is not protection at all.",
          },
          {
            id: "fresh",
            state: "A hash lookup on Q4_bonus_plan.exe, 20 minutes old and unsigned, returns: no match in any database. The user says it was a normal attachment.",
            wires: [
              { id: "clean", label: "Close it: nothing in the database means it is clean" },
              { id: "sandbox", label: "Detonate it and watch behaviour; the hash is new, not safe" },
              { id: "allow", label: "Add its hash to the allow-list so the alert stops" },
            ],
            cut: "sandbox",
            hint: "A hash only knows files the world has already seen.",
            why: "No match only means this exact byte sequence is new, and a recompiled payload always looks like this. Behaviour is the next evidence. Allow-listing a hash nobody has vouched for gives an attacker a free pass.",
          },
          {
            id: "tape",
            state: "A backup tape of claim files leaves the building weekly for offsite storage. If it is lost, it must be unreadable. Arclight must still be able to restore it.",
            wires: [
              { id: "hash", label: "SHA-256 every file and store the hashes on the tape" },
              { id: "samekey", label: "AES-encrypt it and put the key on the tape" },
              { id: "vault", label: "AES-encrypt it and keep the key in a vault off the tape" },
            ],
            cut: "vault",
            hint: "You must get the data back, and a thief must not.",
            why: "Hashing is one-way so nothing could ever be restored. Encryption is right, but a key stored on the tape hands the thief the lock and the key together. Keeping the key elsewhere is what makes the encryption mean anything.",
          },
        ],
        lesson: "Pick by the job: encoding changes format for anyone, encryption hides data from everyone without the key and the key must live apart, and hashing proves identity but can never give data back.",
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
          { key: "SHA256", value: "4f7d2a9c1be86035d9a4c7e2f1b08d63a5c9e7f4b2d1086a3c5e9f7b4d2a1c80", label: "The fingerprint", note: "The identity you take to threat intelligence. Use SHA256: MD5 and SHA1 are here for older tools." },
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
          { id: "kx", text: "Both sides agree a fresh session key with asymmetric key exchange", note: "The key itself never crosses the wire. (In TLS 1.3 the key shares actually ride inside the Hello messages and the certificate is encrypted; the order here is the logical one.)" },
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
