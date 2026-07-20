/**
 * Learning Rooms — Batch 20
 *
 * Closes two of the platform's largest genuine foundational gaps, found by
 * measurement rather than guesswork:
 *
 * - encoding-encryption-hashing — 8 sections across the platform touch
 *   crypto, and every one of them is Intermediate/Advanced and about an
 *   *application* (TLS inspection, Kerberos encryption types). Nothing ever
 *   teaches the underlying distinction between "reversible with no key"
 *   (encoding), "reversible only with a key" (encryption), and "not
 *   reversible at all" (hashing) — which is the single most common
 *   beginner confusion, and the thing "base64 is encrypted" and "hashed
 *   passwords are encrypted passwords" both get wrong.
 *
 * - timestamps-and-timelines — zero dedicated sections across 296 reading
 *   sections in 71 rooms, despite timestamp confusion (UTC vs local,
 *   epoch seconds vs milliseconds, clock skew) being a real, practical
 *   trap that has caused actual timeline errors in this platform's own
 *   content. Teaches the formats, the discipline of stating a timezone,
 *   and the skill of building a timeline that's ordered by when things
 *   really happened, not by which alert fired first.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// ROOM 1: encoding-encryption-hashing
// =============================================================================

const suspiciousAttachmentEvent: TelemetryEvent = {
  id: "evt-hash-la1-001",
  ts: "2026-05-14T16:32:09.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "file_create",
  severity: "medium",
  hostname: "WKS-SAL07.meridian.local",
  description:
    "Microsoft Defender for Endpoint recorded a new executable written to disk in a user's Downloads folder shortly after the user reported an unexpected email attachment; the file was written by the user's browser process, not by an email client directly.",
  raw: {
    Timestamp: "2026-05-14T16:32:09.000Z",
    DeviceName: "WKS-SAL07",
    ActionType: "FileCreated",
    FileName: "Q3_Invoice_Adjustment.exe",
    FolderPath: "C:\\Users\\p.oduya\\Downloads\\Q3_Invoice_Adjustment.exe",
    SHA256: "e1a4c7f92b3d5e8a1c6f0b4d7e2a9c5f8b1d4e7a0c3f6b9d2e5a8c1f4b7d0e3a",
    SHA1: "3f9a1c7e5b2d8f4a6c0e9b3d7f1a5c8e2b4d6f90",
    MD5: "9d4f2a7c1e6b8d3f5a0c9e2b7d4f1a6c",
    FileSize: 812544,
    InitiatingProcessAccountName: "p.oduya",
    InitiatingProcessFileName: "chrome.exe",
    InitiatingProcessCommandLine: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
    ReportId: 48213,
  },
};

const encodedScheduledTaskEvent: TelemetryEvent = {
  id: "evt-enc-ac1-001",
  ts: "2026-04-14T02:10:00.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "process_create",
  severity: "low",
  hostname: "WKS-IT03.meridian.local",
  process: {
    name: "powershell.exe",
    pid: 4412,
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_name: "svchost.exe",
    parent_pid: 1108,
    cmdline:
      "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAKQA=",
    user: "MERIDIAN\\svc_maint",
    integrity: "medium",
  },
  description:
    "A detection rule that flags any -EncodedCommand or -enc usage fired for this scheduled PowerShell run on WKS-IT03, launched by the Task Scheduler service at 02:10 local time.",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-51820 confirms this scheduled task deploys Meridian IT's monthly disk-cleanup and temp-file purge script to workstations via SCCM; the script is Base64-encoded to survive quoting of its embedded multi-line logic, per IT's standard packaging process.",
  raw: {
    "winlog.event_id": 1,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "winlog.event_data.CommandLine":
      "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAKQA=",
    "winlog.event_data.ParentImage": "C:\\Windows\\System32\\svchost.exe",
    "winlog.event_data.ParentCommandLine": "svchost.exe -k netsvcs -p -s Schedule",
    "winlog.event_data.IntegrityLevel": "Medium",
    "winlog.event_data.User": "MERIDIAN\\svc_maint",
    "winlog.event_data.CurrentDirectory": "C:\\Windows\\System32\\",
  },
};

const encodingRoom: Room = {
  id: "encoding-encryption-hashing",
  title: "Encoding, Encryption & Hashing — What They Actually Are",
  description:
    "The three operations analysts confuse constantly, taught from first principles: encoding (reversible by anyone, no key — just a transport format), encryption (reversible only with the right key), and hashing (not reversible at all, ever). Goes deep on what a hash IS mechanically, why it's one-way, the properties that make it useful, and the four things a SOC analyst actually uses it for — plus the two misconceptions that trip up almost every junior analyst at least once: 'Base64 is encrypted' and 'hashed passwords are encrypted passwords.'",
  difficulty: "beginner",
  category: "Foundations",
  estimatedMinutes: 60,
  xp: 270,
  icon: "🔐",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    {
      type: "reading",
      id: "enc-r1",
      heading: "Three Different Jobs, Constantly Confused",
      content:
        `You will see all three of these words in almost every shift — "the payload was Base64-encoded," "the traffic was encrypted," "we matched on the file hash" — and if you can't instantly tell which of three completely different operations each sentence describes, you will misjudge how serious a finding is. That's the entire point of this room: not memorizing definitions, but being able to look at any of the three and know exactly what an attacker (or a legitimate program) can and can't do with it.\n\n` +
        `**The one-sentence version of each**\n\n` +
        `Encoding changes how data is *represented* so it can travel safely through a system that only accepts certain characters — a mail server, a URL, a command line. It uses a public, published rule that anyone can run in reverse. There is no secret involved. Encryption changes data so that only someone holding a specific secret (a key) can read it back — this is the one actually designed to keep information away from someone. Hashing takes data of any size and produces a short, fixed-length fingerprint of it — and critically, there is no way to run that process backwards, not even with a key, because the process itself throws information away on purpose.\n\n` +
        `**Why this order matters**\n\n` +
        `Notice the pattern: encoding is reversible by anyone, encryption is reversible only by someone with the key, and hashing is not reversible by anyone, ever, under any circumstance. That single axis — reversible without a key / reversible with a key / not reversible at all — is worth remembering better than any definition, because it's what determines what each one is actually *for*. Encoding solves a formatting problem. Encryption solves a confidentiality problem. Hashing solves an identity and integrity problem: proving something is exactly what it claims to be, without needing to protect it as a secret at all.\n\n` +
        `**A preview of the trap this room exists to close**\n\n` +
        `An attacker running "powershell -enc <blob>" is not hiding anything from a determined analyst — that blob decodes in one click, with no key, no password, no cracking involved. It defeats a specific, narrower kind of defense: a detection rule that just looks for suspicious *text* in a command line. Meanwhile, a company that says user passwords are "encrypted in our database" is very often wrong in a way that matters — they are almost always hashed, and the difference changes what a breach actually exposes. Both of those sentences will make complete sense to you by the end of this room, and the diagram below is the picture to hold onto while you read the rest of it: two of these operations have a return arrow, and one is a dead end by design.`,
      diagram:
        "flowchart LR\n" +
        "  subgraph ENC[\"Encoding (Base64 / hex / URL) -- reversible, no key\"]\n" +
        "    A1[Plaintext] -->|encode| A2[Encoded text]\n" +
        "    A2 -->|decode| A1\n" +
        "  end\n" +
        "  subgraph CRY[\"Encryption (AES / RSA) -- reversible, needs a key\"]\n" +
        "    B1[Plaintext] -->|encrypt with key| B2[Ciphertext]\n" +
        "    B2 -->|decrypt with key| B1\n" +
        "  end\n" +
        "  subgraph HSH[\"Hashing (SHA-256) -- one-way, no key\"]\n" +
        "    C1[Any-length input] -->|hash| C2[Fixed-length digest]\n" +
        "    C2 --> C3[No function reverses this -- dead end]\n" +
        "  end",
      diagramCaption: "Three operations -- only two of them come back",
    },
    {
      type: "reading",
      id: "enc-r2",
      heading: "Encoding: Base64, Hex, and URL-Encoding — Not Security",
      content:
        `Encoding exists to solve one narrow problem: some system in the path only accepts a limited set of characters, but you need to send it data (binary bytes, a password with punctuation, a script full of quotes) that doesn't fit that limit. Encoding maps your data onto a safe character set using a fixed, public rule. It never tries to hide anything, and reversing it requires nothing but the same public rule everyone already knows.\n\n` +
        `**Base64** takes raw bytes and represents them using only 64 printable characters: A-Z, a-z, 0-9, plus + and /, with = used for padding at the end when the input length isn't a clean multiple of 3 bytes. You can recognize it on sight: that specific character set, and a total length that's always a multiple of 4. It's everywhere — email attachments, API tokens, data embedded in URLs or JSON, and command-line arguments that need to survive a shell's quoting rules intact.\n\n` +
        `**Hex encoding** represents each byte as two characters from 0-9 and a-f (e.g. a byte value of 255 becomes "ff"). You'll meet it constantly in hashes (a SHA-256 hash is 64 hex characters), MAC addresses, and IPv6 addresses. **URL encoding** (percent-encoding) replaces characters a URL can't safely carry — a space becomes %20, an ampersand inside a parameter becomes %26 — so a browser or web server doesn't misread part of your data as part of the URL's own structure.\n\n` +
        `**Why attackers actually use it — and it isn't to defeat cryptography**\n\n` +
        `You will see "powershell.exe -EncodedCommand <base64 blob>" (often shortened to -enc) constantly in this platform's scenarios. PowerShell's -EncodedCommand flag exists as a legitimate feature: it lets a script with awkward characters — quotes, pipes, newlines — travel safely as a single command-line argument without the shell mangling it. Attackers reuse that legitimate feature for two real, practical reasons. First, it survives being passed through layers of shells and schedulers that would otherwise break a script full of quotes and special characters. Second — and this is the one that matters to you as an analyst — it defeats naive, plaintext string-matching detection rules. A rule looking for the literal text "DownloadString" or a known malicious domain name will never match, because those strings only exist in decoded form; encoded, they're an unrecognizable jumble of A-Z/a-z/0-9/+/=. The blob is not hidden from you as an analyst — you can decode it in one click — it's hidden from a rule that never gets the chance to look at the decoded version at all.\n\n` +
        `**One PowerShell-specific detail worth memorizing**\n\n` +
        `PowerShell's -EncodedCommand specifically expects UTF-16LE (Unicode, 2 bytes per character, least-significant byte first) text, Base64-encoded — not plain ASCII. That's why, if you ever decode one by hand a byte at a time, you'll see what looks like a null byte after every readable character: the letter "I" (0x49) is followed by a 0x00 byte, then "E" (0x45), then another 0x00, and so on. That pattern is completely normal for this specific encoding and is not, itself, a sign of anything unusual — it's simply what UTF-16LE text looks like once you're looking at the raw bytes instead of a rendered string.`,
      codeExample:
        "RECOGNIZING BASE64 ON SIGHT\n" +
        "=======================================================\n" +
        "Character set: A-Z a-z 0-9 + /       (= for padding, at the end only)\n" +
        "Length:        always a multiple of 4\n" +
        "\n" +
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n" +
        "-- starts \"SQBFAFgA...\" -- this exact opening is worth recognizing:\n" +
        "   it decodes (as UTF-16LE) to \"IEX (\" -- PowerShell's Invoke-Expression\n" +
        "\n" +
        "WHY -enc DEFEATS A NAIVE STRING-MATCH RULE\n" +
        "=======================================================\n" +
        "Rule looks for:      \"DownloadString\" in the command line\n" +
        "Plaintext command:    ...Net.WebClient).DownloadString(...)   <- MATCHES\n" +
        "Encoded command:       powershell -enc RABvAHcAbgBsAG8AYQBkAFMA...\n" +
        "                                        ^ the literal text \"DownloadString\"\n" +
        "                                          never appears anywhere -- NO MATCH\n" +
        "=======================================================\n" +
        "No key. No password. No cracking. Decode it and you see everything --\n" +
        "the rule just never got the chance to look at the decoded version.",
    },
    {
      type: "flag",
      id: "enc-f1",
      prompt:
        "Decode this Base64 string by hand or with any decoder (CyberChef, an online tool, or a terminal command) and enter the exact plaintext it produces, including punctuation: SGVsbG8sIFNPQyE=",
      answer: "Hello, SOC!",
      hint: "Remember from Reading 2: no key, no password — just run the same public rule in reverse. A quick web search for 'base64 decode' plus pasting the string will do it in seconds.",
      xp: 20,
    },
    {
      type: "question",
      id: "enc-q1",
      question:
        "A proxy rule blocks any request whose body contains the plaintext string 'DownloadString'. An attacker's PowerShell command uses -EncodedCommand and the payload still runs, even though the analyst can plainly see the literal text '-EncodedCommand' sitting right there in the process log. Why does encoding defeat this particular rule even though the flag itself isn't hidden at all?",
      options: [
        "The rule matched literal substrings inside the payload, like DownloadString — encoded, those characters never appear in the command line at all, even though -EncodedCommand itself stays fully visible",
        "The -EncodedCommand flag switches PowerShell into a special logging-exempt mode, so Windows never records anything about the command that actually ran",
        "Encoding here actually functions as encryption, scrambling the payload with a secret key only the attacker possesses, which is why no tool can read it",
        "Any command using -EncodedCommand automatically executes with SYSTEM-level privileges, which bypasses Windows' logging and detection pipeline entirely",
      ],
      answer: 0,
      explanation:
        "This is the exact mechanism from Reading 2: encoding is a public, reversible transformation with no key, so it can't 'hide' anything from a human analyst who bothers to decode it — but it completely defeats a naive rule that only ever inspects the raw, still-encoded text. Windows logs the full command line (including the encoded blob) just fine, encoding involves no key or encryption at all, and -EncodedCommand carries no inherent privilege escalation whatsoever.",
      xp: 20,
    },
    {
      type: "analyst_choice",
      id: "enc-ac1",
      heading: "Verdict: A Scheduled Task Running Encoded PowerShell at 2 AM",
      scenario:
        "A detection rule that flags any powershell.exe invocation using -EncodedCommand or -enc fired for this scheduled task run on WKS-IT03. Reading 2 taught that Base64-encoded PowerShell is a favorite technique for defeating naive string-matching detection, so the rule treats every match as worth a look by default. Review the process event and the attached change ticket before deciding what this is.",
      event: encodedScheduledTaskEvent,
      correct_verdict: "false_positive",
      explanation:
        "Encoding a script is also simply how legitimate deployment tooling safely passes a multi-line, quote-heavy script through a single command-line argument — SCCM packages, scheduled maintenance jobs, and DSC configurations do this routinely, exactly as Reading 2 described. Here the parent process (svchost.exe running the Task Scheduler service), the account (a maintenance service account), the fixed 2 AM schedule, and a confirmed change ticket (CHG-51820) all line up with a documented monthly cleanup job, not an attacker. The encoding itself is not the finding — it never is, on its own.",
      fp_trap:
        "It's tempting to treat any -EncodedCommand invocation as automatically malicious, because Reading 2 taught it as a common evasion technique. But encoding a script is also just how you safely pass a multi-line or quote-heavy script through a command line — plenty of legitimate deployment tooling does this constantly. The signal that actually matters is context: is this parent process, this account, and this timing expected on this host, and does a change ticket account for it? Escalating on the mere presence of the flag, without checking any of that, burns analyst time on findings that belong in a 'known, expected, tune the rule' bucket instead.",
      xp: 30,
    },
    {
      type: "reading",
      id: "enc-r3",
      heading: "Hashing, Part 1: What It Is, and Why It's One-Way",
      content:
        `A hash function takes an input of *any* length — a single character, a password, a 4 GB disk image — and produces an output of one *fixed* length, called a hash, a digest, or (informally) a fingerprint. SHA-256, the algorithm you'll see constantly, always produces exactly 256 bits of output, rendered as 64 hexadecimal characters, no matter whether you fed it one byte or the entire contents of a hard drive. The same input, run through the same algorithm, always produces exactly the same output, every single time, on any computer, forever — that determinism is what makes a hash useful as an identity at all.\n\n` +
        `**Why there is no "unhash" function, even in principle**\n\n` +
        `This is the part that's genuinely different from encryption, and worth sitting with. Encryption is reversible because it doesn't discard any information — encrypt something, and every bit of the original is still recoverable, just scrambled, provided you have the key. Hashing is fundamentally different: compressing an effectively unlimited range of possible inputs down into a fixed, comparatively tiny output (256 bits can represent about 1.15 x 10^77 distinct values — an enormous number, but still nowhere near as large as "every possible file that could ever exist") necessarily throws information away. Multiple different inputs could, in principle, map to the same output. There is no mathematical operation that takes a 256-bit digest and reconstructs the original data, because the digest simply does not contain enough information to do so — not "we haven't found the trick yet," but "the information required to reverse it was destroyed the moment the hash was computed." The only way to find an input that produces a given hash is to guess an input, hash it, and see if it matches — over and over, as many times as it takes. That's what "cracking" a hash actually means: not decryption, but brute-force guessing checked against the one-way function.\n\n` +
        `**What "SHA-256 is broken" would even mean**\n\n` +
        `You'll hear that MD5 and SHA-1 (older, shorter hash algorithms) are "broken," while SHA-256 is not. This doesn't mean anyone learned to reverse them — the one-way property still holds for both. It means researchers found ways to deliberately construct two *different* inputs that produce the *same* hash (called a collision) far faster than blind guessing should allow, which undermines the "this hash uniquely identifies this exact data" guarantee an analyst relies on. SHA-256 has no practical collision attack known today, which is exactly why it's the default recommendation for anything security-relevant, and why still seeing MD5 or SHA-1 relied upon for integrity in 2026 is itself worth a second look.\n\n` +
        `**Fixed length is a feature, not a limitation**\n\n` +
        `Because every SHA-256 output is exactly 64 hex characters regardless of the input's size, a database of a hundred million known file hashes takes a small, predictable, indexable amount of storage — nowhere near the cost of storing a hundred million actual files. That property alone is what makes hash-based threat intelligence, malware repositories, and forensic file catalogs operationally possible at scale. The next reading builds directly on this: the properties that make hashing frustrating to reverse are the exact same properties that make it useful.`,
    },
    {
      type: "reading",
      id: "enc-r4",
      heading: "Hashing, Part 2: The Properties That Make It Useful",
      content:
        `Every practical use of hashing in a SOC traces back to four properties. Learn them as consequences, not trivia — each one directly explains something you'll rely on during an investigation.\n\n` +
        `**Deterministic → a hash is a usable file identity.** The same file, hashed a thousand times on a thousand different machines, produces the exact same output every time. This is what lets an analyst say "this file matches a known-malicious sample" with total confidence based on a 64-character string alone, with no need to ever compare the files byte-by-byte directly.\n\n` +
        `**The avalanche effect → similarity in, chaos out.** Change even a single bit anywhere in the input, and on average roughly half of the output bits flip, in a way that looks completely unrelated to the original output. Take the two text strings "invoice.pdf" and "Invoice.pdf" — they differ by exactly one bit (the case of the first letter). Hash each one, and the two SHA-256 digests share no visible pattern whatsoever; you could not guess one from the other no matter how you studied them. This is precisely why a hash can only ever tell you "identical" or "not identical" — it can never tell you "close." Recompile a piece of malware with one line changed, and its hash is a completely different, unrelated string, useless for matching the old sample.\n\n` +
        `**Collision resistance → why algorithm choice matters.** A "collision" is two different inputs producing the same hash. Every hash function has collisions in theory (a fixed-size output can't represent infinite unique inputs), but a *good* hash function makes finding one computationally infeasible. MD5 and SHA-1 no longer meet that bar — practical collision techniques exist for both — which is why threat intel built on MD5/SHA-1 alone deserves a more skeptical read than the same intel built on SHA-256.\n\n` +
        `**Fixed length → cheap to store, cheap to search.** Whether you're identifying a 4 KB script or a 40 GB forensic disk image, the hash representing it is the same 64 hex characters. That's what makes it practical to hold, index, and search across millions of hashes in a threat intelligence feed or an internal file catalog — you're never storing or comparing the actual files themselves, just their fingerprints.\n\n` +
        `The diagram below is worth studying carefully: two inputs that a human would call "basically the same" produce two outputs that share nothing recognizable at all. That gap between input similarity and output similarity is the avalanche effect, and it's the property behind both of hashing's superpowers (exact-match identity) and its sharpest limitation (no notion of "close enough"), which the next reading covers in full.`,
      diagram:
        "flowchart TB\n" +
        "  A[\"invoice.pdf\"] --> B[\"SHA-256\"] --> C[\"Digest A\"]\n" +
        "  D[\"Invoice.pdf (one letter's case flipped)\"] --> E[\"SHA-256\"] --> F[\"Digest B\"]\n" +
        "  C -.-> G{{\"No visible similarity between Digest A and Digest B at all\"}}\n" +
        "  F -.-> G",
      diagramCaption: "One-bit input change, completely unrelated output (the avalanche effect)",
    },
    {
      type: "question",
      id: "enc-q2",
      question:
        "You hash the text string 'invoice.pdf' and separately hash 'Invoice.pdf' — the two inputs differ by exactly one bit (the case of a single letter). What does the fact that the resulting SHA-256 outputs share no visible pattern tell you about hashing's ability to detect 'similar but not identical' inputs?",
      options: [
        "Nothing similar shows in the output — the avalanche effect means a single-bit change flips roughly half the output bits, so hash comparison only ever answers 'identical' or 'different,' never 'close' enough for fuzzy matching",
        "It proves SHA-256 itself is broken, since two nearly identical inputs should logically produce nearly identical outputs if the algorithm were functioning correctly",
        "It means the two strings were accidentally hashed using two different algorithms, which is why their outputs look completely unrelated to each other",
        "It means the hash function hit an internal error and failed to fully process one of the two input strings correctly",
      ],
      answer: 0,
      explanation:
        "The avalanche effect is the hash function working exactly as designed, not a flaw — a small input change producing a completely unrelated output is the entire point, since it's what prevents an attacker from nudging a malicious file's bytes slightly to slip past a hash-based block while still doing the same damage. Nothing here indicates a mismatched algorithm or a processing error; both digests are valid, correctly-computed SHA-256 outputs that simply look unrelated by design.",
      xp: 20,
    },
    {
      type: "reading",
      id: "enc-r5",
      heading: "The Four Things a SOC Analyst Actually Uses Hashing For",
      content:
        `Everything in the last two readings exists to support four concrete jobs you'll do with hashes on a real shift.\n\n` +
        `**1. File identity and IOC (Indicator of Compromise) matching.** Instead of sending an entire suspicious file to a threat intelligence service — slow, bandwidth-heavy, and a privacy or confidentiality problem if the file contains sensitive company data — you send its hash. The hash travels; the file itself never has to leave your network. If that exact 64-character string is already known and catalogued as malicious somewhere in the world, you get a match back instantly, with nothing about your file's actual contents ever exposed to a third party.\n\n` +
        `**2. Integrity verification.** When you download a large file, the vendor often publishes its expected hash alongside it — you hash your downloaded copy and compare; a mismatch means the file was corrupted or tampered with in transit. Forensics uses this same idea at a higher stakes level: when an investigator acquires a disk image, they hash it immediately (the acquisition hash). Every time that evidence is later accessed or presented, it gets re-hashed and compared to the original. If the two ever disagree, the integrity of the evidence itself is now in question — this is exactly why "chain of custody" in digital forensics leans so heavily on hashing.\n\n` +
        `**3. Password storage — and why salting exists.** A well-built system never stores your actual password; it stores a hash of it. When you log in, the server hashes what you typed and compares that to the stored hash — if they match, you're in, and the server still never had to keep your actual password anywhere. This means a stolen password database does not hand an attacker your plaintext passwords directly; they'd have to crack each hash by guessing. But there's a catch: if two users independently pick the identical password, and the server just hashes the plain password with nothing else, both users end up with the identical stored hash — visibly revealing that they share a password, and letting an attacker who cracks one password get both for free, or worse, use pre-computed "rainbow tables" (huge pre-built lookup tables mapping common passwords to their hashes) to crack enormous numbers of accounts almost instantly. The fix is a salt: a random, unique value generated per user and combined with the password before hashing. Now two identical passwords produce two completely different stored hashes (the avalanche effect from Reading 4 in action), and pre-computed rainbow tables become useless, because the attacker would need a separate table for every possible salt.\n\n` +
        `**4. Deduplication and known-good filtering.** Investigators routinely deal with enormous volumes of files on a compromised host. Reference sets like NIST's NSRL (National Software Reference Library) catalog the hashes of millions of known, legitimate operating-system and application files. Hash every file on the disk, filter out everything matching the known-good set, and you can spend your limited time looking at the much smaller pile of files nobody has already vouched for — instead of manually eyeballing every DLL Windows ships with by default.`,
      diagram:
        "sequenceDiagram\n" +
        "  participant U as User\n" +
        "  participant S as Server\n" +
        "  U->>S: Register with password \"Sunshine1!\"\n" +
        "  S->>S: Generate a fresh, random salt unique to this user\n" +
        "  S->>S: Compute hash(password + salt)\n" +
        "  S->>S: Store [salt, hash] -- the plaintext password is discarded, never stored\n" +
        "  Note over S: A second user who also picks \"Sunshine1!\" gets a different salt,<br/>so a completely different stored hash\n" +
        "  U->>S: Later: log in with \"Sunshine1!\"\n" +
        "  S->>S: Recompute hash(entered password + stored salt)\n" +
        "  S-->>U: New hash matches stored hash -> access granted",
      diagramCaption: "Password storage with salting -- the plaintext never touches the database",
    },
    {
      type: "ordering",
      id: "enc-o1",
      heading: "Order the Steps of Salted Password Storage",
      instructions: "Arrange the steps in the order a well-built server actually performs them, from a new user's registration through their next login.",
      items: [
        { id: "step-submit", text: "User chooses a password and submits it at signup" },
        { id: "step-salt", text: "The server generates a fresh, random salt unique to this user" },
        { id: "step-combine", text: "The server combines the password and the salt" },
        { id: "step-hash", text: "The server runs that combination through the hash function" },
        { id: "step-store", text: "The server stores the resulting hash together with the salt — the plaintext password is discarded and never stored" },
        { id: "step-login", text: "At the next login, the server repeats the salt-combine-hash steps using the stored salt and compares the new hash to the one on file" },
      ],
      correct_order: ["step-submit", "step-salt", "step-combine", "step-hash", "step-store", "step-login"],
      explanation:
        "This is the full flow from Reading 5: the salt is generated once, at registration, and stored alongside the hash (a salt isn't a secret — it just has to be unique per user); every later login recomputes the hash the same way and compares, so the server never needs to keep the actual password anywhere at all, before or after registration.",
      xp: 35,
    },
    {
      type: "log_analysis",
      id: "enc-la1",
      heading: "Checking a Hash Against Threat Intelligence",
      context:
        "A user reported an unexpected email attachment that turned out to have been opened; shortly afterward, EDR recorded a new executable written to disk by the user's browser. Before deciding how urgent this is, you want to check the file's SHA256 against threat intelligence.",
      event: suspiciousAttachmentEvent,
      questions: [
        {
          question:
            "You submit this file's SHA256 (e1a4c7f9...d0e3a) to threat intelligence via the platform's Check Hash feature and get back 'No match found.' Given what Reading 3 taught about how a hash identifies data, what should you conclude?",
          options: [
            "'No match' is not proof of safety — it only means this exact byte sequence has never been catalogued as malicious before, which is exactly what you'd expect from a freshly compiled or slightly modified payload with no reputation history yet; further behavioral analysis is still warranted",
            "'No match' definitively proves the file is benign, since malicious files are always known to threat intelligence databases before they're used in an attack",
            "The hash lookup itself must have failed technically, since a hash of a genuinely new file should still return a match against something",
            "This means the file was hashed with the wrong algorithm, since a properly hashed file always has prior threat intelligence coverage",
          ],
          answer: 0,
          explanation:
            "This is the limit from Reading 3's determinism property working against the defender: a hash identifies one exact byte sequence, and any attacker who recompiles or even slightly modifies a payload gets a brand-new hash with zero history anywhere. 'Not found' simply means nobody has seen and catalogued this exact file before — it says nothing about behavior, and it is one of the most common junior-analyst mistakes to read it as a clean bill of health.",
          xp: 25,
        },
        {
          question:
            "This file's SHA256 is a full 64 hex characters, the same length it would be whether the file were 4 KB or 400 MB. Why does this fixed-length property matter operationally for a SOC storing and searching millions of file hashes in a threat intel feed?",
          options: [
            "It makes storage and lookups cheap and predictable at scale — a database of a hundred million hashes takes a small, fixed, indexable amount of space, nowhere close to what storing a hundred million actual files would cost",
            "It means larger files are always considered more suspicious than smaller ones, since their hash represents more compressed data",
            "It has no operational relevance at all — hash length is purely a cosmetic detail of the algorithm's output format",
            "It means the hash reveals the original file's exact size, since the digest length scales with the input",
          ],
          answer: 0,
          explanation:
            "Reading 3 covers this directly: fixed output length is exactly what makes hash-based threat intel and file catalogs practical at scale — you're storing and searching a predictable 64-character string, never the file itself. The digest length never changes regardless of input size, so it reveals nothing at all about how large the original file was, and file size has no bearing on how 'suspicious' a hash is.",
          xp: 25,
        },
        {
          question:
            "A colleague says: 'I renamed this file from Q3_Invoice_Adjustment.exe to update.exe in the EDR console, and the SHA256 stayed exactly the same — so the hash must not actually factor in the filename at all.' Are they reasoning correctly, and what does this tell you about what a hash actually identifies?",
          options: [
            "They're reasoning correctly — a hash is computed purely from a file's byte content, never its filename, path, or other metadata; that's precisely why renaming a malicious file is a useless evasion technique against hash-based detection, and also why hash-based matching is powerful regardless of how many times a sample gets renamed across different victims",
            "They're wrong — filenames are always included as part of what gets hashed, so a rename should have produced a completely different hash",
            "The hash only stayed the same because EDR consoles cache old hash values and don't recompute them after a rename",
            "This can only be explained by a hash collision, which is extremely unlikely to happen by coincidence on a rename",
          ],
          answer: 0,
          explanation:
            "The colleague is right, and this is a genuinely useful thing to know: a cryptographic hash is a function of the file's actual bytes, full stop — no filename, timestamp, or path is ever part of the input. That's exactly why hash-based IOC matching still works when the same malware sample gets renamed differently on every victim machine, and it's not a caching artifact or a coincidental collision — it's the hash function correctly doing the one thing it's defined to do.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "enc-r6",
      heading: "The Critical Limits of a Hash",
      content:
        `Everything that makes hashing powerful also defines exactly where it stops being useful, and the juniors who get burned are almost always the ones who forgot one of these three limits.\n\n` +
        `**A hash identifies one exact byte sequence — nothing more.** Recompile the same malware with a single line changed, flip one byte in a config string, even just change the compiler's build timestamp embedded in the binary, and the hash is a completely different, unrelated string, as Reading 4's avalanche effect guarantees. This is exactly why file hashing sits at the very bottom of the Pyramid of Pain, a widely-used model ranking indicator types by how much it costs an attacker to change them: hashes are trivial and free for an attacker to invalidate (one recompile), while indicators further up the pyramid — TTPs, tools, network infrastructure — cost the attacker real time and money to change. A hash match is real evidence when you get one, but its absence tells you almost nothing, and pinning a detection strategy entirely on hash matching is pinning it on the cheapest thing for an attacker to defeat.\n\n` +
        `**'Not found in threat intelligence' is not the same as 'safe.'** Log Analysis 1 walked through this directly: a freshly compiled payload, used for the first time against your organization, has by definition never been seen or catalogued anywhere before. A clean hash lookup on a brand-new sample is the expected, unremarkable result of a targeted or simply new attack — not evidence of anything benign.\n\n` +
        `**A hash tells you nothing about behavior.** It cannot tell you what a file does when it runs, what it connects to, or what it modifies. It answers exactly one question — "is this the identical byte sequence as something I already know about?" — and nothing else. Sandboxing, static analysis, and behavioral EDR telemetry exist precisely because that one question, however useful, is never the whole picture.\n\n` +
        `**Tying this back to the platform directly**\n\n` +
        `The Check Hash button you've used in this platform's scenarios submits exactly the SHA256 you now understand in full: a deterministic, fixed-length, one-way fingerprint of a file's exact byte content, checked against a catalog of previously-seen samples. You now know precisely what that means when it comes back clean — not "this file is safe," but "this exact file has not been catalogued before," which for a targeted or freshly-built attack is exactly the answer you should expect to get.`,
    },
    {
      type: "matching",
      id: "enc-m1",
      heading: "Match the Question to the Right Operation — and Kill the Two Big Misconceptions",
      instructions: "Match each question or claim to the operation (encoding, encryption, or hashing) it correctly describes.",
      pairs: [
        { id: "reversible-no-key", left: "Is it reversible without any secret key at all?", right: "Encoding — yes, anyone can reverse it with the same public rule; it was never designed to hide anything" },
        { id: "reversible-with-key", left: "Is it reversible only by someone holding the correct secret?", right: "Encryption — yes, that is the entire point of a key; without it the ciphertext is not practically recoverable" },
        { id: "reversible-never", left: "Is it reversible at all, even by someone with a key?", right: "Hashing — no, there is no key and no reverse function; the only way 'back' is guessing an input and hashing it again to check" },
        { id: "fixed-length", left: "Does the output length stay the same no matter how large the input is?", right: "Hashing — always a fixed length (SHA-256 is always 256 bits / 64 hex characters), which is exactly why it's cheap to store and search at scale" },
        { id: "myth-base64", left: "'This PowerShell command is Base64 — it must be encrypted, so I can't read it without a password'", right: "False — Base64 is encoding, not encryption; anyone can decode it instantly with no key, password, or cracking involved" },
        { id: "myth-hashed-password", left: "'The database stores hashed passwords, so the passwords are encrypted'", right: "False — hashing is one-way with no key and no decrypt function; 'hashed' and 'encrypted' are two different, non-interchangeable operations with different guarantees" },
      ],
      explanation:
        "The first four pairings are the core distinction from Reading 1 applied directly: reversibility without a key, reversibility with a key, and no reversibility at all, plus the fixed-length property unique to hashing. The last two are the exact misconceptions this room exists to close — 'encoded' and 'encrypted' get used interchangeably in casual speech, but they describe operations with completely different security guarantees, and confusing them leads to both overestimating how hidden an encoded payload is and underestimating what a stolen hash database actually exposes.",
      xp: 40,
    },
    {
      type: "reading",
      id: "enc-r7",
      heading: "Encryption: Reversible — But Only With a Key",
      content:
        `Encryption is the one operation of the three actually designed to keep information confidential. It transforms plaintext into ciphertext using an algorithm and a key, such that recovering the plaintext requires that same key (or, for one entire category of encryption, a mathematically related one). There are two fundamentally different approaches, and almost every secure system you'll investigate uses both together, for a very practical reason.\n\n` +
        `**Symmetric encryption — one shared key, fast.** Both parties use the exact same secret key to encrypt and decrypt. AES (Advanced Encryption Standard) is the algorithm you'll see everywhere — it's fast enough to encrypt large volumes of data in real time, which is exactly what you want once a connection is actually flowing data. Its weakness is pure logistics: both sides need the identical key before they can talk securely, and if that key ever has to travel over the same untrusted network the parties are trying to protect, you've undermined the whole scheme before it started.\n\n` +
        `**Asymmetric encryption — a keypair, slower, but solves key distribution.** Instead of one shared secret, each party has a mathematically linked keypair: a public key, freely shared with anyone, and a private key, kept secret and never transmitted. Data encrypted with the public key can only be decrypted with the matching private key. RSA and ECC (Elliptic Curve Cryptography) are the algorithms you'll see. This elegantly solves the key-distribution problem — the public key doesn't need to be protected at all — but the underlying math is computationally far more expensive, making it impractical for encrypting large volumes of data continuously.\n\n` +
        `**Why TLS (Transport Layer Security — what makes a connection "https") uses both.** A web browser connecting to a server has never met that server before and has no shared secret with it. So the connection starts with asymmetric encryption purely to solve one problem: safely agreeing on a brand-new, temporary symmetric key without ever sending that key in the clear. Once both sides hold that shared symmetric key, the connection switches entirely to fast symmetric encryption (AES) for the actual data — every page load, every request, every response. This hybrid design gets the best of both: asymmetric encryption's ability to establish trust between strangers, and symmetric encryption's speed for the bulk of the traffic that follows.`,
      diagram:
        "sequenceDiagram\n" +
        "  participant C as Client (browser)\n" +
        "  participant Srv as Server\n" +
        "  C->>Srv: ClientHello\n" +
        "  Srv-->>C: ServerHello + certificate (contains server's public key)\n" +
        "  Note over C,Srv: Asymmetric encryption (RSA/ECC) used ONLY to safely agree on a shared secret\n" +
        "  C->>Srv: Shared secret, encrypted with the server's public key\n" +
        "  Note over C,Srv: Both sides now derive the same symmetric session key\n" +
        "  C->>Srv: Application data, encrypted with the fast symmetric key (AES)\n" +
        "  Srv-->>C: Application data, encrypted with the same symmetric key",
      diagramCaption: "Why TLS uses both: asymmetric to agree a key, symmetric for the actual data",
    },
    {
      type: "reading",
      id: "enc-r8",
      heading: "What an Analyst Can — and Can't — See Inside TLS Without Decrypting It",
      content:
        `A common beginner assumption is that encrypted traffic is a total black box to an analyst unless it's decrypted first (via TLS inspection, an intercepting proxy that most enterprises deploy specifically to regain that visibility). That's not actually true, and knowing exactly what's still visible without decryption is what makes an entire category of detection — beacon and command-and-control detection — possible at all.\n\n` +
        `**What is visible in plaintext, even inside an encrypted connection:**\n\n` +
        `The SNI (Server Name Indication) field, sent as part of the TLS handshake before encryption is established, tells the server which hostname the client is trying to reach — and it travels unencrypted, in the clear, so any network monitoring tool can log exactly which domain a client connected to, encrypted session or not. The server's certificate, presented during the handshake, is also unencrypted and includes the domain(s) it's valid for, its issuer, and its validity dates. A JA3 (client-side) or JA3S (server-side) fingerprint — a hash of specific characteristics of how a TLS client or server negotiates the handshake (which cipher suites it offers, in what order, and other parameters) — can flag when a particular piece of malware's TLS library behaves distinctly differently from a normal browser, even without reading a single byte of the actual conversation. And regardless of encryption, an analyst can always observe connection metadata: timing (how often does this host talk to this destination, and how regularly), and byte volumes (small, near-identical request and response sizes repeating at fixed intervals is a classic beacon signature — a compromised host "checking in" with its command-and-control server on a schedule).\n\n` +
        `**What genuinely stays hidden without decryption:** the actual application data — the HTTP request path and parameters, headers, cookies, the response body, any credentials submitted through the encrypted channel. TLS protects the entire payload, not just part of it; there's no partial-encryption exception for headers versus body.\n\n` +
        `**Why this matters for your day-to-day work:** you do not need to break encryption to build a reasonable initial hypothesis that a host is beaconing to a C2 (command-and-control) server. A workstation making small, byte-identical HTTPS requests to an unfamiliar domain every 60 seconds, with an SNI that doesn't resolve to any business relationship you recognize, and a JA3 fingerprint that doesn't match any known legitimate application on that host, is a strong finding built entirely out of metadata — before any TLS inspection or decryption ever enters the picture.`,
    },
    {
      type: "question",
      id: "enc-q3",
      question:
        "An analyst can't decrypt a workstation's outbound TLS connection to an unfamiliar domain, but still flags it as a likely beacon to a command-and-control server. What could the analyst have legitimately observed without ever breaking the encryption?",
      options: [
        "The plaintext SNI hostname from the handshake, the server's certificate details, a JA3/JA3S fingerprint of the negotiation itself, and the connection's timing and byte-volume pattern — none of which require decrypting the application data",
        "Nothing meaningful at all — TLS is understood to hide every observable detail of a connection completely until it is decrypted by an intercepting proxy somewhere in the path",
        "The full HTTP request path and the entire response body, since TLS is commonly understood to only encrypt request headers, leaving the body itself in the clear",
        "The plaintext password submitted during login, since TLS is understood to only begin protecting data after the authentication step has already completed",
      ],
      answer: 0,
      explanation:
        "This is the exact list from Reading 8: SNI, certificate metadata, JA3/JA3S, and connection timing/byte-volume patterns are all observable without decryption, and together they're enough to build a real beaconing hypothesis. TLS is not a total black box (ruling out the second option), but it also doesn't selectively protect only headers — the entire application payload, including the request path, body, and any submitted credentials, is fully encrypted with no exception.",
      xp: 25,
    },
  ],
};

// =============================================================================
// ROOM 2: timestamps-and-timelines
// =============================================================================

const crowdstrikeSkewEvent: TelemetryEvent = {
  id: "evt-time-la1-001",
  ts: "2026-06-11T22:47:14.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "medium",
  hostname: "WKS-FIN22.meridian.local",
  process: {
    name: "powershell.exe",
    pid: 5544,
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_name: "explorer.exe",
    parent_pid: 2210,
    cmdline: "powershell.exe -Command Get-Process",
    user: "MERIDIAN\\r.desai",
    integrity: "medium",
  },
  description:
    "CrowdStrike recorded this process launch on WKS-FIN22. The SOC alert queue renders it in the on-call analyst's own browser timezone (US/Eastern, EDT in June, UTC-4), while the underlying record itself carries CrowdStrike's own timestamp field, stored in UTC.",
  raw: {
    event_simpleName: "ProcessRollup2",
    ContextTimeStamp: 1781218034.187,
    aid: "8f2c1e6a9b3d4f1084c7e2a1b6d9f3e0",
    ComputerName: "WKS-FIN22",
    UserName: "r.desai",
    FileName: "powershell.exe",
    CommandLine: "powershell.exe -Command Get-Process",
    ParentBaseFileName: "explorer.exe",
    LocalAddressIP4: "10.40.2.18",
  },
};

const offHoursLogonEvent: TelemetryEvent = {
  id: "evt-time-ac1-001",
  ts: "2026-03-10T03:50:00.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_success",
  severity: "low",
  hostname: "WKS-BLR14.meridian.local",
  authentication: { method: "password", result: "success", logon_type: 2 },
  description:
    "A console logon (LogonType 2) was recorded for account s.krishnan on WKS-BLR14, an interactive-only workstation with no remote-access configuration, located at Meridian's Bengaluru office.",
  it_verify_result: "confirmed",
  it_verify_message:
    "Facilities badge log for the Bengaluru office confirms s.krishnan badged into the building at 09:15 local time (IST, UTC+5:30) that morning, consistent with the start of their normal shift.",
  raw: {
    "event.code": "4624",
    "winlog.channel": "Security",
    "winlog.computer_name": "WKS-BLR14",
    "winlog.event_data.TargetUserName": "s.krishnan",
    "winlog.event_data.LogonType": "2",
    "winlog.event_data.AuthenticationPackageName": "Negotiate",
    "winlog.event_data.WorkstationName": "WKS-BLR14",
    "winlog.event_data.IpAddress": "-",
    "winlog.event_id": 4624,
  },
};

const timelineRoom: Room = {
  id: "timestamps-and-timelines",
  title: "Timestamps, Timezones & Building a Timeline",
  description:
    "The formats you'll meet in every investigation — ISO 8601, Unix epoch seconds vs milliseconds, Windows FILETIME, syslog's year-less format — plus the discipline that actually prevents mistakes: why every mature SIEM stores UTC and renders local, why your raw log and your screen can legitimately disagree, why three log sources rarely agree on the exact second something happened, and how to build a timeline that's ordered by when things really happened rather than by which alert you happened to open first.",
  difficulty: "beginner",
  category: "Foundations",
  estimatedMinutes: 50,
  xp: 245,
  icon: "🕒",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    {
      type: "reading",
      id: "time-r1",
      heading: "Timestamp Formats You'll Actually Meet",
      content:
        `Every log line you'll ever open has a timestamp, and it will not always be in the same format. Being able to instantly recognize which format you're looking at — without having to guess — is a basic, constant skill, not a one-time thing to memorize and forget.\n\n` +
        `**ISO 8601** is the format most modern SIEMs display by default: 2026-06-11T22:47:14Z. Reading it left to right: year-month-day, a literal "T" separating the date from the time, then hours:minutes:seconds, and finally a timezone indicator. That trailing "Z" stands for "Zulu time," military shorthand for UTC (Coordinated Universal Time — the global time standard with no offset applied, sometimes still casually called GMT). If you instead see a numeric offset like +05:30 or -04:00 at the end, that's telling you the timestamp is already expressed in a specific local zone relative to UTC, not UTC itself — a genuinely different piece of information than a "Z."\n\n` +
        `**Unix epoch time** counts seconds (or, increasingly, milliseconds) elapsed since January 1, 1970, 00:00:00 UTC — a single, unbroken integer with no separators at all, like 1781218034. You can tell seconds from milliseconds by digit count alone: a current epoch-in-seconds value has 10 digits, while the same instant in milliseconds has 13 (three extra digits for the sub-second precision). Mixing these up is a common, entirely avoidable error — treating a millisecond value as if it were seconds lands you on a date roughly 31,000 years in the future.\n\n` +
        `**Windows FILETIME** is what you'll encounter inside some low-level Windows artifacts and forensic tooling: a 64-bit number counting 100-nanosecond intervals since January 1, 1601 (not 1970), which is why it looks nothing like an epoch value — it's an 17-to-18-digit integer, dramatically larger than any Unix timestamp you'll see for a current date.\n\n` +
        `**Syslog's classic format** — still common on network devices, Linux systems, and older appliances — looks like "Jun 11 22:47:14" and, notably, carries no year at all. That's a real, practical gap: the format simply predates any expectation that a log file would need to be read years after it was written. When you're working from an old archive or a device whose logs were exported without their ingestion metadata, the year has to be inferred from context — the file's own modification date, surrounding log entries with fuller timestamps, or ingestion records — never simply assumed to be "this year."\n\n` +
        `All four of these can describe the exact same instant. The diagram below shows one moment, expressed three different ways, to make that point visually before the next reading covers the single most important habit for working with any of them.`,
      diagram:
        "flowchart TB\n" +
        "  T{{\"The same instant\"}}\n" +
        "  T --> ISO[\"ISO 8601: 2026-06-11T22:47:14Z\"]\n" +
        "  T --> EPOCH[\"Unix epoch (seconds): 1781218034\"]\n" +
        "  T --> SYSLOG[\"Syslog (no year): Jun 11 22:47:14\"]\n" +
        "  ISO -.->|\"Z = UTC, zero offset\"| N1[\"Timezone stated explicitly\"]\n" +
        "  EPOCH -.->|\"seconds since 1970-01-01 UTC\"| N2[\"No timezone field at all -- UTC by convention\"]\n" +
        "  SYSLOG -.->|\"year is not in the line\"| N3[\"Ambiguous without outside context\"]",
      diagramCaption: "One moment, three formats you'll meet in the same investigation",
    },
    {
      type: "reading",
      id: "time-r2",
      heading: "UTC vs Local Time: The Discipline of Stating the Zone",
      content:
        `Every mature SIEM follows the same rule internally: store every timestamp in UTC, and render it in whatever local timezone is convenient for the person looking at the screen. Understanding why, and what that means for you, prevents one of the most common — and most avoidable — analyst mistakes.\n\n` +
        `**Why UTC for storage.** A SOC frequently has analysts, servers, and log sources spread across multiple timezones, sometimes multiple countries. If every system stored its own local time with no fixed reference point, comparing two events from two different sources would require knowing (and correctly applying) each source's local offset, every single time, by hand. Storing everything in UTC — one single, unambiguous reference — removes that problem entirely at the storage layer, and shifts timezone conversion to a display-only concern, done once, correctly, by the tooling.\n\n` +
        `**Why local for display.** A human reading an alert queue at 3 AM their own local time does not want to mentally add or subtract hours from a UTC timestamp every time they glance at the screen. So the console takes the stored UTC value and renders it in whatever timezone the analyst's account (or browser) is configured for — which is a legitimate, deliberate convenience, not a bug.\n\n` +
        `**Why the raw log and the console can legitimately disagree — and why that's not a contradiction.** If you export the raw event and see "2026-06-11T22:47:14Z," but the SIEM's alert queue displays "18:47:14" for that same event, both are correct simultaneously. They describe the exact same instant; one is UTC, the other is that instant rendered in EDT (Eastern Daylight Time, UTC-4 in June). The mistake is treating either number as "the" time without asking which zone it's in — and the discipline that prevents that mistake is simple and worth building as a habit: never write down or repeat a timestamp without also stating (or at least confirming to yourself) its timezone. "The logon happened at 22:47" is an incomplete sentence; "the logon happened at 22:47 UTC" is a fact you can safely hand to someone else, put in a report, or compare against a second source.\n\n` +
        `**Not every device actually follows the UTC-storage rule.** Some older or misconfigured appliances — a branch-office firewall, a legacy application server — log in local time directly, with no UTC conversion happening anywhere in the pipeline. That's exactly why you can't assume every raw timestamp you meet is UTC just because ISO 8601's "Z" convention exists; you have to actually check what a given source is doing, especially before comparing it against a second source that might behave differently.`,
      diagram:
        "flowchart LR\n" +
        "  D[\"Device clock (local timezone)\"] --> L[\"Raw log line\"]\n" +
        "  L --> ING[\"SIEM ingest -- normalizes and stores in UTC\"]\n" +
        "  ING --> CON[\"Analyst's console -- renders in THEIR OWN browser timezone\"]\n" +
        "  CON -.->|\"same stored instant, different displayed text\"| CON2[\"Two analysts in two timezones see two different clock times for the identical event\"]",
      diagramCaption: "Why the raw log and your screen can legitimately disagree",
    },
    {
      type: "question",
      id: "time-q1",
      question:
        "A log field holds the value 1746500000000 — a plain integer with no separators. Using the digit-count heuristic from Reading 1, what unit is this most likely expressed in, and roughly how would you convert it toward a human-readable date?",
      options: [
        "Milliseconds — the value has 13 digits, the expected length for a current-era epoch timestamp in milliseconds; dividing by 1,000 converts it to the familiar 10-digit epoch-in-seconds form first",
        "Seconds — any all-digit timestamp with more than 8 characters should always be read directly as epoch seconds, with no further conversion needed",
        "This must be a Windows FILETIME value, since FILETIME is also a large plain integer with no separators between any of its digits",
        "There's no way to tell the unit from digit count alone — the number of digits never carries any information about whether a value is seconds or milliseconds",
      ],
      answer: 0,
      explanation:
        "13 digits is exactly the seconds-vs-milliseconds tell from Reading 1: current-era epoch-in-seconds values run 10 digits, and milliseconds adds three more for sub-second precision. This value is too short to be FILETIME, which for a current date runs 17-18 digits (counting 100-nanosecond intervals since 1601, not 1970) — a much larger number than either flavor of Unix epoch time.",
      xp: 20,
    },
    {
      type: "flag",
      id: "time-f1",
      prompt:
        "A raw event field shows event_time: 1770000000000. Using the digit-count rule from Reading 1, is this Unix epoch time in seconds or milliseconds? Answer with one word.",
      answer: "milliseconds",
      hint: "Count the digits before deciding. A current epoch-in-seconds value has 10 digits.",
      xp: 20,
    },
    {
      type: "reading",
      id: "time-r3",
      heading: "Clock Skew, NTP, and Why Your Three Sources Disagree",
      content:
        `Even once every timestamp is correctly converted to UTC, you'll still routinely find that a firewall, a Domain Controller, and an EDR agent each report a slightly different time for what should be the same real-world moment. That's not a format problem — it's clock skew, and it's normal, expected, and needs to be actively accounted for rather than assumed away.\n\n` +
        `**What clock skew actually is.** Every computer keeps its own internal clock, running off its own hardware — and left alone, hardware clocks drift, some faster and some slower, by anywhere from a few seconds to several minutes over time. A firewall appliance that's been running for months without a sync might be three minutes fast; an EDR agent on a laptop that was recently offline might be two minutes slow. Neither device is malfunctioning in any dramatic sense — this is just what unmanaged clocks do.\n\n` +
        `**NTP (Network Time Protocol)** is the standard fix: devices periodically check in with a trusted time server and adjust their own clock to match, keeping drift down to a fraction of a second under normal conditions. A well-run environment has NTP properly configured and monitored on every device that produces security-relevant logs, precisely because timeline accuracy depends on it. When you're investigating and something's clock looks off by more than a trivial amount, checking that device's NTP sync status is a genuinely useful diagnostic step — it tells you whether you're looking at a real timing anomaly or just an unsynced clock.\n\n` +
        `**Why "A happened before B" needs real care across sources.** If a Domain Controller logs a logon at 13:58:47 UTC and a firewall — three minutes fast — logs an outbound connection from that same host at 14:02:10 by its own clock, the connection did not actually happen 3 minutes and 23 seconds after the logon; once you correct for the firewall's known 3-minute skew, it's closer to 23 seconds after. Ordering events strictly by their raw, uncorrected timestamps across multiple sources, without ever checking each source's clock health, is exactly how an analyst gets a sequence of events backward — sometimes badly enough to draw the wrong conclusion about what caused what.`,
      diagram:
        "flowchart TB\n" +
        "  subgraph BEFORE[\"Before normalization -- each source's own uncorrected clock\"]\n" +
        "    FW1[\"Firewall: 14:02:10 (clock running ~3 min fast)\"]\n" +
        "    DC1[\"Domain Controller: 13:58:47 (accurately synced)\"]\n" +
        "    EDR1[\"EDR agent: 13:57:02 (clock running ~2 min slow)\"]\n" +
        "  end\n" +
        "  subgraph AFTER[\"After normalizing to UTC and correcting for known skew\"]\n" +
        "    DC2[\"13:58:47 UTC -- logon\"]\n" +
        "    EDR2[\"13:59:02 UTC -- process launch\"]\n" +
        "    FW2[\"13:59:10 UTC -- outbound connection\"]\n" +
        "  end\n" +
        "  BEFORE -.->|\"check NTP sync status, correct for skew\"| AFTER",
      diagramCaption: "Same three events -- wrong order until clock skew is accounted for",
    },
    {
      type: "reading",
      id: "time-r4",
      heading: "Building a Timeline: Normalize, Order, and Don't Trust Detection Order",
      content:
        `Building an accurate timeline is a distinct skill from reading any one log correctly, and it's worth treating as a checklist rather than something you do by feel.\n\n` +
        `**Normalize everything to one timezone first — before you order anything.** Pull every relevant event from every relevant source, and convert every single timestamp to the same zone (UTC is the house standard for exactly the reasons in Reading 2) before you try to sequence them. Trying to eyeball the order of events that are still expressed in a mix of local times and UTC is how avoidable mistakes happen.\n\n` +
        `**Order by when things happened, not by when you looked at them.** An alert queue shows you alerts in the order they fired or the order you opened them — that is not the same as the order the underlying events actually occurred. A single intrusion might generate a phishing-click alert, a process-execution alert, and a data-exfiltration alert that all land in your queue within the same few minutes, in an order that has nothing to do with which stage of the attack happened first; detection latency differs by tool, by log source, and by how each alerting pipeline is built. The timeline you build should always be sorted by each event's own normalized timestamp, never by arrival order in your tools.\n\n` +
        `**Dwell time is the number a SOC actually gets judged on.** Dwell time is the gap between when an attacker first gained access (or performed the first malicious action) and when that activity was first detected. A fast, well-instrumented environment might have a dwell time measured in hours; a poorly monitored one can run for months. Building an accurate timeline is what lets you state this number honestly instead of guessing — and it's frequently a very different number from "how long did it take us to contain the incident once we noticed it," which measures response speed rather than detection speed.\n\n` +
        `**Detected order is not the same as happened order — say that sentence to yourself often.** It's tempting, especially under time pressure, to assume the first alert you saw represents the first thing that happened. Reading 3 already showed you why raw timestamps across sources can be misleading without skew correction; this reading adds the second half of the same lesson — even correctly normalized timestamps get sorted wrong if you default to "queue order" instead of actually checking each event's own time.`,
      diagram:
        "flowchart LR\n" +
        "  A[\"First compromise (initial access)\"] -->|\"dwell time -- the gap a SOC is judged on\"| B[\"First detection (alert fires)\"]\n" +
        "  B -->|\"response time\"| C[\"Containment\"]",
      diagramCaption: "Dwell time: the gap between compromise and detection",
    },
    {
      type: "question",
      id: "time-q2",
      question:
        "During an investigation, three alerts land in your queue in this order: (1) a data-exfiltration alert from DLP, (2) a phishing-click alert from the email gateway, (3) a suspicious-process alert from EDR. After normalizing all three underlying events to UTC, the process execution actually occurred first, the phishing click second, and the exfiltration third. What does this discrepancy illustrate, and what should you do with it?",
      options: [
        "Detection order isn't the same as when events actually happened — different tools have different detection latency, so the investigation timeline and any dwell-time figure should be built from each event's own normalized timestamp, not queue arrival order",
        "This means one of the three tools has an incorrect system clock and urgently needs to be resynced with NTP before any of its alerts can be trusted at all",
        "The queue arrival order should be treated as authoritative, since alerts come from the SOC's own trusted tooling and should outweigh raw event timestamps",
        "This discrepancy is only possible if one of the events came from a compromised or tampered log source, since normalized timestamps should always match arrival order exactly",
        "The three tools must be misconfigured to use three different logging severity levels, since same-severity alerts should always arrive in the exact order their triggering events occurred",
      ],
      answer: 0,
      explanation:
        "This is exactly the point of Reading 4: alert arrival order reflects each tool's own detection pipeline and latency, not the true sequence of events, which is why the timeline has to be built from normalized timestamps rather than queue order. It doesn't imply a clock problem on its own (detection latency alone fully explains it), the queue order is not more authoritative than the underlying timestamps, mismatched order between detection and occurrence is completely normal rather than a sign of log tampering, and logging levels have no bearing on alert arrival order at all.",
      xp: 20,
    },
    {
      type: "log_analysis",
      id: "time-la1",
      heading: "Same Instant, Two Displayed Times",
      context:
        "WKS-FIN22 is a workstation used by r.desai in Meridian's finance team. The SOC's alert queue renders every timestamp in the on-call analyst's own browser timezone — currently US/Eastern (EDT, UTC-4 in June). Review the raw CrowdStrike Falcon record below, which carries the vendor's own ContextTimeStamp field.",
      event: crowdstrikeSkewEvent,
      questions: [
        {
          question:
            "ContextTimeStamp shows 1781218034.187. Before doing any timezone conversion at all, what does the fact that its whole-number part has 10 digits tell you about its unit?",
          options: [
            "It's Unix epoch time in seconds — a 10-digit whole-number part is the expected length for a current-era epoch-in-seconds value; a millisecond epoch value for the same instant would carry roughly 13 digits before the decimal point",
            "It's Unix epoch time in milliseconds, since CrowdStrike always logs with sub-second precision regardless of digit count",
            "It must be a Windows FILETIME value, since the presence of a decimal point is a FILETIME-specific feature",
            "The digit count carries no information here — you would always need to consult CrowdStrike's own documentation before assuming anything",
          ],
          answer: 0,
          explanation:
            "10 digits before the decimal point is the seconds-epoch signature from Reading 1; the fractional part after the decimal is just sub-second precision, not evidence of a millisecond epoch (which would show as three extra whole-number digits, not a decimal). FILETIME is a much larger integer entirely (17-18 digits, counting from 1601), not a shorter decimal value — and while checking documentation is good practice generally, the digit-count heuristic is specifically useful because it works even when you don't have docs in front of you.",
          xp: 25,
        },
        {
          question:
            "The SIEM console displays this alert's time as 18:47:14. A teammate insists it actually happened at 22:47:14, since that's the UTC-based ContextTimeStamp value in the raw record. Who is right, and what should you actually do before adding this event to a multi-source incident timeline?",
          options: [
            "Both numbers describe the exact same instant — 18:47:14 is simply the console's local (EDT, UTC-4) rendering of the same moment the raw record stores as 22:47:14 UTC; before building a timeline, every event from every source should be normalized to one shared timezone (UTC) rather than compared using whatever each console happens to display",
            "The teammate is wrong, and the raw ContextTimeStamp field should be disregarded in favor of whatever the SIEM console renders",
            "The console is malfunctioning and should be reported as a bug, since a properly built SIEM should only ever display UTC to any analyst",
            "This is a four-hour clock skew between the EDR agent and the SIEM platform, and the agent's system clock needs to be resynced via NTP",
          ],
          answer: 0,
          explanation:
            "This is Reading 2's central point: the raw UTC value and the console's local rendering describe the identical instant, and the fix isn't picking one over the other — it's normalizing every source to one shared zone before comparing or ordering anything. Disregarding the raw field would mean losing the one unambiguous source of truth; rendering local time is a deliberate console convenience, not a bug; and this scenario is a timezone conversion, not clock skew (skew is an actual disagreement in what time two clocks currently read, which this is not).",
          xp: 25,
        },
        {
          question:
            "A firewall log entry, expressed entirely in the same local zone (EDT, no conversion needed), shows an outbound connection from 10.40.2.18 at 19:02:00 that same day. Relative to the PowerShell launch in this event, did that outbound connection happen before or after?",
          options: [
            "After — the PowerShell launch normalizes to 18:47:14 EDT, and 19:02:00 EDT is roughly 15 minutes later, so the outbound connection follows the process launch and is worth investigating as a possible next step in the same sequence",
            "Before — since 19:02 uses fewer leading digits when read as a raw string, it should be treated as occurring earlier",
            "There's no way to compare the two, since they were produced by two completely different systems (EDR and firewall)",
            "They're effectively simultaneous, since both times round to roughly 7 PM local",
          ],
          answer: 0,
          explanation:
            "Once the PowerShell launch is correctly normalized to 18:47:14 EDT, comparing it against the firewall's already-local 19:02:00 is a straightforward ~15-minute gap, with the outbound connection coming after — exactly the kind of causal ordering a timeline is built to support. Comparing timestamps as raw text strings is not a valid method; different source systems absolutely can be compared once both are expressed in the same zone (that's the entire purpose of normalization); and 15 minutes is a meaningful gap for sequencing an investigation, not close enough to call simultaneous.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "time-r5",
      heading: "Practical Traps: DST, No-Year Logs, Duplicate Events, and Timestomping",
      content:
        `A few specific situations account for most of the timeline mistakes analysts actually make in practice, beyond the basic format and skew issues already covered.\n\n` +
        `**Daylight Saving Time (DST) transitions.** Twice a year, in regions that observe it, local clocks either skip an hour forward or repeat an hour going backward. A timeline built in local time that happens to span a DST transition night can end up with an event that appears to occur "before" an earlier one, or an hour that seems to repeat entirely — pure artifacts of the local clock changing mid-investigation, not anything happening in the environment. Building the timeline in UTC from the start sidesteps this completely, since UTC never observes DST at all.\n\n` +
        `**Logs with no year.** As Reading 1 covered, classic syslog format doesn't include a year. Working from an old archive or export, it's tempting to just assume "this year" — which silently produces a wrong date on anything older, and can shift an entire timeline by exactly 365 days without any obvious error message. Always corroborate the year from something external to the log line itself: file metadata, ingestion timestamps, or a neighboring log entry that does carry a full date.\n\n` +
        `**The same event logged twice by two different systems.** A single logon might legitimately appear once in a Domain Controller's Security log and once in a VPN concentrator's own log, because both systems genuinely observed and independently recorded the same real-world action. Failing to recognize this can inflate a timeline into "two separate login events," when it's actually one event seen from two vantage points — worth cross-referencing (hostname, user, source IP, and a matching normalized time) before assuming duplication means something happened twice.\n\n` +
        `**Timestomping and log clearing — an attacker deliberately breaking the sequence.** Some attackers actively work to defeat exactly the kind of timeline you're learning to build. Timestomping is modifying a file's own recorded timestamps (creation, modification, access times) to make it look older or blend in with surrounding legitimate files. Clearing the Windows Security event log entirely — which itself generates a very specific and well-known event, ID 1102 — is a blunter version of the same goal: erase the evidence a timeline would otherwise be built from. Neither of these is a reason to give up on the timeline; a 1102 entry, or a suspicious gap in otherwise continuous logging, is itself a meaningful data point and often one of the strongest indicators in the whole investigation that something was deliberately hidden.`,
    },
    {
      type: "matching",
      id: "time-m1",
      heading: "Match Each Timeline Trap to the Correct Handling",
      instructions: "Match each situation to the correct way an analyst should handle it.",
      pairs: [
        { id: "ms-epoch", left: "A field shows a 13-digit integer like 1770000000000", right: "Unix epoch in milliseconds — divide by 1,000 to reach the familiar 10-digit epoch-in-seconds form before converting to a calendar date" },
        { id: "no-year", left: "A syslog line reads 'Jun 11 22:47:14 fw01 ...' with no year visible anywhere", right: "The year isn't in the log line at all — infer it from file metadata, ingestion records, or a neighboring full-date entry, never by assuming 'this year'" },
        { id: "skew-90s", left: "Two agents on two different hosts log what should be the same real-world action 90 seconds apart", right: "Suspect clock skew before suspecting a genuine 90-second gap — check each host's NTP sync status before drawing any conclusion" },
        { id: "clear-1102", left: "Event 1102 (audit log cleared) appears partway through a suspected intrusion timeline", right: "Treat any surrounding gap in the logs as suspicious — clearing logs is a documented way attackers break a timeline, not routine maintenance on its own" },
        { id: "dst-night", left: "An investigation spans the night of a Daylight Saving Time transition", right: "Local clocks jump forward or repeat an hour that night — build and read the timeline in UTC to avoid an hour of genuine ambiguity" },
        { id: "dup-event", left: "The same login appears in both the Domain Controller's Security log and the VPN concentrator's own log", right: "Two systems legitimately observing and recording the same real action — cross-reference user, host, and time before treating it as two separate events" },
      ],
      explanation:
        "Each pairing comes directly from Readings 1, 3, and 5: recognizing an epoch's unit by digit count, treating a missing year as something to corroborate rather than assume, checking NTP status before trusting an apparent gap between sources, reading a cleared audit log as a meaningful signal rather than noise, building in UTC specifically to avoid DST ambiguity, and recognizing genuinely duplicate observations of one real event instead of double-counting them.",
      xp: 40,
    },
    {
      type: "ordering",
      id: "time-o1",
      heading: "Order the Steps for Building a Reliable Multi-Source Timeline",
      instructions: "Arrange these steps in the order an analyst should actually perform them when reconstructing an incident from multiple log sources.",
      items: [
        { id: "step-pull", text: "Pull the raw events from every relevant source — EDR, firewall, Domain Controller, VPN, and any others in scope" },
        { id: "step-ntp", text: "Check the clock-sync (NTP) status of each source system" },
        { id: "step-normalize", text: "Normalize every timestamp to a single shared timezone — UTC is the house standard" },
        { id: "step-sort", text: "Sort all events strictly by their normalized timestamp, not by which alert fired or was reviewed first" },
        { id: "step-gaps", text: "Flag any suspicious gaps in the timeline, especially ones bordering a log-clearing event such as 1102" },
        { id: "step-narrative", text: "Reconstruct the narrative and calculate dwell time between first compromise and first detection" },
      ],
      correct_order: ["step-pull", "step-ntp", "step-normalize", "step-sort", "step-gaps", "step-narrative"],
      explanation:
        "This mirrors Readings 3 and 4 directly: gather everything first, check each source's clock health before trusting its timestamps, normalize to one zone, sort by actual (not detected) time, watch specifically for gaps that might represent deliberate log tampering, and only then build the narrative — which is exactly where an honest dwell-time figure comes from.",
      xp: 35,
    },
    {
      type: "analyst_choice",
      id: "time-ac1",
      heading: "Verdict: A Logon That Looks Like It Happened at 3:50 AM",
      scenario:
        "A detection rule flagging interactive logons outside a 07:00-19:00 local business-hours window fired on this event. Review the raw record and the attached facilities verification below before deciding what this is.",
      event: offHoursLogonEvent,
      correct_verdict: "false_positive",
      explanation:
        "The raw event.code 4624 timestamp of 2026-03-10T03:50:00Z is stored in UTC, per Reading 2's house discipline — it is not the local wall-clock time at the site where the logon happened. WKS-BLR14 is located at Meridian's Bengaluru office, which runs on IST (UTC+5:30, no DST observed). Converting 03:50 UTC to IST gives 09:20 local — squarely inside business hours and consistent with the facilities badge log confirming s.krishnan entered the building at 09:15 local that same morning. The 'off-hours' flag fired because the detection rule's business-hours window was applied to the raw UTC value directly instead of the site's local time.",
      fp_trap:
        "It's tempting to read 03:50 straight off the raw event and treat any pre-dawn timestamp as an automatic red flag for off-hours access. But Reading 2 exists precisely because every mature SIEM stores timestamps in UTC — the raw field's numeric value is not the local wall-clock time at the physical site where the logon occurred. Escalating purely on the number, without first converting to the correct local timezone for where the workstation actually sits, is exactly the mistake this room is built to prevent, and it's a realistic way to generate a false positive on every single Bengaluru employee's normal 9 AM start of shift.",
      xp: 30,
    },
  ],
};

export const roomsBatch20 = [encodingRoom, timelineRoom];
