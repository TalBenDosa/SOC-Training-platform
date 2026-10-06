/**
 * Learning Rooms — Batch 17 (Room 3)
 *
 * "TLS & Encrypted Traffic Analysis" (tls-encrypted-traffic)
 *
 * Advanced deep dive into TLS: handshake mechanics, SNI, certificate chain
 * validation, self-signed and short-lived certs, JA3/JA3S/JARM fingerprinting,
 * detecting C2 inside TLS without decryption, and when interception is and
 * isn't possible.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import { KQL_PRIMER } from "@/data/kqlPrimer";

// ── Log analysis event 1: TLS beacon session (metadata only, no decryption) ─
const tlsBeaconEvent: TelemetryEvent = {
  id: "evt-tls-la1-001",
  ts: "2026-04-02T20:11:03.000Z",
  source: "proxy",
  vendor: "Corelight (Zeek)",
  event_type: "net_connection",
  severity: "high",
  hostname: "WKS-MKT09.solvix.local",
  src_ip: "10.40.8.44",
  dst_ip: "146.70.87.201",
  dst_port: 443,
  protocol: "tcp",
  network: { domain: "cdn-assets-static.net" },
  description:
    "WKS-MKT09 has established 96 short TLS sessions to 146.70.87.201 over the past 96 minutes, each carrying a nearly identical byte count in both directions; the session below is one representative sample",
  raw: {
    "id.orig_h": "10.40.8.44",
    "id.resp_h": "146.70.87.201",
    "id.resp_p": 443,
    "ssl.version": "TLSv12",
    "ssl.cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "ssl.server_name": "cdn-assets-static.net",
    "ssl.ja3": "e7d705a3286e19ea42f587b344ee6865",
    "ssl.ja3s": "7e7558f4374aed341ef2d452af381db7",
    "ssl.issuer": "CN=cdn-assets-static.net",
    "ssl.subject": "CN=cdn-assets-static.net",
    "ssl.validation_status": "self signed certificate",
    duration: 0.891,
    orig_bytes: 216,
    resp_bytes: 198,
  },
};

// ── Log analysis event 2: certificate/JARM investigation of a rare destination
const certInvestigationEvent: TelemetryEvent = {
  id: "evt-tls-la2-001",
  ts: "2026-04-05T09:47:29.000Z",
  source: "ids",
  vendor: "Corelight (Zeek)",
  event_type: "net_connection",
  severity: "medium",
  hostname: "SRV-BUILD04.solvix.local",
  src_ip: "10.40.2.77",
  dst_ip: "185.183.96.14",
  dst_port: 8443,
  protocol: "tcp",
  network: { domain: "ci-artifact-sync.io" },
  description:
    "SRV-BUILD04, a CI/CD build server, connected once to 185.183.96.14 on TCP/8443; this is the first connection ever recorded to this destination from any host on the 10.40.2.0/24 build segment",
  raw: {
    "id.orig_h": "10.40.2.77",
    "id.resp_h": "185.183.96.14",
    "id.resp_p": 8443,
    "ssl.version": "TLSv12",
    "ssl.server_name": "ci-artifact-sync.io",
    "ssl.subject": "CN=ci-artifact-sync.io",
    "ssl.issuer": "CN=ci-artifact-sync.io",
    "ssl.cert_serial": "01",
    "ssl.not_valid_before": "2026-04-04T08:00:00Z",
    "ssl.not_valid_after": "2027-04-04T08:00:00Z",
    "ssl.validation_status": "self signed certificate",
    "ssl.ja3": "72a589da586844d7f0818ce684948eea",
    cert_age_hours_at_connection: 25.8,
    destination_hosts_seen_before_today: 0,
  },
};

const tlsRoom = {
  id: "tls-encrypted-traffic",
  title: "TLS & Encrypted Traffic Analysis",
  description:
    "Learn to investigate encrypted traffic like an analyst who can't (and often shouldn't try to) decrypt it: the TLS handshake step by step, why SNI remains the last cleartext field, how to read a certificate chain and spot self-signed or suspiciously short-lived certs, JA3/JA3S/JARM fingerprinting, and how to detect C2 hiding inside TLS purely from metadata, timing, and certificate anomalies — plus when SSL interception is genuinely possible and when it isn't.",
  difficulty: "advanced" as const,
  category: "Network Security" as const,
  estimatedMinutes: 70,
  xp: 400,
  icon: "🔐",
  prerequisites: ["tcpip-deep-dive"],
  tasks: [
    // ── Reading 1: TLS handshake ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tls-r1",
      heading: "The TLS Handshake, Step by Step (TLS 1.2 vs. TLS 1.3)",
      content:
        `Before any encrypted application data flows, TLS negotiates the encryption itself in the clear (or nearly so) — and that negotiation is exactly what an analyst reads, since it's the one part of an HTTPS conversation not hidden by the encryption it's setting up.\n\n` +
        `**TLS 1.2 handshake, message by message**\n\n` +
        `1. **ClientHello** — the client proposes a TLS version, a list of cipher suites it supports (in preference order), a random value, and extensions — including, critically, the **SNI (Server Name Indication)** extension naming the hostname it's trying to reach.\n` +
        `2. **ServerHello** — the server picks one cipher suite from the client's list and replies with its own random value.\n` +
        `3. **Certificate** — the server sends its certificate chain (its own leaf certificate plus any intermediate certificates needed to build a chain of trust back to a root CA).\n` +
        `4. **ServerKeyExchange / ServerHelloDone** — for cipher suites using ephemeral key exchange (modern Diffie-Hellman variants), the server sends key exchange parameters, then signals it's done with its part of the handshake.\n` +
        `5. **ClientKeyExchange** — the client sends its own key exchange material, from which both sides can independently derive the same shared symmetric session key.\n` +
        `6. **ChangeCipherSpec + Finished (client)**, then **ChangeCipherSpec + Finished (server)** — both sides switch to encrypted communication and exchange a final "Finished" message, encrypted with the just-negotiated key, proving the handshake wasn't tampered with.\n` +
        `7. **Application Data** — the actual HTTP request/response (or any other application protocol) now flows, fully encrypted.\n\n` +
        `**TLS 1.3: fewer round trips, more of the handshake itself encrypted**\n\n` +
        `TLS 1.3 (the modern default) collapses this into a single round trip in the common case (1-RTT): the ClientHello now includes a guessed key share directly, and the server can reply with ServerHello, its certificate, and Finished all at once, with the certificate itself now encrypted (though SNI, in standard TLS 1.3 without the newer ECH extension, is still sent in the clear in the ClientHello — more on this in the next reading). TLS 1.3 also supports **0-RTT** resumption for previously-visited servers, letting the client send encrypted application data in its very first flight — faster, but with subtle replay-attack tradeoffs that's why 0-RTT is typically restricted to idempotent requests.\n\n` +
        `**Why the handshake matters even though you can't read the data after it**\n\n` +
        `Every field in this handshake — negotiated TLS version, chosen cipher suite, the certificate itself, and (as later readings cover) the exact ordering and content of the ClientHello — is visible to any network monitoring tool positioned to see the traffic, with zero decryption required. This is the entire foundation of metadata-based encrypted traffic analysis: the "envelope" of a TLS session tells you a great deal, even though its contents stay sealed.`,
      codeExample:
        "TLS 1.2 HANDSHAKE -- RECORD TYPE BYTE + MESSAGE FLOW\n" +
        "=======================================================\n" +
        "TLS record content types (first byte of a TLS record):\n" +
        "  0x14  ChangeCipherSpec\n" +
        "  0x15  Alert\n" +
        "  0x16  Handshake\n" +
        "  0x17  Application Data (encrypted payload)\n" +
        "\n" +
        "Client                                    Server\n" +
        "  ClientHello (version, ciphers, SNI) --->\n" +
        "                                  <---  ServerHello\n" +
        "                                  <---  Certificate\n" +
        "                                  <---  ServerKeyExchange\n" +
        "                                  <---  ServerHelloDone\n" +
        "  ClientKeyExchange ------------------->\n" +
        "  ChangeCipherSpec, Finished --------->\n" +
        "                                  <---  ChangeCipherSpec, Finished\n" +
        "  [Application Data, encrypted, both directions]\n" +
        "=======================================================\n\n" +
        "openssl s_client -connect example.com:443 (excerpt)\n" +
        "=======================================================\n" +
        "CONNECTED(00000003)\n" +
        "depth=2 C = US, O = Example CA, CN = Example Root CA\n" +
        "verify return:1\n" +
        "---\n" +
        "Certificate chain\n" +
        " 0 s:CN = example.com\n" +
        "   i:CN = Example Intermediate CA\n" +
        " 1 s:CN = Example Intermediate CA\n" +
        "   i:CN = Example Root CA\n" +
        "---\n" +
        "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, how many round trips does a typical TLS 1.3 handshake require in the common case, compared to TLS 1.2?",
        options: [
          "Two round trips, the same count as TLS 1.2",
          "One round trip (1-RTT), with a key share sent in the ClientHello",
          "Zero round trips (0-RTT) on every connection, including the first",
          "Three round trips, since the encrypted certificate needs its own flight",
        ],
        answer: 1,
        explanation:
          "TLS 1.3 collapses the handshake into a single round trip (1-RTT) in the common case: the ClientHello includes a guessed key share directly, letting the server reply with ServerHello, its certificate, and Finished all at once. “Two round trips, the same count as TLS 1.2” is the older protocol's count. “Zero round trips (0-RTT) on every connection” confuses the common case with 0-RTT resumption, which only applies to servers the client has visited before and is restricted to idempotent requests. “Three round trips, since the encrypted certificate needs its own flight” is backwards — the encrypted certificate travels in the same server flight as ServerHello.",
      },
    },

    // ── Reading 2: SNI + cert chain validation ───────────────────────────────
    {
      type: "reading" as const,
      id: "tls-r2",
      heading: "SNI — the Last Cleartext Field — and Certificate Chain Validation",
      content:
        `**Why SNI exists, and why it's still visible**\n\n` +
        `A single server (or, more realistically, a single reverse proxy / CDN edge / load balancer IP) very often hosts many different HTTPS sites, each with its own certificate. Before the TLS certificate is sent, the server needs to know WHICH certificate to present — but the certificate itself can't be selected until the client tells the server what hostname it's trying to reach. That's the SNI (Server Name Indication) extension: the client states the target hostname in cleartext, inside the ClientHello, before any encryption keys have even been established. This is why, even in standard TLS 1.3, the destination hostname remains visible to any network monitoring tool positioned on the path — and it's exactly the field most enterprise proxies and firewalls use to allow/block/categorize HTTPS traffic without needing to decrypt anything. (Encrypted Client Hello, ECH, is a newer extension specifically designed to hide SNI too, but as of this writing it is not yet universally deployed, and where it IS used it represents another meaningful visibility reduction for defenders — conceptually the same trade-off as DoH from the DNS room.)\n\n` +
        `**Certificate chain of trust**\n\n` +
        `A TLS certificate is validated by walking a **chain**: the server presents its own **leaf certificate** (issued to the specific hostname), which was signed by an **intermediate CA certificate**, which was itself signed by a **root CA certificate** that the client's operating system or browser already trusts implicitly (root CAs are pre-installed in a trust store). Validation succeeds only if every link in that chain checks out: each certificate's signature is valid, none are expired, the leaf certificate's Common Name (CN) or, more importantly in modern browsers, its Subject Alternative Name (SAN) list actually matches the hostname the client requested (SNI), and none of the certificates in the chain have been revoked (checked via CRL — Certificate Revocation List — or OCSP — Online Certificate Status Protocol, though OCSP checking is inconsistently enforced across clients in practice).\n\n` +
        `**Self-signed and short-lived certificates as a red flag**\n\n` +
        `A **self-signed certificate** is one where the issuer and subject are identical — the certificate vouches for itself, with no independent, trusted third party (a CA) attesting that the holder actually controls the claimed domain. Legitimate infrastructure sometimes uses self-signed certs deliberately (internal-only tools, some IoT/embedded device management interfaces, lab/dev environments) — but they are also the path of least resistance for attacker infrastructure and are, notably, the **default TLS certificate behavior of several popular C2 frameworks** unless the operator specifically configures something else. A certificate that is both self-signed AND was issued within the last day or two — trivial to generate on demand, and cheap to discard and regenerate the moment it's flagged — is a substantially stronger combined signal than either fact alone: legitimate infrastructure certificates, even self-signed internal ones, are typically provisioned once and left in place for a long time, not regenerated every session or every day.\n\n` +
        `**The Let's Encrypt nuance**\n\n` +
        `It's worth being precise here: publicly-trusted, free, short-lived certificates from providers like Let's Encrypt (typically valid 90 days) are used by an enormous share of entirely legitimate websites today — short validity alone is not a red flag in isolation, since it's now the industry norm, not the exception. What matters is the **combination**: is the cert self-signed (not from any trusted CA at all), was it issued suspiciously recently relative to when this destination first appeared in your traffic, and does the certificate's claimed identity make any sense for what the destination is actually being used for.`,
      codeExample:
        "openssl x509 -noout -text -in leaf.pem (excerpt)\n" +
        "=======================================================\n" +
        "Certificate:\n" +
        "    Data:\n" +
        "        Serial Number: 01 (0x1)\n" +
        "        Issuer: CN = ci-artifact-sync.io\n" +
        "        Validity\n" +
        "            Not Before: Apr  4 08:00:00 2026 GMT\n" +
        "            Not After : Apr  4 08:00:00 2027 GMT\n" +
        "        Subject: CN = ci-artifact-sync.io\n" +
        "        X509v3 extensions:\n" +
        "            X509v3 Subject Alternative Name:\n" +
        "                DNS:ci-artifact-sync.io\n" +
        "=======================================================\n" +
        "Issuer == Subject  ->  SELF-SIGNED\n" +
        "Issued ~25 hours before this connection was observed\n" +
        "=======================================================\n\n" +
        "CERTIFICATE CHAIN VALIDATION CHECKS\n" +
        "=======================================================\n" +
        "[ ] Signature valid at every link in the chain\n" +
        "[ ] Not expired (current time within Not Before/Not After)\n" +
        "[ ] SNI/hostname matches leaf cert's CN or SAN list\n" +
        "[ ] Chain terminates in a trusted root CA\n" +
        "[ ] Not revoked (CRL / OCSP, inconsistently checked)\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, what makes a self-signed certificate that is ALSO very recently issued a stronger combined signal than either fact alone?",
        options: [
          "Legitimate certs, even self-signed internal ones, are issued once and kept a long time; a day-old one breaks that norm",
          "Short-lived, recently issued certificates are rare on legitimate sites, so a new issue date is suspicious on its own",
          "A brand-new certificate has no revocation history yet, so CRL and OCSP checks have nothing to clear it against",
          "Self-signed already marks C2 infrastructure on its own, so the recent date only adds a minor confirming detail",
        ],
        answer: 0,
        explanation:
          "The reading explains that legitimate infrastructure, even self-signed internal tools, is provisioned once and left in place for a long time — not regenerated every session or every day — while attacker certificates are cheap to generate and discard. That is why the pair is far stronger than either fact. “Short-lived, recently issued certificates are rare on legitimate sites” contradicts the Let's Encrypt nuance: short validity is now the industry norm. “A brand-new certificate has no revocation history yet” is beside the point — a self-signed certificate has no CA behind it to publish revocations at all. “Self-signed already marks C2 infrastructure on its own” over-weights one fact: the reading lists internal tools, appliances and lab gear that legitimately use self-signed certificates.",
      },
    },

    // ── Reading 3: JA3/JA3S/JARM ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tls-r3",
      heading: "JA3, JA3S, JARM — and why JA4 replaced them",
      content:
        `The specific TLS version, cipher suite list, extension list, and elliptic curve preferences a client offers in its ClientHello are determined by the TLS library and its configuration, not by whatever application layer happens to be riding on top. This means the same TLS library — say, a specific version of a Cobalt Strike default profile, or Python's default requests library, or a bare-bones malware TLS implementation — produces a **consistent, fingerprint-able ClientHello** across every connection it ever makes, even as the destination domain, IP, and certificate all change from campaign to campaign.\n\n` +
        `**JA3: fingerprinting the client**\n\n` +
        `JA3 builds a fingerprint from the ClientHello by concatenating, in order: the TLS version, the list of offered cipher suites, the list of extensions, the list of elliptic curves, and the list of elliptic curve point formats — each list joined by hyphens, the whole string joined by commas — then taking the MD5 hash of that string as the final JA3 fingerprint. Because this reflects the TLS library and its configuration, not the destination, a known-malicious tool's JA3 hash stays the same even as its C2 infrastructure rotates through dozens of different domains and IPs to evade domain/IP blocklists — which is exactly the evasion JA3 was designed to defeat.\n\n` +
        `**JA3S: fingerprinting the server's response**\n\n` +
        `JA3S applies the same idea to the ServerHello — the server's chosen cipher and extension list — producing a fingerprint of the SERVER's TLS stack/configuration. A specific JA3S is often paired with a specific JA3 for a known toolkit (a particular C2 framework's client always negotiates against a server configured a particular way), and the JA3+JA3S pair together is a stronger fingerprint than either alone.\n\n` +
        `**JARM: actively fingerprinting a server, without needing to see real client traffic first**\n\n` +
        `JA3/JA3S are both **passive** — you can only compute them from traffic you've actually observed. JARM is different: it's an **active** fingerprinting technique where the scanning tool itself sends ten specially-crafted, varied TLS ClientHello probes to a target server and builds a fingerprint from how the server responds across all ten (its selected cipher for each different probe, ordering behavior, extension support). This means JARM lets defenders proactively fingerprint suspected C2 infrastructure servers directly — including infrastructure your own network hasn't talked to yet — and compare the result against known JARM signatures published for common C2 frameworks (default, unmodified Cobalt Strike team servers, Metasploit, certain phishing kit infrastructure, and others have well-documented, recognizable JARM hashes when operators don't bother customizing their TLS stack configuration).\n\n` +
        `**The essential caveat**\n\n` +
        `None of these fingerprints identify malicious intent by themselves — they identify a specific TLS library/configuration. A JA3 hash shared by a piece of malware might also, coincidentally, be shared by a completely legitimate application using the same underlying TLS library version with default settings (this happens constantly with common language runtimes and HTTP client libraries). JA3/JA3S/JARM are best used as a **pivot and correlation tool** — "show me everything else on the network with this same fingerprint" or "does this fingerprint match a documented, known-malicious signature" — not as a standalone verdict.\n\n` +
        `**JA3 has aged badly — and this is why "no JA3 match" proves nothing**\n\n` +
        `JA3's weakness is hiding in the word *order*. It concatenates the cipher and extension lists **in the exact order they appear** in the ClientHello — and since early 2023 Chrome (and every Chromium-based browser) deliberately **randomises the order of its TLS extensions on every single connection** (a GREASE-style anti-ossification measure). Because JA3 hashes order-sensitively, one unchanged browser now emits an effectively unlimited stream of *different* JA3 hashes — billions of them — which destroys JA3's founding premise that "one TLS library/config = one stable hash". So a JA3 that never repeats is now normal for modern browsers, and the absence of a JA3 match tells you nothing at all.\n\n` +
        `**JA4 / JA4+ was built to fix exactly this.**\n\n` +
        `The JA4 TLS-client fingerprint **sorts** the cipher and extension lists before hashing, so extension-order randomisation no longer changes the result. It also uses a partly human-readable, structured format instead of a single opaque MD5, and it is one of a whole family — **JA4S** (server), **JA4H** (HTTP), **JA4X** (X.509 certificates), **JA4T** (TCP) — that fingerprints far more of the stack. JA4/JA4+ is supported today in **Suricata** and **Zeek**. Practical guidance for 2026: JA3/JA3S/JARM are still useful against tools that use old or fixed-order TLS stacks (a great deal of malware and many C2 defaults never randomise), but reach for **JA4+ as the current standard** for anything modern — and never read a missing JA3 match as evidence of anything.`,
      codeExample:
        "HOW A JA3 FINGERPRINT IS BUILT\n" +
        "=======================================================\n" +
        "From the ClientHello, concatenate (comma-separated):\n" +
        "  TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFmt\n" +
        "  each list itself hyphen-separated, in the order offered\n" +
        "\n" +
        "Example JA3 string:\n" +
        "  769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,\n" +
        "  0-10-11,23-24,0\n" +
        "\n" +
        "MD5 hash of that string = the JA3 fingerprint, e.g.:\n" +
        "  e7d705a3286e19ea42f587b344ee6865\n" +
        "=======================================================\n\n" +
        "JA3 vs JA3S vs JARM -- WHAT EACH FINGERPRINTS\n" +
        "=======================================================\n" +
        "JA3    Passive. The CLIENT's ClientHello -- identifies\n" +
        "       the TLS library/config the connecting tool uses,\n" +
        "       stable even as the destination domain/IP changes\n" +
        "JA3S   Passive. The SERVER's ServerHello response to a\n" +
        "       real observed session -- identifies the server's\n" +
        "       TLS stack/config\n" +
        "JARM   Active. Scanner sends 10 varied ClientHello probes\n" +
        "       at a target server and fingerprints the pattern\n" +
        "       of responses -- works even on infrastructure your\n" +
        "       network hasn't talked to yet\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, what is the key difference between JA3 and JARM?",
        options: [
          "JA3 fingerprints the server's ServerHello reply, while JARM fingerprints the client's ClientHello",
          "JA3 is passive, from observed ClientHellos; JARM actively probes a server you may never have talked to",
          "JA3 hashes the lists in the order offered, while JARM sorts them first so browser randomisation can't change it",
          "JA3 needs decrypted traffic to compute, while JARM works from unencrypted handshake metadata alone",
        ],
        answer: 1,
        explanation:
          "JA3 is passive — computed only from ClientHellos you have actually observed. JARM is active — a scanner sends ten crafted ClientHello probes to a target server and fingerprints how it responds, which works even against infrastructure your network has never contacted. “JA3 fingerprints the server's ServerHello reply” describes JA3S, not JA3. “JARM sorts them first so browser randomisation can't change it” describes JA4, the sorted replacement for JA3. “JA3 needs decrypted traffic” is wrong: the ClientHello is sent before any encryption exists, so JA3 needs no decryption at all.",
      },
    },

    // ── Reading 4: detecting C2 in TLS without decryption ────────────────────
    {
      type: "reading" as const,
      id: "tls-r4",
      heading: "Detecting C2 Inside TLS Without Decryption",
      content:
        `Bringing together the handshake, certificate, and fingerprint knowledge from the last three readings, here is how an analyst actually builds a case that an encrypted session is C2 traffic — without ever seeing a single byte of decrypted application data.\n\n` +
        `**Certificate anomalies**\n\n` +
        `Self-signed, very recently issued (relative to first appearance of the destination on your network), or with a Subject/SAN that has no coherent relationship to what the destination claims to be used for (as covered in Reading 2) — each is weak alone, meaningful in combination.\n\n` +
        `**JA3/JA3S matches against known toolkits**\n\n` +
        `A connection whose JA3 (and ideally JA3S) matches a documented signature for a known C2 framework's default, unmodified configuration is high-confidence evidence — though sophisticated operators increasingly randomize or customize their TLS stack specifically to defeat this, so a JA3 match is strong positive evidence, but its absence proves nothing.\n\n` +
        `**Beacon timing: regular intervals, even with jitter**\n\n` +
        `C2 frameworks "sleep" between check-ins rather than maintaining a constant connection, both to reduce their footprint and to look less like a persistent, monitored session. Naive beacons check in at a perfectly fixed interval — trivially detected by just looking for near-identical time gaps between connections to the same destination. Modern frameworks add **jitter** (randomizing the sleep time by a configured percentage) specifically to break that pattern — but jitter only randomizes WITHIN a band; it doesn't make the beacon look like genuinely random human traffic. This is covered in full mathematical detail in the tunneling room later in this curriculum, but the short version: even with jitter, the intervals between a host's connections to one destination cluster tightly around the configured sleep time, in a way ordinary human browsing (which has no configured "interval" at all) never does.\n\n` +
        `**Packet/session size consistency**\n\n` +
        `Ordinary browsing produces highly variable request and response sizes (different pages, different assets, different amounts of user interaction). A beacon's check-in, by contrast, is usually a small, simple "anything for me?" request, and the response (when there's no new task queued) is similarly small and consistent — so a series of TLS sessions to the same destination with near-identical byte counts, session after session, is a strong shape-based signal, independent of anything about the certificate or fingerprint.\n\n` +
        `**Destination rarity and reputation**\n\n` +
        `A destination that has never been contacted by any host on your network before today, contacted now by exactly one host, with no corresponding legitimate business reason (no matching change ticket, no known vendor relationship, no DNS record suggesting an established, reputable service) is inherently more suspicious than the same technical signature against a well-known, widely-used, long-established destination. "First contact ever, from exactly one host" is one of the cheapest and most effective network-wide filters for surfacing candidates worth deeper review.\n\n` +
        `**SNI/domain-to-hosting mismatch**\n\n` +
        `A destination IP hosted on infrastructure with no coherent relationship to the SNI hostname being claimed (a residential/consumer ISP IP range presenting itself as a legitimate corporate SaaS product's SNI, for example) is a strong red flag that requires no decryption at all to observe — just correlating the connection's destination IP against IP/ASN reputation and ownership data alongside the SNI value from the handshake.\n\n` +
        `**The case only gets strong in combination**\n\n` +
        `Any one of these signals alone regularly has an innocent explanation. A case worth escalating combines several: a rare, first-seen destination + a self-signed, recently-issued certificate + a JA3 that doesn't match any recognized legitimate browser/library + sessions repeating at a tight, jitter-consistent interval + near-identical byte counts every time. That combination, entirely visible from metadata, is what a mature detection pipeline (or an experienced analyst working a queue) is actually built to surface.`,
      codeExample:
        "METADATA-ONLY C2-IN-TLS DETECTION CHECKLIST\n" +
        "=======================================================\n" +
        "[ ] Certificate: self-signed AND recently issued\n" +
        "    relative to destination's first appearance\n" +
        "[ ] JA3/JA3S matches a known-malicious toolkit signature\n" +
        "    (strong positive; absence proves nothing)\n" +
        "[ ] Session intervals cluster tightly around a fixed\n" +
        "    value, even accounting for jitter -- unlike genuine\n" +
        "    human browsing\n" +
        "[ ] Session byte counts near-identical, session after\n" +
        "    session, to the same destination\n" +
        "[ ] Destination is rare/first-seen on the network, with\n" +
        "    no business justification\n" +
        "[ ] Destination IP/ASN has no coherent relationship to\n" +
        "    the claimed SNI hostname\n" +
        "-------------------------------------------------------\n" +
        "One checked box: weak signal, needs more context.\n" +
        "Several checked together: escalate.\n" +
        "=======================================================",
    },

    // ── Reading 5: when interception is/isn't possible ───────────────────────
    {
      type: "reading" as const,
      id: "tls-r5",
      heading: "When TLS Interception Is (and Isn't) Possible",
      content:
        `Everything covered so far assumes you're analyzing TLS metadata WITHOUT decrypting the traffic. Some organizations also deploy active **TLS/SSL interception** (forward proxy MITM) to inspect content directly — but it's far from a universal solution, and knowing its limits matters as much as knowing how it works.\n\n` +
        `**How interception works**\n\n` +
        `An enterprise forward proxy or NGFW performing SSL inspection sits in the middle of every outbound HTTPS connection: it terminates the client's TLS connection using a certificate it generates on the fly (signed by an internal CA that the organization has deployed to every managed device's trust store), separately establishes its own TLS connection out to the real destination, and relays the decrypted content between the two — inspecting it in the middle, then re-encrypting on both legs. To the client, this looks like a normal, validating HTTPS connection specifically because the internal CA's root certificate has been pushed to the device's trust store in advance; without that trust-store deployment, every intercepted site would show a certificate warning.\n\n` +
        `**Where interception breaks down: certificate pinning**\n\n` +
        `**Certificate pinning** is a technique where an application hard-codes (pins) the exact certificate, or public key, or CA it expects to see for a specific service, and refuses to connect if presented with anything else — even a certificate that would otherwise validate successfully against the device's trust store. This is a deliberate security feature (it defeats exactly this kind of interception, which is also why some malicious/adversarial tooling deliberately implements pinning too — for the same reason). Mobile banking apps, some messaging apps, and, notably, several C2 frameworks specifically implement certificate pinning against their own team server's certificate precisely to prevent a defender's SSL inspection appliance from ever seeing their C2 traffic's actual content — the connection simply fails outright rather than being interceptable, which itself can be a signal (an application or process whose HTTPS connections are consistently failing specifically at your interception point, while working fine when tested from outside it).\n\n` +
        `**Other practical and legal limits**\n\n` +
        `Many organizations explicitly exclude certain traffic categories from interception for legal, regulatory, or trust reasons: banking and financial sites, healthcare portals (relevant to data privacy regulation), and sometimes personal webmail, specifically to avoid the organization taking on liability for having visibility into that content. **HSTS (HTTP Strict Transport Security)** preloading can also complicate interception for specific domains that browsers refuse to downgrade or accept substitute certificates for under any circumstances once HSTS is in effect. And practically: interception requires deploying and maintaining the internal CA across every managed device, which fails outright for unmanaged/BYOD devices, IoT devices, and third-party/contractor equipment that will never trust your internal CA — for that traffic, metadata-only analysis (everything covered in this room up to this point) is not a fallback option, it is the ONLY option.\n\n` +
        `**The practical takeaway for an analyst**\n\n` +
        `Even in an organization that DOES deploy SSL interception broadly, you should never assume it universally covers everything — pinned applications, excluded categories, and unmanaged devices all still require metadata-based analysis. This is exactly why the skills in this room (SNI, certificate metadata, JA3/JA3S/JARM, and beacon-timing analysis) remain essential even in a mature security program with full interception capability, not just a fallback for organizations without it.`,
      codeExample:
        "TLS INTERCEPTION -- WHAT WORKS AND WHAT DOESN'T\n" +
        "=======================================================\n" +
        "WORKS:  Managed corporate device, browser trusts the\n" +
        "        internal CA, application performs standard\n" +
        "        trust-store-based certificate validation\n" +
        "\n" +
        "FAILS:  Certificate-pinned applications/tools (mobile\n" +
        "        banking, some messaging apps, many C2 frameworks\n" +
        "        pinning their own team-server cert on purpose)\n" +
        "\n" +
        "FAILS:  Unmanaged / BYOD / IoT / contractor devices that\n" +
        "        never received the internal CA\n" +
        "\n" +
        "EXCLUDED BY POLICY: banking, healthcare, sometimes\n" +
        "        personal webmail -- legal/regulatory reasons\n" +
        "\n" +
        "=======================================================\n" +
        "A pinned app's connections FAILING specifically at your\n" +
        "interception point (while working fine outside it) is\n" +
        "itself a useful signal an app is deliberately resisting\n" +
        "inspection.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, why does certificate pinning defeat TLS interception even on a managed device where the internal CA is trusted?",
        options: [
          "The app accepts only the certificate or key it hard-coded, so the proxy's trust-store-valid substitute is refused",
          "Pinned apps insist on TLS 1.3, which encrypts the certificate so the proxy cannot see which one to substitute",
          "Pinning makes the app check revocation over OCSP, and the proxy's on-the-fly certificates have no OCSP responder",
          "Pinned apps send Encrypted Client Hello, so the proxy never learns the hostname it would need to forge a cert for",
        ],
        answer: 0,
        explanation:
          "Certificate pinning hard-codes the exact certificate or public key an application expects and refuses anything else — even the proxy's substitute certificate, which validates fine against the device's trust store. That is what defeats interception by design. “Pinned apps insist on TLS 1.3” misunderstands interception: the proxy terminates the client's TLS session itself, so the protocol version does not hide anything from it. “Pinning makes the app check revocation over OCSP” describes a different, inconsistently enforced check that the reading never ties to pinning. “Pinned apps send Encrypted Client Hello” confuses pinning with ECH; ECH hides SNI from passive observers, and a forward proxy still sees the destination it connects to.",
      },
    },

    // ── Reading 6: TLS version/cipher downgrade as a fingerprint ─────────────
    {
      type: "reading" as const,
      id: "tls-r6",
      heading: "TLS Version and Cipher Suite Choice as a Fingerprint of the Software Behind a Connection",
      content:
        `Beyond JA3's full-string hashing, even a coarse read of TLS version and cipher suite list tells you something valuable: modern browsers and modern C2 frameworks tend to look very different from each other at this level, and that difference is itself detectable without any special tooling.\n\n` +
        `**What a modern browser's ClientHello looks like**\n\n` +
        `A current version of Chrome, Firefox, Edge, or Safari negotiates TLS 1.3 by default, offers a long, actively-maintained list of modern cipher suites and extensions (including things like GREASE values specifically designed to prevent ossification/fingerprinting of the browser's own TLS stack over time), and supports modern features like ALPN (Application-Layer Protocol Negotiation, used to negotiate HTTP/2) as standard. This produces a rich, current, well-populated ClientHello.\n\n` +
        `**What a bare-bones or hand-rolled TLS stack looks like**\n\n` +
        `Many malware families and simple/legacy tools use minimal TLS libraries, older language runtime defaults, or deliberately stripped-down implementations that offer a much shorter cipher suite list (sometimes just 3-6 options), negotiate an older TLS version (1.2 rather than 1.3) even when talking to a server that would happily support 1.3, and lack modern extensions entirely. None of this is proof of malice on its own — plenty of legitimate embedded devices, older enterprise software, and simple internal automation scripts have exactly this same "thin" TLS fingerprint — but it is a meaningful anomaly specifically when observed FROM a device that should be running a modern, fully-patched browser or standard enterprise software stack, and isn't.\n\n` +
        `**Downgrade attacks: a related but distinct concern**\n\n` +
        `Historically, protocol downgrade attacks (like POODLE, exploiting fallback to SSLv3) tricked a connection into negotiating a deliberately weaker, exploitable protocol version even when both endpoints actually supported something stronger, typically via an on-path attacker manipulating the negotiation. Modern browsers and servers have largely closed this specific class of attack through protocol version intolerance detection and the removal of SSLv3/TLS 1.0/1.1 support entirely from current software. For a SOC today, seeing ANY internal system still negotiating SSLv3, TLS 1.0, or TLS 1.1 at all is primarily a **compliance and legacy-system** finding (unpatched, end-of-life software still in production) rather than an active-attack finding — but it remains worth flagging and tracking, both because such systems are often unpatched in other ways too, and because some threat actors specifically target legacy protocol support as an easier initial foothold.\n\n` +
        `**Putting version/cipher observations to use**\n\n` +
        `As a lightweight, no-tooling-required first pass before reaching for full JA3 computation: does the TLS version and rough cipher suite richness match what you'd expect from the claimed application on that host? A "browser" claiming to be Chrome but negotiating TLS 1.2 with four cipher suites and no ALPN is a mismatch worth a second look — exactly the kind of anomaly that a full JA3 lookup would confirm or refute definitively, but that a quick glance at the raw handshake fields can already flag.`,
      codeExample:
        "MODERN BROWSER vs BARE-BONES TLS STACK -- ROUGH COMPARISON\n" +
        "=======================================================\n" +
        "                    Modern Chrome/Firefox   Minimal/legacy\n" +
        "                                            TLS library\n" +
        "-------------------------------------------------------\n" +
        "TLS version          1.3 (default)           1.2, sometimes\n" +
        "                                              even when 1.3\n" +
        "                                              is available\n" +
        "Cipher suites offered ~15-20+, modern,        Often 3-6,\n" +
        "                      actively maintained     sometimes\n" +
        "                                              older/weaker\n" +
        "GREASE values         Present (anti-           Absent\n" +
        "                      fingerprinting noise)\n" +
        "ALPN (HTTP/2 nego)     Present                 Often absent\n" +
        "=======================================================\n\n" +
        "A HOST CLAIMING TO BE A MODERN BROWSER BUT NEGOTIATING\n" +
        "LIKE A BARE-BONES LIBRARY IS A MISMATCH WORTH A SECOND LOOK\n" +
        "=======================================================",
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tls-q1",
      question:
        "Why does the SNI (Server Name Indication) field remain visible in cleartext even in a fully modern TLS 1.3 connection (assuming ECH is not in use)?",
      options: [
        "TLS 1.3 leaves every handshake message unencrypted, exactly as TLS 1.2 did, so SNI is visible along with the certificate and key exchange",
        "SNI is sent in the ClientHello before any keys exist, because the server needs the hostname to choose which certificate to present",
        "SNI is encrypted by TLS 1.3, but proxies and sensors log the name from the server certificate's subject and present it as SNI",
        "SNI was dropped from the TLS 1.3 ClientHello, so the visible hostname is derived from the DNS query that preceded the connection",
      ],
      answer: 1,
      explanation:
        "The chicken-and-egg problem is structural: certificate selection depends on knowing the target hostname, but the certificate exchange is part of establishing the very encryption that would otherwise protect that hostname. SNI has to be sent in the ClientHello, before any shared secret exists, which is exactly why it remains the 'last cleartext field' and exactly why network security tools rely on it so heavily for HTTPS-based filtering and monitoring. Encrypted Client Hello (ECH) is a newer, not-yet-universal extension designed specifically to close this gap. TLS 1.3 does encrypt the certificate and later handshake fields (as Reading 1 covers), and standard TLS 1.3 still carries the SNI extension in its ClientHello — nothing about the protocol removed it.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tls-q2",
      question:
        "While triaging outbound TLS from a workstation, you have four separate findings. Judge each one on its own, with no other context. Based on this room's readings, which is the WEAKEST standalone evidence of malicious activity?",
      options: [
        "The destination server presents a self-signed certificate (its issue date is not known)",
        "The client's JA3 matches a documented fingerprint of a known C2 framework's default, unmodified configuration",
        "The SNI claims a well-known corporate SaaS product, but the destination IP sits in a residential ISP range",
        "Every session to the destination carries a near-identical byte count, session after session",
      ],
      answer: 0,
      explanation:
        "A self-signed certificate by itself is routine on legitimate internal tools, lab environments and IoT/embedded management interfaces, so on its own it is weak evidence — it only becomes a strong signal when combined with something else, such as being issued in the last day or two (Reading 2's 'substantially stronger combined signal'). The other three are each described in the detection reading as strong on their own: a JA3 match against a known C2 framework's default configuration is high-confidence evidence; an SNI that claims a corporate SaaS product from a residential ISP address is a strong red flag needing no decryption; and near-identical byte counts across sessions are a strong shape-based beacon signal. Even so, the case only becomes escalation-worthy in combination — timing, byte consistency, certificate anomaly, fingerprint and destination rarity together.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tls-q3",
      question:
        "Your organization has full SSL/TLS interception deployed on all managed laptops. A specific application's outbound HTTPS connections consistently fail at the interception point with a certificate error, while working normally when tested from an unmanaged network with no interception. What does this most likely indicate?",
      options: [
        "The interception appliance's own CA certificate has expired, so every application on managed laptops should be failing, not just this one",
        "The application pins its expected server certificate and rejects the proxy's substitute one, so its content stays opaque and only metadata is available",
        "The application uses a TLS version or cipher suite the proxy cannot negotiate, so decryption fails the same way for every client on the network",
        "The application's server presents a self-signed certificate, which proves the destination is attacker-controlled rather than a legitimate vendor",
      ],
      answer: 1,
      explanation:
        "This is the exact signature of certificate pinning: the application refuses any certificate other than the one it has hard-coded/pinned, which includes the interception proxy's generated substitute certificate, even though that substitute would otherwise validate fine against the device's trust store. This is a legitimate, common security feature in many applications (and is also deliberately used by some C2 frameworks for the same reason) — either way, it means this application's actual content will never be visible through interception, and an analyst has to fall back on metadata-based techniques (destination reputation, JA3, timing, certificate details of the pinned cert itself) for anything involving it.",
      xp: 25,
    },

    // ── Log Analysis 1: TLS beacon session ────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "tls-la1",
      heading: "Investigating a Repeating TLS Session Pattern",
      context:
        "WKS-MKT09 belongs to a member of the marketing team whose normal daily traffic is almost entirely to well-known SaaS marketing/analytics platforms. A network anomaly rule flagged repeated sessions to 146.70.87.201, an IP with no prior history on this network before today: 96 sessions over 96 minutes, averaging one every 60.4 seconds with a standard deviation of only 5.1 seconds, and the bytes sent per session vary by a standard deviation of just 4.2 bytes. Review the representative session record below.",
      event: tlsBeaconEvent,
      questions: [
        {
          question:
            "The raw record shows ssl.validation_status: 'self signed certificate' with ssl.issuer and ssl.subject both 'CN=cdn-assets-static.net'. Combined with the 96-sessions-in-96-minutes timing pattern stated above, what does this combination suggest?",
          options: [
            "Routine CDN asset loading — pages refresh assets on a timer, and CDN edge nodes often present self-signed certificates",
            "A likely beacon — a self-signed cert under a generic CDN-style name, plus a ~60 s interval with only a 5.1 s spread",
            "An appliance health check — self-signed certificates and fixed intervals are normal for device management traffic",
            "A client retrying a failed TLS handshake every minute, which a misconfigured certificate on the server would cause",
          ],
          answer: 1,
          explanation:
            "A 5.1-second standard deviation around a ~60-second mean, held across 96 sessions, is the jittered-but-clustered rhythm Reading 4 describes; paired with a self-signed certificate behind a generic, CDN-sounding name, it is a strong combined signal. “Routine CDN asset loading” fails twice: real CDNs present publicly trusted certificates, and asset loading follows page views, not a 60-second clock. “An appliance health check” is the right explanation for the internal backup appliance later in this room, but this destination is an external IP with no history on the network before today. “A client retrying a failed TLS handshake” is contradicted by the record itself: each session lasts about a second and carries data both ways (orig_bytes 216, resp_bytes 198), so the handshakes completed.",
          xp: 25,
        },
        {
          question:
            "The byte-count standard deviation across sessions is 4.2, stated above — a very small variation in bytes sent, session after session. Why does this specific metric matter alongside the timing pattern?",
          options: [
            "It re-measures the timing signal in another unit, so it adds confidence only when the timing evidence is weak",
            "Uniform sizes fit a repeated check-in, not browsing; it is a separate signal that reinforces the timing",
            "It shows the sessions carried no real payload, so the beacon is idle and the host can wait for routine review",
            "TLS padding hides true sizes, so byte counts are unreliable and the timing evidence should carry the decision",
          ],
          answer: 1,
          explanation:
            "Byte-count consistency is a distinct signal from timing consistency, and both come from connection metadata alone. A simple 'anything for me?' check-in produces near-identical sizes every time, while real content loading varies with what is requested — so seeing both patterns together is much stronger than either. “It re-measures the timing signal in another unit” is wrong: a process could connect on a clock while sending very different payloads, or vice versa, so the two are independent. “The beacon is idle and the host can wait” treats a working C2 channel as harmless; an idle beacon is waiting for tasking, which is exactly when you want to catch it. “TLS padding hides true sizes” overstates padding: it adds a few bytes, and a 4.2-byte spread across 96 sessions is still a clear shape.",
          xp: 25,
        },
        {
          question:
            "Given everything observed, what is the correct next step?",
          options: [
            "Block 146.70.87.201 at the perimeter and close the case, since the combined signals already confirm C2",
            "Find the owning process via EDR on WKS-MKT09 and check the JA3/JA3S against known toolkits before deciding",
            "Ask the marketing user whether they installed a new tool, and close the finding if they confirm they did",
            "Collect another 24 hours of sessions so the interval statistics are more reliable before taking any action",
          ],
          answer: 1,
          explanation:
            "The certificate, timing and byte-size signals all point the same way, so this needs endpoint investigation: EDR shows which process owns the sessions, and the JA3/JA3S can be checked against known toolkit fingerprints, while the destination is treated as a priority indicator. “Block … and close the case” acts before finding the process — the implant stays on the host and can fall back to other infrastructure, and any other infected hosts go unscoped. “Ask the marketing user” relies on a self-report a user cannot verify; even a yes does not tell you what the tool is doing. “Collect another 24 hours of sessions” waits for statistics that are already decisive at 96 sessions — what is missing is attribution to a process, not more samples.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: cert/JARM investigation of rare destination ─────────
    {
      type: "log_analysis" as const,
      id: "tls-la2",
      heading: "A CI/CD Build Server's First-Ever Connection to a New Destination",
      context:
        "SRV-BUILD04 runs the company's CI/CD pipeline and normally only talks to a small, well-documented set of package registries, artifact repositories, and internal services. destination_hosts_seen_before_today confirms 185.183.96.14 has never been contacted from the 10.40.2.0/24 build segment before. Review the session record below.",
      event: certInvestigationEvent,
      questions: [
        {
          question:
            "ssl.not_valid_before and ssl.not_valid_after both show exactly one year apart, but cert_age_hours_at_connection is only 25.8 — meaning the certificate was issued roughly a day before this connection occurred, for a destination the build segment has never contacted before. Why does the certificate's AGE matter here more than its total validity PERIOD (one year)?",
          options: [
            "A one-year validity is unusually long for a self-signed cert, and that length is the main sign of attacker infrastructure",
            "The one-year period is unremarkable; issuing it about a day before the first-ever contact points to newly built infrastructure",
            "The period matters more: a one-year cert signals a long-term plan, while its age only reflects the most recent rotation",
            "A day-old certificate is normal under Let's Encrypt-style 90-day rotation, so here the age is the weaker of the two signals",
          ],
          answer: 1,
          explanation:
            "As Reading 2 explains, validity PERIOD is not the signal — short and long periods are both common on legitimate infrastructure. What matters is AGE relative to first contact: the certificate is about 26 hours old when SRV-BUILD04, which has never talked to this destination, connects to it — consistent with infrastructure stood up for this purpose rather than an established service the build server depends on. “A one-year validity is unusually long for a self-signed cert” invents a norm: whoever generates a self-signed certificate picks any period, and internal tools often use a year or more. “A one-year cert signals a long-term plan” reads intent into a number the issuer chose at will. “Normal under Let's Encrypt-style 90-day rotation” misreads the record: this certificate is self-signed (issuer equals subject), not issued by Let's Encrypt or any public CA, so that rotation pattern does not apply.",
          xp: 25,
        },
        {
          question:
            "The record carries a passive JA3 for SRV-BUILD04's ClientHello but no JARM. Given that this is the FIRST connection ever observed to 185.183.96.14, why is running a JARM scan the more useful next pivot?",
          options: [
            "Zeek derives JARM from the ServerHello, so it will appear in the record once a second session is captured",
            "JARM is active: you can probe 185.183.96.14 now and compare the result with published C2 server JARMs",
            "JA3 describes the server's TLS stack, so on its own it cannot say whether the destination is C2 infrastructure",
            "JARM sorts the cipher list before hashing, so it survives the randomisation that breaks JA3 matching on browsers",
          ],
          answer: 1,
          explanation:
            "This is the distinction from Reading 3: JA3 is passive and only describes the CLIENT side of the session you already captured — here, the build server's TLS library. JARM is active: you probe 185.183.96.14 yourself, now, and compare the result with published JARM signatures for C2 team servers, without waiting for more traffic. “Zeek derives JARM from the ServerHello” is wrong — JARM needs ten crafted probes, so no passive sensor produces it however many sessions it sees; the server-side passive fingerprint is JA3S. “JA3 describes the server's TLS stack” swaps JA3 and JA3S. “JARM sorts the cipher list before hashing” describes JA4, not JARM.",
          xp: 25,
        },
        {
          question:
            "What is the appropriate response, balancing the genuine risk signals against the fact that CI/CD systems do sometimes legitimately need to reach new third-party services (e.g. a newly adopted build dependency or artifact mirror)?",
          options: [
            "Block 185.183.96.14 and rebuild SRV-BUILD04 now — a first-ever destination with a day-old self-signed cert is enough",
            "Allow it for now, since build servers add new dependencies all the time, and raise it at the next change-board review",
            "JARM-scan it and check threat intel, check pipeline changes for a new dependency, and escalate if nothing explains it",
            "Ask the build team whether they recognise ci-artifact-sync.io, add it to the allowlist if they do, and close the alert",
          ],
          answer: 2,
          explanation:
            "A first-time connection from a build server is genuinely ambiguous — new dependencies and artifact mirrors are added legitimately — so you verify before either dismissing or over-reacting: fingerprint the destination and check threat intelligence, and in parallel check the pipeline configuration and change history for a documented new dependency. If nothing explains it, the day-old self-signed certificate on a never-seen destination is enough to escalate for endpoint investigation. “Block … and rebuild SRV-BUILD04 now” destroys the evidence and breaks the pipeline before you know whether a legitimate change explains it. “Allow it for now … and raise it at the next change-board review” leaves a possible C2 channel open on the build server for days. “Ask the build team whether they recognise” the name trusts recognition of a domain anyone could register; a plausible name is not a documented change.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: internal self-signed appliance FP trap ──────────────
    {
      type: "analyst_choice" as const,
      id: "tls-ac1",
      heading: "Verdict: A Self-Signed Certificate With an Unusual JA3 on an Internal Segment",
      scenario:
        "A detection rule flagged a TLS session from SRV-BACKUP02 to 10.40.1.40 on port 8007 using a self-signed certificate and a JA3 hash that does not match any common browser or standard library signature in the threat-intel feed. IT change records confirm 10.40.1.40 is the management interface of the company's on-premises backup appliance (a Proxmox Backup Server instance), which has used a vendor-default self-signed certificate since its installation eight months ago, and the connection recurs nightly at the scheduled backup job time.",
      event: {
        id: "evt-tls-ac1-001",
        ts: "2026-04-06T01:00:04.000Z",
        source: "ids",
        vendor: "Corelight (Zeek)",
        event_type: "net_connection",
        severity: "low",
        hostname: "SRV-BACKUP02.solvix.local",
        src_ip: "10.40.1.55",
        dst_ip: "10.40.1.40",
        dst_port: 8007,
        protocol: "tcp",
        it_verify_result: "confirmed",
        it_verify_message: "10.40.1.40 is the Proxmox Backup Server management appliance, in production since 2025-08; self-signed cert is the vendor default and has not been rotated. Nightly connection matches the scheduled 01:00 backup job.",
        description:
          "SRV-BACKUP02 connects nightly at 01:00 to 10.40.1.40:8007 using a self-signed certificate that has been in place for eight months, with a JA3 not present in the standard-browser reference list",
        raw: {
          "id.orig_h": "10.40.1.55",
          "id.resp_h": "10.40.1.40",
          "id.resp_p": 8007,
          "ssl.subject": "CN=pbs-appliance",
          "ssl.issuer": "CN=pbs-appliance",
          "ssl.validation_status": "self signed certificate",
          "ssl.ja3": "6734f37431670b3ab4292b8f60f29984",
          cert_age_hours_at_connection: 5832,
          destination_hosts_seen_before_today: 244,
          recurrence: "nightly, 01:00 local, 8 months observed",
        },
      },
      correct_verdict: "false_positive",
      explanation:
        "Every individual element here — self-signed certificate, unrecognized JA3 — is exactly the kind of raw signal that this room teaches you to weigh, but the surrounding context resolves it clearly as benign: it_verify_result is confirmed by IT (a legitimate management appliance with a documented, unrotated vendor-default certificate), the certificate is nearly 5,832 hours (about 8 months) old — not recently issued — and destination_hosts_seen_before_today is 244, meaning this is a well-established, frequently-used internal destination, not a rare, first-seen one. Many internal appliances and management interfaces (backup servers, hypervisor management, network gear web UIs) ship with self-signed certificates by default and are never issued a proper internal-CA certificate — this is common, if not ideal, practice, and does not by itself indicate compromise.",
      fp_trap:
        "A self-signed certificate plus an unfamiliar JA3 is exactly the combination Reading 3 and Reading 4 taught you to weigh as suspicious — but those readings were explicit that these signals build a case only in combination with rarity, recency, and lack of business justification. Here, the certificate is old (not recently issued), the destination has been contacted 244 times before (not rare or first-seen), and IT has explicitly confirmed the appliance's identity and purpose. Escalating purely because a system triggers two individually-suspicious-sounding facts, without checking their actual values (age, rarity) or available IT verification, is exactly the kind of alert fatigue trap that erodes trust in a detection program over time. Not every self-signed certificate is a C2 beacon — most, in most networks, are boring internal appliances that were never properly issued a real certificate.",
      xp: 30,
    },

    // ── Matching: fingerprint/handshake concept -> definition ───────────────
    {
      type: "matching" as const,
      id: "tls-m1",
      heading: "Match Each TLS Concept to What It Actually Tells an Analyst",
      instructions: "Match each TLS-related term to the correct description of what it reveals during an investigation.",
      pairs: [
        { id: "sni", left: "SNI (Server Name Indication)", right: "The hostname the client is requesting, sent in cleartext in the ClientHello, before any encryption is established — the last visible field even in TLS 1.3" },
        { id: "ja3", left: "JA3", right: "Passive fingerprint of the CLIENT's TLS stack/configuration, built from its ClientHello — stays consistent even as destination domains/IPs change" },
        { id: "ja3s", left: "JA3S", right: "Passive fingerprint of the SERVER's TLS stack/configuration, built from its ServerHello response to an observed session" },
        { id: "jarm", left: "JARM", right: "Active fingerprint built by sending 10 varied probe ClientHellos at a target server — usable even against infrastructure your network hasn't talked to yet" },
        { id: "pinning", left: "Certificate pinning", right: "An application hard-codes the exact certificate/key it trusts and refuses anything else, including a valid substitute from an SSL interception proxy — defeats interception by design" },
        { id: "selfsigned", left: "Self-signed certificate", right: "Issuer and subject are identical; no independent CA vouches for it — common on internal appliances and also the default behavior of several C2 frameworks" },
      ],
      explanation:
        "Each of these concepts answers a distinct question during a TLS investigation: SNI tells you the intended destination, JA3/JA3S fingerprint the client and server TLS stacks respectively (useful for pivoting on known-malicious tooling), JARM lets you actively probe suspicious infrastructure, certificate pinning explains why some traffic will never be visible even with full interception deployed, and self-signed certificates are a common but not conclusive signal that requires context (age, rarity, IT verification) to interpret correctly.",
      xp: 40,
    },

    // ── Ordering: TLS 1.2 handshake sequence ────────────────────────────────
    {
      type: "ordering" as const,
      id: "tls-o1",
      heading: "Order the TLS 1.2 Handshake, Message by Message",
      instructions: "Arrange these handshake messages into the correct chronological order for a standard TLS 1.2 session.",
      items: [
        { id: "clienthello", text: "ClientHello (TLS version, cipher list, SNI, random value)" },
        { id: "serverhello", text: "ServerHello (chosen cipher, server random value)" },
        { id: "certificate", text: "Certificate (server sends its certificate chain)" },
        { id: "serverhellodone", text: "ServerKeyExchange / ServerHelloDone" },
        { id: "clientkeyexchange", text: "ClientKeyExchange (client sends its key material)" },
        { id: "clientfinished", text: "ChangeCipherSpec + Finished (client)" },
        { id: "serverfinished", text: "ChangeCipherSpec + Finished (server)" },
        { id: "appdata", text: "Application Data (encrypted HTTP request/response begins)" },
      ],
      correct_order: [
        "clienthello",
        "serverhello",
        "certificate",
        "serverhellodone",
        "clientkeyexchange",
        "clientfinished",
        "serverfinished",
        "appdata",
      ],
      explanation:
        "The client proposes parameters and states its target hostname via SNI; the server picks a cipher and presents its certificate chain; both sides exchange key material to independently derive the same session key; both sides confirm the handshake wasn't tampered with via their respective Finished messages (the first message actually encrypted with the new key); and only then does real application data begin flowing. Every field up through ClientKeyExchange is visible to network monitoring with zero decryption required — which is the entire basis for metadata-only TLS analysis.",
      xp: 35,
    },

    // ── Query Fill: KQL to find beacon-shaped TLS sessions by JA3 + cadence ──
    {
      type: "query_fill" as const,
      id: "tls-qf1",
      heading: "Write It Yourself: Surface Beacon-Shaped TLS Sessions in KQL",
      language: "kql",
      context: KQL_PRIMER +
        "Using the pattern confirmed in Log Analysis 1 (96 sessions to one destination, tight interval clustering, and a byte-count standard deviation of 4.2), write the KQL that flags the session-count and byte-consistency parts of that pattern across the whole network, so candidates surface without inspecting any single session first. Choose thresholds that would still catch the Log Analysis 1 host. (Interval clustering needs a separate time-delta step and is not part of this query.)",
      template:
        "NetworkSessionEvents\n| where DestinationPort == {{port}}\n| summarize SessionCount = count(), AvgBytesOut = avg(BytesSent), StdevBytesOut = stdev(BytesSent) by SourceIp, DestinationIp, JA3Hash\n| where SessionCount > {{threshold}}\n| where StdevBytesOut < {{stdevlimit}}",
      blanks: [
        { id: "port", answers: ["443"], placeholder: "standard HTTPS port" },
        { id: "threshold", answers: ["10", "12", "15", "20", "24", "25", "30", "40", "48", "50", "60", "70", "75", "80", "90"], placeholder: "minimum session count to consider a repeating pattern" },
        { id: "stdevlimit", answers: ["5", "6", "7", "8", "9", "10", "12", "15", "20"], placeholder: "byte-count standard deviation ceiling (low = suspiciously consistent)" },
      ],
      explanation:
        "This mirrors exactly the two signals you evaluated in Log Analysis 1: a high SessionCount to the same destination/JA3 pair, combined with a LOW standard deviation in bytes sent per session. Any session-count floor from 10 up to 90 and any stdev ceiling from 5 to 20 is accepted: each still catches the 96-session, 4.2-byte-stdev host, while a floor of 96 or more, or a ceiling of 4 or less, would miss it. Ordinary browsing produces high variance in request sizes; a beacon's repeated, near-identical check-in produces the opposite — many sessions, tightly clustered byte counts. Grouping by JA3Hash alongside source/destination also lets this same query catch the case where a beacon rotates its destination IP or domain but keeps using the same underlying TLS library/configuration.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "tls-f1",
      prompt:
        "Reading 6 suggests a quick first pass before computing any JA3: does the negotiated cipher suite look like a modern browser or a thin, legacy TLS stack? In Log Analysis 1, which cipher suite did the WKS-MKT09 session actually negotiate? Enter it exactly as recorded.",
      answer: "TLS_RSA_WITH_AES_128_CBC_SHA",
      hint: "It is one of the handshake fields in the raw record, next to the negotiated TLS version — not a fingerprint hash.",
      xp: 25,
    },
  ],
};

export default [tlsRoom];
