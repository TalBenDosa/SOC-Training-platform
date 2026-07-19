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
    "ssl.ja3s": "a0e9f5d64349fb13191bc781f81f42e1",
    "ssl.cert_chain_issuer": "CN=cdn-assets-static.net",
    "ssl.cert_chain_subject": "CN=cdn-assets-static.net",
    "ssl.validation_status": "self signed certificate",
    duration: 0.891,
    orig_bytes: 216,
    resp_bytes: 198,
    sessions_last_96min: 96,
    interval_seconds_avg: 60.4,
    interval_seconds_stddev: 5.1,
    orig_bytes_stddev_across_sessions: 4.2,
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
    "ssl.jarm": "27d3ed3ed0003ed1dc42d43d00041d5d6e2ecd3b0d0e2f6f2c0c0c0c0c0c0c",
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
  xp: 640,
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
    },

    // ── Reading 3: JA3/JA3S/JARM ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tls-r3",
      heading: "JA3, JA3S, and JARM Fingerprinting",
      content:
        `The specific TLS version, cipher suite list, extension list, and elliptic curve preferences a client offers in its ClientHello are determined by the TLS library and its configuration, not by whatever application layer happens to be riding on top. This means the same TLS library — say, a specific version of a Cobalt Strike default profile, or Python's default requests library, or a bare-bones malware TLS implementation — produces a **consistent, fingerprint-able ClientHello** across every connection it ever makes, even as the destination domain, IP, and certificate all change from campaign to campaign.\n\n` +
        `**JA3: fingerprinting the client**\n\n` +
        `JA3 builds a fingerprint from the ClientHello by concatenating, in order: the TLS version, the list of offered cipher suites, the list of extensions, the list of elliptic curves, and the list of elliptic curve point formats — each list joined by hyphens, the whole string joined by commas — then taking the MD5 hash of that string as the final JA3 fingerprint. Because this reflects the TLS library and its configuration, not the destination, a known-malicious tool's JA3 hash stays the same even as its C2 infrastructure rotates through dozens of different domains and IPs to evade domain/IP blocklists — which is exactly the evasion JA3 was designed to defeat.\n\n` +
        `**JA3S: fingerprinting the server's response**\n\n` +
        `JA3S applies the same idea to the ServerHello — the server's chosen cipher and extension list — producing a fingerprint of the SERVER's TLS stack/configuration. A specific JA3S is often paired with a specific JA3 for a known toolkit (a particular C2 framework's client always negotiates against a server configured a particular way), and the JA3+JA3S pair together is a stronger fingerprint than either alone.\n\n` +
        `**JARM: actively fingerprinting a server, without needing to see real client traffic first**\n\n` +
        `JA3/JA3S are both **passive** — you can only compute them from traffic you've actually observed. JARM is different: it's an **active** fingerprinting technique where the scanning tool itself sends ten specially-crafted, varied TLS ClientHello probes to a target server and builds a fingerprint from how the server responds across all ten (its selected cipher for each different probe, ordering behavior, extension support). This means JARM lets defenders proactively fingerprint suspected C2 infrastructure servers directly — including infrastructure your own network hasn't talked to yet — and compare the result against known JARM signatures published for common C2 frameworks (default, unmodified Cobalt Strike team servers, Metasploit, certain phishing kit infrastructure, and others have well-documented, recognizable JARM hashes when operators don't bother customizing their TLS stack configuration).\n\n` +
        `**The essential caveat**\n\n` +
        `None of these fingerprints identify malicious intent by themselves — they identify a specific TLS library/configuration. A JA3 hash shared by a piece of malware might also, coincidentally, be shared by a completely legitimate application using the same underlying TLS library version with default settings (this happens constantly with common language runtimes and HTTP client libraries). JA3/JA3S/JARM are best used as a **pivot and correlation tool** — "show me everything else on the network with this same fingerprint" or "does this fingerprint match a documented, known-malicious signature" — not as a standalone verdict.`,
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
        "TLS 1.3 does not support encryption of any handshake fields at all",
        "The server must know which hostname the client is requesting BEFORE it can select and send the correct certificate for that hostname — and no encryption keys have been established yet at that point in the handshake, so this specific field is necessarily sent in the clear",
        "SNI is encrypted, but browsers choose to display it in cleartext for debugging purposes",
        "SNI only appears in TLS 1.2, not TLS 1.3",
      ],
      answer: 1,
      explanation:
        "The chicken-and-egg problem is structural: certificate selection depends on knowing the target hostname, but the certificate exchange is part of establishing the very encryption that would otherwise protect that hostname. SNI has to be sent in the ClientHello, before any shared secret exists, which is exactly why it remains the 'last cleartext field' and exactly why network security tools rely on it so heavily for HTTPS-based filtering and monitoring. Encrypted Client Hello (ECH) is a newer, not-yet-universal extension designed specifically to close this gap.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tls-q2",
      question:
        "A workstation makes repeated TLS sessions to the same external IP roughly every 60 seconds (with a small amount of jitter), each session's byte count nearly identical, using a self-signed certificate that was issued nine hours ago. Individually, which of these facts is the WEAKEST standalone evidence of malicious activity?",
      options: [
        "The self-signed, 9-hour-old certificate, taken completely alone with no other context",
        "The combination of all of the listed factors together",
        "Nothing here is weak evidence — any single one of these facts alone is sufficient grounds for immediate incident declaration",
        "The consistent session interval, taken completely alone with no other context",
      ],
      answer: 0,
      explanation:
        "A self-signed, recently-issued certificate, by itself, is common on legitimate internal tools, lab environments, and some IoT/embedded management interfaces — weak evidence alone. The tight, jitter-consistent interval and near-identical byte-count-per-session pattern are each individually more distinctive of scripted/automated check-in behavior than a bare certificate fact is. It's the full combination — timing, byte consistency, AND the certificate anomaly together, especially against a rare/first-seen destination — that builds a genuinely strong case, exactly as this room's detection checklist emphasizes.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tls-q3",
      question:
        "Your organization has full SSL/TLS interception deployed on all managed laptops. A specific application's outbound HTTPS connections consistently fail at the interception point with a certificate error, while working normally when tested from an unmanaged network with no interception. What does this most likely indicate?",
      options: [
        "The interception appliance is broken and needs to be restarted",
        "The application implements certificate pinning against its expected server certificate, and is correctly rejecting the interception proxy's substitute certificate — meaning this specific application's traffic content will not be visible to your SSL inspection regardless of how it's configured, and metadata-based analysis remains your only option for it",
        "The application is not using HTTPS at all, and the failure is unrelated to TLS",
        "This proves conclusively that the application is malware",
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
        "WKS-MKT09 belongs to a member of the marketing team whose normal daily traffic is almost entirely to well-known SaaS marketing/analytics platforms. A network anomaly rule flagged repeated sessions to 146.70.87.201, an IP with no prior history on this network before today. Review the representative session record below.",
      event: tlsBeaconEvent,
      questions: [
        {
          question:
            "The raw record shows ssl.validation_status: 'self signed certificate' with ssl.cert_chain_issuer and ssl.cert_chain_subject both 'CN=cdn-assets-static.net', alongside sessions_last_96min: 96 and interval_seconds_avg: 60.4 with interval_seconds_stddev: 5.1. What does this combination suggest?",
          options: [
            "This is routine CDN asset-loading traffic — CDN domains are always trustworthy regardless of certificate details",
            "A self-signed certificate on a destination presenting itself with a generic CDN-style name, combined with 96 sessions repeating at a tightly consistent ~60-second interval (a standard deviation of only 5.1 seconds around that average), matches the beacon-timing and certificate-anomaly patterns described in this room's detection checklist far more closely than ordinary asset-loading traffic, which would not repeat at such a fixed interval",
            "The stddev value proves this traffic is completely random and therefore benign",
            "Self-signed certificates are always issued by Let's Encrypt, which is always safe",
          ],
          answer: 1,
          explanation:
            "A tight standard deviation (5.1 seconds) around a ~60-second average interval, sustained across 96 sessions, is exactly the jittered-but-clustered pattern described in Reading 4 — genuine human-driven asset loading does not repeat at a fixed interval like this. Combined with a self-signed certificate on a domain whose name is generic and CDN-suggestive but unverified by any trusted CA, this is a strong combined signal, not a single weak one.",
          xp: 25,
        },
        {
          question:
            "orig_bytes_stddev_across_sessions is 4.2 (a very small variation in bytes sent, session after session). Why does this specific metric matter alongside the timing pattern?",
          options: [
            "It doesn't add anything beyond what the timing interval already shows",
            "Near-identical byte counts session after session is the shape of a simple, repeated check-in request rather than ordinary browsing, which would show highly variable request/response sizes depending on what content is actually being loaded each time — this is the session-size-consistency signal from Reading 4, independent of and reinforcing the timing signal",
            "A low byte-count standard deviation always indicates the connection failed to transmit any real data",
            "This metric can only be computed after full TLS decryption, so it should be disregarded in a metadata-only investigation",
          ],
          answer: 1,
          explanation:
            "Byte-count consistency across many sessions to the same destination is a distinct signal from timing consistency, and both are fully derivable from connection metadata alone — no decryption required. A repeated, simple 'anything for me?' beacon check-in naturally produces near-identical sizes every time, unlike real content loading, which varies with what's actually being requested. Seeing both the timing AND the size pattern together substantially strengthens the case beyond either alone.",
          xp: 25,
        },
        {
          question:
            "Given everything observed, what is the correct next step?",
          options: [
            "Close the finding, since HTTPS traffic on port 443 to a domain with a CDN-style name is expected on any corporate network",
            "Escalate for endpoint investigation on WKS-MKT09 (pull EDR process telemetry to identify what process is generating these sessions), compute or pull the JA3/JA3S fingerprint for this traffic to check it against known toolkit signatures, and treat 146.70.87.201 / cdn-assets-static.net as a high-priority indicator pending further review, given the combined certificate, timing, and byte-consistency signals",
            "Add cdn-assets-static.net to the corporate CDN allowlist so the alerts stop",
            "Contact the marketing team member by email asking if they personally initiated 96 connections, and take no further action regardless of the answer",
          ],
          answer: 1,
          explanation:
            "With a self-signed, recently-observed certificate, a tightly clustered check-in interval, and near-identical session sizes all pointing the same direction, this warrants real investigation rather than dismissal: identify the responsible process on the endpoint via EDR, pull a JA3/JA3S fingerprint to check against known malicious toolkit signatures, and treat the destination as a high-priority indicator. Allowlisting the very domain under investigation, or relying solely on a user's self-report without technical verification, would both be premature and risky given the strength of the combined evidence.",
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
            "A one-year validity period is unusually short and is, by itself, conclusive proof of malicious infrastructure",
            "The one-year total validity period is unremarkable on its own (plenty of legitimate self-issued or internal certificates use similar periods) — what's notable is that the cert was issued only about a day before this very first-ever connection from this network segment, suggesting infrastructure that was stood up specifically and recently, shortly before being contacted, rather than long-standing, established infrastructure",
            "Certificate age can never be determined from a TLS session; only from a DNS WHOIS lookup",
            "The exact one-year gap between not_valid_before and not_valid_after proves the certificate was issued by a trusted public CA",
          ],
          answer: 1,
          explanation:
            "As Reading 2 explains, short validity periods (like Let's Encrypt's 90 days) are now completely normal for legitimate infrastructure, so validity PERIOD alone isn't the signal. What matters here is AGE relative to first contact: this certificate is barely a day old at the moment SRV-BUILD04 — which has never talked to this destination before — connects to it. That timing is far more consistent with infrastructure recently stood up for a specific purpose than with an established, long-running legitimate service SRV-BUILD04 would have a documented reason to depend on.",
          xp: 25,
        },
        {
          question:
            "The record includes both a JA3 value and a JARM value. Given that this is the FIRST connection ever observed to this destination, why is JARM the more immediately actionable field to pivot on next?",
          options: [
            "JARM and JA3 answer the exact same question and either one is equally useful here",
            "JARM is an active fingerprinting technique — an analyst can independently query 185.183.96.14 directly right now and compare the resulting JARM signature against known threat-intelligence-published JARM hashes for C2 frameworks, without needing to wait for or rely on any additional passive traffic to be observed from this one session",
            "JA3 values expire after 24 hours and are no longer usable for lookups",
            "JARM can only be computed by the destination server itself, never by a defender",
          ],
          answer: 1,
          explanation:
            "This is exactly the distinction from Reading 3: JA3 is passive and reflects only what was captured in this one session's ClientHello (still useful, but limited to what you've already observed). JARM is active — an analyst can independently probe 185.183.96.14 right now, generate a fresh JARM signature for it, and compare that against published threat-intel JARM signatures for known C2 frameworks, entirely independent of whatever else does or doesn't get captured passively from SRV-BUILD04's traffic going forward.",
          xp: 25,
        },
        {
          question:
            "What is the appropriate response, balancing the genuine risk signals against the fact that CI/CD systems do sometimes legitimately need to reach new third-party services (e.g. a newly adopted build dependency or artifact mirror)?",
          options: [
            "Immediately treat this as a confirmed incident and wipe SRV-BUILD04 without further investigation",
            "Dismiss it entirely — CI/CD systems routinely reach new destinations, so a first-time connection alone is never worth reviewing",
            "Actively fingerprint 185.183.96.14 with JARM and check it against threat intel, review SRV-BUILD04's build/pipeline configuration and recent change history to see whether any legitimate new dependency explains this destination, and if no documented business justification is found, treat it as a priority finding requiring endpoint investigation on SRV-BUILD04",
            "Allowlist ci-artifact-sync.io immediately so the pipeline doesn't break",
          ],
          answer: 2,
          explanation:
            "The correct balance here is verification before either dismissal or overreaction: a first-time connection from a build server is genuinely ambiguous on its own (new dependencies and artifact sources do get added legitimately), which is exactly why you check the pipeline's own configuration and recent change history for a documented explanation, WHILE ALSO actively fingerprinting the destination and checking it against threat intelligence in parallel. If no legitimate business justification turns up, the combination of a same-day-issued self-signed certificate, a rare/first-ever destination, and no explanatory change record is enough to escalate for full endpoint investigation.",
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
        "A detection rule flagged a TLS session from SRV-BACKUP02 to 10.40.1.40 on port 8006 using a self-signed certificate and a JA3 hash that does not match any common browser or standard library signature in the threat-intel feed. IT change records confirm 10.40.1.40 is the management interface of the company's on-premises backup appliance (a Proxmox Backup Server instance), which has used a vendor-default self-signed certificate since its installation eight months ago, and the connection recurs nightly at the scheduled backup job time.",
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
        dst_port: 8006,
        protocol: "tcp",
        it_verify_result: "confirmed",
        it_verify_message: "10.40.1.40 is the Proxmox Backup Server management appliance, in production since 2025-08; self-signed cert is the vendor default and has not been rotated. Nightly connection matches the scheduled 01:00 backup job.",
        description:
          "SRV-BACKUP02 connects nightly at 01:00 to 10.40.1.40:8006 using a self-signed certificate that has been in place for eight months, with a JA3 not present in the standard-browser reference list",
        raw: {
          "id.orig_h": "10.40.1.55",
          "id.resp_h": "10.40.1.40",
          "id.resp_p": 8006,
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
      context:
        "Using the pattern confirmed in Log Analysis 1 (repeated sessions to one destination, tight interval clustering, near-identical byte counts), write the KQL that would flag this pattern across the whole network without needing to inspect any single session manually first.",
      template:
        "NetworkSessionEvents\n| where DestinationPort == {{port}}\n| summarize SessionCount = count(), AvgBytesOut = avg(BytesSent), StdevBytesOut = stdev(BytesSent) by SourceIp, DestinationIp, JA3Hash\n| where SessionCount > {{threshold}}\n| where StdevBytesOut < {{stdevlimit}}",
      blanks: [
        { id: "port", answers: ["443"], placeholder: "standard HTTPS port" },
        { id: "threshold", answers: ["20", "30", "50"], placeholder: "minimum session count to consider a repeating pattern" },
        { id: "stdevlimit", answers: ["10", "15", "20"], placeholder: "byte-count standard deviation ceiling (low = suspiciously consistent)" },
      ],
      explanation:
        "This mirrors exactly the two signals you evaluated in Log Analysis 1: a high SessionCount to the same destination/JA3 pair, combined with a LOW standard deviation in bytes sent per session. Ordinary browsing produces high variance in request sizes; a beacon's repeated, near-identical check-in produces the opposite — many sessions, tightly clustered byte counts. Grouping by JA3Hash alongside source/destination also lets this same query catch the case where a beacon rotates its destination IP or domain but keeps using the same underlying TLS library/configuration.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "tls-f1",
      prompt:
        "Look at Log Analysis 1, the repeating TLS session investigation. What is the exact ssl.ja3 hash value recorded in the raw log for the WKS-MKT09 sessions? Enter it exactly as shown.",
      answer: "e7d705a3286e19ea42f587b344ee6865",
      hint: "Look for the ssl.ja3 field in the raw block of the WKS-MKT09 session event.",
      xp: 25,
    },
  ],
};

export default [tlsRoom];
