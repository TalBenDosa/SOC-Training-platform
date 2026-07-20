/**
 * Learning Rooms — Batch 17 (Room 2)
 *
 * "DNS Internals, Tunneling & Abuse" (dns-deep-dive)
 *
 * Advanced deep dive into DNS: the full resolution path, record types beyond
 * A/AAAA, DoH/DoT blind spots, DNS tunneling detection (entropy, query length,
 * TXT/NULL volume, query rate), DGA vs legitimate CDN randomness, fast-flux,
 * NXDOMAIN bursts, sinkholes, and the exact fields in Sysmon Event 22 and
 * Zeek dns.log.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ── Log analysis event 1: DNS tunneling captured at the endpoint (Sysmon 22) ─
const dnsTunnelEvent: TelemetryEvent = {
  id: "evt-dns-la1-001",
  ts: "2026-03-04T01:12:44.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "dns_query",
  severity: "high",
  hostname: "WKS-FIN07.solvix.local",
  dns: {
    query: "a3f9e7c1b8d2f04e91a6c5b7d8e2f109c4.updates.solvix-cdn-relay.net",
    query_type: "TXT",
    rcode: "NOERROR",
  },
  description:
    "WKS-FIN07 issued 214 DNS TXT/NULL queries against subdomains of updates.solvix-cdn-relay.net in the last 6 minutes, each with a unique 32-40 character hex-like subdomain label; the query below is one representative sample",
  raw: {
    "winlog.event_id": 22,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.QueryName": "a3f9e7c1b8d2f04e91a6c5b7d8e2f109c4.updates.solvix-cdn-relay.net",
    "winlog.event_data.QueryStatus": "0",
    "winlog.event_data.QueryResults": "type: 16 TXT",
    "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "winlog.event_data.ProcessId": "8844",
    "winlog.event_data.ProcessGuid": "{4a1c7e2b-9f30-6604-1a00-000000004b02}",
    "winlog.event_data.User": "SOLVIX\\r.donahue",
    "winlog.event_data.UtcTime": "2026-03-04 01:12:44.201",
    queries_last_360s: 214,
    unique_subdomains_last_360s: 211,
    avg_query_label_length_chars: 37.4,
    query_type_breakdown_last_360s: { TXT: 168, A: 46 },
  },
};

// ── Log analysis event 2: DGA-shaped NXDOMAIN burst over the network ────────
const dgaBurstEvent: TelemetryEvent = {
  id: "evt-dns-la2-001",
  ts: "2026-03-06T14:03:18.000Z",
  source: "dns",
  vendor: "Corelight (Zeek)",
  event_type: "dns_query",
  severity: "high",
  hostname: "WKS-OPS22.solvix.local",
  src_ip: "10.40.7.61",
  dns: {
    query: "kqxpzr4t.top",
    query_type: "A",
    rcode: "NXDOMAIN",
  },
  description:
    "WKS-OPS22 queried the corporate DNS resolver for 340 distinct domains within an 8-minute period; 318 of those queries returned NXDOMAIN, and the domain shown below is one representative sample of the failed set",
  raw: {
    "id.orig_h": "10.40.7.61",
    "id.resp_h": "10.40.0.53",
    proto: "udp",
    query: "kqxpzr4t.top",
    qclass_name: "C_INTERNET",
    qtype_name: "A",
    rcode_name: "NXDOMAIN",
    AA: false,
    RD: true,
    RA: true,
    answers: [],
    TTLs: [],
    domains_queried_last_8min: 340,
    nxdomain_count_last_8min: 318,
    distinct_tlds_last_8min: ["top", "xyz", "info", "cc", "biz"],
  },
};

const dnsDeepDiveRoom = {
  id: "dns-deep-dive",
  title: "DNS Internals, Tunneling & Abuse",
  description:
    "Move past 'DNS is the internet's phone book' into the internals a working SOC analyst reads directly: the full resolution path, record types beyond A/AAAA, why DoH/DoT create real monitoring blind spots, the exact statistical signals (entropy, query length, TXT/NULL volume, query rate) that separate DNS tunneling from legitimate traffic, telling DGA malware apart from ordinary CDN randomness, fast-flux infrastructure and sinkholing, and the precise fields in Sysmon Event 22 and Zeek dns.log you'll pull for every DNS investigation.",
  difficulty: "advanced" as const,
  category: "Network Security" as const,
  estimatedMinutes: 65,
  xp: 400,
  icon: "🧭",
  prerequisites: ["networking-protocols", "dns-investigation"],
  tasks: [
    // ── Reading 1: full resolution path ──────────────────────────────────────
    {
      type: "reading" as const,
      id: "dns-r1",
      heading: "The Full DNS Resolution Path, End to End",
      content:
        `Beginner training teaches "DNS translates names to IPs." An analyst needs the full mechanics, because tunneling, fast-flux, and DGA detection all depend on understanding exactly which hop in this chain sees what.\n\n` +
        `**Stub resolver -> recursive resolver -> iterative lookups**\n\n` +
        `Your device runs a lightweight **stub resolver** that doesn't know how to walk the DNS hierarchy itself — it just asks a configured **recursive resolver** (your corporate DNS server, your ISP's resolver, or a public resolver like 8.8.8.8/1.1.1.1) to do the work and hand back a final answer. The recursive resolver is the one that actually performs **iterative** lookups on your behalf: it asks a root server "who handles .com?", gets referred to the .com TLD servers, asks them "who handles solvix.com?", gets referred to solvix.com's authoritative nameservers, and finally asks those nameservers for the actual A record. Only the recursive resolver ever talks to the root/TLD/authoritative chain; your device only ever talks to the recursive resolver.\n\n` +
        `**Caching and TTL**\n\n` +
        `Every DNS answer carries a **Time To Live (TTL)**, in seconds, telling every resolver and client along the way how long they're allowed to cache and reuse that answer before asking again. Short TTLs (seconds to a few minutes) mean an operator wants to be able to change the answer quickly — legitimate for load-balanced/CDN infrastructure and DNS-based failover, but also the exact mechanism fast-flux botnets abuse to rotate through many bot IPs rapidly. Long TTLs (hours to a day) mean the answer is expected to be stable and every resolver in the chain will happily serve the cached copy without re-asking, which reduces load but also means a malicious DNS response, once cached, can persist in intermediate caches for a while even after the authoritative record is fixed.\n\n` +
        `**Why this matters for your visibility as an analyst**\n\n` +
        `If your organization forces all clients to use the corporate recursive resolver (and blocks direct outbound port 53/853/443-to-known-DoH-providers at the firewall), then every single name resolution any device performs passes through one point you can log, filter, and alert on. If clients can freely choose their own resolver — a public recursive resolver, a device that hard-codes 8.8.8.8, or a browser configured to use encrypted DNS directly to a third party — some or all of that visibility disappears, because those queries never touch your corporate resolver's logs at all. Nearly every technique in this room assumes you have at least query-level visibility somewhere in this chain; the next reading covers exactly when that assumption breaks down.`,
      codeExample:
        "THE FULL RESOLUTION PATH FOR 'mail.solvix.com'\n" +
        "=======================================================\n" +
        "1. Stub resolver (your laptop) checks its local cache\n" +
        "2. Cache miss -> asks the configured recursive resolver\n" +
        "   (e.g. 10.40.0.53, the corporate DNS server)\n" +
        "3. Recursive resolver asks a ROOT server:\n" +
        "     \"who handles .com?\" -> referred to .com TLD servers\n" +
        "4. Recursive resolver asks a .com TLD server:\n" +
        "     \"who handles solvix.com?\" -> referred to solvix.com's\n" +
        "     authoritative nameservers\n" +
        "5. Recursive resolver asks solvix.com's authoritative NS:\n" +
        "     \"what is the A record for mail.solvix.com?\"\n" +
        "6. Authoritative NS answers: 198.51.100.22, TTL=300\n" +
        "7. Recursive resolver caches the answer for 300s, returns\n" +
        "   it to the stub resolver, which also caches it locally\n" +
        "=======================================================\n\n" +
        "TTL: SHORT vs LONG -- THE SECURITY TRADE-OFF\n" +
        "=======================================================\n" +
        "Short TTL (secs-mins)  Fast failover/load-balancing, BUT\n" +
        "                       also enables rapid IP rotation --\n" +
        "                       exactly what fast-flux abuses\n" +
        "Long TTL (hours-day)   Efficient caching, BUT a poisoned\n" +
        "                       or malicious answer persists in\n" +
        "                       caches longer once it gets in\n" +
        "=======================================================",
    },

    // ── Reading 2: record types + DoH/DoT blind spots ────────────────────────
    {
      type: "reading" as const,
      id: "dns-r2",
      heading: "DNS Record Types Beyond A/AAAA, and Why DoH/DoT Blind Your Monitoring",
      content:
        `**Record types you'll actually use in investigations**\n\n` +
        `Beyond A (IPv4) and AAAA (IPv6): CNAME aliases one name to another (heavily used by CDNs and cloud services — investigating a suspicious hostname often means chasing a CNAME chain to find where it truly resolves); MX identifies which servers handle mail for a domain (relevant to email spoofing/BEC investigations); NS identifies a domain's authoritative nameservers (a domain whose NS records changed recently, or point to a bulletproof/disposable DNS provider, is a signal worth weighing); TXT holds arbitrary text — used legitimately for SPF/DKIM/domain-verification records, but also, as you'll see, one of the favorite record types for DNS tunneling because it can carry substantially more data per response than an A record; PTR is the reverse of A — IP-to-name lookup, useful for sanity-checking whether an IP's reverse DNS matches what it claims to be; SRV and NULL records are rarer in normal traffic and are worth extra scrutiny purely because of that rarity — NULL records in particular have essentially no legitimate modern use case and their appearance at all is itself informative.\n\n` +
        `**DoH and DoT: encrypting DNS, and what it costs you**\n\n` +
        `Traditional DNS travels in cleartext UDP/TCP on port 53 — trivially visible to any network monitoring tool. **DoT (DNS over TLS)**, on port 853, and **DoH (DNS over HTTPS)**, tunneled inside normal HTTPS traffic on port 443, both encrypt the query and response, primarily to stop on-path eavesdropping and tampering (ISP DNS hijacking, in-flight manipulation). This is a genuine privacy and integrity win for the end user — and a genuine blind spot for a SOC that relies on inspecting DNS query content. With DoT, at minimum you can still see that a connection is happening on port 853, to which destination, and you can block the port outright if you choose. With DoH, the query is indistinguishable at the network layer from any other HTTPS request to the same destination — a client resolving via Cloudflare's DoH endpoint (1.1.1.1's HTTPS DoH service) looks, from a flow-record perspective, identical to a client just browsing to a page hosted at that same IP, unless you're doing full TLS inspection (see the TLS room) or you specifically fingerprint/blocklist known public DoH provider endpoints.\n\n` +
        `**Why this matters operationally**\n\n` +
        `Malware and legitimate privacy-focused browsers alike increasingly default to DoH. If your organization allows clients to reach arbitrary DoH providers over port 443, an infected host can resolve a C2 domain, or tunnel data through DNS query patterns, entirely outside your visibility — the query never appears in your corporate resolver's logs, and it's indistinguishable from ordinary HTTPS traffic at the flow level. The standard mitigation is to explicitly block or intercept traffic to known public DoH resolver IP/domain lists and force all resolution through an internally-controlled resolver (or an internally-hosted DoH/DoT endpoint you do log), converting an invisible channel back into a visible, filterable one.`,
      codeExample:
        "DNS RECORD TYPES AN ANALYST ACTUALLY USES\n" +
        "=======================================================\n" +
        "A       IPv4 address\n" +
        "AAAA    IPv6 address\n" +
        "CNAME   Alias to another name (common CDN/cloud pattern)\n" +
        "MX      Mail server for the domain (email/BEC investigations)\n" +
        "NS      Authoritative nameservers for the domain\n" +
        "TXT     Arbitrary text (SPF/DKIM, but also a favorite\n" +
        "        tunneling record -- carries more data per reply)\n" +
        "PTR     Reverse lookup, IP -> name\n" +
        "NULL    Raw binary data, essentially no legitimate modern\n" +
        "        use -- rare enough that seeing one at all matters\n" +
        "=======================================================\n\n" +
        "PLAINTEXT DNS vs DoT vs DoH -- WHAT A SOC CAN SEE\n" +
        "=======================================================\n" +
        "                Port    Query content visible?  Can block\n" +
        "                                                 by port?\n" +
        "-------------------------------------------------------\n" +
        "Plain DNS       53      YES, fully cleartext      Yes\n" +
        "DoT             853     No (TLS-encrypted)        Yes (853)\n" +
        "DoH             443     No (looks like any HTTPS) Only via\n" +
        "                        request to same IP         known-\n" +
        "                                                   provider\n" +
        "                                                   blocklists\n" +
        "                                                   or TLS\n" +
        "                                                   inspection\n" +
        "=======================================================",
    },

    // ── Reading 3: DNS tunneling detection ───────────────────────────────────
    {
      type: "reading" as const,
      id: "dns-r3",
      heading: "DNS Tunneling: How Data Hides Inside Queries, and the Statistics That Reveal It",
      content:
        `DNS tunneling encodes arbitrary data — commands, files, C2 traffic — inside DNS queries and responses, exploiting the fact that DNS is almost universally allowed outbound through firewalls (blocking it breaks name resolution entirely) and is rarely fully content-inspected the way HTTP traffic is.\n\n` +
        `**How the encoding actually works**\n\n` +
        `A tunneling client (tools like iodine, dnscat2, or a DNS-based C2 channel in frameworks like Cobalt Strike) needs a channel in both directions. Outbound (client-to-server) data is encoded directly into the **subdomain labels** of the query itself — e.g. querying a3f9e7c1b8d2f04e91a6c5b7d8e2f109c4.updates.example.net, where the long hex/base32-looking label isn't a real hostname at all, it's encoded payload data, and updates.example.net is the attacker-controlled domain whose authoritative nameserver is the tunneling server, decoding each incoming query as it arrives. Inbound (server-to-client) data rides back in the **response**, most commonly using TXT records (which permit larger, more flexible text payloads than an A record's 4 bytes) or, less commonly today, NULL records (raw binary, but rare enough to be conspicuous on its own) or chains of CNAME responses.\n\n` +
        `**The statistical signals that separate tunneling from normal DNS**\n\n` +
        `- **Subdomain entropy.** Real hostnames are built from human-readable words and predictable patterns; encoded tunnel payloads look like near-random hex/base32/base64 strings. Shannon entropy — a measure of how unpredictable a string's characters are — is dramatically higher for encoded payload labels than for legitimate hostnames. A subdomain like "a3f9e7c1b8d2f04e91a6c5b7d8e2f109c4" scores close to the theoretical maximum for its character set; "www" or "checkout-api" does not.\n` +
        `- **Query length.** DNS labels max out at 63 characters and full names at 255; legitimate hostnames rarely approach either limit. Tunneling tools maximize label length to squeeze the most payload into each query, so queries consistently running 40+ characters in the leftmost label are a strong signal.\n` +
        `- **Query rate and volume per host.** Because each individual DNS query/response pair only carries a small amount of payload (tens to low hundreds of bytes), moving any meaningful amount of data requires a very high query rate — hundreds of queries in minutes from a single host is far outside normal application behavior (a normal workstation might resolve a few dozen distinct hostnames per hour during active browsing, not hundreds of unique subdomains under one parent domain in minutes).\n` +
        `- **TXT/NULL record volume specifically.** A host suddenly issuing a large volume of TXT (or any NULL) queries, especially concentrated against one or two parent domains, is unusual — TXT lookups are normally a small minority of any host's total DNS traffic (mostly used by mail servers checking SPF, not workstations).\n` +
        `- **Uniqueness of subdomains under one parent.** Legitimate applications reuse a small, stable set of hostnames. A tunneling channel, because each query IS a data chunk, produces an enormous number of never-repeated, unique subdomains under the same parent domain — a ratio of unique_subdomains ≈ total_queries is itself the tell.\n\n` +
        `**Why no single signal is used alone**\n\n` +
        `High entropy alone can occur legitimately (hashed cache-busting URLs, some CDN subdomain schemes — covered in the next reading). High volume alone can be a busy proxy server doing normal resolution on behalf of many users. It's the **combination** — high entropy, near-maximum label length, high query rate, disproportionate TXT/NULL usage, and a near-1:1 ratio of unique subdomains to total queries, all against the same parent domain, from the same host — that turns a set of individually explainable signals into a confident tunneling detection.`,
      codeExample:
        "SHANNON ENTROPY -- WHY IT SEPARATES TUNNEL PAYLOADS FROM WORDS\n" +
        "=======================================================\n" +
        "Entropy = -sum( p(c) * log2(p(c)) ) over each character c\n" +
        "in the string, where p(c) is that character's frequency.\n" +
        "\n" +
        "\"checkout-api\"                    entropy ~ 3.0 bits/char\n" +
        "  (predictable letters, common words, low randomness)\n" +
        "\n" +
        "\"a3f9e7c1b8d2f04e91a6c5b7d8e2f109c4\" entropy ~ 3.9 bits/char\n" +
        "  (near-uniform hex distribution -- close to the max\n" +
        "   possible for a 16-character alphabet, log2(16)=4.0)\n" +
        "=======================================================\n\n" +
        "TUNNELING DETECTION SIGNAL CHECKLIST\n" +
        "=======================================================\n" +
        "[ ] Subdomain entropy near the theoretical max for its\n" +
        "    character set\n" +
        "[ ] Query label length consistently 40+ characters\n" +
        "[ ] Query rate/volume far above this host's own baseline\n" +
        "[ ] Disproportionate share of TXT or any NULL queries\n" +
        "[ ] unique_subdomains / total_queries ratio near 1.0\n" +
        "    (almost every query is a NEW, never-repeated label)\n" +
        "[ ] All of the above concentrated against one parent domain\n" +
        "=======================================================",
    },

    // ── Reading 4: DGA vs legitimate CDN randomness ──────────────────────────
    {
      type: "reading" as const,
      id: "dns-r4",
      heading: "DGA Malware vs. Legitimate CDN Randomness: Telling Them Apart",
      content:
        `Random-looking subdomains are not, by themselves, evidence of anything malicious — plenty of completely legitimate infrastructure generates them constantly. Cloud storage buckets, CDN edge nodes, load-balancer session routing, and collaboration-tool relay servers all commonly use algorithmically generated, high-entropy subdomains (a random S3 bucket name, an Azure Blob Storage account, a CloudFront distribution ID, a Teams/Skype relay node). Confusing this with a **Domain Generation Algorithm (DGA)** — malware's technique for generating hundreds or thousands of candidate C2 domain names algorithmically, so a single hardcoded domain can't be blocklisted or taken down — is a common and costly false-positive trap. Telling them apart reliably comes down to four differentiators.\n\n` +
        `**1. Success rate: NXDOMAIN ratio**\n\n` +
        `This is the single strongest differentiator. A DGA generates domains algorithmically without knowing in advance which ones the attacker has actually registered — the attacker typically registers only a small handful out of the thousands the algorithm can produce, often just one at a time, rotating which one is "live." This means a DGA-infected host querying its full candidate list will see the overwhelming majority of queries fail with NXDOMAIN (domain doesn't exist), with only a rare success. Legitimate CDN/cloud randomness, by contrast, resolves successfully essentially every time — a random-looking CloudFront or S3 subdomain is still a real, currently-provisioned resource, so it always returns a valid answer. A burst of hundreds of queries with a 90%+ NXDOMAIN rate is a DGA fingerprint; a burst of hundreds of queries that all resolve successfully is not.\n\n` +
        `**2. Parent domain and TLD reputation**\n\n` +
        `Legitimate CDN randomness sits under a small, well-known set of parent domains you'll recognize immediately (cloudfront.net, s3.amazonaws.com, blob.core.windows.net, akamaized.net). DGA-generated domains are typically registered fresh, often under cheap or historically abuse-heavy TLDs (.top, .xyz, .info, .cc, .biz turn up disproportionately often in DGA activity, though this shifts as defenders adapt and is never conclusive alone), and the parent "domain" itself changes constantly — because in a DGA, the randomness isn't confined to a subdomain under one stable parent, the entire second-level domain is generated fresh each time.\n\n` +
        `**3. Domain age**\n\n` +
        `A DGA-registered domain is, almost by definition, extremely newly registered — often minutes to days before use, since registering thousands of domains in advance is both expensive and creates a large static blocklist target. A "Newly Registered Domain (NRD)" check against WHOIS/domain-age threat intelligence is one of the highest-value enrichments you can add to any suspicious-domain investigation. Legitimate CDN infrastructure domains, by contrast, are typically years old and extremely well-established.\n\n` +
        `**4. Volume and pattern per host**\n\n` +
        `A DGA-infected host typically queries its candidate list in a tight burst — many distinct, algorithmically-generated second-level domains in a short window, trying each until one resolves (or giving up until the next scheduled check-in). Legitimate CDN/cloud randomness usually appears as a small number of distinct random subdomains, resolved once, then reused/cached for a while — not hundreds of never-repeated top-level random domains queried back-to-back.\n\n` +
        `**Putting it together**\n\n` +
        `A burst of hundreds of distinct, freshly-registered, mostly-NXDOMAIN domains under constantly-changing second-level names, disproportionately on low-reputation TLDs, from one host in a short window, is DGA behavior. A modest number of high-entropy subdomains that all resolve successfully, live under a small set of well-known, long-established parent domains, is ordinary CDN/cloud traffic — even though, on entropy alone, the two can look deceptively similar.`,
      codeExample:
        "DGA vs LEGITIMATE CDN RANDOMNESS -- SIDE BY SIDE\n" +
        "=======================================================\n" +
        "                    DGA malware        Legit CDN/cloud\n" +
        "-------------------------------------------------------\n" +
        "NXDOMAIN rate       Very high (>90%)   Near zero\n" +
        "Parent domain        Changes constantly  Small, stable,\n" +
        "                     (2nd-level itself   well-known set\n" +
        "                     is randomized)       (cloudfront.net,\n" +
        "                                          s3.amazonaws.com)\n" +
        "Domain age           Very new (mins-days) Years old,\n" +
        "                     (Newly Registered     well-established\n" +
        "                     Domain)\n" +
        "TLD pattern           Often cheap/abuse-   Standard, well-\n" +
        "                      heavy TLDs (.top,     known TLDs\n" +
        "                      .xyz, .info, .cc)\n" +
        "Query pattern         Burst of hundreds of  Small number of\n" +
        "                      never-repeated 2LDs,  random subdomains,\n" +
        "                      trying each until one resolved once,\n" +
        "                      resolves              reused/cached\n" +
        "=======================================================",
    },

    // ── Reading 5: fast-flux and sinkholes ────────────────────────────────────
    {
      type: "reading" as const,
      id: "dns-r5",
      heading: "Fast-Flux DNS and Sinkholes",
      content:
        `**Fast-flux: hiding infrastructure behind a rotating army of IPs**\n\n` +
        `Fast-flux is an infrastructure-resilience technique used by botnets and phishing/malware hosting operations: a single domain name is configured with an extremely short TTL (often 60-300 seconds) and its A records rotate rapidly through a large, constantly-changing pool of IP addresses — frequently the IPs of already-compromised residential/consumer devices acting as reverse proxies in front of the real backend. The effect is that even if a defender identifies and blocks or takes down one of the IPs currently associated with the malicious domain, the domain simply resolves to a different IP shortly after (governed by that short TTL), and the malicious service stays reachable. This makes IP-based blocking largely ineffective against fast-flux infrastructure — the domain itself, not any single IP, has to be the target of a takedown or blocklist.\n\n` +
        `**Double-flux: rotating the nameservers too**\n\n` +
        `A more resilient variant, double-flux, rotates not just the A records but the domain's own authoritative NS records as well, through a similarly large, changing pool. This means even identifying and taking down the domain's nameserver infrastructure doesn't reliably kill the domain, because the NS delegation itself keeps moving. Double-flux setups are harder to build and less common, but appear in more sophisticated, well-resourced criminal infrastructure.\n\n` +
        `**Detecting fast-flux from DNS logs alone**\n\n` +
        `The signature is directly visible in resolution history: querying the same domain name repeatedly over a short period returns a **different A record each time**, each with a very short TTL, and the returned IPs frequently span multiple, unrelated hosting providers or even multiple countries/ASNs — a pattern completely unlike legitimate load-balanced infrastructure, which typically rotates among a small, stable, well-documented pool of IPs within one provider's known ranges. A domain whose resolution history shows dozens of distinct IPs across dozens of different networks within a single day is a strong fast-flux indicator.\n\n` +
        `**DNS sinkholing: turning the malicious channel into a detection tool**\n\n` +
        `A **sinkhole** is a defensive technique where a known-malicious or high-confidence-suspicious domain is deliberately made to resolve — either at your own internal resolver, or via cooperation with upstream registrars/researchers at internet scale — to an IP address you (or a trusted third party like a CERT) control, instead of its real, attacker-operated infrastructure. The immediate defensive benefit is obvious: infected hosts trying to reach that domain for C2 instructions or further payloads simply can't reach the real attacker infrastructure anymore. But the detection benefit is arguably even more valuable: **the sinkhole's own connection/web logs now tell you exactly which internal hosts are infected**, because any device on your network attempting to resolve or connect to that domain is, by definition, running something that's trying to reach it — a query hitting your sinkhole is itself a compromise indicator for the querying host, with essentially zero false positives, since no legitimate software should ever be trying to reach a domain you've deliberately sinkholed. Many organizations treat "internal host resolved or connected to a known sinkholed domain" as one of their highest-confidence, lowest-noise detection rules precisely for this reason.`,
      codeExample:
        "FAST-FLUX SIGNATURE IN A dns.log RESOLUTION HISTORY\n" +
        "=======================================================\n" +
        "Same domain, queried repeatedly, over 20 minutes:\n" +
        "\n" +
        "14:00:02  update-relay-svc.net -> 41.223.18.4    TTL=60\n" +
        "14:01:19  update-relay-svc.net -> 187.44.201.9   TTL=60\n" +
        "14:02:31  update-relay-svc.net -> 93.174.95.16   TTL=60\n" +
        "14:03:47  update-relay-svc.net -> 5.188.62.11    TTL=60\n" +
        "14:05:02  update-relay-svc.net -> 41.223.18.101  TTL=60\n" +
        "\n" +
        "  -> 5 distinct IPs, 5 different networks/countries,\n" +
        "     in 5 minutes, TTL pinned at 60s every time\n" +
        "  -> NOT what a normal CDN/load-balancer pool looks like\n" +
        "     (typically a small, stable set within one provider)\n" +
        "=======================================================\n\n" +
        "WHY A SINKHOLE HIT IS SUCH HIGH-CONFIDENCE EVIDENCE\n" +
        "=======================================================\n" +
        "Sinkhole domain resolves to YOUR controlled IP instead\n" +
        "of the attacker's real infrastructure.\n" +
        "\n" +
        "Any internal host querying/connecting to it at all means:\n" +
        "  - No legitimate software has any reason to reach it\n" +
        "  - The querying host is running something that DOES\n" +
        "  = near-zero false-positive compromise indicator\n" +
        "=======================================================",
    },

    // ── Reading 6: Sysmon 22 + Zeek dns.log fields ────────────────────────────
    {
      type: "reading" as const,
      id: "dns-r6",
      heading: "The Exact Fields: Sysmon Event 22 (DNS Query) and Zeek dns.log",
      content:
        `Two DNS log sources dominate real investigations, and they answer fundamentally different questions — knowing which one to pull, and which fields matter in each, is what separates a fast investigation from a slow one.\n\n` +
        `**Sysmon Event ID 22 — DNS query, from the endpoint**\n\n` +
        `Sysmon runs on the endpoint itself and hooks DNS resolution at the process level, which means it can answer the question no purely network-based DNS log ever can: **which process, on which host, run by which user, made this specific query?** Key fields: QueryName (the domain/subdomain queried), QueryStatus (the resolution result code — 0 means success), QueryResults (the actual answer(s) returned, often including the record type), Image (the full path to the executable that issued the query — this is the field that turns "someone queried a suspicious domain" into "powershell.exe queried a suspicious domain," a completely different investigation), ProcessId/ProcessGuid (for pivoting into the rest of that process's Sysmon telemetry — its parent process, command line, any files it touched, any other network connections it made), and User (the account context). When your investigation needs to answer "what on this machine is doing this," Sysmon 22 is the log you need — and it's frequently the only source that can answer it at all, since by the time a query reaches your network-level DNS sensor or resolver, all process context has already been stripped away.\n\n` +
        `**Zeek dns.log — the network-wide view**\n\n` +
        `Zeek observes DNS traffic on the wire, network-wide, regardless of which specific process or even which specific host originated it (useful when you don't yet have endpoint agents deployed everywhere, or when you need visibility into non-Windows/unmanaged/IoT devices that don't run Sysmon at all). Key fields: id.orig_h/id.resp_h (querying host and resolver), query (the full queried name), qclass_name/qtype_name (query class, almost always C_INTERNET, and query type — A, TXT, NULL, etc.), rcode_name (the response code — NOERROR for success, NXDOMAIN for non-existent domain, SERVFAIL for a resolution failure), AA/TC/RD/RA (flags: Authoritative Answer, TrunCated, Recursion Desired, Recursion Available), answers (the actual list of returned values), and TTLs (the TTL for each answer, in parallel array position with answers). Because Zeek sees every DNS packet regardless of source, it's the natural place to compute the aggregate, cross-host statistics (query rate, unique-subdomain ratios, NXDOMAIN bursts) that tunneling and DGA detection depend on — those patterns are visible network-wide in a way no single endpoint's Sysmon log alone can show you.\n\n` +
        `**Using them together**\n\n` +
        `In practice the strongest investigations pivot between both: Zeek's dns.log (or your DNS resolver's own query logs) surfaces the aggregate statistical anomaly across the whole network — one host with an abnormal NXDOMAIN rate, or a burst of high-entropy TXT queries — and Sysmon Event 22 on that specific flagged host then answers exactly which process caused it, which is the detail you need before you can act (kill a process, isolate a host, or clear a false positive caused by, say, a legitimate but chatty background service).`,
      codeExample:
        "SYSMON EVENT ID 22 (DNS QUERY) -- KEY FIELDS\n" +
        "=======================================================\n" +
        "UtcTime          Timestamp of the query\n" +
        "QueryName        The domain/subdomain queried\n" +
        "QueryStatus      Resolution result code (0 = success)\n" +
        "QueryResults     Actual answer(s) returned, incl. record type\n" +
        "Image            Full path of the process that queried it\n" +
        "ProcessId /\n" +
        "ProcessGuid      Pivot key into the rest of that process's\n" +
        "                 Sysmon telemetry (parent, cmdline, files...)\n" +
        "User             Account context the process ran as\n" +
        "=======================================================\n\n" +
        "ZEEK dns.log -- KEY FIELDS\n" +
        "=======================================================\n" +
        "id.orig_h / id.resp_h   Querying host / resolver used\n" +
        "query                   Full queried domain name\n" +
        "qclass_name / qtype_name  Query class (C_INTERNET) / type\n" +
        "                          (A, AAAA, TXT, NULL, MX, ...)\n" +
        "rcode_name              NOERROR / NXDOMAIN / SERVFAIL / ...\n" +
        "AA / TC / RD / RA        Authoritative / Truncated /\n" +
        "                         Recursion Desired / Recursion\n" +
        "                         Available flags\n" +
        "answers                 Returned value(s)\n" +
        "TTLs                    TTL per answer (parallel array)\n" +
        "=======================================================\n\n" +
        "WHICH SOURCE ANSWERS WHICH QUESTION\n" +
        "=======================================================\n" +
        "\"Which process on which host did this?\"  -> Sysmon 22\n" +
        "\"Is this pattern happening network-wide,\n" +
        " and what's the aggregate statistical shape?\" -> Zeek dns.log\n" +
        "=======================================================",
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dns-q1",
      question:
        "A host issues 200 DNS TXT queries in three minutes, each to a different, never-repeated subdomain (average label length 41 characters, high measured entropy) under the same parent domain. Which single additional data point would most strengthen a tunneling determination versus a benign explanation?",
      options: [
        "The parent domain's WHOIS registration date and country",
        "Whether nearly all 200 subdomains are unique, never-repeated labels (a ratio near 1.0 of unique-to-total queries) rather than a small set of values being requested repeatedly",
        "The TTL value returned in the DNS response",
        "Whether the workstation's screen resolution matches company standard",
      ],
      answer: 1,
      explanation:
        "A near-1:1 ratio of unique subdomains to total queries is one of the strongest tunneling-specific signals, because it reflects the core mechanic of the technique: each query IS a chunk of encoded payload data, so almost no query is ever repeated. High entropy and long labels alone can have other explanations (some legitimate cache-busting or CDN schemes also produce high-entropy strings); it's the combination with a near-total lack of repetition, high volume, and TXT-record concentration that makes the case strong.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dns-q2",
      question:
        "One host generates a burst of 300 DNS queries to 300 different, freshly-changing second-level domains in five minutes, with a 96% NXDOMAIN rate. Another host resolves 40 different, high-entropy subdomains, all under d111abcd8ef9it.cloudfront.net, all of which resolve successfully. Which is more consistent with DGA malware, and why?",
      options: [
        "The second host — high entropy is always the strongest DGA signal regardless of resolution outcome",
        "The first host — the overwhelming NXDOMAIN rate against constantly-changing second-level domains is the DGA fingerprint (the malware doesn't know in advance which of its algorithmically-generated candidates the attacker has actually registered); the second host's pattern — successful resolutions under a small, stable, well-known CDN parent domain — is the fingerprint of ordinary CDN/cloud traffic",
        "Neither is suspicious, since both involve high query volume which is normal on any corporate network",
        "The second host, because cloudfront.net is a well-known malware distribution platform",
      ],
      answer: 1,
      explanation:
        "NXDOMAIN rate is the single strongest DGA-vs-legitimate-randomness differentiator: DGA malware generates far more candidate domains than an attacker actually registers, so the vast majority fail to resolve. Legitimate CDN/cloud subdomains, even when high-entropy, resolve successfully essentially every time because they're real, currently-provisioned resources under a small set of well-known, long-established parent domains (cloudfront.net here). High entropy alone, without the NXDOMAIN and constantly-changing-parent-domain pattern, is not sufficient to call something DGA.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dns-q3",
      question:
        "Your Zeek dns.log shows an aggregate NXDOMAIN burst from workstation 10.40.7.61 across dozens of freshly-registered domains. You want to know exactly what process on that workstation is generating these queries. Which log source answers that question, and why can Zeek's dns.log not answer it on its own?",
      options: [
        "Zeek's dns.log itself can answer this — the id.orig_h field already identifies the exact process",
        "Sysmon Event ID 22 on that specific host, because it hooks DNS resolution at the process level (fields like Image and ProcessId) — Zeek only observes network traffic and has no visibility into which process on the sending host issued any given query",
        "The corporate DHCP server logs, because they record which process requested each IP lease",
        "No log source can ever answer this question after the fact; only a live memory dump can",
      ],
      answer: 1,
      explanation:
        "Zeek (and any purely network-based DNS log) sees which host sent a query (id.orig_h) but has no visibility whatsoever into which process on that host generated it — that context simply doesn't exist on the wire. Sysmon Event 22 runs on the endpoint and hooks DNS resolution at the OS/process level specifically to capture that missing context (Image, ProcessId, ProcessGuid, User), which is exactly why endpoint DNS logging and network DNS logging are complementary, not redundant.",
      xp: 25,
    },

    // ── Log Analysis 1: DNS tunneling via Sysmon 22 ──────────────────────────
    {
      type: "log_analysis" as const,
      id: "dns-la1",
      heading: "Investigating a Burst of High-Entropy TXT Queries",
      context:
        "WKS-FIN07 belongs to r.donahue in Accounts Payable. EDR telemetry shows this workstation has issued 214 DNS queries in the last 6 minutes, almost entirely against subdomains of updates.solvix-cdn-relay.net — a domain that does not appear anywhere in Solvix's approved vendor/CDN allowlist. Review the representative Sysmon Event ID 22 record below.",
      event: dnsTunnelEvent,
      questions: [
        {
          question:
            "QueryName is 'a3f9e7c1b8d2f04e91a6c5b7d8e2f109c4.updates.solvix-cdn-relay.net' with QueryResults showing a TXT record answer. Combined with avg_query_label_length_chars: 37.4 and unique_subdomains_last_360s: 211 out of queries_last_360s: 214, what does this combination suggest?",
          options: [
            "This is normal CDN cache-busting behavior — long random labels under a CDN-style domain name are completely routine",
            "The near-1:1 ratio of unique subdomains to total queries, combined with a consistently long, high-entropy label and a preference for TXT responses, matches the statistical signature of DNS tunneling — each query behaving like a distinct chunk of encoded data rather than a repeated, cacheable hostname",
            "QueryStatus 0 means the query failed, which rules out any data actually being transmitted",
            "TXT records cannot be requested by a Windows DNS client, so this must be a logging error",
          ],
          answer: 1,
          explanation:
            "QueryStatus 0 actually means the query SUCCEEDED (0 is the success code), so data-carrying responses were returned. The near-total lack of repeated subdomains (211 unique out of 214 queries), the consistently long ~37-character labels, and the skew toward TXT (168 of 214) together match the DNS tunneling signature described in Reading 3 far more closely than any explanation involving a small set of stable, reused CDN hostnames.",
          xp: 25,
        },
        {
          question:
            "The Image field shows 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' as the process issuing these queries, running as SOLVIX\\r.donahue. Why does this specific field matter to the investigation, beyond confirming which host made the queries?",
          options: [
            "It doesn't matter — DNS investigations should stop at the network layer and never need process context",
            "It tells the analyst exactly which process to pivot into next — PowerShell issuing hundreds of high-entropy DNS TXT queries directly (rather than, say, a browser or an approved backup agent) is a very different and more actionable finding, and this ProcessId can now be used to pull the rest of that process's Sysmon telemetry: its parent process, full command line, and any other activity",
            "PowerShell can never make DNS queries directly, so this field must indicate the log was tampered with",
            "It confirms r.donahue personally typed the malicious command interactively at the keyboard",
          ],
          answer: 1,
          explanation:
            "This is exactly the advantage Sysmon Event 22 has over network-only DNS logs: it tells you WHICH process did this. PowerShell directly issuing this volume of high-entropy TXT queries — rather than a recognized, approved application — is a significant, actionable detail, and ProcessGuid/ProcessId let the analyst immediately pivot to that process's full ancestry and command line to determine how it was launched (a script, a scheduled task, an interactive session, or another process spawning it) before concluding intent.",
          xp: 25,
        },
        {
          question:
            "What is the correct next investigative step given everything observed so far?",
          options: [
            "Close the finding since QueryStatus 0 indicates the DNS server behaved normally",
            "Pull the full Sysmon process tree for ProcessGuid {4a1c7e2b-9f30-6604-1a00-000000004b02} to find the PowerShell process's parent, command line, and launch mechanism; block/sinkhole solvix-cdn-relay.net at the resolver; and treat WKS-FIN07 as requiring isolation and full endpoint investigation given the volume and shape of this traffic",
            "Rename the workstation to remove it from the corporate DNS zone",
            "Add solvix-cdn-relay.net to the approved CDN allowlist since it resembles a legitimate CDN naming pattern",
          ],
          answer: 1,
          explanation:
            "With a strong statistical tunneling signature plus process-level attribution to PowerShell rather than an approved application, the priority is understanding how that PowerShell process was launched (pulling its Sysmon process ancestry via ProcessGuid), cutting off the channel itself (blocking or sinkholing the domain at the resolver so any ongoing communication stops immediately), and treating the endpoint as compromised pending full investigation — not closing the finding or, worse, allowlisting the very domain generating the suspicious traffic.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: DGA-shaped NXDOMAIN burst ────────────────────────────
    {
      type: "log_analysis" as const,
      id: "dns-la2",
      heading: "A Burst of Failed Lookups Against Freshly-Changing Domains",
      context:
        "The corporate resolver's aggregate query logs flagged WKS-OPS22 (10.40.7.61) for an unusual failure rate. In an 8-minute window, this host queried 340 distinct domains, of which 318 returned NXDOMAIN. Review the representative Zeek dns.log record below, one of the failed queries from that set.",
      event: dgaBurstEvent,
      questions: [
        {
          question:
            "The sample query is for 'kqxpzr4t.top' and rcode_name is 'NXDOMAIN', with distinct_tlds_last_8min showing top, xyz, info, cc, and biz. Combined with nxdomain_count_last_8min: 318 out of domains_queried_last_8min: 340, what pattern does this match most closely?",
          options: [
            "A misconfigured internal application repeatedly retrying the same failed hostname due to a typo",
            "The pattern matches DGA malware behavior: a high volume of distinct, freshly-changing second-level domains, spread across several low-reputation TLDs, with an overwhelming (93.5%) NXDOMAIN rate — consistent with malware working through an algorithmically-generated candidate list, most of which the attacker never actually registered",
            "This is expected behavior for any host running a modern web browser with DNS prefetching enabled",
            "The NXDOMAIN rate proves this is entirely benign, since a failed lookup means no data was ever transmitted",
          ],
          answer: 1,
          explanation:
            "A 93.5% NXDOMAIN rate against 340 distinct, changing second-level domains spread across several TLDs historically associated with cheap/abuse-heavy registration (.top, .xyz, .info, .cc, .biz) is the fingerprint described in Reading 4: DGA malware generates far more candidate domains than the attacker registers, so the vast majority fail. A repeated single-hostname typo would show one repeated domain, not 340 distinct ones; DNS prefetching resolves real page-linked hostnames, which would show a low NXDOMAIN rate, not 93.5%.",
          xp: 25,
        },
        {
          question:
            "Why is the query volume and NXDOMAIN rate a stronger differentiator here than entropy alone would be?",
          options: [
            "Entropy is never useful in any DNS investigation and should be ignored entirely",
            "Because 'kqxpzr4t.top' has only moderate entropy compared to a true random hex string, and DGA algorithms don't always produce maximally random-looking output — some produce pronounceable or dictionary-word-based domains specifically to evade naive entropy-based detection, which is exactly why NXDOMAIN rate, volume, and changing-parent-domain pattern remain reliable even when entropy alone would be a weaker or inconsistent signal",
            "Entropy can only be computed on TXT record queries, and this event is an A record query",
            "The domain's length exceeds the DNS protocol maximum, invalidating the query entirely",
          ],
          answer: 1,
          explanation:
            "Some DGA families deliberately use word-based or pronounceable generation schemes specifically to defeat entropy-based detection. This is exactly why an experienced analyst leans on multiple, harder-to-evade signals together — NXDOMAIN rate, volume/burst pattern, constantly-changing second-level domains, and TLD reputation — rather than relying on entropy as a single silver-bullet metric, which sophisticated malware authors already design around.",
          xp: 25,
        },
        {
          question:
            "What is the appropriate response given this confirmed pattern?",
          options: [
            "No action needed, since 318 failed lookups mean the malware never successfully reached its C2 infrastructure and therefore caused no harm",
            "Isolate WKS-OPS22 for endpoint investigation (this pattern strongly indicates active malware attempting C2 check-in), preserve the full list of queried domains for threat-intel correlation, and monitor whether any of the 22 domains that DID resolve successfully are now being contacted for follow-on traffic — those are the ones that matter most operationally",
            "Add all 340 domains to the corporate DNS allowlist so future queries succeed and stop generating alerts",
            "Disable DNS logging on this host since the volume is overwhelming the SIEM's ingestion",
          ],
          answer: 1,
          explanation:
            "A DGA burst with a small number of successful resolutions (340 - 318 = 22 successes) means the attacker likely does have live infrastructure behind at least one of those 22 registered domains — those are the highest-priority pivot points, since follow-on C2 traffic or payload delivery would go there next. The correct response is isolating the endpoint for full investigation, not dismissing the finding because most attempts failed (failure to resolve most candidates is the expected DGA pattern, not evidence of no harm) and certainly not allowlisting attacker-controlled domains.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: legitimate browser DoH configuration FP trap ────────
    {
      type: "analyst_choice" as const,
      id: "dns-ac1",
      heading: "Verdict: A Workstation Bypassing the Corporate DNS Resolver Over Port 443",
      scenario:
        "A detection rule fired because WKS-DEV18 established a long-lived, repeating TLS connection on port 443 to 1.1.1.1 (Cloudflare) roughly every few seconds, with no corresponding queries appearing in the corporate DNS resolver's logs for that host during the same period — exactly the blind-spot pattern described in Reading 2 for DNS over HTTPS. IT records confirm the browser installed on this developer's machine is a recent version of Firefox, which enables DoH to Cloudflare by default in several regions unless centrally disabled by policy.",
      event: {
        id: "evt-dns-ac1-001",
        ts: "2026-03-05T11:20:00.000Z",
        source: "proxy",
        vendor: "Zscaler Internet Access",
        event_type: "net_connection",
        severity: "low",
        hostname: "WKS-DEV18.solvix.local",
        src_ip: "10.40.6.201",
        dst_ip: "1.1.1.1",
        dst_port: 443,
        protocol: "tcp",
        network: { domain: "cloudflare-dns.com", bytes_in: 812, bytes_out: 340 },
        description:
          "WKS-DEV18 opened a new short TLS session to 1.1.1.1 roughly every few seconds over several hours, with SNI cloudflare-dns.com; no matching queries appear in the corporate DNS resolver logs for this host during the same window",
        raw: {
          "url.domain": "cloudflare-dns.com",
          "tls.sni": "cloudflare-dns.com",
          "destination.ip": "1.1.1.1",
          "destination.port": 443,
          "network.protocol": "https",
          connections_last_4h: 1840,
          browser_process_hint: "firefox.exe",
        },
      },
      correct_verdict: "false_positive",
      explanation:
        "The destination (1.1.1.1) and SNI (cloudflare-dns.com) both point specifically to Cloudflare's public DoH endpoint, and the browser confirmed on this machine (a recent Firefox release) is well known to enable DoH to this exact provider by default in many configurations. The volume (roughly one connection every few seconds over hours) matches ordinary DoH query traffic for a developer actively browsing documentation, package registries, and repositories, not a tunneling or exfiltration pattern (no unusual entropy, no aggregate NXDOMAIN burst, no evidence the payload is anything other than ordinary encrypted DNS lookups). The absence of matching corporate resolver logs is explained entirely by DoH bypassing that resolver by design — this is the expected, documented blind spot from Reading 2, not evidence of something being hidden maliciously.",
      fp_trap:
        "The 'DNS resolution happening completely outside our visibility' framing sounds alarming, and it's tempting to treat any DoH usage as inherently suspicious specifically because it defeats your usual DNS monitoring. But DoH is default browser behavior for a large and growing share of legitimate traffic, not a targeted evasion technique in the vast majority of cases. The correct organizational response to this scenario is a policy decision — block known public DoH provider endpoints and force resolution through an internally logged resolver, or accept the blind spot — not treating every individual DoH session as an incident. Escalating this specific session as malicious, without any other supporting signal (volume anomaly, unusual destination beyond the known Cloudflare DoH IP, entropy, or NXDOMAIN pattern), is exactly the over-alerting trap this reading warned about.",
      xp: 30,
    },

    // ── Matching: record type <-> security relevance ────────────────────────
    {
      type: "matching" as const,
      id: "dns-m1",
      heading: "Match Each DNS Signal to What It Reveals in an Investigation",
      instructions: "Match each DNS-related signal or record type to the investigative conclusion it supports.",
      pairs: [
        { id: "nxdomain", left: "High NXDOMAIN rate across many distinct, changing domains", right: "Strong indicator of DGA malware working through an algorithmically-generated candidate domain list" },
        { id: "txt", left: "Disproportionate volume of TXT record queries/responses", right: "One of the favorite record types for DNS tunneling, since TXT carries more payload per response than an A record" },
        { id: "ttl-short", left: "Same domain resolving to a rapidly-changing set of unrelated IPs, each with a very short TTL", right: "Fast-flux infrastructure, designed to survive individual IP blocks/takedowns" },
        { id: "sinkhole", left: "An internal host querying/connecting to a known sinkholed domain", right: "Near-zero-false-positive compromise indicator — no legitimate software has any reason to reach a domain deliberately sinkholed by defenders" },
        { id: "unique-ratio", left: "Near-1:1 ratio of unique subdomains to total queries under one parent domain", right: "Signature of DNS tunneling — each query behaves like a distinct chunk of encoded data rather than a cacheable, reused hostname" },
        { id: "doh", left: "TLS traffic on port 443 to a known public DoH provider with no matching corporate resolver logs", right: "Expected DNS-over-HTTPS blind spot, not inherently malicious — requires provider-list blocking policy to regain visibility, not incident-by-incident escalation" },
      ],
      explanation:
        "Each of these signals is drawn directly from a distinct detection technique covered in this room: NXDOMAIN rate and domain churn separate DGA malware from legitimate randomness; TXT-record concentration and unique-subdomain ratio are core DNS-tunneling statistics; short-TTL IP rotation is the fast-flux fingerprint; sinkhole hits are a uniquely high-confidence detection because of how sinkholing works by design; and DoH traffic is a known, expected visibility gap requiring a policy-level response rather than treating every instance as an incident.",
      xp: 40,
    },

    // ── Ordering: DNS resolution path ────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "dns-o1",
      heading: "Order the Full DNS Resolution Path for a Cache-Miss Query",
      instructions: "Arrange the steps in the order they actually occur when a client resolves a brand-new hostname with nothing cached anywhere.",
      items: [
        { id: "stub", text: "Stub resolver on the client checks its local cache — miss" },
        { id: "ask-recursive", text: "Client asks its configured recursive resolver to resolve the name" },
        { id: "ask-root", text: "Recursive resolver asks a root server which servers handle the TLD" },
        { id: "ask-tld", text: "Recursive resolver asks the TLD server which servers are authoritative for the domain" },
        { id: "ask-auth", text: "Recursive resolver asks the domain's authoritative nameserver for the actual record" },
        { id: "answer", text: "Authoritative nameserver returns the answer with a TTL value" },
        { id: "cache", text: "Recursive resolver caches the answer for the TTL duration and returns it to the client" },
        { id: "clientcache", text: "Client's stub resolver also caches the answer locally" },
      ],
      correct_order: ["stub", "ask-recursive", "ask-root", "ask-tld", "ask-auth", "answer", "cache", "clientcache"],
      explanation:
        "This is the full iterative resolution chain: the client's stub resolver never talks to root/TLD/authoritative servers directly — it delegates the entire process to the recursive resolver, which walks the hierarchy step by step (root, then TLD, then authoritative) before returning a final answer that gets cached at multiple layers according to the TTL. Understanding exactly which hop does what is what lets you reason correctly about caching behavior, TTL abuse, and where in this chain your organization's visibility actually sits.",
      xp: 35,
    },

    // ── Query Fill: KQL for DNS tunneling detection ──────────────────────────
    {
      type: "query_fill" as const,
      id: "dns-qf1",
      heading: "Write It Yourself: Surface DNS Tunneling Candidates in KQL",
      language: "kql",
      context:
        "Using the signals from Reading 3 and the pattern you confirmed in Log Analysis 1 (high volume, mostly-unique subdomains, TXT-heavy, under one parent domain), write the KQL a detection engineer would ship to flag hosts exhibiting this pattern across the whole environment.",
      template:
        "DnsEvents\n| where QueryType == \"{{qtype}}\"\n| summarize TotalQueries = count(), UniqueSubdomains = dcount(Name) by ClientIP, bin(TimeGenerated, {{window}})\n| where UniqueSubdomains > {{threshold}}\n| where (UniqueSubdomains * 1.0 / TotalQueries) > {{ratio}}",
      blanks: [
        { id: "qtype", answers: ["TXT"], placeholder: "record type favored for tunneling payloads" },
        { id: "window", answers: ["5m", "10m", "5min", "10min"], placeholder: "aggregation window" },
        { id: "threshold", answers: ["50", "100"], placeholder: "minimum unique-subdomain count to consider" },
        { id: "ratio", answers: ["0.8", "0.9", "80", "90"], placeholder: "unique-to-total ratio threshold (near 1.0 = each query is unique)" },
      ],
      explanation:
        "This mirrors the exact statistical case you built in Log Analysis 1: filter to TXT queries (the record type most favored for tunneling payload capacity), group by client and a short time window, count both total queries and unique subdomains, and alert when both the raw unique-subdomain volume AND the ratio of unique-to-total queries are high — because a near-1.0 ratio is what distinguishes 'many queries to a small reused set of hostnames' (normal) from 'nearly every query is a brand-new, never-repeated label' (the tunneling fingerprint).",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "dns-f1",
      prompt:
        "Look at Log Analysis 2, the DGA-shaped NXDOMAIN burst. What is the exact rcode_name value returned for the sample query to kqxpzr4t.top? Enter it exactly as shown in the raw log.",
      answer: "NXDOMAIN",
      hint: "Look at the rcode_name field in the raw Zeek dns.log record for WKS-OPS22's sample query.",
      xp: 25,
    },
  ],
};

export default [dnsDeepDiveRoom];
