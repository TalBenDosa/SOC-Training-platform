/**
 * Scenario pack: "Threat-Intel Hunt, Chasing a Recorded Future IOC Set to a Live Beacon"
 *
 * INTERMEDIATE tier. The platform's first PROACTIVE, threat-intelligence-led case.
 * It does NOT open with an alert. It opens with a Recorded Future intelligence
 * update: a freshly promoted indicator set, two C2 network indicators (a domain
 * and its hosting IP) and a malware file hash, tied to an active intrusion
 * campaign (GLASSTHORN / the SystemBC proxy-implant family). No detection has
 * fired in the estate yet; the intel is context, not an alarm.
 *
 * The teaching arc is intel → sweep → confirmed active infection → verdict. The
 * analyst takes the indicator set and sweeps the estate for it, then reads what
 * comes back. On ONE workstation (WKS-NEXA-238, the account d.mercer) every
 * indicator lines up and moves in the same direction: the implant landed and set a
 * Run key two days earlier, started at the user's logon this morning, the Windows
 * DNS server and Falcon logged that host resolving the flagged domain to the
 * flagged IP, the Zscaler proxy and Falcon logged recurring, evenly-spaced,
 * same-size HTTPS callbacks from that process to that domain and IP under a
 * non-browser user agent, and Falcon shows the process whose SHA256 is the exact
 * malware hash from the feed. Read together, that is a live compromise, the
 * verdict is malicious.
 *
 * The benign control is the lesson that not every IOC hit is a live compromise.
 * A SECOND host (WKS-NEXA-112, its own incident) also "matched" a feed indicator, 
 * but the domain it queried is a FORMER C2 that has since been seized and
 * sinkholed. Falcon and the DNS server show a browser resolving it to a research
 * sinkhole address; Recorded Future scores it far below the live set and flags it
 * as a sinkhole name; there is no proxy beacon and no implant hash on that host.
 * Same "an indicator matched" shape, opposite verdict: a stale hit, not an active
 * infection. Intel needs validation.
 *
 * SOURCES (registry vendor keys only): recorded-future (the intelligence update /
 * IOC set and the stale-domain record, risk score, evidence rules),
 * windows-dns-server (the DNS resolutions of the flagged domains, live and stale),
 * zscaler-internet-access (the proxy callback sessions to the live C2),
 * crowdstrike-falcon (file landing, Run key, the implant process and its DNS /
 * network activity, the follow-on file, and the confirming detection).
 *
 * Covers T1071.004 (Application Layer Protocol: DNS) for the C2 name resolution,
 * T1071.001 (Application Layer Protocol: Web Protocols) for the HTTPS beacon,
 * T1547.001 (Registry Run Keys) for persistence and T1105 (Ingress Tool Transfer)
 * for the follow-on pull.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate" (the
 * ScenarioBundle itself carries no difficulty field). Enterprise with a Windows
 * AD estate running CrowdStrike Falcon + Zscaler Internet Access + Windows DNS,
 * subscribed to Recorded Future.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csDns, csNetwork, csFile, csRegistry, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { zscalerWeb } from "@/lib/sim/emitters/zscaler";

export function buildThreatIntelHuntScenario(scenarioId = "threat-intel-hunt-2026"): ScenarioBundle {
  const B = new Date("2026-08-31T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // The confirmed compromise is one case; the stale-indicator host is its own.
  const INCIDENT = "inc:tih:1";
  const INCIDENT_CONTROL = "inc:tih:0";

  const cx = "nexacorp" as const;
  const dnsServer = { hostname: "DNS-NEXA-01", fqdn: "DNS-NEXA-01.nexacorp.com", ip: "10.20.5.12" };

  // The host the sweep confirms as a live compromise, and its user.
  const infected = { hostname: "WKS-NEXA-238", ip: "10.20.6.238" };
  const victim = { sam: "d.mercer", email: "d.mercer@nexacorp.com", title: "Accounts Payable Specialist" };

  // The benign control: a second host that matched an indicator that is stale.
  const benignHost = { hostname: "WKS-NEXA-112", ip: "10.20.6.112" };
  const benignUser = { sam: "r.okafor", email: "r.okafor@nexacorp.com" };

  // ── The Recorded Future indicator set (the campaign IOCs) ──────────────────
  const c2Domain = "static-cdn-sync.cyou";      // live C2 domain
  const c2Ip = "193.42.108.77";                 // the IP the C2 domain resolves to
  const implantHash = makeSha256("threat_intel_hunt_systembc_implant_2026");
  const implantPath = `C:\\Users\\${victim.sam}\\AppData\\Roaming\\SysCache\\winsyncsvc.exe`;
  const followOnHash = "eaf86a8817d28361491a0c3b4b20948a7228d40281dfd90158d1576abb8efb91";
  const followOnPath = `C:\\Users\\${victim.sam}\\AppData\\Local\\Temp\\u.bin`;

  // The stale indicator: a former C2 from the same campaign, now sinkholed.
  const staleDomain = "telemetry-sync-cdn.top";
  const sinkholeIp = "184.105.247.6";           // a research sinkhole address

  const malwareUa = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)";
  const implantPid = 7712;
  const explorerPid = 5044;
  const implantCtx = {
    processName: "winsyncsvc.exe", processPath: implantPath, pid: implantPid,
    parentName: "explorer.exe", parentPid: explorerPid, sha256: implantHash,
  } as const;
  const base = { companyId: cx, host: infected.hostname, user: victim.email, srcIp: infected.ip, incidentId: INCIDENT } as const;

  // A Zscaler beacon session: small, same URL, same non-browser user agent, 6m02s apart.
  const beacon = (id: string, at: number, bytes: number, description: string): TelemetryEvent => {
    const e = zscalerWeb({
      ...base, id, ts: T(at), url: `https://${c2Domain}/api/v1/gate`, domain: c2Domain, method: "GET", status: 200,
      category: "Newly Registered and Observed Domains", appName: "General Browsing", userAgent: malwareUa,
      bytesSent: 311, bytesReceived: bytes, severity: "medium", mitre: "T1071.001", tactic: "Command and Control", description,
    });
    return { ...e, dst_ip: c2Ip, raw: { ...e.raw, "zscaler.cip": infected.ip, "zscaler.sip": c2Ip } };
  };

  // The Recorded Future risk-list rows, as the vendor's API returns them (full_log).
  const rfRow = (entity: string, type: string, riskScore: number, riskString: string, evidence: { rule: string; criticality: string }[], extra: Record<string, unknown> = {}) =>
    ({ entity, type, riskScore, riskString, evidenceDetails: evidence, ...extra });

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL (its own incident), a STALE indicator hit that is NOT a
    //    live compromise. A second host resolved a domain from the same feed, but
    //    that domain is a former C2 that has since been seized and sinkholed: it
    //    answers with a research sinkhole address, Recorded Future scores it far
    //    below the live set, and nothing else on this host follows.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_00_stale_sinkhole",
      ts: "2026-08-30T16:41:12.000Z",
      source: "dns",
      vendor: "Windows DNS Server",
      event_type: "dns_query",
      hostname: dnsServer.hostname,
      src_ip: benignHost.ip,
      severity: "informational",
      expected_verdict: "fp",
      incident_id: INCIDENT_CONTROL,
      fp_explanation:
        `The control case for the hunt. ${benignHost.hostname} did query ${staleDomain}, which is on the same feed, so an indicator "matched". But that domain is a former C2 the vendor now lists as a sinkhole name: it resolved to the research sinkhole ${sinkholeIp}, not to attacker-run hosting. Crucially, this host shows no proxy callbacks to it afterwards, only a browser made the lookup, and none of the campaign's file hash is on the endpoint. A matched indicator alone is not a compromise; validate before you isolate. Contrast this with ${infected.hostname}, where the domain, the IP, the recurring callbacks and the on-disk hash all line up.`,
      description:
        `Sweeping the feed's domains through the Windows DNS analytic log found ${benignHost.hostname} resolving ${staleDomain} the previous afternoon, answered with ${sinkholeIp}. The vendor record flags this domain as a former C2 that has been seized and sinkholed.`,
      raw: {
        "dns.question.name": staleDomain,
        "dns.question.type": "A",
        "dns.resolved_ip": sinkholeIp,
        "dns.response_code": "NOERROR",
        "source.ip": benignHost.ip,
        "event.action": "query",
        "event.outcome": "success",
      },
    },
    csDns({
      id: "evt_tih_00b_stale_falcon_dns", ts: "2026-08-30T16:41:12.400Z", companyId: cx, host: benignHost.hostname, user: benignUser.email, srcIp: benignHost.ip,
      incidentId: INCIDENT_CONTROL, domain: staleDomain, resolvedIp: sinkholeIp, severity: "informational",
      processName: "chrome.exe", processPath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", pid: 9120,
      cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", parentName: "explorer.exe", parentPid: 5120,
      description: `Falcon on ${benignHost.hostname} recorded chrome.exe resolving ${staleDomain}.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE TRIGGER, a Recorded Future intelligence update. NOT a detection
    //    of our estate: an IOC set promoted to high risk and tied to an active
    //    campaign. The indicators themselves are what we go sweep.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_01_recorded_future_note",
      ts: T(0),
      source: "threat_intel",
      vendor: "Recorded Future",
      event_type: "threat_intel_match",
      severity: "high",
      description:
        `A Recorded Future risk-list update promoted a new indicator set to high risk: the domain ${c2Domain}, its hosting IP ${c2Ip}, and a malware file hash, all associated with an active intrusion campaign. This is intelligence context, no estate detection has fired. It is the starting point for a sweep, not an alarm.`,
      raw: {
        "vendor.product": "Recorded Future Intelligence Cloud",
        "threat_intel.associated_actor":
          "intrusion set tracked as TEMP.Halberd, associated with the GLASSTHORN campaign and SystemBC proxy tooling",
        "threat_intel.first_observed_itw": "2026-08-24",
        "tags": ["GLASSTHORN", "SystemBC", "C2-infrastructure"],
        "message": `Risk List update: ${c2Domain}, ${c2Ip} and a malware file hash promoted to Very Malicious.`,
        "full_log": JSON.stringify([
          rfRow(c2Domain, "InternetDomainName", 92, "5/12", [
            { rule: "Recently Active C&C Server", criticality: "Malicious" },
            { rule: "Reported by Insikt Group", criticality: "Very Malicious" },
            { rule: "Historically Linked to Malware", criticality: "Malicious" },
          ], { relatedEntities: [c2Ip, implantHash], relatedCampaign: "GLASSTHORN", relatedMalware: "SystemBC", firstSeen: "2026-08-24" }),
          rfRow(c2Ip, "IpAddress", 89, "4/12", [
            { rule: "Recently Active C&C Server", criticality: "Malicious" },
            { rule: "Reported by Insikt Group", criticality: "Very Malicious" },
          ]),
          rfRow(implantHash, "Hash", 94, "4/12", [
            { rule: "Linked to Intrusion Method", criticality: "Malicious" },
            { rule: "Reported by Insikt Group", criticality: "Very Malicious" },
          ], { algorithm: "SHA-256" }),
        ]),
      },
    },
    {
      id: "evt_tih_01b_recorded_future_stale",
      ts: T(1 * SEC),
      source: "threat_intel",
      vendor: "Recorded Future",
      event_type: "threat_intel_match",
      severity: "low",
      description:
        `The same risk list also carries ${staleDomain}, a former C2 from the campaign, scored far below the live set and tagged as a sinkhole name. It is listed for reference.`,
      raw: {
        "vendor.product": "Recorded Future Intelligence Cloud",
        "tags": ["GLASSTHORN", "historical"],
        "message": `Risk List record for ${staleDomain}.`,
        "full_log": JSON.stringify([
          rfRow(staleDomain, "InternetDomainName", 45, "2/12", [
            { rule: "Historical C&C Server", criticality: "Suspicious" },
            { rule: "Sinkhole DNS Name", criticality: "Unusual" },
          ], { relatedEntities: [sinkholeIp], relatedCampaign: "GLASSTHORN", firstSeen: "2026-06-02", lastSeen: "2026-07-19" }),
        ]),
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. HOW THE IMPLANT GOT THERE AND STAYED, two days earlier the file lands in
    //    AppData\Roaming and a Run key is set, so it starts at every logon. How the
    //    file first arrived is outside the telemetry window.
    // ─────────────────────────────────────────────────────────────────────
    csFile({
      ...base, id: "evt_tih_01c_implant_landed", ts: "2026-08-29T13:12:05.000Z", action: "file_create",
      path: implantPath, sha256: implantHash, size: 482_816, severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: `winsyncsvc.exe was written to ${victim.sam}'s roaming profile (AppData\\Roaming\\SysCache) on ${infected.hostname}; the sensor records no writing process.`,
    }),
    csRegistry({
      ...base, id: "evt_tih_01d_run_key", ts: "2026-08-29T13:12:09.000Z",
      keyPath: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "SysCacheSync", valueData: implantPath,
      severity: "medium", mitre: "T1547.001", tactic: "Persistence",
      description: `A Run-key value SysCacheSync was set for ${victim.sam}, pointing at the roaming-profile executable.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE IMPLANT RUNS, started at the user's logon through the Run key, 09 minutes
    //    before its first callback. The hash on disk is the exact feed hash.
    // ─────────────────────────────────────────────────────────────────────
    csProcess({
      ...base, id: "evt_tih_06_edr_hash_match", ts: "2026-08-31T08:41:10.000Z",
      processName: "winsyncsvc.exe", processPath: implantPath, cmdline: `"${implantPath}"`,
      parentName: "explorer.exe", parentPid: explorerPid, pid: implantPid, sha256: implantHash, signed: false, integrity: "medium",
      mitre: "T1547.001", tactic: "Persistence", severity: "high",
      description:
        `Falcon shows a process on ${infected.hostname}, winsyncsvc.exe from the user's AppData, started under explorer.exe at logon. Its SHA256 equals the malware hash in the feed. It is unsigned. The match is on the hash value, not the file name.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE BEACON, name resolution (T1071.004) and recurring callbacks every 6m02s
    //    (T1071.001): DNS server, Falcon and the proxy all see it.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_02_dns_c2_resolution",
      ts: T(-10 * MIN),
      source: "dns",
      vendor: "Windows DNS Server",
      event_type: "dns_query",
      hostname: dnsServer.hostname,
      src_ip: infected.ip,
      severity: "medium",
      mitre_technique: "T1071.004",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      description:
        `Sweeping the feed's domain across the DNS logs returned ${infected.hostname} resolving ${c2Domain} to ${c2Ip}: the exact domain-to-IP pairing named in the intelligence update, coming from a workstation.`,
      raw: {
        "dns.question.name": c2Domain,
        "dns.question.type": "A",
        "dns.resolved_ip": c2Ip,
        "dns.response_code": "NOERROR",
        "source.ip": infected.ip,
        "event.action": "query",
        "event.outcome": "success",
      },
    },
    csDns({
      ...base, id: "evt_tih_02b_falcon_dns", ts: T(-10 * MIN + 400), domain: c2Domain, resolvedIp: c2Ip, severity: "medium",
      mitre: "T1071.004", tactic: "Command and Control", ...implantCtx,
      cmdline: `"${implantPath}"`,
      description: `winsyncsvc.exe on ${infected.hostname} resolved ${c2Domain}.`,
    }),
    csNetwork({
      ...base, id: "evt_tih_02c_falcon_connect_1", ts: T(-10 * MIN + 6 * SEC), remoteIp: c2Ip, remotePort: 443, application: "tls", severity: "medium",
      mitre: "T1071.001", tactic: "Command and Control", ...implantCtx, cmdline: `"${implantPath}"`,
      description: `winsyncsvc.exe opened an outbound TLS connection to ${c2Ip}:443.`,
    }),
    beacon("evt_tih_03_proxy_beacon_1", -10 * MIN + 6 * SEC, 642,
      `Zscaler recorded ${infected.hostname} making a short HTTPS GET to ${c2Domain} (${c2Ip}) under a non-browser user agent, 642 bytes returned: the first of several evenly-spaced, same-size requests.`),
    beacon("evt_tih_03b_proxy_beacon_2", -10 * MIN + 6 * SEC + 362 * SEC, 648,
      `A second Zscaler session six minutes after the first: same host, same URL path, same user agent, 648 bytes.`),
    beacon("evt_tih_04_proxy_beacon_3", 2 * MIN + 10 * SEC, 645,
      `A third session, 6m02s after the second: same host, same URL path, same user agent, 645 bytes.`),
    csNetwork({
      ...base, id: "evt_tih_04b_falcon_connect_2", ts: T(2 * MIN + 10 * SEC), remoteIp: c2Ip, remotePort: 443, application: "tls", severity: "medium",
      mitre: "T1071.001", tactic: "Command and Control", ...implantCtx, cmdline: `"${implantPath}"`,
      description: `winsyncsvc.exe opened another outbound TLS connection to ${c2Ip}:443.`,
    }),
    beacon("evt_tih_04c_proxy_beacon_4", 8 * MIN + 12 * SEC, 651,
      `A fourth session, 6m02s later: same host, same URL path, same user agent, 651 bytes.`),
    beacon("evt_tih_04d_proxy_beacon_5", 14 * MIN + 14 * SEC, 656,
      `A fifth session, 6m02s later: same host, same URL path, same user agent, 656 bytes.`),
    csNetwork({
      ...base, id: "evt_tih_04e_falcon_connect_3", ts: T(14 * MIN + 14 * SEC), remoteIp: c2Ip, remotePort: 443, application: "tls", severity: "medium",
      mitre: "T1071.001", tactic: "Command and Control", ...implantCtx, cmdline: `"${implantPath}"`,
      description: `winsyncsvc.exe opened another outbound TLS connection to ${c2Ip}:443.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE FOLLOW-ON PULL, one session breaks the small same-size pattern with a
    //    multi-megabyte download from a /files path (T1105); the process writes it
    //    to Temp. Nothing executes it in the window.
    // ─────────────────────────────────────────────────────────────────────
    (() => {
      const e = zscalerWeb({
        ...base, id: "evt_tih_05_proxy_tool_pull", ts: T(15 * MIN + 20 * SEC), url: `https://${c2Domain}/files/u.bin`, domain: c2Domain, method: "GET", status: 200,
        category: "Newly Registered and Observed Domains", appName: "General Browsing", userAgent: malwareUa,
        bytesSent: 318, bytesReceived: 1_908_736, severity: "high", mitre: "T1105", tactic: "Command and Control",
        description: `A larger Zscaler session from ${infected.hostname} to the same host ${c2Domain} (${c2Ip}): 1.82 MB returned from a /files path, the callback channel pulling a follow-on file down onto the workstation.`,
      });
      return { ...e, dst_ip: c2Ip, raw: { ...e.raw, "zscaler.cip": infected.ip, "zscaler.sip": c2Ip } };
    })(),
    csFile({
      ...base, id: "evt_tih_05b_follow_on_written", ts: T(15 * MIN + 24 * SEC), action: "file_create",
      path: followOnPath, sha256: followOnHash, size: 1_908_736, severity: "medium", mitre: "T1105", tactic: "Command and Control",
      actorProcess: "winsyncsvc.exe", actorPath: implantPath, actorPid: implantPid, actorParentName: "explorer.exe", actorParentPid: explorerPid,
      actorSha256: implantHash, actorSigned: "unsigned",
      description: `winsyncsvc.exe wrote u.bin to the user's Temp folder.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE DETECTION, Falcon raises the alert-grade detection that turns the
    //    hunt into a confirmed case, tying the on-disk hash to the callbacks.
    // ─────────────────────────────────────────────────────────────────────
    {
      ...csAlert({
        ...base, id: "evt_tih_07_falcon_detection", ts: T(18 * MIN), severity: "critical", action: "detected",
        threatName: "Known C2 Implant Communicating With Flagged Infrastructure", mitre: "T1071.001", tactic: "Command and Control",
        technique: "Application Layer Protocol", processName: "winsyncsvc.exe", processPath: implantPath, cmdline: `"${implantPath}"`,
        sha256: implantHash, pid: implantPid, parentPath: "C:\\Windows\\explorer.exe",
        detail: "A known-bad file hash executing and communicating with attacker infrastructure named in current intelligence.",
        description:
          `Falcon raised a Critical detection on ${infected.hostname}: a known-bad file hash executing and communicating with attacker infrastructure named in current intelligence. It correlates the on-disk hash, the callbacks and the flagged domain and IP into one confirmed compromise.`,
      }),
      edr_scope: "hybrid",
    },
  ];

  // Declared in the order the records happened, whichever product wrote them.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  const iocs: IOC[] = [
    {
      type: "domain",
      value: c2Domain, // static-cdn-sync.cyou, the live C2, resolved and beaconed to
      first_seen: T(-10 * MIN),
      last_seen: T(18 * MIN),
      reputation: "malicious",
      tags: ["campaign-ioc", "c2-domain", "live"],
    },
    {
      type: "ip",
      value: c2Ip, // 193.42.108.77, the IP the live C2 resolves to
      first_seen: T(-10 * MIN),
      last_seen: T(18 * MIN),
      reputation: "malicious",
      tags: ["campaign-ioc", "c2-address", "live"],
    },
    {
      type: "sha256",
      value: implantHash, // the malware file hash found on the matched host
      first_seen: "2026-08-29T13:12:05Z",
      last_seen: T(18 * MIN),
      reputation: "malicious",
      tags: ["campaign-ioc", "implant", "on-disk-match"],
    },
    {
      type: "sha256",
      value: followOnHash, // the follow-on file the implant pulled to Temp
      first_seen: T(15 * MIN + 24 * SEC),
      last_seen: T(15 * MIN + 24 * SEC),
      reputation: "suspicious",
      tags: ["follow-on", "u.bin"],
    },
    {
      type: "host",
      value: infected.hostname, // WKS-NEXA-238, the confirmed live compromise
      first_seen: "2026-08-29T13:12:05Z",
      last_seen: T(18 * MIN),
      reputation: "suspicious",
      tags: ["affected", "confirmed-compromise", "workstation"],
    },
    {
      type: "user",
      value: victim.sam, // d.mercer, the account on the infected workstation
      first_seen: "2026-08-29T13:12:05Z",
      last_seen: T(18 * MIN),
      reputation: "suspicious",
      tags: ["affected", "workstation-user"],
    },
    {
      type: "domain",
      value: staleDomain, // telemetry-sync-cdn.top, a FEED indicator that is stale
      first_seen: "2026-08-30T16:41:12Z",
      last_seen: "2026-08-30T16:41:12Z",
      reputation: "clean",
      tags: ["campaign-ioc", "sinkholed", "stale-indicator", "not-a-live-hit"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "No detection fired before this case was opened, the work began from a vendor intelligence record. What kind of case is this, and what did the record actually give you?",
      hint: "Look at evt_tih_01: is it reporting something that happened in your estate, or is it context you then went looking for?",
      kind: "single",
      options: [
        { value: "intel_led", label: "A proactive hunt: Recorded Future promoted an indicator set (domain, IP, file hash) for an active intrusion set, and the analyst searched the estate's logs for matches" },
        { value: "edr_alert", label: "An endpoint alert: Falcon detected a running implant first, and the vendor record was pulled in afterwards purely to enrich a detection that had already fired on its own" },
        { value: "pentest", label: "A red-team exercise: the indicator set was seeded by an internal penetration test, so the DNS and proxy matches are simulated and no real adversary activity is involved" },
        { value: "user_report", label: "A user-reported case: the account holder phoned the service desk about a slow machine, and the intelligence record was attached to that ticket after triage had begun" },
      ],
      answer: "intel_led",
      xp: 55,
      explanation:
        "The starting point (evt_tih_01) is a Recorded Future risk-list update: an indicator set, a domain, its IP, and a malware file hash, promoted to high risk and tied to an active intrusion set. Nothing in the estate had alarmed. That is the definition of a threat-intelligence-led hunt: you take external indicators and go looking, rather than reacting to an alert. Everything after it (the DNS, proxy and EDR hits) is what the sweep turned up. (b) inverts the order, the Falcon detection comes at the end, after the hunt has already surfaced the host; it did not start the case. (c) invents a pen-test that no record mentions, and the callbacks and on-disk hash are real telemetry. (d) invents a user report that never happened.",
    },
    {
      id: "q2",
      prompt:
        "Two hosts each 'matched' a domain from the feed: WKS-NEXA-238 and WKS-NEXA-112. One is a live compromise and one is not. Which is which, and what makes the difference?",
      hint: "Compare what follows each DNS hit, the resolved address, and whether any callbacks or on-host file hash appear afterwards.",
      kind: "single",
      options: [
        { value: "238_live_112_stale", label: "WKS-NEXA-238 is live, it resolved the flagged domain to the flagged IP, kept calling back and carries the file hash; WKS-NEXA-112 only reached a seized domain now sinkholed, with no callbacks or hash" },
        { value: "112_live_238_stale", label: "WKS-NEXA-112 is the live compromise because it reached the domain first in time, and WKS-NEXA-238 is the stale one since its later hits are just cached DNS answers being replayed from the local resolver" },
        { value: "both_live", label: "Both hosts are live compromises, any resolution of a flagged domain is a confirmed infection regardless of the address returned, so both must be treated as actively beaconing right now" },
        { value: "both_stale", label: "Neither is a live compromise, both domains appear on the provider's sinkhole list, so every match is historical DNS residue and the case can be closed without isolating either host" },
      ],
      answer: "238_live_112_stale",
      xp: 70,
      explanation:
        "This is the core lesson: a matched indicator is a starting point, not a verdict. On WKS-NEXA-238 every signal lines up and continues, it resolved the flagged domain to the exact flagged IP, then made recurring same-size callbacks to that domain and IP, and Falcon found the campaign's file hash executing on it. That chain is a live compromise. WKS-NEXA-112 'matched' too, but the domain it queried is a former C2 that has been seized and sinkholed: it resolved to a research sinkhole address, and there are no callbacks and no implant hash on that host. Same shape, opposite meaning. (b) invents a caching story the logs do not support and reverses the verdict. (c) treats any match as proof, exactly the mistake the control teaches against. (d) is the opposite over-correction: one of the two is genuinely active.",
    },
    {
      id: "q3",
      prompt:
        "For WKS-NEXA-238, what specifically raises the DNS and proxy activity from 'a domain was looked up' to 'this host is actively talking to command-and-control infrastructure'?",
      hint: "One lookup proves little. Read the resolution and the sessions that follow it together.",
      kind: "single",
      options: [
        { value: "correlated_beacon", label: "The host resolved the flagged domain to the flagged IP, then made recurring, evenly-spaced, same-size HTTPS requests to that domain and IP under a non-browser user agent" },
        { value: "nxdomain", label: "The flagged domain returned NXDOMAIN on its later lookups, and repeated failed resolutions of a flagged name are the signature of an implant rotating through fallback C2 domains" },
        { value: "port_only", label: "The sessions used TCP 443 with TLS to an external address, and outbound encrypted traffic from a workstation to the internet is by itself sufficient to confirm a live C2 channel" },
        { value: "one_lookup", label: "The DNS server logged the host looking up the flagged domain, and that single resolution is the whole basis for the verdict, the proxy sessions add nothing the lookup does not show" },
      ],
      answer: "correlated_beacon",
      xp: 60,
      explanation:
        "It is the correlation across sources that makes the case. The Windows DNS log shows the host resolving the flagged domain to the exact flagged IP; the Zscaler log then shows repeated HTTPS GETs to that same domain and IP, evenly spaced, near-identical in size, under a non-browser user agent, the fingerprint of an automated callback rather than a person browsing. Neither log alone is decisive; together they show a host reaching attacker infrastructure on a cadence. (b) is wrong on the facts, the resolution succeeded (NOERROR), not NXDOMAIN, and a failed lookup would prove less, not more. (c) over-reads one field: almost all normal web traffic is 443. (d) stops at the lookup and never reads the sessions that turn a match into a confirmed channel.",
    },
    {
      id: "q4",
      prompt:
        "The feed's file hash was found on WKS-NEXA-238 via Falcon. What makes that a real detection of the campaign's malware rather than a coincidence?",
      hint: "Think about which field the match is on, and whether the process does anything that ties it to the rest of the evidence.",
      kind: "single",
      options: [
        { value: "sha256_and_behaviour", label: "The process's SHA256 equals the feed's hash exactly, and that same process is the one calling the flagged domain and IP, a content match joined to its behaviour" },
        { value: "filename_match", label: "The executable's file name matches a name listed in the feed, which is enough to confirm the malware regardless of the file's actual hash or what the process does" },
        { value: "path_match", label: "The file sits in AppData\\Roaming\\SysCache, and an executable running from a roaming profile folder is automatically the feed's malware because that is where implants live" },
        { value: "signed_trusted", label: "Falcon reports the binary as signed and trusted, and a valid signature on a binary running from a flagged host is what confirms the sample is the campaign's own tooling" },
      ],
      answer: "sha256_and_behaviour",
      xp: 60,
      explanation:
        "A hash IOC matches on the file's content, not its name. Falcon reports the process's SHA256 as exactly the value promoted in the feed, and, decisively, that same process is the one making the callbacks to the flagged domain and IP. Identity by hash plus corroborating behaviour is what turns 'a file with a hash' into 'the campaign's implant, running.' (b) is the classic trap: a file name is trivially changed and proves nothing; the whole point of a hash indicator is to ignore the name. (c) over-reads location, plenty of legitimate software runs from AppData, so a path is context, not proof. (d) is contradicted by the record, the binary is unsigned, and a trusted signature would argue against a match, not for it.",
    },
    {
      id: "q5",
      prompt:
        "The hunt confirmed a live infection on WKS-NEXA-238. Given that this began from a feed and that WKS-NEXA-112's hit is stale, what response fits the evidence?",
      hint: "Match each action to what the evidence supports, contain the confirmed host, act on the live indicators, and validate rather than isolate the stale hit.",
      kind: "single",
      options: [
        { value: "contain_block_hunt_validate", label: "Isolate WKS-NEXA-238 and reset d.mercer, block the live domain and IP, quarantine the file, sweep the estate for the same indicators, and validate the sinkholed-domain hit rather than isolating that host" },
        { value: "isolate_every_match", label: "Immediately isolate every host that resolved any domain from the feed, including WKS-NEXA-112, since a feed match is a confirmed infection and all matched hosts must be pulled off the network at once" },
        { value: "close_from_feed", label: "Close the case as informational, the activity came from a threat-intel feed rather than a fired detection rule, so there is no confirmed incident that would justify containing any host" },
        { value: "block_stale_only", label: "Block the sinkholed domain at the proxy and take no host action, because the seized former-C2 domain is the only indicator in the record with a confirmed, law-enforcement-verified reputation" },
      ],
      answer: "contain_block_hunt_validate",
      xp: 65,
      explanation:
        "Response has to track the evidence per host. WKS-NEXA-238 is a confirmed live compromise, so it is isolated, its user reset, the live domain and IP blocked, and the on-disk file quarantined; and because the same indicators could be anywhere, the estate is swept for them. WKS-NEXA-112's hit is stale, a sinkholed former C2 with no callbacks and no hash, so it is validated and documented, not treated like the live host. (b) is the over-reaction the control exists to prevent: isolating a host over a sinkholed match burns effort and disrupts users on no real evidence. (c) confuses provenance with severity, intelligence-led findings are still real incidents, and this one is confirmed on the host. (d) fixates on the one indicator that is not a live threat while ignoring the active infection.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "New intel list to check across the estate",
    threat_actor: "GLASSTHORN intrusion set (TEMP.Halberd), SystemBC proxy-implant operator",
    attack_kind: "threat_hunt",
    briefing:
      "An intel provider pushed a new list of network destinations and a file fingerprint linked to an active operation. Nothing has alarmed yet; this is a proactive check. Work through the environment for those items and decide which of the machines that match, if any, is genuinely reaching attacker-run systems right now.",
    narrative: `This case did not start with an alert. At 09:00 a Recorded Future risk-list update promoted a small indicator set to high risk (Risk Score 92/99 for the domain): the domain static-cdn-sync.cyou, its hosting IP 193.42.108.77, and a malware file hash, all tied to the active GLASSTHORN campaign and the SystemBC proxy-implant family. The same list carried a related former C2, telemetry-sync-cdn.top, scored far lower (45) and tagged as a sinkhole name. None of this was a detection in the estate: it was context, and the job was to sweep for it.

Sweeping the domains through the Windows DNS analytic log and Falcon's DNS events returned two hosts. The first, from the day before, was WKS-NEXA-112 (r.okafor) resolving telemetry-sync-cdn.top in a browser, but that domain answered with 184.105.247.6, a research sinkhole, and nothing else on that host followed it: no callbacks, no implant hash. That is a stale indicator, an IOC that matched but points at seized infrastructure, not a live compromise. It is the control the whole case turns on, and it is its own case.

The second hit was different. WKS-NEXA-238, the workstation of accounts-payable clerk d.mercer, resolved static-cdn-sync.cyou to exactly 193.42.108.77, the domain-and-IP pairing named in the feed. The sweep led back through the host's history. On 29 August at 13:12 a file named winsyncsvc.exe landed in d.mercer's roaming profile (AppData\\Roaming\\SysCache) and a Run-key value SysCacheSync was set to start it; how the file first arrived is outside the telemetry window. At 08:41 on 31 August d.mercer logged on, explorer.exe started the Run-key target, and Falcon recorded winsyncsvc.exe, unsigned, with a SHA256 equal to the feed's malware hash. Nine minutes later, at 08:50, the process resolved the C2 domain and called out; the Zscaler proxy shows recurring HTTPS GETs to that domain and IP every 6m02s (08:50:06, 08:56:08, 09:02:10, 09:08:12, 09:14:14): 642 to 656 bytes each, same URL path, same non-browser user agent, the even cadence and constant size of an automated callback, not a person browsing. At 09:15 one session broke the pattern with a 1.82 MB download from a /files path on the same host, and winsyncsvc.exe wrote the result, u.bin, to the user's Temp folder: the channel pulling a follow-on file down (Ingress Tool Transfer). Nothing in the window executes it.

At 09:18 Falcon raised a Critical detection on WKS-NEXA-238 correlating the on-disk hash, the callbacks and the flagged infrastructure into one confirmed compromise. Read end to end, the hunt did exactly what a hunt is for: it took external intelligence, validated it against the estate, and separated a genuine active infection on WKS-NEXA-238 from a stale, sinkholed match on WKS-NEXA-112, the same "an indicator matched" shape with opposite verdicts.`,
    learning_objectives: [
      "Run a threat-intelligence-led hunt: start from an external indicator set (domain, IP, file hash) and sweep the estate for it, rather than reacting to an alert that already fired",
      "Correlate a DNS resolution with proxy callbacks to promote a bare indicator match into evidence of an active command-and-control channel (T1071.004 → T1071.001)",
      "Confirm a file-hash indicator by matching on the SHA256 value and its behaviour, not on the file name or path",
      "Distinguish a live compromise from a stale/sinkholed indicator hit, a seized former-C2 domain resolving to a sinkhole with no follow-on activity is not an infection",
      "Scope an intelligence-led response per host: contain and remediate the confirmed host and its live indicators, sweep for the same set, and validate rather than isolate stale matches",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T16:41:12.000Z", phase: "Baseline", action: `${benignHost.hostname} resolves ${staleDomain} → sinkhole ${sinkholeIp}: a stale, seized indicator, not a live hit` },
      { ts: "2026-08-29T13:12:05.000Z", phase: "Persistence", action: `winsyncsvc.exe lands in ${victim.sam}'s AppData\\Roaming\\SysCache and a Run key SysCacheSync is set (T1547.001); the original delivery step is outside the telemetry` },
      { ts: "2026-08-31T08:41:10.000Z", phase: "Execution", action: `At logon explorer.exe starts winsyncsvc.exe through the Run key; its SHA256 equals the feed hash` },
      { ts: T(-10 * MIN), phase: "Command and Control", action: `${infected.hostname} resolves ${c2Domain} → ${c2Ip} and the implant begins calling out every 6m02s (T1071.004, T1071.001)` },
      { ts: T(0), phase: "Threat Intelligence", action: `Recorded Future promotes an indicator set (${c2Domain}, ${c2Ip}, malware hash) for the GLASSTHORN campaign` },
      { ts: T(14 * MIN + 14 * SEC), phase: "Command and Control", action: `Fifth callback, 656 bytes: the fixed cadence is visible across the proxy and Falcon (T1071.001)` },
      { ts: T(15 * MIN + 20 * SEC), phase: "Command and Control", action: `1.82 MB pull from ${c2Domain}/files, written to Temp as u.bin: follow-on file transfer (T1105)` },
      { ts: T(18 * MIN), phase: "Detection", action: "Falcon correlates on-disk hash + callbacks + flagged infrastructure into a Critical confirmed compromise" },
    ],
    questions,
  };
}
