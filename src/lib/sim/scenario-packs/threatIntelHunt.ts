/**
 * Scenario pack: "Threat-Intel Hunt — Chasing a Recorded Future IOC Set to a Live Beacon"
 *
 * INTERMEDIATE tier. The platform's first PROACTIVE, threat-intelligence-led case.
 * It does NOT open with an alert. It opens with a Recorded Future intelligence
 * update: a freshly promoted indicator set — two C2 network indicators (a domain
 * and its hosting IP) and a malware file hash — tied to an active intrusion
 * campaign (GLASSTHORN / the SystemBC proxy-implant family). No detection has
 * fired in the estate yet; the intel is context, not an alarm.
 *
 * The teaching arc is intel → sweep → confirmed active infection → verdict. The
 * analyst takes the indicator set and sweeps the estate for it, then reads what
 * comes back. On ONE workstation (WKS-NEXA-238, the account d.mercer) every
 * indicator lines up and moves in the same direction: the Windows DNS server
 * logged that host resolving the flagged domain to the flagged IP; the Zscaler
 * proxy logged recurring, evenly-spaced, same-size HTTPS callbacks from that host
 * to that domain and IP under a non-browser user agent; and CrowdStrike Falcon
 * shows a process on that host whose SHA256 is the exact malware hash from the
 * feed, communicating with the same infrastructure. Read together, that is a live
 * compromise — the verdict is malicious.
 *
 * The benign control is the lesson that not every IOC hit is a live compromise.
 * A SECOND host (WKS-NEXA-112) also "matched" a feed indicator — but the domain
 * it queried is a FORMER C2 that has since been seized and sinkholed. The DNS log
 * shows it resolving to a research sinkhole address, and there is no proxy beacon
 * and no implant hash anywhere on that host. Same "an indicator matched" shape,
 * opposite verdict: a stale hit, not an active infection. Intel needs validation.
 *
 * SOURCES (registry vendor keys only): recorded-future (the intelligence update /
 * IOC set — risk score, evidence rules, associated actor/campaign),
 * windows-dns-server (the DNS resolutions of the flagged domains, live and stale),
 * zscaler-internet-access (the proxy callback sessions to the live C2),
 * crowdstrike-falcon (the malware hash present on the matched host and the
 * confirming detection).
 *
 * Covers T1071.004 (Application Layer Protocol: DNS) for the C2 name resolution,
 * T1071.001 (Application Layer Protocol: Web Protocols) for the HTTPS beacon, and
 * T1105 (Ingress Tool Transfer) for the follow-on pull — all Command and Control.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate" (the
 * ScenarioBundle itself carries no difficulty field). Enterprise with a Windows
 * AD estate running CrowdStrike Falcon + Zscaler Internet Access + Windows DNS,
 * subscribed to Recorded Future.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildThreatIntelHuntScenario(scenarioId = "threat-intel-hunt-2026"): ScenarioBundle {
  const B = new Date("2026-08-31T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One case — the whole intel-to-confirmation hunt is a single incident.
  const INCIDENT = "inc:tih:1";

  const domain = "NEXACORP";
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

  // The stale indicator: a former C2 from the same campaign, now sinkholed.
  const staleDomain = "telemetry-sync-cdn.top";
  const sinkholeIp = "184.105.247.6";           // a research sinkhole address

  const sensorId = "d41c8a2e6b7f40915ac8e3d720b1f6a4";
  const malwareUa = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a STALE indicator hit that is NOT a live compromise.
    //    A second host resolved a domain from the same feed, but that domain is
    //    a former C2 that has since been seized and sinkholed: it answers with a
    //    research sinkhole address, and nothing else on this host follows. Same
    //    "an indicator matched" shape as the real case, opposite verdict.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_00_stale_sinkhole",
      ts: "2026-08-30T16:41:12Z",
      source: "dns",
      vendor: "Windows DNS Server",
      event_type: "dns_query",
      hostname: dnsServer.hostname,
      user_email: benignUser.email,
      src_ip: benignHost.ip,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        `The control case for the hunt. ${benignHost.hostname} did query ${staleDomain}, which is on the same feed — so an indicator "matched". But that domain is a former C2 the vendor now lists as seized and sinkholed: it resolved to the research sinkhole ${sinkholeIp}, not to attacker-run hosting. Crucially, this host shows no proxy callbacks to it afterwards and none of the campaign's file hash on the endpoint. A matched indicator alone is not a compromise; validate before you isolate. Contrast this with ${infected.hostname}, where the domain, the IP, the recurring callbacks and the on-disk hash all line up.`,
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
        "host.name": dnsServer.hostname,
        "event.dataset": "windows.dns_server",
        "event.module": "windows",
        "message": `DNS A query ${staleDomain} from ${benignHost.ip} answered ${sinkholeIp} — resolution to a known sinkhole range; domain listed as seized former infrastructure.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE TRIGGER — a Recorded Future intelligence update. NOT a detection
    //    of our estate: an IOC set promoted to high risk and tied to an active
    //    campaign. Risk score, evidence rules and actor association are carried
    //    in the vendor record; the indicators themselves are what we go sweep.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_01_recorded_future_note",
      ts: T(0),
      source: "threat_intel",
      vendor: "Recorded Future",
      event_type: "threat_intel_match",
      severity: "high",
      user_email: undefined,
      description:
        `A Recorded Future risk-list update promoted a new indicator set to high risk: the domain ${c2Domain}, its hosting IP ${c2Ip}, and a malware file hash, all associated with an active intrusion campaign. This is intelligence context — no estate detection has fired. It is the starting point for a sweep, not an alarm.`,
      raw: {
        "vendor.product": "Recorded Future Intelligence Cloud",
        "event.dataset": "recordedfuture.threat_intelligence",
        "event.module": "recordedfuture",
        "threat_intel.associated_actor":
          "intrusion set tracked as TEMP.Halberd, associated with the GLASSTHORN campaign and SystemBC proxy tooling",
        "threat_intel.active_exploitation_confirmed": true,
        "threat_intel.first_observed_itw": "2026-08-24",
        "threat_intel.cisa_kev_listed": false,
        "tags": [
          "GLASSTHORN",
          "SystemBC",
          "C2-infrastructure",
          `domain:${c2Domain}`,
          `ip:${c2Ip}`,
          `sha256:${implantHash}`,
          `sinkholed:${staleDomain}`,
        ],
        "message":
          `Risk List update — 3 indicators promoted to Very Malicious (Risk Score 92/99): ${c2Domain}, ${c2Ip}, malware hash ${implantHash}. Related former C2 ${staleDomain} now seized/sinkholed.`,
        "full_log": JSON.stringify({
          entity: c2Domain,
          type: "InternetDomainName",
          riskScore: 92,
          riskString: "5/12",
          evidenceDetails: [
            { rule: "Recently Active C&C Server", criticality: "Malicious" },
            { rule: "Reported by Insikt Group", criticality: "Very Malicious" },
            { rule: "Historically Linked to Malware", criticality: "Malicious" },
          ],
          relatedEntities: [c2Ip, implantHash],
          relatedCampaign: "GLASSTHORN",
          relatedMalware: "SystemBC",
          firstSeen: "2026-08-24",
        }),
        "event.provider": "recordedfuture",
        "rule.description": "Recorded Future indicator set promoted to high risk (active campaign)",
        "rule.level": 8,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. SWEEP HIT #1 (DNS) — the flagged domain, resolved by the estate.
    //    The Windows DNS analytic log shows the infected host resolving the C2
    //    domain to the exact flagged IP. Name resolution as the first C2 step
    //    (T1071.004). This is an observation the analyst pivoted to.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_02_dns_c2_resolution",
      ts: T(2 * MIN),
      source: "dns",
      vendor: "Windows DNS Server",
      event_type: "dns_query",
      hostname: dnsServer.hostname,
      user_email: victim.email,
      src_ip: infected.ip,
      severity: "medium",
      mitre_technique: "T1071.004",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      description:
        `Sweeping the feed's domain across the DNS logs returned ${infected.hostname} resolving ${c2Domain} to ${c2Ip} — the exact domain-to-IP pairing named in the intelligence update, coming from a workstation.`,
      raw: {
        "dns.question.name": c2Domain,
        "dns.question.type": "A",
        "dns.resolved_ip": c2Ip,
        "dns.response_code": "NOERROR",
        "source.ip": infected.ip,
        "event.action": "query",
        "event.outcome": "success",
        "host.name": dnsServer.hostname,
        "event.dataset": "windows.dns_server",
        "event.module": "windows",
        "message": `DNS A query ${c2Domain} from ${infected.ip} answered ${c2Ip}.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. SWEEP HIT #2 (proxy) — a callback to the C2. Zscaler shows an HTTPS
    //    GET from the infected host to the flagged domain and IP, small payload,
    //    non-browser user agent. First of a recurring, evenly-spaced pattern
    //    (T1071.001 — web protocols).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_03_proxy_beacon_1",
      ts: T(2 * MIN + 10 * SEC),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: infected.hostname,
      user_email: victim.email,
      src_ip: infected.ip,
      dst_ip: c2Ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      description:
        `Zscaler recorded ${infected.hostname} making a short HTTPS GET to ${c2Domain} (${c2Ip}) under a non-browser user agent — 642 bytes returned, the first of several evenly-spaced same-size requests.`,
      network: { url: `https://${c2Domain}/api/v1/gate`, domain: c2Domain, method: "GET", status: 200, bytes_in: 642, user_agent: malwareUa },
      raw: {
        "action": "Allowed",
        "url.full": `https://${c2Domain}/api/v1/gate`,
        "url.domain": c2Domain,
        "url.path": "/api/v1/gate",
        "url.category": "Botnet",
        "url.reputation": "Malicious",
        "http.request.method": "GET",
        "http.response.status_code": 200,
        "http.user_agent": malwareUa,
        "destination.domain": c2Domain,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "network.bytes": 642,
        "session.bytes": 642,
        "network.transport": "tcp",
        "network.protocol": "ssl",
        "network.application": "HTTPS",
        "source.ip": infected.ip,
        "user.name": victim.sam,
        "user.email": victim.email,
        "event.action": "web-request",
        "threat.name": "SystemBC",
        "threat.category": "Command and Control",
        "threat.technique.id": "T1071.001",
        "threat.technique.name": "Application Layer Protocol: Web Protocols",
        "threat.tactic.id": "TA0011",
        "threat.tactic.name": "Command and Control",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. SWEEP HIT #3 (proxy) — the callback repeats. Six minutes on, the same
    //    host makes another almost-identical request to the same destination.
    //    Two evenly-spaced, same-size sessions are the periodic pattern.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_04_proxy_beacon_2",
      ts: T(8 * MIN + 12 * SEC),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: infected.hostname,
      user_email: victim.email,
      src_ip: infected.ip,
      dst_ip: c2Ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      description:
        `A second Zscaler session six minutes after the first: ${infected.hostname} to ${c2Domain} (${c2Ip}), 648 bytes, same non-browser user agent and same URL path — the callback repeating on a fixed cadence.`,
      network: { url: `https://${c2Domain}/api/v1/gate`, domain: c2Domain, method: "GET", status: 200, bytes_in: 648, user_agent: malwareUa },
      raw: {
        "action": "Allowed",
        "url.full": `https://${c2Domain}/api/v1/gate`,
        "url.domain": c2Domain,
        "url.path": "/api/v1/gate",
        "url.category": "Botnet",
        "url.reputation": "Malicious",
        "http.request.method": "GET",
        "http.response.status_code": 200,
        "http.user_agent": malwareUa,
        "destination.domain": c2Domain,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "network.bytes": 648,
        "session.bytes": 648,
        "network.transport": "tcp",
        "network.protocol": "ssl",
        "network.application": "HTTPS",
        "network.session_id": "zia-8841207734",
        "source.ip": infected.ip,
        "user.name": victim.sam,
        "user.email": victim.email,
        "event.action": "web-request",
        "threat.name": "SystemBC",
        "threat.category": "Command and Control",
        "threat.technique.id": "T1071.001",
        "threat.technique.name": "Application Layer Protocol: Web Protocols",
        "threat.tactic.id": "TA0011",
        "threat.tactic.name": "Command and Control",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. SWEEP HIT #4 (proxy) — a larger transfer. One session breaks the small
    //    same-size pattern with a multi-megabyte download from the same C2 — the
    //    channel used to pull a follow-on file (T1105 — Ingress Tool Transfer).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_05_proxy_tool_pull",
      ts: T(14 * MIN),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: infected.hostname,
      user_email: victim.email,
      src_ip: infected.ip,
      dst_ip: c2Ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      description:
        `A larger Zscaler session from ${infected.hostname} to the same host ${c2Domain} (${c2Ip}): 1.82 MB returned from a /files path, the callback channel pulling a follow-on file down onto the workstation.`,
      network: { url: `https://${c2Domain}/files/u.bin`, domain: c2Domain, method: "GET", status: 200, bytes_in: 1_908_736, user_agent: malwareUa },
      raw: {
        "action": "Allowed",
        "url.full": `https://${c2Domain}/files/u.bin`,
        "url.domain": c2Domain,
        "url.path": "/files/u.bin",
        "url.extension": "bin",
        "url.category": "Botnet",
        "url.reputation": "Malicious",
        "http.request.method": "GET",
        "http.response.status_code": 200,
        "http.user_agent": malwareUa,
        "destination.domain": c2Domain,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "network.bytes": 1_908_736,
        "session.bytes": 1_908_736,
        "network.transport": "tcp",
        "network.protocol": "ssl",
        "source.ip": infected.ip,
        "user.name": victim.sam,
        "user.email": victim.email,
        "event.action": "web-request",
        "threat.name": "SystemBC",
        "threat.category": "Command and Control",
        "threat.technique.id": "T1105",
        "threat.technique.name": "Ingress Tool Transfer",
        "threat.tactic.id": "TA0011",
        "threat.tactic.name": "Command and Control",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. SWEEP HIT #5 (EDR) — the file hash, on disk and running. Falcon shows
    //    a process on the infected host whose SHA256 is the exact malware hash
    //    from the feed — the hash MATCH is on the value, not a filename. It is
    //    the process making the callbacks (T1071.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_06_edr_hash_match",
      ts: T(16 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: infected.hostname,
      user_email: victim.email,
      src_ip: infected.ip,
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      description:
        `Falcon shows a process on ${infected.hostname}, winsyncsvc.exe from the user's AppData, whose SHA256 equals the malware hash in the feed. It is unsigned and is the process reaching ${c2Domain}. The match is on the hash value, not the file name.`,
      process: {
        name: "winsyncsvc.exe",
        pid: 7712,
        path: implantPath,
        parent_name: "explorer.exe",
        parent_pid: 5044,
        cmdline: `"${implantPath}"`,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: implantHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.ComputerName": infected.hostname,
        "event.action": "process_created",
        "process.name": "winsyncsvc.exe",
        "process.pid": "7712",
        "process.executable": implantPath,
        "process.command_line": `"${implantPath}"`,
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "5044",
        "process.hash.sha256": implantHash,
        "process.code_signature.status": "unsigned",
        "process.integrity_level": "Medium",
        "ioc.hash.sha256": implantHash,
        "ioc.domain": c2Domain,
        "ioc.ip": c2Ip,
        "threat.software.name": "SystemBC",
        "threat.technique.id": "T1071.001",
        "threat.technique.name": "Application Layer Protocol: Web Protocols",
        "threat.tactic.id": "TA0011",
        "threat.tactic.name": "Command and Control",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": infected.hostname,
        "host.ip": infected.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE DETECTION — Falcon raises the alert-grade detection that turns the
    //    hunt into a confirmed case, tying the on-disk hash to the callbacks and
    //    the flagged infrastructure. is_detection + edr_scope "hybrid" (host
    //    artifact AND the DNS/proxy/TI control-plane facets).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_tih_07_falcon_detection",
      ts: T(18 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: infected.hostname,
      user_email: victim.email,
      src_ip: infected.ip,
      severity: "critical",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      incident_id: INCIDENT,
      is_detection: true,
      edr_scope: "hybrid",
      description:
        `Falcon raised a Critical detection on ${infected.hostname}: a known-bad file hash executing and communicating with attacker infrastructure named in current intelligence. It correlates the on-disk hash, the callbacks and the flagged domain and IP into one confirmed compromise.`,
      process: {
        name: "winsyncsvc.exe",
        pid: 7712,
        path: implantPath,
        parent_name: "explorer.exe",
        parent_pid: 5044,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: implantHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "Known C2 Implant Communicating With Flagged Infrastructure",
        "crowdstrike.Tactic": "Command and Control",
        "crowdstrike.Technique": "Application Layer Protocol",
        "crowdstrike.SeverityName": "Critical",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.ComputerName": infected.hostname,
        "process.name": "winsyncsvc.exe",
        "process.hash.sha256": implantHash,
        "ioc.hash.sha256": implantHash,
        "ioc.domain": c2Domain,
        "ioc.ip": c2Ip,
        "threat.software.name": "SystemBC",
        "threat.tactic.id": "TA0011",
        "threat.tactic.name": "Command and Control",
        "threat.technique.id": "T1071.001",
        "threat.technique.name": "Application Layer Protocol: Web Protocols",
        "host.name": infected.hostname,
        "host.ip": infected.ip,
        "user.name": `${domain}\\${victim.sam}`,
        "event.outcome": "success",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "domain",
      value: c2Domain, // static-cdn-sync.cyou — the live C2, resolved and beaconed to
      first_seen: T(0),
      last_seen: T(18 * MIN),
      reputation: "malicious",
      tags: ["campaign-ioc", "c2-domain", "live"],
    },
    {
      type: "ip",
      value: c2Ip, // 193.42.108.77 — the IP the live C2 resolves to
      first_seen: T(0),
      last_seen: T(18 * MIN),
      reputation: "malicious",
      tags: ["campaign-ioc", "c2-address", "live"],
    },
    {
      type: "sha256",
      value: implantHash, // the malware file hash found on the matched host
      first_seen: T(0),
      last_seen: T(18 * MIN),
      reputation: "malicious",
      tags: ["campaign-ioc", "implant", "on-disk-match"],
    },
    {
      type: "host",
      value: infected.hostname, // WKS-NEXA-238 — the confirmed live compromise
      first_seen: T(2 * MIN),
      last_seen: T(18 * MIN),
      reputation: "suspicious",
      tags: ["affected", "confirmed-compromise", "workstation"],
    },
    {
      type: "user",
      value: victim.sam, // d.mercer — the account on the infected workstation
      first_seen: T(2 * MIN),
      last_seen: T(18 * MIN),
      reputation: "suspicious",
      tags: ["affected", "workstation-user"],
    },
    {
      type: "domain",
      value: staleDomain, // telemetry-sync-cdn.top — a FEED indicator that is stale
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
        "No detection fired before this case was opened — the work began from a vendor intelligence record. What kind of case is this, and what did the record actually give you?",
      hint: "Look at evt_tih_01: is it reporting something that happened in your estate, or is it context you then went looking for?",
      kind: "single",
      options: [
        { value: "intel_led", label: "A proactive hunt: Recorded Future promoted an indicator set (domain, IP, file hash) for an ongoing intrusion set, and the analyst went and searched the logs to see whether anything in the estate matched it" },
        { value: "edr_alert", label: "An endpoint alert: Falcon detected a running implant first, and the vendor record was pulled in afterwards purely to enrich a detection that had already fired on its own" },
        { value: "pentest", label: "A red-team exercise: the indicator set was seeded by an internal penetration test, so the matches are simulated and no real adversary activity is involved anywhere" },
        { value: "user_report", label: "A user-reported case: the account holder phoned the service desk about a slow machine, and the intelligence record was attached to that ticket after the fact" },
      ],
      answer: "intel_led",
      xp: 55,
      explanation:
        "The starting point (evt_tih_01) is a Recorded Future risk-list update: an indicator set — a domain, its IP, and a malware file hash — promoted to high risk and tied to an active intrusion set. Nothing in the estate had alarmed. That is the definition of a threat-intelligence-led hunt: you take external indicators and go looking, rather than reacting to an alert. Everything after it (the DNS, proxy and EDR hits) is what the sweep turned up. (b) inverts the order — the Falcon detection comes at the end, after the hunt has already surfaced the host; it did not start the case. (c) invents a pen-test that no record mentions, and the callbacks and on-disk hash are real telemetry. (d) invents a user report that never happened.",
    },
    {
      id: "q2",
      prompt:
        "Two hosts each 'matched' a domain from the feed: WKS-NEXA-238 and WKS-NEXA-112. One is a live compromise and one is not. Which is which, and what makes the difference?",
      hint: "Compare what follows each DNS hit — the resolved address, and whether any callbacks or on-host file hash appear afterwards.",
      kind: "single",
      options: [
        { value: "238_live_112_stale", label: "WKS-NEXA-238 is the live compromise — it resolved the flagged domain to the flagged IP, kept calling back, and carries the file hash; WKS-NEXA-112 only reached a seized domain now pointed at a sinkhole, with no callbacks and no hash" },
        { value: "112_live_238_stale", label: "WKS-NEXA-112 is the live compromise because it reached the domain first in time, and WKS-NEXA-238 is the stale one since its later hits are just cached DNS answers being replayed from the resolver" },
        { value: "both_live", label: "Both hosts are live compromises — any resolution of a flagged domain is a confirmed infection regardless of the address returned, so both must be treated as actively beaconing right now" },
        { value: "both_stale", label: "Neither is a live compromise — both domains are on a sinkhole list, so every match is historical and the case can be closed without isolating either host" },
      ],
      answer: "238_live_112_stale",
      xp: 70,
      explanation:
        "This is the core lesson: a matched indicator is a starting point, not a verdict. On WKS-NEXA-238 every signal lines up and continues — it resolved the flagged domain to the exact flagged IP, then made recurring same-size callbacks to that domain and IP, and Falcon found the campaign's file hash executing on it. That chain is a live compromise. WKS-NEXA-112 'matched' too, but the domain it queried is a former C2 that has been seized and sinkholed: it resolved to a research sinkhole address, and there are no callbacks and no implant hash on that host. Same shape, opposite meaning. (b) invents a caching story the logs do not support and reverses the verdict. (c) treats any match as proof — exactly the mistake the control teaches against. (d) is the opposite over-correction: one of the two is genuinely active.",
    },
    {
      id: "q3",
      prompt:
        "For WKS-NEXA-238, what specifically raises the DNS and proxy activity from 'a domain was looked up' to 'this host is actively talking to command-and-control infrastructure'?",
      hint: "One lookup proves little. Read the resolution and the sessions that follow it together.",
      kind: "single",
      options: [
        { value: "correlated_beacon", label: "The host resolved the flagged domain to the flagged IP and then made recurring, evenly-spaced, same-size HTTPS requests to that same domain and IP under a non-browser user agent" },
        { value: "nxdomain", label: "The domain returned NXDOMAIN, and a failed resolution to a flagged domain is on its own conclusive proof of an active channel" },
        { value: "port_only", label: "The sessions used port 443, and any outbound 443 traffic to an external address is by itself sufficient to confirm a live channel" },
        { value: "one_lookup", label: "A single DNS lookup of the domain occurred, which is the whole basis for the verdict with no need to look at the proxy sessions at all" },
      ],
      answer: "correlated_beacon",
      xp: 60,
      explanation:
        "It is the correlation across sources that makes the case. The Windows DNS log shows the host resolving the flagged domain to the exact flagged IP; the Zscaler log then shows repeated HTTPS GETs to that same domain and IP, evenly spaced, near-identical in size, under a non-browser user agent — the fingerprint of an automated callback rather than a person browsing. Neither log alone is decisive; together they show a host reaching attacker infrastructure on a cadence. (b) is wrong on the facts — the resolution succeeded (NOERROR), not NXDOMAIN — and a failed lookup would prove less, not more. (c) over-reads one field: almost all normal web traffic is 443. (d) stops at the lookup and never reads the sessions that turn a match into a confirmed channel.",
    },
    {
      id: "q4",
      prompt:
        "The feed's file hash was found on WKS-NEXA-238 via Falcon. What makes that a real detection of the campaign's malware rather than a coincidence?",
      hint: "Think about which field the match is on, and whether the process does anything that ties it to the rest of the evidence.",
      kind: "single",
      options: [
        { value: "sha256_and_behaviour", label: "The process's SHA256 equals the feed's hash exactly, and that same process is the one calling out to the flagged domain and IP — the match is on the file's content, joined to its behaviour" },
        { value: "filename_match", label: "The executable's file name matches a name listed in the feed, which is enough to confirm the malware regardless of the file's actual hash or what the process does" },
        { value: "path_match", label: "The file sits in an AppData folder, and any executable running from AppData is automatically the feed's malware because that is where implants always live" },
        { value: "signed_trusted", label: "Falcon reports the binary as signed and trusted, and a trusted signature on a flagged host is what confirms the sample is the campaign's tooling" },
      ],
      answer: "sha256_and_behaviour",
      xp: 60,
      explanation:
        "A hash IOC matches on the file's content, not its name. Falcon reports the process's SHA256 as exactly the value promoted in the feed, and — decisively — that same process is the one making the callbacks to the flagged domain and IP. Identity by hash plus corroborating behaviour is what turns 'a file with a hash' into 'the campaign's implant, running.' (b) is the classic trap: a file name is trivially changed and proves nothing; the whole point of a hash indicator is to ignore the name. (c) over-reads location — plenty of legitimate software runs from AppData, so a path is context, not proof. (d) is contradicted by the record — the binary is unsigned — and a trusted signature would argue against a match, not for it.",
    },
    {
      id: "q5",
      prompt:
        "The hunt confirmed a live infection on WKS-NEXA-238. Given that this began from a feed and that WKS-NEXA-112's hit is stale, what response fits the evidence?",
      hint: "Match each action to what the evidence supports — contain the confirmed host, act on the live indicators, and validate rather than isolate the stale hit.",
      kind: "single",
      options: [
        { value: "contain_block_hunt_validate", label: "Isolate WKS-NEXA-238 and reset d.mercer, block the live domain and IP and quarantine the on-disk file, sweep the rest of the estate for the same indicator set, and validate the sinkholed-domain hits rather than isolating those hosts" },
        { value: "isolate_every_match", label: "Immediately isolate every host that resolved any domain from the feed, including WKS-NEXA-112, since a feed match is a confirmed infection and all matched hosts must be pulled off the network at once" },
        { value: "close_from_feed", label: "Close the case as informational — the activity came from a threat-intel feed rather than a fired alert, so there is no confirmed incident that would justify containment of any host" },
        { value: "block_stale_only", label: "Block the sinkholed domain at the proxy and take no host action, because the seized former-C2 domain is the only indicator with a confirmed reputation in the record" },
      ],
      answer: "contain_block_hunt_validate",
      xp: 65,
      explanation:
        "Response has to track the evidence per host. WKS-NEXA-238 is a confirmed live compromise, so it is isolated, its user reset, the live domain and IP blocked, and the on-disk file quarantined; and because the same indicators could be anywhere, the estate is swept for them. WKS-NEXA-112's hit is stale — a sinkholed former C2 with no callbacks and no hash — so it is validated and documented, not treated like the live host. (b) is the over-reaction the control exists to prevent: isolating a host over a sinkholed match burns effort and disrupts users on no real evidence. (c) confuses provenance with severity — intelligence-led findings are still real incidents, and this one is confirmed on the host. (d) fixates on the one indicator that is not a live threat while ignoring the active infection.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Threat-Intel Hunt — From a Recorded Future IOC Set to a Live Beacon",
    threat_actor: "GLASSTHORN intrusion set (TEMP.Halberd) — SystemBC proxy-implant operator",
    attack_kind: "threat_hunt",
    briefing:
      "An intel provider pushed a new list of network destinations and a file fingerprint linked to an active operation. Nothing has alarmed yet — this is a proactive check. Work through the environment for those items, decide whether any machine is genuinely reaching attacker-run systems right now, and tell a real live hit apart from one that only resembles a match.",
    narrative: `This case did not start with an alert. At 09:00 a Recorded Future risk-list update promoted a small indicator set to high risk (Risk Score 92/99): the domain static-cdn-sync.cyou, its hosting IP 193.42.108.77, and a malware file hash, all tied to the active GLASSTHORN campaign and the SystemBC proxy-implant family. The record also flagged a related former C2, telemetry-sync-cdn.top, as seized and sinkholed. None of this was a detection in the estate — it was context, and the job was to sweep for it.

Sweeping the domains through the Windows DNS analytic log returned two hits. The first, from the day before, was WKS-NEXA-112 resolving telemetry-sync-cdn.top — but that domain answered with 184.105.247.6, a research sinkhole, and nothing else on that host followed it. That is a stale indicator: an IOC that matched but points at seized infrastructure, not a live compromise. It is the control the whole case turns on.

The second DNS hit was different. WKS-NEXA-238, the workstation of accounts-payable clerk d.mercer, resolved static-cdn-sync.cyou to exactly 193.42.108.77 — the domain-and-IP pairing named in the feed. Pivoting to the Zscaler proxy, that same host was making recurring HTTPS GETs to that domain and IP: 642 bytes, then 648 bytes six minutes later, same URL path, same non-browser user agent — the even cadence and constant size of an automated callback, not a person browsing. One session broke the pattern with a 1.82 MB download from a /files path on the same host: the channel pulling a follow-on file down (Ingress Tool Transfer).

CrowdStrike Falcon closed the loop on the endpoint. A process on WKS-NEXA-238, winsyncsvc.exe running from the user's AppData, had a SHA256 equal to the feed's malware hash — an unsigned binary, and the very process reaching the C2. The match was on the file's content, not its name. At 09:18 Falcon raised a Critical detection correlating the on-disk hash, the callbacks and the flagged infrastructure into one confirmed compromise.

Read end to end, the hunt did exactly what a hunt is for: it took external intelligence, validated it against the estate, and separated a genuine active infection on WKS-NEXA-238 from a stale, sinkholed match on WKS-NEXA-112 — the same "an indicator matched" shape, opposite verdicts.`,
    learning_objectives: [
      "Run a threat-intelligence-led hunt: start from an external indicator set (domain, IP, file hash) and sweep the estate for it, rather than reacting to an alert that already fired",
      "Correlate a DNS resolution with proxy callbacks to promote a bare indicator match into evidence of an active command-and-control channel (T1071.004 → T1071.001)",
      "Confirm a file-hash indicator by matching on the SHA256 value and its behaviour, not on the file name or path",
      "Distinguish a live compromise from a stale/sinkholed indicator hit — a seized former-C2 domain resolving to a sinkhole with no follow-on activity is not an infection",
      "Scope an intelligence-led response per host: contain and remediate the confirmed host and its live indicators, sweep for the same set, and validate rather than isolate stale matches",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T16:41:12Z", phase: "Baseline", action: `${benignHost.hostname} resolves ${staleDomain} → sinkhole ${sinkholeIp} — a stale, seized indicator, not a live hit` },
      { ts: T(0), phase: "Threat Intelligence", action: `Recorded Future promotes an indicator set (${c2Domain}, ${c2Ip}, malware hash) for the GLASSTHORN campaign` },
      { ts: T(2 * MIN), phase: "Command and Control", action: `${infected.hostname} resolves ${c2Domain} → ${c2Ip} in the DNS logs (T1071.004)` },
      { ts: T(2 * MIN + 10 * SEC), phase: "Command and Control", action: `First HTTPS callback ${infected.hostname} → ${c2Domain} (${c2Ip}), 642 bytes (T1071.001)` },
      { ts: T(8 * MIN + 12 * SEC), phase: "Command and Control", action: `Callback repeats six minutes on, 648 bytes, same path/agent — a fixed cadence (T1071.001)` },
      { ts: T(14 * MIN), phase: "Command and Control", action: `1.82 MB pull from ${c2Domain}/files — follow-on file transfer (T1105)` },
      { ts: T(16 * MIN), phase: "Command and Control", action: `Falcon: winsyncsvc.exe SHA256 == feed hash, the process making the callbacks (T1071.001)` },
      { ts: T(18 * MIN), phase: "Detection", action: "Falcon correlates on-disk hash + callbacks + flagged infrastructure into a Critical confirmed compromise" },
    ],
    questions,
  };
}
