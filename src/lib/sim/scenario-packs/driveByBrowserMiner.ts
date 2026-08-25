/**
 * Scenario pack: "Free PDF Tool, Injected — In-Browser Cryptojacking"
 *
 * FOUNDATION tier. One user, one laptop, no lateral movement, no credential
 * theft, no download or execution of any binary. Tomer Ravid uses a genuine,
 * frequently-used free online PDF converter for a routine work task. The site
 * itself hasn't changed — but it now loads a third-party script from a host
 * with no relationship to it, and that script compiles and runs a WebAssembly
 * cryptominer inside his own browser tab for as long as it stays open.
 *
 * This is deliberately not a bundled-installer miner: nothing is ever
 * downloaded to Downloads and nothing the user runs is malicious. The only
 * process involved is chrome.exe itself, and the only persistence the attack
 * has is the open tab — closing it ends the incident completely. Covers T1189
 * (Drive-by Compromise) for the script hand-off and T1496 (Resource
 * Hijacking) for the mining impact, including the WebSocket-to-Stratum relay
 * pattern browser miners use because a browser tab cannot open a raw TCP
 * socket to a mining pool directly.
 *
 * SOURCE-LIGHT: only `edr` (CrowdStrike Falcon) and `firewall` (Palo Alto
 * Networks NGFW) events.
 *
 * NOTE: `difficulty: "foundation"` is declared on the SCENARIOS registry
 * entry in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildDriveByBrowserMinerScenario(
  scenarioId = "drive-by-browser-miner-2026",
): ScenarioBundle {
  const B = new Date("2026-05-19T11:02:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const SEC = 1_000;
  const MIN = 60_000;

  const host = { hostname: "LAP-6690", ip: "10.14.41.22" };
  const victim = { email: "t.ravid@nexacorp.com", name: "Tomer Ravid", sam: "t.ravid" };
  const sensorId = "9c17a04eb2d6491fa88031f6bc7205de";

  const legitSite = "quickconvert-tools.io";
  const scriptHost = "edge-metrics-cdn14.com";
  const poolRelay = "ws-relay-pool9.com";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. Ordinary work. He uses this converter most weeks.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_01_site_visit",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Business Analyst",
      src_ip: host.ip,
      severity: "low",
      description:
        "LAP-6690 loaded quickconvert-tools.io/convert/pdf-to-word at 11:02, a browser-based PDF converter Tomer uses regularly, allowed under the category computer-and-internet-info.",
      network: {
        url: `https://${legitSite}/convert/pdf-to-word`,
        domain: legitSite,
        method: "GET",
        status: 200,
        bytes_in: 88_240,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "104.26.9.201",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${legitSite}/convert/pdf-to-word`,
        "pan.http_method": "GET",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "618004",
        "source.ip": host.ip,
        "url.domain": legitSite,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The page hands off to a host with no relationship to it.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_02_script_fetch",
      ts: T(8 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1189",
      mitre_tactic: "Initial Access",
      description:
        "Eight seconds into the page load, the same browser session fetched /lib/wm-core.js from edge-metrics-cdn14.com, referred by quickconvert-tools.io.",
      network: {
        url: `https://${scriptHost}/lib/wm-core.js`,
        domain: scriptHost,
        method: "GET",
        status: 200,
        bytes_in: 21_408,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "172.67.144.29",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "content-delivery-networks",
        "pan.url": `${scriptHost}/lib/wm-core.js`,
        "pan.referer": `https://${legitSite}/convert/pdf-to-word`,
        "pan.http_method": "GET",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "618011",
        "source.ip": host.ip,
        "url.domain": scriptHost,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 3. That script pulls a compiled WebAssembly module from the same host.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_03_wasm_fetch",
      ts: T(9 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1189",
      mitre_tactic: "Initial Access",
      description:
        "One second later the same session fetched /lib/wm-mod.wasm, 184 KB, from edge-metrics-cdn14.com.",
      file: { name: "wm-mod.wasm", path: "/lib/wm-mod.wasm", extension: "wasm", size: 188_416 },
      network: {
        url: `https://${scriptHost}/lib/wm-mod.wasm`,
        domain: scriptHost,
        method: "GET",
        status: 200,
        bytes_in: 188_416,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "172.67.144.29",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "content-delivery-networks",
        "pan.url": `${scriptHost}/lib/wm-mod.wasm`,
        "pan.referer": `https://${legitSite}/convert/pdf-to-word`,
        "pan.http_method": "GET",
        "pan.session_id": "618011",
        "source.ip": host.ip,
        "url.domain": scriptHost,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 4. The tab's own sandboxed renderer process — the one that will run
    //    the module. Nothing is downloaded to disk to get here.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_04_renderer",
      ts: T(10 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      description:
        "chrome.exe spawned a sandboxed renderer process for the quickconvert-tools.io tab, PID 8842, running at low integrity — Chrome's normal per-site process model.",
      process: {
        name: "chrome.exe",
        pid: 8842,
        path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        parent_name: "chrome.exe",
        parent_pid: 5120,
        cmdline:
          '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --site-per-process --lang=en-US --renderer-client-id=14',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "low",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "process_created",
        "process.name": "chrome.exe",
        "process.pid": "8842",
        "process.executable": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "process.command_line":
          '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --site-per-process --lang=en-US --renderer-client-id=14',
        "process.integrity_level": "Low",
        "process.parent.name": "chrome.exe",
        "process.parent.pid": "5120",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. THE EVENT THAT MATTERS — a long-lived WebSocket tunnel to a mining
    //    relay. Browsers can't open a raw TCP stratum socket, so the miner
    //    tunnels the mining protocol over WebSocket to a relay that speaks
    //    Stratum to the real pool on the miner's behalf.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_05_ws_open",
      ts: T(11 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "At 11:02:11 the renderer opened a WebSocket connection to ws-relay-pool9.com, categorised unknown, app websocket — the tunnel a browser-based miner uses in place of a direct Stratum socket.",
      network: { domain: poolRelay },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "45.155.204.61",
        "pan.dport": "443",
        "pan.app": "websocket",
        "pan.category": "unknown",
        "pan.url": `${poolRelay}/socket`,
        "pan.session_id": "618022",
        "source.ip": host.ip,
        "url.domain": poolRelay,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 6. The compiled module gets cached to disk — a completely ordinary
    //    Chrome mechanism, corroborating that the module actually ran.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_06_wasm_cache",
      ts: T(40 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "The renderer process (PID 8842) wrote a compiled copy of the module to Chrome's own Code Cache, confirming wm-mod.wasm was compiled and executed rather than just downloaded.",
      file: {
        name: "wm-mod_0",
        path: "C:\\Users\\t.ravid\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Code Cache\\wasm\\a1f4c9_0",
        extension: "",
        size: 176_640,
      },
      raw: {
        "crowdstrike.event_simpleName": "FileWritten",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "a1f4c9_0",
        "file.path": "C:\\Users\\t.ravid\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Code Cache\\wasm\\a1f4c9_0",
        "file.size": "176640",
        "process.name": "chrome.exe",
        "process.pid": "8842",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 7. The session finally closes, 24 minutes later, when he moves to a
    //    different task. This is the traffic-end summary for the same
    //    connection opened in evt_dbm_05.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_07_ws_close",
      ts: T(24 * MIN + 11 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "The WebSocket session to ws-relay-pool9.com stayed open for 24 minutes before closing, exchanging small, steady bursts consistent with mining job assignments and share submissions rather than a page's normal traffic pattern.",
      network: { domain: poolRelay, bytes_out: 18_400, bytes_in: 64_200 },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "45.155.204.61",
        "pan.dport": "443",
        "pan.app": "websocket",
        "pan.category": "unknown",
        "pan.bytes_sent": "18400",
        "pan.bytes_received": "64200",
        "pan.elapsed_time": "1440",
        "pan.session_id": "618022",
        "source.ip": host.ip,
        "url.domain": poolRelay,
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 8. Falcon's behavioural engine ties the pieces together.
    // ---------------------------------------------------------------------
    {
      id: "evt_dbm_08_edr_alert",
      mitre_technique: "T1496",
      ts: T(24 * MIN + 26 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Falcon raised a Critical detection on LAP-6690, tying renderer PID 8842 to a 24-minute WebSocket session against a mining relay and to sustained near-100% CPU usage on that single tab for the same window. No file was ever downloaded or executed outside the browser, so nothing was killed — the finding requires the tab to be closed.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "BrowserRendererResourceHijacking",
        "crowdstrike.detection.description":
          "A browser renderer process maintained a long-lived WebSocket connection to a known mining-relay pattern while consuming sustained high CPU, consistent with an in-browser cryptocurrency miner.",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.confidence": "80",
        "crowdstrike.detection.tactic": "Impact",
        "crowdstrike.detection.technique": "Resource Hijacking",
        "crowdstrike.detection.technique_id": "T1496",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.process_tree": "chrome.exe > chrome.exe (renderer, PID 8842)",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "malware.category": "cryptominer",
        "threat.technique.id": "T1496",
        "threat.technique.name": "Resource Hijacking",
        "event.action": "alert",
        "event.outcome": "detected",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "domain",
      value: scriptHost,
      first_seen: T(8 * SEC),
      last_seen: T(9 * SEC),
      reputation: "malicious",
      tags: ["script-injection", "wasm-delivery"],
    },
    {
      type: "domain",
      value: poolRelay,
      first_seen: T(11 * SEC),
      last_seen: T(24 * MIN + 11 * SEC),
      reputation: "malicious",
      tags: ["mining-pool-relay", "websocket-tunnel"],
    },
    {
      type: "domain",
      value: legitSite,
      first_seen: T(0),
      last_seen: T(0),
      reputation: "suspicious",
      tags: ["compromised-legitimate-site", "referrer"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(24 * MIN + 26 * SEC),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "No file was ever downloaded to Downloads and no unfamiliar .exe ever ran. Why is this still Resource Hijacking (T1496) rather than a non-event?",
      hint: "Compare this chain to a bundled-installer miner — what did the user actually run in each case?",
      kind: "single",
      options: [
        { value: "in_browser", label: "The mining code ran entirely inside the browser's own renderer process — no separate binary is needed for the technique to apply" },
        { value: "not_real", label: "It isn't really Resource Hijacking without a dropped binary; this should be logged as informational" },
        { value: "cache_is_malware", label: "The WASM file cached to disk in evt_dbm_06 is itself the malware and should be quarantined" },
        { value: "site_compromised_only", label: "The only real issue is that quickconvert-tools.io was compromised; nothing downstream matters on its own" },
      ],
      answer: "in_browser",
      xp: 50,
      explanation:
        "T1496 is defined by the outcome — compute resources spent on someone else's behalf — not by the delivery mechanism. Here the 'payload' is a WebAssembly module that a legitimate, unmodified chrome.exe process compiles and runs entirely within its own sandbox; no separate executable is ever required. (b) misreads the technique as needing a dropped binary, which most in-browser cryptojacking never has. (c) misidentifies the cached file: it's Chrome's own ordinary code cache, harmless on its own and only meaningful as corroborating evidence once you already know the module was malicious. (d) is half right that the site being a delivery vector matters, but the impact — the tab spending CPU on someone else's mining for 24 minutes — is a separate, real fact regardless of blame for the initial compromise.",
    },
    {
      id: "q2",
      prompt:
        "evt_dbm_06 shows Chrome writing a file into its own Code Cache folder. Every site chrome.exe visits does this routinely. Why is this event still worth including in the investigation?",
      kind: "single",
      options: [
        { value: "corroborates_execution", label: "On its own it proves nothing, but it corroborates — via matching PID and timing — that wm-mod.wasm from evt_dbm_03 was actually compiled and run, not just fetched" },
        { value: "proves_malware", label: "Any file written to Code Cache by a script from a third-party host is definitive proof of malware" },
        { value: "shows_persistence", label: "It shows the miner has established persistence and will restart with the browser" },
        { value: "irrelevant", label: "It's routine browser behaviour and has no evidentiary value here at all" },
      ],
      answer: "corroborates_execution",
      xp: 50,
      explanation:
        "Downloading a .wasm file (evt_dbm_03) only proves the browser fetched bytes — it doesn't by itself prove they ran. The Code Cache write, tied to the same renderer PID (8842) shortly afterward, is what closes that gap: it shows the module reached the compile-and-execute stage. (b) overclaims — Code Cache fills up with entries from every site a user visits and is not inherently suspicious; it only matters here because of what else is happening on the same PID and connection. (c) is incorrect: Code Cache is cleared with normal browser cache maintenance and holds nothing that restarts anything — it isn't a persistence mechanism. (d) throws away a legitimate corroborating detail; 'routine' doesn't mean 'uninformative' when it lines up with the rest of the timeline.",
    },
    {
      id: "q3",
      prompt:
        "The tab that hosts quickconvert-tools.io could theoretically host several renderer processes for several open tabs. Which pair of events lets you confirm PID 8842 specifically — and not some other tab — is the one running the miner?",
      kind: "single",
      options: [
        { value: "renderer_and_wsopen", label: "evt_dbm_04_renderer and evt_dbm_05_ws_open — the renderer's creation timestamp and the WebSocket connection opening one second later, in immediate sequence" },
        { value: "site_and_renderer", label: "evt_dbm_01_site_visit and evt_dbm_04_renderer — the initial page load and the renderer being created" },
        { value: "script_and_wasm", label: "evt_dbm_02_script_fetch and evt_dbm_03_wasm_fetch — the loader script and the module it pulled" },
        { value: "wsopen_and_wsclose", label: "evt_dbm_05_ws_open and evt_dbm_07_ws_close — the connection opening and the same connection ending" },
      ],
      answer: "renderer_and_wsopen",
      xp: 60,
      explanation:
        "evt_dbm_04 creates renderer PID 8842 at T+10s; evt_dbm_05 shows the WebSocket connection opening at T+11s, one second later — close enough in sequence, with only one renderer process in this timeline, to attribute the connection to that specific process rather than assuming it. evt_dbm_06 later reinforces the same attribution by citing the identical PID. (b) only tells you a page loaded and a renderer exists — it doesn't connect that renderer to any network activity. (c) shows what was fetched, not which process later used it. (d) confirms the connection's own lifespan, which matters for scoping duration, but says nothing about which process owns it — that link comes from the timing against evt_dbm_04.",
    },
    {
      id: "q4",
      prompt:
        "pan.category on the mining connection is 'unknown' and pan.app is 'websocket' — a category and app-type that cover enormous amounts of legitimate traffic. What's the practical implication for detection?",
      kind: "single",
      options: [
        { value: "duration_signal", label: "Category and app alone can't distinguish this from ordinary web traffic; duration and destination pattern (a single relay held open for 24 minutes) are what make it stand out" },
        { value: "block_websocket", label: "WebSocket traffic should be blocked outbound by default, since legitimate sites rarely need it" },
        { value: "policy_bug", label: "This traffic should have been categorised as mining and blocked; its absence means the category database is broken" },
        { value: "no_signal", label: "There's no way to detect this at the firewall layer at all; only the EDR alert matters" },
      ],
      answer: "duration_signal",
      xp: 50,
      explanation:
        "Both fields describe huge swaths of normal browsing — chat apps, dashboards, and collaboration tools all use WebSocket, and 'unknown' is simply the absence of a specific category, not a red flag by itself. What's unusual is behavioural: a single destination held open continuously for 24 minutes with steady small bidirectional bursts, which is not how a page's WebSocket connections normally behave (most close or go idle quickly). (b) would break a large amount of legitimate functionality — WebSocket is mainstream web infrastructure, not an indicator on its own. (c) assumes a database failure without evidence; mining-relay domains rotate constantly and rarely have time to accumulate a category. (d) is too strong — the firewall log is exactly what supplies the duration and destination pattern that make this detectable, even without a category to lean on.",
    },
    {
      id: "q5",
      prompt:
        "You're closing this ticket. Given nothing was downloaded and nothing persists outside the browser session, what does adequate remediation look like?",
      kind: "single",
      options: [
        { value: "close_tab_notify", label: "Confirm the browser tab/process is closed, notify the site owner that their page is serving injected mining script, and add the two attacker domains to the blocklist" },
        { value: "reimage", label: "Reimage LAP-6690 — an unknown WebAssembly module executed on the host and the machine can no longer be trusted" },
        { value: "reset_password", label: "Force a password reset for Tomer, since arbitrary code executed on his session" },
        { value: "ignore", label: "No action needed beyond noting it — Detection, No Action means Falcon judged this not worth remediating" },
      ],
      answer: "close_tab_notify",
      xp: 60,
      explanation:
        "Nothing in this chain wrote a persistence mechanism, touched credentials, or left anything running once the tab and its renderer process are gone — closing them ends the entire impact by design, and evt_dbm_07 already shows the connection was already closed before the alert fired. The remaining work is upstream: quickconvert-tools.io is an unwitting victim serving attacker-controlled script and needs to be told, and the two domains belong on the network blocklist so the same tab doesn't reconnect on reload. (b) is disproportionate — nothing here reached disk outside Chrome's own ordinary cache, so there is no unknown-state binary to distrust the host over. (c) has no basis: no credential store, token, or session was touched anywhere in this evidence. (d) misreads 'Detection, No Action' — that field describes what Falcon's sensor did automatically (nothing, because killing chrome.exe would be disruptive), not a verdict that the finding is unimportant.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Free PDF Tool, Injected — In-Browser Cryptojacking",
    threat_actor: "Commodity cryptojacking script operator (web-injection)",
    attack_kind: "drive_by_browser_miner",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-6690 at 11:26, citing a browser renderer process that held a 24-minute WebSocket connection to a mining relay while running at sustained high CPU. The user was using a familiar online PDF tool at the time. Work out where the mining code came from and what, if anything, needs remediation.",
    narrative: `At 11:02 Tomer Ravid opened quickconvert-tools.io, a free browser-based PDF converter he uses most weeks, to turn a contract into an editable Word file. The firewall allowed the page under computer-and-internet-info — an accurate category for a genuine tool.

Eight seconds into the page load, the same browser session fetched a script from edge-metrics-cdn14.com, a host with no connection to quickconvert-tools.io, carrying that page's URL as its referer. A second later it fetched wm-mod.wasm, 184 KB, from the same host — a compiled WebAssembly module. Ten seconds in, chrome.exe spawned a new sandboxed renderer process, PID 8842, for that tab — Chrome's ordinary per-site process model, running at low integrity as it always does.

One second after that, PID 8842 opened a WebSocket connection to ws-relay-pool9.com and held it open. A browser tab can't open a raw TCP socket to a mining pool directly, so browser miners tunnel the Stratum mining protocol over WebSocket to a relay that speaks Stratum to the real pool on their behalf — which is exactly the shape of this connection. Half a minute later, the same renderer wrote a compiled copy of the module into Chrome's own Code Cache — ordinary browser behaviour, but tied by PID and timing to everything else, it confirms the module didn't just download, it ran.

The connection stayed open for 24 minutes, exchanging small steady bursts, before closing when Tomer moved on to something else. Falcon's behavioural engine flagged the pattern fifteen seconds after that: a renderer process, a long-lived relay connection, sustained high CPU on one tab, tied together as Resource Hijacking. Nothing was killed — there was no separate process to kill, and no file outside Chrome's own cache was ever written.`,
    learning_objectives: [
      "Recognise in-browser cryptojacking (T1189 hand-off into T1496 impact) as distinct from a bundled-installer miner — no executable is ever downloaded or run",
      "Treat a browser's own on-disk caching of a compiled module as corroborating evidence of execution, not evidence of malware on its own",
      "Correlate a specific renderer process, by PID and timing, with the outbound connection it owns to scope which browser tab is responsible",
      "Explain why disguising mining traffic as ordinary WebSocket / uncategorised application traffic defeats simple category- or protocol-based firewall rules",
      "Scope remediation correctly for a transient, session-bound compromise — closing the browser ends the impact; there is no persistence mechanism to remove",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `User loads a genuine page on ${legitSite}` },
      { ts: T(8 * SEC), phase: "Initial Access", action: `Injected script loaded from ${scriptHost} (T1189)` },
      { ts: T(9 * SEC), phase: "Initial Access", action: "Compiled WebAssembly module fetched from the same host (T1189)" },
      { ts: T(10 * SEC), phase: "Execution", action: "Chrome spawns a sandboxed renderer process for the tab" },
      { ts: T(11 * SEC), phase: "Impact", action: `Renderer opens a WebSocket tunnel to mining relay ${poolRelay} (T1496)` },
      { ts: T(40 * SEC), phase: "Impact", action: "Compiled module cached to disk by the same renderer process" },
      { ts: T(24 * MIN + 11 * SEC), phase: "Impact", action: "Mining connection closes after 24 minutes (T1496)" },
      { ts: T(24 * MIN + 26 * SEC), phase: "Detection", action: "Falcon raises a Critical Resource Hijacking detection — no process killed" },
    ],
    questions,
  };
}
