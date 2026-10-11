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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { driveByBrowserMinerScenarioEvents } from "./driveByBrowserMiner.events";

export function buildDriveByBrowserMinerScenario(
  scenarioId = "drive-by-browser-miner-2026",
): ScenarioBundle {
  const { title, events, T, SEC, MIN, host, legitSite, scriptHost, poolRelay } = driveByBrowserMinerScenarioEvents();

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
        { value: "in_browser", label: "The coinminer executed as WebAssembly inside Chrome's own sandbox — T1496 does not require a dropped executable" },
        { value: "not_real", label: "Without a dropped binary it falls short of Resource Hijacking, so it should be logged as an informational PUA event" },
        { value: "cache_is_malware", label: "The WASM copy cached to disk by the renderer is itself the malware, and quarantining it resolves the hijacking" },
        { value: "site_compromised_only", label: "The real issue is that quickconvert-tools.io was compromised; the tab's CPU use is just a symptom of the site owner's problem" },
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
        { value: "corroborates_execution", label: "Alone it proves nothing, but the matching PID and timing corroborate that wm-mod.wasm was compiled and run, not just fetched" },
        { value: "proves_malware", label: "A Code Cache entry created for a module served from a third-party host is itself proof the module is malicious" },
        { value: "shows_persistence", label: "It shows the compiled module has been stored for reuse, so the miner will relaunch by itself whenever Chrome restarts on this laptop" },
        { value: "irrelevant", label: "It is routine browser housekeeping written for every site, so it adds nothing beyond what the alert already says" },
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
        { value: "renderer_and_wsopen", label: "The PID 8842 renderer creation and the WebSocket opening one second later, in direct sequence" },
        { value: "site_and_renderer", label: "The quickconvert-tools.io page load and the PID 8842 renderer created for that tab moments later" },
        { value: "script_and_wasm", label: "The wm-core.js loader fetch from edge-metrics-cdn14.com and the wm-mod.wasm module it pulled" },
        { value: "wsopen_and_wsclose", label: "The WebSocket opening to ws-relay-pool9.com and that same connection closing 24 minutes later" },
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
        { value: "duration_signal", label: "Category and app can't separate it from normal web traffic; one relay held open for 24 minutes is what stands out" },
        { value: "block_websocket", label: "Outbound WebSocket should be blocked by default at the perimeter, since few business sites depend on it" },
        { value: "policy_bug", label: "It should have been categorised as mining and blocked; an 'unknown' category means the vendor URL database is broken" },
        { value: "no_signal", label: "The firewall layer cannot detect this pattern, so only the endpoint EDR alert carries any detection value" },
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
        { value: "close_tab_notify", label: "Confirm the tab and renderer are closed, tell the site owner their page serves injected mining script, and blocklist both domains" },
        { value: "reimage", label: "Reimage LAP-6690 — an unknown WebAssembly module executed on the host, so the machine can no longer be trusted" },
        { value: "reset_password", label: "Force a password reset for Tomer and revoke his sessions, since attacker-supplied code executed under his login" },
        { value: "ignore", label: "No action needed beyond noting it — the Falcon disposition 'Detection, No Action' means it needs no remediation" },
      ],
      answer: "close_tab_notify",
      xp: 60,
      explanation:
        "Nothing in this chain wrote a persistence mechanism, touched credentials, or left anything running once the tab and its renderer process are gone — closing them ends the entire impact by design, and evt_dbm_07 already shows the connection was already closed before the alert fired. The remaining work is upstream: quickconvert-tools.io is an unwitting victim serving attacker-controlled script and needs to be told, and the two domains belong on the network blocklist so the same tab doesn't reconnect on reload. (b) is disproportionate — nothing here reached disk outside Chrome's own ordinary cache, so there is no unknown-state binary to distrust the host over. (c) has no basis: no credential store, token, or session was touched anywhere in this evidence. (d) misreads 'Detection, No Action' — that field describes what Falcon's sensor did automatically (nothing, because killing chrome.exe would be disruptive), not a verdict that the finding is unimportant.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
