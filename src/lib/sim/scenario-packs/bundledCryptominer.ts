/**
 * Scenario pack: "Slow Laptop — Coinminer Bundled with a Video Converter"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement, no credential theft.
 * This one starts life as a service-desk ticket rather than a security alert:
 * a machine is slow and the fans never stop. It is the most common way a real
 * junior analyst first meets malware.
 *
 * The teaching point is what "impact" means. Nothing was stolen, no account was
 * touched, and every reflex an analyst has for grading severity — data at risk,
 * accounts compromised, lateral movement — returns nothing. The impact is that
 * the organisation's compute is being spent on someone else's behalf (T1496),
 * on a laptop that is also running the finance team's month-end close. Analysts
 * who score severity purely by "what did they take" will file this as low and
 * leave it running for weeks.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { bundledCryptominerScenarioEvents } from "./bundledCryptominer.events";

export function buildBundledCryptominerScenario(
  scenarioId = "bundled-cryptominer-2026",
): ScenarioBundle {
  const { title, events, T, MIN, HOUR, host, downloadSite, pool, installerHash, minerHash } = bundledCryptominerScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: minerHash,
      first_seen: T(4 * MIN + 40_000),
      last_seen: T(15 * HOUR + 20 * MIN),
      reputation: "malicious",
      tags: ["coinminer", "unsigned", "appdata", "masquerading"],
    },
    {
      type: "sha256",
      value: installerHash,
      first_seen: T(0),
      last_seen: T(4 * MIN + 45_000),
      reputation: "malicious",
      tags: ["bundled-installer", "unsigned"],
    },
    {
      type: "domain",
      value: pool,
      first_seen: T(10 * MIN + 6_000),
      last_seen: T(15 * HOUR + 8 * MIN),
      reputation: "malicious",
      tags: ["mining-pool", "stratum"],
    },
    {
      type: "domain",
      value: downloadSite,
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["freeware-distribution", "bundling"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(15 * HOUR + 20 * MIN),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which detail in evt_bcm_05_miner_start most clearly identifies this as a coinminer rather than any other unsigned background process?",
      kind: "single",
      options: [
        { value: "stratum_args", label: "The command line — a stratum+tcp pool URL, a wallet identifier and a CPU-thread hint" },
        { value: "appdata", label: "It runs from a WinHost folder in AppData, a location commodity droppers favour over Program Files" },
        { value: "unsigned", label: "It is an unsigned 6.4 MB binary, while the other background processes on the host carry signatures" },
        { value: "parent", label: "Its parent is VideoConvertPro_Setup.exe, a freeware installer pulled from a shareware download site" },
      ],
      answer: "stratum_args",
      xp: 50,
      explanation:
        "The arguments name the activity outright: stratum+tcp is the mining-pool protocol, -u carries a wallet address, and --cpu-max-threads-hint=70 tells it how much of the machine to consume. Nothing else needs interpreting. The other three options overstate ordinary facts into rules that will burn you: plenty of legitimate software installs to AppData (Teams, Slack, Zoom), unsigned binaries are common in any estate that runs internal tooling, and the parent being the installer proves only that the bundler dropped and ran it — the very same installer also delivered a genuinely-working video converter, so 'the installer launched it' is not by itself proof of what the process does.",
    },
    {
      id: "q2",
      prompt:
        "The firewall allowed the TCP/3333 session under CORP-ANY-OUTBOUND with pan.app 'unknown-tcp'. What is the lesson for detection?",
      kind: "single",
      options: [
        { value: "long_unknown", label: "A long-lived session on a non-standard port with an unidentified app is itself a detectable pattern" },
        { value: "block_3333", label: "Port 3333 should be blocked outbound, since it is the default stratum port most mining pools listen on" },
        { value: "no_lesson", label: "None — the firewall applied CORP-ANY-OUTBOUND as written, so this is purely an endpoint problem" },
        { value: "tls", label: "TLS inspection should be enabled for this destination so the pool traffic payload can be read inline" },
      ],
      answer: "long_unknown",
      xp: 60,
      explanation:
        "pan.elapsed_time is 39,602 seconds — eleven hours on one session — with pan.app 'unknown-tcp', meaning the firewall could not identify the protocol at all. That combination is rare in normal traffic and cheap to alert on, and it does not depend on knowing this particular pool domain or port. Blocking 3333 (b) fixes exactly one port; miners move to 443 and to pool domains that look like CDNs, so port blocklists age badly. Option (d) misunderstands the traffic — stratum here is not HTTPS, so there is no TLS session to inspect.",
    },
    {
      id: "q3",
      prompt:
        "Accounts Touched is 1 and Data Accessed Outside Baseline is 'none'. How should you grade the severity?",
      kind: "single",
      options: [
        { value: "real_impact", label: "Serious — the impact is stolen compute plus an unauthorised persistent foothold, not stolen data" },
        { value: "low", label: "Low — nothing was accessed and no account was compromised, so the business impact is negligible" },
        { value: "critical", label: "Critical — assume data theft occurred and simply was not logged, given the eleven-hour outbound session" },
        { value: "info", label: "Informational — a software-policy violation for IT to clean up rather than a security incident" },
      ],
      answer: "real_impact",
      xp: 60,
      explanation:
        "MITRE puts Resource Hijacking under Impact for a reason: the harm is that the organisation's compute is being spent for someone else's profit, here with the miner tuned to 70% of CPU threads and running through the night on a machine Finance also uses for month-end close. There is a second, larger point. Something unsigned achieved execution and persistence on a corporate endpoint through a route nobody controlled — the same route delivers ransomware just as easily, and the miner is the visible symptom of an invisible gap. Option (b) is the grading error this scenario exists to correct. Option (c) invents evidence rather than reporting its absence. Option (d) hands a live persistence mechanism to the service desk as a slowness ticket.",
    },
    {
      id: "q4",
      prompt:
        "Which removal step is essential and most often forgotten?",
      kind: "single",
      options: [
        { value: "task", label: "Deleting the WinHostSync scheduled task — otherwise it relaunches the miner at the next logon" },
        { value: "kill", label: "Killing PID 11020 from the Falcon console, after which the host returns to its normal CPU load" },
        { value: "block_pool", label: "Blocking eu1.pool-relay-mining.com at the proxy, which stops the miner from doing any useful work" },
        { value: "uninstall", label: "Uninstalling VideoConvert Pro through Apps & Features, which removes everything its installer added" },
      ],
      answer: "task",
      xp: 50,
      explanation:
        "evt_bcm_04 is the event that makes this survive: a scheduled task set to AtLogon with a five-minute delay, running as the user. Kill the process (b) and it is back five minutes after the next login, which is how these tickets get reopened three times. Blocking the pool (c) idles the miner without removing it — the process still runs, still burns CPU, and still has persistence waiting for a new pool address. And uninstalling the parent application (d) is not the same as removing what it dropped; the miner lives in AppData under a different name and no uninstaller touches it.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Freeware bundler (cryptomining monetisation)",
    attack_kind: "bundled_cryptominer",
    briefing:
      "The service desk escalated LAP-1806 this morning: the machine is slow, the fans run constantly, and the battery is dead by lunchtime. CrowdStrike Falcon also has a High detection open on the same host from 09:12. Work out what is running, how it survives a reboot, and how serious this is.",
    narrative: `At 17:52 yesterday Oren Mizrahi downloaded VideoConvertPro_Setup.exe from videoconvert-pro.net. He had a conference video in the wrong format and needed it converted before the morning. He installed it at 17:56. The installer is unsigned; Windows warned him and he clicked through, which is what people do at ten to six.

Forty seconds into the install, a second binary was written: C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe, 6.4 MB, unsigned. The name is doing deliberate work — svchost is one of the most familiar strings in a Windows process list, and "helper" reads as harmless. Five seconds later schtasks.exe registered a task called WinHostSync to run it at every logon, five minutes after the desktop loads. The delay is not an accident; it puts the process start well away from the moment anyone would be watching the machine boot.

At 18:02 the installer launched it directly — the WinHostSync task is what brings it back after every future logon. Its command line names exactly what it is: stratum+tcp://eu1.pool-relay-mining.com:3333, a wallet identifier, and --cpu-max-threads-hint=70. The firewall let the connection out under the default outbound rule as pan.app "unknown-tcp", and that session stayed open for eleven hours.

The service-desk symptoms follow directly from that command line: --cpu-max-threads-hint=70 pins most of the CPU, so the fans run constantly and the battery drains by lunchtime. The session never closed and the process never idled — the laptop mined all night on a desk in an empty office, which is exactly what Falcon's Resource Hijacking detection flagged.

Nothing was stolen. One account was involved and only for its local session, and no data was touched outside baseline. The detection is still "Detection, No Action" — Falcon has been watching it run since 09:12 this morning, and the scheduled task is still registered.`,
    learning_objectives: [
      "Identify Resource Hijacking (T1496) from stratum pool arguments and a wallet identifier on a command line",
      "Recognise masquerading (T1036.005) — a binary named to blend into the Windows process list",
      "Use a long-lived 'unknown-tcp' session as a detection pattern independent of any specific port or domain",
      "Grade severity by impact type rather than by whether data was stolen",
      "Remove persistence (T1053.005) as well as the running process, or the incident reopens at the next logon",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `VideoConvertPro_Setup.exe downloaded from ${downloadSite}` },
      { ts: T(4 * MIN), phase: "Execution", action: "User runs the unsigned installer (T1204.002)" },
      { ts: T(4 * MIN + 40_000), phase: "Stealth", action: "svchost_helper.exe written to AppData under a system-like name (T1036.005)" },
      { ts: T(4 * MIN + 45_000), phase: "Persistence", action: "Scheduled task WinHostSync registered at logon with a 5-minute delay (T1053.005)" },
      { ts: T(10 * MIN), phase: "Impact", action: "Miner starts with pool and wallet arguments (T1496)" },
      { ts: T(10 * MIN + 6_000), phase: "Impact", action: `11-hour TCP/3333 session to ${pool}, allowed as unknown-tcp` },
      { ts: T(15 * HOUR + 8 * MIN), phase: "Impact", action: "Miner runs uninterrupted overnight — sustained high CPU from --cpu-max-threads-hint=70" },
      { ts: T(15 * HOUR + 20 * MIN), phase: "Detection", action: "Falcon raises a High detection — detect only, nothing contained" },
    ],
    questions,
  };
}
