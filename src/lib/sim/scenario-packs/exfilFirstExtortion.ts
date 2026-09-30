/**
 * Scenario pack: "Exfiltration-First Extortion — Ransomware Without an Encryptor"
 *
 * ADVANCED tier. An attacker who already has an interactive foothold on
 * LAPTOP-NX-R.DOYLE — a Finance Operations Manager's laptop at NexaCorp
 * Financial Ltd. — spends one overnight window staging, archiving and
 * exfiltrating client financial records to a consumer cloud-storage service,
 * then extorts the company over the stolen data alone. How the foothold was
 * obtained is deliberately out of scope: this pack starts at Collection.
 *
 * The teaching point is that this IS a ransomware-class incident even though
 * nothing on disk was ever encrypted, renamed, or replaced with a ransom
 * note. A growing share of real extortion crews (BianLian and Karakurt are
 * public examples) have dropped the encryption step entirely — it is noisy,
 * recoverable from backups, and unnecessary once the data itself is gone.
 * Every event in this pack is deliberately mundane on its own: a recursive
 * copy job, a password-protected archive, a sync tool talking to a well-known
 * cloud provider, a DLP policy that is live but configured to audit rather
 * than block. The signal is the SHAPE of the sequence — staging, archive,
 * sustained cloud egress, in that order, overnight — combined with the
 * conspicuous ABSENCE of any T1486 (Data Encrypted for Impact) telemetry
 * anywhere in the environment.
 *
 * Covers T1074.001 (Local Data Staging), T1560.001 (Archive Collected Data:
 * Archive via Utility) and T1567.002 (Exfiltration Over Web Service:
 * Exfiltration to Cloud Storage).
 *
 * SOURCES: edr (Microsoft Defender for Endpoint) + firewall (Palo Alto
 * Networks NGFW) + dlp (Microsoft Purview) + siem (Microsoft Sentinel) — the
 * exact stack NexaCorp's company profile already declares. This pack should
 * be company-allowlisted to environments that plausibly run Purview DLP,
 * i.e. Microsoft-365-email shops: nexacorp, medcore and globallogis. See the
 * delivery notes for the reasoning; rocketstack (Google Workspace, no
 * Microsoft 365) is a poor fit for a Purview-flavoured DLP event.
 *
 * NOTE: `difficulty: "advanced"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { exfilFirstExtortionScenarioEvents } from "./exfilFirstExtortion.events";

export function buildExfilFirstExtortionScenario(
  scenarioId = "exfil-first-extortion-2026",
): ScenarioBundle {
  const { title, events, T, MIN, HOUR, host, victim, fileServer, megaNode, archiveHash, rcloneHash, flaggedFileHash } = exfilFirstExtortionScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "domain",
      value: megaNode,
      first_seen: T(24 * MIN + 15_000),
      last_seen: T(59 * MIN),
      reputation: "suspicious",
      tags: ["legitimate-cloud-service", "abused-for-exfiltration", "exfil-destination"],
    },
    {
      type: "sha256",
      value: archiveHash,
      first_seen: T(9 * MIN),
      last_seen: T(10 * MIN),
      reputation: "suspicious",
      tags: ["archive-utility", "unsigned", "portable", "staging-dir"],
    },
    {
      type: "sha256",
      value: rcloneHash,
      first_seen: T(24 * MIN),
      last_seen: T(59 * MIN),
      reputation: "malicious",
      tags: ["renamed-binary", "cloud-sync-tool", "exfil-tool", "masquerading"],
    },
    {
      type: "sha256",
      value: flaggedFileHash,
      first_seen: T(10 * MIN),
      last_seen: T(10 * MIN),
      reputation: "unknown",
      tags: ["sensitivity-labeled", "client-data", "dlp-match"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(2 * HOUR + 35 * MIN),
      reputation: "unknown",
      tags: ["affected", "existing-foothold"],
    },
    {
      type: "email",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(2 * HOUR + 35 * MIN),
      reputation: "unknown",
      tags: ["compromised-session", "legitimate-access-abused"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Three technique tags appear across this chain: T1074.001, T1560.001 and T1567.002. Which event does T1560.001 (Archive via Utility) belong to?",
      hint: "Staging gathers files. Archiving compresses them. Exfiltration moves them off the host — three separate pieces of evidence, in that order.",
      kind: "single",
      options: [
        { value: "archive", label: "7z.exe archive — staged files compressed into a password-protected, header-encrypted multi-volume set" },
        { value: "staging", label: "Local staging — robocopy mirrors the entire \\\\SRV-NX-FIN01\\Shares tree to a local cache folder" },
        { value: "exfil_tool", label: "rclone launch — the renamed rclone binary starts up on the laptop with a Mega remote configured as its target" },
        { value: "session_end", label: "Firewall session end — the Mega session closes after logging 39.6 GB sent from the laptop overnight" },
      ],
      answer: "archive",
      xp: 40,
      explanation:
        "evt_efe_01 is T1074.001 (Local Data Staging) — files are gathered into one local location, nothing is compressed or moved yet. evt_efe_02 is T1560.001: a utility, 7z.exe, is used to package the staged files into an archive — the technique is specifically about the act of archiving, independent of what happens to the archive afterwards. evt_efe_04 and evt_efe_06 are both T1567.002 (Exfiltration to Cloud Storage) — the tool starting, and the bytes actually leaving. Treating all three as one blob loses the point of the exercise: each technique has its own, separately-timestamped evidence, and an analyst who can only point at 'the archive' without knowing which log proves it hasn't actually read the chain.",
    },
    {
      id: "q2",
      prompt:
        "evt_efe_05 and evt_efe_06 show pan.action: allow and pan.category: online-storage-and-backup for a session that ultimately moved 39.6 GB overnight. Why didn't the firewall block this on its own?",
      kind: "single",
      options: [
        { value: "category_not_volume", label: "Category policy judges what kind of site a destination is, not how much data crosses the session, and no volume limit was set for this one" },
        { value: "tls_bypass", label: "TLS inspection was disabled for this session, so the firewall only saw the handshake and could not measure how much data moved inside it" },
        { value: "misrouted", label: "The traffic was classified as internal because the Mega storage node's IP falls inside NexaCorp's own address range, bypassing egress policy" },
        { value: "dlp_should_block", label: "It is purely a DLP failure — the firewall has no role here, because stopping outbound transfers by content or size belongs to DLP alone" },
      ],
      answer: "category_not_volume",
      xp: 40,
      explanation:
        "online-storage-and-backup is a legitimate, widely-used category — blanket-blocking it would break real business use of services like OneDrive, Dropbox or Box elsewhere in the company. Category policy answers 'what kind of site is this', not 'how much or what data is inside this session', so a category-allowed destination has no volume ceiling by default. Option (b) is contradicted by the log itself: pan.bytes_sent and pan.bytes_received are populated precisely because TLS inspection was active. Option (c) has no supporting evidence — the destination is a public IP. Option (d) draws too sharp a line: firewalls and DLP have different, complementary jobs, and the actual gap here is that NOTHING in the stack — not the firewall, not DLP — was configured to stop a large transfer to an allowed category, which is exactly the finding worth writing up.",
    },
    {
      id: "q3",
      prompt:
        "evt_efe_03_dlp_audit shows purview.ActionTaken: Audit and no BlockAccess anywhere in PolicyDetails.Rules.Actions. What does that tell you about NexaCorp's DLP posture at the time of the incident?",
      kind: "single",
      options: [
        { value: "detect_not_prevent", label: "The Endpoint DLP rule was live and matched 1,847 labeled items, but its actions only logged and notified, so nothing interrupted the archiving" },
        { value: "policy_disabled", label: "The DLP policy was disabled at the time, so this record is a retroactive audit entry that Purview generated once the policy was switched back on" },
        { value: "false_positive", label: "This is a false positive — 7z.exe is common IT software, so a labeled-data match on its file reads should be tuned out of the rule and dismissed" },
        { value: "blocked_but_logged_wrong", label: "The policy did block the activity; ActionTaken: Audit is a known logging quirk and does not reflect the enforcement that happened on the host" },
      ],
      answer: "detect_not_prevent",
      xp: 50,
      explanation:
        "o365.PolicyDetails.Rules.RuleMode is 'Enforce' — the policy is live, not disabled, which rules out (b). It matched 1,847 real instances of IBAN data at 90% confidence, which is not a plausible false positive to wave away as (c) suggests. And RuleMode: Enforce with Actions: [Audit, NotifyUser] — no BlockAccess or RestrictAccess anywhere — means the enforced behaviour IS logging, not blocking, which directly contradicts (d). This is the core lesson: 'enforced' does not mean 'blocking'. A DLP rule can be fully active and still be a pure visibility control, if none of its configured actions actually restrict anything — which is precisely why the archive kept building undisturbed.",
    },
    {
      id: "q4",
      prompt:
        "There is no encryption event, no ransom-note file, and no mass file-rename anywhere in this environment — yet NexaCorp's security mailbox has received a data-extortion demand. How should this incident be classified and prioritised?",
      kind: "single",
      options: [
        { value: "exfil_extortion_ransomware_class", label: "Ransomware-class: an exfil-only extortion where the leverage is stolen data, not encrypted systems — scope, contain, assess notification duties" },
        { value: "downgrade_no_encryption", label: "Downgrade it — with no encryptor there is no ransomware, so it becomes a standard data-loss case handled on the normal DLP-violation triage timeline" },
        { value: "wait_for_encryption", label: "Hold at the current priority and monitor for an encryptor being deployed, since encryption is what formally defines the ransomware category" },
        { value: "false_extortion", label: "Treat the extortion email as unverified and unrelated to this activity until the sender independently proves possession of the actual client files" },
      ],
      answer: "exfil_extortion_ransomware_class",
      xp: 60,
      explanation:
        "Several real extortion crews (BianLian and Karakurt are documented examples) have publicly dropped the encryption step entirely — encrypting systems is noisy, recoverable from backups, and unnecessary once the data itself is gone. Every technical marker of exfiltration is present and dated inside one overnight window (T1074.001 → T1560.001 → T1567.002), and the volume matches what the extortion message references. Option (b) treats 'no encryptor' as 'no ransomware' — exactly the outdated assumption this scenario exists to correct; the same regulatory-notification and executive-escalation obligations apply either way, because client financial records left the building. Option (c) trades response time for a confirmation that will never come in an exfil-only operation — there is nothing left in this playbook to encrypt. Option (d) is the riskiest read of all: the byte counts, archive artifacts and DLP match count already corroborate the claim independently of the email itself.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Exfiltration-only extortion crew (BianLian/Karakurt-style — no encryptor deployed)",
    attack_kind: "exfil_first_extortion",
    briefing:
      "Sentinel escalated an incident to Critical at 03:40 overnight after NexaCorp's security mailbox received a data-extortion email referencing client records. No EDR containment action fired, no files were encrypted, and no ransom note exists anywhere on disk. Work out what actually left the building, how, and why nothing stopped it.",
    narrative: `Some time before this window opens, an attacker already had an interactive foothold on LAPTOP-NX-R.DOYLE — Rhian Doyle's laptop, a Finance Operations Manager whose job genuinely requires access to the client-records file share. How that foothold was obtained is outside this incident's evidence; what the logs show starts at 01:05.

At 01:05, robocopy.exe — a signed, built-in Windows utility — mirrored the entire root of \\\\SRV-NX-FIN01\\Shares into a local cache folder under C:\\ProgramData\\Adobe\\ARM, a path chosen to look like ordinary Adobe update debris. Nine minutes later, a portable copy of 7z.exe sitting in the same folder built a password-protected, header-encrypted archive from everything staged, split into 2 GB volumes. A minute into that archiving pass, Microsoft Purview Endpoint DLP matched 1,847 instances of labeled client financial data being read by an unallowed application — and logged it, because the matching rule's configured action is Audit, not Block.

At 01:29, a binary named AdobeARMHelper.exe — not the real Adobe update path — started with an rclone-style command line: copy the local archive to a remote named 'mega', using a config file dropped alongside it. Fifteen seconds later the firewall logged a new TLS session to gfs301n112.userstorage.mega.co.nz, allowed under the category online-storage-and-backup, exactly as any legitimate use of that service would be. The session closed at 02:04, thirty-five minutes later, having sent 39.6 GB out.

A minute after that, Sentinel correlated the staging, the archive and the sustained egress into a single incident — and recorded, alongside the correlation, that the encryption-events count, the ransom-note-artifact count and the mass-file-rename count for the entire window are all zero. At 03:38, NexaCorp's security mailbox received a message referencing a volume of client data consistent with what had just left the building. Nothing on any host, anywhere in the environment, had been encrypted.`,
    learning_objectives: [
      "Recognise exfiltration-only extortion as a ransomware-class incident even with zero T1486 (Data Encrypted for Impact) telemetry",
      "Sequence local data staging (T1074.001), archive via utility (T1560.001) and exfiltration to cloud storage (T1567.002) as three distinct, separately-evidenced techniques rather than one event",
      "Read Purview Endpoint DLP RuleMode and Actions fields to distinguish an enforced-but-audit-only policy from a disabled or a blocking one",
      "Explain why a firewall category-allow decision (online-storage-and-backup) says nothing about the volume of a transfer",
      "Correlate a DeviceId, hostname and user identity across EDR, DLP and SIEM sources to reconstruct one incident from independently-generated logs",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Collection", action: `robocopy mirrors \\\\${fileServer.name}\\Shares to a local staging cache on LAPTOP-NX-R.DOYLE (T1074.001)` },
      { ts: T(9 * MIN), phase: "Collection", action: "7z.exe builds a password-protected, header-encrypted multi-volume archive from the staged files (T1560.001)" },
      { ts: T(10 * MIN), phase: "Detection", action: "Purview Endpoint DLP matches 1,847 instances of labeled client data read by an unallowed app — logged, not blocked" },
      { ts: T(24 * MIN), phase: "Exfiltration", action: "Renamed rclone binary (AdobeARMHelper.exe) starts with a Mega cloud remote configured" },
      { ts: T(24 * MIN + 15_000), phase: "Exfiltration", action: "Firewall session opens to a Mega storage node, allowed under online-storage-and-backup" },
      { ts: T(59 * MIN), phase: "Exfiltration", action: "Session closes after 39.6 GB transferred over roughly 35 minutes (T1567.002)" },
      { ts: T(60 * MIN), phase: "Detection", action: "Sentinel correlates staging, archive and egress into one incident; zero encryption/ransom-note/rename events in the window" },
      { ts: T(2 * HOUR + 35 * MIN), phase: "Extortion", action: "Security mailbox receives a data-extortion demand; incident escalated to Critical" },
    ],
    questions,
  };
}
