import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { linuxPrivescSuidScenarioEvents } from "./linuxPrivescSuid.events";

/**
 * Foothold www-data → SUID misconfiguration → ROOT (INTERMEDIATE)
 *
 * A pure-Linux privilege-escalation intrusion. It fills the Privilege-Escalation
 * gap in the platform's MITRE coverage and adds Linux depth beyond the SSH /
 * cryptominer pack. There are NO Windows concepts here: privilege is expressed
 * the way Linux expresses it — uid / gid / euid / egid / auid / suid — and the
 * whole story turns on one number changing (euid: 33 → 0) while another does NOT
 * (uid / auid stay at the www-data service account).
 *
 * THE FOOTHOLD IS OUT OF SCOPE. The attacker is already executing commands as
 * www-data (uid 33) — the working assumption is a web shell on an internet-facing
 * Ubuntu application server. auditd therefore records these commands with
 * auid=4294967295 (loginuid unset): www-data has no login session, because a web
 * server process never logged in. That unset loginuid is itself a signal — an
 * interactive-looking command run under a service account that never authenticated.
 *
 * PRIVILEGE CHAIN (the spine of the scenario):
 *   1. Discovery: `id` confirms uid=33(www-data), then `sudo -l` returns
 *      res=failed — www-data is NOT in sudoers, so the sanctioned road to root
 *      (sudo, which would be logged and attributable) is closed.
 *   2. The attacker enumerates SUID binaries with `find / -perm -4000 -type f`
 *      and discovers that /usr/bin/find itself carries the setuid bit — a real
 *      class of deployment mistake (a packaging/`chmod u+s` accident).
 *   3. EXPLOIT (GTFOBins): `find . -exec /bin/sh -p \; -quit`. Because find is
 *      SUID root, the execve of /bin/sh runs with euid=0; `sh -p` preserves that
 *      euid instead of dropping it back to the real uid. The auditd SYSCALL for
 *      the find execve shows the crux directly: uid=33 euid=0.
 *   4. Every later action runs as uid=33 euid=0: reading /etc/shadow (a
 *      root-only file), and creating a uid-0 backdoor account. The account and
 *      its remote login are the persistence + payoff.
 *
 * The benign discriminator (evt 1) is the real Linux administrator using sudo
 * legitimately: res=success, auid=1001 — a human loginuid — through the audited
 * sudo path. It is the control case for "root was reached": one route is
 * sanctioned and attributable, the other keeps the www-data identity and forges
 * euid=0 with no authorization record at all.
 */
export function buildLinuxPrivescSuidScenario(
  scenarioId = "linux-privesc-suid-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, admin, attackerIp, backdoorUser, keyFingerprint, INCIDENT } = linuxPrivescSuidScenarioEvents();

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "user",
      value: "www-data",
      first_seen: T(38 * MIN),
      last_seen: T(47 * MIN),
      reputation: "suspicious",
      tags: ["compromised-foothold", "uid-33", "service-account", "no-login-session"],
    },
    {
      type: "host",
      value: host.fqdn,
      first_seen: T(38 * MIN),
      last_seen: T(56 * MIN),
      // "unknown", not "malicious": this is the organisation's own internet-facing
      // app server — the victim, not adversary infrastructure. Tagging your own
      // estate malicious is how a blocklist ends up blocking production.
      reputation: "unknown",
      tags: ["internet-facing", "linux-app-server", "compromised"],
    },
    {
      type: "user",
      value: backdoorUser,
      first_seen: T(47 * MIN),
      last_seen: T(52 * MIN),
      reputation: "malicious",
      tags: ["backdoor-account", "uid-0", "root-equivalent", "persistence"],
    },
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(52 * MIN),
      last_seen: T(56 * MIN),
      reputation: "malicious",
      // The backdoor SSH login authenticates with the attacker's ed25519 key —
      // its fingerprint (keyFingerprint) is surfaced as event evidence on the
      // sshd login record, not as a separate IOC (an OpenSSH key fingerprint is
      // not a file sha256, so it does not belong in the hash-typed IOC set).
      tags: ["external", "backdoor-ssh-login", "publickey"],
    },
  ];

  const killchain = [
    { ts: T(0), phase: "Baseline", action: "Administrator d.okonkwo escalates to root through sudo — res=success, auid 1001, the sanctioned and attributable path (T1548.003)" },
    { ts: T(38 * MIN), phase: "Discovery", action: "www-data shell runs id — uid 33, and auid 4294967295: a command under a service account with no login session (T1033)" },
    { ts: T(39 * MIN), phase: "Discovery", action: "sudo -l returns res=failed — www-data is not in sudoers, the sudo road to root is closed (T1033)" },
    { ts: T(41 * MIN), phase: "Discovery", action: "find / -perm -4000 enumerates SUID binaries and reveals /usr/bin/find is setuid — a misconfiguration (T1083)" },
    { ts: T(43 * MIN), phase: "Privilege Escalation", action: "find . -exec /bin/sh -p \\; abuses the SUID bit — the execve runs with euid=0 while uid stays 33 (T1548.001)" },
    { ts: T(43 * MIN), phase: "Privilege Escalation", action: "Falcon detects /bin/sh spawned by find with effective UID root — the alert-grade EDR detection (T1068)" },
    { ts: T(45 * MIN), phase: "Credential Access", action: "cat /etc/shadow succeeds with euid=0 — a root-only file read under the www-data real uid (T1003.008)" },
    { ts: T(47 * MIN), phase: "Persistence", action: "useradd creates the uid-0 account sysupdate — a second root-equivalent identity (T1136.001)" },
    { ts: T(52 * MIN), phase: "Persistence", action: "Accepted publickey for sysupdate from 193.32.162.140 — the backdoor account logs in remotely (T1078.003)" },
    { ts: T(56 * MIN), phase: "Detection", action: "Sentinel correlates the detection, the euid=0 records and the new root account into one incident (T1068)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "lpe_q1",
      xp: 50,
      kind: "single",
      prompt:
        "Event lpe_03 is an auditd USER_CMD record for `sudo -l` run by www-data, with res=failed. Before you know how the attacker reached root, what does this single record already tell you?",
      hint: "Read the res field together with the sudo message, and remember what sudo would have logged if the password were merely wrong.",
      options: [
        { value: "no_sudo_path", label: "www-data has no sudo entitlement at all, so the escalation that follows must use some mechanism other than sudo" },
        { value: "wrong_pw", label: "www-data mistyped the sudo password, so the same sudo rule is probably still usable once the right password is supplied" },
        { value: "will_escalate", label: "A failed sudo -l is the usual reconnaissance step before a sudo exploit, so root was most likely reached through sudo next" },
        { value: "no_tty", label: "The terminal is (none), so auditd could not have captured a real command and this record is a spurious artefact" },
      ],
      answer: "no_sudo_path",
      explanation:
        "res=failed alongside the sudo message 'user NOT in sudoers' means no sudo rule exists for www-data — the account cannot escalate through sudo at all. That closes off the sanctioned, logged road to root and tells you in advance that the escalation you are about to find took some OTHER path (here, a SUID binary). A wrong password produces a different sudo message ('incorrect password attempts'), not 'NOT in sudoers', so the second option misreads the record. The third assumes an outcome the evidence denies. And terminal=(none) is normal for a command run from a non-login service shell — auditd records it fine; the (none) tty is actually corroborating evidence that this is www-data with no interactive session, not a spurious record.",
    },
    {
      id: "lpe_q2",
      xp: 75,
      kind: "single",
      prompt:
        "In lpe_05 the SYSCALL for the find execve shows uid=33 but euid=0, and the PATH details give /usr/bin/find as mode 0104755. Which mechanism does this combination describe?",
      hint: "Compare the real uid with the effective uid, and read the leading digits of the file mode.",
      options: [
        { value: "suid_bit", label: "/usr/bin/find carries the setuid bit (mode 04755), so executing it sets euid to the file owner, root, whoever runs it" },
        { value: "sudo_rule", label: "A narrow NOPASSWD sudoers rule lets www-data run find as root, which is why the execve shows euid 0 with uid 33" },
        { value: "kernel_exploit", label: "A kernel privilege-escalation exploit overwrote the process's cred structure in memory, forcing its euid to 0" },
        { value: "world_writable", label: "/usr/bin/find is world-writable, so www-data swapped in its own copy that runs as root when it is executed" },
      ],
      answer: "suid_bit",
      explanation:
        "The leading 04 in 0104755 is the setuid bit (the 010 prefix is the regular-file type; 4755 = setuid + rwxr-xr-x). When a setuid binary owned by root is executed, the kernel sets the new process's euid to the file owner's uid — 0 — while the real uid stays that of the caller, 33. That is exactly the uid=33 euid=0 the SYSCALL shows, and it is the entire escalation. A sudoers rule is refuted by lpe_03 (www-data is not in sudoers) and would have produced a sudo/USER_CMD record, not a find execve. There is no kernel-exploit evidence anywhere in the timeline. And mode 4755 is not world-writable (the last three bits are r-x, not rwx); had the binary been writable the story would be tampering, not SUID abuse.",
    },
    {
      id: "lpe_q3",
      xp: 75,
      kind: "single",
      prompt:
        "You need to prove the escalation actually succeeded — that commands are now running with root privilege, not merely that an exploit was attempted. Which event demonstrates it most directly?",
      hint: "Look for an action that is impossible for uid 33 but succeeds, and check the euid on that same record.",
      options: [
        { value: "shadow_read", label: "The /etc/shadow read — it succeeds (exit=3, a valid fd) with euid=0 on a 0640 root:shadow file www-data cannot open" },
        { value: "suid_enum", label: "The find / -perm -4000 enumeration — it located the setuid binary and listed root-owned files across the filesystem" },
        { value: "id_disc", label: "The id command at the start of the session — it reports the account's identity, including any effective root uid" },
        { value: "siem_alert", label: "The Sentinel correlation alert — it confirms the escalation technique and the root shell from Falcon's own detection" },
      ],
      answer: "shadow_read",
      explanation:
        "/etc/shadow is mode 0640 owned by root:shadow, so a process with real and effective uid 33 cannot open it — the openat would fail with EACCES. In lpe_07 it succeeds (exit=3 is a live file descriptor) and the same record carries euid=0: root access is not just claimed, it is exercised on a file only root can read. That is the strongest possible proof the shell truly holds root. The SUID enumeration only located the weakness; it ran as euid 33 and reads nothing privileged. The id command described the account before any escalation (euid 33). The Sentinel alert asserts the conclusion but is a downstream correlation, not the primitive evidence — you prove root from the shadow read, and the alert is what it fired on.",
    },
    {
      id: "lpe_q4",
      xp: 100,
      kind: "multi",
      prompt:
        "Both lpe_01 (the admin's sudo) and the intrusion chain end with a process running as root. Select the TWO observations that identify the intrusion's escalation as malicious while clearing the administrator's.",
      hint: "Compare the auid on each root action, and compare whether an authorization record exists for each.",
      options: [
        { value: "auid", label: "The admin's root action carries auid=1001 (a human loginuid); the intrusion's root actions carry auid=4294967295 — no login session behind them" },
        { value: "authz", label: "The admin's escalation has an authorization record (sudo USER_CMD, res=success); the intrusion's euid=0 appears with no sudo and no authorization record at all" },
        { value: "asroot", label: "Only the intrusion's processes run as root — the administrator's sudo command stayed at the admin's own uid 1001 throughout the session" },
        { value: "hostname", label: "The two occur on different hosts, so the admin's sudo session is irrelevant to the web-app-07 incident and can be set aside entirely" },
      ],
      answer: ["auid", "authz"],
      explanation:
        "The discriminators are provenance and authorization, not the fact of being root. auid (loginuid) is immutable once set and follows every child process: the admin's escalation carries auid=1001, tied to a named human who authenticated, while every escalated event in the intrusion carries auid=4294967295 — root privilege with no login session behind it, which for an interactive-looking action is deeply abnormal. And the admin's escalation went through sudo, which made and logged an authorization decision (res=success); the intrusion's euid=0 appears through a SUID execve with no sudo and no authorization record anywhere. The third option is false — the admin's sudo did run systemctl as root (that is what sudo does); 'ran as root' is exactly what does NOT separate them. The fourth is factually wrong: both occur on web-app-07, and the admin session is the control case precisely because it is on the same host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Opportunistic intruder operating a www-data web-shell foothold",
    attack_kind: "linux_privilege_escalation",
    briefing:
      "CrowdStrike Falcon raised a Critical privilege-escalation detection on web-app-07, an internet-facing Ubuntu application server: a shell running with an effective UID of root but a real UID of the www-data service account. Establish how root was reached, prove whether it succeeded, and find what the intruder did with it.",
    narrative:
      "web-app-07 is an internet-facing Ubuntu application server at Northwind Logistics. How the attacker first got the ability to run commands as www-data is out of scope for this ticket — assume a web shell on the application it hosts; what matters here is what they did once they had it. A foothold as www-data (uid 33) is nearly worthless on its own: the account owns the web root and little else. So the intruder did what real operators do — they looked for a way up. They ran id to confirm who they were, then sudo -l, which came back 'user NOT in sudoers': no sanctioned road to root. Undeterred, they enumerated setuid binaries with find / -perm -4000, and one result stood out — /usr/bin/find itself was setuid root, an accident of some past deployment script that had run chmod u+s and never undone it. That single misconfiguration was the whole game. Using the well-known GTFOBins technique, they ran `find . -exec /bin/sh -p \\; -quit`; because find executes as root, the shell it spawned held euid 0, and the -p flag stopped that privilege from being dropped. From that root shell they read /etc/shadow — a file www-data can never open — and created sysupdate, a second account with uid 0, giving themselves a durable root-equivalent identity. Minutes later that account logged in over SSH from 193.32.162.140 with an attacker-controlled key. Falcon caught the escalation at the instant the root shell appeared; auditd recorded every step in the language of Linux privilege — uid, euid and auid — and the difference between this and the administrator's legitimate sudo session earlier in the day is written in exactly those three numbers.",
    learning_objectives: [
      "Read auditd uid / euid / suid / auid fields to establish the exact privilege an actor holds on a Linux host, and recognise that a real uid can stay unprivileged while the effective uid becomes root",
      "Recognise the SUID-abuse escalation primitive from a file mode of 04755 and a uid≠euid SYSCALL record, and connect it to the GTFOBins technique that exploits it",
      "Use `sudo -l` returning 'NOT in sudoers' to rule the sudo path out and infer that escalation took another mechanism",
      "Prove an escalation actually succeeded — not merely that it was attempted — by finding a root-only action (reading /etc/shadow) that completes under a non-root real uid",
      "Separate a malicious escalation from a legitimate administrator reaching root, using loginuid (auid) provenance and the presence or absence of an authorization record rather than the fact of running as root",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
