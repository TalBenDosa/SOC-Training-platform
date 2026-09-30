import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { linuxSshCryptominerScenarioEvents } from "./linuxSshCryptominer.events";

/**
 * Exposed SSH → Cron Persistence → Cryptominer (INTERMEDIATE)
 *
 * A pure-Linux intrusion. Deliberately contains NO Windows concepts:
 * no integrity levels, no DLLs, no Authenticode. Privilege is expressed the way
 * Linux expresses it — uid / gid / euid / egid / auid — and the persistence the
 * attacker installs is bounded by exactly those numbers.
 *
 * PRIVILEGE CHAIN (SPEC rule 1):
 *   The attacker lands as svc-backup (uid 1004, gid 1004). Event lsc_06 is an
 *   auditd USER_CMD record showing `sudo -l` returning res=failed — svc-backup is
 *   NOT in sudoers. The attacker therefore never has root, and every later action
 *   stays inside what uid 1004 already owns:
 *     - writes under /home/svc-backup/ (owned by uid 1004)
 *     - installs a USER crontab via /usr/bin/crontab, which is setgid crontab(102);
 *       the auditd SYSCALL shows egid=102 while uid/euid stay 1004, which is the
 *       exact mechanism that lets an unprivileged user create
 *       /var/spool/cron/crontabs/svc-backup (ouid=1004 ogid=102 mode=0600).
 *     - the miner runs as uid 1004, capped by that account's limits.
 *   Nothing is written to /etc/cron.d, /etc/systemd/system, or any root-owned path.
 */
export function buildLinuxSshCryptominerScenario(
  scenarioId = "linux-ssh-cryptominer-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, attacker, pool, minerHash } = linuxSshCryptominerScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip", value: attacker.spray1, first_seen: T(52 * MIN), reputation: "malicious", tags: ["ssh-auth-failure", "external", "hosting-provider"] },
    { type: "ip", value: attacker.spray2, first_seen: T(31 * MIN), reputation: "malicious", tags: ["ssh-auth-failure", "external", "hosting-provider"] },
    { type: "ip", value: attacker.spray3, first_seen: T(31 * MIN), reputation: "malicious", tags: ["ssh-auth-failure", "external"] },
    { type: "ip", value: attacker.success, first_seen: T(58 * MIN), reputation: "malicious", tags: ["ssh-auth-success", "external", "interactive-session"] },
    { type: "ip", value: attacker.payloadHost, first_seen: T(64 * MIN), reputation: "malicious", tags: ["payload-host", "http", "external"] },
    { type: "ip", value: pool.ip, first_seen: T(72 * MIN), reputation: "malicious", tags: ["outbound", "long-lived-session", "tcp-3333"] },
    { type: "domain", value: pool.domain, first_seen: T(72 * MIN), reputation: "malicious", tags: ["mining-pool", "external"] },
    { type: "url", value: "http://45.61.136.14/updates/kworker", first_seen: T(64 * MIN), reputation: "malicious", tags: ["payload-url", "cleartext-http"] },
    { type: "sha256", value: minerHash, first_seen: T(64 * MIN), reputation: "malicious", tags: ["elf", "dropped-file", "masqueraded-name"] },
    { type: "user", value: "svc-backup", first_seen: T(58 * MIN), reputation: "suspicious", tags: ["compromised-account", "uid-1004", "password-auth"] },
    { type: "host", value: host.fqdn, first_seen: T(31 * MIN), reputation: "suspicious", tags: ["internet-exposed-ssh", "tcp-2202"] },
  ];

  const killchain = [
    { ts: T(0), phase: "Baseline", action: "Legitimate admin publickey session from the corporate VPN egress — the control case for the auth log" },
    { ts: T(31 * MIN), phase: "Credential Access", action: "Distributed password guessing on tcp/2202 from three hosting-provider IPs, generic usernames (T1110.001)" },
    { ts: T(52 * MIN), phase: "Credential Access", action: "Guessing narrows to svc-backup — 'Invalid user' becomes 'Failed password for svc-backup' (T1110.001)" },
    { ts: T(58 * MIN), phase: "Initial Access", action: "Accepted password for svc-backup from 193.32.162.140 — an IP with no prior failures (T1078)" },
    { ts: T(60 * MIN), phase: "Discovery", action: "id, uname -a, /etc/os-release, crontab -l run in session 41 as uid 1004 (T1033)" },
    { ts: T(61 * MIN), phase: "Discovery", action: "sudo -l returns res=failed — svc-backup is not in sudoers, no root path available (T1033)" },
    { ts: T(64 * MIN), phase: "Command and Control", action: "curl pulls a 6.4 MB ELF over HTTP into a hidden dir inside the account's own home (T1105)" },
    { ts: T(66 * MIN), phase: "Defense Evasion", action: "chmod 755 on a file owned by uid 1004; named 'kworker' to imitate a kernel thread (T1036.005)" },
    { ts: T(68 * MIN), phase: "Persistence", action: "User crontab installed via setgid-crontab binary — /var/spool/cron/crontabs/svc-backup, mode 0600 (T1053.003)" },
    { ts: T(70 * MIN), phase: "Impact", action: "Miner launched as uid 1004 with Monero wallet and pool on the command line (T1496)" },
    { ts: T(72 * MIN), phase: "Impact", action: "Long-lived outbound session to pool.supportxmr.com:3333 permitted by catch-all egress policy 42 (T1496)" },
    { ts: T(85 * MIN), phase: "Baseline", action: "Nightly restic job starts from a root-owned /etc/cron.d entry as uid 34 — the benign CPU consumer" },
    { ts: T(95 * MIN), phase: "Detection", action: "Sustained load average alert on the 8-vCPU host; top shows kworker 690% alongside restic 96%" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "lsc_q1",
      xp: 50,
      kind: "single",
      prompt:
        "auth.log for 14 April contains two successful SSH sessions — d.okonkwo at 21:40 and svc-backup at 22:38. Which single field in these records separates the intrusion from the legitimate session?",
      hint: "Compare the authentication method recorded on each Accepted line, not the timestamps.",
      options: [
        { value: "method", label: "The authentication method — publickey for d.okonkwo, password for svc-backup, and only passwords can be guessed" },
        { value: "hour", label: "The hour of the session — 22:38 falls outside business hours while 21:40 is still inside the change window" },
        { value: "port", label: "The destination port — the admin reached tcp/22 while the attacker reached the exposed tcp/2202 listener" },
        { value: "shell", label: "The login shell recorded by PAM — the attacker was given /bin/bash while the admin received /bin/sh" },
      ],
      answer: "method",
      explanation:
        "Both Accepted lines look identical at a glance, but d.okonkwo's says 'Accepted publickey' and svc-backup's says 'Accepted password'. A public key cannot be brute-forced, which is why no Failed password lines precede the admin session while 21 minutes of them precede the other. Note also what the Accepted line does NOT match: 193.32.162.140 appears in no failure record at all, so do not expect the winning address to be the one you were counting failures from — in a distributed campaign the guessing nodes and the hands-on node are different machines. Hour is not evidence — 21:40 is also outside business hours, so it separates nothing. Port is wrong: both sessions arrive on tcp/2202, the host's only listener. The shell is identical for both and is not recorded on the Accepted line at all.",
    },
    {
      id: "lsc_q2",
      xp: 75,
      kind: "single",
      prompt:
        "Event lsc_06 is an auditd USER_CMD record for `sudo -l` with res=failed. What does this record let you conclude about the rest of the incident?",
      hint: "auditd records identity as numbers. Read uid, euid and auid across every later event.",
      options: [
        { value: "no_root", label: "The attacker never obtained root, so the blast radius is bounded to files and jobs owned by uid 1004" },
        { value: "escalated", label: "The attacker escalated moments later, because a failed sudo attempt normally precedes a working kernel exploit" },
        { value: "wrong_pw", label: "The attacker mistyped the password for svc-backup, so the sudo rule itself may still be usable later" },
        { value: "no_shell", label: "The attacker had no interactive terminal, because auditd cannot record USER_CMD without a controlling tty" },
      ],
      answer: "no_root",
      explanation:
        "res=failed together with the sudo line 'user NOT in sudoers' means no sudo rule exists for this account, and every later auditd SYSCALL confirms it — uid, euid and auid stay 1004 to the end. Nothing in the timeline shows an escalation, so assuming one contradicts the evidence. A mistyped password produces a different sudo message ('3 incorrect password attempts'), not 'NOT in sudoers'. And USER_CMD carries terminal=pts/0, which is itself proof of an interactive tty, so the last option is contradicted by the record it claims to interpret.",
    },
    {
      id: "lsc_q3",
      xp: 75,
      kind: "single",
      prompt:
        "In lsc_09 an unprivileged account creates a file under /var/spool/cron/crontabs, a directory it does not own. Which detail in the SYSCALL record explains how that was permitted?",
      hint: "Compare the uid fields with the gid fields on that one record.",
      options: [
        { value: "setgid", label: "egid becomes 102 while uid and euid stay 1004 — /usr/bin/crontab is setgid crontab and writes on the user's behalf" },
        { value: "world", label: "The spool directory is world-writable at mode 0777, so any local account can create files inside it directly" },
        { value: "root_cron", label: "The cron daemon runs as root and creates the file itself after the user submits the job over a local socket" },
        { value: "sudo_rule", label: "A narrow sudoers entry permits svc-backup to run /usr/bin/crontab as root without supplying a password" },
      ],
      answer: "setgid",
      explanation:
        "The record shows uid=1004 euid=1004 but egid=102 sgid=102 fsgid=102, and the resulting file is ouid=1004 ogid=102 mode=0600. That gid shift is the setgid bit on /usr/bin/crontab doing exactly its job, which is why a user crontab needs no root at all. The spool directory is mode 1730 root:crontab, never world-writable. Cron reads the spool but does not create entries on request. And a sudoers entry is directly refuted by lsc_06. This is also why the persistence had to be a user crontab: writing to /etc/cron.d or a systemd unit would have required root, which the timeline never grants.",
    },
    {
      id: "lsc_q4",
      xp: 100,
      kind: "single",
      prompt:
        "You must attribute the mining process in lsc_10 to a specific identity for the incident report. Which pair of events, read together, ties the miner to a named account and a named external actor?",
      hint: "One event names the identity, another names the process running under it. Neither is enough alone.",
      options: [
        { value: "auth_proc", label: "lsc_04 and lsc_10 — the Accepted password for svc-backup from 193.32.162.140, and the miner running as that same uid 1004" },
        { value: "fw_pool", label: "lsc_11 and lsc_13 — the outbound session to the pool, and the load alert showing the process burning 690% CPU" },
        { value: "dl_chmod", label: "lsc_07 and lsc_08 — the curl download of the ELF payload, and the chmod that made that same file executable" },
        { value: "cron_bkp", label: "lsc_09 and lsc_12 — the crontab written for svc-backup, and the nightly restic job started from cron on the host" },
      ],
      answer: "auth_proc",
      explanation:
        "Attribution needs an identity plus an action under it. lsc_04 supplies the identity and its origin: svc-backup authenticated by password from 193.32.162.140, auid=1004, session 41. lsc_10 supplies the action: the miner running as UID 1004 with bash as its parent, in that same session lineage. Together they name both the account and the external address. The firewall-and-alert pair proves impact but names no user. The download-and-chmod pair proves file staging but names no external session. The crontab-and-restic pair mixes the malicious job with an unrelated legitimate one and proves nothing about who logged in.",
    },
    {
      id: "lsc_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "The load alert in lsc_13 lists kworker at 690% and restic at 96%. Select the TWO observations that identify kworker as the malicious consumer and clear restic.",
      hint: "Look at where each binary lives and what launched it.",
      options: [
        { value: "path", label: "kworker executes from a hidden directory under a user home, while restic executes from the system path /usr/bin" },
        { value: "parent", label: "kworker was launched by an interactive bash in the SSH session, while restic was launched by cron from a root-owned file" },
        { value: "cpu", label: "kworker consumes far more CPU than restic, and mining software always saturates every core it can reach" },
        { value: "name", label: "kworker is not a name used by any Linux distribution, while restic is a widely packaged open-source utility" },
      ],
      answer: ["path", "parent"],
      explanation:
        "Location and lineage are the discriminators. A legitimate service binary lives in the system path and is started by an init or cron chain — restic satisfies both, and its /etc/cron.d entry is root-owned, which means it was provisioned by an administrator. kworker satisfies neither: it sits in ~/.cache/.fontconfig and its parent is the attacker's interactive shell. CPU share is not evidence — the backup job is legitimately CPU-heavy, and this miner was explicitly capped with --max-cpu-usage 90, so 'more CPU means malicious' would misclassify plenty of real workloads. The last option is a factual trap: kworker IS a real kernel thread name, which is precisely why it was chosen for masquerading — but real kworker threads are kernel tasks with no on-disk binary and never appear under /home.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "UNC-COALFIRE (opportunistic, financially motivated)",
    attack_kind: "linux_ssh_cryptomining",
    briefing: "A sustained load-average alert fired on nix-bkp-01, a Linux backup server, at 23:15 — the host has been above threshold for over half an hour. The nightly backup job is also running on it. Confirm what is consuming the CPU.",
    narrative:
      "nix-bkp-01 is a Linux backup server at Northwind Logistics. Two years ago someone moved its SSH daemon from port 22 to port 2202 and recorded it as a security improvement. It was not — the host still answers the whole internet, and automated scanners find non-standard SSH ports in minutes. On the evening of Tuesday 14 April 2026 an opportunistic crew began guessing passwords against it from a small pool of hosting-provider addresses. The guessing started with generic usernames, then narrowed to svc-backup, a service account created for a since-retired rsync job and left with a password that had never been rotated. At 22:38 one node logged in — a node that had never sent a single failed attempt, because in these operations the cracking infrastructure and the hands-on-keyboard infrastructure are deliberately different machines. What followed is unglamorous and extremely common: the intruder checked who they were, discovered they could not become root, and settled for what an ordinary user account can still do. They pulled an ELF binary over plain HTTP into a hidden folder in their own home directory, renamed it after a kernel thread, installed a per-user crontab to keep it alive, and pointed it at a Monero pool. Thirty-seven minutes later the monitoring stack noticed the load average, not the intrusion. Your task: prove from auth.log exactly when and how the account was taken, establish from auditd what privileges the intruder actually held, explain how persistence was possible without root, and separate the miner from the legitimate backup job sharing the same CPU alert.",
    learning_objectives: [
      "Read sshd/auth.log to distinguish password from publickey authentication, locate the moment a brute-force campaign converts into a successful login, and recognise that in a distributed campaign the address that succeeds may appear in none of the failure records",
      "Use auditd uid/gid/euid/egid/auid fields — not Windows-style privilege concepts — to establish the exact privilege level an intruder holds on a Linux host",
      "Explain how an unprivileged account installs cron persistence through the setgid crontab binary, and why /etc/cron.d and systemd units were out of reach",
      "Correlate authentication evidence with process and network evidence to attribute a mining process to a named account and external source address",
      "Discriminate resource hijacking from a legitimate high-CPU batch job using binary location, parent process and job ownership rather than CPU share",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
