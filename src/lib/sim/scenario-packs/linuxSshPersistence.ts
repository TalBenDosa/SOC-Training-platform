import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { linuxSshPersistenceScenarioEvents } from "./linuxSshPersistence.events";

/**
 * Exposed SSH → Cron-Persisted Backdoor (INTERMEDIATE)
 *
 * A pure-Linux intrusion read from the defender's seat: sshd and auditd on the
 * server, Falcon on the endpoint, the perimeter firewall. Deliberately contains NO
 * Windows concepts: no integrity levels, no DLLs, no Authenticode. Privilege is
 * expressed the way Linux expresses it — uid / gid / auid / ses — and the
 * persistence the intruder installs is bounded by exactly those numbers.
 *
 * PRIVILEGE CHAIN (SPEC rule 1):
 *   The intruder lands as svc-backup (uid 1004, gid 1004), session 41. Event lsp_07
 *   is an auditd USER_CMD record showing `sudo -l` returning res=failed, and nothing
 *   later in the timeline runs as anyone but uid 1004. Every action stays inside what
 *   that account already owns:
 *     - writes under /home/svc-backup/ (owned by uid 1004)
 *     - installs a USER crontab via /usr/bin/crontab, which is setgid crontab(102):
 *       the file it creates is /var/spool/cron/crontabs/svc-backup with ouid=1004
 *       ogid=102 mode=0600 — no root needed.
 *     - the binary runs as svc-backup, and cron relaunches it as svc-backup.
 *   Nothing is written to /etc/cron.d, /etc/systemd/system, or any root-owned path.
 *
 * DETECTION: the shift is paged by the Falcon detection on the masqueraded process
 * (lsp_11, T1036.004). Everything before it is reconstructed backwards from there;
 * the periodic outbound TLS (lsp_12–lsp_14, T1071.001) and the cron relaunch (lsp_15)
 * are what make it an active, persistent foothold rather than a one-off.
 */
export function buildLinuxSshPersistenceScenario(
  scenarioId = "linux-ssh-persistence-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, attacker, implantHash, payloadUrl } = linuxSshPersistenceScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip", value: attacker.guessA, first_seen: T(31 * MIN), reputation: "malicious", tags: ["ssh-auth-failure", "external", "hosting-provider", "unknown-account"] },
    { type: "ip", value: attacker.guessB, first_seen: T(52 * MIN), reputation: "malicious", tags: ["ssh-auth-failure", "external", "hosting-provider"] },
    { type: "ip", value: attacker.success, first_seen: T(58 * MIN), reputation: "malicious", tags: ["ssh-auth-success", "external", "interactive-session"] },
    { type: "ip", value: attacker.payloadHost, first_seen: T(64 * MIN), reputation: "malicious", tags: ["payload-host", "http", "external"] },
    { type: "ip", value: attacker.checkin, first_seen: T(70 * MIN), reputation: "malicious", tags: ["outbound-443", "periodic-session", "hosting-provider"] },
    { type: "url", value: payloadUrl, first_seen: T(64 * MIN), reputation: "malicious", tags: ["payload-url", "cleartext-http"] },
    { type: "sha256", value: implantHash, first_seen: T(64 * MIN), reputation: "malicious", tags: ["elf", "dropped-file", "masqueraded-name", "hidden-directory"] },
    { type: "user", value: "svc-backup", first_seen: T(58 * MIN), reputation: "suspicious", tags: ["compromised-account", "uid-1004", "password-auth"] },
    { type: "host", value: host.fqdn, first_seen: T(31 * MIN), reputation: "suspicious", tags: ["internet-exposed-ssh", "tcp-2202"] },
  ];

  const killchain = [
    { ts: T(0), phase: "Baseline", action: "Legitimate admin publickey session from the corporate VPN egress — the control case for the auth log" },
    { ts: T(31 * MIN), phase: "Credential Access", action: "Password guessing against sshd from 176.111.174.26 — acct=\"?\", a username that does not exist on the host (T1110.001)" },
    { ts: T(52 * MIN), phase: "Credential Access", action: "Guessing moves to the real account svc-backup from a second node, 92.118.39.73 (T1110.001)" },
    { ts: T(58 * MIN), phase: "Initial Access", action: "Accepted password for svc-backup from 46.161.27.119 — an address with no prior failures; auditd opens session 41, auid 1004 (T1078)" },
    { ts: T(60 * MIN), phase: "Discovery", action: "/usr/bin/id run in session 41 as uid 1004 (T1033)" },
    { ts: T(61 * MIN), phase: "Discovery", action: "sudo -l returns res=failed — no root path for svc-backup (T1033)" },
    { ts: T(64 * MIN), phase: "Command and Control", action: "curl pulls an ELF over plain HTTP from 147.45.112.38 into a hidden directory in the account's own home (T1105)" },
    { ts: T(66 * MIN), phase: "Defense Evasion", action: "chmod 755 on ~/.cache/.fontconfig/kworker, a file owned by uid 1004 in a dot-directory (T1564.001)" },
    { ts: T(68 * MIN), phase: "Persistence", action: "User crontab created via the setgid crontab binary — /var/spool/cron/crontabs/svc-backup, ouid 1004 ogid 102 (T1053.003)" },
    { ts: T(70 * MIN), phase: "Detection", action: "Falcon detection: 'kworker' — a kernel-thread name — running from the hidden directory as svc-backup, parent bash (T1036.004)" },
    { ts: T(70 * MIN), phase: "Command and Control", action: "kworker connects to 38.180.62.144:443; the firewall shows the same 3-second, ~1.9 KB session again five minutes later (T1071.001)" },
    { ts: T(80 * MIN), phase: "Persistence", action: "cron runs /bin/sh -c '~/.cache/.fontconfig/kworker >/dev/null 2>&1' as svc-backup — the crontab entry firing (T1053.003)" },
    { ts: T(95 * MIN), phase: "Baseline", action: "Nightly restic backup starts from root-owned /etc/cron.d as user backup and uploads to its Backblaze B2 repository — the benign outbound session" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "lsp_q1",
      xp: 50,
      kind: "single",
      prompt:
        "auth.log for 14 April contains two Accepted lines — d.okonkwo at 21:40 and svc-backup at 22:38. Which single field in these lines separates the intrusion from the legitimate session?",
      hint: "Read the word right after 'Accepted' on each line, not the timestamps.",
      options: [
        { value: "method", label: "The authentication method — publickey for d.okonkwo, password for svc-backup, and only a password can be guessed" },
        { value: "hour", label: "The hour of the session — 22:38 falls outside business hours while 21:40 is still inside the change window" },
        { value: "port", label: "The source port — 41772 is in the ephemeral range while the admin's 58114 is a fixed client port" },
        { value: "proto", label: "The protocol token — the intrusion negotiated ssh1 while the admin session negotiated ssh2" },
      ],
      answer: "method",
      explanation:
        "d.okonkwo's line says 'Accepted publickey' and svc-backup's says 'Accepted password'. A key cannot be brute-forced, which is why no failure from 82.166.44.9 precedes the admin session while failed PAM authentications precede the other. Note also what the Accepted line does NOT match: 46.161.27.119 appears in no failure record at all — in a distributed campaign the guessing nodes and the node that logs in are different machines, so do not expect the winning address to be the one you counted failures from. Hour separates nothing (21:40 is also after hours). Both source ports are ordinary ephemeral client ports, and both lines end in ssh2.",
    },
    {
      id: "lsp_q2",
      xp: 75,
      kind: "single",
      prompt:
        "lsp_07 is an auditd USER_CMD record for `sudo -l` with res=failed in session 41. Read together with the records after it, what does it establish about the rest of the incident?",
      hint: "auditd records identity as numbers. Follow uid / auid / ouid across every later record.",
      options: [
        { value: "no_root", label: "The intruder never obtained root, so the blast radius is bounded to files and jobs owned by svc-backup (uid 1004)" },
        { value: "escalated", label: "The intruder escalated moments later, because a failed sudo attempt normally precedes a working kernel exploit" },
        { value: "wrong_pw", label: "The intruder does not actually know svc-backup's password, so the account itself does not need a reset" },
        { value: "no_shell", label: "The intruder had no interactive terminal, because auditd cannot record USER_CMD without a controlling tty" },
      ],
      answer: "no_root",
      explanation:
        "res=failed means sudo granted nothing, and every later record agrees: the SYSCALL and PATH records stay at uid / auid / ouid 1004, the crontab lands in the per-user spool, and Falcon shows kworker and the cron relaunch running as svc-backup. Nothing in the timeline shows uid 0, so assuming an escalation contradicts the evidence. 'Does not know the password' is refuted by lsp_04 — the session itself began with 'Accepted password for svc-backup', so the password must be reset. And USER_CMD carries terminal=pts/0, which is itself proof of an interactive tty.",
    },
    {
      id: "lsp_q3",
      xp: 75,
      kind: "single",
      prompt:
        "In lsp_10 an unprivileged account creates /var/spool/cron/crontabs/svc-backup, in a directory it does not own. Which detail in the PATH record explains how that was permitted?",
      hint: "Compare the owner and group of the new file with the account's own uid and gid (1004 / 1004).",
      options: [
        { value: "setgid", label: "ouid is 1004 but ogid is 102 (crontab) — /usr/bin/crontab is setgid crontab and writes the spool file on the user's behalf" },
        { value: "world", label: "The spool directory is world-writable at mode 0777, so any local account can create files inside it directly" },
        { value: "root_cron", label: "The cron daemon runs as root and creates the file itself after the user submits the job over a local socket" },
        { value: "sudo_rule", label: "A narrow sudoers entry permits svc-backup to run /usr/bin/crontab as root without supplying a password" },
      ],
      answer: "setgid",
      explanation:
        "The new file is ouid=1004 ogid=102 mode=0100600. The account's own group is 1004, so group 102 can only come from the program that wrote it: /usr/bin/crontab is setgid crontab, which is exactly how a user crontab is installed without root. The spool directory is mode 1730 root:crontab, never world-writable. cron reads the spool but does not create entries on request. A sudoers entry is refuted by lsp_07. This is also why the persistence had to be a user crontab: /etc/cron.d or a systemd unit would have required root, which the timeline never grants.",
    },
    {
      id: "lsp_q4",
      xp: 100,
      kind: "single",
      prompt:
        "For the incident report you must attribute the process Falcon flagged in lsp_11 to an account and an external source. Which pair of events, read together, does that?",
      hint: "One event names the identity and where it came from; another names the process running under it. Neither is enough alone.",
      options: [
        { value: "auth_proc", label: "lsp_04 and lsp_11 — 'Accepted password for svc-backup from 46.161.27.119', and the detection on kworker running as svc-backup under an interactive bash" },
        { value: "fw_pair", label: "lsp_13 and lsp_14 — the two firewall sessions from the server to 38.180.62.144:443 five minutes apart" },
        { value: "dl_chmod", label: "lsp_08 and lsp_09 — the curl download of the ELF, and the chmod that made that same file executable" },
        { value: "cron_bkp", label: "lsp_15 and lsp_16 — cron relaunching the binary, and cron starting the nightly restic job on the same host" },
      ],
      answer: "auth_proc",
      explanation:
        "Attribution needs an identity plus an action under it. lsp_04 supplies the identity and its origin: svc-backup authenticated by password from 46.161.27.119 (lsp_05 adds the auditd session id, 41, and login id 1004 for the same login). lsp_11 supplies the action: kworker running as svc-backup with bash — the interactive shell of that session — as its parent. The firewall pair proves the outbound behaviour but names no user and no inbound source. The download-and-chmod pair proves staging but not who logged in from where. The cron pair mixes the persistence with an unrelated legitimate job.",
    },
    {
      id: "lsp_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "Both kworker and the nightly restic job open outbound TLS from nix-bkp-01 on tcp/443 through the same Allow-Outbound-Internet firewall rule. Select the TWO observations that separate kworker's traffic from the legitimate backup.",
      hint: "Compare what each process is and where it lives, then the shape of its sessions.",
      options: [
        { value: "process", label: "kworker runs from a hidden directory under a user home as svc-backup; restic runs from /usr/bin as user backup and names its storage endpoint on its own command line" },
        { value: "shape", label: "kworker's sessions are ~1.9 KB, three seconds long and repeat every five minutes to a bare hosting-provider IP; restic's is one long bulk upload to its repository" },
        { value: "volume", label: "restic sent 1.8 GB out of the network, and a large outbound transfer is the stronger indicator of a malicious channel" },
        { value: "port", label: "kworker uses a non-standard destination port that the firewall had to fall back to a catch-all rule for" },
      ],
      answer: ["process", "shape"],
      explanation:
        "Process identity and session shape are the discriminators. restic is a system binary, started by a root-owned /etc/cron.d entry as the dedicated backup account, and its command line declares the Backblaze B2 repository it then uploads to in one long session. kworker sits in ~/.cache/.fontconfig, runs as the account taken over by password, has no configured destination, and checks in with small, near-identical sessions on a fixed interval — the beacon shape. Volume alone is a trap: a backup server is supposed to move gigabytes off-site. And both use tcp/443 through the same Allow-Outbound-Internet rule, so port and rule separate nothing.",
    },
    {
      id: "lsp_q6",
      xp: 75,
      kind: "single",
      prompt:
        "lsp_15 shows cron running /bin/sh -c '/home/svc-backup/.cache/.fontconfig/kworker >/dev/null 2>&1' as svc-backup after the binary was already running. Which containment and eradication plan matches the evidence?",
      hint: "Kill only the process and ask what lsp_15 will do 30 minutes later.",
      options: [
        { value: "full", label: "Contain the host, kill kworker, remove the svc-backup crontab and ~/.cache/.fontconfig, reset svc-backup and disable password SSH, block 38.180.62.144 and 147.45.112.38" },
        { value: "kill_only", label: "Kill pid 1974 and delete the binary — the crontab line only fires at boot, so it is inert until the next reboot" },
        { value: "root_rebuild", label: "Rebuild the server immediately, because a failed sudo shows the intruder reached root and may have a rootkit" },
        { value: "block_only", label: "Block 38.180.62.144 at the firewall and keep monitoring — without its server the binary can do nothing" },
      ],
      answer: "full",
      explanation:
        "The cron relaunch proves the per-user crontab is live and fires on a schedule, not only at boot, so killing the process alone lets cron start it again; the crontab, the hidden directory and the binary must all go. The way in was a guessed password on an internet-exposed sshd, so svc-backup's password must be reset and password authentication turned off, or the next guessing run walks back in. Blocking only the check-in address leaves the account, the binary and the crontab in place, and the payload host was a second piece of infrastructure. A rebuild for root compromise is not supported: lsp_07 shows sudo was refused and nothing ever ran as uid 0.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Opportunistic SSH-scanning intrusion set",
    attack_kind: "linux_ssh_intrusion",
    briefing: "Falcon raised a High detection on nix-bkp-01, a Linux backup server: a process named kworker is running from a hidden directory under /home/svc-backup. Work out how it got there, under which identity, what it talks to, and whether it will come back.",
    narrative:
      "nix-bkp-01 is a Linux backup server at Northwind Logistics. Two years ago someone moved its SSH daemon from port 22 to port 2202 and recorded it as a security improvement. It was not — the host still answers the whole internet, and automated scanners find non-standard SSH ports in minutes. On the evening of Tuesday 14 April 2026 an opportunistic crew began guessing passwords against it from hosting-provider addresses: first names that do not exist on the box, then svc-backup, a service account created for a since-retired rsync job and left with a password that had never been rotated. At 22:38 a third address logged in — one that had never sent a single failed attempt, because the guessing infrastructure and the hands-on-keyboard infrastructure are deliberately different machines. What followed is unglamorous and extremely common: the intruder checked who they were, found they could not become root, and settled for what an ordinary account can still do. They pulled an ELF binary over plain HTTP into a hidden folder in the account's own home, named it after a kernel thread, installed a per-user crontab to keep it alive, and started it. It began opening short TLS sessions to one hosting-provider address every five minutes. Falcon flagged the kernel-thread name running from a home directory — the first thing anyone was paged on. Your task: prove from auth.log and auditd exactly when and how the account was taken, establish what privileges the intruder actually held, explain how persistence was possible without root, show what the binary talks to, and separate its traffic from the legitimate backup job that leaves the same server through the same firewall rule.",
    learning_objectives: [
      "Read sshd/auth.log and auditd to distinguish password from publickey authentication, recognise acct=\"?\" as an unknown-user failure, and locate the moment a guessing campaign converts into a login — from an address that may appear in none of the failure records",
      "Use auditd uid / gid / auid / ses / ouid / ogid fields — not Windows-style privilege concepts — to establish the exact privilege level an intruder holds on a Linux host",
      "Explain how an unprivileged account installs cron persistence through the setgid crontab binary, and confirm the persisted command from cron's own process launch",
      "Pivot from an EDR detection to its network connection and the matching firewall sessions (local port, destination, interval, size) to recognise periodic check-in traffic",
      "Discriminate a check-in channel from a legitimate backup upload using process path, account, declared destination and session shape rather than port, rule or volume",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
