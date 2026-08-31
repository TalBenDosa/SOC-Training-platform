import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

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
  const B = new Date("2026-05-19T13:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = {
    name: "web-app-07",
    fqdn: "web-app-07.northwind-logistics.io",
    publicIp: "84.200.17.88",
    privateIp: "10.40.6.21",
    os: "Ubuntu 22.04.4 LTS",
  };

  // The real Linux administrator — reused from the estate's admin identity. His
  // sudo session is the benign control case, NOT part of the intrusion.
  const admin = {
    user: "d.okonkwo",
    email: "d.okonkwo@northwind-logistics.io",
    title: "Linux Systems Administrator",
    auid: "1001",
    vpnEgress: "82.166.44.9",
  };

  // The attacker's external address — appears ONLY on the backdoor SSH login.
  const attackerIp = "193.32.162.140";

  // The uid-0 backdoor account the attacker creates once euid=0 is held.
  const backdoorUser = "sysupdate";

  // The attacker's ed25519 authorized-key fingerprint, in OpenSSH SHA256 form.
  // It is appended to the backdoor account and is what the remote login presents.
  const keyFingerprint = "SHA256:mV3zQ8Xy1kP0rLd7nBqW9sTfUvJhCgEaRbYtZ2oNxK4";

  // The setgid/euid mechanics turn on this one file carrying mode 04755.
  const suidBinary = "/usr/bin/find";

  // One incident. Host-primary Linux privilege escalation → the alert-grade
  // CrowdStrike detection carries edr_scope "edr"; the auditd rows are the
  // mechanism and the pivot evidence.
  const INCIDENT = "inc:lpe:1";

  const events: TelemetryEvent[] = [
    // ── 1. BENIGN DISCRIMINATOR — the sanctioned road to root ────────────────
    {
      id: "lpe_01_admin_sudo",
      ts: T(0),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "sudo_command",
      hostname: host.name,
      user_email: admin.email,
      user_title: admin.title,
      severity: "informational",
      expected_verdict: "fp",
      mitre_technique: "T1548.003",
      mitre_tactic: "Privilege Escalation",
      description:
        "Administrator d.okonkwo ran `sudo systemctl restart nginx` on web-app-07. auditd recorded USER_CMD with res=success from terminal pts/1, auid 1001.",
      process: {
        name: "sudo",
        pid: 2041,
        path: "/usr/bin/sudo",
        parent_name: "bash",
        parent_pid: 2010,
        cmdline: "sudo systemctl restart nginx",
        user: "d.okonkwo",
      },
      fp_explanation:
        "This is the control case for the whole scenario: a legitimate escalation to root, and the thing every later event should be compared against. Three attributes make it sanctioned. It goes through sudo, so an authorization decision was made and logged (res=success, not failed). Its auid is 1001 — a real human loginuid, tied to a named administrator who authenticated an interactive session — and auid is immutable, so it follows the escalation into the root command. And it originates on an admin terminal (pts/1). The intrusion later reaches root too, but does none of these things: no sudo, no authorization record, and an auid that is not a person. Students who alert on 'a process ran as root' alone will flag this and be wrong.",
      raw: {
        "data.audit.type": "USER_CMD",
        "data.audit.pid": "2041",
        "data.audit.uid": "1001",
        "data.audit.auid": "1001",
        "data.audit.ses": "22",
        "data.audit.cwd": "/home/d.okonkwo",
        "data.audit.cmd": "2F7573722F62696E2F73797374656D63746C2072657374617274206E67696E78",
        "data.audit.terminal": "pts/1",
        "data.audit.exe": "/usr/bin/sudo",
        "data.audit.res": "success",
        "sudo.user": admin.user,
        "sudo.runas": "root",
        "sudo.command": "/usr/bin/systemctl restart nginx",
        "sudo.tty": "pts/1",
      },
    },

    // ── 2. Foothold discovery — who am I ─────────────────────────────────────
    {
      id: "lpe_02_id_discovery",
      ts: T(38 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "linux_execve",
      hostname: host.name,
      severity: "medium",
      mitre_technique: "T1033",
      mitre_tactic: "Discovery",
      description:
        "A shell running as www-data on web-app-07 executed `id`. The SYSCALL record shows uid=33 euid=33 and, tellingly, auid=4294967295 — the process belongs to no login session.",
      process: {
        name: "id",
        pid: 40318,
        path: "/usr/bin/id",
        parent_name: "sh",
        parent_pid: 40290,
        cmdline: "id",
        user: "www-data",
      },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "59",
        "data.audit.success": "yes",
        "data.audit.exit": "0",
        "data.audit.ppid": "40290",
        "data.audit.pid": "40318",
        "data.audit.auid": "4294967295",
        "data.audit.uid": "33",
        "data.audit.gid": "33",
        "data.audit.euid": "33",
        "data.audit.egid": "33",
        "data.audit.suid": "33",
        "data.audit.fsuid": "33",
        "data.audit.tty": "(none)",
        "data.audit.ses": "4294967295",
        "data.audit.comm": "id",
        "data.audit.exe": "/usr/bin/id",
        "data.audit.cwd": "/var/www/html",
        "data.audit.key": "exec-tracking",
        "data.audit.execve.a0": "id",
      },
    },

    // ── 3. THE PRIVILEGE BOUNDARY — sudo is not available ────────────────────
    {
      id: "lpe_03_sudo_denied",
      ts: T(39 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "sudo_command",
      hostname: host.name,
      severity: "medium",
      mitre_technique: "T1033",
      mitre_tactic: "Discovery",
      description:
        "The www-data shell ran `sudo -l`. auditd recorded USER_CMD with res=failed, and sudo logged 'www-data : user NOT in sudoers' from terminal (none).",
      process: {
        name: "sudo",
        pid: 40325,
        path: "/usr/bin/sudo",
        parent_name: "sh",
        parent_pid: 40290,
        cmdline: "sudo -l",
        user: "www-data",
      },
      raw: {
        "data.audit.type": "USER_CMD",
        "data.audit.pid": "40325",
        "data.audit.uid": "33",
        "data.audit.auid": "4294967295",
        "data.audit.ses": "4294967295",
        "data.audit.cwd": "/var/www/html",
        "data.audit.cmd": "7375646F202D6C",
        "data.audit.terminal": "(none)",
        "data.audit.exe": "/usr/bin/sudo",
        "data.audit.res": "failed",
        "sudo.user": "www-data",
        "sudo.command": "list",
      },
    },

    // ── 4. SUID enumeration — finding the misconfiguration ───────────────────
    {
      id: "lpe_04_suid_enum",
      ts: T(41 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "linux_execve",
      hostname: host.name,
      severity: "high",
      mitre_technique: "T1083",
      mitre_tactic: "Discovery",
      description:
        "www-data enumerated setuid binaries with `find / -perm -4000 -type f`. The output included /usr/bin/find itself, which is not SUID on a stock Ubuntu install.",
      process: {
        name: "find",
        pid: 40361,
        path: "/usr/bin/find",
        parent_name: "sh",
        parent_pid: 40290,
        cmdline: "find / -perm -4000 -type f 2>/dev/null",
        user: "www-data",
      },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "59",
        "data.audit.success": "yes",
        "data.audit.exit": "0",
        "data.audit.ppid": "40290",
        "data.audit.pid": "40361",
        "data.audit.auid": "4294967295",
        "data.audit.uid": "33",
        "data.audit.gid": "33",
        "data.audit.euid": "33",
        "data.audit.egid": "33",
        "data.audit.tty": "(none)",
        "data.audit.ses": "4294967295",
        "data.audit.comm": "find",
        "data.audit.exe": "/usr/bin/find",
        "data.audit.cwd": "/var/www/html",
        "data.audit.key": "exec-tracking",
        "data.audit.execve.a0": "find",
      },
    },

    // ── 5. THE EXPLOIT — SUID find spawns a root shell ───────────────────────
    {
      id: "lpe_05_suid_exploit",
      ts: T(43 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "linux_priv_change",
      hostname: host.name,
      severity: "critical",
      mitre_technique: "T1548.001",
      mitre_tactic: "Privilege Escalation",
      description:
        "www-data ran `find . -exec /bin/sh -p \\; -quit` from /var/www/html. Because /usr/bin/find carries mode 04755, the execve runs with euid=0 — the SYSCALL shows uid=33 but euid=0, the moment privilege is gained.",
      process: {
        name: "find",
        pid: 40377,
        path: "/usr/bin/find",
        parent_name: "sh",
        parent_pid: 40290,
        cmdline: "find . -exec /bin/sh -p ; -quit",
        user: "www-data",
      },
      file: {
        name: "find",
        path: suidBinary,
      },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "59",
        "data.audit.success": "yes",
        "data.audit.exit": "0",
        "data.audit.ppid": "40290",
        "data.audit.pid": "40377",
        "data.audit.auid": "4294967295",
        "data.audit.uid": "33",
        "data.audit.gid": "33",
        "data.audit.euid": "0",
        "data.audit.egid": "33",
        "data.audit.suid": "0",
        "data.audit.fsuid": "0",
        "data.audit.tty": "(none)",
        "data.audit.ses": "4294967295",
        "data.audit.comm": "find",
        "data.audit.exe": "/usr/bin/find",
        "data.audit.cwd": "/var/www/html",
        "data.audit.key": "privilege-escalation",
        "data.audit.execve.a0": "find",
        "data.audit.file.name": suidBinary,
        "data.audit.file.mode": "0104755",
        "data.audit.file.ouid": "0",
        "data.audit.file.ogid": "0",
        "data.audit.file.nametype": "NORMAL",
      },
    },

    // ── 6. THE EDR DETECTION — Falcon flags the euid transition ──────────────
    {
      id: "lpe_06_edr_detection",
      ts: T(43 * MIN + 6_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      severity: "critical",
      mitre_technique: "T1068",
      mitre_tactic: "Privilege Escalation",
      is_detection: true, // alert-grade: the /bin/sh child of find running with effective UID root is the escalation crux
      edr_scope: "edr",   // host-primary Linux privesc → investigated in the EDR console
      description:
        "The Falcon Linux sensor raised a Privilege Escalation detection: /bin/sh was spawned by find and is running with an effective UID of root while its real UID is www-data (33).",
      process: {
        name: "sh",
        pid: 40378,
        path: "/usr/bin/dash",
        parent_name: "find",
        parent_pid: 40377,
        cmdline: "/bin/sh -p",
        user: "www-data",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.DetectName": "Privilege Escalation via SUID Binary",
        "crowdstrike.Tactic": "Privilege Escalation",
        "crowdstrike.Technique": "Setuid and Setgid",
        "crowdstrike.Objective": "Gain Access",
        "crowdstrike.SeverityName": "Critical",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.FileName": "dash",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.CommandLine": "/bin/sh -p",
        "crowdstrike.ParentProcessName": "find",
        "crowdstrike.ParentProcessId_decimal": "40377",
        "crowdstrike.UserName": "www-data",
        "crowdstrike.UID": "33",
        "crowdstrike.ComputerName": host.name,
        "process.name": "sh",
        "process.parent.name": "find",
        "user.name": "www-data",
        "user.effective.name": "root",
        "threat.tactic.name": "Privilege Escalation",
        "threat.tactic.id": "TA0004",
        "threat.technique.name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "threat.technique.id": "T1548.001",
        "host.os.name": "Ubuntu",
        "host.os.version": "22.04.4 LTS",
        "event.outcome": "success",
      },
    },

    // ── 7. ROOT ACTION #1 — read /etc/shadow (proof the shell is root) ───────
    {
      id: "lpe_07_read_shadow",
      ts: T(45 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "file_access",
      hostname: host.name,
      severity: "critical",
      mitre_technique: "T1003.008",
      mitre_tactic: "Credential Access",
      description:
        "From the root shell, `cat /etc/shadow` opened the password-hash file. The SYSCALL is openat (257) with uid=33 euid=0 — a file mode 0640 root:shadow, unreadable to www-data, is read successfully.",
      process: {
        name: "cat",
        pid: 40402,
        path: "/usr/bin/cat",
        parent_name: "sh",
        parent_pid: 40378,
        cmdline: "cat /etc/shadow",
        user: "www-data",
      },
      file: {
        name: "shadow",
        path: "/etc/shadow",
      },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "257",
        "data.audit.success": "yes",
        "data.audit.exit": "3",
        "data.audit.ppid": "40378",
        "data.audit.pid": "40402",
        "data.audit.auid": "4294967295",
        "data.audit.uid": "33",
        "data.audit.gid": "33",
        "data.audit.euid": "0",
        "data.audit.egid": "33",
        "data.audit.fsuid": "0",
        "data.audit.tty": "(none)",
        "data.audit.ses": "4294967295",
        "data.audit.comm": "cat",
        "data.audit.exe": "/usr/bin/cat",
        "data.audit.cwd": "/var/www/html",
        "data.audit.key": "sensitive-file-read",
        "data.audit.file.name": "/etc/shadow",
        "data.audit.file.mode": "0100640",
        "data.audit.file.ouid": "0",
        "data.audit.file.ogid": "42",
        "data.audit.file.nametype": "NORMAL",
      },
    },

    // ── 8. ROOT ACTION #2 — create a uid-0 backdoor account ──────────────────
    {
      id: "lpe_08_backdoor_user",
      ts: T(47 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "account_create",
      hostname: host.name,
      severity: "critical",
      mitre_technique: "T1136.001",
      mitre_tactic: "Persistence",
      description:
        "The root shell ran useradd to create the account sysupdate with uid 0 and gid 0 — a second root-equivalent identity — and seeded its authorized_keys. The SYSCALL shows uid=33 euid=0 executing /usr/sbin/useradd.",
      process: {
        name: "useradd",
        pid: 40455,
        path: "/usr/sbin/useradd",
        parent_name: "sh",
        parent_pid: 40378,
        cmdline: "useradd -o -u 0 -g 0 -M -s /bin/bash sysupdate",
        user: "www-data",
      },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "59",
        "data.audit.success": "yes",
        "data.audit.exit": "0",
        "data.audit.ppid": "40378",
        "data.audit.pid": "40455",
        "data.audit.auid": "4294967295",
        "data.audit.uid": "33",
        "data.audit.gid": "33",
        "data.audit.euid": "0",
        "data.audit.egid": "0",
        "data.audit.fsuid": "0",
        "data.audit.fsgid": "0",
        "data.audit.tty": "(none)",
        "data.audit.ses": "4294967295",
        "data.audit.comm": "useradd",
        "data.audit.exe": "/usr/sbin/useradd",
        "data.audit.cwd": "/var/www/html",
        "data.audit.key": "identity-change",
        "data.audit.acct": backdoorUser,
        "data.audit.res": "success",
        "data.audit.execve.a0": "useradd",
      },
    },

    // ── 9. THE PAYOFF — remote login as the backdoor account ─────────────────
    {
      id: "lpe_09_backdoor_login",
      ts: T(52 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_login",
      hostname: host.name,
      src_ip: attackerIp,
      dst_ip: host.publicIp,
      dst_port: 22,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1078.003",
      mitre_tactic: "Persistence",
      description:
        "'Accepted publickey for sysupdate' from 193.32.162.140 on tcp/22 — the backdoor account authenticating with the attacker-controlled key, minutes after it was created.",
      authentication: { method: "publickey", result: "success" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": attackerIp,
        "data.srcport": "51884",
        "data.dstport": "22",
        "data.dstuser": backdoorUser,
        "data.audit.type": "USER_AUTH",
        "data.audit.acct": backdoorUser,
        "data.audit.uid": "0",
        "data.audit.auid": "0",
        "data.audit.ses": "48",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.terminal": "ssh",
        "data.audit.addr": attackerIp,
        "data.audit.op": "PAM:authentication",
        "data.audit.grantors": "pam_unix",
        "data.audit.res": "success",
        "sshd.auth_method": "publickey",
        "sshd.key_fingerprint": keyFingerprint,
      },
    },

    // ── 10. CORRELATION — SIEM ties the chain together ───────────────────────
    {
      id: "lpe_10_siem_correlation",
      ts: T(56 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.name,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1068",
      mitre_tactic: "Privilege Escalation",
      description:
        "Sentinel correlated the Falcon privilege-escalation detection with the auditd euid=0 records and the new uid-0 account, and raised a single incident for web-app-07.",
      raw: {
        "AlertName": "LinuxPrivilegeEscalation_SUID_RootAccountCreated",
        "alert.rule.id": "SEN-LNX-0247",
        "host.name": host.fqdn,
        "host.ip": host.privateIp,
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "ExtendedProperties.Foothold Account": "www-data",
        "ExtendedProperties.Escalation Technique": "SUID find (T1548.001)",
        "ExtendedProperties.New Root Account": backdoorUser,
        "ExtendedProperties.External Login Source": attackerIp,
        "ExtendedProperties.Window Start": T(38 * MIN),
        "ExtendedProperties.Window End": T(52 * MIN),
      },
    },
  ];

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
        { value: "no_sudo_path", label: "www-data has no sudo entitlement, so whatever escalation follows did NOT go through sudo — a different mechanism must be responsible" },
        { value: "wrong_pw", label: "www-data typed the wrong sudo password, so the same sudo rule is probably still usable with the correct one" },
        { value: "will_escalate", label: "A failed sudo -l is the normal first step of a working sudo exploit, so root was almost certainly obtained through sudo moments later" },
        { value: "no_tty", label: "The terminal is (none), so auditd could not have recorded the command at all and the record must be spurious" },
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
        { value: "suid_bit", label: "/usr/bin/find carries the setuid bit (mode 04755), so executing it sets euid to the file owner (root) regardless of who runs it" },
        { value: "sudo_rule", label: "A narrow sudoers rule lets www-data run find as root without a password, which is why euid becomes 0" },
        { value: "kernel_exploit", label: "A kernel vulnerability was exploited to overwrite the process credentials, forcing euid to 0" },
        { value: "world_writable", label: "/usr/bin/find is world-writable, so www-data replaced it with a copy that runs as root" },
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
        { value: "shadow_read", label: "lpe_07 — cat /etc/shadow succeeds (exit=3, a valid fd) with euid=0, reading a 0640 root:shadow file that www-data cannot open" },
        { value: "suid_enum", label: "lpe_04 — the find / -perm -4000 enumeration that located the setuid binary in the first place" },
        { value: "id_disc", label: "lpe_02 — the id command, which reported the account's identity at the start of the session" },
        { value: "siem_alert", label: "lpe_10 — the Sentinel correlation alert that named the escalation technique" },
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
        { value: "asroot", label: "Only the intrusion's processes ever run as root — the administrator's sudo command never actually reached uid/euid 0" },
        { value: "hostname", label: "The two occur on different hosts, so the admin activity is irrelevant to the web-app-07 incident and can be set aside" },
      ],
      answer: ["auid", "authz"],
      explanation:
        "The discriminators are provenance and authorization, not the fact of being root. auid (loginuid) is immutable once set and follows every child process: the admin's escalation carries auid=1001, tied to a named human who authenticated, while every escalated event in the intrusion carries auid=4294967295 — root privilege with no login session behind it, which for an interactive-looking action is deeply abnormal. And the admin's escalation went through sudo, which made and logged an authorization decision (res=success); the intrusion's euid=0 appears through a SUID execve with no sudo and no authorization record anywhere. The third option is false — the admin's sudo did run systemctl as root (that is what sudo does); 'ran as root' is exactly what does NOT separate them. The fourth is factually wrong: both occur on web-app-07, and the admin session is the control case precisely because it is on the same host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Foothold to Root — SUID Misconfiguration on a Linux App Server",
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
