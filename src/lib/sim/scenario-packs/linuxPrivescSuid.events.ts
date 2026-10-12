/**
 * Events-only half of the ./linuxPrivescSuid.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./linuxPrivescSuid.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

/** Telemetry half of the linuxPrivescSuid scenario: the events and the story title, no answer key. */
export function linuxPrivescSuidScenarioEvents() {
  const title = "Foothold to Root — SUID Misconfiguration on a Linux App Server";
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
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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
        "crowdstrike.ParentBaseFileName": "find",
        "crowdstrike.ParentProcessId": "40377",
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
        "threat.technique.id": "T1548",
        "threat.technique.subtechnique.id": "T1548.001",
        "host.os.name": "Ubuntu",
        "host.os.version": "22.04.4 LTS",
        "event.outcome": "success",
      },
    },

    // ── 7. ROOT ACTION #1 — read /etc/shadow (proof the shell is root) ───────
    {
      id: "lpe_07_read_shadow",
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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
      incident_id: INCIDENT,
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

  return { title, events, B, T, MIN, host, admin, attackerIp, backdoorUser, keyFingerprint, suidBinary, INCIDENT };
}
