/**
 * Linux auditd event BUILDER: the alert the Wazuh auditd decoder writes (data.audit.*).
 *
 * auditd logs one event as several records that share one `audit(<epoch>:<serial>)` stamp: the
 * SYSCALL (the process credentials, the syscall and its result), the CWD, the EXECVE argv of an
 * exec and a PATH item for each file the syscall touched. Wazuh's decoder merges the records of
 * one event into one alert: `data.audit.id` (the serial), the SYSCALL fields, `data.audit.cwd`,
 * `data.audit.execve.a0..aN` and `data.audit.file.*`. A story that shows the records of one event
 * as separate rows (the SYSCALL row, then its EXECVE row, then its PATH row) gives every row the
 * event's merged fields; `data.audit.type` names the record the row stands for.
 *
 * A SYSCALL record always prints all eight credential ids (uid euid suid fsuid / gid egid sgid
 * fsgid): a SUID binary changes euid / suid / fsuid only, never the real uid or the gids.
 */
export interface AuditdFile {
  name: string;
  inode: string | number;
  mode: string;          // e.g. 0100644, 0104755 (SUID)
  ouid: string;
  ogid: string;
  nametype: "NORMAL" | "CREATE" | "DELETE" | "PARENT";
}
export interface AuditdEventOpts {
  serial: string | number;                       // the audit event serial (data.audit.id)
  type: "SYSCALL" | "EXECVE" | "PATH" | "CWD";   // the record this row stands for
  syscall: string;                               // number as auditd prints it on x86_64 (59 execve, 257 openat, 90 chmod …)
  success?: boolean;
  exit?: string;
  pid: number | string;
  ppid: number | string;
  auid: string;
  uid: string;
  gid: string;
  euid?: string; suid?: string; fsuid?: string;  // default: the real uid
  egid?: string; sgid?: string; fsgid?: string;  // default: the real gid
  tty: string;
  ses: string;
  comm: string;
  exe: string;
  key: string;
  cwd: string;
  argv?: string[];                               // the EXECVE record of an exec
  file?: AuditdFile;                             // the PATH item the event names
}

/** The merged Wazuh auditd alert fields of one audit event, as a raw block. */
export function auditdRaw(o: AuditdEventOpts): Record<string, string> {
  const euid = o.euid ?? o.uid;
  return {
    "data.audit.type": o.type,
    "data.audit.id": String(o.serial),
    "data.audit.arch": "c000003e",
    "data.audit.syscall": o.syscall,
    "data.audit.success": o.success === false ? "no" : "yes",
    "data.audit.exit": o.exit ?? "0",
    "data.audit.ppid": String(o.ppid),
    "data.audit.pid": String(o.pid),
    "data.audit.auid": o.auid,
    "data.audit.uid": o.uid,
    "data.audit.gid": o.gid,
    "data.audit.euid": euid,
    "data.audit.suid": o.suid ?? euid,
    "data.audit.fsuid": o.fsuid ?? euid,
    "data.audit.egid": o.egid ?? o.gid,
    "data.audit.sgid": o.sgid ?? o.gid,
    "data.audit.fsgid": o.fsgid ?? o.gid,
    "data.audit.tty": o.tty,
    "data.audit.ses": o.ses,
    "data.audit.comm": o.comm.slice(0, 15),
    "data.audit.exe": o.exe,
    "data.audit.key": o.key,
    "data.audit.cwd": o.cwd,
    ...Object.fromEntries((o.argv ?? []).map((a, i) => [`data.audit.execve.a${i}`, a])),
    ...(o.file ? {
      "data.audit.file.name": o.file.name,
      "data.audit.file.inode": String(o.file.inode),
      "data.audit.file.mode": o.file.mode,
      "data.audit.file.ouid": o.file.ouid,
      "data.audit.file.ogid": o.file.ogid,
      "data.audit.file.nametype": o.file.nametype,
    } : {}),
  };
}
