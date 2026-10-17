/**
 * `netstat` with switches, printed the way the real tool prints it, so the analyst reads the
 * same table on the training host as on a real one.
 *
 *  - Windows (`netstat -ano`, `-an`, `-anob`, `-n`, `-p tcp` …): the "Active Connections"
 *    table with Proto / Local Address / Foreign Address / State [/ PID]. `-a` adds the
 *    listening ports and UDP endpoints, `-n` keeps addresses numeric (without it the foreign
 *    side is resolved to the known domain and service name), `-o` adds the PID column and
 *    `-b` adds the owning image under each row.
 *  - Linux (`netstat -tulpn`, `-antp`, `-anp` …): the net-tools table with Proto / Recv-Q /
 *    Send-Q / Local Address / Foreign Address / State [/ PID/Program name].
 *
 * Bare `netstat` keeps the console's own summary view (see rtr.ts). The rows come from the
 * same data: the case's connections plus the host's normal listeners. Nothing is labelled;
 * the analyst still has to match the PID of the odd connection to a process.
 */
import type { EdrInvestigation, EdrProcess } from "./investigations";
import { isServerHost } from "./hostBaseline";

interface Sock {
  proto: "tcp" | "udp";
  local: string; lport: number;
  foreign: string; fport: number | null; fname?: string;
  listen: boolean;
  pid: number; name: string;
}

const WIN_PORTS: Record<number, string> = {
  21: "ftp", 22: "ssh", 25: "smtp", 53: "domain", 80: "http", 88: "kerberos", 135: "epmap", 139: "netbios-ssn",
  389: "ldap", 443: "https", 445: "microsoft-ds", 636: "ldaps", 3389: "ms-wbt-server",
};
const NIX_PORTS: Record<number, string> = {
  21: "ftp", 22: "ssh", 25: "smtp", 53: "domain", 80: "http", 443: "https", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
};

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
/** Deterministic client port in the OS's dynamic range (Windows 49152-65535, Linux 32768-60999). */
const ephemeral = (seed: string, linux: boolean) => (linux ? 32768 + (hash(seed) % 28232) : 49152 + (hash(seed) % 16383));
const col = (s: string, w: number) => (s.length >= w ? s + " " : s.padEnd(w));

function sockets(inv: EdrInvestigation, procs: EdrProcess[], killed: ReadonlySet<number>, isolated: boolean, linux: boolean): Sock[] {
  const out: Sock[] = [];
  const find = (pred: (p: EdrProcess) => boolean) => procs.find(pred);
  const listen = (proto: "tcp" | "udp", local: string, lport: number, p: EdrProcess | undefined) => {
    if (p) out.push({ proto, local, lport, foreign: "", fport: null, listen: true, pid: p.pid, name: p.name });
  };
  if (linux) {
    listen("tcp", "0.0.0.0", 22, find(p => p.name === "sshd"));
    const resolved = find(p => p.name === "systemd-resolved");
    listen("tcp", "127.0.0.53", 53, resolved);
    listen("udp", "127.0.0.53", 53, resolved);
  } else {
    listen("tcp", "0.0.0.0", 135, find(p => /-k RPCSS/i.test(p.cmdline)));
    listen("tcp", "0.0.0.0", 445, find(p => p.pid === 4));
    if (isServerHost(inv.host)) listen("tcp", "0.0.0.0", 5985, find(p => /WinRM/i.test(p.cmdline)) ?? find(p => p.pid === 4));
    listen("tcp", "0.0.0.0", 49664, find(p => p.name.toLowerCase() === "lsass.exe"));
    listen("tcp", inv.host.ip, 139, find(p => p.pid === 4));
    listen("udp", "0.0.0.0", 5353, find(p => /-k NetworkService -p$/i.test(p.cmdline)));
  }
  // A contained host has had its connections torn down; local listeners remain.
  if (isolated) return out;
  const seen = new Set<string>();
  for (const p of inv.processes) {
    if (killed.has(p.pid)) continue;
    for (const c of p.network ?? []) {
      // `proto` is the transport; older practice cases store the layer-7 name there (HTTP / TLS / DNS).
      const raw = (c.proto ?? "tcp").toLowerCase();
      if (raw === "icmp") continue;
      const proto: "tcp" | "udp" = raw === "udp" || raw === "dns" ? "udp" : "tcp";
      const key = `${p.pid}|${proto}|${c.direction}|${c.remote_ip}|${c.remote_port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const seed = `${inv.host.name}|${key}`;
      if (proto === "udp") {
        // An unconnected UDP client socket: netstat shows only its local end.
        out.push({ proto: "udp", local: "0.0.0.0", lport: ephemeral(seed, linux), foreign: "", fport: null, listen: false, pid: p.pid, name: p.name });
        continue;
      }
      if (!isIp(c.remote_ip)) continue;
      if (c.direction === "inbound") {
        out.push({ proto: "tcp", local: inv.host.ip, lport: c.remote_port, foreign: c.remote_ip, fport: ephemeral(seed, linux), listen: false, pid: p.pid, name: p.name });
      } else {
        out.push({ proto: "tcp", local: inv.host.ip, lport: ephemeral(seed, linux), foreign: c.remote_ip, fport: c.remote_port, fname: c.domain, listen: false, pid: p.pid, name: p.name });
      }
    }
  }
  return out;
}

const ipNum = (ip: string) => ip.split(".").reduce((a, o) => a * 256 + (Number(o) || 0), 0);
const byAddress = (a: Sock, b: Sock) =>
  (a.proto === b.proto ? 0 : a.proto === "tcp" ? -1 : 1) || ipNum(a.local) - ipNum(b.local) || a.lport - b.lport;

const WIN_USAGE = "netstat: this console supports -a, -n, -o, -b and -p tcp|udp (for example: netstat -ano).";
const NIX_USAGE = "netstat: this console supports -a, -t, -u, -l, -n and -p (for example: netstat -tulpn).";

function windows(inv: EdrInvestigation, all: Sock[], args: string[]): string {
  const flags = new Set<string>();
  let protoFilter: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!/^[-/]./.test(a)) return WIN_USAGE;
    for (const ch of a.slice(1).toLowerCase()) {
      if (ch === "p") {
        protoFilter = (args[++i] ?? "").toLowerCase();
        if (protoFilter !== "tcp" && protoFilter !== "udp") return WIN_USAGE;
      } else if ("anob".includes(ch)) flags.add(ch);
      else return WIN_USAGE;
    }
  }
  const showAll = flags.has("a"), numeric = flags.has("n"), pid = flags.has("o"), owner = flags.has("b");
  const rows = all
    .filter(s => (showAll || (!s.listen && s.proto === "tcp")) && (!protoFilter || s.proto === protoFilter))
    .sort(byAddress);
  const lines = ["", "Active Connections", "", `  ${col("Proto", 7)}${col("Local Address", 23)}${col("Foreign Address", 23)}${pid ? col("State", 16) + "PID" : "State"}`];
  for (const s of rows) {
    const local = `${s.local}:${s.lport}`;
    const foreign = s.proto === "udp" ? "*:*"
      : s.listen ? (numeric ? "0.0.0.0:0" : `${inv.host.name}:0`)
      : numeric ? `${s.foreign}:${s.fport}` : `${s.fname ?? s.foreign}:${WIN_PORTS[s.fport ?? 0] ?? s.fport}`;
    const state = s.proto === "udp" ? "" : s.listen ? "LISTENING" : "ESTABLISHED";
    lines.push(`  ${col(s.proto.toUpperCase(), 7)}${col(local, 23)}${col(foreign, 23)}${pid ? col(state, 16) + s.pid : state}`.trimEnd());
    if (owner) lines.push(s.pid === 4 ? " Can not obtain ownership information" : ` [${s.name}]`);
  }
  return lines.join("\n");
}

function linuxTable(inv: EdrInvestigation, all: Sock[], args: string[]): string {
  const flags = new Set<string>();
  for (const a of args) {
    if (!/^-[a-z]+$/i.test(a)) return NIX_USAGE;
    for (const ch of a.slice(1).toLowerCase()) {
      if ("atulnp".includes(ch)) flags.add(ch);
      else return NIX_USAGE;
    }
  }
  const tcp = flags.has("t") || !flags.has("u"), udp = flags.has("u") || !flags.has("t");
  const servers = flags.has("l") && !flags.has("a"), everything = flags.has("a");
  const numeric = flags.has("n"), prog = flags.has("p");
  const rows = all.filter(s => (s.proto === "tcp" ? tcp : udp) && (everything || (servers ? s.listen : !s.listen)));
  const name = (ip: string, port: number) => numeric ? `${ip}:${port}`
    : `${ip === inv.host.ip ? inv.host.name : ip === "127.0.0.53" ? "_localdnsstub" : ip}:${NIX_PORTS[port] ?? port}`;
  const lines = [
    `Active Internet connections (${servers ? "only servers" : everything ? "servers and established" : "w/o servers"})`,
    `Proto Recv-Q Send-Q ${col("Local Address", 23)} ${col("Foreign Address", 23)} ${prog ? "State".padEnd(11) + " PID/Program name" : "State"}`,
  ];
  for (const s of rows) {
    const local = name(s.local, s.lport);
    const foreign = s.listen || s.proto === "udp" ? "0.0.0.0:*"
      : numeric ? `${s.foreign}:${s.fport}` : `${s.fname ?? s.foreign}:${NIX_PORTS[s.fport ?? 0] ?? s.fport}`;
    const state = s.proto === "udp" ? "" : s.listen ? "LISTEN" : "ESTABLISHED";
    lines.push(`${s.proto.padEnd(5)} ${"0".padStart(6)} ${"0".padStart(6)} ${col(local, 23)} ${col(foreign, 23)} ${prog ? state.padEnd(11) + ` ${s.pid}/${s.name}` : state}`.trimEnd());
  }
  return lines.join("\n");
}

/** `netstat <switches>` in the host OS's native table format. */
export function netstatWithSwitches(
  inv: EdrInvestigation, procs: EdrProcess[], killed: ReadonlySet<number>, isolated: boolean, linux: boolean, args: string[],
): string {
  const all = sockets(inv, procs, killed, isolated, linux);
  return linux ? linuxTable(inv, all, args) : windows(inv, all, args);
}
