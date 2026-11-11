/**
 * VMware vSphere: vCenter Server events and ESXi host syslog (card: docs/log-schemas/virt-vmware.md).
 *
 * What a SIEM receives:
 *  - vCenter: every stored event on the vpxd syslog stream (RFC 5424, APP-NAME vpxd), the line body
 *    `Event [eventId] [partInfo] [createdTime] [eventType] [severity] [user] [target] [chainId] [desc]`. The typed
 *    fields (ipAddress, userAgent, principal, role) are only inside `desc` on this stream. Kind `vcenter.syslog.event`.
 *    The QueryEvents API object (`vcenter.api.event`) is documented in the card and validated, never produced
 *    from feed events (the feed reads the syslog stream).
 *  - ESXi: vmsyslogd forwarding (RFC 3164 default), program per log: sshd (auth.log), shell (shell.log),
 *    Hostd (hostd.log), vobd (vobd.log). Kinds `esxi.syslog.<program>`. ESXi has no file event: a ransomware
 *    note or a staged binary is a shell command line, never a "file created" record.
 * Text-native: `record` is the flat parsed record, `rawLine` the wire line rebuilt from the same values.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, UseCase } from "../types";

type Rec = Record<string, unknown>;

// ── Schema ────────────────────────────────────────────────────────────────────

const SYSLOG = ["pri", "timestamp", "hostname", "program", "pid", "message"];
const ARG = (p: string, inner: string) => [p, `${p}._typeName`, `${p}.name`, `${p}.${inner}`, `${p}.${inner}._typeName`, `${p}.${inner}.type`, `${p}.${inner}.value`];
const kinds: Record<string, KindSchema> = {
  "vcenter.syslog.event": {
    required: [...SYSLOG, "eventId", "partInfo", "createdTime", "eventType", "severity", "user", "target", "chainId", "desc"],
    optional: [],
  },
  "vcenter.api.event": {
    required: ["_typeName", "key", "chainId", "createdTime", "userName", "fullFormattedMessage"],
    optional: [
      "ipAddress", "userAgent", "locale", "sessionId", "callCount", "loginTime", "principal", "group", "propagate",
      "role", "role._typeName", "role.roleId", "role.name", "eventTypeId", "severity", "message", "objectId", "objectType", "objectName",
      "arguments", "arguments[]._typeName", "arguments[].key", "arguments[].value", "changeTag", "auditId", "from", "to", "template",
      ...ARG("entity", "entity"), ...ARG("datacenter", "datacenter"), ...ARG("computeResource", "computeResource"),
      ...ARG("host", "host"), ...ARG("vm", "vm"), ...ARG("ds", "datastore"), ...ARG("alarm", "alarm"), ...ARG("source", "entity"),
    ],
  },
  "esxi.syslog.sshd": { required: SYSLOG, optional: [] },
  "esxi.syslog.shell": { required: [...SYSLOG, "user", "command"], optional: [] },
  "esxi.syslog.hostd": { required: [...SYSLOG, "Originator", "sub"], optional: ["opID", "sid", "user", "version", "msgid", "rhost"] },
  "esxi.syslog.vobd": { required: [...SYSLOG, "correlator", "uptime_us", "vob_id"], optional: [] },
};

export function kindOf(r: Rec): string | null {
  if (typeof r._typeName === "string") return "vcenter.api.event";
  if (r.program === "vpxd") return "vcenter.syslog.event";
  const p = String(r.program ?? "").toLowerCase();
  return ["sshd", "shell", "hostd", "vobd"].includes(p) ? `esxi.syslog.${p}` : null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : undefined);
const r$ = (ev: TelemetryEvent, ...keys: string[]) => { const r = (ev.raw ?? {}) as Rec; for (const k of keys) { const v = str(r[k]); if (v !== undefined) return v; } return undefined; };
const pidOf = (ev: TelemetryEvent, ctx: NativeCtx, program: string) => Number(r$(ev, "syslog.pid") ?? ctx.int(`${ev.hostname}:${program}`, 2_090_000, 2_140_000));
/** vpxd stamps the syslog header a few hundred microseconds after the event (card samples). */
const usIso = (ms: number, extraUs: number) => { const d = new Date(ms); const us = String(d.getUTCMilliseconds() * 1000 + extraUs).padStart(6, "0"); return `${d.toISOString().slice(0, 19)}.${us}`; };
const msIso = (ms: number) => new Date(ms).toISOString();

/** The vCenter event class an authored row names (UserLoginSessionEvent, PermissionAddedEvent ...). */
function vcClass(ev: TelemetryEvent): string | undefined {
  return r$(ev, "vsphere.event.eventTypeId", "vsphere.event.typeName");
}

function vcenterLine(ev: TelemetryEvent, ctx: NativeCtx, timeMs: number): NativeLog | null {
  const cls = vcClass(ev);
  if (!cls) return null;
  const host = r$(ev, "syslog.hostname") ?? ev.hostname;
  if (!host) return null;
  const eventId = Number(r$(ev, "vsphere.event.key") ?? ctx.int(`${ev.id}:vc-key`, 4_000_000, 9_000_000));
  const chainId = Number(r$(ev, "vsphere.event.chainId") ?? eventId);
  const eventType = cls.includes(".") && !cls.startsWith("vim.") ? "vim.event.EventEx" : cls.startsWith("vim.") ? cls : `vim.event.${cls}`;
  const severity = r$(ev, "vsphere.event.severity") ?? (ev.event_type === "auth_failure" ? "error" : "info");
  const user = r$(ev, "vsphere.event.userName") ?? "";
  // The target bracket is the inventory context, observed as the datacenter name (empty for session events).
  const target = /Session|Login|Logout/.test(cls) ? "" : r$(ev, "vsphere.event.datacenter.name") ?? "";
  const desc = r$(ev, "vsphere.event.fullFormattedMessage") ?? ev.description ?? cls;
  const pid = pidOf(ev, ctx, "vpxd");
  const created = usIso(timeMs, 0).replace(/$/, "Z");
  const timestamp = `${usIso(timeMs, 300)}+00:00`;
  const message = `Event [${eventId}] [1-1] [${created}] [${eventType}] [${severity}] [${user}] [${target}] [${chainId}] [${desc}]`;
  const record: Rec = { pri: 14, timestamp, hostname: host, program: "vpxd", pid, eventId, partInfo: "1-1", createdTime: created, eventType, severity, user, target, chainId, desc, message };
  return { sourceId: "vmware_vsphere", kind: "vcenter.syslog.event", format: "syslog", record, rawLine: `<14>1 ${timestamp} ${host} vpxd ${pid} - -  ${message}`, timeMs };
}

function esxiLine(ev: TelemetryEvent, ctx: NativeCtx, timeMs: number, program: string): NativeLog | null {
  const host = r$(ev, "syslog.hostname") ?? ev.hostname;
  if (!host) return null;
  const pid = pidOf(ev, ctx, program);
  const ts = msIso(timeMs);
  const authored = r$(ev, "syslog.message") ?? "";
  if (program === "sshd") {
    const port = r$(ev, "source.port");
    const user = (ev.user_email ?? "root").split("@")[0];
    const message = ev.event_type === "ssh_login" && ev.src_ip
      ? `Accepted keyboard-interactive/pam for ${user} from ${ev.src_ip} port ${port ?? ctx.int(`${ev.id}:port`, 49_200, 64_000)} ssh2`
      : authored || (ev.src_ip ? `error: PAM: Authentication failure for ${user} from ${ev.src_ip}` : "");
    if (!message) return null;
    const pri = 38;
    return { sourceId: "vmware_vsphere", kind: "esxi.syslog.sshd", format: "syslog", timeMs,
      record: { pri, timestamp: ts, hostname: host, program: "sshd", pid, message }, rawLine: `<${pri}>${ts} ${host} sshd[${pid}]: ${message}` };
  }
  if (program === "shell") {
    const m = /^\[([^\]]+)\]:\s?(.*)$/s.exec(authored);
    const user = m?.[1] ?? (ev.user_email ?? "root").split("@")[0];
    const command = m?.[2] ?? r$(ev, "process.command_line");
    if (!command) return null;
    const message = `[${user}]: ${command}`;
    const pri = 13;
    return { sourceId: "vmware_vsphere", kind: "esxi.syslog.shell", format: "syslog", timeMs,
      record: { pri, timestamp: ts, hostname: host, program: "shell", pid, user, command, message }, rawLine: `<${pri}>${ts} ${host} shell[${pid}]: ${message}` };
  }
  if (program === "vobd") {
    const vob = vcClass(ev) ?? r$(ev, "vob.id");
    const text = r$(ev, "vsphere.event.fullFormattedMessage") ?? ev.description;
    if (!vob || !text) return null;
    const correlator = vob.startsWith("vob.user.") ? "UserLevelCorrelator" : "GenericCorrelator";
    const uptime = `${ctx.int(`${host}:boot`, 1_200_000, 1_900_000)}${String(ctx.int(`${ev.id}:us`, 100_000, 999_999))}us`;
    const message = `[${correlator}] ${uptime}: [${vob}] ${text}`;
    const pri = 14;
    return { sourceId: "vmware_vsphere", kind: "esxi.syslog.vobd", format: "syslog", timeMs,
      record: { pri, timestamp: ts, hostname: host, program: "vobd", pid, correlator, uptime_us: uptime, vob_id: vob, message }, rawLine: `<${pri}>${ts} ${host} vobd[${pid}]: ${message}` };
  }
  return null;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if ((ev.source as string) !== "virtualization" || !/vmware/i.test(ev.vendor ?? "")) return null;
  const timeMs = Date.parse(ev.ts);
  if (!Number.isFinite(timeMs)) return null;
  const program = r$(ev, "syslog.program")?.toLowerCase();
  if (program === "vpxd" || (!program && /vcenter/i.test(ev.vendor ?? ""))) return vcenterLine(ev, ctx, timeMs);
  if (program === "sshd" || program === "shell" || program === "vobd") return esxiLine(ev, ctx, timeMs, program);
  // An ESXi audit event with no program named arrives on vobd (esx.audit.* observations).
  if (!program && /esx\.audit\./.test(vcClass(ev) ?? "")) return esxiLine(ev, ctx, timeMs, "vobd");
  return null;
}

// ── Use cases ─────────────────────────────────────────────────────────────────

const VC = ["vcenter.syslog.event"], SH = ["esxi.syslog.shell"], VOB = ["esxi.syslog.vobd"], SSH = ["esxi.syslog.sshd"];
const useCases: UseCase[] = [
  {
    id: "vmware_vsphere.vcenter-login-spray", title: "vCenter login failures for many accounts from one address",
    sourceId: "vmware_vsphere", kinds: VC, severity: "high", mitre: ["T1110.003"],
    description: "One client failing vCenter logins for many different accounts in a short time is a password spray against the hypervisor's control plane. A success from the same address afterwards means one guess worked: that account can reach every VM.",
    logic: "// Splunk (vpxd syslog)\nsourcetype=vmware:vclog:vpxd \"vim.event.BadUsernameSessionEvent\"\n| rex \"\\[Cannot login (?<user>[^@\\]]+)@(?<src_ip>[\\d.]+)\\]\"\n| bin _time span=10m | stats dc(user) as accounts by src_ip, _time | where accounts >= 5",
    match: { field: "eventType", op: "eq", value: "vim.event.BadUsernameSessionEvent" },
    threshold: { groupBy: ["hostname"], count: 5, windowSec: 600, distinct: "user" },
    falsePositives: ["A backup or monitoring product with a stale password retrying one account (one account, not many)"],
  },
  {
    id: "vmware_vsphere.admin-permission-granted", title: "Administrator role granted in vCenter",
    sourceId: "vmware_vsphere", kinds: VC, severity: "high", mitre: ["T1098"],
    description: "A permission with the Administrator role on the root folder or a datacenter gives the principal full control of every host and VM below it. Attackers grant it to an account they control right after getting in.",
    logic: "// Splunk (vpxd syslog)\nsourcetype=vmware:vclog:vpxd \"vim.event.PermissionAddedEvent\" \"role is Administrator\"",
    match: { all: [{ field: "eventType", op: "eq", value: "vim.event.PermissionAddedEvent" }, { field: "desc", op: "icontains", value: "Administrator" }] },
    falsePositives: ["A planned access change by the virtualization team with a change ticket"],
  },
  {
    id: "vmware_vsphere.esxi-ssh-enabled", title: "SSH or the ESXi Shell enabled on a host",
    sourceId: "vmware_vsphere", kinds: VOB, severity: "medium", mitre: ["T1021.004"],
    description: "ESXi ships with SSH off. Turning it on is the step before every hands-on-keyboard ESXi attack: power off the VMs, then encrypt the datastore.",
    logic: "// Splunk (vobd)\nsourcetype=vmw-syslog \"[esx.audit.ssh.enabled]\" OR \"[esx.audit.shell.enabled]\"",
    match: { field: "vob_id", op: "in", value: ["esx.audit.ssh.enabled", "esx.audit.shell.enabled"] },
    falsePositives: ["Vendor support sessions and patching windows (should be time-boxed and ticketed)"],
  },
  {
    id: "vmware_vsphere.mass-vm-poweroff", title: "VMs powered off from the ESXi shell",
    sourceId: "vmware_vsphere", kinds: SH, severity: "critical", mitre: ["T1489"],
    description: "Ransomware for ESXi powers every VM off before it encrypts, so the disk files are not locked. A loop over vim-cmd vmsvc/power.off or esxcli vm process kill typed in the shell is that step.",
    logic: "// Splunk (shell.log)\nsourcetype=vmw-syslog program=shell (\"vmsvc/power.off\" OR \"vm process kill\")",
    match: { any: [{ field: "command", op: "contains", value: "vmsvc/power.off" }, { field: "command", op: "contains", value: "vm process kill" }] },
    falsePositives: ["A maintenance script during a planned host shutdown"],
  },
  {
    id: "vmware_vsphere.binary-run-from-tmp", title: "Binary made executable and run from /tmp on an ESXi host",
    sourceId: "vmware_vsphere", kinds: SH, severity: "critical", mitre: ["T1486", "T1059.004"],
    description: "Nothing legitimate on ESXi runs from /tmp. A file copied there, made executable and pointed at /vmfs/volumes is an encryptor.",
    logic: "// Splunk (shell.log)\nsourcetype=vmw-syslog program=shell \"chmod +x /tmp/\"",
    match: { all: [{ field: "command", op: "contains", value: "chmod +x /tmp/" }] },
    falsePositives: ["None expected: treat as an incident"],
  },
  {
    id: "vmware_vsphere.root-ssh-login", title: "root SSH login on an ESXi host",
    sourceId: "vmware_vsphere", kinds: SSH, severity: "medium", mitre: ["T1078.003", "T1021.004"],
    description: "Interactive root logins over SSH are rare on a managed host. Check where the address comes from and whether SSH was enabled just before.",
    logic: "// Splunk (auth.log)\nsourcetype=vmw-syslog program=sshd \"Accepted\" \"for root from\"",
    match: { all: [{ field: "message", op: "startsWith", value: "Accepted" }, { field: "message", op: "contains", value: "for root from" }] },
    falsePositives: ["Break-glass access during an outage, documented in a ticket"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "vmware_vsphere",
    category: "virtualization",
    card: "virt-vmware.md",
    product: "VMware vSphere",
    format: "syslog",
    vendorMatch: ["vmware"],
    telemetrySources: ["virtualization"],
    kinds,
  },
  fromTelemetry,
  useCases,
};
