/**
 * SentinelOne Singularity — native module (card: docs/log-schemas/edr-sentinelone.md).
 *
 * Two native shapes, never mixed:
 *   - Deep Visibility / Singularity Data Lake telemetry as exported by Cloud Funnel 2.0 — ONE flat
 *     JSON object whose keys literally contain dots ("src.process.cmdline", "event.type"), with the
 *     current spaced event.type names: "Process Creation", "DNS Resolved" / "DNS Unresolved",
 *     "IP Connect", "File Creation" / "File Modification" / "File Deletion", "Behavioral Indicators"
 *     (card sample only). Numbers stay numbers (pids, ports, epoch-ms times), booleans stay booleans.
 *   - Threats API v2.1 — one element of `data[]` (kind "threat"), nested camelCase.
 *
 * Actor model (card §5): src.process.* performs the action, tgt.process.* / tgt.file.* is the
 * object, src.process.parent.* is the actor's parent; DNS also names the physical resolver
 * (svchost Dnscache) as osSrc.process.* on Windows.
 *
 * Correlation: same host → same agent.uuid (seeded `${companyId}:${host}`); a process's uid is
 * seeded from host + image name + OS pid, so the tgt.process.uid of its Process Creation equals
 * the src.process.uid / process.unique.key of its own DNS / IP / file events and the
 * src.process.parent.uid of its children. Storyline: one id per host + attack chain — the
 * incident (TelemetryEvent.incident_id) when the event belongs to one, else the chain root
 * (the first process whose parent is a shell such as explorer.exe / services.exe), so parent
 * and child share it; the Threat's threatInfo.storyline is the same value.
 *
 * Returns null (never fakes a record) for events edrFacts marks unsupported, registry and logon
 * events (the card documents event.type names for them but NO key names), process events with no
 * image at all, and network events with no IPv4 peer.
 */
import { techniqueName } from "./_edr_mde_sophos_common";
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { edrFacts, type EdrFacts, type EdrProc } from "./edr-normalize";
import {
  osOf, rhex, hostIpOf, egressIp, hostRole, companyDisplay, digits, iso, isoMicro, userOf, procName, imagePath, drivePath,
  ntDevicePath, pidOf, procSeed, netFacts, fixPath, baseName, isIPv4, SHELLS, OFFICE, SCRIPT_HOSTS, LOLBINS, PRIVATE_CIDRS,
  USER_WRITABLE_RE, DOWNLOADS_PUBLIC_RE, type UserFacts,
  foreignDetectionName,
} from "./_cs-s1-common";

// ── schema ───────────────────────────────────────────────────────────────────

const COMMON_REQ = ["timestamp", "event.time", "event.type", "event.category", "meta.event.name", "event.id", "trace.id", "agent.uuid",
  "endpoint.name", "endpoint.os", "account.id", "site.id"];
const COMMON_OPT = ["packet.id", "i.scheme", "i.version", "dataSource.name", "dataSource.vendor", "dataSource.category", "account.name",
  "site.name", "group.id", "mgmt.id", "mgmt.url", "mgmt.osRevision", "agent.version", "endpoint.type", "os.name", "process.unique.key"];
const PROC_SUFFIX = ["name", "displayName", "pid", "uid", "cmdline", "image.path", "image.sha1", "image.sha256", "image.md5",
  "image.binaryIsExecutable", "user", "integrityLevel", "sessionId", "startTime", "storyline.id", "isStorylineRoot", "signedStatus",
  "verifiedStatus", "publisher", "subsystem", "isNative64Bit", "isRedirectCmdProcessor"];
const COUNTERS = ["childProcCount", "netConnCount", "netConnOutCount", "netConnInCount", "dnsCount", "tgtFileCreationCount",
  "tgtFileModificationCount", "tgtFileDeletionCount", "registryChangeCount", "moduleCount", "crossProcessCount", "indicatorGeneralCount",
  "indicatorEvasionCount", "indicatorExploitationCount", "indicatorPersistenceCount", "indicatorInjectionCount", "indicatorReconnaissanceCount",
  "indicatorRansomwareCount", "indicatorInfostealerCount", "indicatorPostExploitationCount", "indicatorBootConfigurationUpdateCount"];
const px = (prefix: string, keys: string[]) => keys.map(k => `${prefix}${k}`);
const ACTOR = [...px("src.process.", PROC_SUFFIX), ...px("src.process.", COUNTERS), ...px("src.process.parent.", PROC_SUFFIX)];

const FILE_KIND: KindSchema = {
  required: [...COMMON_REQ, "tgt.file.path"],
  optional: [...COMMON_OPT, ...ACTOR, ...px("tgt.file.", ["name", "extension", "size", "type", "isExecutable", "location", "creationTime",
    "modificationTime", "id", "sha1", "sha256", "isSigned", "oldPath"])],
};
const DNS_KIND: KindSchema = {
  required: [...COMMON_REQ, "event.dns.request"],
  optional: [...COMMON_OPT, ...ACTOR, ...px("osSrc.process.", PROC_SUFFIX), "event.dns.response", "event.dns.status"],
};
const DETAIL_OBJ = (o: string, keys: string[]) => keys.map(k => `${o}.${k}`);

const kinds: Record<string, KindSchema> = {
  "Process Creation": {
    required: [...COMMON_REQ, "tgt.process.name", "tgt.process.pid", "tgt.process.uid", "tgt.process.cmdline", "tgt.process.storyline.id"],
    optional: [...COMMON_OPT, ...ACTOR, ...px("tgt.process.", PROC_SUFFIX)],
  },
  "DNS Resolved": DNS_KIND,
  "DNS Unresolved": DNS_KIND,
  "IP Connect": {
    required: [...COMMON_REQ, "src.ip.address", "src.port.number", "dst.ip.address", "dst.port.number", "event.network.direction", "event.network.connectionStatus"],
    optional: [...COMMON_OPT, ...ACTOR, "event.network.protocolName", "event.repetitionCount"],
  },
  "File Creation": FILE_KIND,
  "File Modification": FILE_KIND,
  "File Deletion": FILE_KIND,
  "Behavioral Indicators": {
    required: [...COMMON_REQ, "indicator.name", "indicator.category"],
    optional: [...COMMON_OPT, ...ACTOR, "indicator.description", "indicator.metadata"],
  },
  threat: {
    required: ["id", "threatInfo.threatId", "threatInfo.threatName", "threatInfo.classification", "threatInfo.confidenceLevel",
      "threatInfo.mitigationStatus", "threatInfo.analystVerdict", "threatInfo.incidentStatus", "threatInfo.storyline", "threatInfo.createdAt",
      "threatInfo.identifiedAt", "agentRealtimeInfo.agentComputerName", "agentRealtimeInfo.agentUuid", "agentDetectionInfo.agentUuid"],
    optional: [
      ...DETAIL_OBJ("agentDetectionInfo", ["accountId", "accountName", "agentDetectionState", "agentDomain", "agentIpV4", "agentIpV6",
        "agentLastLoggedInUpn", "agentLastLoggedInUserMail", "agentLastLoggedInUserName", "agentMitigationMode", "agentOsName", "agentOsRevision",
        "agentRegisteredAt", "agentVersion", "cloudProviders", "externalIp", "groupId", "groupName", "siteId", "siteName"]),
      ...DETAIL_OBJ("agentRealtimeInfo", ["accountId", "accountName", "activeThreats", "agentDecommissionedAt", "agentDomain", "agentId",
        "agentInfected", "agentIsActive", "agentIsDecommissioned", "agentMachineType", "agentMitigationMode", "agentNetworkStatus", "agentOsName",
        "agentOsRevision", "agentOsType", "agentVersion", "groupId", "groupName", "networkInterfaces[].id", "networkInterfaces[].inet[]",
        "networkInterfaces[].inet6[]", "networkInterfaces[].name", "networkInterfaces[].physical", "operationalState", "rebootRequired",
        "scanAbortedAt", "scanFinishedAt", "scanStartedAt", "scanStatus", "siteId", "siteName", "storageName", "storageType", "userActionsNeeded"]),
      ...DETAIL_OBJ("containerInfo", ["id", "image", "labels", "name"]),
      "indicators", "indicators[].category", "indicators[].description", "indicators[].ids[]", "indicators[].tactics", "indicators[].tactics[].name",
      "indicators[].tactics[].source", "indicators[].tactics[].techniques[].link", "indicators[].tactics[].techniques[].name",
      ...DETAIL_OBJ("kubernetesInfo", ["cluster", "controllerKind", "controllerLabels", "controllerName", "namespace", "namespaceLabels", "node", "pod", "podLabels"]),
      "mitigationStatus", ...DETAIL_OBJ("mitigationStatus[]", ["action", "actionsCounters.failed", "actionsCounters.notFound",
        "actionsCounters.pendingReboot", "actionsCounters.success", "actionsCounters.total", "agentSupportsReport", "groupNotFound", "lastUpdate",
        "latestReport", "mitigationEndedAt", "mitigationStartedAt", "status"]),
      ...DETAIL_OBJ("threatInfo", ["analystVerdictDescription", "automaticallyResolved", "browserType", "certificateId", "classificationSource",
        "cloudFilesHashVerdict", "collectionId", "detectionEngines", "detectionEngines[].key", "detectionEngines[].title", "detectionType", "engines[]",
        "externalTicketExists", "externalTicketId", "failedActions", "fileExtension", "fileExtensionType", "filePath", "fileSize",
        "fileVerificationType", "incidentStatusDescription", "initiatedBy", "initiatedByDescription", "initiatingUserId", "initiatingUsername",
        "isFileless", "isValidCertificate", "maliciousProcessArguments", "md5", "mitigatedPreemptively", "mitigationStatusDescription",
        "originatorProcess", "pendingActions", "processUser", "publisherName", "reachedEventsLimit", "rebootRequired", "sha1", "sha256", "updatedAt"]),
      "whiteningOptions[]",
    ],
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (typeof record["event.type"] === "string") return record["event.type"] as string;
  if (record.threatInfo && typeof record.threatInfo === "object") return "threat";
  return null;
}

// ── helpers ──────────────────────────────────────────────────────────────────

const lc = (s?: string) => (s ?? "").toLowerCase();
const INTEGRITY: Record<string, string> = { low: "LOW", medium: "MEDIUM", high: "HIGH", system: "SYSTEM" };
const DISPLAY: Record<string, string> = {
  "powershell.exe": "Windows PowerShell", "pwsh.exe": "PowerShell 7", "cmd.exe": "Windows Command Processor", "winword.exe": "Microsoft Word",
  "excel.exe": "Microsoft Excel", "outlook.exe": "Microsoft Outlook", "powerpnt.exe": "Microsoft PowerPoint", "explorer.exe": "Windows Explorer",
  "chrome.exe": "Google Chrome", "msedge.exe": "Microsoft Edge", "rundll32.exe": "Windows host process (Rundll32)",
  "regsvr32.exe": "Microsoft(C) Register Server", "mshta.exe": "Microsoft (R) HTML Application host", "wscript.exe": "Microsoft (R) Windows Based Script Host",
  "cscript.exe": "Microsoft (R) Console Based Script Host", "certutil.exe": "CertUtil.exe", "svchost.exe": "Host Process for Windows Services",
};
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** ULID-shaped trace id (48-bit time prefix + 80 bits from the seed) — Cloud Funnel trace.id style. */
function ulid(ctx: NativeCtx, ms: number, seed: string): string {
  let t = "";
  let n = Math.floor(ms);
  for (let i = 0; i < 10; i++) { t = CROCKFORD[n % 32] + t; n = Math.floor(n / 32); }
  const h = rhex(ctx, seed, 16);
  let r = "";
  for (let i = 0; i < 16; i++) r += CROCKFORD[parseInt(h[i], 16) * 2 % 32];
  return t + r;
}
const id19 = (ctx: NativeCtx, seed: string) => `18${digits(ctx, seed, 17)}`;
const uidOf = (ctx: NativeCtx, seed: string) => rhex(ctx, `${seed}:s1uid`, 16).toUpperCase();

interface Base { ctx: NativeCtx; ev: TelemetryEvent; f: EdrFacts; host: string; os: "Win" | "Lin" | "Mac"; hostIp: string; agentUuid: string; u: UserFacts }

function tenant(ctx: NativeCtx) {
  return {
    accountId: id19(ctx, `${ctx.companyId}:s1:account`), accountName: companyDisplay(ctx),
    siteId: id19(ctx, `${ctx.companyId}:s1:site`), siteName: `${companyDisplay(ctx)}-HQ`,
    mgmtUrl: /\.eu$|\.de$|\.nl$|\.org$/.test(ctx.domain) ? "euce1-108.sentinelone.net" : "usea1-012.sentinelone.net",
  };
}
function groupOf(ctx: NativeCtx, host: string) {
  const role = hostRole(host);
  const name = role === "dc" ? "Domain Controllers" : role === "server" ? "Servers" : "Workstations";
  return { groupId: id19(ctx, `${ctx.companyId}:s1:group:${name}`), groupName: name };
}
const osName = (os: string, host: string) => (os === "Win" ? (["server", "dc"].includes(hostRole(host)) ? "Windows Server 2022 Standard" : "Windows 11 Enterprise") : os === "Mac" ? "macOS" : "Linux");
const osRevision = (os: string, host: string) => (os === "Win" ? (["server", "dc"].includes(hostRole(host)) ? "20348" : "26100") : undefined);
const agentVersion = (os: string) => (os === "Win" ? "25.1.3.334" : os === "Mac" ? "25.1.2.6873" : "25.1.2.17");

function common(b: Base, type: string, category: string, meta: string, uniqueKey?: string): Record<string, unknown> {
  const { ctx, ev, f, host, os } = b;
  const t = tenant(ctx);
  const trace = ulid(ctx, Math.floor(f.timeMs / 60_000) * 60_000, `${ctx.companyId}:${host}:trace:${Math.floor(f.timeMs / 60_000)}`);
  const role = hostRole(host);
  return {
    timestamp: iso(f.timeMs), "event.time": f.timeMs, "event.type": type, "event.category": category, "meta.event.name": meta,
    "event.id": `${trace}_${ctx.int(`${ev.id}:s1:seq`, 1, 999)}`, "trace.id": trace, "packet.id": rhex(ctx, `${ctx.companyId}:${host}:packet:${Math.floor(f.timeMs / 60_000)}`, 32).toUpperCase(),
    "i.scheme": "edr", "i.version": "preprocess-lib-1.0", "dataSource.name": "SentinelOne", "dataSource.vendor": "SentinelOne", "dataSource.category": "security",
    "account.id": t.accountId, "account.name": t.accountName, "site.id": t.siteId, "site.name": t.siteName, "group.id": groupOf(ctx, host).groupId,
    "mgmt.id": String(ctx.int(`${ctx.companyId}:s1:mgmt`, 10_000, 99_999)), "mgmt.url": t.mgmtUrl, "mgmt.osRevision": osRevision(os, host),
    "agent.uuid": b.agentUuid, "agent.version": agentVersion(os), "endpoint.name": host,
    "endpoint.os": os === "Win" ? "windows" : os === "Mac" ? "osx" : "linux",
    "endpoint.type": role === "laptop" ? "laptop" : role === "workstation" ? "desktop" : "server",
    "os.name": osName(os, host), "process.unique.key": uniqueKey,
  };
}

/** `root` is undefined when the event does not name the parent (S1 would know; the authored event does not). */
interface Story { id: string; root?: boolean }
/** Storyline of process `p` whose parent is `parent` (see module header). */
function storyline(b: Base, p: EdrProc, parent: EdrProc): Story {
  const { ctx, host, ev } = b;
  const pn = lc(procName(p));
  const par = lc(procName(parent));
  const mk = (s: string) => rhex(ctx, `${ctx.companyId}:${host}:story:${s}`, 16).toUpperCase();
  if (SHELLS.has(pn)) return { id: mk(`shell:${pn}`), root: true };
  const rootish = !par || SHELLS.has(par);
  const root = par ? SHELLS.has(par) : undefined;
  if (ev.incident_id) return { id: mk(`inc:${ev.incident_id}`), root };
  return { id: mk(`root:${rootish ? pn : par}`), root };
}
/** Storyline of a parent whose own parent is unknown: shells and non-incident parents are taken as chain roots. */
function parentStoryline(b: Base, parent: EdrProc): Story {
  const { ctx, host, ev } = b;
  const par = lc(procName(parent));
  const mk = (s: string) => rhex(ctx, `${ctx.companyId}:${host}:story:${s}`, 16).toUpperCase();
  if (SHELLS.has(par)) return { id: mk(`shell:${par}`), root: true };
  if (ev.incident_id) return { id: mk(`inc:${ev.incident_id}`), root: false };
  return { id: mk(`root:${par}`), root: true };
}

const qualifiedUser = (b: Base) => (b.u.user ? (b.os === "Win" ? `${b.u.domain}\\${b.u.user}` : b.u.user) : undefined);

function signedOf(p: EdrProc, path?: string): { signed?: "signed" | "unsigned"; publisher?: string } {
  if (p.signed === false) return { signed: "unsigned" };
  if (path && /^C:\\Windows\\/i.test(path)) return { signed: "signed", publisher: "MICROSOFT WINDOWS" };
  if (path && /\\Microsoft Office\\/i.test(path)) return { signed: "signed", publisher: "MICROSOFT CORPORATION" };
  if (p.signed === true) return { signed: "signed" };
  return {};
}

/** Flat `${prefix}*` keys for one process. `self` adds the image/identity detail S1 records for the event's main process. */
function procKeys(b: Base, prefix: string, p: EdrProc, story: Story, opts: { self: boolean; fallbackCmd?: boolean; startMs?: number }): Record<string, unknown> {
  const { ctx, host, os, u } = b;
  const name = procName(p);
  if (!name) return {};
  const pathRaw = imagePath(p);
  const path = pathRaw ? drivePath(pathRaw) : undefined;
  const sig = signedOf(p, path);
  const cmd = p.cmdline ?? (opts.fallbackCmd ? (path ? (path.includes(" ") ? `"${path}"` : path) : name) : undefined);
  const win = os === "Win";
  const k = (s: string) => `${prefix}${s}`;
  return {
    [k("name")]: name, [k("displayName")]: DISPLAY[lc(name)], [k("pid")]: pidOf(ctx, host, p), [k("uid")]: uidOf(ctx, procSeed(ctx, host, p)),
    [k("cmdline")]: cmd, [k("image.path")]: path,
    [k("image.sha256")]: p.sha256, [k("image.md5")]: p.md5,
    [k("image.binaryIsExecutable")]: opts.self && /\.(exe|com|scr)$/i.test(name) ? true : undefined,
    [k("user")]: opts.self || prefix.includes("parent") || prefix === "src.process." ? qualifiedUser(b) : undefined,
    [k("integrityLevel")]: win && opts.self ? (INTEGRITY[lc(p.integrity)] ?? (u.system ? "SYSTEM" : "MEDIUM")) : undefined,
    [k("sessionId")]: win && opts.self ? (u.system ? 0 : 1) : undefined,
    [k("startTime")]: opts.startMs,
    [k("storyline.id")]: story.id, [k("isStorylineRoot")]: story.root,
    [k("signedStatus")]: sig.signed, [k("verifiedStatus")]: sig.signed ? (sig.signed === "signed" ? "verified" : "unverified") : undefined,
    [k("publisher")]: sig.publisher,
    [k("subsystem")]: win && opts.self ? "SYS_WIN32" : undefined,
  };
}

/** The acting process (src.process.*) and its parent (src.process.parent.*), as on DNS / IP / file events. */
function actorKeys(b: Base): Record<string, unknown> {
  const { f } = b;
  if (!procName(f.proc)) return {};
  const st = storyline(b, f.proc, f.parent);
  return {
    ...procKeys(b, "src.process.", f.proc, st, { self: true }),
    ...(procName(f.parent) ? procKeys(b, "src.process.parent.", f.parent, procName(f.parent) && !SHELLS.has(lc(procName(f.parent))) && !st.root ? { id: st.id, root: false } : parentStoryline(b, f.parent), { self: false }) : {}),
  };
}
const actorUid = (b: Base) => (procName(b.f.proc) ? uidOf(b.ctx, procSeed(b.ctx, b.host, b.f.proc)) : undefined);

// ── renderers ────────────────────────────────────────────────────────────────

function processCreation(b: Base): Record<string, unknown> | null {
  const { ctx, host, f } = b;
  if (!procName(f.proc) && !f.proc.cmdline) return null;
  const p: EdrProc = procName(f.proc) ? f.proc : { ...f.proc, name: baseName(f.proc.cmdline!.split(/\s/)[0].replace(/"/g, "")) };
  const st = storyline(b, p, f.parent);
  const parentKnown = !!procName(f.parent);
  const pst = parentKnown ? (st.root ? parentStoryline(b, f.parent) : { id: st.id, root: false }) : st;
  return {
    ...common(b, "Process Creation", "process", "PROCESSCREATION", uidOf(ctx, procSeed(ctx, host, p))),
    ...(parentKnown ? procKeys(b, "src.process.", f.parent, pst, { self: false }) : {}),
    ...procKeys(b, "tgt.process.", p, st, { self: true, fallbackCmd: true, startMs: f.timeMs }),
    ...(b.os === "Win" ? { "tgt.process.isNative64Bit": false, "tgt.process.isRedirectCmdProcessor": false } : {}),
  };
}

const QTYPE: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33 };

function dns(b: Base, ev: TelemetryEvent): { type: string; rec: Record<string, unknown> } | null {
  const { ctx, f, host, os } = b;
  const q = f.dns.query ?? f.net.domain;
  if (!q) return null;
  const rcode = lc(ev.dns?.rcode);
  const unresolved = rcode === "nxdomain" || rcode === "servfail";
  const type = unresolved ? "DNS Unresolved" : "DNS Resolved";
  const resp = !unresolved && f.dns.response ? `type: ${QTYPE[(f.dns.type ?? "A").toUpperCase()] ?? 1} ${f.dns.response.split(/[;,\s]+/).filter(Boolean).join(";")};` : undefined;
  const dnscache: EdrProc = { name: "svchost.exe", path: "C:\\Windows\\System32\\svchost.exe", pid: ctx.int(`${ctx.companyId}:${host}:dnscache`, 300, 700) * 4 };
  return {
    type,
    rec: {
      ...common(b, type, "dns", "DNS", actorUid(b)), "event.dns.request": q, "event.dns.response": resp, ...actorKeys(b),
      ...(os === "Win" ? {
        "osSrc.process.name": "svchost.exe", "osSrc.process.pid": dnscache.pid, "osSrc.process.uid": uidOf(ctx, procSeed(ctx, host, dnscache)),
        "osSrc.process.cmdline": "C:\\Windows\\system32\\svchost.exe -k NetworkService -p -s Dnscache", "osSrc.process.image.path": dnscache.path,
        "osSrc.process.user": "NT AUTHORITY\\NETWORK SERVICE", "osSrc.process.integrityLevel": "SYSTEM", "osSrc.process.isStorylineRoot": true,
      } : {}),
    },
  };
}

function ipConnect(b: Base, ev: TelemetryEvent): Record<string, unknown> | null {
  const { ctx, f } = b;
  const n = netFacts(f, ev);
  if (!n.remoteIp || !isIPv4(n.remoteIp)) return null;
  const local = n.localIp && isIPv4(n.localIp) ? n.localIp : b.hostIp;
  const localPort = n.localPort ?? ctx.int(`${ev.id}:s1:sport`, 49152, 65535);
  const remotePort = n.remotePort ?? ctx.int(`${ev.id}:s1:rport`, 49152, 65535);
  const svcPort = n.inbound ? localPort : remotePort;
  const proto = n.protocol === "udp" ? "udp" : svcPort === 443 ? "https" : svcPort === 80 ? "http" : "tcp";
  const [src, sport, dst, dport] = n.inbound ? [n.remoteIp, remotePort, local, localPort] : [local, localPort, n.remoteIp, remotePort];
  return {
    // meta.event.name: "TCPV4" is card-confirmed; "UDPV4" for UDP sockets is UNVERIFIED.
    ...common(b, "IP Connect", "ip", n.protocol === "udp" ? "UDPV4" : "TCPV4", actorUid(b)),
    "src.ip.address": src, "src.port.number": sport, "dst.ip.address": dst, "dst.port.number": dport,
    "event.network.direction": n.inbound ? "INCOMING" : "OUTGOING", "event.network.connectionStatus": "SUCCESS",
    "event.network.protocolName": proto, "event.repetitionCount": 1, ...actorKeys(b),
  };
}

const PE_EXT = new Set(["exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "com"]);
function file(b: Base, ev: TelemetryEvent): { type: string; rec: Record<string, unknown> } | null {
  const { ctx, f, host } = b;
  const raw = fixPath(f.file.path);
  if (!raw) return null;
  const path = drivePath(raw);
  const type = ev.event_type === "file_delete" ? "File Deletion" : ev.event_type === "file_modify" ? "File Modification" : "File Creation";
  const meta = type === "File Deletion" ? "FILEDELETION" : type === "File Modification" ? "FILEMODIFICATION" : "FILECREATION";
  const ext = (f.file.extension ?? (/\.([A-Za-z0-9]+)$/.exec(path)?.[1] ?? "")).replace(/^\./, "").toLowerCase();
  const exe = PE_EXT.has(ext);
  const fileSigned = (ev.raw?.["file.signed"] ?? ev.raw?.["file.signature.status"]) as unknown;
  const isSigned = fileSigned === undefined ? undefined : /unsigned|false|not/i.test(String(fileSigned)) ? "unsigned" : "signed";
  return {
    type,
    rec: {
      ...common(b, type, "file", meta, actorUid(b)),
      "tgt.file.path": path, "tgt.file.extension": ext || undefined, "tgt.file.size": f.file.size,
      "tgt.file.type": exe ? "PE" : "UNKNOWN", "tgt.file.isExecutable": exe, "tgt.file.location": "Local",
      "tgt.file.creationTime": type === "File Creation" ? f.timeMs : undefined, "tgt.file.modificationTime": type === "File Deletion" ? undefined : f.timeMs,
      "tgt.file.id": rhex(ctx, `${ctx.companyId}:${host}:fid:${path.toLowerCase()}`, 20).toUpperCase(),
      // Hashes are usually on Modification/Scan events (card §3c, UNVERIFIED on Creation) — kept when authored.
      "tgt.file.sha256": type === "File Deletion" ? undefined : f.file.sha256, "tgt.file.isSigned": isSigned,
      ...actorKeys(b),
    },
  };
}

// ── threats ──────────────────────────────────────────────────────────────────

const S1_CATEGORY: Record<string, string> = {
  "credential access": "InfoStealer", "defense evasion": "Evasion", persistence: "Persistence", "privilege escalation": "Exploitation",
  execution: "General", discovery: "Reconnaissance", "lateral movement": "PostExploitation", collection: "InfoStealer",
  exfiltration: "InfoStealer", "command and control": "PostExploitation", impact: "Ransomware", "initial access": "Exploitation",
};
const TACTIC_BY_TECH: [RegExp, string][] = [
  [/^T1003|^T1555|^T1552|^T1558|^T1110/, "Credential Access"], [/^T1486|^T1490|^T1496|^T1485/, "Impact"], [/^T1547|^T1053|^T1543|^T1546/, "Persistence"],
  [/^T1027|^T1070|^T1562|^T1218|^T1036|^T1055/, "Defense Evasion"], [/^T1059|^T1204|^T1203/, "Execution"], [/^T1021|^T1570/, "Lateral Movement"],
  [/^T1071|^T1105|^T1219|^T1572|^T1090/, "Command and Control"], [/^T1048|^T1041|^T1567/, "Exfiltration"], [/^T1115|^T1056|^T1113|^T1005/, "Collection"],
  [/^T1566|^T1195|^T1190/, "Initial Access"], [/^T1082|^T1087|^T1018|^T1046/, "Discovery"],
];
const EXT_TYPE: [RegExp, string][] = [[/^(exe|dll|sys|scr|com|msi)$/, "Executable"], [/^(ps1|vbs|js|jse|bat|cmd|hta|wsf|sh|py)$/, "Script"],
  [/^(docx?|docm|xlsx?|xlsm|pptx?|pdf)$/, "Document"], [/^(zip|rar|7z|iso|img)$/, "Archive"]];

function threat(b: Base, ev: TelemetryEvent): Record<string, unknown> {
  const { ctx, f, host, os, u } = b;
  const d = f.detection!;
  const r = ev.raw ?? {};
  const t = tenant(ctx);
  const g = groupOf(ctx, host);
  const fileFirst = !!f.file.path && (d.action === "quarantined" || !procName(f.proc));
  const trig: EdrProc = fileFirst ? { name: f.file.name ?? baseName(fixPath(f.file.path)), path: fixPath(f.file.path), sha256: f.file.sha256 ?? f.proc.sha256, md5: f.file.md5 } : f.proc;
  // threatName is the file the threat is about — a placeholder detection name never stands in.
  const trigName = procName(trig) ?? (foreignDetectionName(d.name) ? baseName(fixPath(f.file.path ?? f.proc.path)) : d.name) ?? "unknown";
  const trigPath = imagePath(trig);
  const st = procName(trig) ? storyline(b, trig, fileFirst ? f.proc : f.parent) : storyline(b, { name: `alert:${f.eventId}` }, {});
  const threatId = id19(ctx, `${ev.id}:s1:threat`);
  const tech = d.techniqueId?.split(",")[0]?.trim();
  const tactic = d.tactic ?? (tech ? TACTIC_BY_TECH.find(([re]) => re.test(tech))?.[1] : undefined);
  const sev = lc(d.severity);
  const malicious = String(r["s1.threat.confidenceLevel"] ?? (sev === "critical" || sev === "high" ? "malicious" : "suspicious"));
  const mitigated = d.action !== "detected";
  const classification = String(r["s1.threat.classification"] ?? r["s1.detection.classification"] ??
    (/^T1486/.test(tech ?? "") ? "Ransomware" : /^T1003|^T1555/.test(tech ?? "") ? "Infostealer" : /^T1219/.test(tech ?? "") ? "PUA" : fileFirst ? "Malware" : "Generic.Heuristic"));
  const behavioral = !fileFirst && !!procName(f.proc);
  const classificationSource = String(r["s1.detection.classification_source"] ?? (behavioral ? "Behavioral" : "Cloud"));
  const identified = f.timeMs + ctx.int(`${ev.id}:s1:ident`, 200, 2500);
  const created = identified + ctx.int(`${ev.id}:s1:created`, 100, 900);
  const mitEnd = created + ctx.int(`${ev.id}:s1:mit`, 150, 600);
  const ext = /\.([A-Za-z0-9]+)$/.exec(trigName)?.[1]?.toLowerCase() ?? "";
  const cmd = trig.cmdline ?? (fileFirst ? f.proc.cmdline : undefined);
  const args = cmd ? cmd.replace(/^\s*("[^"]*"|\S+)\s*/, "") : undefined;
  const actions = d.action === "quarantined" ? ["kill", "quarantine"] : d.action === "killed" || d.action === "blocked" ? ["kill"] : [];
  const mitigationMode = !mitigated && (sev === "critical" || sev === "high") && malicious === "malicious" ? "detect" : "protect";
  const winPath = trigPath ? (os === "Win" ? ntDevicePath(trigPath) : trigPath) : undefined;
  const signed = trig.signed ?? (r["file.signed"] !== undefined ? !/unsigned|false|not/i.test(String(r["file.signed"])) : undefined);
  const engine = behavioral ? { key: "executables", title: "Behavioral AI" } : { key: "sentinelone_cloud", title: "SentinelOne Cloud" };
  return {
    id: threatId,
    agentDetectionInfo: {
      accountId: t.accountId, accountName: t.accountName, agentDetectionState: null, agentDomain: os === "Win" ? ctx.netbios : null,
      agentIpV4: b.hostIp, agentLastLoggedInUpn: u.system ? null : u.upn ?? null, agentLastLoggedInUserName: u.system ? null : u.user ?? null,
      agentMitigationMode: mitigationMode, agentOsName: osName(os, host), agentOsRevision: osRevision(os, host) ?? null,
      agentUuid: b.agentUuid, agentVersion: agentVersion(os), externalIp: egressIp(ctx), groupId: g.groupId, groupName: g.groupName,
      siteId: t.siteId, siteName: t.siteName,
    },
    agentRealtimeInfo: {
      accountId: t.accountId, accountName: t.accountName, activeThreats: mitigated ? 0 : 1, agentComputerName: host, agentDecommissionedAt: null,
      agentDomain: os === "Win" ? ctx.netbios : null, agentId: id19(ctx, `${ctx.companyId}:${host}:s1:agentId`), agentInfected: !mitigated,
      agentIsActive: true, agentIsDecommissioned: false,
      agentMachineType: hostRole(host) === "laptop" ? "laptop" : hostRole(host) === "workstation" ? "desktop" : "server",
      agentMitigationMode: mitigationMode, agentNetworkStatus: "connected", agentOsName: osName(os, host), agentOsRevision: osRevision(os, host) ?? null,
      agentOsType: os === "Win" ? "windows" : os === "Mac" ? "macos" : "linux", agentUuid: b.agentUuid, agentVersion: agentVersion(os),
      groupId: g.groupId, groupName: g.groupName,
      networkInterfaces: [{ id: id19(ctx, `${ctx.companyId}:${host}:s1:nic`), inet: [b.hostIp],
        inet6: [`fe80::${rhex(ctx, `${ctx.companyId}:${host}:ip6`, 16).replace(/^(....)(....)(....)(....)$/, "$1:$2:$3:$4").replace(/(^|:)0+(?=[0-9a-f])/g, "$1")}`], name: os === "Win" ? "Ethernet" : "eth0",
        physical: rhex(ctx, `${ctx.companyId}:${host}:mac`, 12).toUpperCase().replace(/(..)(?!$)/g, "$1:") }],
      operationalState: "na", rebootRequired: false, siteId: t.siteId, siteName: t.siteName, userActionsNeeded: [],
    },
    containerInfo: { id: null, image: null, labels: null, name: null },
    indicators: [{
      category: S1_CATEGORY[lc(tactic)] ?? "General",
      // SentinelOne's own indicator wording (engine + behaviour) — never a Defender threat
      // name or a scenario placeholder.
      description: !foreignDetectionName(d.name) && d.name !== trigName ? d.name
        : behavioral ? `${techniqueName(tech, d.technique) ?? "Suspicious behavior"} detected by the Behavioral AI engine`
        : "Detected by the Static AI engine — file classified as malicious",
      ids: [ctx.int(`s1:indicator:${d.name ?? tech ?? "generic"}`, 10, 999)],
      tactics: tech ? [{ name: tactic ?? "Execution", source: "MITRE", techniques: [{ link: `https://attack.mitre.org/techniques/${tech.replace(".", "/")}/`, name: tech }] }] : [],
    }],
    kubernetesInfo: { cluster: null, controllerKind: null, controllerLabels: null, controllerName: null, namespace: null, namespaceLabels: null, node: null, pod: null, podLabels: null },
    mitigationStatus: actions.map((a, i) => ({
      action: a, actionsCounters: { failed: 0, notFound: 0, pendingReboot: 0, success: 1, total: 1 }, agentSupportsReport: true, groupNotFound: false,
      lastUpdate: isoMicro(ctx, mitEnd + 20 + i * 300, `${ev.id}:s1:lu${i}`), latestReport: a === "quarantine" ? "/threats/mitigation-report" : null,
      mitigationEndedAt: isoMicro(ctx, mitEnd + i * 300, `${ev.id}:s1:me${i}`), mitigationStartedAt: isoMicro(ctx, created + 50 + i * 300, `${ev.id}:s1:ms${i}`), status: "success",
    })),
    threatInfo: {
      analystVerdict: "undefined", analystVerdictDescription: "Undefined", automaticallyResolved: false, browserType: null, certificateId: "",
      classification, classificationSource, cloudFilesHashVerdict: trig.sha256 && malicious === "malicious" ? "black" : null,
      collectionId: id19(ctx, `${ev.id}:s1:collection`), confidenceLevel: malicious, createdAt: isoMicro(ctx, created, `${ev.id}:s1:ca`),
      detectionEngines: [engine], detectionType: behavioral ? "dynamic" : "static", engines: [engine.title],
      externalTicketExists: false, externalTicketId: null, failedActions: false,
      fileExtension: ext ? ext.toUpperCase() : null, fileExtensionType: EXT_TYPE.find(([re]) => re.test(ext))?.[1] ?? "Unknown",
      filePath: winPath ?? null, fileSize: fileFirst ? f.file.size ?? null : null,
      fileVerificationType: signed === false ? "NotSigned" : signed === true ? "SignedVerified" : null,
      identifiedAt: isoMicro(ctx, identified, `${ev.id}:s1:ia`), incidentStatus: "unresolved", incidentStatusDescription: "Unresolved",
      initiatedBy: "agent_policy", initiatedByDescription: "Agent Policy", initiatingUserId: null, initiatingUsername: null,
      isFileless: !trigPath && !!cmd, isValidCertificate: signed === true, maliciousProcessArguments: args ?? null, md5: trig.md5 ?? null,
      mitigatedPreemptively: d.action === "blocked", mitigationStatus: mitigated ? "mitigated" : "not_mitigated",
      mitigationStatusDescription: mitigated ? "Mitigated" : "Not mitigated",
      originatorProcess: (fileFirst ? procName(f.proc) : procName(f.parent)) ?? null, pendingActions: false,
      processUser: qualifiedUser(b) ?? null, publisherName: "", reachedEventsLimit: false, rebootRequired: false,
      sha1: null, sha256: trig.sha256 ?? null, storyline: st.id, threatId, threatName: trigName,
      updatedAt: isoMicro(ctx, actions.length ? mitEnd + 400 : created, `${ev.id}:s1:ua`),
    },
    whiteningOptions: trig.sha256 ? ["hash", "path"] : ["path"],
  };
}

const prune = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = edrFacts(ev);
  if (f.kind === "unsupported" || !f.host) return null;
  const host = f.host;
  const os = osOf(f, ev);
  const b: Base = { ctx, ev, f, host, os, hostIp: hostIpOf(ctx, f, host), agentUuid: rhex(ctx, `${ctx.companyId}:${host}:s1agent`, 32), u: userOf(ctx, f, os) };
  const timeMs = Date.parse(ev.ts);
  const out = (kind: string, rec: Record<string, unknown> | null): NativeLog | null =>
    rec ? { sourceId: "sentinelone", kind, format: "json", record: kind === "threat" ? rec : prune(rec), timeMs } : null;
  switch (f.kind) {
    case "process": return out("Process Creation", processCreation(b));
    case "network": return out("IP Connect", ipConnect(b, ev));
    case "dns": { const r = dns(b, ev); return r ? out(r.type, r.rec) : null; }
    case "file": { const r = file(b, ev); return r ? out(r.type, r.rec) : null; }
    case "detection": return out("threat", threat(b, ev));
    // Registry / logon: the card names the event types but documents no keys — not rendered.
    default: return null;
  }
}

// ── use cases ────────────────────────────────────────────────────────────────

const SCRIPTS = SCRIPT_HOSTS.filter(s => s !== "cmd.exe");
const ENCODED = "\\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\\s";

const useCases: UseCase[] = [
  {
    id: "sentinelone.office_spawns_encoded_script", title: "Office application spawns a script host with an encoded command", sourceId: "sentinelone",
    kinds: ["Process Creation"], severity: "high", mitre: ["T1566.001", "T1204.002", "T1059.001", "T1027"],
    description: "In a Process Creation event src.process.* is the creator and tgt.process.* the new process. An Office creator with a PowerShell / wscript / mshta target whose command line carries an encoded-command switch is the macro hand-off. Pivot on tgt.process.storyline.id in Event Search to see the whole chain (DNS, connections, dropped files) and on the Threat with the same storyline.",
    logic: "S1QL: event.type = 'Process Creation' AND src.process.name in:anycase ('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE') AND tgt.process.name in:anycase ('powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe') AND tgt.process.cmdline RegExp '\\s-(e|enc|encodedcommand)\\s'",
    match: { all: [{ field: "src.process.name", op: "in", value: OFFICE }, { field: "tgt.process.name", op: "in", value: SCRIPTS }, { field: "tgt.process.cmdline", op: "regex", value: ENCODED }] },
    falsePositives: ["Signed internal add-ins that shell out to PowerShell (rarely encoded)"],
  },
  {
    id: "sentinelone.script_host_encoded_command", title: "Script host launched with an encoded command line", sourceId: "sentinelone",
    kinds: ["Process Creation"], severity: "medium", mitre: ["T1059.001", "T1027"],
    description: "Encoded PowerShell from any creator. Decode the argument, check the creator (src.process.name) and whether the same storyline then made network connections.",
    logic: "S1QL: event.type = 'Process Creation' AND tgt.process.name in:anycase ('powershell.exe','pwsh.exe') AND tgt.process.cmdline RegExp '\\s-(e|enc|encodedcommand)\\s'",
    match: { all: [{ field: "tgt.process.cmdline", op: "regex", value: `(powershell|pwsh)(\\.exe)?"?\\s` }, { field: "tgt.process.cmdline", op: "regex", value: ENCODED }] },
    falsePositives: ["SCCM / Intune / RMM agents running encoded maintenance scripts"],
  },
  {
    id: "sentinelone.lolbin_external_connection", title: "LOLBin makes an outbound connection to an external address", sourceId: "sentinelone",
    kinds: ["IP Connect"], severity: "high", mitre: ["T1105", "T1218", "T1197"],
    description: "certutil / bitsadmin / rundll32 / regsvr32 / mshta / msiexec / curl as src.process.name of an OUTGOING IP Connect to a non-RFC1918 dst.ip.address is a download or proxy-execution step. The storyline shows what started it.",
    logic: "S1QL: event.type = 'IP Connect' AND event.network.direction = 'OUTGOING' AND src.process.name in:anycase ('certutil.exe','bitsadmin.exe','rundll32.exe','regsvr32.exe','mshta.exe','msiexec.exe','curl.exe') AND NOT dst.ip.address in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')",
    match: { all: [{ field: "event.network.direction", op: "eq", value: "OUTGOING" }, { field: "src.process.name", op: "in", value: LOLBINS }, { field: "dst.ip.address", op: "notCidr", value: PRIVATE_CIDRS }] },
    falsePositives: ["msiexec reaching a vendor CDN during a sanctioned install", "curl.exe in developer tooling"],
  },
  {
    id: "sentinelone.script_host_external_connection", title: "Script host connects to an external address", sourceId: "sentinelone",
    kinds: ["IP Connect"], severity: "high", mitre: ["T1059.001", "T1071.001"],
    description: "PowerShell / wscript / cscript / mshta opening an OUTGOING connection to the internet is how stagers fetch the next stage. The src.process.netConnOutCount counter and a rare dst.ip.address across agents make it stand out.",
    logic: "S1QL: event.type = 'IP Connect' AND event.network.direction = 'OUTGOING' AND src.process.name in:anycase ('powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe') AND NOT dst.ip.address in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16') | group count = estimate_distinct(agent.uuid) by dst.ip.address | filter count < 3",
    match: { all: [{ field: "event.network.direction", op: "eq", value: "OUTGOING" }, { field: "src.process.name", op: "in", value: SCRIPTS }, { field: "dst.ip.address", op: "notCidr", value: PRIVATE_CIDRS }] },
    falsePositives: ["Admin scripts calling public APIs (package galleries, cloud CLIs)"],
  },
  {
    id: "sentinelone.written_then_executed", title: "Executable written to a user-writable folder and then executed", sourceId: "sentinelone",
    kinds: ["File Creation", "Process Creation"], severity: "high", mitre: ["T1105", "T1204.002"],
    description: "On one agent, a File Creation of an executable (tgt.file.isExecutable) under Downloads / AppData / Temp / ProgramData / Public is followed within the hour by a Process Creation whose tgt.process.image.path is in such a folder. Confirm it is the same file: tgt.file.path = tgt.process.image.path (and the hashes).",
    logic: "PowerQuery: (event.type = 'File Creation' AND tgt.file.isExecutable = true AND tgt.file.path RegExp '\\\\(Downloads|AppData|Temp|ProgramData|Public)\\\\') OR (event.type = 'Process Creation' AND tgt.process.image.path RegExp '\\\\(Downloads|AppData|Temp|ProgramData|Public)\\\\') | group types = estimate_distinct(event.type) by agent.uuid | filter types = 2",
    match: { any: [
      { all: [{ field: "event.type", op: "eq", value: "File Creation" }, { field: "tgt.file.isExecutable", op: "eq", value: true }, { field: "tgt.file.path", op: "regex", value: USER_WRITABLE_RE }] },
      { all: [{ field: "event.type", op: "eq", value: "Process Creation" }, { field: "tgt.process.image.path", op: "regex", value: USER_WRITABLE_RE }] },
    ] },
    threshold: { groupBy: ["agent.uuid"], count: 2, windowSec: 3600, distinct: "event.type" },
    falsePositives: ["Users installing software from Downloads", "Self-updating apps under AppData (Teams, Zoom)"],
  },
  {
    id: "sentinelone.unsigned_exec_downloads_public", title: "Unsigned binary executed from Downloads or C:\\Users\\Public", sourceId: "sentinelone",
    kinds: ["Process Creation"], severity: "medium", mitre: ["T1204.002", "T1036"],
    description: "tgt.process.signedStatus = unsigned for an image in the browser Downloads folder or the world-writable Public profile — typical of phishing payloads and cracked installers.",
    logic: "S1QL: event.type = 'Process Creation' AND tgt.process.signedStatus = 'unsigned' AND tgt.process.image.path RegExp '\\\\Users\\\\([^\\\\]+\\\\Downloads|Public)\\\\'",
    match: { all: [{ field: "tgt.process.signedStatus", op: "eq", value: "unsigned" }, { field: "tgt.process.image.path", op: "regex", value: DOWNLOADS_PUBLIC_RE }] },
    falsePositives: ["Portable / unsigned internal tools distributed by IT"],
  },
  {
    id: "sentinelone.credential_access_threat", title: "Credential-access threat (LSASS / SAM / browser credential store)", sourceId: "sentinelone",
    kinds: ["threat"], severity: "critical", mitre: ["T1003", "T1003.001", "T1555.003"],
    description: "A Threat whose indicators map to T1003 (OS credential dumping, incl. LSASS memory) or T1555 (credential stores), or that S1 classifies as Infostealer. Treat every account with a session on agentRealtimeInfo.agentComputerName as exposed — even when mitigationStatus says the process was killed.",
    logic: "Threats API: GET /web/api/v2.1/threats?classifications=Infostealer  — or in the console: Incidents → Threats, filter Indicators: MITRE T1003 / T1555",
    match: { any: [{ field: "indicators[].tactics[].techniques[].name", op: "regex", value: "^T(1003|1555)" }, { field: "threatInfo.classification", op: "eq", value: "Infostealer" }] },
    falsePositives: ["Approved red-team / pentest windows", "Password managers / backup agents reading browser stores"],
  },
  {
    id: "sentinelone.malicious_threat_not_mitigated", title: "Malicious threat that was not mitigated", sourceId: "sentinelone",
    kinds: ["threat"], severity: "high", mitre: [],
    description: "threatInfo.confidenceLevel = malicious with threatInfo.mitigationStatus = not_mitigated: the agent detected but did not kill or quarantine — usually because the agent policy is in Detect mode (agentRealtimeInfo.agentMitigationMode = detect). The threat is still active: mitigate (Kill / Quarantine / Remediate / Rollback) or Disconnect from network.",
    logic: "Threats API: GET /web/api/v2.1/threats?confidenceLevels=malicious&mitigationStatuses=not_mitigated",
    match: { all: [{ field: "threatInfo.confidenceLevel", op: "eq", value: "malicious" }, { field: "threatInfo.mitigationStatus", op: "in", value: ["not_mitigated", "active"] }] },
    falsePositives: ["Groups intentionally kept in Detect mode during a pilot"],
  },
  {
    id: "sentinelone.inbound_rdp_from_internet", title: "Inbound RDP from an internet address", sourceId: "sentinelone",
    kinds: ["IP Connect"], severity: "high", mitre: ["T1021.001", "T1133"],
    description: "An INCOMING IP Connect on dst.port.number 3389 whose src.ip.address is not RFC1918: the endpoint accepts RDP from outside (or through a VPN pool that should not reach it). Correlate with the VPN / identity logs for the user behind that address.",
    logic: "S1QL: event.type = 'IP Connect' AND event.network.direction = 'INCOMING' AND dst.port.number = 3389 AND NOT src.ip.address in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')",
    match: { all: [{ field: "event.network.direction", op: "eq", value: "INCOMING" }, { field: "dst.port.number", op: "eq", value: 3389 }, { field: "src.ip.address", op: "notCidr", value: PRIVATE_CIDRS }] },
    falsePositives: ["Remote-access gateways that NAT users to a public range"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "sentinelone", category: "edr", card: "edr-sentinelone.md", product: "SentinelOne Singularity",
    format: "json", vendorMatch: ["sentinelone", "sentinel one"], telemetrySources: ["edr", "av"], kinds,
  },
  fromTelemetry,
  useCases,
};
