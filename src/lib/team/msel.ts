/**
 * The scripted curveballs of a team exercise (MSEL) and the logs behind them, in rotation
 * (owner, 2026-11-07: "no repetition"). Before, every session carried the same four inject texts,
 * the same Marketing-analytics decoy (a pool of three vendors, two fixed upload sizes) and the
 * same twist (rundll32 loading msupd###.dll). Now each session draws:
 *  - a DECOY of one of several kinds (analytics export, DR replication, data-room upload, auditor
 *    evidence upload, agency media hand-off, log backlog flush), each with its own reporter, host,
 *    destination, approval and believable volume against the host's own earlier transfer;
 *  - a TWIST of one of several kinds (second implant, new persistence, credential reuse, new remote
 *    session, new account, the spray resuming), each backed by the logs a real product writes for it;
 *  - one of several texts for every inject.
 * 2026-11-08 (Sdema review K4 / K8): a twist follows from what its story achieved (twistGround): an
 * implant, persistence, a backdoor account or a remote session only where code ran or an account logged
 * on, credential reuse only after a sign-in worked, and a story of failures only gets the spray resuming
 * from a new exit node. Implants live in a real user's profile or in machine-wide folders (never
 * C:\Users\Public\AppData), a server nobody works at has no Explorer parent, a loaded DLL is written
 * first (DeviceFileEvents), and no raw pid copy contradicts the session's one pid per process. The
 * analytics decoy uploads megabytes, not gigabytes.
 * The history ranking (variety.ts) keeps an organization from seeing the same kinds and texts in
 * consecutive exercises. Attacker infrastructure is fictional (documentation addresses, made-up
 * domains); partner endpoints are vendor names or fictional firms.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { COMPANY_ASSETS, type CompanyAssets } from "@/lib/sim/companyProfilesMeta";
import { mdeProcess, mdeFile } from "@/lib/sim/emitters/mde";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import type { WafRuleKey } from "@/lib/logs/native/sources/_web-common";
import { winLogon, winFailedLogon, winAccountCreate, winGroupMemberAdd, domainSidFor } from "@/lib/sim/emitters/windowsSecurity";
import type { Stack } from "@/lib/logs/native/stack";
import type { TicketSpec } from "./fpAlerts";
import { docIp, fakeC2Domain, intIn, pickOf, rankByHistory } from "./variety";

// ── Firewall / EDR record shapes (shared with the timeline) ─────────────────────
export type FwFlavour = "pan" | "forti" | "checkpoint" | "cisco";
export function fwFlavour(firewall: string): { flavour: FwFlavour; vendor: string } {
  const f = firewall.toLowerCase();
  if (f.includes("forti")) return { flavour: "forti", vendor: "Fortinet FortiGate" };
  if (f.includes("check point") || f.includes("checkpoint")) return { flavour: "checkpoint", vendor: "Check Point NGFW" };
  if (f.includes("cisco")) return { flavour: "cisco", vendor: "Cisco Firepower" };
  return { flavour: "pan", vendor: "Palo Alto Networks PAN-OS" };
}

export interface FwConn { srcIp: string; dstIp: string; domain: string; url: string; category: string; app: string; bytesOut: number; bytesIn: number; sessions?: number; port?: string }
export function firewallRaw(flavour: FwFlavour, c: FwConn): Record<string, unknown> {
  const port = c.port ?? "443";
  if (flavour === "forti") return {
    "data.type": "utm", "data.subtype": "webfilter", "data.level": "notice", "data.action": "passthrough",
    "data.srcip": c.srcIp, "data.dstip": c.dstIp, "data.dstport": port, "data.service": port === "443" ? "HTTPS" : `tcp/${port}`,
    "data.hostname": c.domain, "data.url": c.url, "data.catdesc": c.category, "data.app": c.app,
    "data.sentbyte": String(c.bytesOut), "data.rcvdbyte": String(c.bytesIn),
    ...(c.sessions ? { "data.countweb": String(c.sessions) } : {}),
    "firewall.action": "allow", "action_result": "allowed",
  };
  if (flavour === "checkpoint") return {
    "action": "Accept", "layer_name": "Application & URL Filtering", "src": c.srcIp, "dst": c.dstIp,
    "service": port, "service_id": port === "443" ? "https" : `tcp-${port}`, "proto": "6", "resource": c.url, "app_category": c.category,
    "appi_name": c.app, "bytes_out": String(c.bytesOut), "bytes_in": String(c.bytesIn),
    "ProductName": "URL Filtering", "action_result": "allowed",
  };
  if (flavour === "cisco") return {
    "cisco.ftd.action": "Allow", "cisco.ftd.url": c.url, "cisco.ftd.url_category": c.category,
    "cisco.ftd.application": c.app, "source.ip": c.srcIp, "destination.ip": c.dstIp, "destination.port": port,
    "network.bytes_out": String(c.bytesOut), "network.bytes_in": String(c.bytesIn), "action_result": "allowed",
  };
  return {
    "url.domain": c.domain, "url.full": c.url, "pan.url.category": c.category, "pan.app": c.app,
    "pan.action": "allow", "pan.rule": port === "443" ? "ALLOW-WEB-OUT" : "ALLOW-INTERNAL", "source.ip": c.srcIp, "destination.ip": c.dstIp,
    "destination.port": port, "pan.bytes_sent": String(c.bytesOut), "pan.bytes_received": String(c.bytesIn),
    ...(c.sessions ? { "pan.repeatcnt": String(c.sessions) } : {}),
    "event.action": "allow", "action_result": "allowed",
  };
}

export interface ProcCtx { path: string; cmdline: string; parent: string; account?: string }
export function edrConnRaw(edrVendor: string, host: string, proc: string, pid: number, localIp: string, dstIp: string, domain: string, ctx?: ProcCtx, port = "443"): Record<string, unknown> {
  const v = edrVendor.toLowerCase();
  // The process context is the evidence on a LOLBin beacon: rundll32.exe itself is a
  // signed Microsoft binary (its hash looks up clean); the DLL on its command line,
  // launched from a user-writable folder, is what's malicious.
  const neutral = {
    "process.name": proc, "process.pid": String(pid), "destination.ip": dstIp, "destination.port": port, ...(domain ? { "destination.domain": domain } : {}), "source.ip": localIp,
    ...(ctx ? { "process.executable": ctx.path, "process.command_line": ctx.cmdline, "process.parent.name": ctx.parent } : {}),
  };
  if (v.includes("crowdstrike") || v.includes("falcon")) return { "crowdstrike.event_simpleName": "NetworkConnectIP4", "crowdstrike.ComputerName": host, "crowdstrike.RemoteAddressIP4": dstIp, "crowdstrike.RemotePort": port, "crowdstrike.LocalAddressIP4": localIp, ...(ctx ? { "crowdstrike.CommandLine": ctx.cmdline, "crowdstrike.ParentBaseFileName": ctx.parent } : {}), ...neutral };
  if (v.includes("sentinelone")) return { "s1.eventType": "IP Connect", "s1.agent.computerName": host, ...(ctx ? { "s1.src.process.cmdline": ctx.cmdline, "s1.src.process.parent.name": ctx.parent } : {}), ...neutral };
  if (v.includes("sophos")) return { "sophos.event_type": "Network", ...neutral };
  return {
    "ActionType": "ConnectionSuccess", "DeviceName": host.toLowerCase(), "RemoteIP": dstIp, "RemotePort": port, ...(domain ? { "RemoteUrl": domain } : {}), "LocalIP": localIp,
    "InitiatingProcessFileName": proc, "InitiatingProcessId": String(pid),
    ...(ctx ? {
      "InitiatingProcessFolderPath": ctx.path.replace(/\\[^\\]+$/, ""), "InitiatingProcessCommandLine": ctx.cmdline,
      "InitiatingProcessParentFileName": ctx.parent, ...(ctx.account ? { "InitiatingProcessAccountName": ctx.account } : {}),
    } : {}),
    ...neutral,
  };
}

// ── Inject texts ────────────────────────────────────────────────────────────────
export interface InjectText { key: string; text: string; expected_response: string; expected_decision?: "rejected" | "handled"; linked_objective: string }

const TICKETS: InjectText[] = [
  { key: "ticket:vishing_mfa", text: "A user in Finance says someone from 'IT support' phoned asking them to read back an MFA code to 'verify their account'. How should this be handled?",
    expected_response: "Tier-1 answers the help-desk ticket: never read back an MFA code, verify the caller through a known channel, and report it as a social-engineering attempt.", expected_decision: "rejected", linked_objective: "accuracy · help-desk handling" },
  { key: "ticket:ceo_gift_cards", text: "Reception forwards a text that claims to be from the CEO: buy six gift cards for a client event right now and send the codes back by reply. Can they go ahead?",
    expected_response: "Refuse: a gift-card request by text is a classic pretext. Confirm with the CEO through a known number, keep the message, report it as social engineering.", expected_decision: "rejected", linked_objective: "accuracy · help-desk handling" },
  { key: "ticket:supplier_bank_change", text: "Accounts payable got a call from a supplier's 'new finance manager' asking to switch the payment account before Friday's invoice run. The caller is pushing hard. What should they do?",
    expected_response: "Refuse the change on the call: verify through the supplier contact already on file, never through details the caller gives, and report the attempt.", expected_decision: "rejected", linked_objective: "accuracy · help-desk handling" },
  { key: "ticket:exec_reset_by_phone", text: "The service desk has a caller who says they are the CFO's assistant and needs the CFO's MFA reset now, because the CFO is boarding a flight. Should the desk do it?",
    expected_response: "Refuse to reset on that call: the account owner must verify through the documented process (call-back to the number on file, manager approval). Log it as a likely pretext.", expected_decision: "rejected", linked_objective: "accuracy · help-desk handling" },
  { key: "ticket:reported_phish", text: "A user forwarded an email to the SOC mailbox asking if it is safe: a 'shared document' from a partner whose sign-in page looks slightly off. They have not clicked. What next?",
    expected_response: "Handle it: thank the user, analyse the message (sender, link, headers), block the sender and URL if malicious, and search for other recipients.", expected_decision: "handled", linked_objective: "accuracy · help-desk handling" },
  { key: "ticket:usb_found", text: "Facilities found a USB stick labelled 'Salary review' in the car park and handed it to the service desk. Someone wants to plug it in to find the owner. What should the desk do?",
    expected_response: "Handle it safely: do not plug it into any company machine; bag it and pass it to the SOC for analysis on an isolated system, and remind staff of the policy.", expected_decision: "handled", linked_objective: "accuracy · help-desk handling" },
  { key: "ticket:unexpected_prompt", text: "A user reports two sign-in approval prompts on their phone that they did not start. They pressed Deny both times. Anything else they should do?",
    expected_response: "Handle it: the password is likely known to someone else. Reset it, review the account's recent sign-ins, revoke sessions and thank the user for denying.", expected_decision: "handled", linked_objective: "accuracy · help-desk handling" },
];
const ANNOUNCEMENTS: InjectText[] = [
  { key: "ann:log_rationale", text: "Reminder: log every containment decision with its rationale; this incident will be reviewed after the shift.", expected_response: "Informational; decisions should carry a logged rationale.", linked_objective: "documentation" },
  { key: "ann:handover", text: "Shift lead: the next shift takes over in a while. Keep the case notes current so the handover needs no phone call.", expected_response: "Informational; case notes kept current for handover.", linked_objective: "documentation" },
  { key: "ann:evidence", text: "Legal asks that evidence for any confirmed incident is pinned to its case with the source log, not pasted as text.", expected_response: "Informational; evidence pinned from the source log.", linked_objective: "documentation" },
  { key: "ann:status_cadence", text: "The SOC manager wants a short status in the case every time its scope changes, not only at the end.", expected_response: "Informational; scope changes noted as they happen.", linked_objective: "communication" },
];

/** The help-desk ticket and the announcement of a session, least recently used first. */
export function pickInjectTexts(rnd: () => number, seen: Record<string, number>): { ticket: InjectText; announcement: InjectText } {
  return { ticket: rankByHistory(TICKETS, t => t.key, seen, rnd)[0], announcement: rankByHistory(ANNOUNCEMENTS, t => t.key, seen, rnd)[0] };
}
export const INJECT_TEXT_KEYS = [...TICKETS, ...ANNOUNCEMENTS].map(t => t.key);

// ── Decoys ──────────────────────────────────────────────────────────────────────
export interface DecoyCtx {
  assets: CompanyAssets; companyId: string; rnd: () => number;
  fw: { flavour: FwFlavour; vendor: string };
  /** People / hosts already used by the attacks and the benign-positive alerts. */
  usedUsers: Set<string>; usedHosts: Set<string>; ips: Set<string>; baseTs: string;
}
export interface DecoyBuild {
  kind: string;
  inject: InjectText;
  ticket: TicketSpec;
  /** The decoy's firewall rows, each with where it lands relative to the inject: "baseline" well before, "near" around it. */
  rows: { ev: TelemetryEvent; when: "baseline" | "before" | "after" }[];
  host: string; user?: string;
}
interface DecoyKind {
  id: string;
  /** Who reports it and what they see, with {host} {domain} {size} placeholders. */
  texts: string[];
  expected: string;
  person?: RegExp;
  server?: boolean;
  dest: (c: DecoyCtx) => { domain: string; url: string; app: string; category: string; label: string };
  /** Upload sizes (MB): the host's own earlier transfer, then the two that prompt the call. */
  sizes: { baseline: [number, number]; big: [number, number] };
  ticket: (c: DecoyCtx, who: { host: string; user?: string; label: string }) => TicketSpec;
  why: (who: { host: string; user?: string; label: string; domain: string }) => string;
}

const ITSM_N = (p: string, c: DecoyCtx) => `${p}00${intIn(30000, 69999, c.rnd)}`;
const DECOYS: DecoyKind[] = [
  { id: "analytics_export", person: /market|sales|product|growth/i,
    texts: [
      "Marketing's manager messages the SOC: their newly approved product-analytics tool 'looks like data exfil' in the firewall logs, repeated uploads from {host} to {domain}. Is this a real incident?",
      "A Marketing analyst asks the SOC whether they broke something: the firewall dashboard shows {size} leaving {host} for {domain} this afternoon. Should they stop the export?",
    ],
    expected: "Recognise a sanctioned tool: the request is approved, the destination is the vendor's own ingestion endpoint and the host sent the same kind of batch earlier. Do NOT over-escalate. A decoy: discrimination, not detection.",
    dest: c => { const v = pickOf([["api2.amplitude.com", "amplitude", "Amplitude"], ["api-eu.mixpanel.com", "mixpanel", "Mixpanel"], ["heapanalytics.com", "heap-analytics", "Heap"], ["api.segment.io", "segment", "Segment"]] as const, c.rnd);
      return { domain: v[0], url: `https://${v[0]}/batch`, app: v[1], category: "business-and-economy", label: v[2] }; },
    // An analytics SDK posts event batches of a few MB; the burst behind the call is tens of MB (a backfill of the
    // campaign's events), never gigabytes: an approved domain is not "fine at any volume".
    sizes: { baseline: [2, 8], big: [18, 70] },
    ticket: (c, w) => ({ table: "sc_req_item", number: ITSM_N("RITM", c), state: "Closed Complete", short: `Software request: ${w.label} product analytics for Marketing`, requestedFor: w.user, group: "Service Desk" }),
    why: w => `Sanctioned SaaS: ${w.label} is Marketing's approved analytics tool (approved request); the batched uploads go to the vendor's own ingestion endpoint ${w.domain}. Expected traffic, not exfiltration.` },
  { id: "dr_replication", server: true,
    texts: [
      "The network team flags {host}: it has pushed {size} to cloud storage in the last hour and is still going. Is the server being emptied?",
      "Infrastructure on-call asks the SOC to check {host}: an outbound transfer to {domain} is filling the internet link. Do we cut it?",
    ],
    expected: "Recognise the disaster-recovery replication: the standing change covers it, the destination is the company's own storage account / bucket, and the server sends the same stream every night. Do NOT cut it.",
    dest: c => {
      if (c.rnd() < 0.5) { const acct = `asr${pickOf(["cache", "rep", "dr"], c.rnd)}${intIn(1000, 9999, c.rnd)}`; return { domain: `${acct}.blob.core.windows.net`, url: `https://${acct}.blob.core.windows.net/`, app: "ms-azure-storage", category: "online-storage-and-backup", label: "Azure Site Recovery" }; }
      const region = pickOf(["eu-central-2", "eu-west-1", "us-east-1"], c.rnd); return { domain: `s3.${region}.wasabisys.com`, url: `https://s3.${region}.wasabisys.com/dr-${c.assets.domain.split(".")[0]}`, app: "amazon-aws-s3", category: "online-storage-and-backup", label: "Veeam offsite copy" };
    },
    sizes: { baseline: [900, 3000], big: [4000, 14000] },
    ticket: (c, w) => ({ table: "change_request", number: ITSM_N("CHG", c), state: "Implement", short: `${w.label} for ${w.host} (standard change)`, ci: w.host, group: "Infrastructure Operations", window: [-intIn(240, 600, c.rnd), intIn(240, 600, c.rnd)] }),
    why: w => `${w.label} of ${w.host} to the company's own storage at ${w.domain}, under the standing change; the volume matches the server's nightly change rate. Not exfiltration.` },
  { id: "data_room", person: /financ|account|controller|legal|compliance|operations|manager/i,
    texts: [
      "Legal's office asks the SOC: {host} is uploading hundreds of documents to an outside site, {domain}. The person says it is for a deal. Can that be right?",
      "A finance manager is worried: {size} of contracts went from {host} to {domain} and they have never heard of it. Is someone stealing the files?",
    ],
    expected: "Recognise the approved virtual data room: the request is approved by Legal, the destination is the data-room provider and the uploader is on the deal team. Not an incident.",
    dest: c => { const v = pickOf([["upload.keystonedealrooms.com", "Keystone Deal Rooms"], ["files.harbourvdr.com", "Harbour VDR"]] as const, c.rnd);
      return { domain: v[0], url: `https://${v[0]}/api/v2/upload`, app: "ssl", category: "business-and-economy", label: v[1] }; },
    sizes: { baseline: [20, 90], big: [180, 1500] },
    ticket: (c, w) => ({ table: "sc_req_item", number: ITSM_N("RITM", c), state: "Closed Complete", short: `Project ${pickOf(["Juniper", "Atlas", "Kestrel", "Marlin"], c.rnd)}: ${w.label} data room access for the deal team`, requestedFor: w.user, group: "Legal Operations" }),
    why: w => `The deal team's approved data room (${w.label}, ${w.domain}); the uploader is on the approved request. Not exfiltration.` },
  { id: "audit_upload", person: /compliance|financ|account|risk|controller|it/i,
    texts: [
      "The CFO's office wants to know why {host} sent {size} to {domain} this morning. Nobody told them about any upload.",
      "Internal audit asks the SOC whether the upload from {host} to an outside portal, {domain}, is allowed. It looks like a lot of files.",
    ],
    expected: "Recognise the external auditor's evidence portal: the request is approved, the uploader is the named audit contact and the destination is the audit firm's portal. Not an incident.",
    dest: c => { const v = pickOf([["portal.marlowreyes-audit.com", "Marlow & Reyes Assurance"], ["evidence.crestline-assurance.com", "Crestline Assurance"]] as const, c.rnd);
      return { domain: v[0], url: `https://${v[0]}/requests/upload`, app: "ssl", category: "business-and-economy", label: v[1] }; },
    sizes: { baseline: [10, 60], big: [90, 700] },
    ticket: (c, w) => ({ table: "sc_req_item", number: ITSM_N("RITM", c), state: "Closed Complete", short: `Year-end audit: evidence upload to ${w.label}`, requestedFor: w.user, group: "Finance Systems" }),
    why: w => `Evidence for the year-end audit, uploaded by the named audit contact to ${w.label}'s portal (${w.domain}) under the approved request. Not exfiltration.` },
  { id: "media_agency", person: /market|sales|product|communication|design/i,
    texts: [
      "Marketing's manager asks the SOC: the firewall shows {size} of video leaving {host} for {domain}. Is that a leak?",
      "A team lead noticed {host} uploading gigabytes to {domain} all afternoon. Should IT block it?",
    ],
    expected: "Recognise the agency hand-off: the request is approved, the files are the campaign's raw footage and the destination is the agency's file-transfer service. Not an incident.",
    dest: c => { const v = pickOf([["drop.brightfoldstudio.com", "Brightfold Studio"], ["transfer.lumenreel.co", "Lumenreel"]] as const, c.rnd);
      return { domain: v[0], url: `https://${v[0]}/upload`, app: "ssl", category: "online-storage-and-backup", label: v[1] }; },
    sizes: { baseline: [150, 600], big: [1500, 6000] },
    ticket: (c, w) => ({ table: "sc_req_item", number: ITSM_N("RITM", c), state: "Closed Complete", short: `Large file transfer to ${w.label} for the spring campaign`, requestedFor: w.user, group: "Service Desk" }),
    why: w => `Campaign footage handed to the agency ${w.label} through its transfer service (${w.domain}) under the approved request. Not exfiltration.` },
  { id: "log_backlog", server: true,
    texts: [
      "The network team sees {host} sending {size} to {domain} after this morning's outage. Is a server leaking data?",
      "Infrastructure asks the SOC to check an unusual upload burst from {host} to {domain}. It started when the link came back.",
    ],
    expected: "Recognise the observability agent flushing its backlog: the destination is the company's log-intake endpoint, the burst started when the link came back and the change covers the agent. Not an incident.",
    dest: c => { const v = pickOf([["http-intake.logs.datadoghq.eu", "Datadog Agent"], ["http-intake.logs.datadoghq.com", "Datadog Agent"]] as const, c.rnd);
      return { domain: v[0], url: `https://${v[0]}/api/v2/logs`, app: "ssl", category: "computer-and-internet-info", label: v[1] }; },
    sizes: { baseline: [20, 80], big: [150, 600] },
    ticket: (c, w) => ({ table: "incident", number: ITSM_N("INC", c), state: "Resolved", short: `Internet link down at the office; restored, monitoring agents catching up`, ci: w.host, group: "Network Engineering" }),
    why: w => `The ${w.label} on ${w.host} flushed the logs it buffered during the outage to the company's own log intake (${w.domain}). Not exfiltration.` },
];
export const DECOY_KINDS = DECOYS.map(d => d.id);

const isServer = (h: string) => /^(SRV|SVR|DC)-|-SRV-|prod-srv|-DC\d/i.test(h);

/** One decoy for the session (the least recently used kind that this company can carry), or null. */
export function buildDecoy(c: DecoyCtx, seen: { decoys: Record<string, number>; injects: Record<string, number> }, force?: string): DecoyBuild | null {
  const a = c.assets;
  const order = force ? DECOYS.filter(d => d.id === force) : rankByHistory(DECOYS, d => d.id, seen.decoys, c.rnd);
  for (const d of order) {
    let host: string | undefined, user: string | undefined;
    if (d.server) {
      host = [a.fileServer, ...a.hosts.filter(isServer)].find(h => h !== a.dc && !c.usedHosts.has(h));
    } else {
      const people = a.roster.filter(r => !c.usedUsers.has(`${r.name}@${a.domain}`));
      const p = people.find(r => d.person!.test(r.title ?? "")) ?? (force ? people[0] : undefined);
      if (!p) continue;
      user = `${p.name}@${a.domain}`;
      const seat = Object.values(a.seats ?? {}).flat().find(s => s.user === p.name)?.host;
      host = seat && !c.usedHosts.has(seat) ? seat : a.hosts.find(h => !isServer(h) && h !== a.dc && h !== a.fileServer && !c.usedHosts.has(h));
    }
    if (!host) continue;
    const dest = d.dest(c);
    const ip = docIp(c.rnd, c.ips);
    const src = `${a.subnet}.${intIn(30, 230, c.rnd)}`;
    const mb = (r: [number, number]) => intIn(r[0], r[1], c.rnd) * 1_048_576 + intIn(0, 1_048_575, c.rnd);
    const sizes = [mb(d.sizes.baseline), mb(d.sizes.big), mb(d.sizes.big)];
    const who = { host, user, label: dest.label, domain: dest.domain };
    const why = d.why(who);
    const row = (k: number, bytes: number, fp: boolean): TelemetryEvent => { const bytesIn = Math.floor(bytes / intIn(600, 1400, c.rnd)); return {
      id: `msel_false_lead_fw${k}`, ts: c.baseTs, source: "firewall", vendor: c.fw.vendor, event_type: "net_connection", severity: k === 0 ? "informational" : "medium",
      hostname: host, ...(user ? { user_email: user } : {}), src_ip: src, dst_ip: ip, dst_port: 443, protocol: "tcp",
      network: { url: dest.url, domain: dest.domain, method: "POST", bytes_out: bytes, bytes_in: bytesIn },
      description: `${k === 0 ? "Outbound HTTPS upload" : "Large outbound HTTPS upload"} from ${host} to ${dest.domain}`, ...(fp ? { fp_explanation: why } : {}),
      raw: firewallRaw(c.fw.flavour, { srcIp: src, dstIp: ip, domain: dest.domain, url: dest.url, category: dest.category, app: dest.app, bytesOut: bytes, bytesIn, sessions: intIn(2, 40, c.rnd) }),
    } as TelemetryEvent; };
    const human = (b: number) => (b >= 1_073_741_824 ? `${(b / 1_073_741_824).toFixed(1)} GB` : `${Math.round(b / 1_048_576)} MB`);
    const textIdx = rankByHistory(d.texts.map((_, i) => i), i => `lead:${d.id}:${i}`, seen.injects, c.rnd)[0];
    const text = d.texts[textIdx].replaceAll("{host}", host).replaceAll("{domain}", dest.domain).replaceAll("{size}", human(sizes[1] + sizes[2]));
    c.usedHosts.add(host); if (user) c.usedUsers.add(user);
    return {
      kind: d.id, host, user,
      inject: { key: `lead:${d.id}:${textIdx}`, text, expected_response: d.expected, linked_objective: "accuracy · discrimination (reject false leads)" },
      ticket: d.ticket(c, who),
      rows: [{ ev: row(0, sizes[0], false), when: "baseline" }, { ev: row(1, sizes[1], true), when: "before" }, { ev: row(2, sizes[2], true), when: "after" }],
    };
  }
  return null;
}

// ── Twists ──────────────────────────────────────────────────────────────────────
export interface TwistCtx {
  rnd: () => number; baseTs: string; assets: CompanyAssets | undefined; stack: Stack;
  host: string; hostIp: string; hostUser?: string; victim?: string; seenHost: boolean;
  /** The story's own process on the host, if any (its name, pid and context). */
  proc?: { name: string; pid: number; path?: string; cmdline?: string; parent?: string };
  edr: string; fw: { flavour: FwFlavour; vendor: string }; useSysmon: boolean; ips: Set<string>; domains: Set<string>;
  /** Hosts / people the session already uses for other things (the remote-session target avoids them). */
  usedHosts: Set<string>;
  /** People other incidents of the session are about: a twist never drags them into this one. */
  avoidUsers?: Set<string>;
  /** The host's operating system, read from the story's own process paths on it. */
  os: "windows" | "linux" | "mac";
  /** The organization (its domain SIDs and FQDNs); found from `assets` when absent. */
  companyId?: string;
  /**
   * The twist story's malicious rows (any host), in feed order: what the attack ACHIEVED, and where. A
   * twist follows from it (an implant only where something ran, a backdoor account only after code ran,
   * the spray resuming when the spray never got in). Absent: the story's process on the host is the only
   * proof of execution there.
   */
  story?: TelemetryEvent[];
}
export interface TwistBuild { kind: string; inject: InjectText; rows: TelemetryEvent[] }
interface TwistKind { id: string; fits: (c: TwistCtx, g: TwistGround) => boolean; texts: string[]; expected: string; rows: (c: TwistCtx, g: TwistGround) => { rows: TelemetryEvent[]; vars: Record<string, string> } }

/** What the twist's story achieved: code ran on the host, an account logged on there, a cloud sign-in worked, or only failures / blocks. */
export interface TwistGround {
  exec: boolean; logon: boolean; signin: boolean; failedOnly: boolean;
  /** The accounts a failure-only story tried (spray / brute force), and the address it came from. */
  sprayed: string[]; sprayIp?: string;
  /** The failures were cloud sign-ins (Entra / Okta / VPN), not Windows logons. */
  cloud: boolean;
}
const FAIL_ET = /^(auth_failure|account_lockout|vpn_failed|mfa_denied|ssh_failed|db_failed|ids_blocked|net_blocked|waf_block|http_blocked|av_blocked|email_blocked|email_quarantined)$/;
const EXEC_SRC = new Set(["edr", "sysmon", "av", "linux_audit"]);
const EXEC_ET = /^(process_create|linux_execve|scheduled_task|service_install|registry_set|process_access|privilege_escalation|sudo_command|linux_cron|k8s_exec)$/;
const LOGON_ET = /^(auth_success|ssh_login|vpn_login)$/;
const CLOUD_SRC = new Set(["o365", "okta", "gws", "vpn", "saas"]);
const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/;
const shortHost = (h?: string) => (h ?? "").toLowerCase().split(".")[0];

export function twistGround(c: TwistCtx): TwistGround {
  const dc = c.assets?.dc;
  if (!c.story) {
    const exec = !!c.proc;
    // A host-less story's twist lands on the victim's own device: the account worked somewhere.
    const signin = !exec && !!c.victim && c.host !== dc && !isServer(c.host);
    // A story whose malicious rows sit on the domain controller with no process of its own there: logons that failed.
    return { exec, logon: exec, signin, failedOnly: !exec && !signin && c.host === dc, sprayed: c.victim ? [c.victim] : [], cloud: false };
  }
  const rows = c.story;
  const onHost = rows.filter(r => shortHost(r.hostname) === shortHost(c.host));
  const exec = !!c.proc || onHost.some(r => EXEC_SRC.has(r.source) && EXEC_ET.test(r.event_type));
  const logon = onHost.some(r => LOGON_ET.test(r.event_type) && !CLOUD_SRC.has(r.source));
  const signin = rows.some(r => LOGON_ET.test(r.event_type) && CLOUD_SRC.has(r.source))
    || rows.some(r => !!r.user_email && CLOUD_SRC.has(r.source) && /^(sharepoint_|email_sent$|teams_)/.test(r.event_type));
  const fails = rows.filter(r => FAIL_ET.test(r.event_type));
  const domain = c.assets?.domain;
  const who = (r: TelemetryEvent) => {
    const t = (r.raw as Record<string, unknown> | undefined)?.["winlog.event_data.TargetUserName"];
    return typeof t === "string" && t && domain && !t.endsWith("$") ? `${t}@${domain}` : r.user_email;
  };
  const sprayed = [...new Set(fails.filter(r => /auth_failure|account_lockout|vpn_failed|ssh_failed/.test(r.event_type)).map(who).filter((u): u is string => !!u && u.includes("@")))];
  const pub = fails.map(r => r.src_ip).filter((ip): ip is string => !!ip && !PRIVATE.test(ip));
  const sprayIp = pub.sort((a, b) => pub.filter(x => x === b).length - pub.filter(x => x === a).length)[0];
  return {
    exec, logon, signin, failedOnly: !exec && !logon && !signin && fails.length > 0,
    sprayed: sprayed.length ? sprayed : c.victim ? [c.victim] : [], sprayIp,
    cloud: fails.filter(r => CLOUD_SRC.has(r.source)).length * 2 > fails.length,
  };
}

const user0 = (e?: string) => (e ? e.split("@")[0] : undefined);
/**
 * An attacker address for a twist: a documentation address from 198.51.100.0/24. 192.0.2.0/24 stands for the
 * ordinary outside world in the XDR baseline (sentinel/baseline.ts OUTSIDE), so an attacker there could read as
 * everyday traffic; 203.0.113.0/24 maps to one country in the geo table (variety.ts DOC_NETS).
 */
function attackerIp(c: TwistCtx): string {
  for (let k = 0; k < 200; k++) {
    const ip = `198.51.100.${intIn(10, 250, c.rnd)}`;
    if (!c.ips.has(ip)) { c.ips.add(ip); return ip; }
  }
  return docIp(c.rnd, c.ips);
}
const RE_OBJ = "adaptability · re-scope on new evidence";
const companyOf = (c: TwistCtx) => c.companyId ?? Object.entries(COMPANY_ASSETS).find(([, a]) => a === c.assets)?.[0];
/** Somebody works at this host interactively (a workstation with its user): only then do Explorer, a Run key or a profile folder exist for the attacker to use. */
const interactive = (c: TwistCtx) => !!c.hostUser && !isServer(c.host) && c.host !== c.assets?.dc;
/** Folders an implant can be written to on this host: the user's profile when somebody works there, else machine-wide folders. */
function implantDirs(c: TwistCtx): string[] {
  const u = interactive(c) ? user0(c.hostUser) : undefined;
  const machine = [`C:\\ProgramData\\${pickOf(["Packages", "SoftwareDistribution", "USOShared"], c.rnd)}`, "C:\\Windows\\Temp"];
  return u ? [`C:\\Users\\${u}\\AppData\\Local\\Temp`, `C:\\Users\\${u}\\AppData\\Roaming\\${pickOf(["Microsoft\\Crypto", "Adobe\\Updater", "Zoom\\bin"], c.rnd)}`, machine[0]] : machine;
}
/** The process that starts a user-less payload on a server: a scheduled task's host or the WMI provider host, never Explorer. */
const serverParent = (c: TwistCtx) => pickOf(["svchost.exe", "WmiPrvSE.exe"], c.rnd);
const procUser = (c: TwistCtx) => (interactive(c) ? user0(c.hostUser) : undefined);
/** Drop the pid copies from a legacy raw block: the session prints one canonical pid per process (native/index canonicalPids) on the row and its record. */
function withoutRawPids(raw: Record<string, unknown>): Record<string, unknown> {
  const out = { ...raw };
  for (const k of ["process.pid", "process.parent.pid", "ProcessId", "InitiatingProcessId", "InitiatingProcessParentId", "crowdstrike.RawProcessId", "s1.srcProcPid"]) delete out[k];
  return out;
}
/** An MDE process row for a twist (authored as Defender, relabelled to the session's EDR like every EDR row). */
function twistProc(c: TwistCtx, o: { id: string; name: string; path: string; cmdline: string; parent: string; system: boolean; eventType?: TelemetryEvent["event_type"]; linux?: boolean; description: string; extra?: Record<string, string> }): TelemetryEvent {
  const companyId = companyOf(c);
  const u = o.system ? null : c.hostUser ?? null;
  const ev = mdeProcess({
    id: o.id, ts: c.baseTs, companyId, host: c.host, user: u, srcIp: c.hostIp,
    processName: o.name, processPath: o.path, cmdline: o.cmdline, parentName: o.parent, severity: "medium",
    integrity: o.linux ? undefined : o.system ? "System" : "High", signed: /^(C:\\Windows\\|\/usr\/bin\/|\/bin\/)/i.test(o.path),
    ...(o.system ? o.linux ? { runAsUser: "root", accountName: "root", accountDomain: c.host.toLowerCase() } : { runAsUser: "NT AUTHORITY\\SYSTEM", accountName: "system", accountDomain: "nt authority" } : {}),
    ...(o.extra ? { extra: o.extra } : {}),
    description: o.description,
  });
  delete (ev as Partial<TelemetryEvent>).is_detection;
  return { ...ev, ...(o.eventType ? { event_type: o.eventType } : {}), raw: withoutRawPids(ev.raw ?? {}) } as TelemetryEvent;
}

/** Rules about volume or the client, not the input: a returning operator is not "the same request" there. */
const VOLUME_RULES = new Set(["rate", "login_volumetric", "login_stolen", "size_body", "bad_bot", "custom"]);
/** The request a web story attacked from outside: its site (and origin, when the story shows the server's own log), path, input and rule. */
function webTarget(c: TwistCtx): { site: WebSite; path: string; query: string; method: "GET" | "POST"; ua: string; rule: WafRuleKey; matched?: string; location?: string; status: number; bytes: number } | null {
  const raw = (e: TelemetryEvent) => (e.raw ?? {}) as Record<string, unknown>;
  const str = (e: TelemetryEvent, k: string) => (typeof raw(e)[k] === "string" ? (raw(e)[k] as string) : undefined);
  // The last outside request a rule matched whose input is in the query string with URL escapes in it (the
  // returning operator re-encodes them), on a site whose origin log the story shows.
  const hit = [...(c.story ?? [])].reverse().find(e => e.source === "waf" && !!e.src_ip && !PRIVATE.test(e.src_ip) && !!e.network?.domain
    && typeof raw(e)["waf.rule.key"] === "string" && !VOLUME_RULES.has(String(raw(e)["waf.rule.key"])) && /%[0-9A-Fa-f]{2}/.test(str(e, "url.query") ?? "")
    && (c.story ?? []).some(o => o.source === "web_server" && o.network?.domain === e.network?.domain));
  if (!hit) return null;
  const domain = hit.network!.domain!, path = str(hit, "url.path") ?? "/";
  const origins = (c.story ?? []).filter(e => e.source === "web_server" && e.network?.domain === domain);
  const answer = [...origins].reverse().find(e => str(e, "url.path") === path) ?? origins[origins.length - 1];
  return { site: { site: domain, host: answer.hostname!, ip: answer.dst_ip! }, path, query: str(hit, "url.query")!, method: str(hit, "http.request.method") === "POST" ? "POST" : "GET",
    ua: hit.network?.user_agent ?? "python-requests/2.31.0", rule: raw(hit)["waf.rule.key"] as WafRuleKey, matched: str(hit, "waf.matched_data"), location: str(hit, "waf.match_location"),
    status: answer.network?.status ?? 200, bytes: answer.network?.bytes_in ?? 1840 };
}

const TWISTS: TwistKind[] = [
  { id: "second_implant", fits: (_c, g) => g.exec,
    texts: [
      "EDR update: {hostRef} is now beaconing to a NEW C2 domain. The picture just changed: re-scope the incident and confirm your containment still holds.",
      "Threat hunting flagged {hostRef}: a process there is calling a domain nobody has seen before, on a steady interval. Is this part of your incident?",
      "Network team: {hostRef} started regular HTTPS check-ins to an unfamiliar domain about once a minute. Please look before the end of the shift.",
    ],
    expected: "Adapt: a second implant on a host already in the case. Re-open or re-scope the case (new IOC: the domain and its address), and check that containment covers it.",
    rows: (c) => {
      const domain = fakeC2Domain(c.rnd, c.domains), ip = attackerIp(c);
      const unix = c.os !== "windows";
      const people = interactive(c);
      const loader = c.proc && c.proc.name.toLowerCase() !== "rundll32.exe" && (unix || c.rnd() < 0.4) ? "story" : unix ? "unix" : pickOf(["rundll32", "regsvr32", "dropped"] as const, c.rnd);
      const dir = pickOf(implantDirs(c), c.rnd);
      const stem = `${pickOf(["msupd", "wincfg", "cache", "svcmgr", "onedrv", "teamsx", "drvhlp", "netsvc"], c.rnd)}${intIn(10, 999, c.rnd)}`;
      const pid = c.proc?.pid ?? 4 * intIn(750, 2250, c.rnd);
      const home = user0(c.hostUser);
      const unixPath = c.os === "mac" && home ? `/Users/${home}/Library/Application Support/${stem.replace(/\d+$/, "")}/${stem}` : pickOf([`/tmp/.${stem}`, `/var/tmp/${stem}`, `/dev/shm/.${stem}`], c.rnd);
      const winParent = () => (people ? pickOf(["explorer.exe", "svchost.exe"], c.rnd) : serverParent(c));
      const p = loader === "story" ? { name: c.proc!.name, path: c.proc!.path ?? (unix ? unixPath : `${dir}\\${c.proc!.name}`), cmdline: c.proc!.cmdline ?? c.proc!.name, parent: c.proc!.parent ?? (unix ? "bash" : winParent()) }
        : loader === "unix" ? { name: unixPath.split("/").pop()!, path: unixPath, cmdline: `${unixPath} ${pickOf(["-d", "--daemon", "-q"], c.rnd)}`, parent: c.os === "mac" ? "launchd" : pickOf(["bash", "sh", "systemd"], c.rnd) }
        : loader === "rundll32" ? { name: "rundll32.exe", path: "C:\\Windows\\System32\\rundll32.exe", cmdline: `"C:\\Windows\\System32\\rundll32.exe" ${dir}\\${stem}.dll,${pickOf(["DllRegisterServer", "StartW", "Run", "EntryPoint"], c.rnd)}`, parent: winParent() }
        : loader === "regsvr32" ? { name: "regsvr32.exe", path: "C:\\Windows\\System32\\regsvr32.exe", cmdline: `"C:\\Windows\\System32\\regsvr32.exe" /s ${dir}\\${stem}.dll`, parent: people ? "explorer.exe" : serverParent(c) }
        : { name: `${stem}.exe`, path: `${dir}\\${stem}.exe`, cmdline: `"${dir}\\${stem}.exe" ${pickOf(["-k netsvc", "/silent", "--update"], c.rnd)}`, parent: people ? pickOf(["explorer.exe", "svchost.exe"], c.rnd) : "svchost.exe" };
      const urlPath = pickOf(["/api/v2/status", "/cdn/sync", "/v1/telemetry", "/static/poll", "/updates/check"], c.rnd);
      const out = intIn(900, 4800, c.rnd), inn = intIn(300, 1400, c.rnd);
      const account = procUser(c);
      const ctx: ProcCtx = { path: p.path, cmdline: p.cmdline, parent: p.parent, account };
      // The payload the loader runs was written to disk first (DeviceFileEvents FileCreated), by the process
      // already running there for the story: the cause of the new beacon is on the host's own timeline.
      const payload = loader === "rundll32" || loader === "regsvr32" ? `${dir}\\${stem}.dll` : loader === "dropped" ? p.path : undefined;
      const writer = c.proc ?? (c.story ?? []).filter(r => shortHost(r.hostname) === shortHost(c.host) && r.process?.name).map(r => r.process!).pop();
      const drop: TelemetryEvent[] = payload ? [(() => {
        const f = mdeFile({
          id: "msel_twist_drop", ts: c.baseTs, companyId: companyOf(c), host: c.host, user: account ? c.hostUser : null, srcIp: c.hostIp, path: payload,
          size: intIn(90, 900, c.rnd) * 1024 + intIn(0, 1023, c.rnd), signed: false, severity: "low",
          ...(writer ? { initiatingProcess: writer.name, ...(writer.cmdline ? { initiatingCmdline: writer.cmdline } : {}) } : {}),
          description: `${payload.split("\\").pop()} written on ${c.host}`,
        });
        return { ...f, ...(writer ? { process: { name: writer.name, pid: writer.pid, ...(writer.path ? { path: writer.path } : {}), ...(writer.cmdline ? { cmdline: writer.cmdline } : {}) } } : {}) } as TelemetryEvent;
      })()] : [];
      const dns: TelemetryEvent = c.useSysmon && !unix ? {
        id: "msel_twist_dns", ts: c.baseTs, source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query", severity: "low",
        hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp, dns: { query: domain, query_type: "A", response: ip, rcode: "NOERROR" },
        description: `${c.host} looked up ${domain}`,
        raw: { "event.code": "22", "winlog.provider_name": "Microsoft-Windows-Sysmon", "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
          "winlog.computer_name": c.host, "winlog.event_data.QueryName": domain, "winlog.event_data.QueryStatus": "0",
          "winlog.event_data.QueryResults": `::ffff:${ip};`, "winlog.event_data.Image": p.path },
      } as TelemetryEvent : {
        id: "msel_twist_dns", ts: c.baseTs, source: "dns", vendor: "Infoblox DNS", event_type: "dns_query", severity: "low",
        hostname: c.host, src_ip: c.hostIp, network: { domain }, dns: { query: domain, query_type: "A", response: ip, rcode: "NOERROR" },
        description: `${c.host} looked up ${domain}`,
        raw: { "dns.question.name": domain, "dns.question.type": "A", "dns.response_code": "NOERROR", "dns.answers.data": ip, "dns.answers.ttl": String(pickOf([60, 300, 600], c.rnd)), "client.ip": c.hostIp },
      } as TelemetryEvent;
      const fw: TelemetryEvent = {
        id: "msel_twist_fw", ts: c.baseTs, source: "firewall", vendor: c.fw.vendor, event_type: "net_connection", severity: "medium",
        hostname: c.host, src_ip: c.hostIp, dst_ip: ip, dst_port: 443, protocol: "tcp",
        network: { url: `https://${domain}${urlPath}`, domain, method: pickOf(["POST", "GET"], c.rnd), bytes_out: out, bytes_in: inn },
        description: `Outbound HTTPS from ${c.host} to ${domain}`,
        raw: firewallRaw(c.fw.flavour, { srcIp: c.hostIp, dstIp: ip, domain, url: `https://${domain}${urlPath}`, category: pickOf(["newly-registered-domain", "unknown"], c.rnd), app: "ssl", bytesOut: out, bytesIn: inn, sessions: intIn(6, 40, c.rnd) }),
      } as TelemetryEvent;
      const edr: TelemetryEvent = {
        id: "msel_twist_edr", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "net_connection", severity: "medium",
        hostname: c.host, user_email: account ? c.hostUser : undefined, src_ip: c.hostIp, dst_ip: ip, dst_port: 443, protocol: "tcp",
        process: { name: p.name, pid, path: p.path, cmdline: p.cmdline, parent_name: p.parent, user: account ?? (unix ? "root" : "NT AUTHORITY\\SYSTEM") },
        description: `${p.name} on ${c.host} connected to ${ip}:443`,
        raw: withoutRawPids(edrConnRaw(c.edr, c.host, p.name, pid, c.hostIp, ip, domain, ctx)),
      } as TelemetryEvent;
      return { rows: [...drop, dns, fw, edr], vars: { domain, ip } };
    } },
  { id: "new_persistence", fits: (_c, g) => g.exec,
    texts: [
      "EDR update: something on {hostRef} just set itself up to start again after a reboot. Check whether your containment covers it.",
      "Endpoint team: a new autostart entry appeared on {hostRef} a moment ago, pointing at a file in a writable folder. Does this change your case?",
      "Heads-up from the EDR console: {hostRef} has a fresh persistence mechanism. The incident may not be over.",
    ],
    expected: "Adapt: the attacker added persistence on a host in the case. Re-scope (the autostart entry and its file are new IOCs) and make sure the eradication plan removes it.",
    rows: (c) => {
      const people = interactive(c);
      const home = people ? user0(c.hostUser) : undefined;
      const sys = !people;
      if (c.os !== "windows") {
        const stem = `${pickOf(["dbus-helper", "kworkerd", "update-notifier", "netcheck", "syncd"], c.rnd)}${intIn(1, 99, c.rnd)}`;
        const mac = c.os === "mac";
        const file = mac && home ? `/Users/${home}/Library/Application Support/.${stem}/${stem}` : pickOf([`/var/tmp/.${stem}`, `/usr/local/lib/.${stem}/${stem}`, ...(home ? [`/home/${home}/.cache/${stem}`] : [])], c.rnd);
        const how = mac ? "launchd" : pickOf(["cron", "systemd"] as const, c.rnd);
        const plist = home ? `/Users/${home}/Library/LaunchAgents/com.${stem}.plist` : `/Library/LaunchDaemons/com.${stem}.plist`;
        const cmd = how === "launchd" ? `launchctl load -w ${plist}`
          : how === "cron" ? `/bin/sh -c (crontab -l 2>/dev/null; echo "*/${pickOf([5, 10, 15], c.rnd)} * * * * ${file}") | crontab -`
          : `systemctl enable --now ${stem}.service`;
        const tool = how === "launchd" ? "launchctl" : how === "cron" ? "crontab" : "systemctl";
        const first = twistProc(c, { id: "msel_twist_persist", name: tool, path: mac ? `/bin/${tool}` : `/usr/bin/${tool}`, cmdline: cmd, parent: mac ? "zsh" : "bash", system: !home, linux: true,
          description: `${tool} added an autostart entry on ${c.host}` });
        const run = twistProc(c, { id: "msel_twist_run", name: file.split("/").pop()!, path: file, cmdline: file, parent: how === "launchd" ? "launchd" : how === "cron" ? "cron" : "systemd", system: !home || how !== "launchd", linux: true,
          description: `${file.split("/").pop()} started on ${c.host}` });
        return { rows: [first, run], vars: { file } };
      }
      const stem = `${pickOf(["OneDriveSync", "AdobeUpd", "TeamsHelper", "EdgeUpdateCore", "PrintSvcHost"], c.rnd)}${intIn(1, 99, c.rnd)}`;
      const base = home ? pickOf([`C:\\Users\\${home}\\AppData\\Roaming`, "C:\\ProgramData", `C:\\Users\\${home}\\AppData\\Local`], c.rnd) : "C:\\ProgramData";
      const file = `${base}\\${pickOf(["Microsoft", "Updater", "Cache"], c.rnd)}\\${stem.toLowerCase()}.exe`;
      // A Run key only runs when somebody logs on: a server nobody works at gets a task or a service.
      const how = people ? pickOf(["run_key", "task", "service"] as const, c.rnd) : pickOf(["task", "service"] as const, c.rnd);
      const hive = home ? "HKCU" : "HKLM";
      const runKey = `${hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`;
      const first: TelemetryEvent = how === "run_key" ? (() => {
        const ev = twistProc(c, { id: "msel_twist_persist", name: "reg.exe", path: "C:\\Windows\\System32\\reg.exe", parent: "cmd.exe", system: sys, eventType: "registry_set",
          cmdline: `reg add ${runKey} /v ${stem} /t REG_SZ /d "${file}" /f`, description: `A Run key value ${stem} was set on ${c.host}` });
        return { ...ev, registry: { path: runKey, key: stem, value: file },
          raw: { ...ev.raw, ActionType: "RegistryValueSet", RegistryKey: runKey, RegistryValueName: stem, RegistryValueData: file, RegistryValueType: "String",
            "registry.path": runKey, "registry.key": stem, "registry.value": file, "event.action": "registry_value_set" } } as TelemetryEvent;
      })() : how === "task" ? twistProc(c, { id: "msel_twist_persist", name: "schtasks.exe", path: "C:\\Windows\\System32\\schtasks.exe", parent: "cmd.exe", system: sys, eventType: "scheduled_task",
          cmdline: `schtasks.exe /create /tn "${stem}" /sc ${pickOf([people ? "onlogon" : "onstart", "minute /mo 15", "daily /st 09:00"], c.rnd)} ${sys ? "/ru SYSTEM " : ""}/tr "${file}" /f`,
          description: `schtasks.exe created the scheduled task ${stem} on ${c.host}` })
        : (() => {
          const ev = twistProc(c, { id: "msel_twist_persist", name: "sc.exe", path: "C:\\Windows\\System32\\sc.exe", parent: "cmd.exe", system: sys, eventType: "service_install",
            cmdline: `sc.exe create ${stem} binPath= "${file}" start= auto`, description: `sc.exe installed the service ${stem} on ${c.host}` });
          return { ...ev, raw: { ...ev.raw, "service.name": stem, "service.path": file } } as TelemetryEvent;
        })();
      const run = twistProc(c, { id: "msel_twist_run", name: file.split("\\").pop()!, path: file, cmdline: `"${file}"`,
        parent: how === "service" ? "services.exe" : how === "task" ? "svchost.exe" : "explorer.exe", system: how !== "run_key",
        description: `${file.split("\\").pop()} started on ${c.host}` });
      return { rows: [first, run], vars: { file } };
    } },
  { id: "credential_reuse", fits: (c, g) => !!c.victim && g.signin,
    texts: [
      "Identity team: {user} just signed in from an address the company has never seen, after your incident started. Did the password reset happen?",
      "Entra / Okta update: a fresh sign-in for {user} from {ip}, then mail access. The account may still be in the attacker's hands.",
      "The help desk says {user} is at their desk, yet their account just signed in from somewhere else. Is this connected to your case?",
    ],
    expected: "Adapt: the stolen credentials are being reused. Re-scope to the account, revoke its sessions, reset the password and block the new address.",
    rows: (c) => {
      const ip = attackerIp(c), u = c.victim!;
      const [city, country, lat, lon] = pickOf([["Bucharest", "Romania", 44.4268, 26.1025], ["Kuala Lumpur", "Malaysia", 3.139, 101.6869], ["Lagos", "Nigeria", 6.5244, 3.3792], ["Sao Paulo", "Brazil", -23.5505, -46.6333], ["Hanoi", "Vietnam", 21.0278, 105.8342]] as const, c.rnd);
      const signin = cloudSignIn(c, { id: "msel_twist_signin", user: u, ip, city, country, lat, lon, ok: true, description: `${u} signed in from ${city}, ${country} (${ip})` });
      const access: TelemetryEvent = c.stack.collab === "m365" ? {
        id: "msel_twist_access", ts: c.baseTs, source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "sharepoint_download", severity: "low",
        user_email: u, src_ip: ip, description: `${u} downloaded a file from SharePoint`,
        raw: { "data.office365.Operation": "FileDownloaded", "data.office365.Workload": "SharePoint", "data.office365.SiteUrl": `https://${(c.assets?.domain ?? "corp.com").split(".")[0]}.sharepoint.com/sites/${pickOf(["Finance", "HR", "Projects"], c.rnd)}`,
          "data.office365.SourceFileName": pickOf(["Q3_forecast.xlsx", "Org_chart_2026.pdf", "Vendor_contacts.xlsx", "Board_pack_draft.docx"], c.rnd), "data.office365.ResultStatus": "Succeeded", "data.office365.ClientIP": ip,
          "data.office365.UserId": u },
      } as TelemetryEvent : cloudSignIn(c, { id: "msel_twist_access", user: u, ip, city, country, lat, lon, ok: true, description: `${u} signed in again from ${ip}` });
      return { rows: [signin, access], vars: { ip, user: u } };
    } },
  { id: "new_remote_session", fits: (c, g) => !!c.stack.onprem_ad && !!c.assets && c.os === "windows" && (g.exec || g.logon),
    texts: [
      "Server team: a Remote Desktop session reached {target} from {hostRef}. Nobody in IT is working on that server today.",
      "Windows logs show {hostRef} opening an interactive remote session on {target}. Has the attacker moved on from the first host?",
      "A colleague noticed someone logged on to {target} over RDP from {hostRef}. Should this be in the case?",
    ],
    expected: "Adapt: lateral movement to a new server. Add the target to the scope, check what the account did there and contain it.",
    rows: (c) => {
      const a = c.assets!;
      const target = [a.fileServer, ...a.hosts.filter(isServer)].find(h => h && h !== c.host && h !== a.dc && !c.usedHosts.has(h)) ?? a.fileServer;
      const tip = `${a.subnet}.${intIn(5, 29, c.rnd)}`, u = user0(c.hostUser ?? c.victim) ?? "administrator";
      const fw: TelemetryEvent = {
        id: "msel_twist_rdpfw", ts: c.baseTs, source: "firewall", vendor: c.fw.vendor, event_type: "net_connection", severity: "informational",
        hostname: c.host, src_ip: c.hostIp, dst_ip: tip, dst_port: 3389, protocol: "tcp", description: `${c.hostIp} connected to ${tip}:3389`,
        raw: firewallRaw(c.fw.flavour, { srcIp: c.hostIp, dstIp: tip, domain: "", url: "", category: "private-ip-addresses", app: "ms-rdp", bytesOut: intIn(40000, 900000, c.rnd), bytesIn: intIn(400000, 9000000, c.rnd), port: "3389" }),
      } as TelemetryEvent;
      // RDP: NLA authenticates first (a type-3 logon), the session itself is type 10 from the client's address.
      const logon = winLogon({
        id: "msel_twist_logon", ts: c.baseTs, companyId: companyOf(c), host: target, targetUser: u, ...(c.hostUser || c.victim ? { userEmail: c.hostUser ?? c.victim } : {}),
        srcIp: c.hostIp, logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ", workstation: c.host.toUpperCase(), lmPackage: "-", keyLength: "0",
        subjectSid: "S-1-5-18", subjectUser: `${target}$`, processName: "C:\\Windows\\System32\\svchost.exe", logSource: "windows_security", severity: "informational",
        description: `${u} logged on to ${target} (Remote Desktop)`,
      });
      return { rows: [fw, logon], vars: { target } };
    } },
  { id: "new_account", fits: (c, g) => !!c.stack.onprem_ad && !!c.assets && g.exec,
    texts: [
      "Directory alert: a new account, {acct}, appeared on {dc} and was put in {group}. The request did not come through IT.",
      "The identity team spotted an account nobody requested, {acct}, created on {dc} from the session you are investigating. Does this change your scope?",
      "AD change report: {acct} was created on {dc} and added to {group} a few minutes ago. IT says it is not theirs.",
    ],
    expected: "Adapt: the attacker created a backdoor account. Add it to the scope, disable it, and check which session created it.",
    rows: (c) => {
      const a = c.assets!, companyId = companyOf(c);
      const acct = pickOf(["svc-", "adm-", "it-", "sql"], c.rnd) + pickOf(["sync", "backup2", "monitor", "helpdesk", "update", "report"], c.rnd) + (c.rnd() < 0.5 ? String(intIn(1, 9, c.rnd)) : "");
      const group = pickOf(["Remote Desktop Users", "Backup Operators", "Server Operators", "IT-Admins"], c.rnd);
      const by = user0(c.hostUser ?? c.victim) ?? "administrator";
      const BUILTIN: Record<string, string> = { "Remote Desktop Users": "S-1-5-32-555", "Backup Operators": "S-1-5-32-551", "Server Operators": "S-1-5-32-549" };
      const global = group === "IT-Admins";
      const subjectSid = domainSidFor(companyId, by), memberSid = domainSidFor(companyId, acct);
      const userEmail = c.hostUser ?? c.victim ?? null;
      const create = winAccountCreate({
        id: "msel_twist_acct", ts: c.baseTs, companyId, host: a.dc, targetUser: acct, targetSid: memberSid, userEmail,
        subjectUser: by, subjectSid, samAccountName: acct, displayName: acct, upn: `${acct}@${a.domain}`, primaryGroupId: "513", uac: "%%2080 %%2082 %%2084",
        severity: "medium", description: `${by} created a new account, ${acct}, on ${a.dc}`,
      });
      const add = winGroupMemberAdd({
        id: "msel_twist_group", ts: c.baseTs, companyId, host: a.dc, targetUser: by, userEmail,
        eventId: global ? "4728" : "4732", subjectUser: by, subjectSid,
        memberName: `CN=${acct},CN=Users,DC=${a.domain.split(".").join(",DC=")}`, memberSid,
        groupName: group, groupDomain: global ? a.netbios : "Builtin", groupSid: BUILTIN[group] ?? domainSidFor(companyId, group),
        severity: "medium", description: `${acct} was added to ${group} on ${a.dc}`,
      });
      return { rows: [create, { ...add, raw: { ...add.raw, "event.action": global ? "added-member-to-group" : "added-member-to-local-group" } } as TelemetryEvent], vars: { acct, group, dc: a.dc } };
    } },
  // ── A story made only of failures or blocks never got in: its twist is the attacker trying again from a new
  //    exit node, and (when the story names the accounts it tried) sometimes one of them finally working.
  // Web injection round (2026-11-12): a web story's operator comes back to the same page from a new exit
  // node, the request it was blocked on first, then the same input double URL-encoded, which the rule does
  // not decode and lets through. Only where the session has a WAF and the story attacked a site from outside.
  { id: "web_return", fits: c => !!c.stack.waf && !!webTarget(c),
    texts: [
      "Web team: the {path} page on {site} (server {server}) is being hit again, now from {ip}. The block on the first address held. Same attacker? Did anything get through this time?",
      "The WAF dashboard shows a new source, {ip}, sending the same kind of requests to {site}{path} on {server} that you saw earlier. Is your containment holding?",
      "Application owner for {site} ({server}): requests to {path} started again a few minutes ago from {ip}. Should we take the page offline?",
    ],
    expected: "Pivot on the site, the path and the shape of the input, not on the address: the operator came back from a new exit node with a new encoding. Block the new source, read the WAF rows that were let through and the origin's answers to them (status, size, time), check the server for anything that ran after them, and ask the owner to fix or disable the page rather than chase addresses.",
    rows: c => {
      const t = webTarget(c)!;
      const ip = attackerIp(c);
      const base = { srcIp: ip, path: t.path, method: t.method, ua: t.ua, severity: "medium" as const };
      // The same input with every escape escaped once more (%3B -> %253B): the rule reads it once, the application twice.
      const twice = t.query.replace(/%([0-9A-Fa-f]{2})/g, "%25$1");
      const rows: TelemetryEvent[] = [
        wafRequest(t.site, { ...base, id: "msel_twist_web_1", ts: c.baseTs, query: t.query, action: "block", rule: t.rule, ...(t.matched ? { matched: t.matched } : {}), ...(t.location ? { location: t.location } : {}),
          description: `WAF rule matched a request to ${t.path}` }),
        wafRequest(t.site, { ...base, id: "msel_twist_web_2", ts: c.baseTs, query: twice, action: "allow", status: t.status, bytes: t.bytes, description: `WAF passed a request to ${t.path}` }),
        webAccess(t.site, { ...base, id: "msel_twist_web_3", ts: c.baseTs, query: twice, status: t.status, bytes: t.bytes, description: `Site answered a request to ${t.path}` }),
      ];
      return { rows, vars: { ip, site: t.site.site, path: t.path, server: t.site.host } };
    } },
  { id: "spray_resumes", fits: (c, g) => g.failedOnly && (g.sprayed.length > 0 || !!c.assets),
    texts: [
      "Identity team: the password spray is back, now from {ip}, a source the block did not cover. {user} is among the accounts it is trying. Did anything get in?",
      "Heads-up: bad-password attempts for {user} and other accounts started again a few minutes ago, from {ip}. Is your block holding, and did any of them succeed?",
      "A new burst of failed logons for {user} and others is coming from {ip}. Does your containment cover the new source?",
    ],
    expected: "Adapt: the attacker moved to a new exit node. Block the new address too, check every account it tried for a successful logon (reset and revoke any that succeeded) and keep the targeted accounts under watch.",
    rows: (c, g) => {
      const ip = attackerIp(c);
      const users = shuffledOf(g.sprayed, c.rnd).slice(0, 4);
      for (let k = 0; users.length < 3 && c.assets && k < 20; k++) {
        const r = pickOf(c.assets.roster, c.rnd), e = `${r.name}@${c.assets.domain}`;
        if (!users.includes(e) && !c.avoidUsers?.has(e)) users.push(e);
      }
      const win = !g.cloud && !!c.assets;
      const fail = (u: string, k: number) => win
        ? winFailedLogon({ id: `msel_twist_spray_${k}`, ts: c.baseTs, companyId: companyOf(c), host: c.assets!.dc, targetUser: u.split("@")[0], userEmail: u, srcIp: ip,
            subStatus: "0xC000006A", logonType: 3, authPackage: "NTLM", workstation: "-", severity: "medium", description: `Failed network logon for ${u.split("@")[0]} from ${ip}` })
        : cloudSignIn(c, { id: `msel_twist_spray_${k}`, user: u, ip, city: "", country: "", ok: false, description: `${u} failed to sign in from ${ip}` });
      const rows = users.map(fail);
      // One account the story itself sprayed now works: only an account the feed shows being tried.
      const known = g.sprayed.filter(u => users.includes(u));
      if (known.length && c.story && c.rnd() < 0.5) {
        const u = pickOf(known, c.rnd);
        rows.push(win
          ? winLogon({ id: "msel_twist_spray_hit", ts: c.baseTs, companyId: companyOf(c), host: c.assets!.dc, targetUser: u.split("@")[0], userEmail: u, srcIp: ip,
              logonType: 3, authPackage: "NTLM", workstation: "-", severity: "medium", description: `Network logon for ${u.split("@")[0]} from ${ip}` })
          : cloudSignIn(c, { id: "msel_twist_spray_hit", user: u, ip, city: "", country: "", ok: true, description: `${u} signed in from ${ip}` }));
      }
      return { rows, vars: { ip, user: users[0] } };
    } },
];
export const TWIST_KINDS = TWISTS.map(t => t.id);

const shuffledOf = <T,>(xs: T[], rnd: () => number): T[] => { const a = [...xs]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };

/** An Entra ID sign-in for a twist (relabelled in an Okta shop), the full SigninLogs row the stories' emitter writes. */
function cloudSignIn(c: TwistCtx, o: { id: string; user: string; ip: string; city: string; country: string; lat?: number; lon?: number; ok: boolean; description: string }): TelemetryEvent {
  const known = o.country !== "";
  return entraSignIn({
    id: o.id, ts: c.baseTs, companyId: companyOf(c), user: o.user, srcIp: o.ip, result: o.ok ? "success" : "failure", errorCode: o.ok ? undefined : "50126",
    app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000", resource: "Office 365 Exchange Online",
    mfa: false, isInteractive: true, managed: false, compliant: false, os: "Windows 10", browser: "Chrome 141.0.0",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    riskLevel: "none", riskEventTypes: [], riskDetail: "none", conditionalAccess: "notApplicable", incomingTokenType: "none",
    ...(known ? { geo: { city: o.city, country: o.country, ...(o.lat !== undefined ? { latitude: o.lat, longitude: o.lon } : {}) } } : {}),
    severity: "medium", description: o.description,
  });
}

/** The session's twist: the least recently used kind that this incident can carry, given what its story achieved. */
export function buildTwist(c: TwistCtx, seen: { twists: Record<string, number>; injects: Record<string, number> }, force?: string): TwistBuild | null {
  const order = force ? TWISTS.filter(t => t.id === force) : rankByHistory(TWISTS, t => t.id, seen.twists, c.rnd);
  const g = twistGround(c);
  for (const t of order) {
    if (!t.fits(c, g)) continue;
    const { rows, vars } = t.rows(c, g);
    const who = user0(c.victim);
    // A host the team saw is named as it is; a cloud-only story's twist lands on the victim's own device, and says so.
    const hostRef = c.seenHost || !who ? c.host : `${c.host} (${who}'s own device)`;
    const i = rankByHistory(t.texts.map((_, k) => k), k => `twist:${t.id}:${k}`, seen.injects, c.rnd)[0];
    const fill = (s: string) => s.replaceAll("{hostRef}", hostRef).replaceAll("{user}", vars.user ?? c.victim ?? c.hostUser ?? "the account")
      .replace(/\{(\w+)\}/g, (_m, k: string) => vars[k] ?? _m);
    return { kind: t.id, inject: { key: `twist:${t.id}:${i}`, text: fill(t.texts[i]), expected_response: t.expected, linked_objective: RE_OBJ }, rows };
  }
  return null;
}
