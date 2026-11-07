/**
 * The scripted curveballs of a team exercise (MSEL) and the logs behind them, in rotation
 * (owner, 2026-11-07: "no repetition"). Before, every session carried the same four inject texts,
 * the same Marketing-analytics decoy (a pool of three vendors, two fixed upload sizes) and the
 * same twist (rundll32 loading msupd###.dll). Now each session draws:
 *  - a DECOY of one of several kinds (analytics export, DR replication, data-room upload, auditor
 *    evidence upload, agency media hand-off, log backlog flush), each with its own reporter, host,
 *    destination, approval and believable volume against the host's own earlier transfer;
 *  - a TWIST of one of several kinds (second implant, new persistence, credential reuse, new remote
 *    session, new account), each backed by the logs a real product writes for it;
 *  - one of several texts for every inject.
 * The history ranking (variety.ts) keeps an organization from seeing the same kinds and texts in
 * consecutive exercises. Attacker infrastructure is fictional (documentation addresses, made-up
 * domains); partner endpoints are vendor names or fictional firms.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { CompanyAssets } from "@/lib/sim/companyProfilesMeta";
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
      "Marketing's manager messages the SOC: their newly approved product-analytics tool 'looks like data exfil' in the firewall logs, large uploads from {host} to {domain}. Is this a real incident?",
      "A Marketing analyst asks the SOC whether they broke something: the firewall dashboard shows {size} leaving {host} for {domain} this afternoon. Should they stop the export?",
    ],
    expected: "Recognise a sanctioned tool: the request is approved, the destination is the vendor's own ingestion endpoint and the host sent the same kind of batch earlier. Do NOT over-escalate. A decoy: discrimination, not detection.",
    dest: c => { const v = pickOf([["api2.amplitude.com", "amplitude", "Amplitude"], ["api-eu.mixpanel.com", "mixpanel", "Mixpanel"], ["heapanalytics.com", "heap-analytics", "Heap"], ["api.segment.io", "segment", "Segment"]] as const, c.rnd);
      return { domain: v[0], url: `https://${v[0]}/batch`, app: v[1], category: "business-and-economy", label: v[2] }; },
    sizes: { baseline: [40, 180], big: [600, 2600] },
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
    sizes: { baseline: [30, 120], big: [700, 3200] },
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
    const row = (k: number, bytes: number, fp: boolean): TelemetryEvent => ({
      id: `msel_false_lead_fw${k}`, ts: c.baseTs, source: "firewall", vendor: c.fw.vendor, event_type: "net_connection", severity: k === 0 ? "informational" : "medium",
      hostname: host, ...(user ? { user_email: user } : {}), src_ip: src, dst_ip: ip, dst_port: 443, protocol: "tcp",
      network: { url: dest.url, domain: dest.domain, method: "POST", bytes_out: bytes, bytes_in: Math.floor(bytes / intIn(600, 1400, c.rnd)) },
      description: `${k === 0 ? "Outbound HTTPS upload" : "Large outbound HTTPS upload"} from ${host} to ${dest.domain}`, ...(fp ? { fp_explanation: why } : {}),
      raw: firewallRaw(c.fw.flavour, { srcIp: src, dstIp: ip, domain: dest.domain, url: dest.url, category: dest.category, app: dest.app, bytesOut: bytes, bytesIn: Math.floor(bytes / 900), sessions: intIn(2, 40, c.rnd) }),
    } as TelemetryEvent);
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
  /** The host's operating system, read from the story's own process paths on it. */
  os: "windows" | "linux" | "mac";
}
export interface TwistBuild { kind: string; inject: InjectText; rows: TelemetryEvent[] }
interface TwistKind { id: string; fits: (c: TwistCtx) => boolean; texts: string[]; expected: string; rows: (c: TwistCtx, v: Record<string, string>) => { rows: TelemetryEvent[]; vars: Record<string, string> } }

const user0 = (e?: string) => (e ? e.split("@")[0] : undefined);
const RE_OBJ = "adaptability · re-scope on new evidence";
const TWISTS: TwistKind[] = [
  { id: "second_implant", fits: () => true,
    texts: [
      "EDR update: {hostRef} is now beaconing to a NEW C2 domain. The picture just changed: re-scope the incident and confirm your containment still holds.",
      "Threat hunting flagged {hostRef}: a process there is calling a domain nobody has seen before, on a steady interval. Is this part of your incident?",
      "Network team: {hostRef} started regular HTTPS check-ins to an unfamiliar domain about once a minute. Please look before the end of the shift.",
    ],
    expected: "Adapt: a second implant on a host already in the case. Re-open or re-scope the case (new IOC: the domain and its address), and check that containment covers it.",
    rows: (c) => {
      const domain = fakeC2Domain(c.rnd, c.domains), ip = docIp(c.rnd, c.ips);
      const userDir = user0(c.hostUser) ?? "Public";
      const unix = c.os !== "windows";
      const loader = c.proc && c.proc.name.toLowerCase() !== "rundll32.exe" && (unix || c.rnd() < 0.4) ? "story" : unix ? "unix" : pickOf(["rundll32", "regsvr32", "dropped"] as const, c.rnd);
      const dir = pickOf([`C:\\Users\\${userDir}\\AppData\\Local\\Temp`, `C:\\Users\\${userDir}\\AppData\\Roaming\\${pickOf(["Microsoft\\Crypto", "Adobe\\Updater", "Zoom\\bin"], c.rnd)}`, `C:\\ProgramData\\${pickOf(["Packages", "SoftwareDistribution", "USOShared"], c.rnd)}`], c.rnd);
      const stem = `${pickOf(["msupd", "wincfg", "cache", "svcmgr", "onedrv", "teamsx", "drvhlp", "netsvc"], c.rnd)}${intIn(10, 999, c.rnd)}`;
      const pid = c.proc?.pid ?? intIn(3000, 9000, c.rnd);
      const unixPath = c.os === "mac" ? `/Users/${userDir}/Library/Application Support/${stem.replace(/\d+$/, "")}/${stem}` : pickOf([`/tmp/.${stem}`, `/var/tmp/${stem}`, `/dev/shm/.${stem}`], c.rnd);
      const p = loader === "story" ? { name: c.proc!.name, path: c.proc!.path ?? (unix ? unixPath : `${dir}\\${c.proc!.name}`), cmdline: c.proc!.cmdline ?? c.proc!.name, parent: c.proc!.parent ?? (unix ? "bash" : "explorer.exe") }
        : loader === "unix" ? { name: unixPath.split("/").pop()!, path: unixPath, cmdline: `${unixPath} ${pickOf(["-d", "--daemon", "-q"], c.rnd)}`, parent: c.os === "mac" ? "launchd" : pickOf(["bash", "sh", "systemd"], c.rnd) }
        : loader === "rundll32" ? { name: "rundll32.exe", path: "C:\\Windows\\System32\\rundll32.exe", cmdline: `"C:\\Windows\\System32\\rundll32.exe" ${dir}\\${stem}.dll,${pickOf(["DllRegisterServer", "StartW", "Run", "EntryPoint"], c.rnd)}`, parent: pickOf(["explorer.exe", "svchost.exe"], c.rnd) }
        : loader === "regsvr32" ? { name: "regsvr32.exe", path: "C:\\Windows\\System32\\regsvr32.exe", cmdline: `"C:\\Windows\\System32\\regsvr32.exe" /s ${dir}\\${stem}.dll`, parent: "explorer.exe" }
        : { name: `${stem}.exe`, path: `${dir}\\${stem}.exe`, cmdline: `"${dir}\\${stem}.exe" ${pickOf(["-k netsvc", "/silent", "--update"], c.rnd)}`, parent: pickOf(["explorer.exe", "taskeng.exe", "svchost.exe"], c.rnd) };
      const urlPath = pickOf(["/api/v2/status", "/cdn/sync", "/v1/telemetry", "/static/poll", "/updates/check"], c.rnd);
      const out = intIn(900, 4800, c.rnd), inn = intIn(300, 1400, c.rnd);
      const ctx: ProcCtx = { path: p.path, cmdline: p.cmdline, parent: p.parent, account: user0(c.hostUser) };
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
        hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp, dst_ip: ip, dst_port: 443, protocol: "tcp",
        process: { name: p.name, pid, path: p.path, cmdline: p.cmdline, parent_name: p.parent, ...(c.hostUser ? { user: user0(c.hostUser) } : {}) },
        description: `${p.name} on ${c.host} connected to ${ip}:443`,
        raw: edrConnRaw(c.edr, c.host, p.name, pid, c.hostIp, ip, domain, ctx),
      } as TelemetryEvent;
      return { rows: [dns, fw, edr], vars: { domain, ip } };
    } },
  { id: "new_persistence", fits: () => true,
    texts: [
      "EDR update: something on {hostRef} just set itself up to start again after a reboot. Check whether your containment covers it.",
      "Endpoint team: a new autostart entry appeared on {hostRef} a moment ago, pointing at a file in a user-writable folder. Does this change your case?",
      "Heads-up from the EDR console: {hostRef} has a fresh persistence mechanism. The incident may not be over.",
    ],
    expected: "Adapt: the attacker added persistence on a host in the case. Re-scope (the autostart entry and its file are new IOCs) and make sure the eradication plan removes it.",
    rows: (c) => {
      const userDir = user0(c.hostUser) ?? "Public";
      const pid = intIn(3000, 9000, c.rnd);
      const who = c.hostUser ? { user: user0(c.hostUser) } : {};
      if (c.os !== "windows") {
        const stem = `${pickOf(["dbus-helper", "kworkerd", "update-notifier", "netcheck", "syncd"], c.rnd)}${intIn(1, 99, c.rnd)}`;
        const mac = c.os === "mac";
        const file = mac ? `/Users/${userDir}/Library/Application Support/.${stem}/${stem}` : pickOf([`/var/tmp/.${stem}`, `/usr/local/lib/.${stem}/${stem}`, `/home/${userDir}/.cache/${stem}`], c.rnd);
        const how = mac ? "launchd" : pickOf(["cron", "systemd"] as const, c.rnd);
        const cmd = how === "launchd" ? `launchctl load -w /Users/${userDir}/Library/LaunchAgents/com.${stem}.plist`
          : how === "cron" ? `/bin/sh -c (crontab -l 2>/dev/null; echo "*/${pickOf([5, 10, 15], c.rnd)} * * * * ${file}") | crontab -`
          : `systemctl enable --now ${stem}.service`;
        const tool = how === "launchd" ? "launchctl" : how === "cron" ? "crontab" : "systemctl";
        const first: TelemetryEvent = {
          id: "msel_twist_persist", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "process_create", severity: "medium",
          hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp,
          process: { name: tool, pid, path: mac ? `/bin/${tool}` : `/usr/bin/${tool}`, parent_name: mac ? "zsh" : "bash", parent_pid: pid - 12, cmdline: cmd, ...who },
          description: `${tool} added an autostart entry on ${c.host}`,
          raw: { "process.name": tool, "host.name": c.host },
        } as TelemetryEvent;
        const run: TelemetryEvent = {
          id: "msel_twist_run", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "process_create", severity: "medium",
          hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp,
          process: { name: file.split("/").pop()!, pid: pid + intIn(40, 400, c.rnd), path: file, cmdline: file, parent_name: how === "launchd" ? "launchd" : how === "cron" ? "cron" : "systemd", parent_pid: pid + 3, ...who },
          description: `${file.split("/").pop()} started on ${c.host}`,
          raw: { "process.name": file.split("/").pop(), "host.name": c.host },
        } as TelemetryEvent;
        return { rows: [first, run], vars: { file } };
      }
      const stem = `${pickOf(["OneDriveSync", "AdobeUpd", "TeamsHelper", "EdgeUpdateCore", "PrintSvcHost"], c.rnd)}${intIn(1, 99, c.rnd)}`;
      const file = `${pickOf([`C:\\Users\\${userDir}\\AppData\\Roaming`, "C:\\ProgramData", `C:\\Users\\${userDir}\\AppData\\Local`], c.rnd)}\\${pickOf(["Microsoft", "Updater", "Cache"], c.rnd)}\\${stem.toLowerCase()}.exe`;
      const how = pickOf(["run_key", "task", "service"] as const, c.rnd);
      const first: TelemetryEvent = how === "run_key" ? {
        id: "msel_twist_persist", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "registry_set", severity: "medium",
        hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp,
        process: { name: "reg.exe", pid, path: "C:\\Windows\\System32\\reg.exe", parent_name: "cmd.exe", parent_pid: pid - 12, cmdline: `reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v ${stem} /t REG_SZ /d "${file}" /f`, ...(c.hostUser ? { user: user0(c.hostUser) } : {}) },
        registry: { path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", key: stem, value: file },
        description: `A Run key value ${stem} was set on ${c.host}`,
        raw: { "event.action": "registry_value_set", "registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry.key": stem, "registry.value": file, "process.name": "reg.exe", "host.name": c.host },
      } as TelemetryEvent : how === "task" ? {
        id: "msel_twist_persist", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "scheduled_task", severity: "medium",
        hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp,
        process: { name: "schtasks.exe", pid, path: "C:\\Windows\\System32\\schtasks.exe", parent_name: "cmd.exe", parent_pid: pid - 12,
          cmdline: `schtasks.exe /create /tn "${stem}" /sc ${pickOf(["onlogon", "minute /mo 15", "daily /st 09:00"], c.rnd)} /tr "${file}" /f`, ...(c.hostUser ? { user: user0(c.hostUser) } : {}) },
        description: `schtasks.exe created the scheduled task ${stem} on ${c.host}`,
        raw: { "process.name": "schtasks.exe", "host.name": c.host },
      } as TelemetryEvent : {
        id: "msel_twist_persist", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "service_install", severity: "medium",
        hostname: c.host, src_ip: c.hostIp,
        process: { name: "sc.exe", pid, path: "C:\\Windows\\System32\\sc.exe", parent_name: "cmd.exe", parent_pid: pid - 12, cmdline: `sc.exe create ${stem} binPath= "${file}" start= auto`, user: "SYSTEM" },
        description: `sc.exe installed the service ${stem} on ${c.host}`,
        raw: { "process.name": "sc.exe", "host.name": c.host, "service.name": stem, "service.path": file },
      } as TelemetryEvent;
      const run: TelemetryEvent = {
        id: "msel_twist_run", ts: c.baseTs, source: "edr", vendor: c.edr, event_type: "process_create", severity: "medium",
        hostname: c.host, user_email: c.hostUser, src_ip: c.hostIp,
        process: { name: file.split("\\").pop()!, pid: pid + intIn(40, 400, c.rnd), path: file, cmdline: `"${file}"`, parent_name: how === "service" ? "services.exe" : how === "task" ? "svchost.exe" : "explorer.exe", parent_pid: pid + 3, ...(c.hostUser ? { user: user0(c.hostUser) } : {}) },
        description: `${file.split("\\").pop()} started on ${c.host}`,
        raw: { "process.name": file.split("\\").pop(), "host.name": c.host },
      } as TelemetryEvent;
      return { rows: [first, run], vars: { file } };
    } },
  { id: "credential_reuse", fits: c => !!c.victim,
    texts: [
      "Identity team: {user} just signed in from an address the company has never seen, after your incident started. Did the password reset happen?",
      "Entra / Okta update: a fresh sign-in for {user} from {ip}, then mail access. The account may still be in the attacker's hands.",
      "The help desk says {user} is at their desk, yet their account just signed in from somewhere else. Is this connected to your case?",
    ],
    expected: "Adapt: the stolen credentials are being reused. Re-scope to the account, revoke its sessions, reset the password and block the new address.",
    rows: (c) => {
      const ip = docIp(c.rnd, c.ips), u = c.victim!;
      const [city, country, lat, lon] = pickOf([["Bucharest", "Romania", 44.4268, 26.1025], ["Kuala Lumpur", "Malaysia", 3.139, 101.6869], ["Lagos", "Nigeria", 6.5244, 3.3792], ["Sao Paulo", "Brazil", -23.5505, -46.6333], ["Hanoi", "Vietnam", 21.0278, 105.8342]] as const, c.rnd);
      const signin: TelemetryEvent = {
        id: "msel_twist_signin", ts: c.baseTs, source: "o365", vendor: "Microsoft Entra ID", event_type: "auth_success", severity: "medium",
        user_email: u, src_ip: ip, description: `${u} signed in from ${city}, ${country} (${ip})`,
        raw: { "data.office365.Operation": "UserLoggedIn", "data.office365.Workload": "AzureActiveDirectory", "data.office365.AzureActiveDirectoryEventType": "AccountLogon",
          "data.office365.UserId": u, "data.office365.ActorIpAddress": ip, "data.office365.ClientIP": ip, "data.office365.ResultStatus": "Succeeded",
          "GeoLocation.country_name": country, "GeoLocation.city_name": city, "GeoLocation.location.lat": lat, "GeoLocation.location.lon": lon, action_result: "allowed" },
      } as TelemetryEvent;
      const access: TelemetryEvent = c.stack.collab === "m365" ? {
        id: "msel_twist_access", ts: c.baseTs, source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "sharepoint_download", severity: "low",
        user_email: u, src_ip: ip, description: `${u} downloaded a file from SharePoint`,
        raw: { "data.office365.Operation": "FileDownloaded", "data.office365.Workload": "SharePoint", "data.office365.SiteUrl": `https://${(c.assets?.domain ?? "corp.com").split(".")[0]}.sharepoint.com/sites/${pickOf(["Finance", "HR", "Projects"], c.rnd)}`,
          "data.office365.SourceFileName": pickOf(["Q3_forecast.xlsx", "Org_chart_2026.pdf", "Vendor_contacts.xlsx", "Board_pack_draft.docx"], c.rnd), "data.office365.ResultStatus": "Succeeded", "data.office365.ClientIP": ip },
      } as TelemetryEvent : { ...signin, id: "msel_twist_access", event_type: "auth_success", description: `${u} signed in again from ${ip}` } as TelemetryEvent;
      return { rows: [signin, access], vars: { ip, user: u } };
    } },
  { id: "new_remote_session", fits: c => !!c.stack.onprem_ad && !!c.assets && c.os === "windows",
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
      const logon: TelemetryEvent = {
        id: "msel_twist_logon", ts: c.baseTs, source: "windows_security", vendor: "Windows Security", event_type: "auth_success", severity: "informational",
        hostname: target, ...(c.hostUser || c.victim ? { user_email: c.hostUser ?? c.victim } : {}), src_ip: c.hostIp,
        description: `${u} logged on to ${target} (Remote Desktop)`,
        raw: { "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.event_id": "4624", "event.code": "4624",
          "winlog.computer_name": target, "winlog.event_data.TargetUserName": u, "winlog.event_data.TargetDomainName": a.netbios, "winlog.event_data.LogonType": "10",
          "winlog.event_data.LogonProcessName": "User32 ", "winlog.event_data.AuthenticationPackageName": "Negotiate", "winlog.event_data.WorkstationName": c.host,
          "winlog.event_data.IpAddress": c.hostIp, "winlog.event_data.TargetLogonId": `0x${intIn(0x100000, 0xFFFFFF, c.rnd).toString(16).toUpperCase()}` },
      } as TelemetryEvent;
      return { rows: [fw, logon], vars: { target } };
    } },
  { id: "new_account", fits: c => !!c.stack.onprem_ad && !!c.assets,
    texts: [
      "Directory alert: a new account, {acct}, appeared on {dc} and was put in {group}. The request did not come through IT.",
      "The identity team spotted an account nobody requested, {acct}, created on {dc} from the session you are investigating. Does this change your scope?",
      "AD change report: {acct} was created on {dc} and added to {group} a few minutes ago. IT says it is not theirs.",
    ],
    expected: "Adapt: the attacker created a backdoor account. Add it to the scope, disable it, and check which session created it.",
    rows: (c) => {
      const a = c.assets!;
      const acct = pickOf(["svc-", "adm-", "it-", "sql"], c.rnd) + pickOf(["sync", "backup2", "monitor", "helpdesk", "update", "report"], c.rnd) + (c.rnd() < 0.5 ? String(intIn(1, 9, c.rnd)) : "");
      const group = pickOf(["Remote Desktop Users", "Backup Operators", "Server Operators", "IT-Admins"], c.rnd);
      const by = user0(c.hostUser ?? c.victim) ?? "administrator";
      const sid = `S-1-5-21-${intIn(1000000000, 3999999999, c.rnd)}-${intIn(1000000000, 3999999999, c.rnd)}-${intIn(1000000000, 3999999999, c.rnd)}`;
      const rid = intIn(1150, 1900, c.rnd);
      const create: TelemetryEvent = {
        id: "msel_twist_acct", ts: c.baseTs, source: "ad", vendor: "Windows Security", event_type: "account_create", severity: "medium", hostname: a.dc,
        ...(c.hostUser || c.victim ? { user_email: c.hostUser ?? c.victim } : {}), description: `${by} created a new account, ${acct}, on ${a.dc}`,
        raw: { "winlog.event_id": "4720", "winlog.channel": "Security", "winlog.computer_name": a.dc, "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "event.code": "4720",
          "winlog.event_data.SubjectUserName": by, "winlog.event_data.SubjectDomainName": a.netbios, "winlog.event_data.TargetUserName": acct, "winlog.event_data.TargetDomainName": a.netbios,
          "winlog.event_data.TargetSid": `${sid}-${rid}`, "winlog.event_data.SamAccountName": acct, "event.action": "user-account-created", "event.outcome": "success", "host.name": a.dc },
      } as TelemetryEvent;
      const add: TelemetryEvent = {
        id: "msel_twist_group", ts: c.baseTs, source: "ad", vendor: "Windows Security", event_type: "group_modify", severity: "medium", hostname: a.dc,
        ...(c.hostUser || c.victim ? { user_email: c.hostUser ?? c.victim } : {}), description: `${acct} was added to ${group} on ${a.dc}`,
        raw: { "winlog.event_id": group === "IT-Admins" ? "4728" : "4732", "event.code": group === "IT-Admins" ? "4728" : "4732", "winlog.channel": "Security", "winlog.computer_name": a.dc,
          "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.event_data.SubjectUserName": by, "winlog.event_data.SubjectDomainName": a.netbios,
          "winlog.event_data.MemberSid": `${sid}-${rid}`, "winlog.event_data.TargetUserName": group, "winlog.event_data.TargetDomainName": group === "IT-Admins" ? a.netbios : "Builtin",
          "event.action": group === "IT-Admins" ? "added-member-to-group" : "added-member-to-local-group", "event.outcome": "success", "host.name": a.dc },
      } as TelemetryEvent;
      return { rows: [create, add], vars: { acct, group, dc: a.dc } };
    } },
];
export const TWIST_KINDS = TWISTS.map(t => t.id);

/** The session's twist: the least recently used kind that this incident can carry. */
export function buildTwist(c: TwistCtx, seen: { twists: Record<string, number>; injects: Record<string, number> }, force?: string): TwistBuild | null {
  const order = force ? TWISTS.filter(t => t.id === force) : rankByHistory(TWISTS, t => t.id, seen.twists, c.rnd);
  for (const t of order) {
    if (!t.fits(c)) continue;
    const { rows, vars } = t.rows(c, {});
    const who = user0(c.victim);
    // A host the team saw is named as it is; a cloud-only story's twist lands on the victim's own device, and says so.
    const hostRef = c.seenHost || !who ? c.host : `${c.host} (${who}'s own device)`;
    const i = rankByHistory(t.texts.map((_, k) => k), k => `twist:${t.id}:${k}`, seen.injects, c.rnd)[0];
    const fill = (s: string) => s.replaceAll("{hostRef}", hostRef).replaceAll("{user}", c.victim ?? c.hostUser ?? "the account")
      .replace(/\{(\w+)\}/g, (_m, k: string) => vars[k] ?? _m);
    return { kind: t.id, inject: { key: `twist:${t.id}:${i}`, text: fill(t.texts[i]), expected_response: t.expected, linked_objective: RE_OBJ }, rows };
  }
  return null;
}
