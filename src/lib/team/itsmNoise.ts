/**
 * ITSM rows that explain nothing (expert review 2026-11-07: an approved ticket sat right before
 * every benign-positive alert and never before an attack, so "a ticket just fired" was the
 * answer). A real ServiceNow feed is mostly unrelated work: printers, access requests, standard
 * changes, laptop swaps. These rows are that background, drawn per session from the company's
 * own people and hosts, and the timeline also places some of them right before attack rows.
 *
 * Also the one converter from a maker's TicketSpec to a ServiceNow record, so a covering ticket
 * and a noise ticket have the same shape (same fields, same states, a CI and a person on both).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { CompanyAssets } from "@/lib/sim/companyProfilesMeta";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import type { TicketSpec } from "./fpAlerts";
import { intIn, pickOf, shuffled } from "./variety";

/** A ServiceNow record for a ticket spec. `window` (change requests) is filled in later by the timeline, once times are final. */
export function ticketRecord(spec: TicketSpec, companyId: string, id: string, ts: string): TelemetryEvent {
  const approved = spec.table !== "incident";
  const kind = spec.table === "incident" ? "incident" : spec.table === "sc_req_item" ? "request" : "change";
  return serviceNowRecord({
    companyId, id, ts, table: spec.table, number: spec.number, state: spec.state, shortDescription: spec.short, severity: "informational",
    extra: {
      ...(approved ? { "servicenow.approval": "Approved" } : {}),
      ...(spec.requestedFor ? { "servicenow.requested_for": spec.requestedFor } : {}),
      ...(spec.ci ? { "servicenow.cmdb_ci": spec.ci } : {}),
      ...(spec.assignedTo ? { "servicenow.assigned_to": spec.assignedTo } : {}),
      ...(spec.group ? { "servicenow.assignment_group": spec.group } : {}),
      ...(spec.workNotes ? { "servicenow.work_notes": spec.workNotes } : {}),
      ...(spec.table === "change_request" ? { "servicenow.type": /standard|scan|schedule|wave/i.test(spec.short) ? "standard" : "normal" } : {}),
    },
    description: `ServiceNow ${kind} ${spec.number} (${spec.state}): ${spec.short}`,
  } as Parameters<typeof serviceNowRecord>[0]);
}

const isServer = (h: string) => /^(SRV|SVR|DC)-|-SRV-|prod-srv|-DC\d/i.test(h);

/**
 * `count` unrelated ITSM records (with a change window in minutes around the record's own time) for the session: a mix of incidents, requests and changes, some
 * approved, some not, each naming a real person or host of the company. Never on the people /
 * hosts in `avoid` (an attack's victim with an unrelated ticket would be a false trail by design,
 * not background).
 */
export function itsmNoise(assets: CompanyAssets | undefined, companyId: string, count: number, rnd: () => number, ts: string,
  avoid: { users?: Set<string>; hosts?: Set<string> } = {}): { ev: TelemetryEvent; window?: [number, number] }[] {
  if (!assets || count <= 0) return [];
  const people = shuffled(assets.roster.map(r => `${r.name}@${assets.domain}`).filter(u => !avoid.users?.has(u)), rnd);
  const hosts = shuffled(assets.hosts.filter(h => !avoid.hosts?.has(h)), rnd);
  const ws = hosts.filter(h => !isServer(h)), srv = hosts.filter(isServer);
  const who = () => pickOf(people.length ? people : [`servicedesk@${assets.domain}`], rnd);
  const n = (p: string) => `${p}00${intIn(30000, 69999, rnd)}`;
  const makers: (() => TicketSpec)[] = [
    () => ({ table: "incident", number: n("INC"), state: pickOf(["New", "In Progress", "Resolved"], rnd), short: `Printer on floor ${intIn(1, 6, rnd)} shows offline`, requestedFor: who(), group: "Service Desk" }),
    () => ({ table: "incident", number: n("INC"), state: pickOf(["In Progress", "Resolved"], rnd), short: "Teams calls drop after a few minutes", requestedFor: who(), group: "Collaboration Services" }),
    () => ({ table: "incident", number: n("INC"), state: "Resolved", short: "Forgot password, reset at the walk-up desk", requestedFor: who(), group: "Service Desk", workNotes: "Identity checked in person against the staff badge." }),
    () => ({ table: "incident", number: n("INC"), state: "In Progress", short: `Laptop battery swelling, swap required`, requestedFor: who(), ci: ws.length ? pickOf(ws, rnd) : undefined, group: "End User Computing" }),
    () => ({ table: "sc_req_item", number: n("RITM"), state: pickOf(["Open", "Work in Progress", "Closed Complete"], rnd), short: "Second monitor and docking station", requestedFor: who(), group: "End User Computing" }),
    () => ({ table: "sc_req_item", number: n("RITM"), state: pickOf(["Open", "Closed Complete"], rnd), short: "Access to the shared mailbox for the team", requestedFor: who(), group: "Identity and Access" }),
    () => ({ table: "sc_req_item", number: n("RITM"), state: pickOf(["Pending", "Closed Complete"], rnd), short: `Software request: ${pickOf(["Adobe Acrobat Pro", "Visio", "Power BI Pro", "Snagit"], rnd)}`, requestedFor: who(), group: "Software Licensing" }),
    () => ({ table: "change_request", number: n("CHG"), state: pickOf(["Scheduled", "Implement", "Review"], rnd), short: "Renew the TLS certificate on the intranet portal", ci: srv.length ? pickOf(srv, rnd) : undefined, assignedTo: who(), group: "Windows Server Team", window: [intIn(-600, -120, rnd), intIn(-60, 600, rnd)] }),
    () => ({ table: "change_request", number: n("CHG"), state: pickOf(["Scheduled", "Implement"], rnd), short: "Firmware update on the core switch stack", group: "Network Engineering", assignedTo: who(), window: [intIn(120, 600, rnd), intIn(660, 900, rnd)] }),
    () => ({ table: "change_request", number: n("CHG"), state: pickOf(["Authorize", "Scheduled"], rnd), short: "Add a firewall rule for the new courier API", group: "Network Engineering", assignedTo: who(), window: [intIn(240, 720, rnd), intIn(780, 1000, rnd)] }),
    () => ({ table: "change_request", number: n("CHG"), state: "Closed", short: "Disk extension on the reporting database", ci: srv.length ? pickOf(srv, rnd) : undefined, assignedTo: who(), group: "Infrastructure Operations", window: [intIn(-1200, -900, rnd), intIn(-840, -700, rnd)] }),
    () => ({ table: "incident", number: n("INC"), state: "New", short: "VPN slow from home in the evening", requestedFor: who(), group: "Network Engineering" }),
  ];
  return shuffled(makers, rnd).concat(shuffled(makers, rnd)).slice(0, count).map((mk, i) => {
    const spec = mk();
    return { ev: ticketRecord(spec, companyId, `itsm_noise_${i}`, ts), window: spec.window };
  });
}
