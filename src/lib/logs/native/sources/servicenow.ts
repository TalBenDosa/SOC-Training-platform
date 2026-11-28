/**
 * ServiceNow ITSM - native module (card: docs/log-schemas/itsm-servicenow.md).
 *
 * Record: the REST Table API response for ONE record, exactly as returned in the default
 * raw mode (`sysparm_display_value=false`): `{"result": {...}}`, every scalar a string,
 * choice fields as their stored value ("state": "2", "approval": "approved"), date/times
 * "YYYY-MM-DD HH:MM:SS" UTC, reference fields as `{link, value}` objects pointing at the
 * referenced table (sys_user, sys_user_group, cmdb_ci …), `sys_created_by` /
 * `sys_updated_by` as user_name strings. Journal fields (`work_notes`, `comments`) carry the
 * ticket's journal as the SIEM connector reads it - the entry list ServiceNow returns for a journal
 * field read with display values (`<sys_created_on> - <user> (Work notes)` + the text) - because
 * the notes ARE the evidence (how the caller was verified, what the agent did); a ticket with no
 * authored note returns them empty. resolved_at / closed_at follow the ticket's own timeline: the
 * authored value, else the record's time when the state says it was resolved / closed - never
 * later than the record itself.
 *
 * CMDB configuration items (cmdb_ci_computer, cmdb_ci_ip_firewall, ...) are the one exception to raw
 * mode: an analyst checking who owns a device reads the CI the way the CMDB form and the SIEM lookup
 * show it, the Table API with `sysparm_display_value=true`, so choices read as their labels
 * ("install_status": "Installed") and references as `{display_value, link}` (the person, the
 * department and the location by name). Without it, "who owns this laptop" would be a sys_id.
 *
 * Input: `source:"soar"` events whose vendor is ServiceNow - the records produced by
 * src/lib/sim/emitters/servicenow.ts (`serviceNowRecord`, legacy `servicenow.*` raw keys).
 * Stable ids: a ticket's sys_id is derived from its number, a user's sys_user sys_id from
 * the email, a group's from its name - so every update of one ticket, and every ticket of
 * one person, correlates. Non-ServiceNow SOAR events have no ITSM record → null.
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";

const P = (...f: string[]) => f.map(x => `result.${x}`);
const COMMON = P("short_description", "description", "priority", "impact", "urgency", "assignment_group", "assigned_to", "opened_by", "opened_at",
  "sys_created_on", "sys_created_by", "approval", "work_notes", "comments", "cmdb_ci", "company", "location", "close_code", "close_notes");
const REQUIRED = P("sys_id", "number", "sys_class_name", "state", "active", "sys_updated_on", "sys_updated_by", "sys_mod_count");

const kinds: Record<string, KindSchema> = {
  incident: {
    required: REQUIRED,
    optional: [...COMMON, ...P("caller_id", "category", "subcategory", "contact_type", "hold_reason", "resolved_at", "closed_at", "incident_state"),
      // Customer-defined columns (ServiceNow prefixes custom columns with u_). Not on the card - they carry the
      // help-desk identity-verification evidence the vishing stories turn on.
      ...P("u_identity_verification", "u_verification_result")],
  },
  change_request: {
    required: REQUIRED,
    optional: [...COMMON, ...P("type", "requested_by", "start_date", "end_date", "risk", "phase", "justification", "implementation_plan", "backout_plan", "test_plan", "chg_model")],
  },
  sc_req_item: {
    required: REQUIRED,
    optional: [...COMMON, ...P("request", "cat_item", "requested_for", "quantity", "stage", "due_date")],
  },
};

// CMDB configuration items (the class label is what sys_class_name reads in display-value mode).
const CMDB_CLASS: Record<string, string> = {
  cmdb_ci_computer: "Computer", cmdb_ci_ip_firewall: "IP Firewall", cmdb_ci_server: "Server",
  cmdb_ci_win_server: "Windows Server", cmdb_ci_linux_server: "Linux Server",
};
const CMDB_REQUIRED = P("sys_id", "name", "sys_class_name", "sys_updated_on", "sys_updated_by", "sys_mod_count");
const CMDB_OPTIONAL = P("asset_tag", "serial_number", "manufacturer", "model_id", "os", "os_version", "ip_address", "assigned_to",
  "department", "location", "company", "install_status", "operational_status", "discovery_source", "last_discovered", "short_description",
  "sys_created_on", "sys_created_by");
for (const table of Object.keys(CMDB_CLASS)) kinds[table] = { required: CMDB_REQUIRED, optional: CMDB_OPTIONAL };
// One journal entry (a work note or a comment) of a ticket: where the Table API keeps the text that the
// ticket's own work_notes / comments columns return empty. element_id is the ticket's sys_id.
kinds.sys_journal_field = { required: P("sys_id", "element", "element_id", "name", "value", "sys_created_by", "sys_created_on"), optional: [] };
const CMDB_BY_LABEL = new Map(Object.entries(CMDB_CLASS).map(([t, l]) => [l, t]));
// install_status / operational_status choice labels (out-of-the-box values).
const INSTALL_STATUS: Record<string, string> = { "1": "Installed", "2": "On Order", "3": "In Maintenance", "4": "Pending Install", "5": "Pending Repair", "6": "In Stock", "7": "Retired", "100": "Absent" };
const OPERATIONAL_STATUS: Record<string, string> = { "1": "Operational", "2": "Non-Operational", "3": "Repair in Progress", "4": "DR Standby", "5": "Ready", "6": "Retired" };

export function kindOf(record: Record<string, unknown>): string | null {
  const r = record.result as Record<string, unknown> | undefined;
  if (!r || typeof r !== "object" || Array.isArray(r)) return null;
  if (typeof r.element === "string" && typeof r.element_id === "string") return "sys_journal_field";
  // Display-value mode (sysparm_display_value=all) wraps every field in {display_value, value}; not rendered.
  if (typeof r.sys_class_name !== "string") return null;
  if (kinds[r.sys_class_name] && !CMDB_CLASS[r.sys_class_name]) return r.sys_class_name;
  return CMDB_BY_LABEL.get(r.sys_class_name) ?? null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
const str = (v: unknown): string | undefined => (v === undefined || v === null || v === "" ? undefined : String(v));
function hx(ctx: NativeCtx, seed: string, len: number): string {
  let s = "";
  for (let i = 0; s.length < len; i++) s += ctx.hex(`${i}|${seed}`, 8);
  return s.slice(0, len);
}
/** sys_id of a referenced record (stable per company + table + natural key). */
export function sysId(ctx: NativeCtx, table: string, key: string): string {
  return hx(ctx, `${ctx.companyId}:snow:${table}:${key.trim().toLowerCase()}`, 32);
}
function ref(ctx: NativeCtx, table: string, key: string) {
  const value = sysId(ctx, table, key);
  return { link: `https://${ctx.org}.service-now.com/api/now/table/${table}/${value}`, value };
}
const userName = (v: string) => (v.includes("@") ? v.split("@")[0] : v);
/** "j.oduya@x" → "J Oduya" (a journal entry names its author by display name). */
const displayName = (v: string) => userName(v).split(/[._]/).filter(Boolean).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
const DT = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
const snowTime = (v: string) => (DT.test(v) ? v : new Date(v).toISOString().slice(0, 19).replace("T", " "));

const STATES: Record<string, Record<string, string>> = {
  incident: { new: "1", "in progress": "2", "on hold": "3", resolved: "6", closed: "7", canceled: "8", cancelled: "8" },
  change_request: { new: "-5", assess: "-4", authorize: "-3", scheduled: "-2", implement: "-1", review: "0", closed: "3", canceled: "4", cancelled: "4" },
  sc_req_item: { pending: "-5", open: "1", "work in progress": "2", "closed complete": "3", "closed incomplete": "4", "closed skipped": "7" },
};
const CLOSED: Record<string, string[]> = { incident: ["7", "8"], change_request: ["3", "4"], sc_req_item: ["3", "4", "7"] };
const RISK: Record<string, string> = { "very high": "1", high: "2", moderate: "3", medium: "3", low: "4" };
const num15 = (v?: string) => (v ? (/^\d/.test(v) ? v.match(/^\d+/)![0] : undefined) : undefined);
const choice = (v?: string) => (v ? v.trim().toLowerCase().replace(/\s+/g, "_") : undefined);

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!(ev.vendor ?? "").toLowerCase().includes("servicenow")) return null;
  const raw = ev.raw ?? {};
  const sn = (k: string) => str(raw[`servicenow.${k}`]);
  const table = sn("table");
  if (table && CMDB_CLASS[table]) return cmdbRecord(ev, ctx, table, sn);
  if (table === "sys_journal_field") return journalRecord(ev, ctx, sn);
  const number = sn("number");
  if (!table || !kinds[table] || !number) return null;

  const stateRaw = sn("state") ?? "";
  const state = /^-?\d+$/.test(stateRaw) ? stateRaw : STATES[table][stateRaw.toLowerCase()] ?? (table === "change_request" ? "-5" : "1");
  const closed = CLOSED[table].includes(state);
  const isNew = state === STATES[table][table === "sc_req_item" ? "open" : "new"];
  const impact = num15(sn("impact"));
  const urgency = num15(sn("urgency"));
  const priority = num15(sn("priority")) ?? (impact && urgency ? String(Math.min(5, Math.max(1, Number(impact) + Number(urgency) - 1))) : undefined);
  const opener = sn("opened_by");
  const assignee = sn("assigned_to");
  const resolver = sn("resolved_by");
  const updatedBy = sn("sys_updated_by") ?? (resolver && /resolved|closed/i.test(stateRaw) ? resolver : undefined) ?? assignee ?? opener ?? "system";
  // The record is read at ev.ts: nothing in it happened later than that.
  const recTime = snowTime(ev.ts);
  const notAfter = (t: string) => (t > recTime ? recTime : t);
  const openedAt = sn("opened_at") ? notAfter(snowTime(sn("opened_at")!)) : isNew ? recTime : undefined;
  const createdOn = sn("sys_created_on") ? notAfter(snowTime(sn("sys_created_on")!)) : openedAt;
  const rank = closed ? 6 : /resolved/i.test(stateRaw) || state === "6" ? 5 : isNew ? 0 : 2;
  const result: Record<string, unknown> = {
    sys_id: sysId(ctx, table, number),
    number,
    sys_class_name: table,
    state,
    active: String(!closed),
  };
  const put = (k: string, v: unknown) => { if (v !== undefined) result[k] = v; };

  put("short_description", sn("short_description"));
  put("description", sn("description"));
  put("priority", priority);
  put("impact", impact);
  put("urgency", urgency);
  put("approval", sn("approval")?.toLowerCase());
  put("assignment_group", sn("assignment_group") ? ref(ctx, "sys_user_group", sn("assignment_group")!) : undefined);
  put("assigned_to", assignee ? ref(ctx, "sys_user", assignee) : undefined);
  // A CI has ONE sys_id, in cmdb_ci and in its class table alike (table-per-class): the ticket's
  // reference and the CI record read from cmdb_ci_computer carry the same value (ciSysId).
  put("cmdb_ci", sn("cmdb_ci") ? { link: `https://${ctx.org}.service-now.com/api/now/table/cmdb_ci/${ciSysId(ctx, sn("cmdb_ci")!)}`, value: ciSysId(ctx, sn("cmdb_ci")!) } : undefined);

  if (table === "incident") {
    const caller = sn("caller_id") ?? ev.user_email;
    put("incident_state", state);
    put("category", choice(sn("category")));
    put("subcategory", choice(sn("subcategory")));
    put("contact_type", choice(sn("contact_type")));
    put("caller_id", caller ? ref(ctx, "sys_user", caller) : undefined);
    put("u_identity_verification", sn("u_identity_verification"));
    put("u_verification_result", sn("u_verification_result"));
    result.hold_reason = "";
    result.resolved_at = sn("resolved_at") ? notAfter(snowTime(sn("resolved_at")!)) : state === "6" || closed ? recTime : "";
    result.closed_at = sn("closed_at") ? notAfter(snowTime(sn("closed_at")!)) : closed ? recTime : "";
  } else if (table === "change_request") {
    put("type", choice(sn("type")));
    const risk = sn("risk");
    put("risk", risk ? (/^\d$/.test(risk) ? risk : RISK[risk.toLowerCase()] ?? "3") : undefined);
    // The person a change row is about is its requester (as caller_id is for an incident).
    const requester = sn("requested_by") ?? ev.user_email;
    put("requested_by", requester ? ref(ctx, "sys_user", requester) : undefined);
    put("start_date", sn("start_date") ? snowTime(sn("start_date")!) : undefined);
    put("end_date", sn("end_date") ? snowTime(sn("end_date")!) : undefined);
  } else {
    const item = sn("catalog_item");
    const forUser = sn("requested_for") ?? ev.user_email;
    put("request", ref(ctx, "sc_request", `REQ-of-${number}`));
    put("cat_item", item ? ref(ctx, "sc_cat_item", item) : undefined);
    put("requested_for", forUser ? ref(ctx, "sys_user", forUser) : undefined);
    result.quantity = "1";
    put("stage", state === "-5" ? "waiting_for_approval" : state === "1" ? "request_approved" : state === "2" ? "fulfillment" : closed ? "complete" : undefined);
  }

  put("opened_by", opener ? ref(ctx, "sys_user", opener) : undefined);
  put("opened_at", openedAt);
  put("sys_created_on", createdOn);
  put("sys_created_by", opener ? userName(opener) : undefined);
  result.sys_updated_on = sn("sys_updated_on") ? notAfter(snowTime(sn("sys_updated_on")!)) : recTime;
  result.sys_updated_by = userName(updatedBy);
  result.sys_mod_count = String(rank + (rank === 0 ? 0 : ctx.int(`${ctx.companyId}:${number}:${state}:mod`, 0, 3)));
  result.close_code = sn("close_code") ?? "";
  result.close_notes = sn("close_notes") ?? "";
  // Journal entries, stamped with the last update and its author (see the header).
  const journal = (kind: "Work notes" | "Additional comments", text?: string) =>
    text ? `${result.sys_updated_on} - ${displayName(updatedBy)} (${kind})
${text}` : "";
  result.work_notes = journal("Work notes", sn("work_notes"));
  result.comments = journal("Additional comments", sn("comments"));

  return { sourceId: "servicenow", kind: table, format: "json", record: { result }, timeMs: Date.parse(ev.ts) };
}

/** sys_id of a configuration item, by its name: the same in cmdb_ci and in every class table. */
export function ciSysId(ctx: NativeCtx, name: string): string {
  return sysId(ctx, "cmdb_ci", name);
}

/**
 * One journal entry, as GET /api/now/table/sys_journal_field?sysparm_query=element_id=<ticket sys_id>
 * returns it: the field it belongs to (work_notes | comments), the ticket's table and sys_id, the
 * text, and who wrote it when. The ticket record itself does not say when a note was added.
 */
function journalRecord(ev: TelemetryEvent, ctx: NativeCtx, sn: (k: string) => string | undefined): NativeLog | null {
  const number = sn("number");
  const value = sn("value") ?? sn("work_notes");
  if (!number || !value) return null;
  const parent = sn("name") ?? "incident";
  const element = sn("element") ?? "work_notes";
  const created = sn("sys_created_on") ? snowTime(sn("sys_created_on")!) : snowTime(ev.ts);
  const result: Record<string, unknown> = {
    sys_id: sysId(ctx, "sys_journal_field", `${number}:${element}:${created}`),
    element,
    element_id: sysId(ctx, parent, number),
    name: parent,
    value,
    sys_created_by: userName(sn("sys_created_by") ?? "system"),
    sys_created_on: created,
  };
  return { sourceId: "servicenow", kind: "sys_journal_field", format: "json", record: { result }, timeMs: Date.parse(ev.ts) };
}

/** One CMDB CI, as GET /api/now/table/<cmdb_ci_*>/<sys_id>?sysparm_display_value=true returns it. */
function cmdbRecord(ev: TelemetryEvent, ctx: NativeCtx, table: string, sn: (k: string) => string | undefined): NativeLog | null {
  const name = sn("name");
  if (!name) return null;
  const recTime = snowTime(ev.ts);
  const dref = (refTable: string, key: string | undefined, display?: string) =>
    key ? { display_value: display ?? key, link: ref(ctx, refTable, key).link } : undefined;
  const owner = sn("assigned_to");
  const ownerName = owner ? (owner.includes("@") && ev.user?.email === owner && ev.user?.full_name ? ev.user.full_name : displayName(owner)) : undefined;
  const result: Record<string, unknown> = { sys_id: ciSysId(ctx, name), name, sys_class_name: CMDB_CLASS[table] };
  const put = (k: string, v: unknown) => { if (v !== undefined) result[k] = v; };
  put("short_description", sn("short_description"));
  put("asset_tag", sn("asset_tag"));
  put("serial_number", sn("serial_number"));
  put("manufacturer", dref("core_company", sn("manufacturer")));
  put("model_id", dref("cmdb_model", sn("model_id")));
  put("os", sn("os"));
  put("os_version", sn("os_version"));
  put("ip_address", sn("ip_address"));
  put("assigned_to", owner ? { display_value: ownerName, link: ref(ctx, "sys_user", owner).link } : undefined);
  put("department", dref("cmn_department", sn("department")));
  put("location", dref("cmn_location", sn("location")));
  const install = sn("install_status");
  put("install_status", install ? INSTALL_STATUS[install] ?? install : undefined);
  const op = sn("operational_status");
  put("operational_status", op ? OPERATIONAL_STATUS[op] ?? op : undefined);
  put("discovery_source", sn("discovery_source"));
  const seen = sn("last_discovered");
  put("last_discovered", seen ? (snowTime(seen) > recTime ? recTime : snowTime(seen)) : undefined);
  result.sys_updated_on = seen ? (snowTime(seen) > recTime ? recTime : snowTime(seen)) : recTime;
  result.sys_updated_by = sn("discovery_source") === "SCCM" ? "sccm.integration" : "discovery";
  result.sys_mod_count = String(ctx.int(`${ctx.companyId}:cmdb:${name}:mod`, 12, 240));
  return { sourceId: "servicenow", kind: table, format: "json", record: { result }, timeMs: Date.parse(ev.ts) };
}

// ── use cases ("context" detections: ITSM records explain or contradict activity elsewhere) ──
const useCases: UseCase[] = [
  {
    id: "servicenow.emergency_change", title: "Emergency change raised", sourceId: "servicenow", kinds: ["change_request"],
    severity: "medium", mitre: ["T1078", "T1685"],
    description: "Emergency changes skip the normal CAB review. Attackers and insiders use them (or forge them) to justify disabling controls or making admin changes at odd hours. Check there is a matching incident, who requested it, and whether the same person approved it.",
    logic: "ServiceNow Table API: GET /api/now/table/change_request?sysparm_query=type=emergency^sys_created_on>=javascript:gs.daysAgoStart(1)  |  SIEM: snow_change type=emergency | table number requested_by start_date end_date",
    match: { field: "result.type", op: "eq", value: "emergency" },
    falsePositives: ["Genuine outages handled through the emergency-change process"],
  },
  {
    id: "servicenow.change_implemented_unapproved", title: "Change implementing without approval", sourceId: "servicenow", kinds: ["change_request"],
    severity: "high", mitre: ["T1078", "T1098"],
    description: "A change in Implement / Review / Closed whose approval is not 'approved' means work was done outside the approved process - the window or ticket an admin points to does not actually authorise the activity you are investigating.",
    logic: "sysparm_query=stateIN-1,0,3^approval!=approved",
    match: { all: [{ field: "result.state", op: "in", value: ["-1", "0", "3"] }, { field: "result.approval", op: "neq", value: "approved" }] },
    falsePositives: ["Standard (pre-approved) changes, whose approval may read 'not requested'"],
  },
  {
    id: "servicenow.change_window_offhours", title: "Change window scheduled outside business hours (context)", sourceId: "servicenow", kinds: ["change_request"],
    severity: "low", mitre: [],
    description: "Context, not an alert: a change scheduled between 22:00 and 06:00 UTC explains - or fails to explain - night-time admin logins, backup jobs and service restarts. Match the host (cmdb_ci), the person (assigned_to) and the time against start_date/end_date (UTC).",
    logic: "sysparm_query=start_dateRELATIVEGE@hour@ago@0  |  SIEM: snow_change | where hour(start_date) >= 22 or hour(start_date) < 6",
    match: { field: "result.start_date", op: "regex", value: " (2[2-3]|0[0-5]):" },
    falsePositives: ["Planned maintenance windows - that is the point: use them to clear night-time alerts"],
  },
  {
    id: "servicenow.helpdesk_auth_reset_by_phone", title: "Password / MFA reset requested by phone", sourceId: "servicenow", kinds: ["incident"],
    severity: "medium", mitre: ["T1684.001", "T1078"],
    description: "Help-desk social engineering (Scattered Spider, voice-cloned callers) starts as an ordinary phone ticket asking for a password or MFA reset. Compare the caller's real activity (sign-ins from their own device minutes earlier) with the ticket and check how identity was verified.",
    logic: "sysparm_query=contact_type=phone^subcategoryLIKEpassword^ORsubcategoryLIKEmfa",
    match: { all: [{ field: "result.contact_type", op: "eq", value: "phone" }, { field: "result.subcategory", op: "regex", value: "password|mfa|authenticator" }] },
    falsePositives: ["Genuine lockouts - most such tickets are legitimate; the point is to cross-check them"],
  },
  {
    id: "servicenow.weak_identity_verification", title: "Reset ticket closed on knowledge-based / voice-only verification", sourceId: "servicenow", kinds: ["incident"],
    severity: "medium", mitre: ["T1684.001"],
    description: "Employee ID, date of birth or 'voice recognised' are all things an attacker can obtain or synthesise. A credential/MFA reset verified only that way (and no call-back to the number on file) is the weak link to report.",
    logic: "sysparm_query=u_identity_verificationLIKEvoice^ORu_identity_verificationLIKEdate of birth^ORu_identity_verificationLIKEemployee id",
    match: { field: "result.u_identity_verification", op: "regex", value: "voice|date of birth|employee id" },
    falsePositives: ["Organisations whose policy requires a call-back - verify it was actually done"],
  },
  {
    id: "servicenow.critical_incident", title: "Priority 1 incident (context)", sourceId: "servicenow", kinds: ["incident"],
    severity: "low", mitre: [],
    description: "Context: a P1 ticket means the business already sees impact. Link your investigation to it (the number goes in the SOC report) and check whether its timeline matches the alerts you are triaging.",
    logic: "sysparm_query=priority=1^active=true",
    match: { field: "result.priority", op: "eq", value: "1" },
    falsePositives: [],
  },
  {
    id: "servicenow.privileged_access_request", title: "Approved request for admin / privileged access (context)", sourceId: "servicenow", kinds: ["sc_req_item"],
    severity: "low", mitre: ["T1078"],
    description: "An approved catalog request for local admin, domain admin or root access explains a new group membership or elevated logons - or, if the activity starts before approval or outlasts due_date, contradicts them.",
    logic: "sysparm_query=approval=approved^short_descriptionLIKEadmin^ORshort_descriptionLIKEprivileged",
    match: { all: [{ field: "result.approval", op: "eq", value: "approved" }, { field: "result.short_description", op: "regex", value: "admin|privileged|root|sudo" }] },
    falsePositives: [],
  },
  {
    id: "servicenow.soc_monitoring_incident", title: "High-priority incident opened from monitoring (context)", sourceId: "servicenow", kinds: ["incident"],
    severity: "low", mitre: [],
    description: "Context: an incident with contact_type=monitoring and priority 1–2 was opened by the SOC/monitoring itself - the ticket an analyst updates and cites.",
    logic: "sysparm_query=contact_type=monitoring^priorityIN1,2",
    match: { all: [{ field: "result.contact_type", op: "eq", value: "monitoring" }, { field: "result.priority", op: "in", value: ["1", "2"] }] },
    falsePositives: [],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "servicenow", category: "itsm", card: "itsm-servicenow.md", product: "ServiceNow ITSM",
    format: "json", vendorMatch: ["servicenow"], telemetrySources: ["soar"], kinds,
  },
  fromTelemetry,
  useCases,
};
