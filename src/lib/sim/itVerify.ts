import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * "Verify with IT": the analyst phones the IT Help Desk and asks whether the action in a
 * log was authorised (a change ticket, an approved request, a sanctioned tool). One rule
 * for the single-user dashboard and the team exercise, so the answer always matches the
 * event's ground truth:
 *   1. an answer authored on the event (it_verify_* / it_context) wins;
 *   2. an FP decoy: IT confirms the approval its explanation rests on (the same ticket the
 *      team feed shows as a ServiceNow record);
 *   3. part of an attack: IT has no ticket / the tool is not allowed;
 *   4. routine activity: IT recognises it as normal work.
 * The team feed carries no answer key, so there the answer is computed on the server
 * (POST /api/team/sessions/[id]/it-verify) from the fired log with its answers joined back.
 */

export type ItVerifyResult = "confirmed" | "unverified";
export interface ItVerifyAnswer { result: ItVerifyResult; message: string }

/** Privileged / account changes: the "is there a change ticket?" question. */
export const IT_ADMIN_EVENT_TYPES = new Set([
  "group_modify", "account_modify", "account_create", "account_delete",
  "privilege_escalation", "privileged_operation", "role_assignment",
  "cloud_role_change", "linux_priv_change",
]);

/** Remote-access / remote-admin tools: the "is this tool allowed here?" question. */
const REMOTE_TOOL = /\b(anydesk|teamviewer|screenconnect|connectwisecontrol|splashtop|rustdesk|atera|quickassist|psexec(?:svc)?)\b/i;
const REMOTE_TOOL_TYPES = new Set(["process_create", "file_create", "service_install", "edr_alert"]);
const TOOL_LABEL: Record<string, string> = {
  anydesk: "AnyDesk", teamviewer: "TeamViewer", screenconnect: "ScreenConnect", connectwisecontrol: "ScreenConnect",
  splashtop: "Splashtop", rustdesk: "RustDesk", atera: "Atera", quickassist: "Quick Assist", psexec: "PsExec", psexecsvc: "PsExec",
};

export function remoteToolOf(ev: TelemetryEvent): string | null {
  if (ev.source !== "edr" && ev.source !== "sysmon") return null;
  if (!REMOTE_TOOL_TYPES.has(ev.event_type)) return null;
  const hay = [ev.process?.name, ev.process?.cmdline, ev.file?.name, ev.description].filter(Boolean).join(" ");
  const m = hay.match(REMOTE_TOOL);
  return m ? (TOOL_LABEL[m[1].toLowerCase()] ?? m[1]) : null;
}

/** Whether the log offers the "Verify with IT" call. */
export function itVerifyApplies(ev: TelemetryEvent): boolean {
  return !!ev.it_verify_result || !!ev.it_context || IT_ADMIN_EVENT_TYPES.has(ev.event_type) || remoteToolOf(ev) !== null;
}

/**
 * The approval reference an FP decoy's explanation cites ("ticket HR-2026-117",
 * "Reference GL-AUDIT-2026-03", "(QB-HR-2026-S14)") — an ID with a digit, right
 * after a ticket/reference word or in parentheses, never a hostname.
 */
export function approvalRefOf(text: string | undefined): string | null {
  if (!text) return null;
  const re = /(?:ticket|ref(?:erence)?|approval ref|access request|request|covers)\s*:?\s*([A-Za-z]{2,}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)|\(([A-Za-z]{2,}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)\)/gi;
  for (const m of text.matchAll(re)) {
    const id = m[1] ?? m[2] ?? "";
    if (id === id.toUpperCase() && /\d/.test(id) && !/^(WS|LT|LAP|WKS|SRV|DC|NB)-/.test(id)) return id;
  }
  return null;
}

type Verdict = "tp" | "escalate" | "fp" | "benign" | "informational";

/** Ground truth for the IT answer: the caller's verdict when it has one (the team answer key). */
function verdictOf(ev: TelemetryEvent, verdict?: string): Verdict {
  if (ev.expected_verdict === "fp" || ev.fp_explanation) return "fp";
  const v = (verdict ?? ev.expected_verdict) as Verdict | undefined;
  if (v) return v;
  if (ev.is_baseline) return "benign";
  return ev.mitre_technique ? "tp" : "benign";
}

const localPart = (s?: string) => (s ?? "").split("@")[0];
const SYSTEM_ACCOUNT = /^(system|local service|network service)$/i;
function whoOf(ev: TelemetryEvent): string {
  const who = localPart(ev.user_email ?? ev.user?.email) || ev.process?.user?.split("\\").pop() || "";
  return SYSTEM_ACCOUNT.test(who) ? "" : who;
}
const HOST_SOURCES = new Set(["edr", "sysmon", "ad", "windows_security", "linux_audit", "virtualization"]);
/** A machine name, never a bare tenant domain ("nexacorp.com"). */
const hostOf = (ev: TelemetryEvent) =>
  ev.hostname && HOST_SOURCES.has(ev.source) && !/^[a-z0-9-]+\.[a-z]{2,}$/i.test(ev.hostname) ? ev.hostname : "";

/** What the caller is asking IT about, in a few words. */
function subjectOf(ev: TelemetryEvent): { what: string; kind: "forward" | "mfa" | "password" | "consent" | "vault" | "change" } {
  const d = (ev.description ?? "").toLowerCase();
  const t = `${d} ${JSON.stringify(ev.raw ?? {})}`.toLowerCase();
  if (/inbox rule|forward|mailbox rule|new-inboxrule|set-mailbox/.test(t)) return { what: "this mail-forwarding rule", kind: "forward" };
  if (/consent|oauth|service principal|app registration/.test(t) && ev.event_type !== "privileged_operation") return { what: "this app consent or registration", kind: "consent" };
  if (/checked out|check-?out|vault|psm session/.test(t)) return { what: "this privileged-account checkout", kind: "vault" };
  // sign-in methods and passwords only on account changes, read from the description (a raw
  // "mfaAuthenticated" flag on a cloud API call is not an MFA change)
  if (ev.event_type === "account_modify" && /authenticator|security info|authentication method|mfa|two-factor|verify push|factor was/.test(d)) return { what: "this change to the account's sign-in methods", kind: "mfa" };
  if (ev.event_type === "account_modify" && /password/.test(d)) return { what: "this password change", kind: "password" };
  switch (ev.event_type) {
    case "account_create": return { what: "creating this account", kind: "change" };
    case "account_delete": return { what: "deleting this account", kind: "change" };
    case "group_modify": return { what: "this group-membership change", kind: "change" };
    case "role_assignment": case "cloud_role_change": return { what: "this role or permission change", kind: "change" };
    case "privilege_escalation": return { what: "granting these privileges", kind: "change" };
    case "linux_priv_change": return { what: "this root / sudo activity", kind: "change" };
    case "privileged_operation": return { what: "this privileged operation", kind: "change" };
    default: return { what: "this change", kind: "change" };
  }
}

function forWhom(ev: TelemetryEvent): string {
  const who = whoOf(ev), host = hostOf(ev);
  return `${who ? ` involving ${who}` : ""}${host ? ` on ${host}` : ""}`;
}

/** The IT answer for one log, or null when the call doesn't apply. */
export function itVerifyAnswer(ev: TelemetryEvent, verdict?: string): ItVerifyAnswer | null {
  if (ev.it_verify_result && ev.it_verify_message) return { result: ev.it_verify_result, message: ev.it_verify_message };
  if (ev.it_context) return ev.it_context;
  if (!itVerifyApplies(ev)) return null;
  const v = verdictOf(ev, verdict);
  const attack = v === "tp" || v === "escalate";
  const tool = remoteToolOf(ev);

  if (ev.it_verify_result) {
    // authored result without a message: say it plainly for this event
    return ev.it_verify_result === "confirmed"
      ? { result: "confirmed", message: `IT confirms ${subjectOf(ev).what}${forWhom(ev)} was requested and approved.` }
      : { result: "unverified", message: `IT has no ticket, change or approval for ${subjectOf(ev).what}${forWhom(ev)}, and nobody in IT recognises it.` };
  }

  if (tool) {
    const host = hostOf(ev);
    if (attack) {
      return { result: "unverified", message: `${tool} is not on the approved software list, and IT has no request to install or run it${host ? ` on ${host}` : ""}. The Service Desk uses only its own managed remote-support tool and never asks staff to install one themselves.` };
    }
    if (v === "fp" && ev.fp_explanation) return { result: "confirmed", message: approvalMessage(ev) };
    return { result: "confirmed", message: `IT confirms the ${tool} activity${host ? ` on ${host}` : ""} is their own administrative work.` };
  }

  if (v === "fp" && ev.fp_explanation) return { result: "confirmed", message: approvalMessage(ev) };

  const { what, kind } = subjectOf(ev);
  if (attack) {
    if (kind === "forward") return { result: "unverified", message: `No change request or HR approval covers ${what}${forWhom(ev)}. IT did not set it up.` };
    if (kind === "consent") return { result: "unverified", message: `IT has no request to approve or register this app, and it is not on the list of approved applications.` };
    if (kind === "vault") return { result: "unverified", message: `There is no approved change or maintenance window covering ${what}${forWhom(ev)}, and no ticket is attached to it.` };
    return { result: "unverified", message: `IT searched the change and request queues: there is no ticket, change or approval for ${what}${forWhom(ev)}, and nobody in IT recognises it.` };
  }
  if (kind === "password" && /changed (?:their|her|his) own|changed password|self-service/i.test(ev.description ?? "")) {
    return { result: "confirmed", message: `A routine self-service password change${forWhom(ev)}. Nothing for IT to follow up.` };
  }
  return { result: "confirmed", message: `IT recognises ${what}${forWhom(ev)} as routine, expected activity that matches normal day-to-day work. Nothing for IT to follow up.` };
}

/** FP decoy: IT confirms the approval the explanation rests on, citing its reference. */
function approvalMessage(ev: TelemetryEvent): string {
  const exp = ev.fp_explanation ?? "";
  const ref = approvalRefOf(exp);
  // The sentence that states the approval (an explanation may open with analyst reasoning:
  // "An auto-forward of ALL mail ... fires a HIGH alert. Triage resolves it to benign: ... ticket INC-90123").
  const sentences = exp.split(/(?<=\.)\s|\s—\s/).map(x => x.trim().replace(/\.$/, "")).filter(Boolean);
  const APPROVAL = /approv|ticket|request|authori[sz]|signed off|change (?:record|window)/i;
  const stated = sentences.find(x => APPROVAL.test(x) && (!ref || x.includes(ref))) ?? sentences.find(x => APPROVAL.test(x));
  const first = (stated ?? sentences[0] ?? "").replace(/^[^:]*\b(benign|triage|resolves?|false positive)\b[^:]*:\s*/i, "");
  const base = first.length > 8 ? first : "the activity was requested and approved";
  return `IT confirms: ${base}${ref && !base.includes(ref) ? ` (${ref})` : ""}.`;
}
