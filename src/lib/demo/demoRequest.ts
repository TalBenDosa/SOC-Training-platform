/**
 * A demo request from the public /demo page: the shape the form sends, its validation, and the email the platform
 * owner receives. Pure (no I/O) so the route stays thin and every rule is unit-tested.
 *
 * Nothing here is stored: the request becomes one email to the address in DEMO_REQUEST_TO (server env), with the
 * requester as Reply-To, so answering it is one click.
 */

export const ORG_TYPES = [
  { id: "college", label: "College or university" },
  { id: "training", label: "Training provider or bootcamp" },
  { id: "soc", label: "Company SOC team" },
  { id: "mssp", label: "MSSP or MDR provider" },
  { id: "other", label: "Other" },
] as const;

export const TEAM_SIZES = [
  { id: "1-10", label: "1 to 10 learners" },
  { id: "11-50", label: "11 to 50 learners" },
  { id: "51-200", label: "51 to 200 learners" },
  { id: "200+", label: "More than 200 learners" },
] as const;

export type OrgType = (typeof ORG_TYPES)[number]["id"];
export type TeamSize = (typeof TEAM_SIZES)[number]["id"];

export interface DemoRequest {
  name: string;
  email: string;
  organization: string;
  role: string;
  orgType: OrgType;
  teamSize: TeamSize;
  /** When suits them, in their own words ("Sun to Thu mornings, Israel time"). */
  availability: string;
  message: string;
}

export type DemoValidation = { ok: true; value: DemoRequest; bot: boolean } | { ok: false; error: string; field?: keyof DemoRequest | "consent" };

const EMAIL_RE = /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']{2,}$/;
/** Control characters, including CR / LF, which must never reach a mail header such as the subject. */
const CONTROL = /[\u0000-\u001f\u007f]/g;

const text = (v: unknown, max: number): string => (typeof v === "string" ? v.replace(/\r\n?/g, "\n").trim().slice(0, max) : "");
const line = (v: unknown, max: number): string => text(v, max).replace(CONTROL, " ").replace(/\s+/g, " ").trim();

/**
 * Validate an untrusted body. `website` is a honeypot field hidden from people: a bot that fills it is answered as
 * if the request went through (bot: true) so it learns nothing, and no email is sent.
 */
export function validateDemoRequest(body: unknown): DemoValidation {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const bot = typeof b.website === "string" && b.website.trim() !== "";
  const name = line(b.name, 100);
  const email = line(b.email, 254).toLowerCase();
  const organization = line(b.organization, 120);
  const role = line(b.role, 80);
  const availability = line(b.availability, 200);
  const message = text(b.message, 2000).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "");
  const orgType = ORG_TYPES.find(o => o.id === b.orgType)?.id;
  const teamSize = TEAM_SIZES.find(s => s.id === b.teamSize)?.id;

  if (name.length < 2) return { ok: false, error: "Enter your full name.", field: "name" };
  if (!EMAIL_RE.test(email)) return { ok: false, error: "Enter a valid work email address.", field: "email" };
  if (organization.length < 2) return { ok: false, error: "Enter your organization's name.", field: "organization" };
  if (!orgType) return { ok: false, error: "Choose the kind of organization.", field: "orgType" };
  if (!teamSize) return { ok: false, error: "Choose roughly how many learners.", field: "teamSize" };
  if (b.consent !== true) return { ok: false, error: "Confirm that we may contact you about the demo.", field: "consent" };
  return { ok: true, bot, value: { name, email, organization, role, orgType, teamSize, availability, message } };
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** The email the platform owner receives. Every value is escaped; the subject carries no line breaks. */
export function demoRequestEmail(r: DemoRequest, receivedAt: Date): { subject: string; html: string; text: string } {
  const orgType = ORG_TYPES.find(o => o.id === r.orgType)!.label;
  const size = TEAM_SIZES.find(s => s.id === r.teamSize)!.label;
  const rows: [string, string][] = [
    ["Name", r.name], ["Email", r.email], ["Organization", r.organization], ["Role", r.role || "Not given"],
    ["Organization type", orgType], ["Learners", size], ["Good times", r.availability || "Not given"],
  ];
  const when = receivedAt.toISOString().replace("T", " ").slice(0, 16) + " UTC";
  const subject = `Demo request: ${r.organization} (${orgType})`.replace(CONTROL, " ").slice(0, 150);
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0f172a">
<h2 style="font-size:18px;margin:0 0 12px">New HACK THE SOC demo request</h2>
<table style="border-collapse:collapse">${rows.map(([k, v]) => `<tr><td style="padding:4px 12px 4px 0;color:#475569;vertical-align:top">${esc(k)}</td><td style="padding:4px 0">${esc(v)}</td></tr>`).join("")}</table>
${r.message ? `<p style="margin:16px 0 4px;color:#475569">Message</p><p style="margin:0;white-space:pre-wrap">${esc(r.message)}</p>` : ""}
<p style="margin:20px 0 0;color:#64748b;font-size:12px">Received ${esc(when)} from the /demo page. Reply to this email to answer ${esc(r.name)} directly.</p>
</div>`;
  const textBody = [
    "New HACK THE SOC demo request", "",
    ...rows.map(([k, v]) => `${k}: ${v}`),
    ...(r.message ? ["", "Message:", r.message] : []),
    "", `Received ${when} from the /demo page. Reply to this email to answer the requester directly.`,
  ].join("\n");
  return { subject, html, text: textBody };
}

/** The recipients from DEMO_REQUEST_TO (comma-separated); empty when unset or malformed. */
export function demoRecipients(env: string | undefined): string[] {
  return (env ?? "").split(",").map(s => s.trim()).filter(s => EMAIL_RE.test(s));
}

/** A scheduling page (DEMO_BOOKING_URL) is offered only when it is an https link. */
export function bookingUrl(env: string | undefined): string | null {
  const v = (env ?? "").trim();
  try { return v && new URL(v).protocol === "https:" ? v : null; } catch { return null; }
}
