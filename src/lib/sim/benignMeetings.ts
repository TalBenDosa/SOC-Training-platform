/**
 * Ordinary Teams meetings for a company's noise pool (Unified Audit Log, RecordType 25).
 *
 * Every Microsoft 365 company holds meetings all day, and the audit log writes a MeetingDetail record
 * for each meeting and a MeetingParticipantDetail record for each person who joined. Without these in
 * the noise, the only meeting records a learner ever saw were an attack's (the deepfake call), so the
 * record type alone gave the attack away (realism R2). Same fields as the attack rows, ordinary values.
 */
import type { TelemetryEvent } from "./types";

export interface MeetingPerson { upn: string; display: string; ip: string; host?: string }
interface MeetingPlan { subject: string; startIso: string; minutes: number }

/** Deterministic GUID-shaped id from a seed (the meeting id a record names). */
function guidOf(seed: string): string {
  let h = 0x811c9dc5;
  const hex: string[] = [];
  for (let i = 0; i < 32; i++) {
    h ^= (seed.charCodeAt(i % seed.length) || 7) + i * 97;
    h = Math.imul(h, 0x01000193) >>> 0;
    hex.push((h & 0xf).toString(16));
  }
  const s = hex.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-4${s.slice(13, 16)}-9${s.slice(17, 20)}-${s.slice(20, 32)}`;
}
const thread = (seed: string) => `19:meeting_${guidOf(seed).replace(/-/g, "")}@thread.v2`;
const noMs = (iso: string) => iso.replace(/\.\d{3}Z$/, "Z");
const plus = (iso: string, min: number) => new Date(Date.parse(iso) + min * 60_000).toISOString();

/** One internal meeting: the organizer's MeetingDetail and one MeetingParticipantDetail per attendee. */
function meeting(companyId: string, n: number, plan: MeetingPlan, organizer: MeetingPerson, attendees: MeetingPerson[]): TelemetryEvent[] {
  const id = guidOf(`${companyId}:meeting:${n}`);
  const chat = thread(`${companyId}:meeting:${n}`);
  const end = plus(plan.startIso, plan.minutes);
  const member = (p: MeetingPerson) => ({ RecipientType: "User", UPN: p.upn, DisplayName: p.display });
  const head = (p: MeetingPerson, op: string) => ({
    "data.office365.Operation": op, "data.office365.RecordType": "25", "data.office365.Workload": "MicrosoftTeams",
    "data.office365.UserId": p.upn, "data.office365.UserType": "0", "data.office365.MeetingDetailId": id, "data.office365.ChatThreadId": chat,
    "source.ip": p.ip, action_result: "allowed",
  });
  const detail: TelemetryEvent = {
    id: `${companyId}_meet_${n}_detail`, ts: end, source: "o365", vendor: "Microsoft Teams", event_type: "cloud_api_call", severity: "informational",
    user_email: organizer.upn, src_ip: organizer.ip, ...(organizer.host ? { hostname: organizer.host } : {}),
    description: `Teams meeting "${plan.subject}" organized by ${organizer.upn.split("@")[0]} ended (${plan.minutes} minutes)`,
    raw: {
      ...head(organizer, "MeetingDetail"), "data.office365.CreationTime": noMs(end).replace(/Z$/, ""),
      "data.office365.ItemName": plan.subject, "data.office365.StartTime": noMs(plan.startIso), "data.office365.EndTime": noMs(end),
      "data.office365.Organizer": member(organizer),
    },
  };
  const parts = attendees.map((p, i): TelemetryEvent => {
    const join = plus(plan.startIso, i % 2), leave = plus(end, -(i % 3));
    return {
      id: `${companyId}_meet_${n}_part_${i}`, ts: leave, source: "o365", vendor: "Microsoft Teams", event_type: "cloud_api_call", severity: "informational",
      user_email: p.upn, src_ip: p.ip, ...(p.host ? { hostname: p.host } : {}),
      description: `${p.upn.split("@")[0]} attended the Teams meeting "${plan.subject}"`,
      raw: {
        ...head(p, "MeetingParticipantDetail"), "data.office365.CreationTime": noMs(leave).replace(/Z$/, ""),
        "data.office365.JoinTime": noMs(join), "data.office365.LeaveTime": noMs(leave), "data.office365.Attendees": [member(p)],
      },
    };
  });
  return [detail, ...parts];
}

/**
 * The company's ordinary meetings: two internal meetings on a working day, each with its organizer's
 * MeetingDetail and the participants' MeetingParticipantDetail records.
 */
export function benignMeetings(companyId: string, day: string, people: MeetingPerson[], subjects: [string, string]): TelemetryEvent[] {
  if (people.length < 3) return [];
  const [a, b, c, d] = [people[0], people[1], people[2], people[3] ?? people[0]];
  return [
    ...meeting(companyId, 1, { subject: subjects[0], startIso: `${day}T08:30:00.000Z`, minutes: 30 }, a, [a, b, c]),
    ...meeting(companyId, 2, { subject: subjects[1], startIso: `${day}T13:00:00.000Z`, minutes: 45 }, c, [c, d, b]),
  ];
}

/** People of a pool who work at a desk: a mailbox in the company domain, an office address, their own workstation. */
export function meetingPeople(pool: TelemetryEvent[], domain: string, max = 4): MeetingPerson[] {
  const seen = new Map<string, MeetingPerson>();
  for (const e of pool) {
    const upn = e.user_email?.toLowerCase();
    if (!upn || !upn.endsWith(`@${domain}`) || seen.has(upn)) continue;
    const local = upn.split("@")[0];
    if (/^(svc|admin|it\.|helpdesk|security|noreply|backup)|\d/.test(local)) continue;
    if (!e.src_ip || !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(e.src_ip)) continue;
    const display = local.split(".").map(w => (w.length === 1 ? `${w.toUpperCase()}.` : w.charAt(0).toUpperCase() + w.slice(1))).join(" ");
    seen.set(upn, { upn, display, ip: e.src_ip, ...(e.hostname && /^(WS|LT|MBP|PC|NB)-/i.test(e.hostname) ? { host: e.hostname } : {}) });
    if (seen.size >= max) break;
  }
  return [...seen.values()];
}
