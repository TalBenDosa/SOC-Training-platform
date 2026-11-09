/**
 * R7 (docs/LOG-REALISM-STANDARD.md): a password spray, brute force or credential-stuffing story is
 * provable from the rows the learner sees. A story whose evidence was one failed sign-in and a SIEM
 * alert claiming "89 failed attempts" now carries the failure burst itself: native failure rows from
 * the same product the story already logs (Windows 4625, Okta user.session.start FAILURE
 * INVALID_CREDENTIALS, Entra 50126, AnyConnect 113005, auditd USER_AUTH res=failed), from the
 * attacker's one address, in a compact run of two to three minutes.
 *
 * Each attempt is a copy of a row the story already authors (the template), so it renders through
 * the same native module and keeps the story's shape (R2). The accounts a story names elsewhere (the
 * locked account, the one whose password worked) keep their authored names; the rest of the sprayed
 * list is drawn from the company's own people (the noise pool), so a story re-homed to another
 * company sprays that company's directory and never names another tenant's people (R3).
 *
 * Expanded by instantiateStory, before people and hosts are re-homed, so the rows follow every swap
 * the story's own rows follow.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { isRehomeablePerson } from "@/lib/sim/nonHuman";

type Outcome = "fail" | "locked" | "ok";

/** One sign-in attempt of a burst. `user` is a key account (an authored UPN) or `#n`, the n-th drawn account. */
interface Attempt { at: number; user: string; outcome?: Outcome; host?: string }

interface BurstPlan {
  /** The authored row every attempt copies (product, raw shape, MITRE). */
  template: string;
  /** The authored row `at` (seconds) is measured from. */
  anchor: string;
  /** How many accounts are drawn from the company's people. */
  draws: number;
  attempts: Attempt[];
  /** Authored rows that already are attempts of the burst: they get the account the burst gives them. */
  own?: Record<string, string>;
  /** Authored rows whose technique the burst corrects (a one-account guess tagged as a spray). */
  retag?: Record<string, string>;
  /** People of the company the noise pool never shows, for a directory too small to spray from. */
  spare?: string[];
}

/** Two rounds of one password across `accounts`, `gap` seconds apart, ending `end` seconds from the anchor. */
function rounds(accounts: string[][], start: number, step: number, gap: number): Attempt[] {
  const out: Attempt[] = [];
  let t = start;
  accounts.forEach((round, r) => {
    if (r > 0) t += gap;
    round.forEach(u => { out.push({ at: Math.round(t * 10) / 10, user: u }); t += step; });
  });
  return out;
}
const draws = (n: number, from = 0) => Array.from({ length: n }, (_, i) => `#${from + i}`);

const PLANS: Record<string, BurstPlan> = {
  // Okta, SWIFT-Operators spray from 198.51.100.203: one password across ten accounts, a second
  // round, b.schwarzer's third failure locks it (qb_d2), h.weber's password works two minutes later.
  "quantumbank-chain-d": {
    template: "qb_d1", anchor: "qb_d1", draws: 8,
    spare: ["c.frei@quantumbank.ch", "s.baumann@quantumbank.ch", "n.gerber@quantumbank.ch"],
    own: { qb_d1: "b.schwarzer@quantumbank.ch" },
    attempts: [
      ...rounds([["h.weber@quantumbank.ch", ...draws(8)], ["b.schwarzer@quantumbank.ch", ...draws(8)]], 6.2, 8.4, 21),
      { at: 176.4, user: "b.schwarzer@quantumbank.ch" },
    ],
  },
  // Okta credential stuffing from 198.51.100.217: one leaked password per account, j.lee retried
  // until Okta locks it (rs_d2), n.shapiro's leaked password works (rs_d3).
  "rocketstack-chain-d": {
    template: "rs_d1", anchor: "rs_d1", draws: 10,
    own: { rs_d1: "#0" },
    attempts: [
      ...rounds([[...draws(4, 1), "j.lee@rocketstack.io", ...draws(5, 5)]], 9.1, 11.3, 0),
      { at: 131.7, user: "j.lee@rocketstack.io" }, { at: 152.4, user: "#3" }, { at: 171.9, user: "j.lee@rocketstack.io" },
    ],
  },
  // The same stuffing list, earlier the same day: a.kim's leaked password works at 11:31, ops-admin is
  // retried until it locks (rs_bf_03).
  "rocketstack-cred-stuffing": {
    template: "rs_bf_01", anchor: "rs_bf_01", draws: 10,
    own: { rs_bf_01: "#0" },
    attempts: [
      ...rounds([[...draws(3, 1), "ops-admin@rocketstack.io", ...draws(6, 4)]], -96.4, 9.6, 0),
      { at: 4.8, user: "ops-admin@rocketstack.io" }, { at: 21.5, user: "#5" }, { at: 38.2, user: "ops-admin@rocketstack.io" },
    ],
  },
  // AnyConnect spray from 198.51.100.167 on the Clinical-VPN group: nine accounts, two rounds;
  // l.willems' second-round guess is the session mc_d3 opens.
  "medcore-chain-d": {
    template: "mc_d2", anchor: "mc_d3", draws: 6,
    own: { mc_d1: "dr.dejong@medcorehealth.org", mc_d2: "l.bakker@medcorehealth.org" },
    attempts: rounds([
      ["dr.dejong@medcorehealth.org", "l.bakker@medcorehealth.org", "l.willems@medcorehealth.org", ...draws(6)],
      ["dr.dejong@medcorehealth.org", "l.bakker@medcorehealth.org", ...draws(6)],
    ], -168.6, 7.9, 12),
  },
  // AnyConnect password guessing on one account from 198.51.100.216: p.hoekstra, twelve rejections
  // (the alert's "12 failed") then the session mc_c2 opens. One account is guessing, not a spray.
  "medcore-chain-c": {
    template: "mc_c1", anchor: "mc_c2", draws: 0,
    retag: { mc_c1: "T1110.001" },
    attempts: rounds([Array(11).fill("p.hoekstra@medcorehealth.org")], -131.5, 11.2, 0),
  },
  // SSH password guessing for root from 198.51.100.97: SRV-GL-LINUX01 first, then SRV-GL-APP02,
  // where root's password is accepted (gl_d3). Each guess is a USER_AUTH res=failed from sshd.
  "globallogis-chain-d": {
    template: "gl_d3", anchor: "gl_d3", draws: 0,
    attempts: [
      ...rounds([Array(6).fill("root")], -298.2, 6.4, 0).map(a => ({ ...a, host: "SRV-GL-LINUX01" })),
      ...rounds([Array(8).fill("root")], -112.6, 12.1, 0).map(a => ({ ...a, host: "SRV-GL-APP02" })),
    ],
  },
  // The credential origin of the impossible-travel case: an Entra ID spray from the Lagos address,
  // one password across ten accounts, k.taylor's rejection among them (evt_imp_00), a second round.
  "impossible-travel": {
    template: "evt_imp_00_spray", anchor: "evt_imp_00_spray", draws: 9,
    attempts: rounds([[...draws(5)], [...draws(4, 5), ...draws(6)]], -71.3, 9.2, 14)
      .filter(a => a.at !== 0),
  },
};

/** Stories with a planned burst (tests read this). */
export const BURST_STORIES = [...Object.keys(PLANS), "nexacorp-chain-d"];

const short = (u: string) => u.split("@")[0].split("\\").pop() ?? u;
function hash(s: string): number { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }

/**
 * The company's people a burst may name: its own domain, never one the story already names, and
 * always one left over, so the story's victim can still be re-homed onto someone the burst does not
 * name. A directory the noise pool shows too little of is topped up from the plan's `spare` people
 * (authored on the story's company; the domain swap carries them like every other account).
 */
function drawPeople(storyId: string, n: number, pool: TelemetryEvent[], taken: Set<string>, spare: string[] = []): string[] {
  if (n <= 0) return [];
  const people = [...new Set(pool.map(e => e.user_email).filter(isRehomeablePerson))];
  const domains = new Map<string, number>();
  for (const p of people) { const d = p.split("@")[1]; domains.set(d, (domains.get(d) ?? 0) + 1); }
  const domain = [...domains].sort((a, b) => b[1] - a[1])[0]?.[0];
  const mine = people.filter(p => p.split("@")[1] === domain && !taken.has(short(p).toLowerCase()))
    .sort((a, b) => hash(`${storyId}:${a}`) - hash(`${storyId}:${b}`));
  const out = mine.slice(0, Math.min(n, mine.length - 1));
  const names = new Set([...out, ...people].map(p => short(p).toLowerCase()));
  for (const s of spare) {
    if (out.length >= n) break;
    if (!names.has(short(s).toLowerCase()) && !taken.has(short(s).toLowerCase())) out.push(domain ? `${short(s)}@${domain}` : s);
  }
  return out;
}

/** The attempt row: the template's product and shape, this account, this time and outcome. */
function attemptRow(tpl: TelemetryEvent, id: string, ts: string, user: string, outcome: Outcome, host?: string, n?: number): TelemetryEvent {
  const raw = { ...(tpl.raw ?? {}) } as Record<string, unknown>;
  const sam = short(user);
  const upn = user.includes("@") ? user : undefined;
  const ip = tpl.src_ip ?? String(raw["source.ip"] ?? "");
  const ev: TelemetryEvent = {
    ...tpl, id, ts, severity: "low", raw,
    event_type: outcome === "ok" ? "auth_success" : "auth_failure",
  };
  delete (ev as { is_detection?: boolean }).is_detection;
  delete (ev as { _burst?: unknown })._burst;
  if (upn) ev.user_email = upn; else delete (ev as { user_email?: string }).user_email;
  if (host) ev.hostname = host;
  const vendor = (tpl.vendor ?? "").toLowerCase();
  if (vendor.includes("windows")) {
    raw["winlog.event_data.TargetUserName"] = sam;
    if (outcome === "ok") {
      raw["event.code"] = "4624";
      delete raw["winlog.event_data.Status"]; delete raw["winlog.event_data.SubStatus"]; delete raw["winlog.event_data.FailureReason"];
      raw["winlog.event_data.TargetLogonId"] = `0x${(hash(id) & 0xffffff).toString(16).toUpperCase()}`;
      raw.action_result = "allowed";
      ev.description = `${tpl.hostname} accepted a network logon (type 3, NTLM) for ${sam} from ${ip}, workstation ${raw["winlog.event_data.WorkstationName"] ?? "-"}`;
    } else {
      const locked = outcome === "locked";
      raw["winlog.event_data.Status"] = locked ? "0xC0000234" : "0xC000006D";
      raw["winlog.event_data.SubStatus"] = locked ? "0x0" : "0xC000006A";
      raw["winlog.event_data.FailureReason"] = locked ? "%%2307" : "%%2313";
      ev.description = `${tpl.hostname} refused a network logon (type 3, NTLM) for ${sam} from ${ip}, workstation ${raw["winlog.event_data.WorkstationName"] ?? "-"}: Status ${raw["winlog.event_data.Status"]}, ${locked ? "the account is locked out" : "bad user name or password"}`;
    }
  } else if (vendor.includes("okta")) {
    ev.description = `Okta refused a sign-in for ${upn} from ${ip}: INVALID_CREDENTIALS`;
  } else if (vendor.includes("anyconnect") || vendor.includes("cisco asa")) {
    raw["cisco.asa.username"] = sam;
    ev.description = `The ASA rejected an AnyConnect authentication for ${sam} from ${ip} on tunnel group ${raw["cisco.asa.tunnel_group"] ?? "-"}`;
  } else if (vendor.includes("entra") || vendor.includes("azure ad")) {
    raw["azure.signinlogs.properties.userPrincipalName"] = upn;
    ev.description = `Entra ID refused a sign-in for ${upn} from ${ip}: error 50126, invalid username or password`;
  } else if (vendor.includes("auditd") || tpl.source === "linux_audit") {
    raw["auditd.log.res"] = "failed";
    raw["system.auth.ssh.event"] = "Failed";
    raw["user.name"] = sam;
    raw["source.port"] = String(32768 + (hash(id) % 28000));
    raw.action_result = "deny";
    ev.description = `sshd on ${host ?? tpl.hostname} refused a password for ${sam} from ${ip} port ${raw["source.port"]}`;
  }
  // The run's attempt number: a second round against the same account is a new attempt, not a copy.
  if (n !== undefined && ev.description) ev.description = `${ev.description} (attempt ${n} from this address)`;
  return ev;
}

/** The account fields of an authored row that already is one of the burst's attempts. */
function withAccount(e: TelemetryEvent, user: string): TelemetryEvent {
  const raw = { ...(e.raw ?? {}) } as Record<string, unknown>;
  const vendor = (e.vendor ?? "").toLowerCase();
  if (vendor.includes("anyconnect") || vendor.includes("cisco asa")) raw["cisco.asa.username"] = short(user);
  else if (vendor.includes("entra") || vendor.includes("azure ad")) raw["azure.signinlogs.properties.userPrincipalName"] = user;
  return { ...e, user_email: user, raw };
}

/** nexacorp-chain-d authors its spray as the `_burst` the 4740 row carries (windows_security companions). */
interface AuthBurst { host?: string; dc?: boolean; ip: string; workstation?: string; attempts: { at: number; user: string; status?: string; subStatus?: string }[] }
const burstOf = (e: TelemetryEvent) => (e as TelemetryEvent & { _burst?: AuthBurst })._burst;

/** A `_burst` with a member server: its attempts become the plan (the accounts other rows name stay, the rest are drawn). */
function planFromBurst(events: TelemetryEvent[]): { plan: BurstPlan; anchor: TelemetryEvent; burst: AuthBurst } | undefined {
  const anchor = events.find(e => burstOf(e)?.host);
  const burst = anchor && burstOf(anchor);
  if (!anchor || !burst?.host) return undefined;
  const tpl = events.find(e => e.id !== anchor.id && e.hostname === burst.host && String(e.raw?.["event.code"] ?? "") === "4625");
  if (!tpl) return undefined;
  const named = new Set(events.filter(e => e !== anchor).map(e => String(e.raw?.["winlog.event_data.TargetUserName"] ?? e.user_email ?? "")).map(u => short(u).toLowerCase()).filter(Boolean));
  const slot = new Map<string, string>();
  const attempts: Attempt[] = burst.attempts.map(a => {
    const key = short(a.user).toLowerCase();
    let user = a.user;
    if (!named.has(key)) { if (!slot.has(key)) slot.set(key, `#${slot.size}`); user = slot.get(key)!; }
    const st = (a.status ?? "").toLowerCase();
    return { at: a.at, user, host: burst.host, outcome: st === "0x0" ? "ok" : st === "0xc0000234" ? "locked" : "fail" };
  });
  return { plan: { template: tpl.id, anchor: anchor.id, draws: slot.size, attempts }, anchor, burst };
}

/** Burst rows slot in by time; the authored rows keep their own order. */
function mergeByTime(events: TelemetryEvent[], rows: TelemetryEvent[]): TelemetryEvent[] {
  const out = [...events];
  for (const r of [...rows].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts))) {
    const t = Date.parse(r.ts);
    const at = out.findIndex(e => Date.parse(e.ts) > t);
    out.splice(at < 0 ? out.length : at, 0, r);
  }
  return out;
}

/**
 * The story's events with its failure burst written out. `pool` is the company's noise pool: the
 * drawn accounts are its people. A story with no plan comes back unchanged.
 */
export function withAuthBurst(storyId: string, events: TelemetryEvent[], pool: TelemetryEvent[]): TelemetryEvent[] {
  const fromBurst = PLANS[storyId] ? undefined : planFromBurst(events);
  const plan = PLANS[storyId] ?? fromBurst?.plan;
  if (!plan) return events;
  const tpl = events.find(e => e.id === plan.template);
  const anchor = events.find(e => e.id === plan.anchor);
  const t0 = anchor ? Date.parse(anchor.ts) : NaN;
  if (!tpl || !Number.isFinite(t0)) return events;
  // Every account the story names already stays out of the draw.
  const taken = new Set<string>();
  for (const e of events) if (e.user_email) taken.add(short(e.user_email).toLowerCase());
  for (const a of plan.attempts) if (!a.user.startsWith("#")) taken.add(short(a.user).toLowerCase());
  for (const u of Object.values(plan.own ?? {})) if (!u.startsWith("#")) taken.add(short(u).toLowerCase());
  const drawn = drawPeople(storyId, plan.draws, pool, taken, plan.spare);
  const who = (u: string) => (u.startsWith("#") ? drawn[Number(u.slice(1))] : u);
  // A drawn slot the company cannot fill (a tiny directory) is left out rather than invented.
  const attempts = plan.attempts.filter(a => who(a.user));
  const tech = plan.retag?.[plan.template];
  const rows = attempts.map((a, i) => {
    const row = attemptRow(tpl, `${plan.template}_b${String(i + 1).padStart(2, "0")}`, new Date(t0 + Math.round(a.at * 1000)).toISOString(), who(a.user)!, a.outcome ?? "fail", a.host, i + 1);
    return tech ? { ...row, mitre_technique: tech } : row;
  });
  const patched = events.map(e => {
    let out = e;
    const owner = plan.own?.[e.id];
    if (owner && who(owner) && !e.user_email) out = withAccount(out, who(owner)!);
    const t = plan.retag?.[e.id];
    if (t) out = { ...out, mitre_technique: t };
    // The spray is now in the feed: the 4740 keeps only the domain controller's side (4776) for the XDR tables.
    if (fromBurst && e.id === fromBurst.anchor.id) {
      const b = fromBurst.burst;
      out = { ...out, _burst: { dc: b.dc, ip: b.ip, workstation: b.workstation,
        attempts: b.attempts.map((a, i) => ({ ...a, user: who(plan.attempts[i].user) ?? a.user })).filter((_, i) => who(plan.attempts[i].user)) } } as TelemetryEvent;
    }
    return out;
  });
  return mergeByTime(patched, rows);
}
