import type { TelemetryEvent } from "@/lib/sim/types";
import { isPeerAddressedRecord } from "@/lib/sim/peerRecords";
import { makeCtx } from "@/lib/logs/native/ctx";
import { accountSid } from "@/lib/logs/native/sources/_sid";
import { edrFacts, threadOf, withThread } from "@/lib/logs/native/sources/edr-normalize";
import { entraObjectId } from "@/lib/logs/native/sources/_identity-common";

/**
 * One host, one IP - and never one IP for two hosts - across a feed pool.
 *
 * The authored noise pools were written event by event, so the same workstation shows
 * up with two or three addresses (WH-TERM-005: .5 / .44 / .82) and two hosts sometimes
 * share one. The first pivot an analyst makes - "what else did this IP / this host do?" -
 * then lies. Each host keeps its most frequent outbound address; an address another host
 * already owns moves to a free one in the same /24. Only host-originated events change
 * (a host's own telemetry, its outbound network rows), and the old address is replaced
 * in that event's raw fields too, so the record agrees with the row.
 */
const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const HOSTISH = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit", "firewall", "proxy", "dns"]);
const inbound = (e: TelemetryEvent) =>
  (e.network as { direction?: string } | undefined)?.direction === "inbound" || /inbound/i.test(String(e.raw?.["network.direction"] ?? ""));
// A logon or share record's IpAddress is the remote client's: it never says what this computer's address is.
const hostOwned = (e: TelemetryEvent) => !!e.hostname && !!e.src_ip && PRIVATE.test(e.src_ip) && HOSTISH.has(e.source) && !inbound(e) && !isPeerAddressedRecord(e);

export function normalizeHostIps(events: TelemetryEvent[]): TelemetryEvent[] {
  const counts = new Map<string, Map<string, number>>();
  for (const e of events) {
    if (!hostOwned(e)) continue;
    const h = e.hostname!.toUpperCase();
    const m = counts.get(h) ?? new Map<string, number>();
    m.set(e.src_ip!, (m.get(e.src_ip!) ?? 0) + 1);
    counts.set(h, m);
  }
  const owner = new Map<string, string>();   // ip → host
  const canonical = new Map<string, string>();
  // Hosts with the most evidence claim their address first.
  const hosts = [...counts].sort((a, b) => Math.max(...b[1].values()) - Math.max(...a[1].values()) || a[0].localeCompare(b[0]));
  const allIps = new Set(events.flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && PRIVATE.test(x)));
  for (const [h, m] of hosts) {
    const ranked = [...m].sort((a, b) => b[1] - a[1]).map(([ip]) => ip);
    let ip = ranked.find(x => !owner.has(x));
    if (!ip) {
      const base = ranked[0].split(".").slice(0, 3).join(".");
      for (let i = 2; i < 255 && !ip; i++) { const c = `${base}.${i}`; if (!owner.has(c) && !allIps.has(c)) ip = c; }
      ip = ip ?? ranked[0];
    }
    owner.set(ip, h); canonical.set(h, ip);
  }
  return events.map(e => {
    if (!hostOwned(e)) return e;
    const want = canonical.get(e.hostname!.toUpperCase());
    if (!want || want === e.src_ip) return e;
    const old = e.src_ip!;
    const raw = e.raw ? Object.fromEntries(Object.entries(e.raw).map(([k, v]) => [k, v === old ? want : v])) : e.raw;
    return { ...e, src_ip: want, raw };
  });
}

/**
 * One account, one SID (R3) across a company's feed. The noise pool and the stories were authored
 * one by one, so a person's 4624 in the noise carried one domain SID and the same person's 4688 in a
 * story another (the realism gate counted 30 such accounts). Every authored domain-user SID next to
 * the account it names becomes that account's SID as every native renderer derives it
 * (_sid.ts accountSid): the Windows Security record, the EDR row and the M365 record then agree.
 * Well-known SIDs (S-1-5-18 ...) and machine accounts (NAME$) are left as they are; a group SID
 * (TargetSid of a 4728 / 4732) is never touched, only the member's.
 */
const SID_OF_NAME: [RegExp, RegExp][] = [
  [/(^|\.)TargetUserSid$/, /(^|\.)TargetUserName$/],
  [/(^|\.)SubjectUserSid$/, /(^|\.)SubjectUserName$/],
  // The EDR vocabularies the story pass reads a user's SID from (_proc-identity SID_PAIRS).
  [/(^|\.)AccountSid$/, /(^|\.)AccountName$/],
  [/(^|\.)InitiatingProcessAccountSid$/, /(^|\.)InitiatingProcessAccountName$/],
  [/(^|\.)UserSid$/, /(^|\.)UserName$/],
  [/(^|\.)user\.id$/, /(^|\.)user\.name$/],
  // A 4769's service account (a user-run SPN such as svc-mssql; machine accounts NAME$ are skipped).
  [/(^|\.)ServiceSid$/, /(^|\.)ServiceName$/],
];
export function normalizeAccountSids(events: TelemetryEvent[], companyId: string): TelemetryEvent[] {
  const ctx = makeCtx(companyId);
  /** The same rule inside nested objects: an object with a login-style Name and a domain-user Sid. Returns the input when nothing changes. */
  const fixEntitySids = (v: unknown): unknown => {
    if (typeof v === "string") {
      if (!/S-1-5-21-/.test(v) || !/^\s*[[{]/.test(v)) return v;
      try { const parsed = JSON.parse(v); const f = fixEntitySids(parsed); return f === parsed ? v : JSON.stringify(f); } catch { return v; }
    }
    if (Array.isArray(v)) { let changed = false; const a = v.map(x => { const f = fixEntitySids(x); if (f !== x) changed = true; return f; }); return changed ? a : v; }
    if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      let res: Record<string, unknown> | null = null;
      const name = o.Name ?? o.AccountName, sid = o.Sid ?? o.AadUserSid;
      if (typeof sid === "string" && /^S-1-5-21-/.test(sid) && typeof name === "string" && /^[a-z][a-z0-9._-]*$/i.test(name) && !name.endsWith("$")) {
        const want = accountSid(ctx, name);
        if (want !== sid) res = { ...o, [o.Sid !== undefined ? "Sid" : "AadUserSid"]: want };
      }
      for (const [k, x] of Object.entries(res ?? o)) {
        if (k === "Sid") continue;
        const f = fixEntitySids(x);
        if (f !== x) (res ??= { ...o })[k] = f;
      }
      return res ?? v;
    }
    return v;
  };
  return events.map(e => {
    const raw = e.raw;
    if (!raw) return e;
    let out: Record<string, unknown> | null = null;
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v !== "string" || !/^S-1-5-21-/.test(v)) continue;
      let name: unknown;
      for (const [sidRe, nameRe] of SID_OF_NAME) {
        if (!sidRe.test(k)) continue;
        const nk = Object.keys(raw).find(x => nameRe.test(x) && x.slice(0, x.lastIndexOf(".") + 1) === k.slice(0, k.lastIndexOf(".") + 1));
        name = nk ? raw[nk] : undefined;
      }
      if (/(^|\.)MemberSid$/.test(k)) {
        const mk = Object.keys(raw).find(x => /(^|\.)MemberName$/.test(x));
        const m = mk ? /^CN=([^,]+)/i.exec(String(raw[mk])) : null;
        name = m ? m[1] : undefined;
        // a CN is a display name ("Anna Weber"); only a login-style CN maps to an account
        if (typeof name === "string" && !/^[a-z][a-z0-9._-]*$/i.test(name)) name = undefined;
      }
      if (typeof name !== "string" || !name || name === "-" || name.endsWith("$")) continue;
      const want = accountSid(ctx, name);
      if (want !== v) (out ??= { ...raw })[k] = want;
    }
    // One object id per UPN: an authored AccountObjectId beside its AccountUpn is the Entra object id every
    // Microsoft record derives for that user (entraObjectId), so a re-homed story does not keep the author's.
    for (const [k, v] of Object.entries(out ?? raw)) {
      if (typeof v !== "string" || !/(^|\.)AccountObjectId$/.test(k)) continue;
      const upn = (out ?? raw)[k.replace(/AccountObjectId$/, "AccountUpn")];
      if (typeof upn !== "string" || !upn.includes("@")) continue;
      const want = entraObjectId(ctx, upn);
      if (want !== v) (out ??= { ...raw })[k] = want;
    }
    // Nested account entities ({ Name, Sid } in a Sentinel / MDI alert's Entities, also JSON-encoded).
    for (const [k, v] of Object.entries(out ?? raw)) {
      const fixed = fixEntitySids(v);
      if (fixed !== v) (out ??= { ...raw })[k] = fixed;
    }
    let ev = out ? { ...e, raw: out } : e;
    // The story pass threads the user's authored SID onto every endpoint row of that user (EDR records
    // without a SID of their own print it): it follows the same rule, or the 4624 and the EDR row disagree.
    const t = threadOf(ev);
    if (t?.sid && /^S-1-5-21-/.test(t.sid)) {
      let user: string | undefined;
      try { user = edrFacts(ev).user ?? undefined; } catch { user = undefined; }
      user = user ?? t.proc?.user ?? t.user ?? ev.process?.user ?? ev.user_email?.split("@")[0];
      if (user && user !== "-" && !user.endsWith("$")) {
        const want = accountSid(ctx, user);
        if (want !== t.sid) ev = withThread(ev, { ...t, sid: want });
      }
    }
    return ev;
  });
}
