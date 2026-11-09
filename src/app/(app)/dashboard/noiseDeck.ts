/**
 * The solo Live Feed's ordinary noise, drawn from the company pool (pure, no React).
 *
 * R8 (docs/LOG-REALISM-STANDARD.md): repeated benign rows are drawn fresh, never copied. The small
 * company pools (QuantumBank has about twenty ordinary rows) cycle within one shift, and the feed used
 * to show the same "security-admin added n.schulz to Core-Banking-DB-Admins" three times, and the
 * same mail three times. Now:
 *  - a one-off action (an account or group change, a mail, a ticket, a policy change) appears at most
 *    once per shift;
 *  - recurring telemetry (a sign-in, a process start, a connection, a DNS lookup, a VPN session) comes
 *    back as the same activity by ANOTHER person of the company, on that person's own machine.
 * R3: the swap is whole. The old feed changed only `user_email` and the prose ("raw fields left
 * intact"), so a row named one person and its record another. A variant replaces the person in every
 * form (mail address, login name, display name) across the whole row, and their workstation and its
 * address with the new person's own. A row that carries an authored SID, or a person with no known
 * name or machine where one is needed, is never varied (it is simply not repeated).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { isRehomeablePerson } from "@/lib/sim/nonHuman";
import { isPeerAddressedRecord } from "@/lib/sim/peerRecords";
import { hostOsFromRows } from "@/lib/sim/hostOs";
import { COMPANY_ASSETS, companyHostOs, type HostOs } from "@/lib/sim/companyProfilesMeta";

/** Telemetry a company produces over and over: a second occurrence is another instance, not a copy. */
export const RECURRING_TYPES = new Set([
  "auth_success", "auth_failure", "mfa_challenge", "mfa_denied", "process_create", "net_connection",
  "net_blocked", "dns_query", "vpn_login", "vpn_logout", "vpn_failed", "file_access", "sharepoint_access",
  "cloud_api_call", "http_request", "kerberos_tgt", "kerberos_tgs",
]);

export const isOnceOnlyNoise = (e: TelemetryEvent) =>
  !!(e.it_verify_result || e.fp_explanation || e.expected_verdict === "fp");

const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const HOSTISH = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit", "firewall", "proxy", "dns"]);
const SERVERISH = /^(srv|svr|server|prod|db|web|app|sql)[-_]|[-_](dc|fs|srv|sql|db|file|exch|app|web)[-_]?\d*$/i;
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function replaceAll(value: unknown, pairs: [RegExp, string][]): unknown {
  if (typeof value === "string") { let out = value; for (const [re, to] of pairs) out = out.replace(re, to); return out; }
  if (Array.isArray(value)) return value.map(v => replaceAll(v, pairs));
  if (value && typeof value === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) o[k] = replaceAll(v, pairs);
    return o;
  }
  return value;
}

interface Person { email: string; name?: string; home?: string; user?: TelemetryEvent["user"]; title?: string }

export class NoiseDeck {
  private deck: TelemetryEvent[] = [];
  private pos = 0;
  private cycle = 0;
  private seenOnce = new Set<string>();
  private usedOneOff = new Set<string>();
  private variants = 0;
  private people: Person[] = [];
  private byEmail = new Map<string, Person>();
  private hostIp = new Map<string, string>();
  private hostOsMemo = new Map<string, HostOs | undefined>();
  /** Pool row id -> the people it has already been shown for this shift. */
  private usedPeople = new Map<string, Set<string>>();

  constructor(private pool: TelemetryEvent[], private rnd: () => number = Math.random) {
    this.learnCompany();
    this.deck = this.shuffle(pool.filter(e => !isOnceOnlyNoise(e)));
  }

  /** The first `n` rows of a fresh shift (diverse sources: drawn from a shuffle of the whole pool). */
  backfill(n: number): TelemetryEvent[] {
    const pick = this.shuffle(this.pool).slice(0, n);
    for (const e of pick) this.markUsed(e);
    const taken = new Set(pick.map(e => e.id));
    this.deck = this.deck.filter(e => !taken.has(e.id)).concat(this.deck.filter(e => taken.has(e.id)));
    return pick;
  }

  /** The next ordinary row: now and then an unsent once-only training row, else the deck. */
  next(): TelemetryEvent | null {
    if (this.rnd() < 0.10) {
      const unsent = this.pool.filter(e => isOnceOnlyNoise(e) && !this.seenOnce.has(e.id));
      if (unsent.length > 0) { const e = unsent[Math.floor(this.rnd() * unsent.length)]; this.markUsed(e); return e; }
    }
    if (this.deck.length === 0) return null;
    // Bounded: two full passes cannot all be unusable unless the pool has nothing recurring.
    for (let tries = 0; tries < this.deck.length * 2 + 2; tries++) {
      if (this.pos >= this.deck.length) { this.deck = this.shuffle(this.deck); this.pos = 0; this.cycle++; }
      const e = this.deck[this.pos++];
      const oneOff = !RECURRING_TYPES.has(e.event_type);
      if (oneOff) {
        if (this.usedOneOff.has(e.id)) continue;
        this.markUsed(e);
        return e;
      }
      if (this.cycle === 0 && !this.usedOneOff.has(e.id)) { this.markUsed(e); return e; }
      const v = this.variant(e);
      if (v) return v;
    }
    return null;
  }

  private markUsed(e: TelemetryEvent) {
    if (isOnceOnlyNoise(e)) this.seenOnce.add(e.id);
    this.usedOneOff.add(e.id);
  }

  private shuffle<T>(arr: T[]): T[] {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(this.rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
  }

  /** Who works here, under what name, at which machine, and each machine's own address. */
  private learnCompany() {
    const hostUsers = new Map<string, Map<string, number>>();
    const ipCounts = new Map<string, Map<string, number>>();
    for (const e of this.pool) {
      const u = e.user_email;
      if (isRehomeablePerson(u)) {
        const p = this.byEmail.get(u) ?? { email: u };
        if (!p.name && e.user?.full_name) p.name = e.user.full_name;
        if (!p.user && e.user) p.user = e.user;
        if (!p.title && e.user_title) p.title = e.user_title;
        if (!this.byEmail.has(u)) { this.byEmail.set(u, p); this.people.push(p); }
        if (e.hostname && !SERVERISH.test(e.hostname)) {
          const m = hostUsers.get(e.hostname) ?? new Map<string, number>();
          m.set(u, (m.get(u) ?? 0) + 1); hostUsers.set(e.hostname, m);
        }
      }
      const inbound = (e.network as { direction?: string } | undefined)?.direction === "inbound";
      if (e.hostname && e.src_ip && PRIVATE.test(e.src_ip) && HOSTISH.has(e.source) && !inbound && !isPeerAddressedRecord(e)) {
        const m = ipCounts.get(e.hostname) ?? new Map<string, number>();
        m.set(e.src_ip, (m.get(e.src_ip) ?? 0) + 1); ipCounts.set(e.hostname, m);
      }
    }
    for (const [h, m] of ipCounts) this.hostIp.set(h, [...m].sort((a, b) => b[1] - a[1])[0][0]);
    // A machine is a person's home when they are its main user; one home per person.
    const claimed = new Set<string>();
    const ranked = [...hostUsers].map(([h, m]) => [h, [...m].sort((a, b) => b[1] - a[1])[0]] as const).sort((a, b) => b[1][1] - a[1][1]);
    for (const [h, [u]] of ranked) {
      const p = this.byEmail.get(u);
      if (p && !p.home && !claimed.has(h)) { p.home = h; claimed.add(h); }
    }
  }

  /** The OS a machine runs: the company's registry when it keeps one, else what the pool's rows show. */
  private osOf(h: string, domain: string): HostOs | undefined {
    const key = `${domain}|${h}`;
    if (this.hostOsMemo.has(key)) return this.hostOsMemo.get(key);
    const co = Object.keys(COMPANY_ASSETS).find(c => COMPANY_ASSETS[c].domain === domain);
    const os = co && COMPANY_ASSETS[co].hostOs ? companyHostOs(co, h) : hostOsFromRows(h, this.pool);
    this.hostOsMemo.set(key, os);
    return os;
  }

  /** The same recurring activity by another person of the company, on their own machine. */
  private variant(e: TelemetryEvent): TelemetryEvent | null {
    const old = e.user_email;
    if (!isRehomeablePerson(old)) return null;
    const text = JSON.stringify(e);
    if (/S-1-5-21-/.test(text)) return null;
    const from = this.byEmail.get(old);
    const onHome = !!(e.hostname && from?.home && e.hostname === from.home);
    if (e.hostname && !onHome && !SERVERISH.test(e.hostname)) return null;   // someone else's desk: not ours to move
    // A public client address is where that person was (home, hotel, mobile): another person is never there.
    if ((e.src_ip && !PRIVATE.test(e.src_ip)) || (e.dst_ip && !PRIVATE.test(e.dst_ip) && e.source === "vpn")) return null;
    const needsName = !!(from?.name && text.includes(from.name));
    const rowOs = onHome ? this.osOf(e.hostname!, old.split("@")[1]) : undefined;
    const cands = this.people.filter(p => p.email !== old && p.email.split("@")[1] === old.split("@")[1]
      && (!onHome || (p.home && this.hostIp.has(p.home) === this.hostIp.has(e.hostname!)))
      // A MacBook's process row moves to another Mac, never onto a Windows desk.
      && (!onHome || !rowOs || [undefined, rowOs].includes(this.osOf(p.home!, p.email.split("@")[1])))
      && (!needsName || !!p.name));
    if (cands.length === 0) return null;
    // People this row has not shown yet come first, so a repeat is a new instance, not a copy.
    const used = this.usedPeople.get(e.id) ?? this.usedPeople.set(e.id, new Set([old])).get(e.id)!;
    const unused = cands.filter(p => !used.has(p.email));
    const pickFrom = unused.length ? unused : cands;
    const to = pickFrom[Math.floor(this.rnd() * pickFrom.length)];
    used.add(to.email);
    const pairs: [RegExp, string][] = [];
    const word = (s: string) => new RegExp(`(?<![A-Za-z0-9._-])${esc(s)}(?![A-Za-z0-9_-])`, "g");
    pairs.push([new RegExp(esc(old), "gi"), to.email]);
    pairs.push([word(old.split("@")[0]), to.email.split("@")[0]]);
    if (needsName && from?.name && to.name) pairs.push([new RegExp(esc(from.name), "g"), to.name]);
    if (onHome && to.home) {
      pairs.push([word(e.hostname!), to.home]);
      const a = this.hostIp.get(e.hostname!), b = this.hostIp.get(to.home);
      if (a && b) pairs.push([new RegExp(`(?<![\\d.])${esc(a)}(?![\\d])`, "g"), b]);
    }
    const { id, ts, ...rest } = e;
    const moved = replaceAll(rest, pairs) as Omit<TelemetryEvent, "id" | "ts">;
    this.variants++;
    const out = { ...moved, id: `${id}_v${this.variants}`, ts } as TelemetryEvent;
    // The person's own job, not the previous one's (a title is not a name, so the swap above leaves it).
    if (out.user_title !== undefined) out.user_title = to.title ?? to.user?.title;
    if (out.user) out.user = to.user ? { ...to.user } : { ...out.user, title: to.title, department: undefined };
    return out;
  }
}
