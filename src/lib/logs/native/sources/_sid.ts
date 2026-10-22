/**
 * One SID per account in every product (not a module itself). Kept dependency-free (it needs only the
 * NativeCtx shape) so the log emitters (src/lib/sim/emitters) can author the very SID the native
 * renderers derive: an emitter-written 4624 TargetUserSid equals the user's Falcon / Defender / Sysmon SID.
 */
import type { NativeCtx } from "../types";

const WELL_KNOWN_SID: Record<string, string> = {
  system: "S-1-5-18", "nt authority\\system": "S-1-5-18", "local system": "S-1-5-18",
  "local service": "S-1-5-19", "nt authority\\local service": "S-1-5-19",
  "network service": "S-1-5-20", "nt authority\\network service": "S-1-5-20",
};
/**
 * The account's SID: well-known for the service accounts, else the user's domain SID: derived exactly as
 * the Windows Security module derives TargetUserSid / SubjectUserSid (./windows_security), so the user an
 * EDR row names carries the SID of that user's 4624 / 4688 on the same domain. An authored SID
 * (EdrFacts.sid, threaded from any record of the story) is used instead whenever the story has one.
 * The M365 records' LogonUserSid / MailboxOwnerSid (collab-email-shared userSid) use this same function.
 */
export function accountSid(ctx: NativeCtx, user: string, _email?: string): string {
  const u = user.toLowerCase();
  const known = WELL_KNOWN_SID[u] ?? WELL_KNOWN_SID[u.split("\\").pop()!];
  if (known) return known;
  const sam = u.split("\\").pop()!.split("@")[0].replace(/\$$/, "");
  // The story's own SID for this account (a standalone scenario's authored 4624 / Falcon UserSid).
  const authored = ctx.userSids?.get(sam);
  if (authored) return authored;
  return `S-1-5-21-${domainSidOf(ctx)}-${ctx.int(`${ctx.companyId}:winsec:rid:${sam}`, 1104, 9800)}`;
}

/**
 * The company's AD domain identifier (the three sub-authorities after S-1-5-21-): ONE per company in
 * every product. NexaCorp's is the value its authored records use; the others are derived with full
 * diffusion (three independent 32-bit values, not three neighbouring hashes of one seed).
 */
const FIXED_DOMAIN_SID: Record<string, string> = { nexacorp: "3421479547-3897544621-1789562108" };
const storyDomain = new WeakMap<ReadonlyMap<string, string>, string | null>();
export function domainSidOf(ctx: NativeCtx): string {
  // A standalone scenario's own domain: the one its authored SIDs use (the most common).
  if (ctx.userSids?.size) {
    let d = storyDomain.get(ctx.userSids);
    if (d === undefined) {
      const votes = new Map<string, number>();
      for (const sid of ctx.userSids.values()) { const m = /^S-1-5-21-(\d+-\d+-\d+)-\d+$/.exec(sid); if (m) votes.set(m[1], (votes.get(m[1]) ?? 0) + 1); }
      d = [...votes.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
      storyDomain.set(ctx.userSids, d);
    }
    if (d) return d;
  }
  const fixed = FIXED_DOMAIN_SID[ctx.companyId];
  if (fixed) return fixed;
  const h = seededHexOf(ctx, `${ctx.companyId}:winsec:domain-sid`, 24);
  return [0, 1, 2].map(i => String(1_000_000_000 + (parseInt(h.slice(i * 8, i * 8 + 8), 16) % 3_000_000_000))).join("-");
}
const seededHexOf = (ctx: NativeCtx, seed: string, len: number) => { let o = ""; for (let i = 0; o.length < len; i++) o += ctx.hex(`${i}|${seed}`, 8); return o.slice(0, len); };
