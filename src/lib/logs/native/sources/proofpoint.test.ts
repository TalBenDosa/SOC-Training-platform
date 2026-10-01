import { describe, it, expect } from "vitest";
import { source, kindOf } from "./proofpoint";
import { validateNative } from "../validate";
import { cardSamples, corpus } from "../testing/corpus";
import type { NativeLog } from "../types";
import { convertAll, hasMailVerdict, highFired, hitCounts, isNativeVendor, isPlanted, present, strings } from "./collab-email-testkit";

const schema = source.schema;
const ARRAYS = ["messagesDelivered", "messagesBlocked", "clicksPermitted", "clicksBlocked"];
const timeOf = (r: Record<string, unknown>) => Date.parse(String(r.messageTime ?? r.clickTime));

/**
 * Card samples: P1–P5 are bare objects (kind via kindOf), P6 is a full /v2/siem/all response whose
 * array names give the kind. SKIPPED: the §2 response envelope with four EMPTY arrays (no event inside).
 */
function toLogs(s: Record<string, unknown>): NativeLog[] {
  if ("queryEndTime" in s) return ARRAYS.flatMap(a => ((s[a] as Record<string, unknown>[]) ?? []).map(r => ({ sourceId: "proofpoint" as const, kind: a, format: "json" as const, record: r, timeMs: timeOf(r) })));
  const k = kindOf(s);
  return k ? [{ sourceId: "proofpoint", kind: k, format: "json", record: s, timeMs: timeOf(s) }] : [];
}
const samples = cardSamples(schema.card) as Record<string, unknown>[];
const sampleLogs = samples.flatMap(toLogs);

const converted = convertAll(source);
const o365Mail = corpus().filter(c => c.ev.source === "o365" && /^email_/.test(c.ev.event_type));
const o365Converted = convertAll(source, o365Mail);
const all = [...converted, ...o365Converted];

describe("proofpoint — card samples", () => {
  it("every card sample validates with zero violations; kinds follow the wire arrays", () => {
    expect(sampleLogs.length).toBe(6);
    for (const l of sampleLogs) expect(validateNative(l, schema), l.kind).toEqual([]);
    expect(sampleLogs.map(l => l.kind).sort()).toEqual(["clicksBlocked", "clicksPermitted", "clicksPermitted", "messagesBlocked", "messagesDelivered", "messagesDelivered"]);
  });
});

describe("proofpoint — corpus conversion", () => {
  it("validates; native 100 %; Defender-authored threats rendered, clean mail null", () => {
    for (const c of all) if (c.log) expect(validateNative(c.log, schema), c.ce.ev.id).toEqual([]);
    const native = converted.filter(c => isNativeVendor(source, c.ce.ev));
    const cross = all.filter(c => !isNativeVendor(source, c.ce.ev));
    console.log(`[proofpoint] native ${native.filter(c => c.log).length}/${native.length}; cross-vendor (Defender/UAL-authored mail) ${cross.filter(c => c.log).length}/${cross.length}`);
    console.log(`[proofpoint] cross-vendor nulls (no TAP threat event / outbound / post-delivery): ${cross.filter(c => !c.log).map(c => c.ce.ev.id).join(", ")}`);
    expect(native.filter(c => c.log).length / native.length).toBeGreaterThanOrEqual(0.95);
    expect(cross.filter(c => c.log).length).toBeGreaterThanOrEqual(8);
    // TAP only reports threats: clean / baseline / outbound mail never becomes a TAP event.
    for (const c of all) if (c.ce.ev.is_baseline || c.ce.ev.event_type === "email_sent" || c.ce.ev.expected_verdict === "fp") expect(c.log, c.ce.ev.id).toBeNull();
  });

  it("evidence values survive verbatim", () => {
    let n = 0;
    for (const c of all) {
      if (!c.log) continue;
      const ev = c.ce.ev;
      const hay = strings(c.log.record);
      const user = ev.user?.email ?? ev.user_email;
      if (user) expect(present(hay, user), `${ev.id} user`).toBe(true);
      if (ev.src_ip) expect(present(hay, ev.src_ip), `${ev.id} ip`).toBe(true);
      if (ev.network?.url) expect(present(hay, ev.network.url), `${ev.id} url`).toBe(true);
      const sha = ev.raw["email.attachments.file.hash.sha256"] ?? ev.raw["data.office365.AttachmentSha256"];
      if (typeof sha === "string") expect(present(hay, sha), `${ev.id} sha`).toBe(true);
      const imid = ev.raw["email.message_id"] ?? ev.raw["data.office365.InternetMessageId"] ?? ev.raw["pps.messageID"];
      if (typeof imid === "string") expect(present(hay, imid), `${ev.id} imid`).toBe(true);
      const qid = ev.raw["pps.QID"];
      if (typeof qid === "string" && c.log.kind.startsWith("messages")) expect(c.log.record.QID).toBe(qid);
      n++;
    }
    expect(n).toBeGreaterThan(8);
  });

  it("GUID / threatID / threatTime link the message and its click; wire-format quirks hold", () => {
    const msg = converted.find(c => c.ce.ev.id === "aitm_01_lure")!.log!;
    const click = converted.find(c => c.ce.ev.id === "aitm_02_click")!.log!;
    expect(msg.kind).toBe("messagesDelivered");
    expect(click.kind).toBe("clicksPermitted");
    expect(click.record.GUID).toBe(msg.record.GUID);
    expect(click.record.messageID).toBe(msg.record.messageID);
    const t = (msg.record.threatsInfoMap as Array<Record<string, unknown>>).find(x => x.threatType === "url")!;
    expect(click.record.threatID).toBe(t.threatID);
    expect(click.record.threatTime).toBe(t.threatTime);
    expect(Date.parse(String(click.record.clickTime))).toBeLessThan(Date.parse(String(click.record.threatTime))); // clicked before conviction
    for (const c of all) {
      if (!c.log) continue;
      const r = c.log.record as Record<string, any>;
      if (c.log.kind.startsWith("messages")) {
        expect(Array.isArray(r.recipient) && Array.isArray(r.fromAddress)).toBe(true);
        expect(typeof r.completelyRewritten).toBe("boolean");
        for (const x of r.threatsInfoMap) { expect(x.classification).toMatch(/^[a-z]+$/); expect(x.threatType).toMatch(/^(url|attachment|message)$/); expect("campaignID" in x).toBe(true); }
      } else {
        expect(typeof r.recipient).toBe("string");
        expect("threatURL" in r && "campaignId" in r).toBe(true);
      }
    }
  });

  it("is deterministic", () => {
    expect(convertAll(source).map(c => c.log)).toEqual(converted.map(c => c.log));
  });
});

describe("proofpoint — use cases", () => {
  const attack = [...sampleLogs, ...all.filter(c => c.ce.origin === "story" && c.log).map(c => c.log!)];
  // Noise = benign / company mail without a product verdict (see hasMailVerdict) — TAP renders none of it.
  const benign = all.filter(c => c.ce.origin !== "story" && !isPlanted(c.ce.ev) && !hasMailVerdict(c.ce.ev));
  const noise = benign.filter(c => c.log).map(c => c.log!);

  it("every use case fires", () => {
    const counts = hitCounts(source.useCases, attack);
    console.log("[proofpoint] use-case hits (attack set):", counts);
    for (const uc of source.useCases) expect(counts[uc.id], uc.id).toBeGreaterThan(0);
  });

  it("benign mail produces (almost) no TAP events, and high/critical rules stay < 2 % on it", () => {
    const fired = highFired(source.useCases, noise);
    console.log(`[proofpoint] benign mail events ${benign.length}, rendered as TAP events ${noise.length}, high/critical hits ${fired.size}`);
    expect(fired.size / Math.max(benign.length, 1)).toBeLessThan(0.02);
  });
});
