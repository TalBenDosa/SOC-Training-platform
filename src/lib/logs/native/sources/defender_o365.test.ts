import { describe, it, expect } from "vitest";
import { source, kindOf, companionLogs } from "./defender_o365";
import { validateNative } from "../validate";
import { cardSamples, corpus } from "../testing/corpus";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { convertAll, hasMailVerdict, highFired, hitCounts, isNativeVendor, isPlanted, present, strings } from "./collab-email-testkit";

const schema = source.schema;
const TENANT = "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31";

/**
 * Card samples D1–D8 are bare Advanced Hunting rows (the card's query-API form); D9 is a streaming
 * envelope. Our native unit is the streaming record, so D1–D8 are wrapped in the documented envelope
 * ({time, tenantId, category, properties}) and D9 contributes records[0]. No sample is skipped.
 */
function toLogs(sample: Record<string, unknown>): NativeLog[] {
  const recs = Array.isArray(sample.records) ? (sample.records as Record<string, unknown>[]) : [sample];
  return recs.map(r => {
    const k = kindOf(r)!;
    const record = "category" in r ? r : { time: r.Timestamp, tenantId: TENANT, category: `AdvancedHunting-${k}`, properties: r };
    return { sourceId: "defender_o365", kind: k, format: "json", record, timeMs: Date.parse(String((record.properties as Record<string, unknown>).Timestamp)) };
  });
}
const samples = cardSamples(schema.card) as Record<string, unknown>[];
const sampleLogs = samples.filter(s => kindOf(s) !== null).flatMap(toLogs);

const converted = convertAll(source);
// Mail-flow events authored under source "o365" (Defender verdicts and UAL-labelled MessageDelivered / SpamFiltered / Send):
// email-security telemetry that the m365 module leaves to this category.
const o365Mail = corpus().filter(c => c.ev.source === "o365" && /^email_/.test(c.ev.event_type));
const o365Converted = convertAll(source, o365Mail);
const companions = (c: (typeof converted)[number]) => companionLogs(c.ce.ev, makeCtx(c.ce.companyId));

describe("defender_o365 — card samples", () => {
  it("every card sample validates with zero violations", () => {
    expect(sampleLogs.length).toBe(9);
    for (const l of sampleLogs) expect(validateNative(l, schema), l.kind).toEqual([]);
  });
});

describe("defender_o365 — corpus conversion", () => {
  it("validates; native ≥ 95 %; cross-vendor + o365 mail-flow coverage", () => {
    const all = [...converted, ...o365Converted];
    for (const c of all) {
      if (c.log) expect(validateNative(c.log, schema), c.ce.ev.id).toEqual([]);
      for (const x of companions(c)) expect(validateNative(x, schema), `${c.ce.ev.id} ${x.kind}`).toEqual([]);
    }
    const native = converted.filter(c => isNativeVendor(source, c.ce.ev));
    const cross = converted.filter(c => !isNativeVendor(source, c.ce.ev));
    console.log(`[defender_o365] native ${native.filter(c => c.log).length}/${native.length}; cross-vendor (Proofpoint-authored) ${cross.filter(c => c.log).length}/${cross.length}; ` +
      `o365-source mail events ${o365Converted.filter(c => c.log).length}/${o365Converted.length}; companion rows ${all.reduce((n, c) => n + companions(c).length, 0)}`);
    expect(native.filter(c => c.log).length / native.length).toBeGreaterThanOrEqual(0.95);
    expect(cross.every(c => c.log)).toBe(true);
    expect(o365Converted.filter(c => c.log).length / o365Converted.length).toBeGreaterThanOrEqual(0.95);
  });

  it("evidence values survive (primary row + its EmailUrlInfo / EmailAttachmentInfo rows)", () => {
    let n = 0;
    for (const c of [...converted, ...o365Converted]) {
      if (!c.log) continue;
      const ev = c.ce.ev;
      const hay = strings(c.log.record, ...companions(c).map(x => x.record));
      const user = ev.user?.email ?? ev.user_email;
      if (user) expect(present(hay, user), `${ev.id} user`).toBe(true);
      if (ev.src_ip) expect(present(hay, ev.src_ip), `${ev.id} ip`).toBe(true);
      if (ev.network?.url) expect(present(hay, ev.network.url), `${ev.id} url`).toBe(true);
      // network.domain is checked when it is the sender or a link domain (EmailEvents has no Reply-To column).
      const fromAddr = String(ev.raw["email.from.address"] ?? ev.raw["pps.sender"] ?? "");
      if (ev.network?.domain && c.log.kind === "EmailEvents" && (ev.network.url || fromAddr.endsWith(`@${ev.network.domain}`)))
        expect(present(hay, ev.network.domain), `${ev.id} domain`).toBe(true);
      const sha = ev.raw["email.attachments.file.hash.sha256"] ?? ev.raw["data.office365.AttachmentSha256"];
      if (typeof sha === "string" && c.log.kind === "EmailEvents") expect(present(hay, sha), `${ev.id} sha`).toBe(true);
      const imid = ev.raw["email.message_id"] ?? ev.raw["data.office365.InternetMessageId"] ?? ev.raw["pps.messageID"];
      if (typeof imid === "string" && c.log.kind !== "UrlClickEvents") expect(present(hay, imid), `${ev.id} imid`).toBe(true);
      n++;
    }
    expect(n).toBeGreaterThan(25);
  });

  it("keeps NetworkMessageId consistent between a message, its click, its ZAP and its companion rows", () => {
    const by = (id: string) => [...converted, ...o365Converted].find(c => c.ce.ev.id === id)!;
    const nm = (l: NativeLog | null) => (l!.record.properties as Record<string, unknown>).NetworkMessageId;
    expect(nm(by("aitm_02_click").log)).toBe(nm(by("aitm_01_lure").log)); // Proofpoint-authored lure + click
    expect(nm(by("aisvg11").log)).toBe(nm(by("aisvg2").log));             // delivery + ZAP
    expect(by("aisvg11").log!.kind).toBe("EmailPostDeliveryEvents");
    for (const c of converted) for (const x of companions(c)) {
      expect(nm(x)).toBe(nm(c.log));
      expect((x.record.properties as Record<string, unknown>).ReportId).toBe((c.log!.record.properties as Record<string, unknown>).ReportId);
    }
  });

  it("native formats: 7-digit Timestamp, JSON-string columns, streaming envelope", () => {
    for (const c of [...converted, ...o365Converted]) {
      if (!c.log) continue;
      const r = c.log.record as Record<string, any>;
      expect(r.category).toBe(`AdvancedHunting-${c.log.kind}`);
      expect(r.properties.Timestamp).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z$/);
      for (const col of ["DetectionMethods", "AuthenticationDetails", "ConfidenceLevel", "UrlChain"]) if (col in r.properties) expect(typeof r.properties[col]).toBe("string");
      expect("LatestDeliveryLocation" in r.properties).toBe(false);
    }
  });

  it("is deterministic", () => {
    expect(convertAll(source).map(c => c.log)).toEqual(converted.map(c => c.log));
    expect(converted.map(companions)).toEqual(converted.map(companions));
  });
});

describe("defender_o365 — use cases", () => {
  const story = [...converted, ...o365Converted].filter(c => c.ce.origin === "story" && c.log);
  const attack = [...sampleLogs, ...story.map(c => c.log!), ...story.flatMap(companions)];
  // Noise = benign / company mail WITHOUT a product verdict. Company events whose authored data already carries a
  // Defender verdict (ThreatTypes / Verdict Malware|Phish, e.g. a quarantined invoice.exe) are real detections, not noise.
  const noiseSet = o365Converted.filter(c => c.ce.origin !== "story" && c.log && !isPlanted(c.ce.ev) && !hasMailVerdict(c.ce.ev));
  const noise = [...noiseSet.map(c => c.log!), ...noiseSet.flatMap(companions)];

  it("every use case fires", () => {
    const counts = hitCounts(source.useCases, attack);
    console.log("[defender_o365] use-case hits (attack set):", counts);
    for (const uc of source.useCases) expect(counts[uc.id], uc.id).toBeGreaterThan(0);
  });

  it("high / critical use cases stay quiet on benign mail flow (< 2 %)", () => {
    const fired = highFired(source.useCases, noise);
    console.log(`[defender_o365] noise: ${fired.size}/${noise.length}`, hitCounts(source.useCases, noise));
    expect(noise.length).toBeGreaterThan(3);
    expect(fired.size / noise.length).toBeLessThan(0.02);
  });
});
