import { describe, it, expect } from "vitest";
import { source, kindOf } from "./linux_auditd";
import { corpusFor } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { sampleLogs, violationsOf, convertAll, contains, isNoise, flatSamples } from "./_dnsHostItsm.testkit";

/*
 * Card samples: all 15 records of host-linux-auditd.md (SYSCALL / EXECVE / CWD / PROCTITLE / PATH /
 * USER_CMD / CRED_ACQ / USER_START / USER_AUTH / USER_LOGIN and 3 sshd lines) are supported — none skipped.
 *
 * Documented nulls: events that are not auditd records and not sshd auth lines — cron / systemd /
 * fail2ban syslog lines, and audit record types this card does not document (CRON_JOB, SERVICE_START,
 * CONFIG_CHANGE). Those need their own card before they can be rendered.
 */
const samples = sampleLogs(source, kindOf);
const events = corpusFor(source.schema.telemetrySources);
const converted = convertAll(source, events);
const UNDOCUMENTED = new Set(["CRON_JOB", "SERVICE_START", "CONFIG_CHANGE"]);
const documentedNull = (raw: Record<string, unknown>) =>
  UNDOCUMENTED.has(String(raw["auditd.log.type"] ?? raw["auditd.log.record_type"] ?? "")) ||
  ["cron", "systemd", "fail2ban"].includes(String(raw["log.source"] ?? "")) && raw["auditd.log.record_type"] === undefined;

/** Shell-style tokens of a command line (quotes stripped). */
function tokens(cmd: string): string[] {
  return (cmd.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map(t => t.replace(/^["']|["']$/g, ""));
}

describe("linux_auditd — card samples", () => {
  it("every supported card sample validates with zero violations", () => {
    expect(samples.skipped).toEqual([]);
    expect(samples.logs.length).toBe(flatSamples(source.schema.card).length);
    for (const l of samples.logs) expect(violationsOf(l, source), `${l.kind}`).toEqual([]);
  });
});

describe("linux_auditd — corpus conversion", () => {
  it("every event converts with zero violations, or is null for a documented reason", () => {
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (!c.log) { expect(documentedNull(c.c.ev.raw ?? {}), `unexpected null ${c.c.ev.id}`).toBe(true); continue; }
      expect(violationsOf(c.log, source), `${c.c.ev.id} → ${c.log.kind}`).toEqual([]);
      expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      if (c.log.kind === "sshd") expect(c.log.rawLine).toMatch(/^<38>\w{3} [ \d]\d \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: /);
      else expect(c.log.rawLine).toMatch(new RegExp(`^(node=\\S+ )?type=${c.log.kind} msg=audit\\(\\d+\\.\\d{3}:\\d+\\): `));
    }
  });
  it("coverage ≥ 95% (all linux_audit events are auditd-native)", () => {
    const candidates = converted.filter(c => !documentedNull(c.c.ev.raw ?? {}));
    const ok = candidates.filter(c => c.log).length;
    const byKind: Record<string, number> = {};
    for (const c of converted) if (c.log) byKind[c.log.kind] = (byKind[c.log.kind] ?? 0) + 1;
    console.log(`[linux_auditd] ${ok}/${candidates.length} (+${converted.length - candidates.length} documented null); kinds ${JSON.stringify(byKind)}`);
    expect(ok / candidates.length).toBeGreaterThanOrEqual(0.95);
  });
  it("evidence survives verbatim", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const ev = c.ev, rec = log.record as Record<string, unknown>;
      const ip = (ev.raw?.["data.srcip"] ?? ev.raw?.["sshd.client_ip"] ?? ev.raw?.["source.ip"] ?? ev.src_ip) as string | undefined;
      if (log.kind === "sshd") {
        expect(rec.hostname).toBe(ev.hostname ?? ev.raw?.["host.hostname"]);
        if (ip) expect(contains(rec, ip), `${ev.id} ip`).toBe(true);
      }
      if (["USER_AUTH", "USER_LOGIN"].includes(log.kind) && ip) expect(rec.addr, `${ev.id} addr`).toBe(ip);
      if ("acct" in rec) {
        const u = (ev.raw?.["data.audit.acct"] ?? ev.raw?.["user.name"] ?? ev.raw?.["data.srcuser"]) as string | undefined;
        if (u) expect(rec.acct, `${ev.id} acct`).toBe(u);
      }
      if (log.kind === "EXECVE" && ev.process?.cmdline) for (const t of tokens(ev.process.cmdline)) expect(contains(rec, t), `${ev.id} argv token ${t}`).toBe(true);
      if (log.kind === "USER_CMD") expect(String(rec.cmd_decoded).length).toBeGreaterThan(0);
      if (log.kind === "PATH" && ev.file?.path) expect(rec.name).toBe(ev.file.path);
    }
  });
  it("hex encoding follows auditd's rule (spaces / quotes → upper-case hex + _decoded)", () => {
    for (const { log } of converted) {
      if (log?.kind !== "EXECVE") continue;
      for (const [k, v] of Object.entries(log.record)) {
        if (!/^a\d+$/.test(k)) continue;
        const dec = log.record[`${k}_decoded`] as string | undefined;
        if (dec !== undefined) { expect(v).toMatch(/^[0-9A-F]+$/); expect(/[\s"'\\]/.test(dec)).toBe(true); }
        else expect(/[\s"'\\]/.test(String(v))).toBe(false);
      }
    }
  });
  it("is deterministic", () => {
    for (const c of events) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("linux_auditd — use cases", () => {
  // Brute-force fixtures built from the card's §4.5 records: 6 USER_AUTH failures and 6 sshd
  // "Failed password" lines from 198.51.100.77 within 3 minutes (the card shows the first two).
  const all = flatSamples(source.schema.card);
  const ua = all.find(r => r.type === "USER_AUTH")!;
  const fl = all.find(r => r.program === "sshd" && String(r.message).startsWith("Failed"))!;
  const t0 = 1_790_810_047_000;
  const burst: NativeLog[] = Array.from({ length: 6 }, (_, i) => [
    { sourceId: "linux_auditd" as const, kind: "USER_AUTH", format: "kv" as const, timeMs: t0 + i * 30_000, record: { ...ua, serial: String(880001 + i * 7) } },
    { sourceId: "linux_auditd" as const, kind: "sshd", format: "kv" as const, timeMs: t0 + i * 30_000 + 1, record: { ...fl, pid: String(38120 + i * 4), message: `Failed password for svc_deploy from 198.51.100.77 port ${54122 + i * 18} ssh2` } },
  ]).flat();
  // Root-shell fixture from the card's §4.4 USER_CMD record with the command switched to `sudo -i`
  // (auditd logs the resulting shell, /bin/bash).
  const uc4 = all.find(r => r.type === "USER_CMD")!;
  burst.push({ sourceId: "linux_auditd", kind: "USER_CMD", format: "kv", timeMs: t0 + 600_000, record: { ...uc4, cmd: "2F62696E2F62617368", cmd_decoded: "/bin/bash" } });
  // Card samples are timed so that records of one sample group sit inside the same window.
  const cardLogs = samples.logs.map((l, i) => ({ ...l, timeMs: t0 + i * 1000 }));
  const story = converted.filter(c => c.c.origin === "story" && c.log).map(c => c.log!);
  const pool = [...cardLogs, ...story, ...burst];
  const noise = converted.filter(c => isNoise(c.c) && c.log).map(c => c.log!);

  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("linux_auditd.")).toBe(true);
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[linux_auditd] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
