import { describe, it, expect } from "vitest";
import { source, kindOf } from "./vmware_vsphere";
import { corpus, cardSamples } from "../testing/corpus";
import { standardChecks } from "../testing/standardChecks";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import { nativeView } from "../index";

/*
 * Card samples: every ```json block of virt-vmware.md is one vCenter syslog event, one QueryEvents API object or one
 * ESXi syslog record; none skipped.
 * Documented nulls: none in the corpus (every vSphere row has a program or a vCenter event class).
 * ESXi has no file event: the corpus' file_create rows (a scp receive, a ransom note copy) render as the shell
 * command lines that did it.
 */
type Rec = Record<string, unknown>;
const vs = corpus().filter(c => (c.ev.source as string) === "virtualization");
const render = (c: (typeof vs)[number]) => source.fromTelemetry(c.ev, makeCtx(c.companyId));

describe("vmware_vsphere: card samples", () => {
  it("every sample is a known kind and validates with zero violations", () => {
    const samples = cardSamples(source.schema.card) as Rec[];
    expect(samples.length).toBeGreaterThanOrEqual(20);
    for (const r of samples) {
      const k = kindOf(r);
      expect(k, JSON.stringify(r).slice(0, 80)).not.toBeNull();
      expect(validateNative({ sourceId: "vmware_vsphere", kind: k!, format: "json", record: r, timeMs: 0 }, source.schema)).toEqual([]);
    }
  });
});

describe("vmware_vsphere: standard checks", () => {
  // The evidence each stream really carries: a vpxd line names the user as vCenter spells it and the client
  // address only for session events (card 2.1: typed fields live inside desc); an ESXi line its user, address, command.
  const evidence = (c: (typeof vs)[number]) => {
    const r = (c.ev.raw ?? {}) as Rec;
    const s = (k: string) => (typeof r[k] === "string" && (r[k] as string).length > 2 ? [r[k] as string] : []);
    if (r["syslog.program"] === "vpxd") return [...s("vsphere.event.userName"), ...(/Session/.test(String(r["vsphere.event.eventTypeId"])) && c.ev.src_ip ? [c.ev.src_ip] : [])];
    if (r["syslog.program"] === "sshd") return c.ev.src_ip ? [c.ev.src_ip] : [];
    return [];
  };
  const rep = standardChecks(source, kindOf, { cards: [source.schema.card], evidence });
  it("records validate, evidence survives, output is deterministic", () => {
    console.log(`[vmware_vsphere] converted ${rep.nativeConverted}/${rep.nativeTotal} native`);
    expect(rep.violations.slice(0, 10)).toEqual([]);
    expect(rep.evidenceMissing.slice(0, 10)).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
    expect(rep.nativeConverted).toBe(rep.nativeTotal);
  });
  it("use cases fire on stories and stay quiet on noise", () => {
    console.log(`[vmware_vsphere] use cases ${JSON.stringify(rep.useCaseHits)}`);
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const [id, h] of Object.entries(rep.useCaseHits)) expect(h.attack, id).toBeGreaterThan(0);
  });
});

describe("vmware_vsphere: what it renders", () => {
  it("vCenter rows are vpxd syslog lines, ESXi rows their program's line, built from the record", () => {
    expect(vs.length).toBeGreaterThan(25);
    for (const c of vs) {
      const l = render(c)!;
      expect(l, c.ev.id).not.toBeNull();
      const r = l.record;
      if (l.kind === "vcenter.syslog.event") {
        expect(l.rawLine).toContain(` vpxd ${r.pid} - -  Event [${r.eventId}] [1-1] [${r.createdTime}] [${r.eventType}] [${r.severity}] [${r.user}] [${r.target}] [${r.chainId}] [${r.desc}]`);
        expect(String(r.eventType)).toMatch(/^vim\.event\./);
      } else {
        expect(l.rawLine).toBe(`<${r.pri}>${r.timestamp} ${r.hostname} ${r.program}[${r.pid}]: ${r.message}`);
      }
    }
  });
  it("the file rows of the story are shell command lines, never a file event ESXi does not write", () => {
    for (const c of vs.filter(x => x.ev.event_type === "file_create")) expect(render(c)!.kind, c.ev.id).toBe("esxi.syslog.shell");
  });
  it("renders under every company's stack (the hypervisor is the company's own product)", () => {
    const c = vs[0];
    for (const co of ["nexacorp", "medcore", "quantumbank"]) expect(nativeView(c.ev, co)?.log.sourceId).toBe("vmware_vsphere");
  });
});
