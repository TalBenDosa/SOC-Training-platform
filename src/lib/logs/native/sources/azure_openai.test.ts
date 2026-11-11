import { describe, it, expect } from "vitest";
import { source, kindOf, isAzureOpenAi } from "./azure_openai";
import { corpus, cardSamples } from "../testing/corpus";
import { standardChecks } from "../testing/standardChecks";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import { nativeView } from "../index";

/*
 * Card samples: the RequestResponse block of cloud-azure-ai-storage.md (the card's only json block).
 * Documented nulls: none (every Azure OpenAI row is a RequestResponse call). The end user and the prompt are
 * not in this record, so only the caller address (masked) and the deployment are evidence here.
 */
type Rec = Record<string, unknown>;
const rows = corpus().filter(c => isAzureOpenAi(c.ev));

describe("azure_openai: card sample", () => {
  it("validates with zero violations", () => {
    const samples = (cardSamples(source.schema.card) as Rec[]).filter(r => kindOf(r));
    expect(samples.length).toBeGreaterThanOrEqual(1);
    for (const r of samples) expect(validateNative({ sourceId: "azure_openai", kind: "RequestResponse", format: "json", record: r, timeMs: 0 }, source.schema)).toEqual([]);
  });
});

describe("azure_openai: standard checks", () => {
  const evidence = (c: (typeof rows)[number]) => {
    const r = (c.ev.raw ?? {}) as Rec;
    return [r["azure.open_ai.properties.model_deployment_name"], r["azure.open_ai.caller_ip_address"]].filter((x): x is string => typeof x === "string" && x.length > 2);
  };
  const rep = standardChecks(source, kindOf, { cards: [source.schema.card], evidence });
  it("records validate, evidence survives, output is deterministic", () => {
    expect(rep.violations.slice(0, 10)).toEqual([]);
    expect(rep.evidenceMissing.slice(0, 10)).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
    expect(rep.nativeConverted).toBe(rep.nativeTotal);
  });
  it("use cases fire on the stories and stay quiet on noise", () => {
    console.log(`[azure_openai] use cases ${JSON.stringify(rep.useCaseHits)}`);
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    const fired = Object.values(rep.useCaseHits).filter(h => h.attack > 0).length;
    expect(fired).toBeGreaterThanOrEqual(2);
    for (const [id, h] of Object.entries(rep.useCaseHits)) if (h.severity === "high") expect(h.noise, id).toBe(0);
  });
});

describe("azure_openai: what it renders", () => {
  it("properties is a JSON string with .NET ticks, the caller is masked, the resource is the company's", () => {
    expect(rows.length).toBeGreaterThan(15);
    for (const c of rows) {
      const ctx = makeCtx(c.companyId);
      const r = source.fromTelemetry(c.ev, ctx)!.record;
      const p = JSON.parse(String(r.properties)) as Rec;
      expect(String(p.requestTime)).toMatch(/^6\d{17}$/);
      expect(Number(p.responseLength)).toBeGreaterThan(0);
      expect(String(r.callerIpAddress)).toMatch(/\.\*\*\*$|^$/);
      expect(String(r.resourceId)).toContain(ctx.tenant.azureSubscriptionId.toUpperCase());
    }
  });
  it("the feed shows it as Azure OpenAI, never as an Activity Log record", () => {
    expect(nativeView(rows[0].ev, rows[0].companyId)?.log.sourceId).toBe("azure_openai");
  });
});
