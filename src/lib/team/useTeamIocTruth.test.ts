// QA M4: the room asks for threat intel only for the IOCs of the logs in hand, each
// IOC once, in batches — and re-asks a refused one when the next log comes into hand.
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { iocDigest } from "@/lib/edr/iocIntel";
import { useTeamIocTruth, iocsOf, IOC_TRUTH_DEBOUNCE_MS, IOC_TRUTH_BACKOFF_MS } from "./useTeamIocTruth";
import type { Ev } from "./types";
import type { IocTruth } from "@/lib/edr/iocIntel";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const log = (id: string, ip: string): Ev => ({ seq: 1, type: "feed.event", actor_id: null, role: null, payload: { id, src_ip: "10.0.0.5", dst_ip: ip } });
let seen: (IocTruth | null)[] = [];
function Probe({ inHand }: { inHand: Ev[] }) { seen.push(useTeamIocTruth("s1", inHand)); return null; }

describe("useTeamIocTruth", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  const bodies: { iocs: { type: string; value: string }[] }[] = [];
  let respond: (b: { iocs: { type: string; value: string }[] }) => { status: number; json?: unknown } = () => ({ status: 200, json: { version: 1, entries: {}, refused: [] } });
  beforeEach(() => {
    vi.useFakeTimers(); seen = []; bodies.length = 0;
    vi.stubGlobal("fetch", vi.fn(async (_u: string, init: { body: string }) => {
      const b = JSON.parse(init.body); bodies.push(b);
      const r = respond(b);
      return { ok: r.status < 300, status: r.status, json: async () => r.json };
    }));
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
  });
  afterEach(() => { act(() => root?.unmount()); el?.remove(); vi.unstubAllGlobals(); vi.useRealTimers(); });
  const render = async (inHand: Ev[]) => { await act(async () => { root!.render(React.createElement(Probe, { inHand })); }); };
  const tick = async (ms: number) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };

  it("asks once per IOC of the logs in hand (internal IPs too are just IOCs), merges the verdicts", async () => {
    const d = iocDigest("ip", "203.0.113.9");
    respond = b => ({ status: 200, json: { version: 1, entries: b.iocs.some(i => i.value === "203.0.113.9") ? { [d]: { v: "malicious" } } : {}, refused: [] } });
    const a = [log("e1", "203.0.113.9")];
    await render(a);
    expect(bodies).toHaveLength(0);                      // debounced
    await tick(IOC_TRUTH_DEBOUNCE_MS + 10);
    expect(bodies).toHaveLength(1);
    expect(bodies[0].iocs.map(i => i.value).sort()).toEqual(["10.0.0.5", "203.0.113.9"]);
    expect(seen.at(-1)?.entries[d]?.v).toBe("malicious");
    // the same log again + a new one: only the new IOC goes out
    await render([...a, log("e2", "198.51.100.4")]);
    await tick(IOC_TRUTH_DEBOUNCE_MS + 10);
    expect(bodies).toHaveLength(2);
    expect(bodies[1].iocs.map(i => i.value)).toEqual(["198.51.100.4"]);
    expect(seen.at(-1)?.entries[d]?.v).toBe("malicious");   // earlier verdicts kept
  });

  it("re-asks a refused IOC when the next log comes into hand; backs off on 429", async () => {
    const d = iocDigest("ip", "203.0.113.9");
    respond = () => ({ status: 200, json: { version: 1, entries: {}, refused: [d] } });
    await render([log("e1", "203.0.113.9")]);
    await tick(IOC_TRUTH_DEBOUNCE_MS + 10);
    respond = () => ({ status: 429 });
    await render([log("e1", "203.0.113.9"), log("e3", "192.0.2.77")]);
    await tick(IOC_TRUTH_DEBOUNCE_MS + 10);
    expect(bodies[1].iocs.map(i => i.value).sort()).toEqual(["192.0.2.77", "203.0.113.9"]);
    respond = () => ({ status: 200, json: { version: 1, entries: { [d]: { v: "malicious" } }, refused: [] } });
    await tick(IOC_TRUTH_BACKOFF_MS / 2);
    expect(bodies).toHaveLength(2);                       // still backing off
    await tick(IOC_TRUTH_BACKOFF_MS);
    expect(bodies).toHaveLength(3);
    expect(seen.at(-1)?.entries[d]?.v).toBe("malicious");
  });

  it("iocsOf de-duplicates across logs", () => {
    expect(iocsOf([log("a", "203.0.113.1"), log("b", "203.0.113.1")]).map(q => q.value).sort()).toEqual(["10.0.0.5", "203.0.113.1"]);
  });
});
