// SEC-17: only uploads that were never finalized AND are old enough go.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { purgeOrphanUploads, ORPHAN_AGE_MS } from "./purgeOrphanUploads";

const NOW = Date.parse("2026-10-01T12:00:00Z");
const old = new Date(NOW - ORPHAN_AGE_MS - 60_000).toISOString();
const fresh = new Date(NOW - 60_000).toISOString();

function admin(opts: { rowsError?: boolean } = {}) {
  const removed: string[] = [];
  const files: Record<string, { id: string; name: string; created_at: string }[]> = {
    "org1/pdf": [
      { id: "1", name: "kept.pdf", created_at: old },        // finalized (has a row)
      { id: "2", name: "abandoned.pdf", created_at: old },   // never finalized, old → delete
      { id: "3", name: "uploading.pdf", created_at: fresh }, // never finalized, still within the URL's life → keep
    ],
  };
  const client = {
    from: (t: string) => ({
      select: () => t === "organizations"
        ? Promise.resolve({ data: [{ id: "org1" }], error: null })
        : { eq: async () => (opts.rowsError ? { data: null, error: { message: "x" } } : { data: [{ storage_key: "org1/pdf/kept.pdf" }], error: null }) },
    }),
    storage: { from: () => ({
      list: async (prefix: string, o: { offset: number }) => ({ data: (files[prefix] ?? []).filter(f => !removed.includes(`${prefix}/${f.name}`)).slice(o.offset), error: null }),
      remove: async (keys: string[]) => { removed.push(...keys); return { error: null }; },
    }) },
  };
  return { client, removed };
}

describe("purgeOrphanUploads", () => {
  it("deletes only the old, unreferenced object", async () => {
    const { client, removed } = admin();
    const r = await purgeOrphanUploads(client as never, NOW);
    expect(removed).toEqual(["org1/pdf/abandoned.pdf"]);
    expect(r.deleted).toBe(1);
  });
  it("deletes nothing when it can't read what is referenced", async () => {
    const { client, removed } = admin({ rowsError: true });
    const r = await purgeOrphanUploads(client as never, NOW);
    expect(removed).toEqual([]);
    expect(r.errors).toBe(1);
  });
});
