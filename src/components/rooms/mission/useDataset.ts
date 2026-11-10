"use client";
import { useEffect, useState } from "react";
import type { MissionDataset } from "@/lib/missions/types";

/** One download per dataset per page: every query mission of the room shares it. */
const cache = new Map<string, Promise<MissionDataset>>();

function load(id: string): Promise<MissionDataset> {
  let p = cache.get(id);
  if (!p) {
    p = fetch(`/api/missions/datasets/${encodeURIComponent(id)}`).then(async r => {
      if (!r.ok) throw new Error(`The case data could not be loaded (${r.status}).`);
      return r.json() as Promise<MissionDataset>;
    });
    p.catch(() => cache.delete(id));
    cache.set(id, p);
  }
  return p;
}

export function useMissionDataset(id: string | undefined): { data: MissionDataset | null; error: string | null; retry: () => void } {
  const [data, setData] = useState<MissionDataset | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!id) return;
    let live = true;
    setError(null);
    load(id).then(d => { if (live) setData(d); }, e => { if (live) setError(e instanceof Error ? e.message : String(e)); });
    return () => { live = false; };
  }, [id, n]);
  return { data, error, retry: () => setN(x => x + 1) };
}
