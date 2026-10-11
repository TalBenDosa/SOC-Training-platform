"use client";
/**
 * useAssignedItems() — the CURRENT learner's assigned items as an itemKey →
 * AssignedInfo map, for the "Assigned" chips on the content lists.
 *
 * One request per page at most: every chip / card on a page shares a single
 * module-level cache (per user, 60 s TTL) and a single in-flight promise, so a
 * rooms grid of 60 cards triggers exactly one GET
 * /api/org/assignments?view=assigned-keys. Guests (no Supabase session) never
 * fetch; users without an org or without assignments get an empty map, so the
 * chips render nothing.
 */
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth/AuthContext";
import type { AssignedMap } from "./assigned";

const TTL_MS = 60_000;
const EMPTY: AssignedMap = Object.freeze({}) as AssignedMap;

let cache: { userId: string; at: number; data: AssignedMap } | null = null;
let inflight: { userId: string; promise: Promise<AssignedMap> } | null = null;

function fresh(userId: string): AssignedMap | null {
  return cache && cache.userId === userId && Date.now() - cache.at < TTL_MS ? cache.data : null;
}

function load(userId: string): Promise<AssignedMap> {
  const hit = fresh(userId);
  if (hit) return Promise.resolve(hit);
  if (inflight && inflight.userId === userId) return inflight.promise;
  const promise = fetch("/api/org/assignments?view=assigned-keys", { cache: "no-store" })
    .then(r => (r.ok ? r.json() : { items: {} }))
    .then(d => {
      const data: AssignedMap = d && typeof d.items === "object" && d.items && !Array.isArray(d.items) ? d.items : EMPTY;
      cache = { userId, at: Date.now(), data };
      return data;
    })
    .catch(() => EMPTY)
    .finally(() => { if (inflight?.promise === promise) inflight = null; });
  inflight = { userId, promise };
  return promise;
}

export function useAssignedItems(): AssignedMap {
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const [items, setItems] = useState<AssignedMap>(() => (userId ? fresh(userId) ?? EMPTY : EMPTY));

  useEffect(() => {
    if (!userId) { setItems(EMPTY); return; }
    let alive = true;
    load(userId).then(d => { if (alive) setItems(d); });
    return () => { alive = false; };
  }, [userId]);

  return items;
}
