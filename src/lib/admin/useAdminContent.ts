"use client";
/**
 * Admin console data that carries answer keys (or verdict-revealing metadata)
 * and therefore must NOT be bundled into client JavaScript. Loaded on demand
 * from admin-only routes instead; one shared request per page load.
 */
import { useEffect, useState } from "react";
import type { Quiz } from "@/lib/quizzes/data";
import type { IOC, TelemetryEvent } from "@/lib/sim/types";

export interface AdminScenarioInfo { slug: string; attack_kind: string; threat_actor: string; logCount: number }

let quizzesP: Promise<Quiz[]> | null = null;
let scenariosP: Promise<Record<string, AdminScenarioInfo>> | null = null;

function loadQuizzes(): Promise<Quiz[]> {
  quizzesP ??= fetch("/api/admin/quizzes")
    // E-23: a failed response used to resolve to [] and stay cached for the
    // whole visit — throw so the cache resets and the next mount retries.
    .then(r => { if (!r.ok) throw new Error(`status ${r.status}`); return r.json(); })
    .then(d => (Array.isArray(d.quizzes) ? d.quizzes : []))
    .catch(() => { quizzesP = null; return []; });
  return quizzesP;
}

function loadScenarioInfo(): Promise<Record<string, AdminScenarioInfo>> {
  scenariosP ??= fetch("/api/admin/scenarios")
    .then(r => { if (!r.ok) throw new Error(`status ${r.status}`); return r.json(); })
    .then(d => Object.fromEntries((Array.isArray(d.scenarios) ? d.scenarios : []).map((s: AdminScenarioInfo) => [s.slug, s])))
    .catch(() => { scenariosP = null; return {}; });
  return scenariosP;
}

/** Built-in quizzes (with answers) — empty until loaded. */
export function useAdminBuiltinQuizzes(): Quiz[] {
  const [q, setQ] = useState<Quiz[]>([]);
  useEffect(() => { let alive = true; loadQuizzes().then(v => { if (alive) setQ(v); }); return () => { alive = false; }; }, []);
  return q;
}

/** Per-scenario admin metadata keyed by slug — empty until loaded. */
export function useAdminScenarioInfo(): Record<string, AdminScenarioInfo> {
  const [s, setS] = useState<Record<string, AdminScenarioInfo>>({});
  useEffect(() => { let alive = true; loadScenarioInfo().then(v => { if (alive) setS(v); }); return () => { alive = false; }; }, []);
  return s;
}

export interface AdminScenarioBundle { events: TelemetryEvent[]; iocs: IOC[]; questionCount: number }

/** One built-in scenario's events + IOCs for the drawer — null until loaded (or when not built-in). */
export function useAdminScenarioBundle(slug: string | null): AdminScenarioBundle | null {
  const [b, setB] = useState<AdminScenarioBundle | null>(null);
  useEffect(() => {
    if (!slug) { setB(null); return; }
    let alive = true;
    fetch(`/api/admin/scenarios?slug=${encodeURIComponent(slug)}`)
      .then(r => (r.ok ? r.json() : null))
      .then(d => { if (alive) setB(d && Array.isArray(d.events) ? d : null); })
      .catch(() => { if (alive) setB(null); });
    return () => { alive = false; };
  }, [slug]);
  return b;
}
