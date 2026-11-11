"use client";
/**
 * The room's investigation console, played on this device: the console spec
 * (incidents, alerts, entities, detections, hunts) from /api/missions/consoles/<id>,
 * the mission dataset's tables, and what the learner did to each incident, kept in
 * localStorage for the whole room (an incident taken in one mission is still yours
 * in the next). Grading never reads storage: a console step sends a snapshot of
 * the incidents with the check.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { hydrate } from "@/lib/missions/kqlCompare";
import type { MissionConsole } from "@/lib/missions/consoles/types";
import type { ConsoleSnapshot, MissionDataset } from "@/lib/missions/types";
import type { IncidentState, SentinelActions, SentinelBookmark, SentinelWorkspace } from "@/lib/sentinel/types";

const ME = { id: "me", name: "You", role: "t1" } as const;

const specs = new Map<string, Promise<MissionConsole>>();
function loadSpec(id: string): Promise<MissionConsole> {
  let p = specs.get(id);
  if (!p) {
    p = fetch(`/api/missions/consoles/${encodeURIComponent(id)}`).then(async r => {
      if (!r.ok) throw new Error(`The console could not be loaded (${r.status}).`);
      return r.json() as Promise<MissionConsole>;
    });
    p.catch(() => specs.delete(id));
    specs.set(id, p);
  }
  return p;
}

interface Saved { states: Record<string, IncidentState>; loose: SentinelBookmark[] }
const key = (roomId: string, id: string) => `soc-mission-console:${roomId}:${id}`;
function read(roomId: string, id: string): Saved {
  try {
    const raw = window.localStorage.getItem(key(roomId, id));
    const v = raw ? JSON.parse(raw) as Partial<Saved> : {};
    return { states: v.states && typeof v.states === "object" ? v.states : {}, loose: Array.isArray(v.loose) ? v.loose : [] };
  } catch {
    return { states: {}, loose: [] };
  }
}
function write(roomId: string, id: string, v: Saved) {
  try { window.localStorage.setItem(key(roomId, id), JSON.stringify(v)); } catch { /* private mode: this page only */ }
}

const fresh = (severity: IncidentState["severity"]): IncidentState => ({ status: "New", owner: null, severity, comments: [], bookmarks: [], tasks: [], activity: [] });

let seq = 0;
const nid = () => `${Date.now().toString(36)}-${(seq++).toString(36)}`;

export interface MissionConsoleHandle {
  workspace: SentinelWorkspace | null;
  states: Map<string, IncidentState>;
  actions: SentinelActions;
  loose: SentinelBookmark[];
  error: string | null;
  retry: () => void;
  /** What the check sends: every incident the learner changed, plus the ones a step reads. */
  snapshots: () => Record<string, ConsoleSnapshot>;
  /** Puts the console back as the room found it (the learner's own work only). */
  reset: () => void;
}

export function useMissionConsole(roomId: string, consoleId: string | undefined, data: MissionDataset | null): MissionConsoleHandle {
  const [spec, setSpec] = useState<MissionConsole | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [n, setN] = useState(0);
  const [saved, setSaved] = useState<Saved>({ states: {}, loose: [] });

  useEffect(() => {
    if (!consoleId) return;
    let live = true;
    setError(null);
    loadSpec(consoleId).then(s => { if (live) setSpec(s); }, e => { if (live) setError(e instanceof Error ? e.message : String(e)); });
    return () => { live = false; };
  }, [consoleId, n]);
  useEffect(() => { if (consoleId) setSaved(read(roomId, consoleId)); }, [roomId, consoleId]);

  const workspace = useMemo<SentinelWorkspace | null>(() => {
    if (!spec || !data) return null;
    return {
      name: spec.name,
      tables: { ...hydrate(data), ...hydrate({ now: data.now, tables: spec.tables }) },
      alerts: spec.alerts, incidents: spec.incidents, entities: spec.entities, rules: spec.rules, hunting: spec.hunting,
      now: data.now,
    };
  }, [spec, data]);

  const states = useMemo(() => {
    const m = new Map<string, IncidentState>();
    for (const inc of spec?.incidents ?? []) m.set(inc.id, saved.states[inc.id] ?? spec?.states[inc.id] ?? fresh(inc.severity));
    return m;
  }, [spec, saved]);

  const now = data?.now ?? new Date(0).toISOString();
  const change = useCallback((incidentId: string, fn: (s: IncidentState) => IncidentState) => {
    if (!consoleId || !spec) return;
    setSaved(prev => {
      const inc = spec.incidents.find(i => i.id === incidentId);
      if (!inc) return prev;
      const cur = prev.states[incidentId] ?? spec.states[incidentId] ?? fresh(inc.severity);
      const next = { ...prev, states: { ...prev.states, [incidentId]: fn(cur) } };
      write(roomId, consoleId, next);
      return next;
    });
  }, [roomId, consoleId, spec]);

  const log = (s: IncidentState, text: string): IncidentState["activity"] => [...s.activity, { at: now, actor: ME.name, text }];

  const actions = useMemo<SentinelActions>(() => ({
    me: { ...ME }, people: spec?.people ?? [], canContain: false, isolatedHosts: new Set<string>(),
    setIsolated: async () => "Isolating a device is not part of this mission: the case here is in the cloud, not on a laptop.",
    updateIncident: async (id, patch) => {
      change(id, s => {
        const words: string[] = [];
        if (patch.owner !== undefined && patch.owner !== s.owner) words.push(patch.owner ? `Assigned to ${patch.owner === ME.name ? "you" : patch.owner}` : "Unassigned");
        if (patch.status && patch.status !== s.status) words.push(patch.status === "Closed" ? `Closed as ${patch.classification ?? "unclassified"}` : `Status ${patch.status}`);
        if (patch.severity && patch.severity !== s.severity) words.push(`Severity ${patch.severity}`);
        const reopened = patch.status && patch.status !== "Closed";
        return {
          ...s, ...patch,
          ...(reopened ? { classification: undefined, closingComment: undefined } : {}),
          activity: words.length ? log(s, words.join(", ")) : s.activity,
        };
      });
      return null;
    },
    addComment: async (id, text) => {
      change(id, s => ({ ...s, comments: [...s.comments, { id: nid(), author: ME.name, text, at: now }], activity: log(s, "Comment added") }));
      return null;
    },
    addBookmark: async b => {
      const full: SentinelBookmark = { ...b, id: nid(), author: ME.name, at: now };
      if (b.incidentId) change(b.incidentId, s => ({ ...s, bookmarks: [...s.bookmarks, full], activity: log(s, `Bookmark added: ${b.name}`) }));
      else if (consoleId) setSaved(prev => { const next = { ...prev, loose: [full, ...prev.loose].slice(0, 30) }; write(roomId, consoleId, next); return next; });
      return null;
    },
    setTask: async (id, title, done) => {
      change(id, s => {
        const has = s.tasks.some(t => t.title === title);
        return { ...s, tasks: has ? s.tasks.map(t => (t.title === title ? { ...t, done, by: ME.name } : t)) : [...s.tasks, { id: nid(), title, done, by: ME.name }] };
      });
      return null;
    },
    queryRan: () => {},
  // eslint-disable-next-line react-hooks/exhaustive-deps -- log reads `now` only
  }), [spec, change, now, roomId, consoleId]);

  const snapshots = useCallback(() => {
    const out: Record<string, ConsoleSnapshot> = {};
    for (const [id, s] of states) {
      out[id] = {
        status: s.status, owner: s.owner, ownerIsMe: s.owner === ME.name, severity: s.severity,
        classification: s.classification, closingComment: s.closingComment,
        comments: s.comments.filter(c => c.author === ME.name).map(c => c.text),
        bookmarks: s.bookmarks.map(b => ({ name: b.name, notes: b.notes, columns: b.columns, rows: b.rows })),
      };
    }
    return out;
  }, [states]);

  const reset = useCallback(() => {
    if (!consoleId) return;
    const next = { states: {}, loose: [] };
    write(roomId, consoleId, next);
    setSaved(next);
  }, [roomId, consoleId]);

  return { workspace, states, actions, loose: saved.loose, error, retry: () => setN(x => x + 1), snapshots, reset };
}
