"use client";
/**
 * SavedSearches — named presets for the Live Feed's search + dropdown filters.
 *
 * The student saves the current free-text query together with the active
 * dropdown filters under a name, then re-applies it later with one click. Purely
 * a convenience layer over the existing filter state — it holds no answers and
 * nothing sensitive, so it persists in localStorage (per browser) under
 * "soc:saved-searches". Every read/write is wrapped in try/catch and the
 * component renders fine when storage is empty or blocked.
 */
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Bookmark, BookmarkPlus, X } from "lucide-react";

/** The full filter state a preset captures. Mirrors the dashboard's filter row. */
export interface FilterSnapshot {
  search: string;
  severityFilter: "all" | "low" | "medium" | "high";
  sourceFilter: string;
  userFilter: string;
  hostFilter: string;
  ipFilter: string;
  mitreFilter: string;
}

interface SavedSearch {
  name: string;
  snapshot: FilterSnapshot;
}

const STORAGE_KEY = "soc:saved-searches";
const MAX_SAVED = 24;

function loadSaved(): SavedSearch[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Defensive: keep only well-formed rows so a hand-edited/corrupt entry can't crash render.
    return parsed
      .filter((r): r is SavedSearch =>
        r && typeof r.name === "string" && r.snapshot && typeof r.snapshot === "object")
      .slice(0, MAX_SAVED);
  } catch {
    return [];
  }
}

function persist(list: SavedSearch[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list.slice(0, MAX_SAVED)));
  } catch {
    /* storage blocked / full — presets simply won't persist this session */
  }
}

/** True when a snapshot carries any active filter worth saving. */
function isSnapshotActive(s: FilterSnapshot): boolean {
  return (
    s.search.trim() !== "" ||
    s.severityFilter !== "all" ||
    s.sourceFilter !== "all" ||
    s.userFilter !== "all" ||
    s.hostFilter !== "all" ||
    s.ipFilter !== "all" ||
    s.mitreFilter !== "all"
  );
}

/** Compact human summary of the non-default filters in a snapshot (for chip tooltips). */
function describeSnapshot(s: FilterSnapshot): string {
  const bits: string[] = [];
  if (s.search.trim()) bits.push(`"${s.search.trim()}"`);
  if (s.severityFilter !== "all") bits.push(`level:${s.severityFilter}`);
  if (s.sourceFilter !== "all") bits.push(`source:${s.sourceFilter}`);
  if (s.userFilter !== "all") bits.push(`user:${s.userFilter}`);
  if (s.hostFilter !== "all") bits.push(`host:${s.hostFilter}`);
  if (s.ipFilter !== "all") bits.push(`ip:${s.ipFilter}`);
  if (s.mitreFilter !== "all") bits.push(`mitre:${s.mitreFilter}`);
  return bits.join(" · ") || "no filters";
}

interface Props {
  current: FilterSnapshot;
  onApply: (snapshot: FilterSnapshot) => void;
}

export function SavedSearches({ current, onApply }: Props) {
  const [saved, setSaved] = useState<SavedSearch[]>([]);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");

  // Load once on mount (localStorage is client-only).
  useEffect(() => { setSaved(loadSaved()); }, []);

  const canSave = isSnapshotActive(current);

  const commitSave = () => {
    const trimmed = name.trim();
    if (!trimmed || !canSave) { setNaming(false); setName(""); return; }
    // Overwrite a same-named preset rather than duplicating it.
    const next = [
      ...saved.filter((s) => s.name.toLowerCase() !== trimmed.toLowerCase()),
      { name: trimmed, snapshot: current },
    ].slice(-MAX_SAVED);
    setSaved(next);
    persist(next);
    setNaming(false);
    setName("");
  };

  const remove = (target: string) => {
    const next = saved.filter((s) => s.name !== target);
    setSaved(next);
    persist(next);
  };

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border/60 bg-bg/40 px-5 py-2">
      <Bookmark className="h-3.5 w-3.5 shrink-0 text-slate-400" />
      <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Saved:</span>

      {saved.length === 0 && !naming && (
        <span className="text-[10px] text-slate-500">No saved searches yet — set filters, then save them.</span>
      )}

      {saved.map((s) => (
        <span
          key={s.name}
          title={describeSnapshot(s.snapshot)}
          className="group flex items-center gap-1 rounded-full border border-cyber-500/30 bg-cyber-500/10 py-0.5 pl-2.5 pr-1 text-[10px] font-semibold text-cyber-300 transition hover:border-cyber-500/60"
        >
          <button onClick={() => onApply(s.snapshot)} className="max-w-[10rem] truncate">
            {s.name}
          </button>
          <button
            onClick={() => remove(s.name)}
            aria-label={`Delete saved search ${s.name}`}
            className="flex h-3.5 w-3.5 items-center justify-center rounded-full text-slate-400 transition hover:bg-severity-high/20 hover:text-severity-high"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}

      {naming ? (
        <span className="flex items-center gap-1">
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") commitSave();
              if (e.key === "Escape") { setNaming(false); setName(""); }
            }}
            placeholder="Name this search…"
            maxLength={40}
            className="h-6 w-40 rounded border border-cyber-500/50 bg-bg px-2 text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none"
          />
          <button
            onClick={commitSave}
            className="rounded border border-cyber-500/50 bg-cyber-500/15 px-2 py-0.5 text-[10px] font-semibold text-cyber-300 hover:bg-cyber-500/25"
          >
            Save
          </button>
          <button
            onClick={() => { setNaming(false); setName(""); }}
            className="rounded border border-border px-1.5 py-0.5 text-[10px] text-slate-400 hover:text-slate-300"
          >
            Cancel
          </button>
        </span>
      ) : (
        <button
          onClick={() => setNaming(true)}
          disabled={!canSave}
          title={canSave ? "Save current search + filters as a preset" : "Set a search or filter first"}
          className={cn(
            "ml-auto flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-semibold transition",
            canSave
              ? "border-cyber-500/40 text-cyber-300 hover:bg-cyber-500/10"
              : "cursor-not-allowed border-border/50 text-slate-600"
          )}
        >
          <BookmarkPlus className="h-3 w-3" /> Save current
        </button>
      )}
    </div>
  );
}
