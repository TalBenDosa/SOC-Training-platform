"use client";
/**
 * The centre column of the learning-plan editors: the items ticked in the
 * module tree, in the order learners will see them. Reorder by drag or ↑/↓,
 * set a per-item priority (High / Normal / Low) and an optional note (≤300
 * chars, e.g. "focus on the Kerberos section"). Presentation only — the server
 * re-validates every id, priority and note on save.
 */
import { useState } from "react";
import { ArrowDown, ArrowUp, GripVertical, MessageSquare, X, CheckCircle2, CircleDot, Circle } from "lucide-react";
import {
  DEFAULT_PRIORITY, PLAN_LIMITS, PRIORITY_LABEL, itemKey,
  type CatalogNode, type ItemStatus, type PlanItem, type Priority,
} from "@/lib/plans/types";

/** Add (in tree order, appended) or remove the given leaf keys from `items`. */
export function applyToggle(items: PlanItem[], keys: string[], select: boolean, leaves: Map<string, CatalogNode>): PlanItem[] {
  if (!select) {
    const drop = new Set(keys);
    return items.filter(i => !drop.has(itemKey(i)));
  }
  const have = new Set(items.map(itemKey));
  const add: PlanItem[] = [];
  for (const k of keys) {
    const leaf = leaves.get(k);
    if (leaf?.item && !have.has(k)) { add.push({ kind: leaf.item.kind, id: leaf.item.id }); have.add(k); }
  }
  return [...items, ...add].slice(0, PLAN_LIMITS.items);
}

export const KIND_LABEL: Record<string, string> = { room: "room", scenario: "scenario", lesson: "lesson", quiz: "quiz" };

export function StatusIcon({ status }: { status?: ItemStatus }) {
  if (status === "done") return <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-neon-green" aria-label="Done" />;
  if (status === "in_progress") return <CircleDot className="h-3.5 w-3.5 shrink-0 text-neon-amber" aria-label="In progress" />;
  if (status === "untracked") return <Circle className="h-3.5 w-3.5 shrink-0 text-slate-700" aria-label="Not tracked" />;
  return <Circle className="h-3.5 w-3.5 shrink-0 text-slate-500" aria-label="Not started" />;
}

export function PlanItemsEditor({
  items, leaves, onChange, statuses, className = "",
}: {
  items: PlanItem[];
  leaves: Map<string, CatalogNode>;
  onChange: (items: PlanItem[]) => void;
  /** Optional per-item status (student page) keyed by itemKey. */
  statuses?: Record<string, ItemStatus>;
  className?: string;
}) {
  const [dragFrom, setDragFrom] = useState<number | null>(null);
  const [noteOpen, setNoteOpen] = useState<Set<string>>(() => new Set());

  function move(from: number, to: number) {
    if (to < 0 || to >= items.length || from === to) return;
    const next = [...items];
    const [x] = next.splice(from, 1);
    next.splice(to, 0, x);
    onChange(next);
  }
  function update(i: number, patch: Partial<PlanItem>) {
    onChange(items.map((it, j) => {
      if (j !== i) return it;
      const n: PlanItem = { ...it, ...patch };
      if (!n.priority || n.priority === DEFAULT_PRIORITY) delete n.priority;
      if (!n.note) delete n.note;
      return n;
    }));
  }

  if (items.length === 0) {
    return (
      <div className={`flex items-center justify-center rounded-lg border border-dashed border-border bg-bg px-4 py-10 text-center text-xs text-slate-500 ${className}`}>
        Tick modules in the tree to add them here.
      </div>
    );
  }

  return (
    <ol className={`space-y-1 overflow-y-auto rounded-lg border border-border bg-bg p-1.5 ${className}`}>
      {items.map((it, i) => {
        const key = itemKey(it);
        const leaf = leaves.get(key);
        const showNote = noteOpen.has(key) || Boolean(it.note);
        return (
          <li
            key={key}
            draggable
            onDragStart={() => setDragFrom(i)}
            onDragOver={e => e.preventDefault()}
            onDrop={() => { if (dragFrom !== null) move(dragFrom, i); setDragFrom(null); }}
            onDragEnd={() => setDragFrom(null)}
            className={`rounded-md border px-2 py-1.5 transition ${dragFrom === i ? "border-cyber-500/50 opacity-60" : "border-border/60 bg-bg-elevated"}`}
          >
            <div className="flex items-center gap-1.5">
              <GripVertical className="h-3.5 w-3.5 shrink-0 cursor-grab text-slate-600" aria-hidden />
              <span className="w-5 shrink-0 text-right font-mono text-[10px] text-slate-500">{i + 1}</span>
              {statuses && <StatusIcon status={statuses[key]} />}
              <span className="min-w-0 flex-1 truncate text-[12px] text-slate-100" title={leaf?.label ?? it.id}>{leaf?.label ?? it.id}</span>
              <span className="shrink-0 text-[9px] uppercase tracking-wider text-slate-500">{KIND_LABEL[it.kind]}</span>
              <select
                value={it.priority ?? DEFAULT_PRIORITY}
                onChange={e => update(i, { priority: Number(e.target.value) as Priority })}
                aria-label="Item priority"
                className={`shrink-0 rounded border border-border bg-bg px-1 py-0.5 text-[10px] focus:outline-none ${
                  (it.priority ?? DEFAULT_PRIORITY) === 1 ? "text-neon-amber" : (it.priority ?? DEFAULT_PRIORITY) === 3 ? "text-slate-500" : "text-slate-300"
                }`}
              >
                {([1, 2, 3] as Priority[]).map(p => <option key={p} value={p}>{PRIORITY_LABEL[p]}</option>)}
              </select>
              <button type="button" onClick={() => setNoteOpen(s => new Set(s).add(key))} title="Add a note" aria-label="Add a note"
                className={`rounded p-0.5 transition hover:bg-white/5 ${it.note ? "text-cyber-300" : "text-slate-500 hover:text-slate-200"}`}>
                <MessageSquare className="h-3.5 w-3.5" />
              </button>
              <button type="button" onClick={() => move(i, i - 1)} disabled={i === 0} aria-label="Move up"
                className="rounded p-0.5 text-slate-500 transition hover:bg-white/5 hover:text-slate-200 disabled:opacity-30"><ArrowUp className="h-3.5 w-3.5" /></button>
              <button type="button" onClick={() => move(i, i + 1)} disabled={i === items.length - 1} aria-label="Move down"
                className="rounded p-0.5 text-slate-500 transition hover:bg-white/5 hover:text-slate-200 disabled:opacity-30"><ArrowDown className="h-3.5 w-3.5" /></button>
              <button type="button" onClick={() => onChange(items.filter((_, j) => j !== i))} aria-label="Remove"
                className="rounded p-0.5 text-slate-500 transition hover:bg-severity-high/10 hover:text-severity-high"><X className="h-3.5 w-3.5" /></button>
            </div>
            {showNote && (
              <input
                value={it.note ?? ""}
                onChange={e => update(i, { note: e.target.value.slice(0, PLAN_LIMITS.note) })}
                onBlur={() => { if (!it.note) setNoteOpen(s => { const n = new Set(s); n.delete(key); return n; }); }}
                maxLength={PLAN_LIMITS.note}
                autoFocus={!it.note}
                placeholder="Note for the learner (optional)"
                className="mt-1 w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/50 focus:outline-none"
              />
            )}
          </li>
        );
      })}
    </ol>
  );
}
