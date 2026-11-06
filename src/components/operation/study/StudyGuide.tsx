"use client";
import React, { createContext, useContext, useEffect, useMemo, useRef } from "react";
import { BookOpen, ChevronLeft, ChevronRight, X } from "lucide-react";
import { ReadingBody } from "@/components/rooms/TaskPlayer";
import type { SanitizedRoomTask } from "@/lib/rooms/sanitize";
import { studyGroups } from "@/lib/rooms/experience/study";

/** Lets a mechanic say the reading is already the main content on screen. */
export const StudyContext = createContext<{ setInline: (inline: boolean) => void } | null>(null);
export function useStudyInline(inline: boolean) {
  const ctx = useContext(StudyContext);
  useEffect(() => {
    ctx?.setInline(inline);
    return () => ctx?.setInline(false);
  }, [ctx, inline]);
}

interface ReaderProps {
  roomId: string;
  tasks: SanitizedRoomTask[];
  stations: { label: string; taskIds: string[] }[];
  completed: Set<string>;
  readingId: string | null;
  onPick: (id: string) => void;
}

function Reader({ roomId, tasks, stations, completed, readingId, onPick }: ReaderProps) {
  const groups = useMemo(() => studyGroups(tasks, stations), [tasks, stations]);
  const flat = useMemo(() => groups.flatMap(g => g.entries), [groups]);
  const at = flat.findIndex(e => e.id === readingId);
  const task = tasks.find(t => t.id === readingId);
  const top = useRef<HTMLDivElement | null>(null);
  // Only the guide's own scroll box moves, never the task behind it.
  useEffect(() => { top.current?.closest("[data-study-scroll]")?.scrollTo({ top: 0 }); }, [readingId]);
  if (!task || task.type !== "reading") return <p className="text-sm text-slate-300">This room has no reading material.</p>;
  const prev = flat[at - 1];
  const next = flat[at + 1];
  return (
    <div className="space-y-4">
      <div ref={top}>
        <label htmlFor="study-reading" className="sr-only">Choose a reading</label>
        <select
          id="study-reading"
          value={task.id}
          onChange={e => onPick(e.target.value)}
          className="w-full rounded-lg border border-white/15 bg-bg-panel px-3 py-2 text-sm text-slate-100"
        >
          {groups.map(g => (
            <optgroup key={g.label} label={g.label}>
              {g.entries.map(e => <option key={e.id} value={e.id}>{completed.has(e.id) ? "✓ " : ""}{e.heading}</option>)}
            </optgroup>
          ))}
        </select>
      </div>
      <div className="space-y-4 [&_h2]:text-2xl">
        <ReadingBody task={task} roomId={roomId} />
      </div>
      <div className="flex items-center justify-between gap-2 border-t border-white/10 pt-3">
        <button disabled={!prev} onClick={() => prev && onPick(prev.id)} className="inline-flex items-center gap-1 text-xs font-semibold text-slate-300 hover:text-white disabled:opacity-30">
          <ChevronLeft className="h-4 w-4" /> Previous
        </button>
        <span className="text-xs text-slate-400">{at + 1} of {flat.length}</span>
        <button disabled={!next} onClick={() => next && onPick(next.id)} className="inline-flex items-center gap-1 text-xs font-semibold text-slate-300 hover:text-white disabled:opacity-30">
          Next <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

/** Beside the task on wide screens. Folding it never touches the task. */
export function StudyAside(p: ReaderProps & { onFold: () => void }) {
  const { onFold, ...reader } = p;
  return (
    <aside aria-label="Study guide" className="sticky top-0 hidden h-[calc(100dvh-7.5rem)] w-[26rem] shrink-0 flex-col overflow-hidden rounded-3xl border border-white/10 bg-[#080d18]/95 lg:flex xl:w-[30rem]">
      <div className="flex items-center gap-2 border-b border-white/10 px-4 py-2.5">
        <BookOpen className="h-4 w-4 text-slate-300" />
        <p className="text-sm font-semibold text-white">Study guide</p>
        <button onClick={onFold} className="ml-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-semibold text-slate-300 hover:bg-white/10 hover:text-white">
          Fold <ChevronRight className="h-4 w-4" />
        </button>
      </div>
      <div data-study-scroll className="min-h-0 flex-1 overflow-y-auto px-4 py-4"><Reader {...reader} /></div>
    </aside>
  );
}

/** Full screen, for the hub, the debrief and phones. */
export function StudyOverlay(p: ReaderProps & { onClose: () => void; closeLabel: string }) {
  const { onClose, closeLabel, ...reader } = p;
  const close = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    close.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div role="dialog" aria-modal="true" aria-label="Study guide" className="absolute inset-0 z-[45] flex flex-col bg-[#060a13]">
      <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
        <BookOpen className="h-5 w-5 text-slate-300" />
        <p className="font-semibold text-white">Study guide</p>
        <button ref={close} onClick={onClose} className="ml-auto inline-flex h-11 items-center gap-1.5 rounded-xl border border-white/15 px-3 text-sm font-semibold text-slate-100 hover:border-white/40">
          <X className="h-4 w-4" /> {closeLabel}
        </button>
      </div>
      <div data-study-scroll className="min-h-0 flex-1 overflow-y-auto px-4 py-5">
        <div className="mx-auto max-w-3xl"><Reader {...reader} /></div>
      </div>
    </div>
  );
}
