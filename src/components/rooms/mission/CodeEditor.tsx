"use client";
/**
 * A code box for the mission benches: a textarea over a coloured layer (KQL is
 * highlighted with the engine's own tokenizer). The browser keeps caret, undo
 * and IME; the layer only paints. Ctrl/Shift+Enter runs. Tab inserts two spaces;
 * Escape then Tab leaves the box (keyboard users are never trapped).
 */
import { forwardRef, useImperativeHandle, useMemo, useRef } from "react";
import { tokenizeKql } from "@/lib/kql";
import type { KqlTable } from "@/lib/kql/types";

export interface CodeEditorHandle { insert: (text: string) => void; focus: () => void }

const TOKEN_CLASS: Record<string, string> = {
  keyword: "text-sky-300", operator: "text-fuchsia-300", function: "text-amber-200", string: "text-emerald-300",
  number: "text-orange-300", comment: "text-slate-500 italic", table: "text-cyan-300 font-semibold",
};

export const CodeEditor = forwardRef<CodeEditorHandle, {
  value: string;
  onChange: (v: string) => void;
  onRun?: () => void;
  language: "kql" | "yara" | "sigma";
  label: string;
  rows?: number;
  tables?: Record<string, KqlTable>;
  errorLine?: number | null;
}>(function CodeEditor({ value, onChange, onRun, language, label, rows = 7, tables, errorLine }, ref) {
  const input = useRef<HTMLTextAreaElement>(null);
  const layer = useRef<HTMLPreElement>(null);
  const escaped = useRef(false);

  useImperativeHandle(ref, () => ({
    insert(text: string) {
      const t = input.current;
      if (!t) { onChange(value + text); return; }
      const at = t.selectionStart ?? value.length;
      const next = value.slice(0, at) + text + value.slice(t.selectionEnd ?? at);
      onChange(next);
      requestAnimationFrame(() => { t.focus(); t.selectionStart = t.selectionEnd = at + text.length; });
    },
    focus() { input.current?.focus(); },
  }), [value, onChange]);

  const segments = useMemo(() => language === "kql"
    ? tokenizeKql(value, tables ? { tables } : undefined).map(t => ({ text: t.text, cls: TOKEN_CLASS[t.class] }))
    : [{ text: value, cls: undefined as string | undefined }], [value, language, tables]);
  const lines = value.split("\n").length;
  const height = Math.max(rows, Math.min(lines + 1, 22)) * 20 + 16;

  return (
    <div className="relative rounded-lg border border-border bg-[#0b1220] font-mono text-[13px] leading-5" style={{ height }}>
      <div aria-hidden className="absolute inset-y-0 left-0 w-9 select-none overflow-hidden border-r border-border/60 py-2 text-right text-[11px] text-slate-600">
        {Array.from({ length: lines }, (_, i) => (
          <div key={i} className={i + 1 === errorLine ? "pr-1.5 text-severity-high" : "pr-1.5"}>{i + 1}</div>
        ))}
      </div>
      <pre ref={layer} aria-hidden className="pointer-events-none absolute inset-0 left-9 m-0 overflow-hidden whitespace-pre px-2 py-2 text-slate-200">
        {segments.map((s, i) => s.cls ? <span key={i} className={s.cls}>{s.text}</span> : <span key={i}>{s.text}</span>)}
        {"\n"}
      </pre>
      <textarea
        ref={input}
        aria-label={label}
        value={value}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        autoComplete="off"
        wrap="off"
        onChange={e => onChange(e.target.value)}
        onScroll={e => { if (layer.current) { layer.current.scrollTop = e.currentTarget.scrollTop; layer.current.scrollLeft = e.currentTarget.scrollLeft; } }}
        onKeyDown={e => {
          if ((e.ctrlKey || e.metaKey || e.shiftKey) && e.key === "Enter") { e.preventDefault(); onRun?.(); return; }
          if (e.key === "Escape") { escaped.current = true; return; }
          if (e.key === "Tab" && !e.shiftKey && !escaped.current) {
            e.preventDefault();
            const t = e.currentTarget, at = t.selectionStart;
            onChange(value.slice(0, at) + "  " + value.slice(t.selectionEnd));
            requestAnimationFrame(() => { t.selectionStart = t.selectionEnd = at + 2; });
            return;
          }
          escaped.current = false;
        }}
        className="absolute inset-0 left-9 resize-none overflow-auto whitespace-pre bg-transparent px-2 py-2 text-transparent caret-white outline-none focus-visible:ring-2 focus-visible:ring-cyber-500/40"
      />
    </div>
  );
});
