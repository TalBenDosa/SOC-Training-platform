"use client";
// A textarea over a coloured layer: the browser keeps caret, selection, undo and IME, the layer
// only paints. Font and line height are fixed, so caret and error positions are plain arithmetic.
import { forwardRef, useCallback, useEffect, useId, useImperativeHandle, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { KqlCompletion } from "@/lib/kql/types";
import { completions, tokenize } from "./engine";

const LINE = 19; const PAD_Y = 6; const PAD_X = 8; const GUTTER = 44;

export interface EditorHandle {
  insert: (text: string) => void;
  cursor: () => number;
  selection: () => string;
  focus: () => void;
  setCursor: (at: number) => void;
}

export interface EditorProps {
  value: string;
  onChange: (v: string) => void;
  onRun: () => void;
  height: number;
  label: string;
  /** Position in the whole editor text. */
  error?: { line: number; column: number } | null;
}

interface Ac { items: KqlCompletion[]; index: number; prefix: string; x: number; y: number }

const KIND_GLYPH: Record<KqlCompletion["kind"], string> = { table: "T", column: "C", operator: "|", function: "f", keyword: "K" };

export const KqlEditor = forwardRef<EditorHandle, EditorProps>(function KqlEditor({ value, onChange, onRun, height, label, error }, ref) {
  const input = useRef<HTMLTextAreaElement>(null);
  const layer = useRef<HTMLPreElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const measure = useRef<HTMLSpanElement>(null);
  const pendingCaret = useRef<number | null>(null);
  const tabLeaves = useRef(false);
  const [ac, setAc] = useState<Ac | null>(null);
  const [activeLine, setActiveLine] = useState(0);
  const listId = useId();

  const lineCount = useMemo(() => value.split("\n").length, [value]);
  const segments = useMemo(() => tokenize(value), [value]);

  const syncScroll = useCallback(() => {
    const t = input.current;
    if (!t) return;
    if (layer.current) { layer.current.scrollTop = t.scrollTop; layer.current.scrollLeft = t.scrollLeft; }
    if (gutter.current) gutter.current.scrollTop = t.scrollTop;
  }, []);
  useLayoutEffect(() => {
    if (pendingCaret.current !== null && input.current) {
      input.current.selectionStart = input.current.selectionEnd = pendingCaret.current;
      pendingCaret.current = null;
    }
    syncScroll();
  }, [value, syncScroll]);

  const charWidth = () => (measure.current?.getBoundingClientRect().width ?? 0) / 20 || 7.2;

  const refreshAc = useCallback((text: string, at: number, force = false) => {
    const before = text.slice(0, at);
    const prefix = /[A-Za-z_][A-Za-z0-9_]*$/.exec(before)?.[0] ?? "";
    const afterPipe = /\|\s*$/.test(before);
    if (!force && !prefix && !afterPipe) { setAc(null); return; }
    const s = prefix.toLowerCase();
    let items = completions(text, at);
    if (s) {
      const starts = items.filter(i => i.label.toLowerCase().startsWith(s));
      items = starts.length ? starts : items.filter(i => i.label.toLowerCase().includes(s));
    }
    // A finished word offers nothing new: do not cover the line for it.
    if (!items.length || (items.length === 1 && items[0].label === prefix)) { setAc(null); return; }
    const lines = before.split("\n");
    const t = input.current;
    const col = lines[lines.length - 1].length - prefix.length;
    setAc({
      items: items.slice(0, 40), index: 0, prefix,
      x: GUTTER + PAD_X + col * charWidth() - (t?.scrollLeft ?? 0),
      y: PAD_Y + lines.length * LINE - (t?.scrollTop ?? 0),
    });
  }, []);

  const accept = useCallback((item: KqlCompletion) => {
    const t = input.current;
    if (!t) return;
    const at = t.selectionStart;
    const start = at - (ac?.prefix.length ?? 0);
    const next = value.slice(0, start) + item.insert + value.slice(at);
    pendingCaret.current = start + item.insert.length;
    onChange(next);
    setAc(null);
  }, [ac, onChange, value]);

  const insert = useCallback((text: string) => {
    const t = input.current;
    const a = t?.selectionStart ?? value.length; const b = t?.selectionEnd ?? value.length;
    pendingCaret.current = a + text.length;
    onChange(value.slice(0, a) + text + value.slice(b));
    t?.focus();
  }, [onChange, value]);

  useImperativeHandle(ref, () => ({
    insert,
    cursor: () => input.current?.selectionStart ?? 0,
    selection: () => { const t = input.current; return t ? t.value.slice(t.selectionStart, t.selectionEnd) : ""; },
    focus: () => input.current?.focus(),
    setCursor: at => { pendingCaret.current = at; if (input.current) input.current.selectionStart = input.current.selectionEnd = at; },
  }), [insert]);

  const noteCaret = () => {
    const t = input.current;
    if (t) setActiveLine(t.value.slice(0, t.selectionStart).split("\n").length - 1);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && e.shiftKey) { e.preventDefault(); setAc(null); onRun(); return; }
    if (ac) {
      if (e.key === "ArrowDown") { e.preventDefault(); setAc({ ...ac, index: (ac.index + 1) % ac.items.length }); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setAc({ ...ac, index: (ac.index - 1 + ac.items.length) % ac.items.length }); return; }
      if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); accept(ac.items[ac.index]); return; }
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setAc(null); tabLeaves.current = true; return; }
    }
    if (e.key === " " && e.ctrlKey) { e.preventDefault(); const t = e.currentTarget; refreshAc(t.value, t.selectionStart, true); return; }
    if (e.key === "Escape") { e.stopPropagation(); tabLeaves.current = true; return; }
    if (e.key === "Tab") {
      // Tab indents, except right after Escape: the way out for keyboard users.
      if (tabLeaves.current) { tabLeaves.current = false; return; }
      if (!e.shiftKey) { e.preventDefault(); insert("    "); }
      return;
    }
    tabLeaves.current = false;
  };

  const errLen = useMemo(() => {
    if (!error) return 0;
    const line = value.split("\n")[error.line - 1] ?? "";
    const word = /^[A-Za-z0-9_.]+/.exec(line.slice(error.column - 1))?.[0];
    return Math.max(word?.length ?? 1, 1);
  }, [error, value]);

  useEffect(() => setAc(null), [height]);

  return (
    <div className="st-editor" style={{ height }}>
      <div className="st-editor-wrap">
        <div ref={gutter} className="st-gutter" aria-hidden>
          {Array.from({ length: lineCount }, (_, i) => <div key={i} className={i === activeLine ? "active" : undefined}>{i + 1}</div>)}
        </div>
        <div className="st-editor-area">
          <pre ref={layer} className="st-editor-layer" aria-hidden data-testid="kql-highlight">
            <code style={{ position: "relative", display: "inline-block", minWidth: "100%", font: "inherit" }}>
              {segments.map((s, i) => s.kind ? <span key={i} className={`st-tok-${s.kind}`}>{s.text}</span> : s.text)}
              {"\n"}
              {error && (
                <span className="st-err-mark" data-testid="kql-error-mark"
                  style={{ top: (error.line - 1) * LINE, left: `${error.column - 1}ch`, width: `${errLen}ch` }}>
                  {" ".repeat(errLen)}
                </span>
              )}
            </code>
          </pre>
          <textarea
            ref={input} className="st-editor-input" value={value} spellCheck={false} autoCorrect="off" autoCapitalize="off" autoComplete="off" wrap="off"
            aria-label={label} role="combobox" aria-autocomplete="list" aria-expanded={!!ac} aria-controls={listId}
            aria-activedescendant={ac ? `${listId}-${ac.index}` : undefined} aria-describedby={`${listId}-help`}
            onChange={e => { onChange(e.target.value); refreshAc(e.target.value, e.target.selectionStart); noteCaret(); }}
            onKeyDown={onKeyDown} onScroll={syncScroll} onClick={() => { setAc(null); noteCaret(); }} onKeyUp={noteCaret} onBlur={() => setAc(null)}
            data-testid="kql-input"
          />
          <span id={`${listId}-help`} className="st-sr">Shift+Enter runs the query. Tab indents. Press Escape, then Tab, to leave the editor.</span>
          <span ref={measure} className="st-mono" style={{ position: "absolute", visibility: "hidden", fontSize: 13, whiteSpace: "pre" }}>{"M".repeat(20)}</span>
        </div>
        <ul id={listId} role="listbox" aria-label="Suggestions" className="st-ac" style={ac ? { left: ac.x, top: ac.y } : { display: "none" }}>
          {ac?.items.map((it, i) => (
            <li key={`${it.kind}:${it.label}`} id={`${listId}-${i}`} role="option" aria-selected={i === ac.index} className="st-ac-opt"
              // mousedown, not click: click would blur the textarea and close the list first.
              onMouseDown={e => { e.preventDefault(); accept(it); }}>
              <span className="st-ac-kind" aria-hidden>{KIND_GLYPH[it.kind]}</span>
              <span>{it.label}</span>
              {it.detail && <span className="detail">{it.detail}</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
});
