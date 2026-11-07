"use client";
import { useMemo, useState } from "react";
import type { KqlColumn, KqlRow } from "@/lib/kql/types";
import { useSentinel } from "./context";
import { fmtValue } from "./engine";
import { entitiesFromRows, KIND_LABEL } from "./helpers";
import { EntityIcon, SlidePanel } from "./ui";

const MAX_ROWS = 50;

export function BookmarkDialog({ query, columns, rows, incidentId, onClose, onSaved }: {
  query: string; columns: KqlColumn[]; rows: KqlRow[]; incidentId?: string; onClose: () => void; onSaved: () => void;
}) {
  const { ws, saveBookmark } = useSentinel();
  const mapped = useMemo(() => entitiesFromRows(rows, ws), [rows, ws]);
  const [name, setName] = useState(`Bookmark from ${firstWord(query)}`);
  const [notes, setNotes] = useState("");
  const [picked, setPicked] = useState<Set<string>>(() => new Set(mapped.map(e => e.id)));
  const [target, setTarget] = useState(incidentId ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const incident = ws.incidents.find(i => i.id === (incidentId ?? target));

  const save = async () => {
    setBusy(true); setErr(null);
    const saved = rows.slice(0, MAX_ROWS).map(r => Object.fromEntries(columns.map(c => [c.name, fmtValue(r[c.name], c.type)])));
    const e = await saveBookmark({
      name: name.trim(), query, columns: columns.map(c => c.name), rows: saved, notes: notes.trim(),
      incidentId: target || undefined, entityIds: [...picked],
    });
    setBusy(false);
    if (e) setErr(e); else onSaved();
  };

  return (
    <SlidePanel title="Add bookmark" subtitle={`${rows.length} selected ${rows.length === 1 ? "row" : "rows"}`} onClose={onClose} width={440}
      footer={<>
        <button type="button" className="st-btn primary" disabled={busy || !name.trim()} onClick={() => void save()}>{busy ? "Adding..." : "Create"}</button>
        <button type="button" className="st-btn" onClick={onClose}>Cancel</button>
      </>}>
      <div className="st-stack">
        {err && <div className="st-msg err" role="alert">{err}</div>}
        <label><span className="st-label">Bookmark name</span>
          <input data-autofocus className="st-input" maxLength={200} value={name} onChange={e => setName(e.target.value)} />
        </label>
        {incidentId
          ? <div><span className="st-label">Incident</span>{incident ? `${incident.number}: ${incident.title}` : incidentId}</div>
          : (
            <label><span className="st-label">Add to incident</span>
              <select className="st-input" value={target} onChange={e => setTarget(e.target.value)}>
                <option value="">None</option>
                {ws.incidents.map(i => <option key={i.id} value={i.id}>{i.number}: {i.title}</option>)}
              </select>
            </label>
          )}
        <label><span className="st-label">Notes</span>
          <textarea className="st-input st-textarea" maxLength={4000} value={notes} onChange={e => setNotes(e.target.value)} placeholder="Why this result matters" />
        </label>
        <div>
          <span className="st-label">Entities mapped from the selected rows</span>
          {mapped.length === 0 && <p className="st-muted st-small">No known entity in the selected rows.</p>}
          <div className="st-stack" style={{ gap: 4 }}>
            {mapped.map(e => (
              <label key={e.id} className="st-check">
                <input type="checkbox" checked={picked.has(e.id)}
                  onChange={() => setPicked(p => { const n = new Set(p); if (n.has(e.id)) n.delete(e.id); else n.add(e.id); return n; })} />
                <EntityIcon kind={e.kind} size={12} /><span className="st-ellipsis">{e.name}</span><span className="st-muted st-small">{KIND_LABEL[e.kind]}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <span className="st-label">Query</span>
          <pre className="st-mono st-small" style={{ margin: 0, padding: 8, background: "var(--st-canvas)", whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 140, overflow: "auto" }}>{query}</pre>
        </div>
        {rows.length > MAX_ROWS && <p className="st-small st-muted">The first {MAX_ROWS} rows are saved with the bookmark.</p>}
      </div>
    </SlidePanel>
  );
}

function firstWord(q: string): string {
  return /^\s*(?:let\b[^\n]*\n\s*)*([A-Za-z_]\w*)/.exec(q)?.[1] ?? "query";
}
