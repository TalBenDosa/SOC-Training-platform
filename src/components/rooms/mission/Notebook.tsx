"use client";
/**
 * Case notebook panel: indicators (typed, shown defanged, each with where it was
 * found), pinned evidence rows (sorted by time into a timeline) and free notes.
 * One notebook per room, kept for the whole room.
 */
import { useId, useMemo, useState } from "react";
import { NotebookPen, Trash2, Plus } from "lucide-react";
import { defang, detectIocType } from "@/lib/missions/normalize";
import type { IocType } from "@/lib/missions/types";
import { cn } from "@/lib/utils";
import { newId, useNotebook } from "./notebookStore";

export const IOC_TYPES: { id: IocType; label: string }[] = [
  { id: "ip", label: "IP" }, { id: "domain", label: "Domain" }, { id: "url", label: "URL" }, { id: "email", label: "Email" },
  { id: "sha256", label: "SHA256" }, { id: "sha1", label: "SHA1" }, { id: "md5", label: "MD5" }, { id: "filename", label: "File name" },
  { id: "host", label: "Host" }, { id: "account", label: "Account" },
];

export function useAddIoc(roomId: string) {
  const { update } = useNotebook(roomId);
  return (value: string, source: string, type?: IocType | null) => {
    const v = value.trim();
    if (!v) return false;
    const t = type ?? detectIocType(v);
    if (!t) return false;
    update(n => n.iocs.some(i => i.type === t && i.value.toLowerCase() === v.toLowerCase()) ? n : { ...n, iocs: [...n.iocs, { id: newId(), type: t, value: v, source }] });
    return true;
  };
}

export function Notebook({ roomId, caseId }: { roomId: string; caseId?: string }) {
  const { nb, update } = useNotebook(roomId);
  const [tab, setTab] = useState<"iocs" | "pins" | "notes">("iocs");
  const [draft, setDraft] = useState("");
  const [draftType, setDraftType] = useState<IocType | "">("");
  const [error, setError] = useState<string | null>(null);
  const ids = useId();
  const detected = draft.trim() ? detectIocType(draft) : null;
  const pins = useMemo(() => [...nb.pins].sort((a, b) => (a.time ?? "").localeCompare(b.time ?? "")), [nb.pins]);

  function add() {
    const v = draft.trim();
    if (!v) return;
    const t = (draftType || detected) as IocType | null;
    if (!t) { setError("Can't tell what this is. Pick its type first."); return; }
    update(n => n.iocs.some(i => i.type === t && i.value.toLowerCase() === v.toLowerCase()) ? n : { ...n, iocs: [...n.iocs, { id: newId(), type: t, value: v, source: "typed" }] });
    setDraft(""); setDraftType(""); setError(null);
  }

  return (
    <aside aria-label="Case notebook" className="rounded-xl border border-border bg-bg-panel/70 p-3 text-sm">
      <div className="mb-2 flex items-center gap-2">
        <NotebookPen className="h-4 w-4 text-cyber-300" aria-hidden />
        <h3 className="font-semibold text-white">Case notebook</h3>
        {caseId && <span className="ml-auto font-mono text-[11px] text-slate-500">{caseId}</span>}
      </div>
      <div role="tablist" aria-label="Notebook sections" className="mb-2 flex gap-1">
        {([["iocs", `Indicators (${nb.iocs.length})`], ["pins", `Pinned (${nb.pins.length})`], ["notes", "Notes"]] as const).map(([id, label]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
            className={cn("rounded-md px-2 py-1 text-xs", tab === id ? "bg-cyber-500/20 text-cyber-100" : "text-slate-400 hover:text-slate-200")}>
            {label}
          </button>
        ))}
      </div>

      {tab === "iocs" && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            <label htmlFor={`${ids}-v`} className="sr-only">Indicator value</label>
            <input id={`${ids}-v`} value={draft} onChange={e => { setDraft(e.target.value); setError(null); }}
              onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
              placeholder="Type or paste an indicator"
              className="min-w-0 flex-1 rounded-md border border-border bg-bg-elevated px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-500/30" />
            <label htmlFor={`${ids}-t`} className="sr-only">Indicator type</label>
            <select id={`${ids}-t`} value={draftType} onChange={e => setDraftType(e.target.value as IocType | "")}
              className="rounded-md border border-border bg-bg-elevated px-1.5 py-1 text-xs text-slate-200">
              <option value="">{detected ? `Auto: ${IOC_TYPES.find(t => t.id === detected)?.label}` : "Type"}</option>
              {IOC_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
            <button type="button" onClick={add} className="inline-flex items-center gap-1 rounded-md border border-cyber-500/40 px-2 py-1 text-xs text-cyber-200 hover:bg-cyber-500/15">
              <Plus className="h-3 w-3" aria-hidden /> Add
            </button>
          </div>
          {error && <p className="text-xs text-neon-amber">{error}</p>}
          {nb.iocs.length === 0
            ? <p className="text-xs text-slate-500">No indicators yet. Select text in the evidence and press &quot;Add selection&quot;, or type one above.</p>
            : (
              <ul className="space-y-1">
                {nb.iocs.map(i => (
                  <li key={i.id} className="flex items-center gap-2 rounded-md bg-bg-elevated/70 px-2 py-1">
                    <span className="shrink-0 rounded bg-cyber-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-cyber-200">{IOC_TYPES.find(t => t.id === i.type)?.label}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-200" title={i.value}>{defang(i.type, i.value)}</span>
                    <span className="hidden max-w-[5.5rem] shrink truncate text-[10px] text-slate-500 sm:inline" title={i.source}>{i.source}</span>
                    <button type="button" aria-label={`Remove ${i.value}`} onClick={() => update(n => ({ ...n, iocs: n.iocs.filter(x => x.id !== i.id) }))}
                      className="rounded p-0.5 text-slate-500 hover:text-severity-high"><Trash2 className="h-3 w-3" aria-hidden /></button>
                  </li>
                ))}
              </ul>
            )}
        </div>
      )}

      {tab === "pins" && (
        pins.length === 0
          ? <p className="text-xs text-slate-500">Pin result rows with the pin button. Pinned rows line up here by time: your timeline.</p>
          : (
            <ol className="space-y-1">
              {pins.map(p => (
                <li key={p.id} className="flex items-start gap-2 rounded-md bg-bg-elevated/70 px-2 py-1">
                  <span className="shrink-0 font-mono text-[10px] text-cyber-200">{p.time ?? "no time"}</span>
                  <span className="min-w-0 flex-1 break-all font-mono text-[11px] text-slate-300">{p.text}</span>
                  <button type="button" aria-label="Unpin" onClick={() => update(n => ({ ...n, pins: n.pins.filter(x => x.id !== p.id) }))}
                    className="rounded p-0.5 text-slate-500 hover:text-severity-high"><Trash2 className="h-3 w-3" aria-hidden /></button>
                </li>
              ))}
            </ol>
          )
      )}

      {tab === "notes" && (
        <>
          <label htmlFor={`${ids}-n`} className="sr-only">Case notes</label>
          <textarea id={`${ids}-n`} value={nb.notes} onChange={e => { const v = e.target.value; update(n => ({ ...n, notes: v })); }} rows={8}
            placeholder="Hypotheses, open questions, what you still need to check."
            className="w-full rounded-md border border-border bg-bg-elevated p-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-500/30" />
        </>
      )}
    </aside>
  );
}
