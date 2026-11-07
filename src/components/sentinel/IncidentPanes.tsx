"use client";
// The slide-overs of an incident: Tasks, Activity log, and the playbook runner.
import { useMemo, useRef, useState } from "react";
import { ClipboardList, MessageSquare, Pencil, Play, Plus, UserRound, Workflow } from "lucide-react";
import type { SentinelIncident } from "@/lib/sentinel/types";
import { useSentinel, type PlaybookRun } from "./context";
import { activityTitle, commentText, entitiesOf, fmtShortTime } from "./helpers";
import { Empty, Select, SlidePanel } from "./ui";

export function TasksPane({ incident, onClose }: { incident: SentinelIncident; onClose: () => void }) {
  const { stateOf, actions, ended, report } = useSentinel();
  const state = stateOf(incident.id);
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  const done = state.tasks.filter(t => t.done).length;
  const add = async () => {
    const t = title.trim();
    if (!t) return;
    setBusy(true);
    const err = await actions.setTask(incident.id, t, false);
    setBusy(false);
    report(err);
    if (!err) setTitle("");
  };
  return (
    <SlidePanel title="Incident tasks" subtitle={`${done}/${state.tasks.length} completed`} onClose={onClose} width={440}
      footer={<button type="button" className="st-btn" onClick={onClose}>Close</button>}>
      <div className="st-progress" aria-hidden><i style={{ width: `${state.tasks.length ? (done / state.tasks.length) * 100 : 0}%` }} /></div>
      {!ended && (
        <form className="st-row" style={{ margin: "10px 0" }} onSubmit={e => { e.preventDefault(); void add(); }}>
          <label className="st-grow"><span className="st-sr">New task</span>
            <input data-autofocus className="st-input" value={title} maxLength={200} onChange={e => setTitle(e.target.value)} placeholder="Add a task" />
          </label>
          <button type="submit" className="st-btn" disabled={!title.trim() || busy}><Plus size={14} aria-hidden />Add task</button>
        </form>
      )}
      {state.tasks.length === 0 && <Empty icon={<ClipboardList size={26} aria-hidden />} title="No tasks yet">Tasks you add are shared with the team.</Empty>}
      <ul>
        {state.tasks.map(t => (
          <li key={t.id} className="st-entity-row">
            <label className="st-check st-grow">
              <input type="checkbox" checked={t.done} disabled={ended}
                onChange={e => void actions.setTask(incident.id, t.title, e.target.checked).then(report)} />
              <span style={t.done ? { textDecoration: "line-through", color: "var(--st-text-2)" } : undefined}>{t.title}</span>
            </label>
            {t.by && <span className="st-small st-muted">{t.by}</span>}
          </li>
        ))}
      </ul>
    </SlidePanel>
  );
}

type Filter = "All" | "Activities" | "Comments";
const FILTERS: { value: Filter; label: Filter }[] = [{ value: "All", label: "All" }, { value: "Activities", label: "Activities" }, { value: "Comments", label: "Comments" }];

export function ActivityPane({ incident, onClose }: { incident: SentinelIncident; onClose: () => void }) {
  const { stateOf, actions, ended, report } = useSentinel();
  const state = stateOf(incident.id);
  const [filter, setFilter] = useState<Filter>("All");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const box = useRef<HTMLTextAreaElement>(null);

  const items = useMemo(() => {
    const out = [
      ...(filter === "Activities" ? [] : state.comments.map(c => ({ key: c.id, at: c.at, comment: true, who: c.author, text: c.text }))),
      // A comment is its own entry here, so the "Comment added" line would only repeat it.
      ...(filter === "Comments" ? [] : state.activity.filter(a => a.text !== "Comment added").map((a, i) => ({ key: `a${i}`, at: a.at, comment: false, who: a.actor, text: a.text }))),
    ];
    return out.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  }, [state.comments, state.activity, filter]);

  const atLimit = state.comments.length >= 100;
  const send = async () => {
    const t = text.trim();
    if (!t) return;
    setBusy(true);
    const err = await actions.addComment(incident.id, t);
    setBusy(false);
    report(err);
    if (!err) setText("");
    box.current?.focus();
  };

  return (
    <SlidePanel title="Incident activity log" onClose={onClose} width={680} noBody>
      <div style={{ padding: "0 16px 10px" }}>
        <Select label="Activity logs content" value={filter} options={FILTERS} onChange={setFilter} className="st-pill">
          Activity logs content : <b>{filter}</b>
        </Select>
      </div>
      <div className="st-panel-body" aria-live="polite">
        {items.length === 0 && <Empty icon={<MessageSquare size={26} aria-hidden />} title="Nothing logged yet" />}
        {items.map(i => (
          <div key={i.key} className={`st-activity-card${i.comment ? " comment" : ""}`}>
            <span className={`who${i.comment ? " person" : ""}`} aria-hidden>{i.comment ? <UserRound size={18} /> : <Pencil size={14} />}</span>
            <div className="body">
              <div className="t"><strong>{i.comment ? i.who : activityTitle(i.text)}</strong> <span className="when">{fmtShortTime(i.at)}</span></div>
              <div className="d">{i.comment ? commentText(i.text) : <>{i.text} by <em>{i.who}</em></>}</div>
            </div>
          </div>
        ))}
      </div>
      {!ended && (
        <div className="st-comment-box">
          {atLimit
            ? <div className="st-msg warn">This incident has reached the limit of 100 comments.</div>
            : (
              <div className="row">
                <span className="who person" aria-hidden><UserRound size={18} /></span>
                <label className="st-grow"><span className="st-sr">Write a comment</span>
                  <textarea ref={box} data-autofocus className="st-input st-textarea" rows={4} maxLength={4000} value={text} placeholder="Write a comment..." onChange={e => setText(e.target.value)}
                    onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); void send(); } }} />
                </label>
              </div>
            )}
          <div className="st-row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
            <button type="button" className="st-btn" onClick={onClose}>Close</button>
            <button type="button" className="st-btn primary" disabled={!text.trim() || busy || atLimit} onClick={() => void send()}>Comment</button>
          </div>
        </div>
      )}
    </SlidePanel>
  );
}

export const PLAYBOOKS: { name: "Isolate device" | "Release device"; description: string }[] = [
  { name: "Isolate device", description: "Cuts the device off the network through the endpoint agent." },
  { name: "Release device", description: "Returns an isolated device to the network." },
];

export function hostIsolated(set: Set<string>, host: string): boolean {
  const h = host.toLowerCase();
  for (const s of set) if (s.toLowerCase() === h) return true;
  return false;
}

export function RunResult({ run }: { run: PlaybookRun }) {
  return <div className={`st-msg ${run.ok ? "ok" : "err"}`} role={run.ok ? "status" : "alert"}>{run.message}</div>;
}

/** Playbooks work on devices, so the panel asks for one unless the caller already chose it. */
export function PlaybookPanel({ incidentId, host, onClose }: { incidentId?: string; host?: string; onClose: () => void }) {
  const { ws, actions, runPlaybook, ended } = useSentinel();
  const incident = ws.incidents.find(i => i.id === incidentId);
  const hosts = useMemo(() => {
    const scoped = incident ? entitiesOf(incident, ws) : Object.values(ws.entities);
    return [...new Set(scoped.filter(e => e.kind === "host").map(e => e.name))].sort((a, b) => a.localeCompare(b));
  }, [incident, ws]);
  const [target, setTarget] = useState(host ?? hosts[0] ?? "");
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<PlaybookRun | null>(null);
  const run = async (name: "Isolate device" | "Release device") => {
    setBusy(name); setResult(null);
    const r = await runPlaybook(name, target, incident?.title);
    setBusy(null); setResult(r);
  };
  return (
    <SlidePanel title="Run playbook" subtitle={incident ? `On incident ${incident.number}` : "On a device"} icon={<Workflow size={20} color="#0078d4" aria-hidden />} onClose={onClose} width={460}
      footer={<button type="button" className="st-btn" onClick={onClose}>Close</button>}>
      {hosts.length === 0 && !host
        ? <Empty icon={<Workflow size={26} aria-hidden />} title="No playbook applies">This incident has no device entity, and every playbook here acts on a device.</Empty>
        : (
          <div className="st-stack">
            {host
              ? <div><span className="st-label">Device</span>{host}</div>
              : <label><span className="st-label">Device</span>
                  <select data-autofocus className="st-input" value={target} onChange={e => setTarget(e.target.value)}>
                    {hosts.map(h => <option key={h} value={h}>{h}</option>)}
                  </select>
                </label>}
            {target && <p className="st-small st-muted">Current state: {hostIsolated(actions.isolatedHosts, target) ? "Isolated" : "Not isolated"}</p>}
            {result && <RunResult run={result} />}
            <table className="st-table">
              <thead><tr><th scope="col">Playbook</th><th scope="col" style={{ width: 90 }}><span className="st-sr">Run</span></th></tr></thead>
              <tbody>
                {PLAYBOOKS.map(p => (
                  <tr key={p.name}>
                    <td style={{ whiteSpace: "normal", height: 44 }}><strong>{p.name}</strong><div className="st-muted">{p.description}</div></td>
                    <td><button type="button" className="st-btn" disabled={ended || !target || busy !== null} onClick={() => void run(p.name)}><Play size={12} aria-hidden />Run</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </SlidePanel>
  );
}

