"use client";
// The slide-overs of an incident: Tasks, Activity log, and the playbook runner.
import { useMemo, useRef, useState } from "react";
import { ListTodo, History, Pencil, Play, Plus, UserRound, Bot } from "lucide-react";
import type { SentinelActions, SentinelIncident, SentinelIsolationRequest } from "@/lib/sentinel/types";
import { useSentinel, type PlaybookRun } from "./context";
import { activityTitle, commentText, entitiesOf, fmtDateTime, fmtShortTime } from "./helpers";
import { Empty, Select, SlidePanel } from "./ui";
import { NO_APPROVER, isNoApprover, waitingForApproval } from "@/lib/team/isolationApproval";

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
      {state.tasks.length === 0 && <Empty icon={<ListTodo size={26} aria-hidden />} title="No tasks yet">Tasks you add are shared with the team.</Empty>}
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
        {items.length === 0 && <Empty icon={<History size={26} aria-hidden />} title="Nothing logged yet" />}
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

/** A device's isolation as the viewer should see it: isolated, waiting for approval, or connected. */
export interface DeviceState { isolated: boolean; pending: SentinelIsolationRequest | null; last: SentinelIsolationRequest | null; label: string; short: string }
export function deviceState(actions: SentinelActions, host: string): DeviceState {
  const h = host.toLowerCase();
  const isolated = hostIsolated(actions.isolatedHosts, host);
  const mine = (actions.isolationRequests ?? []).filter(r => r.host.toLowerCase() === h);
  const last = mine.length ? mine[mine.length - 1] : null;
  const pending = last && last.state === "pending" ? last : null;
  if (isolated) return { isolated, pending: null, last, label: "Isolated", short: "isolated" };
  if (pending) return { isolated, pending, last, label: isNoApprover(pending.approver) ? `Isolation requested. ${NO_APPROVER}` : `Isolation requested, waiting for approval from ${pending.approver}`, short: isNoApprover(pending.approver) ? "no approver on shift" : "isolation requested" };
  if (last?.state === "denied") return { isolated, pending: null, last, label: `Not isolated. The last request was denied by ${last.approver}${last.denyReason ? `: ${last.denyReason}` : ""}`, short: "not isolated" };
  return { isolated, pending: null, last, label: "Not isolated", short: "not isolated" };
}

/** The device picker's option text, with the device's state. */
export function deviceOption(actions: SentinelActions, host: string): string {
  const s = deviceState(actions, host);
  return s.isolated || s.pending ? `${host} (${s.short})` : host;
}

export function RunResult({ run }: { run: PlaybookRun }) {
  return <div className={`st-msg ${run.pending ? "info" : run.ok ? "ok" : "err"}`} role={run.ok ? "status" : "alert"}>{run.message}</div>;
}

/** Why the device should be isolated: an isolation in a team session goes to the senior on shift with it. */
export function IsolationReason({ value, onChange, id, error }: { value: string; onChange: (v: string) => void; id: string; error?: string | null }) {
  return (
    <label htmlFor={id} style={{ display: "block" }}>
      <span className="st-label">Reason for isolating (sent with the request)</span>
      <textarea id={id} className="st-input st-textarea" style={{ minHeight: 56 }} maxLength={500} value={value} onChange={e => onChange(e.target.value)}
        placeholder="What you saw on this device, in a few words" aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-err` : `${id}-help`} />
      {error ? <span id={`${id}-err`} className="st-small" style={{ color: "var(--st-err)" }}>{error}</span>
        : <span id={`${id}-help`} className="st-small st-muted">Isolation needs the approval of the senior on shift. The device is cut off when they approve.</span>}
    </label>
  );
}

/**
 * Playbook runs in this session: the viewer's isolation requests with their answer, and releases.
 * In a side panel (`compact`) each run is a short stacked entry, so nothing is clipped at the panel's
 * width and no long detail stretches a table row (2026-11-08 review: "Wai..." and an empty gap).
 */
export function PlaybookHistory({ runs, actions, maxWidth = 900, compact = false }: { runs: PlaybookRun[]; actions: SentinelActions; maxWidth?: number; compact?: boolean }) {
  const requests = (actions.isolationRequests ?? []).filter(r => r.mine);
  // A request just sent shows from the run until the session log brings it back.
  const shown = runs.filter(r => !(r.pending && requests.some(q => q.host.toLowerCase() === r.host.toLowerCase() && (!q.at || Date.parse(q.at) >= Date.parse(r.at) - 60_000))));
  type Row = { key: string; at: string; playbook: string; host: string; result: string; detail: string };
  const rows: Row[] = [
    ...shown.map(r => ({ key: r.id, at: r.at, playbook: r.playbook, host: r.host, result: r.pending ? "Waiting" : r.ok ? "Succeeded" : "Refused", detail: r.message })),
    ...requests.map(q => ({
      key: `req-${q.seq}`, at: q.at ?? "", playbook: "Isolate device", host: q.host,
      result: q.state === "pending" ? "Waiting" : q.state === "approved" ? "Approved" : "Denied",
      detail: q.state === "pending" ? `${waitingForApproval(q.approver, { requester: q.mine }).replace(/([^.])$/, "$1.")} Reason: ${q.reason}`
        : q.state === "approved" ? `Approved by ${q.approver}. The device is isolated.`
        : `Denied by ${q.approver}${q.denyReason ? `: ${q.denyReason}` : "."}`,
    })),
  ].sort((a, b) => Date.parse(b.at || "0") - Date.parse(a.at || "0"));
  if (!rows.length) return null;
  if (compact) {
    return (
      <div className="st-runs">
        <h3 className="st-label" id="pb-runs-h">Runs in this session</h3>
        <ul aria-labelledby="pb-runs-h">
          {rows.map(r => (
            <li key={r.key} className="st-run">
              <div className="st-run-head">
                <strong>{r.playbook}</strong>
                <span className={`st-run-${r.result.toLowerCase()}`}>{r.result}</span>
              </div>
              <div className="st-small st-muted">{r.at ? fmtDateTime(r.at) : "-"} · <bdi>{r.host}</bdi></div>
              <div className="st-run-detail">{r.detail}</div>
            </li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <table className="st-table st-runs-table" aria-label="Playbook runs" style={{ maxWidth }}>
      <colgroup><col style={{ width: 170 }} /><col style={{ width: 120 }} /><col style={{ width: 140 }} /><col style={{ width: 96 }} /><col /></colgroup>
      <thead><tr><th scope="col">Time</th><th scope="col">Playbook</th><th scope="col">Device</th><th scope="col">Result</th><th scope="col">Details</th></tr></thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.key}>
            <td>{r.at ? fmtDateTime(r.at) : "-"}</td><td>{r.playbook}</td><td className="st-ellipsis" title={r.host}>{r.host}</td>
            <td><span className={`st-run-${r.result.toLowerCase()}`}>{r.result}</span></td>
            <td className="st-run-detail">{r.detail}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Playbooks work on devices, so the panel asks for one unless the caller already chose it. */
export function PlaybookPanel({ incidentId, host, onClose }: { incidentId?: string; host?: string; onClose: () => void }) {
  const { ws, actions, runPlaybook, runs, ended } = useSentinel();
  const incident = ws.incidents.find(i => i.id === incidentId);
  const hosts = useMemo(() => {
    const scoped = incident ? entitiesOf(incident, ws) : Object.values(ws.entities);
    return [...new Set(scoped.filter(e => e.kind === "host").map(e => e.name))].sort((a, b) => a.localeCompare(b));
  }, [incident, ws]);
  const [target, setTarget] = useState(host ?? hosts[0] ?? "");
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<PlaybookRun | null>(null);
  const [reason, setReason] = useState("");
  const [reasonErr, setReasonErr] = useState<string | null>(null);
  const asks = !!actions.requestIsolation;
  const state = target ? deviceState(actions, target) : null;
  const run = async (name: "Isolate device" | "Release device") => {
    if (name === "Isolate device" && asks && !reason.trim()) { setReasonErr("Say in a few words why this device should be isolated."); return; }
    setBusy(name); setResult(null); setReasonErr(null);
    const r = await runPlaybook(name, target, incident?.title, reason.trim());
    setBusy(null); setResult(r);
    if (r.ok && name === "Isolate device") setReason("");
  };
  return (
    <SlidePanel title="Run playbook" subtitle={incident ? `On incident ${incident.number}` : "On a device"} icon={<Bot size={20} color="#6d28d9" aria-hidden />} onClose={onClose} width={460}
      footer={<button type="button" className="st-btn" onClick={onClose}>Close</button>}>
      {hosts.length === 0 && !host
        ? <Empty icon={<Bot size={26} aria-hidden />} title="No playbook applies">This incident has no device entity, and every playbook here acts on a device.</Empty>
        : (
          <div className="st-stack">
            {host
              ? <div><span className="st-label">Device</span>{host}</div>
              : <label><span className="st-label">Device</span>
                  <select data-autofocus className="st-input" value={target} onChange={e => setTarget(e.target.value)}>
                    {hosts.map(h => <option key={h} value={h}>{deviceOption(actions, h)}</option>)}
                  </select>
                </label>}
            {state && <p className="st-small st-muted" role="status">Current state: {state.label}</p>}
            {asks && <IsolationReason id="pb-reason" value={reason} onChange={v => { setReason(v); if (reasonErr) setReasonErr(null); }} error={reasonErr} />}
            {result && <RunResult run={result} />}
            <table className="st-table">
              <thead><tr><th scope="col">Playbook</th><th scope="col" style={{ width: 116 }}><span className="st-sr">Run</span></th></tr></thead>
              <tbody>
                {PLAYBOOKS.map(p => (
                  <tr key={p.name}>
                    <td style={{ whiteSpace: "normal", height: 44 }}><strong>{p.name}</strong><div className="st-muted">{p.description}</div></td>
                    <td><button type="button" className="st-btn" disabled={ended || !target || busy !== null || (p.name === "Isolate device" && !!(state?.isolated || state?.pending))} aria-label={p.name === "Isolate device" && asks ? "Request isolation" : `Run ${p.name}`} onClick={() => void run(p.name)}><Play size={12} aria-hidden />{p.name === "Isolate device" && asks ? "Request" : "Run"}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {target && <PlaybookHistory runs={runs.filter(r => r.host.toLowerCase() === target.toLowerCase())} actions={{ ...actions, isolationRequests: (actions.isolationRequests ?? []).filter(r => r.host.toLowerCase() === target.toLowerCase()) }} compact />}
          </div>
        )}
    </SlidePanel>
  );
}

