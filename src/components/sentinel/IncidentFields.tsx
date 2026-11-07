"use client";
// Owner, Status and Severity: the same three controls in the grid preview and on the details page.
import { useCallback, useRef, useState, type ReactNode } from "react";
import { ChevronDown, CircleUserRound } from "lucide-react";
import type { ClosingClassification, IncidentState, IncidentStatus, SentinelIncident, SentinelSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { CLASSIFICATIONS, SEVERITIES, STATUSES } from "./helpers";
import { Popover, Select, Severity, StatusIcon, type Opt } from "./ui";

const UNASSIGNED = "__unassigned__";

function ClosePopover({ anchor, onClose, onApply }: {
  anchor: HTMLElement; onClose: () => void; onApply: (c: ClosingClassification, comment: string) => Promise<string | null>;
}) {
  const [classification, setClassification] = useState<ClosingClassification | "">("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const apply = async () => {
    if (!classification) return;
    setBusy(true); setErr(null);
    const e = await onApply(classification, comment.trim());
    setBusy(false);
    if (e) setErr(e); else onClose();
  };
  return (
    <Popover anchor={anchor} onClose={onClose} width={330} role="dialog" label="Close incident">
      <div className="st-pop-pad">
        <strong>Close incident</strong>
        {err && <div className="st-msg err" role="alert">{err}</div>}
        <label><span className="st-label">Classification</span>
          <select className="st-input" value={classification} onChange={e => setClassification(e.target.value as ClosingClassification)}>
            <option value="" disabled>Select classification</option>
            {CLASSIFICATIONS.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <label><span className="st-label">Comment</span>
          <textarea className="st-input st-textarea" value={comment} maxLength={4000} onChange={e => setComment(e.target.value)} placeholder="Why this incident is being closed" />
        </label>
        <div className="st-row">
          <button type="button" className="st-btn primary" disabled={!classification || busy} onClick={() => void apply()}>Apply</button>
          <button type="button" className="st-btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </Popover>
  );
}

function useFields(incident: SentinelIncident, state: IncidentState) {
  const { actions, report } = useSentinel();
  return {
    setSeverity: (severity: SentinelSeverity) => { if (severity !== state.severity) void actions.updateIncident(incident.id, { severity }).then(report); },
    setOwner: (v: string) => { const owner = v === UNASSIGNED ? null : v; if (owner !== state.owner) void actions.updateIncident(incident.id, { owner }).then(report); },
    setStatus: (status: IncidentStatus) => { if (status !== state.status) void actions.updateIncident(incident.id, { status }).then(report); },
    close: (classification: ClosingClassification, closingComment: string) => actions.updateIncident(incident.id, { status: "Closed", classification, closingComment }),
  };
}

function ownerOptions(me: string, people: string[]): Opt[] {
  const others = [...new Set(people)].filter(p => p !== me).sort((a, b) => a.localeCompare(b));
  return [
    { value: UNASSIGNED, label: "Unassigned" },
    { value: me, label: `Assign to me (${me})` },
    ...others.map(p => ({ value: p, label: p })),
  ];
}

const sevOptions: Opt<SentinelSeverity>[] = SEVERITIES.map(s => ({ value: s, label: s, icon: <i className={`st-band ${s}`} style={{ height: 14 }} aria-hidden /> }));
const statusOptions: Opt<IncidentStatus>[] = STATUSES.map(s => ({ value: s, label: s, icon: <StatusIcon status={s} /> }));

function StatusControl({ incident, state, className, children }: { incident: SentinelIncident; state: IncidentState; className?: string; children?: ReactNode }) {
  const { ended } = useSentinel();
  const f = useFields(incident, state);
  const [closing, setClosing] = useState<HTMLElement | null>(null);
  const holder = useRef<HTMLSpanElement>(null);
  const stop = useCallback(() => setClosing(null), []);
  return (
    <span ref={holder} style={{ display: "contents" }}>
      <Select label="Status" value={state.status} options={statusOptions} disabled={ended} className={className}
        onChange={s => {
          if (s === "Closed") setClosing(holder.current?.querySelector("button") ?? null);
          else f.setStatus(s);
        }}>
        {children}
      </Select>
      {closing && <ClosePopover anchor={closing} onClose={stop} onApply={f.close} />}
    </span>
  );
}

/** The three-cell strip at the top of the details panel. */
export function FieldBar({ incident, state, collapsed, onToggle, collapseIcon }: {
  incident: SentinelIncident; state: IncidentState; collapsed: boolean; onToggle: () => void; collapseIcon: ReactNode;
}) {
  const { actions, ended } = useSentinel();
  const f = useFields(incident, state);
  const owners = ownerOptions(actions.me.name, actions.people);
  return (
    <div className="st-fieldbar">
      <Select label="Severity" value={state.severity} options={sevOptions} disabled={ended} className="st-fieldcell" onChange={f.setSeverity}>
        <i className={`band st-band ${state.severity}`} aria-hidden />
        <span className="st-grow"><span className="val st-ellipsis">{state.severity}</span><span className="lab">Severity</span></span>
        {!ended && <ChevronDown size={14} aria-hidden />}
      </Select>
      <StatusControl incident={incident} state={state} className="st-fieldcell">
        <span className="st-grow"><span className="val"><StatusIcon status={state.status} />{state.status}</span><span className="lab">Status</span></span>
        {!ended && <ChevronDown size={14} aria-hidden />}
      </StatusControl>
      <Select label="Owner" value={state.owner ?? UNASSIGNED} valueLabel={state.owner ?? "Unassigned"} options={owners} disabled={ended} className="st-fieldcell" onChange={f.setOwner} searchable width={260}>
        <span className="st-grow" style={{ minWidth: 0 }}>
          <span className="val"><CircleUserRound size={14} color="#0078d4" aria-hidden /><span className="st-ellipsis">{state.owner ?? "Unassigned"}</span></span>
          <span className="lab">Owner</span>
        </span>
        {!ended && <ChevronDown size={14} aria-hidden />}
      </Select>
      <button type="button" className="st-collapse-btn" aria-label={collapsed ? "Expand details panel" : "Collapse details panel"} aria-expanded={!collapsed} onClick={onToggle}>{collapseIcon}</button>
    </div>
  );
}

/** Stacked dropdowns of the grid's preview pane. */
export function FieldStack({ incident, state }: { incident: SentinelIncident; state: IncidentState }) {
  const { actions, ended } = useSentinel();
  const f = useFields(incident, state);
  const owners = ownerOptions(actions.me.name, actions.people);
  const cls = "st-input st-row";
  return (
    <div className="st-2col" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginTop: 4 }}>
      <div><div className="st-k">Owner</div>
        <Select label="Owner" value={state.owner ?? UNASSIGNED} valueLabel={state.owner ?? "Unassigned"} options={owners} disabled={ended} className={cls} onChange={f.setOwner} searchable width={260}>
          <span className="st-ellipsis st-grow">{state.owner ?? "Unassigned"}</span><ChevronDown size={12} aria-hidden />
        </Select>
      </div>
      <div><div className="st-k">Status</div>
        <StatusControl incident={incident} state={state} className={cls}>
          <StatusIcon status={state.status} /><span className="st-grow">{state.status}</span><ChevronDown size={12} aria-hidden />
        </StatusControl>
      </div>
      <div><div className="st-k">Severity</div>
        <Select label="Severity" value={state.severity} options={sevOptions} disabled={ended} className={cls} onChange={f.setSeverity}>
          <span className="st-grow"><Severity value={state.severity} /></span><ChevronDown size={12} aria-hidden />
        </Select>
      </div>
    </div>
  );
}
