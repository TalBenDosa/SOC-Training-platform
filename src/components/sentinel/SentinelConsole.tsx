"use client";
import "./sentinel.css";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, Briefcase, ChevronsLeft, ChevronsRight, Crosshair, Eye, Fingerprint, Gauge, Lock, Radar, Search, ShieldCheck, TerminalSquare, Workflow, X,
} from "lucide-react";
import type { IncidentState, SentinelActions, SentinelBookmark, SentinelEntity, SentinelWorkspace } from "@/lib/sentinel/types";
import { SentinelProvider, type LogsRequest, type PlaybookRequest, type PlaybookRun, type Screen, type SentinelCtx } from "./context";
import { setCompletionTables } from "./engine";
import { allBookmarks, bookmarkTable, defaultState, KIND_LABEL, tiComment, tidyWorkspace } from "./helpers";
import { IncidentDetails } from "./IncidentDetails";
import { PlaybookPanel } from "./IncidentPanes";
import { IncidentsPage } from "./IncidentsPage";
import { InvestigationGraph } from "./InvestigationGraph";
import { LogsPanel } from "./LogsPanel";
import { OverviewPage } from "./OverviewPage";
import { AnalyticsPage, AutomationPage, EntityBehaviorPage, HuntingPage, SearchPage, ThreatIntelPage } from "./SimplePages";
import { BladeHeader, SlidePanel } from "./ui";

export interface SentinelConsoleProps {
  workspace: SentinelWorkspace;
  states: Map<string, IncidentState>;
  actions: SentinelActions;
  onRefresh: () => void;
  ended: boolean;
  /** Where the SIEM window link goes when no window is open. */
  backHref?: string;
  /** Deep link from the team room: opens this incident, or this host's entity page. */
  initial?: { incidentId?: string; host?: string };
  /** Bumped when the SIEM window sends the analyst to something. Same shape as initial. */
  goTo?: { incidentId?: string; host?: string; nonce: number };
  /** Brings the SIEM window forward instead of leaving this one. */
  onBack?: () => void;
}

const NAV: { group: string; items: { id: Screen; label: string; icon: typeof Gauge }[] }[] = [
  { group: "General", items: [
    { id: "overview", label: "Overview", icon: Gauge },
    { id: "logs", label: "Logs", icon: TerminalSquare },
    { id: "search", label: "Search", icon: Search },
  ] },
  { group: "Threat management", items: [
    { id: "incidents", label: "Incidents", icon: Briefcase },
    { id: "hunting", label: "Hunting", icon: Crosshair },
    { id: "entity", label: "Entity behavior", icon: Fingerprint },
    { id: "ti", label: "Threat intelligence", icon: ShieldCheck },
  ] },
  { group: "Configuration", items: [
    { id: "analytics", label: "Analytics", icon: Activity },
    { id: "automation", label: "Automation", icon: Workflow },
  ] },
];

/** Focus goes back to what opened a blade, once that is visible again. */
const refocus = (el: HTMLElement | null) => window.setTimeout(() => { if (el?.isConnected) el.focus({ preventScroll: true }); }, 0);

const SCREEN_TITLE: Record<Screen, string> = {
  overview: "Overview", logs: "Logs", search: "Search", incidents: "Incidents", hunting: "Hunting", entity: "Entity behavior", ti: "Threat intelligence", analytics: "Analytics", automation: "Automation",
};

interface Toast { id: number; kind: "incident" | "error" | "info"; title: string; body?: string; incidentId?: string; severity?: string }

export function SentinelConsole({ workspace: source, states, actions, onRefresh, ended, backHref = "/team", initial, goTo, onBack }: SentinelConsoleProps) {
  const workspace = useMemo(() => tidyWorkspace(source), [source]);
  const [screen, setScreen] = useState<Screen>("incidents");
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [navQ, setNavQ] = useState("");
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [focusEntity, setFocusEntity] = useState<string | undefined>(undefined);
  const [investigateId, setInvestigateId] = useState<string | null>(null);
  const [logsOverlay, setLogsOverlay] = useState<(LogsRequest & { key: number }) | null>(null);
  const [logsRequest, setLogsRequest] = useState<(LogsRequest & { key: number }) | null>(null);
  const [logsMounted, setLogsMounted] = useState(false);
  const [playbook, setPlaybook] = useState<PlaybookRequest | null>(null);
  const [entityFocus, setEntityFocus] = useState<string | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(() => new Set());
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [runs, setRuns] = useState<PlaybookRun[]>([]);
  const [looseBookmarks, setLooseBookmarks] = useState<SentinelBookmark[]>([]);
  const logsKey = useRef(0);
  const toastId = useRef(0);
  const knownIds = useRef<Set<string> | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const backFromIncident = useRef<HTMLElement | null>(null);
  const backFromGraph = useRef<HTMLElement | null>(null);
  // The team room hands a new function on every render: a ref keeps the context stable.
  const refreshRef = useRef(onRefresh);
  refreshRef.current = onRefresh;
  const refresh = useCallback(() => refreshRef.current(), []);

  const stateMemo = useRef(new Map<string, IncidentState>());
  const stateOf = useCallback((id: string): IncidentState => {
    const s = states.get(id);
    if (s) return s;
    const cached = stateMemo.current.get(id);
    if (cached) return cached;
    const inc = workspace.incidents.find(i => i.id === id);
    const d = defaultState(inc ?? { severity: "Informational" });
    stateMemo.current.set(id, d);
    return d;
  }, [states, workspace.incidents]);

  // Everything beside the console on the page sits under it, unseen. Without this a keyboard user
  // would tab through the platform's sidebar with nothing visible happening.
  useEffect(() => {
    const touched: Element[] = [];
    for (let at: Element | null = rootRef.current; at && at !== document.body; at = at.parentElement) {
      for (const sib of at.parentElement?.children ?? []) {
        if (sib === at || sib.hasAttribute("inert") || sib.hasAttribute("data-sentinel-keep") || /^(SCRIPT|STYLE|LINK)$/.test(sib.tagName)) continue;
        sib.setAttribute("inert", "");
        touched.push(sib);
      }
    }
    return () => { for (const el of touched) el.removeAttribute("inert"); };
  }, []);

  const pushToast = useCallback((t: Omit<Toast, "id">) => {
    toastId.current += 1;
    const id = toastId.current;
    setToasts(list => [...list.slice(-2), { ...t, id }]);
    window.setTimeout(() => setToasts(list => list.filter(x => x.id !== id)), t.kind === "incident" ? 30_000 : 7000);
  }, []);
  const report = useCallback((err: string | null) => { if (err) pushToast({ kind: "error", title: "The action was refused", body: err }); }, [pushToast]);

  // Incidents that arrive after the first paint get the marker and a notification.
  useEffect(() => {
    const ids = workspace.incidents.map(i => i.id);
    if (!knownIds.current) { knownIds.current = new Set(ids); return; }
    const known = knownIds.current;
    const added = workspace.incidents.filter(i => !known.has(i.id));
    if (!added.length) return;
    for (const i of added) known.add(i.id);
    setFresh(f => new Set([...f, ...added.map(i => i.id)]));
    for (const i of added) pushToast({ kind: "incident", title: `New incident ${i.number}`, body: i.title, incidentId: i.id, severity: i.severity });
  }, [workspace.incidents, pushToast]);

  const go = useCallback((s: Screen) => {
    setScreen(s);
    if (s === "logs") setLogsMounted(true);
    if (s === "entity") setEntityFocus(null);
  }, []);

  const openIncident = useCallback((id: string, opts?: { entityId?: string }) => {
    backFromIncident.current = document.activeElement as HTMLElement | null;
    setInvestigateId(null);
    setFocusEntity(opts?.entityId);
    setIncidentId(id);
    setFresh(f => { if (!f.has(id)) return f; const n = new Set(f); n.delete(id); return n; });
    setToasts(list => list.filter(t => t.incidentId !== id));
  }, []);
  const openInvestigation = useCallback((id: string) => {
    backFromGraph.current = document.activeElement as HTMLElement | null;
    setInvestigateId(id);
  }, []);
  const closeIncident = useCallback(() => { setIncidentId(null); setInvestigateId(null); refocus(backFromIncident.current); }, []);
  const closeInvestigation = useCallback(() => { setInvestigateId(null); refocus(backFromGraph.current); }, []);

  const inIncident = incidentId !== null || investigateId !== null;
  const openLogs = useCallback((req: LogsRequest) => {
    logsKey.current += 1;
    const keyed = { ...req, key: logsKey.current };
    if (inIncident) { setLogsOverlay(keyed); return; }
    setLogsRequest(keyed);
    setLogsMounted(true);
    setScreen("logs");
  }, [inIncident]);

  const openEntity = useCallback((id: string) => {
    setIncidentId(null);
    setInvestigateId(null);
    setEntityFocus(id);
    setScreen("entity");
  }, []);

  // A deep link can name something the poll has not delivered yet: it opens once, when it arrives.
  const deepLinked = useRef(false);
  useEffect(() => {
    if (deepLinked.current || !initial) return;
    const hostEntity = initial.host ? Object.values(workspace.entities).find(e => e.kind === "host" && e.name.toLowerCase() === initial.host?.toLowerCase()) : undefined;
    if (initial.incidentId) {
      const inc = workspace.incidents.find(i => i.id === initial.incidentId);
      if (!inc) return;
      deepLinked.current = true;
      openIncident(inc.id, hostEntity ? { entityId: hostEntity.id } : undefined);
    } else if (hostEntity) {
      deepLinked.current = true;
      openEntity(hostEntity.id);
    }
  }, [initial, workspace, openIncident, openEntity]);

  // The SIEM window sent the analyst here. What they have open stays: only the view moves.
  useEffect(() => {
    if (!goTo) return;
    const inc = goTo.incidentId ? workspace.incidents.find(i => i.id === goTo.incidentId) : undefined;
    if (inc) { openIncident(inc.id); return; }
    const host = goTo.host?.toLowerCase();
    const entity = host ? Object.values(workspace.entities).find(e => e.kind === "host" && e.name.toLowerCase() === host) : undefined;
    if (entity) openEntity(entity.id);
    // Only a new request moves the view, never a workspace refresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [goTo?.nonce]);

  const addToTi = useCallback((entity: SentinelEntity, id: string) => {
    void actions.addComment(id, tiComment(entity)).then(err => {
      report(err);
      if (!err) pushToast({ kind: "info", title: "Added to threat intelligence", body: entity.name });
    });
  }, [actions, pushToast, report]);

  const runPlaybook = useCallback<SentinelCtx["runPlaybook"]>(async (playbookName, host, incidentTitle) => {
    let err: string | null;
    try { err = await actions.setIsolated(host, playbookName === "Isolate device", incidentTitle); }
    catch (e) { err = e instanceof Error ? e.message : "The playbook could not run."; }
    const run: PlaybookRun = {
      id: `${Date.now()}-${Math.random()}`, at: workspace.now, playbook: playbookName, host, by: actions.me.name, ok: !err,
      message: err ?? `${playbookName} succeeded on ${host}.`,
    };
    setRuns(r => [run, ...r].slice(0, 30));
    return run;
  }, [actions, workspace.now]);

  const saveBookmark = useCallback<SentinelActions["addBookmark"]>(async b => {
    const err = await actions.addBookmark(b);
    if (!err && !b.incidentId) setLooseBookmarks(l => [{ ...b, id: `local-${Date.now()}`, author: actions.me.name, at: workspace.now }, ...l]);
    return err;
  }, [actions, workspace.now]);

  const bookmarks = useMemo(() => [...looseBookmarks, ...allBookmarks(states)].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)), [looseBookmarks, states]);
  const tables = useMemo(() => (workspace.tables.HuntingBookmark?.rows.length
    ? workspace.tables
    : { ...workspace.tables, HuntingBookmark: bookmarkTable(bookmarks) }), [workspace.tables, bookmarks]);
  useEffect(() => setCompletionTables(tables, workspace.now), [tables, workspace.now]);

  const ctx = useMemo<SentinelCtx>(() => ({
    ws: workspace, states, actions, ended, tables, bookmarks, fresh, runs, stateOf, report,
    openIncident, openInvestigation, openLogs, openPlaybook: setPlaybook, openEntity, go, addToTi, saveBookmark, runPlaybook, refresh,
  }), [workspace, states, actions, ended, tables, bookmarks, fresh, runs, stateOf, report, openIncident, openInvestigation, openLogs, openEntity, go, addToTi, saveBookmark, runPlaybook, refresh]);

  const incident = incidentId ? workspace.incidents.find(i => i.id === incidentId) : undefined;
  const investigated = investigateId ? workspace.incidents.find(i => i.id === investigateId) : undefined;
  const nq = navQ.trim().toLowerCase();
  const covered = !!incident || !!investigated;
  const focused = screen === "entity" && entityFocus ? workspace.entities[entityFocus] : undefined;
  const ScreenIcon = focused ? Fingerprint : (NAV.flatMap(g => g.items).find(i => i.id === screen)?.icon ?? Gauge);

  return (
    <SentinelProvider value={ctx}>
      <div ref={rootRef} className="st-root" data-testid="sentinel-root">
        <header className="st-topbar">
          <strong>Sentinel</strong>
          <span aria-hidden>|</span>
          <span className="st-ellipsis" data-testid="workspace-name">{workspace.name}</span>
          <span className="st-grow" />
          <span className="st-ellipsis">{actions.me.name}{actions.me.role ? ` (${actions.me.role})` : ""}</span>
          <a href={backHref} onClick={e => { if (onBack) { e.preventDefault(); onBack(); } }}>SIEM window</a>
        </header>
        {ended && <div className="st-ended" role="status"><Lock size={13} aria-hidden />The exercise has ended. This workspace is read-only: queries still run, changes are off.</div>}
        <div className="st-shell">
          {!covered && (
            <BladeHeader icon={<ScreenIcon size={30} color="#0078d4" fill={ScreenIcon === Briefcase ? "#c7e0f4" : "none"} aria-hidden />} {...(focused
              ? { strong: focused.name, sub: KIND_LABEL[focused.kind], crumbs: [{ label: "Home" }, { label: "Sentinel | Entity behavior", onClick: () => setEntityFocus(null) }] }
              : { strong: "Sentinel", light: SCREEN_TITLE[screen], sub: `Selected workspace: '${workspace.name}'`, crumbs: [{ label: "Home" }, { label: "Sentinel" }] })} />
          )}
          <div className="st-body">
          <nav className={`st-nav${navCollapsed ? " collapsed" : ""}`} aria-label="Sentinel menu" hidden={covered}>
            <div className="st-nav-top">
              {!navCollapsed && (
                <label className="st-search st-grow"><Search size={14} aria-hidden /><span className="st-sr">Search menu</span>
                  <input className="st-input" value={navQ} onChange={e => setNavQ(e.target.value)} placeholder="Search" />
                </label>
              )}
              <button type="button" className="st-icon-btn" aria-label={navCollapsed ? "Expand menu" : "Collapse menu"} aria-expanded={!navCollapsed} onClick={() => setNavCollapsed(c => !c)}>
                {navCollapsed ? <ChevronsRight size={15} aria-hidden /> : <ChevronsLeft size={15} aria-hidden />}
              </button>
            </div>
            {NAV.map(g => {
              const items = g.items.filter(i => !nq || i.label.toLowerCase().includes(nq));
              if (!items.length) return null;
              return (
                <div key={g.group}>
                  {!navCollapsed && <div className="st-nav-group"><span>{g.group}</span></div>}
                  {items.map(i => (
                    <button key={i.id} type="button" className="st-nav-item" title={i.label} aria-label={navCollapsed ? i.label : undefined} aria-current={screen === i.id ? "page" : undefined} onClick={() => go(i.id)}>
                      <i.icon size={15} aria-hidden />{!navCollapsed && i.label}
                    </button>
                  ))}
                </div>
              );
            })}
          </nav>
          <main className="st-blade" hidden={covered}>
            {screen === "overview" && <OverviewPage />}
            {screen === "search" && <SearchPage />}
            {screen === "incidents" && <IncidentsPage />}
            {screen === "hunting" && <HuntingPage />}
            {screen === "entity" && <EntityBehaviorPage focus={entityFocus} onFocus={setEntityFocus} />}
            {screen === "ti" && <ThreatIntelPage />}
            {screen === "analytics" && <AnalyticsPage />}
            {screen === "automation" && <AutomationPage />}
            {logsMounted && (
              <div className="st-page" hidden={screen !== "logs"} style={screen === "logs" ? undefined : { display: "none" }}>
                <LogsPanel mode="workspace" request={logsRequest} />
              </div>
            )}
          </main>
          </div>
          {incident && <IncidentDetails key={`incident-${incident.id}`} incident={incident} focusEntity={focusEntity} onClose={closeIncident} hidden={!!investigated} />}
          {investigated && <InvestigationGraph key={`investigate-${investigated.id}`} incident={investigated} onClose={closeInvestigation} />}
          {logsOverlay && (
            <SlidePanel title="Logs" subtitle={workspace.name} width="min(1130px, 80%)" noBody onClose={() => setLogsOverlay(null)}
              icon={<TerminalSquare size={28} color="#0078d4" aria-hidden />}
              footer={<button type="button" className="st-btn primary" onClick={() => setLogsOverlay(null)}>Done</button>}>
              <LogsPanel key={logsOverlay.key} mode="panel" request={logsOverlay} incidentId={logsOverlay.incidentId ?? investigateId ?? incidentId ?? undefined} />
            </SlidePanel>
          )}
          {playbook && <PlaybookPanel incidentId={playbook.incidentId} host={playbook.host} onClose={() => setPlaybook(null)} />}
          <div className="st-toasts" aria-live="polite">
            {toasts.map(t => (
              <div key={t.id} className={`st-toast ${t.kind === "error" ? "err" : t.severity ?? ""}`} role={t.kind === "error" ? "alert" : "status"}>
                {t.incidentId && <Radar size={14} color="#0078d4" aria-hidden />}
                {t.kind === "info" && <Eye size={14} color="#0078d4" aria-hidden />}
                <div className="st-grow">
                  <strong>{t.title}</strong>
                  {t.body && <div className="st-ellipsis" title={t.body} style={{ whiteSpace: t.kind === "error" ? "normal" : undefined }}>{t.body}</div>}
                  {t.incidentId && <button type="button" className="st-link" onClick={() => openIncident(t.incidentId as string)}>Open incident</button>}
                </div>
                <button type="button" className="st-icon-btn" style={{ width: 20, height: 20 }} aria-label="Dismiss notification" onClick={() => setToasts(l => l.filter(x => x.id !== t.id))}><X size={12} aria-hidden /></button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </SentinelProvider>
  );
}
