"use client";
import { useState, useEffect, useMemo, useRef } from "react";
import { Topbar } from "@/components/nav/Topbar";
import {
  Search, Download, Sparkles, Plus, Eye, Edit2, Trash2,
  X, ChevronDown, ChevronRight, ChevronLeft, Check, Save, Shield, Users as UsersIcon,
  LayoutDashboard, HelpCircle, Loader2, AlertTriangle,
  RotateCcw, Target, BookOpen, Activity, Database, Zap, Code2, ExternalLink,
  ShieldCheck, XCircle, AlertCircle, Info, Play, RefreshCw, CheckCircle2,
} from "lucide-react";
import type { ValidationReport, ValidationIssue, IssueSeverity } from "@/lib/sim/logValidator";
import type { TelemetryEvent } from "@/lib/sim/types";
import { cn } from "@/lib/utils";
import { SCENARIOS, buildScenarioBySlug } from "@/lib/sim/scenarios";
import { QUIZZES } from "@/lib/quizzes/data";
import type { Quiz, QuizQuestion } from "@/lib/quizzes/data";
import type { GeneratedQuiz } from "@/app/api/quizzes/generate/route";
import { BUILTIN_LESSONS } from "@/data/builtinLessons";

// --------- Pre-compute log counts (pure, module-level) ------------------------------------------------------------------------------------------
const SCENARIO_LOG_COUNTS: Record<string, number> = {};
for (const s of SCENARIOS) {
  try { SCENARIO_LOG_COUNTS[s.slug] = buildScenarioBySlug(s.slug)?.events.length ?? 0; }
  catch { SCENARIO_LOG_COUNTS[s.slug] = 0; }
}

// --------- Shared helpers ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const ATTACK_KIND_LABEL: Record<string, string> = {
  phishing_to_exfil: "Phishing / Social Engineering",
  identity_bec:      "Identity & Access",
  ransomware:        "Malware",
  oauth_persistence: "Cloud / OAuth",
  insider_threat:    "Insider Threat",
};

const DIFF_CONFIG: Record<string, { label: string; cls: string }> = {
  beginner:     { label: "Beginner",     cls: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25" },
  easy:         { label: "Easy",         cls: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25" },
  intermediate: { label: "Intermediate", cls: "bg-amber-500/10   text-amber-400   border border-amber-500/25"   },
  medium:       { label: "Medium",       cls: "bg-amber-500/10   text-amber-400   border border-amber-500/25"   },
  advanced:     { label: "Advanced",     cls: "bg-violet-500/10  text-violet-400  border border-violet-500/25"  },
  hard:         { label: "Hard",         cls: "bg-rose-500/10    text-rose-400    border border-rose-500/25"    },
  expert:       { label: "Expert",       cls: "bg-rose-500/10    text-rose-400    border border-rose-500/25"    },
  Beginner:     { label: "Beginner",     cls: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25" },
  Intermediate: { label: "Intermediate", cls: "bg-amber-500/10   text-amber-400   border border-amber-500/25"   },
  Advanced:     { label: "Advanced",     cls: "bg-violet-500/10  text-violet-400  border border-violet-500/25"  },
};

function DiffBadge({ d }: { d: string }) {
  const c = DIFF_CONFIG[d] ?? { label: d, cls: "bg-slate-500/10 text-slate-400 border border-slate-500/25" };
  return <span className={cn("rounded px-2 py-0.5 text-[11px] font-semibold", c.cls)}>{c.label}</span>;
}

const STATUS_CFG: Record<string, { cls: string; dot: string }> = {
  published: { cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25", dot: "bg-emerald-400" },
  draft:     { cls: "bg-amber-500/15   text-amber-400   border-amber-500/25",   dot: "bg-amber-400"   },
};

type ItemStatus = "published" | "draft";

function StatusDropdown({ status, onChange }: { status: ItemStatus; onChange: (s: ItemStatus) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    function onClick(e: MouseEvent) { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);
  const cfg = STATUS_CFG[status];
  return (
    <div ref={ref} className="relative inline-block">
      <button
        onClick={e => { e.stopPropagation(); setOpen(v => !v); }}
        className={cn("flex items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] font-semibold transition hover:opacity-80", cfg.cls)}
      >
        <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", cfg.dot)} />
        {status.charAt(0).toUpperCase() + status.slice(1)}
        <ChevronDown className="h-3 w-3 opacity-60" />
      </button>
      {open && (
        <div className="absolute left-0 top-full z-50 mt-1 w-32 rounded border border-[#2a3555] bg-[#0f1423] shadow-xl py-1">
          {(["published","draft"] as ItemStatus[]).map(s => (
            <button key={s} onClick={() => { onChange(s); setOpen(false); }}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-[11px] text-slate-200 hover:bg-[#1a2035] transition">
              <span className={cn("h-1.5 w-1.5 rounded-full", STATUS_CFG[s].dot)} />
              {s.charAt(0).toUpperCase() + s.slice(1)}
              {s === status && <Check className="ml-auto h-3 w-3 text-emerald-400" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function CategoryBadge({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded border border-[#2a3555] bg-[#161c2b] px-2.5 py-1 text-[11px] text-slate-300">
      {label}
    </span>
  );
}

// --------- Slide-in drawer ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function Drawer({ open, onClose, title, children }: {
  open: boolean; onClose: () => void; title: string; children: React.ReactNode;
}) {
  return (
    <>
      {open && <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" onClick={onClose} />}
      <div className={cn(
        "fixed right-0 top-0 z-50 h-full w-[820px] border-l border-[#2a3555] bg-[#0c1120] shadow-2xl transition-transform duration-300 flex flex-col",
        open ? "translate-x-0" : "translate-x-full"
      )}>
        <div className="flex items-center justify-between border-b border-[#2a3555] px-6 py-4 shrink-0">
          <h2 className="text-base font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="rounded p-1.5 text-slate-400 hover:bg-[#1a2035] hover:text-white transition">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">{children}</div>
      </div>
    </>
  );
}

// --------- Shared field components ------------------------------------------------------------------------------------------------------------------------------------------------------

const fieldCls = "w-full rounded border border-[#2a3555] bg-[#0f1423] px-3 py-2.5 text-sm text-slate-200 placeholder:text-slate-600 focus:border-violet-500/50 focus:outline-none transition";

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        {label}{required && <span className="ml-1 text-rose-400">*</span>}
      </label>
      {children}
    </div>
  );
}

// --------- Search + Filter bar ------------------------------------------------------------------------------------------------------------------------------------------------------------------

function FilterBar({ search, onSearch, filters, onFilter }: {
  search: string; onSearch: (v: string) => void;
  filters: { levels: string[]; categories: string[] };
  onFilter: (key: "level" | "category" | "status", v: string) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
        <input
          value={search}
          onChange={e => onSearch(e.target.value)}
          placeholder="Search--¦"
          className="w-full rounded border border-[#2a3555] bg-[#0f1423] py-2 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-violet-500/50 focus:outline-none"
        />
      </div>
      {[
        { key: "level" as const, label: "All Levels", opts: filters.levels },
        { key: "category" as const, label: "All Categories", opts: filters.categories },
        { key: "status" as const, label: "All Status", opts: ["Published", "Draft"] },
      ].map(f => (
        <select key={f.key} onChange={e => onFilter(f.key, e.target.value)}
          className="rounded border border-[#2a3555] bg-[#0f1423] px-3 py-2 text-sm text-slate-300 focus:outline-none">
          <option value="">{f.label}</option>
          {f.opts.map(o => <option key={o} value={o.toLowerCase()}>{o}</option>)}
        </select>
      ))}
    </div>
  );
}

// -------------------------------------------------------------------------------
// OVERVIEW TAB
// -------------------------------------------------------------------------------

function OverviewTab() {
  const stats = [
    { label: "Total Users",      value: "6",    sub: "2 admins",         icon: UsersIcon,    color: "text-violet-400" },
    { label: "Active Scenarios", value: String(SCENARIOS.length), sub: "5 published", icon: Shield,     color: "text-emerald-400" },
    { label: "Active Quizzes",   value: String(QUIZZES.length),   sub: "6 published", icon: HelpCircle, color: "text-amber-400"   },
    { label: "Scenarios Played", value: "1,284", sub: "+47 this week",   icon: Activity,     color: "text-cyan-400"    },
  ];
  return (
    <div className="p-6 space-y-6">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {stats.map(s => (
          <div key={s.label} className="rounded-lg border border-[#2a3555] bg-[#0f1423] p-5">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] uppercase tracking-wider text-slate-500">{s.label}</p>
                <p className="mt-2 font-mono text-3xl font-bold text-white">{s.value}</p>
                <p className="mt-1 text-[11px] text-slate-500">{s.sub}</p>
              </div>
              <s.icon className={cn("h-5 w-5 mt-0.5", s.color)} />
            </div>
          </div>
        ))}
      </div>
      <div className="rounded-lg border border-[#2a3555] bg-[#0f1423] p-5">
        <p className="text-sm font-semibold text-white mb-3">Scenario Overview</p>
        <div className="space-y-2">
          {SCENARIOS.map(s => (
            <div key={s.slug} className="flex items-center gap-3 rounded border border-[#1e2841] bg-[#0a0e1a] px-4 py-2.5">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-200 truncate">{s.title}</p>
                <p className="text-[11px] text-slate-500 truncate">{s.summary.slice(0,80)}--¦</p>
              </div>
              <DiffBadge d={s.difficulty} />
              <span className="font-mono text-[11px] text-slate-500">{SCENARIO_LOG_COUNTS[s.slug]} logs</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// -------------------------------------------------------------------------------
// USERS TAB
// -------------------------------------------------------------------------------

interface AdminUser { id: string; email: string; role: string; status: "active"|"invited"|"suspended"; startDate: string; endDate: string; }
const ROLES = ["admin","instructor","senior_analyst","analyst","threat_hunter"];
const SEED_USERS: AdminUser[] = [
  { id:"u1", email:"alice@cryotech.io",  role:"admin",          status:"active",    startDate:"2025-01-01", endDate:"2026-12-31" },
  { id:"u2", email:"ben@cryotech.io",    role:"instructor",     status:"active",    startDate:"2025-03-15", endDate:"2026-03-14" },
  { id:"u3", email:"carol@cryotech.io",  role:"senior_analyst", status:"active",    startDate:"2025-01-01", endDate:"2025-12-31" },
  { id:"u4", email:"dan@cryotech.io",    role:"analyst",        status:"invited",   startDate:"2026-05-01", endDate:"2027-04-30" },
  { id:"u5", email:"eve@cryotech.io",    role:"threat_hunter",  status:"active",    startDate:"2025-06-01", endDate:"2026-05-31" },
  { id:"u6", email:"frank@cryotech.io",  role:"analyst",        status:"suspended", startDate:"2024-09-01", endDate:"2025-08-31" },
];
const USER_STATUS_CFG: Record<string,string> = {
  active:    "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
  invited:   "bg-violet-500/10  text-violet-400  border border-violet-500/20",
  suspended: "bg-rose-500/10    text-rose-400    border border-rose-500/20",
};

function UsersTab() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [editId, setEditId] = useState<string|null>(null);
  const [draft, setDraft]   = useState<Partial<AdminUser>>({});
  const [adding, setAdding] = useState(false);
  const [newRow, setNewRow] = useState<Omit<AdminUser,"id">>({ email:"", role:"analyst", status:"active", startDate:"", endDate:"" });
  const today = new Date().toISOString().slice(0,10);

  useEffect(() => {
    try { const s=localStorage.getItem("admin_users"); setUsers(s?JSON.parse(s):SEED_USERS); }
    catch { setUsers(SEED_USERS); }
  }, []);

  function persist(next: AdminUser[]) { setUsers(next); localStorage.setItem("admin_users",JSON.stringify(next)); }
  function beginEdit(u:AdminUser) { setEditId(u.id); setDraft({...u}); }
  function cancelEdit() { setEditId(null); setDraft({}); }
  function commitEdit() { persist(users.map(u=>u.id===editId?{...u,...draft} as AdminUser:u)); cancelEdit(); }
  function del(id:string) { persist(users.filter(u=>u.id!==id)); }
  function addUser() {
    if(!newRow.email.trim()) return;
    persist([...users,{...newRow,id:`u-${Date.now()}`}]);
    setNewRow({email:"",role:"analyst",status:"active",startDate:"",endDate:""}); setAdding(false);
  }

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2841] shrink-0">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2"><UsersIcon className="h-4 w-4 text-violet-400"/>User Management</h2>
          <p className="text-[11px] text-slate-500 mt-0.5">{users.filter(u=>u.status==="active").length} active · {users.filter(u=>u.status==="invited").length} invited · {users.filter(u=>u.status==="suspended").length} suspended</p>
        </div>
        <button onClick={()=>{setAdding(v=>!v);cancelEdit();}} className="flex items-center gap-2 rounded bg-teal-600 hover:bg-teal-500 px-4 py-2 text-sm font-semibold text-white transition">
          <Plus className="h-4 w-4"/> Add User
        </button>
      </div>

      {/* Add row */}
      {adding && (
        <div className="grid grid-cols-[2fr_1fr_1fr_1fr_1fr_72px] gap-2 border-b border-emerald-500/20 bg-emerald-500/5 px-6 py-3 items-center shrink-0">
          <input autoFocus placeholder="email@domain.com" value={newRow.email} onChange={e=>setNewRow(f=>({...f,email:e.target.value}))} className={fieldCls} />
          <select value={newRow.role} onChange={e=>setNewRow(f=>({...f,role:e.target.value}))} className={fieldCls}>{ROLES.map(r=><option key={r}>{r}</option>)}</select>
          <select value={newRow.status} onChange={e=>setNewRow(f=>({...f,status:e.target.value as AdminUser["status"]}))} className={fieldCls}><option>active</option><option>invited</option><option>suspended</option></select>
          <input type="date" value={newRow.startDate} onChange={e=>setNewRow(f=>({...f,startDate:e.target.value}))} className={fieldCls} />
          <input type="date" value={newRow.endDate}   onChange={e=>setNewRow(f=>({...f,endDate:e.target.value}))}   className={fieldCls} />
          <div className="flex gap-1 justify-end">
            <button onClick={addUser}          className="rounded p-1.5 text-emerald-400 hover:bg-emerald-500/10 transition"><Check className="h-4 w-4"/></button>
            <button onClick={()=>setAdding(false)} className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] transition"><X className="h-4 w-4"/></button>
          </div>
        </div>
      )}

      {/* Table header */}
      <div className="grid grid-cols-[2fr_1fr_1fr_1fr_1fr_72px] gap-2 border-b border-[#1e2841] bg-[#0a0e1a] px-6 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 shrink-0">
        <span>Email</span><span>Role</span><span>Status</span><span>Access From</span><span>Access Until</span><span className="text-right">Actions</span>
      </div>

      {/* Rows */}
      <div className="flex-1 overflow-y-auto">
        {users.map(u => {
          const editing = editId===u.id;
          const d = editing ? draft : u;
          const expired = u.endDate && u.endDate < today;
          return (
            <div key={u.id} className={cn("grid grid-cols-[2fr_1fr_1fr_1fr_1fr_72px] gap-2 border-b border-[#1e2841] px-6 py-3 items-center transition hover:bg-[#0f1728]", editing && "bg-violet-500/5 border-l-2 border-l-violet-500/40")}>
              {editing
                ? <input value={d.email??""} onChange={e=>setDraft(f=>({...f,email:e.target.value}))} className={cn(fieldCls,"py-1.5 font-mono text-xs")} />
                : <div><p className="font-mono text-sm text-slate-200">{u.email}</p></div>}
              {editing
                ? <select value={d.role??"analyst"} onChange={e=>setDraft(f=>({...f,role:e.target.value}))} className={cn(fieldCls,"py-1.5")}>{ROLES.map(r=><option key={r}>{r}</option>)}</select>
                : <span className="inline-block rounded border border-[#2a3555] bg-[#0f1423] px-2 py-0.5 text-[11px] text-slate-300">{u.role}</span>}
              {editing
                ? <select value={d.status??"active"} onChange={e=>setDraft(f=>({...f,status:e.target.value as AdminUser["status"]}))} className={cn(fieldCls,"py-1.5")}><option>active</option><option>invited</option><option>suspended</option></select>
                : <span className={cn("inline-block rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider", USER_STATUS_CFG[u.status])}>{u.status}</span>}
              {editing
                ? <input type="date" value={d.startDate??""} onChange={e=>setDraft(f=>({...f,startDate:e.target.value}))} className={cn(fieldCls,"py-1.5")} />
                : <span className="font-mono text-[12px] text-slate-400">{u.startDate||"--"}</span>}
              {editing
                ? <input type="date" value={d.endDate??""} onChange={e=>setDraft(f=>({...f,endDate:e.target.value}))} className={cn(fieldCls,"py-1.5")} />
                : <span className={cn("font-mono text-[12px]", expired?"text-rose-400":"text-slate-400")}>{u.endDate||"--"}{expired&&"  ✓"}</span>}
              <div className="flex items-center justify-end gap-1">
                {editing
                  ? <><button onClick={commitEdit} className="rounded p-1.5 text-emerald-400 hover:bg-emerald-500/10 transition"><Check className="h-3.5 w-3.5"/></button>
                        <button onClick={cancelEdit} className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] transition"><X className="h-3.5 w-3.5"/></button></>
                  : <><button onClick={()=>beginEdit(u)} className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-violet-400 transition"><Edit2 className="h-3.5 w-3.5"/></button>
                        <button onClick={()=>del(u.id)} className="rounded p-1.5 text-slate-600 hover:bg-rose-500/10 hover:text-rose-400 transition"><Trash2 className="h-3.5 w-3.5"/></button></>
                }
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// -------------------------------------------------------------------------------
// SCENARIOS TAB
// -------------------------------------------------------------------------------

interface ScenarioRow {
  slug: string; title: string; summary: string;
  category: string; difficulty: string; logCount: number;
  status: ItemStatus; isGenerated: boolean;
  threat_actor: string; attack_kind: string; narrative?: string;
  events?: TelemetryEvent[]; // stored for generated scenarios
}

const TOPICS = ["MITRE ATT&CK","Incident Response","Log Analysis & SIEM","Threat Intelligence","Network Security","Cloud Security","Identity & Access Management","Malware Analysis","Forensics & DFIR","SOC Operations"];

function ScenariosTab() {
  const [search, setSearch]   = useState("");
  const [levelF, setLevelF]   = useState("");
  const [catF,   setCatF]     = useState("");
  const [statusF, setStatusF] = useState("");
  const [hidden,  setHidden]  = useState<string[]>([]);
  const [statusMap, setStatusMap] = useState<Record<string,ItemStatus>>({});
  const [generated, setGenerated] = useState<ScenarioRow[]>([]);
  const [drawer, setDrawer]   = useState<ScenarioRow|null>(null);

  // Generator
  const [showGen, setShowGen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [genError, setGenError] = useState<string|null>(null);
  const [genAttack, setGenAttack] = useState("random");
  const [genPublished, setGenPublished] = useState(false);
  const [genPreview, setGenPreview] = useState<ScenarioRow|null>(null);
  const [genEvents, setGenEvents] = useState<TelemetryEvent[]>([]); // full events from API

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_scenarios")??"[]"));
      setStatusMap(JSON.parse(localStorage.getItem("admin_scenario_status")??"{}"));
      const pub = JSON.parse(localStorage.getItem("published_scenarios")??"[]");
      setGenerated(pub.map((s: { id: string; title: string; narrative?: string; attack_kind: string; difficulty: string; threat_actor: string; published_at: string; events?: TelemetryEvent[] }) => ({
        slug: s.id, title: s.title, summary: s.narrative ?? "",
        category: ATTACK_KIND_LABEL[s.attack_kind]??s.attack_kind,
        difficulty: s.difficulty, logCount: (s.events?.length ?? 0),
        status: (statusMap[s.id] ?? "published") as ItemStatus, isGenerated: true,
        threat_actor: s.threat_actor, attack_kind: s.attack_kind,
        events: s.events ?? [],
      })));
    } catch {}
  }, []);

  const builtIn: ScenarioRow[] = SCENARIOS.map(s => ({
    slug: s.slug, title: s.title, summary: s.summary,
    category: ATTACK_KIND_LABEL[s.attack_kind] ?? s.attack_kind,
    difficulty: s.difficulty, logCount: SCENARIO_LOG_COUNTS[s.slug] ?? 0,
    status: (statusMap[s.slug] ?? "published") as ItemStatus,
    isGenerated: false, threat_actor: s.threat_actor, attack_kind: s.attack_kind,
  }));

  const all = [...generated, ...builtIn.filter(s=>!hidden.includes(s.slug))];

  const filtered = all.filter(s => {
    if (search && !s.title.toLowerCase().includes(search.toLowerCase()) && !s.category.toLowerCase().includes(search.toLowerCase())) return false;
    if (levelF && s.difficulty.toLowerCase() !== levelF) return false;
    if (catF && !s.category.toLowerCase().includes(catF)) return false;
    if (statusF && s.status !== statusF) return false;
    return true;
  });

  function setStatus(slug: string, status: ItemStatus) {
    const next = { ...statusMap, [slug]: status };
    setStatusMap(next);
    localStorage.setItem("admin_scenario_status", JSON.stringify(next));
  }

  function hideScenario(slug: string) {
    const next = [...hidden, slug]; setHidden(next);
    localStorage.setItem("admin_hidden_scenarios", JSON.stringify(next));
  }

  function deleteGenerated(slug: string) {
    const next = generated.filter(s => s.slug !== slug); setGenerated(next);
    const pub = JSON.parse(localStorage.getItem("published_scenarios")??"[]").filter((s: { id: string }) => s.id !== slug);
    localStorage.setItem("published_scenarios", JSON.stringify(pub));
  }

  async function generateScenario() {
    setLoading(true); setGenError(null); setGenPreview(null); setGenEvents([]);
    try {
      const res = await fetch("/api/scenarios/generate", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({attackType:genAttack}) });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error??"Generation failed");
      const evts: TelemetryEvent[] = Array.isArray(data.events) ? data.events : [];
      setGenEvents(evts);
      setGenPreview({
        slug: `gen-${Date.now()}`, title: data.title, summary: data.narrative ?? "",
        category: ATTACK_KIND_LABEL[data.attack_kind]??data.attack_kind,
        difficulty: data.difficulty, logCount: evts.length,
        status: "published", isGenerated: true,
        threat_actor: data.threat_actor, attack_kind: data.attack_kind, narrative: data.narrative,
        events: evts,
      });
    } catch(e) { setGenError(e instanceof Error?e.message:"Error"); }
    finally { setLoading(false); }
  }

  function publishScenario() {
    if (!genPreview) return;
    const entry = { ...genPreview, id: genPreview.slug, events: genEvents, published_at: new Date().toISOString() };
    const existing = JSON.parse(localStorage.getItem("published_scenarios")??"[]");
    localStorage.setItem("published_scenarios", JSON.stringify([entry, ...existing]));
    setGenerated(prev => [{ ...genPreview, events: genEvents }, ...prev]);
    setGenPublished(true);
    setTimeout(() => { setShowGen(false); setGenPreview(null); setGenEvents([]); setGenPublished(false); }, 1500);
  }

  const levels = [...new Set(all.map(s => s.difficulty.toLowerCase()))].map(d => d.charAt(0).toUpperCase()+d.slice(1));
  const categories = [...new Set(all.map(s => s.category))];

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2841] shrink-0">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-400"/>Scenario Management
          </h2>
          <p className="text-[11px] text-slate-500 mt-0.5">{filtered.length} scenarios · {filtered.filter(s=>s.status==="published").length} published</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 rounded border border-[#2a3555] bg-transparent px-4 py-2 text-sm text-slate-300 hover:border-slate-400 transition">
            <Download className="h-3.5 w-3.5"/> Export ({filtered.length})
          </button>
          <button onClick={()=>setShowGen(v=>!v)} className="flex items-center gap-2 rounded bg-violet-600 hover:bg-violet-500 px-4 py-2 text-sm font-semibold text-white transition">
            <Sparkles className="h-3.5 w-3.5"/> Generate with AI
          </button>
          <button className="flex items-center gap-2 rounded bg-teal-600 hover:bg-teal-500 px-4 py-2 text-sm font-semibold text-white transition">
            <Plus className="h-3.5 w-3.5"/> Add Manually
          </button>
        </div>
      </div>

      {/* Generator panel */}
      {showGen && (
        <div className="shrink-0 border-b border-[#1e2841] bg-[#0a0e1a] px-6 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Controls row */}
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Attack Category</label>
              <select value={genAttack} onChange={e=>setGenAttack(e.target.value)} className={cn(fieldCls,"text-sm")}>
                <option value="random"> Random --" surprise me</option>
                <optgroup label="--------- Initial Access / Social Engineering ---------">
                  <option value="phishing">Phishing + Lateral Movement</option>
                  <option value="spearphish_apt">Spearphish - APT Implant (nation-state)</option>
                  <option value="supply_chain">Supply Chain Compromise</option>
                  <option value="watering_hole">Watering Hole + Drive-by Download</option>
                  <option value="smishing_vishing">Smishing / Vishing / Deepfake</option>
                </optgroup>
                <optgroup label="--------- Identity & Cloud ---------">
                  <option value="identity">Identity / BEC / MFA Bypass</option>
                  <option value="cloud_apt">Cloud APT / OAuth Abuse</option>
                  <option value="aitm">AiTM Reverse Proxy Phishing</option>
                  <option value="saml_golden">SAML Golden Ticket / Cloud Lateral</option>
                  <option value="devops_ci">DevOps / CI-CD Pipeline Compromise</option>
                </optgroup>
                <optgroup label="--------- Malware & Ransomware ---------">
                  <option value="ransomware">Ransomware Deployment</option>
                  <option value="infostealer">Infostealer + Credential Market</option>
                  <option value="rootkit">Rootkit / Bootkit Persistence</option>
                  <option value="cryptomining">Cryptomining / Resource Hijack</option>
                </optgroup>
                <optgroup label="--------- Exploitation & Privilege ---------">
                  <option value="webapp">Web App Attack / RCE</option>
                  <option value="privilege_esc">Privilege Escalation / AD</option>
                  <option value="zeroday">Zero-Day / N-Day Exploitation</option>
                  <option value="ad_kerberos">AD Kerberos Attacks (Kerberoast / DCSync)</option>
                  <option value="container_k8s">Container / Kubernetes Escape</option>
                </optgroup>
                <optgroup label="--------- Exfiltration & Impact ---------">
                  <option value="insider">Insider Threat</option>
                  <option value="data_exfil">Data Exfiltration (DLP Bypass)</option>
                  <option value="destructive">Destructive Attack / Data Wipe</option>
                  <option value="ddos_extortion">DDoS + Ransom Extortion</option>
                </optgroup>
                <optgroup label="--------- Specialist ---------">
                  <option value="ot_scada">OT / ICS / SCADA Attack</option>
                  <option value="mobile_mdm">Mobile / MDM Compromise</option>
                  <option value="dns_hijack">DNS Hijacking / BGP Manipulation</option>
                  <option value="llm_aisec">AI / LLM Security Attack</option>
                </optgroup>
              </select>
            </div>
            <button onClick={generateScenario} disabled={loading} className="flex items-center gap-2 rounded bg-violet-600 hover:bg-violet-500 disabled:opacity-50 px-5 py-2.5 text-sm font-semibold text-white transition whitespace-nowrap">
              {loading?<><Loader2 className="h-3.5 w-3.5 animate-spin"/>Generating--¦</>:<><Sparkles className="h-3.5 w-3.5"/>Generate Scenario</>}
            </button>
            <button onClick={()=>{setShowGen(false);setGenPreview(null);setGenEvents([]);}} className="rounded p-2.5 text-slate-500 hover:bg-[#1a2035] transition"><X className="h-4 w-4"/></button>
          </div>

          {genError && <p className="flex items-center gap-1.5 text-xs text-rose-400"><AlertTriangle className="h-3.5 w-3.5"/>{genError}</p>}

          {/* Generated preview --" full scenario + events */}
          {genPreview && (
            <div className="rounded border border-violet-500/20 bg-violet-500/5 space-y-4 p-4">
              {/* Scenario header */}
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="rounded border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[10px] font-bold uppercase text-violet-400">AI Generated</span>
                    <DiffBadge d={genPreview.difficulty} />
                  </div>
                  <p className="text-base font-bold text-white">{genPreview.title}</p>
                  <p className="text-[11px] text-slate-400 mt-0.5">{genPreview.threat_actor} · {genPreview.category} · {genPreview.logCount} log events</p>
                </div>
                <button onClick={publishScenario} disabled={genPublished} className="shrink-0 flex items-center gap-2 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 px-4 py-2.5 text-sm font-semibold text-white transition">
                  {genPublished?<><Check className="h-3.5 w-3.5"/>Published!</>:<><Plus className="h-3.5 w-3.5"/>Publish</>}
                </button>
              </div>

              {/* Narrative */}
              {genPreview.narrative && (
                <div className="rounded border border-[#2a3555] bg-[#080c15] px-3 py-2.5">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Scenario Narrative</p>
                  <p className="text-[11px] leading-relaxed text-slate-300 whitespace-pre-line">{genPreview.narrative}</p>
                </div>
              )}

              {/* Generated log events --" expandable */}
              {genEvents.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1.5">
                    Generated Log Events ({genEvents.length})
                    <span className="ml-2 normal-case font-normal text-slate-600">Review before publishing · click any row for full fields</span>
                  </p>
                  <div className="rounded border border-[#2a3555] bg-[#080c15] p-1.5 space-y-0.5">
                    {genEvents.map((ev, i) => (
                      <AdminEventRow key={ev.id ?? i} ev={ev} idx={i} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Search/filter */}
      <div className="px-6 py-3 border-b border-[#1e2841] shrink-0">
        <FilterBar search={search} onSearch={setSearch} filters={{ levels, categories }}
          onFilter={(k,v)=>{ if(k==="level") setLevelF(v); else if(k==="category") setCatF(v); else setStatusF(v); }} />
      </div>

      {/* Table header */}
      <div className="grid grid-cols-[2.5fr_1.5fr_1fr_60px_140px_80px_80px] gap-2 border-b border-[#1e2841] bg-[#0a0e1a] px-6 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 shrink-0">
        <span>Title</span><span>Category</span><span>Difficulty</span><span>Logs</span><span>Status</span><span>Source</span><span className="text-right">Actions</span>
      </div>

      {/* Rows */}
      <div className="flex-1 overflow-y-auto">
        {filtered.map(s => (
          <div key={s.slug} className="grid grid-cols-[2.5fr_1.5fr_1fr_60px_140px_80px_80px] gap-2 border-b border-[#1e2841] px-6 py-3.5 items-center hover:bg-[#0f1728] transition">
            <div className="min-w-0 cursor-pointer" onClick={()=>setDrawer(s)}>
              <p className="text-sm font-semibold text-white truncate hover:text-violet-300 transition">{s.title}</p>
              <p className="text-[11px] text-slate-500 truncate mt-0.5">{s.summary.slice(0,60)}{s.summary.length>60?"--¦":""}</p>
            </div>
            <CategoryBadge label={s.category} />
            <DiffBadge d={s.difficulty} />
            <span className="font-mono text-sm text-slate-300">{s.logCount}</span>
            <StatusDropdown status={s.status} onChange={v=>setStatus(s.slug,v)} />
            <span className={cn("text-[11px] font-semibold", s.isGenerated?"text-violet-400":"text-slate-500")}>
              {s.isGenerated?"Generated":"Built-in"}
            </span>
            <div className="flex items-center justify-end gap-1">
              <button onClick={()=>setDrawer(s)} className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-violet-400 transition"><Edit2 className="h-3.5 w-3.5"/></button>
              <button onClick={()=>s.isGenerated?deleteGenerated(s.slug):hideScenario(s.slug)} className="rounded p-1.5 text-slate-600 hover:bg-rose-500/10 hover:text-rose-400 transition"><Trash2 className="h-3.5 w-3.5"/></button>
            </div>
          </div>
        ))}
        <p className="px-6 py-3 text-[11px] text-slate-600">Showing {filtered.length} of {all.length} scenarios</p>
      </div>

      {/* Scenario edit drawer */}
      <Drawer open={!!drawer} onClose={()=>setDrawer(null)} title={drawer?.title ?? "Edit Scenario"}>
        {drawer && <ScenarioDrawerContent key={drawer.slug} scenario={drawer} onClose={()=>setDrawer(null)} />}
      </Drawer>
    </div>
  );
}

// --------- Expandable log-event row (admin view) ------------------------------------------------------------------------------------------------------------

const SRC_CLS: Record<string, string> = {
  edr:        "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  sysmon:     "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  o365:       "bg-violet-500/10 text-violet-400 border-violet-500/20",
  ad:         "bg-violet-500/10 text-violet-400 border-violet-500/20",
  cloudtrail: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  firewall:   "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  dns:        "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
};
const SEV_CLS: Record<string, string> = {
  critical: "text-rose-400",
  high:     "text-orange-400",
  medium:   "text-amber-400",
  low:      "text-slate-500",
};

function AdminEventRow({ ev, idx }: { ev: TelemetryEvent; idx: number }) {
  const [open, setOpen]       = useState(false);
  const [showJson, setShowJson] = useState(false);

  // Build ECS-style field list
  const fields: [string, string][] = [
    ["event.id",       ev.id],
    ["event.type",     ev.event_type.replace(/_/g, " ")],
    ["event.provider", ev.vendor ?? ev.source.toUpperCase()],
    ["event.severity", (ev.severity ?? "informational").toUpperCase()],
    ["@timestamp",     new Date(ev.ts).toISOString()],
    ...(ev.mitre_technique ? [["threat.technique.id", ev.mitre_technique]] as [string,string][] : []),
    ...(ev.user_email  ? [["user.email",           ev.user_email]]   as [string,string][] : []),
    ...(ev.hostname    ? [["host.name",             ev.hostname]]     as [string,string][] : []),
    ...(ev.src_ip      ? [["source.ip",             ev.src_ip]]       as [string,string][] : []),
    ...(ev.src_port    ? [["source.port",           String(ev.src_port)]] as [string,string][] : []),
    ...(ev.dst_ip      ? [["destination.ip",        ev.dst_ip]]       as [string,string][] : []),
    ...(ev.dst_port    ? [["destination.port",      String(ev.dst_port)]] as [string,string][] : []),
    ...(ev.protocol    ? [["network.protocol",      ev.protocol]]     as [string,string][] : []),
    ...(ev.process?.name        ? [["process.name",         ev.process.name]]         as [string,string][] : []),
    ...(ev.process?.pid         ? [["process.pid",          String(ev.process.pid)]]  as [string,string][] : []),
    ...(ev.process?.cmdline     ? [["process.command_line", ev.process.cmdline]]      as [string,string][] : []),
    ...(ev.process?.parent_name ? [["process.parent.name",  ev.process.parent_name]]  as [string,string][] : []),
    ...(ev.process?.user        ? [["user.name",            ev.process.user]]         as [string,string][] : []),
    ...(ev.process?.integrity   ? [["process.integrity",    ev.process.integrity]]    as [string,string][] : []),
    ...(ev.file?.path           ? [["file.path",            ev.file.path]]            as [string,string][] : []),
    ...(ev.file?.sha256         ? [["file.hash.sha256",     ev.file.sha256]]          as [string,string][] : []),
    ...(ev.file?.size           ? [["file.size",            `${ev.file.size} B`]]     as [string,string][] : []),
    ...(ev.network?.url         ? [["url.full",             ev.network.url]]          as [string,string][] : []),
    ...(ev.network?.domain      ? [["dns.question.name",    ev.network.domain]]       as [string,string][] : []),
    ...(ev.network?.method      ? [["http.request.method",  ev.network.method]]       as [string,string][] : []),
    ...(ev.network?.bytes_out   ? [["network.bytes_sent",   `${ev.network.bytes_out} B`]] as [string,string][] : []),
    ...(ev.network?.bytes_in    ? [["network.bytes_rcvd",   `${ev.network.bytes_in} B`]]  as [string,string][] : []),
    ...Object.entries(ev.raw ?? {})
      .filter(([, v]) => v !== null && v !== undefined && v !== "" && typeof v !== "object" && typeof v !== "boolean")
      .map(([k, v]) => [k, String(v)] as [string, string]),
    ...Object.entries(ev.raw ?? {})
      .filter(([, v]) => typeof v === "boolean")
      .map(([k, v]) => [k, v ? "true" : "false"] as [string, string]),
  ];

  const srcCls = SRC_CLS[ev.source] ?? "bg-slate-500/10 text-slate-400 border-slate-500/20";

  return (
    <div className={cn("rounded border transition", open ? "border-[#2a3555] bg-[#080c15]" : "border-transparent hover:border-[#1e2841]")}>
      {/* Summary row */}
      <button
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-start gap-2.5 px-2.5 py-2 text-left"
      >
        <ChevronRight className={cn("mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform", open && "rotate-90")} />
        <span className="font-mono text-[10px] text-slate-600 shrink-0 w-5 mt-0.5">{idx + 1}</span>
        <span className={cn("shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase mt-0.5", srcCls)}>
          {ev.source}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[11px] text-slate-300 leading-snug">{ev.description ?? ev.event_type.replace(/_/g, " ")}</p>
          {ev.mitre_technique && (
            <p className="mt-0.5 font-mono text-[10px] text-violet-400/70">{ev.mitre_technique}</p>
          )}
        </div>
        {ev.severity && ev.severity !== "informational" && (
          <span className={cn("shrink-0 text-[9px] font-bold uppercase mt-0.5", SEV_CLS[ev.severity] ?? "text-slate-500")}>
            {ev.severity}
          </span>
        )}
      </button>

      {/* Expanded field list */}
      {open && (
        <div className="border-t border-[#1e2841] px-3 pb-3 pt-2.5 space-y-2.5">
          {/* JSON toggle */}
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Log Fields</span>
            <button
              onClick={() => setShowJson(v => !v)}
              className={cn(
                "flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-semibold transition",
                showJson
                  ? "border-violet-500/40 bg-violet-500/10 text-violet-400"
                  : "border-[#2a3555] text-slate-500 hover:text-slate-300"
              )}
            >
              <Code2 className="h-3 w-3" /> Raw JSON
            </button>
          </div>

          {showJson ? (
            <pre className="max-h-56 overflow-auto rounded border border-[#2a3555] bg-[#060a10] p-2.5 font-mono text-[10px] leading-relaxed text-slate-300 whitespace-pre-wrap">
              {JSON.stringify(ev, null, 2)}
            </pre>
          ) : (
            <div className="space-y-1">
              {fields.map(([k, v]) => (
                <div key={k} className="flex gap-3 items-start">
                  <span className="w-52 shrink-0 font-mono text-[10px] text-slate-500">{k}</span>
                  <span className="font-mono text-[10px] text-slate-200 break-all">{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --------- Scenario drawer content ------------------------------------------------------------------------------------------------------------------------------------------------------

function ScenarioDrawerContent({ scenario, onClose }: { scenario: ScenarioRow; onClose: () => void }) {
  const [title, setTitle]     = useState(scenario.title);
  const [summary, setSummary] = useState(scenario.summary);
  const [diff, setDiff]       = useState(scenario.difficulty);
  const [status, setStatus]   = useState<ItemStatus>(scenario.status);
  const [saved, setSaved]     = useState(false);

  // Load live events --" built-in: from builder; generated: from stored events
  const bundle = useMemo(() => {
    if (scenario.isGenerated) return null;
    try { return buildScenarioBySlug(scenario.slug); } catch { return null; }
  }, [scenario.slug, scenario.isGenerated]);

  // Events to display --" prefer bundle for built-in, stored events for generated
  const displayEvents: TelemetryEvent[] = useMemo(() => {
    if (bundle) return bundle.events;
    return scenario.events ?? [];
  }, [bundle, scenario.events]);

  function save() {
    const edits = JSON.parse(localStorage.getItem("admin_scenario_edits")??"{}");
    edits[scenario.slug] = { title, summary, difficulty: diff, status };
    localStorage.setItem("admin_scenario_edits", JSON.stringify(edits));
    const sm = JSON.parse(localStorage.getItem("admin_scenario_status")??"{}");
    sm[scenario.slug] = status;
    localStorage.setItem("admin_scenario_status", JSON.stringify(sm));
    setSaved(true); setTimeout(onClose, 800);
  }

  return (
    <>
      <Field label="Title" required><input value={title} onChange={e=>setTitle(e.target.value)} className={fieldCls} /></Field>
      <Field label="Summary / Narrative">
        <textarea value={summary} onChange={e=>setSummary(e.target.value)} rows={3} className={cn(fieldCls,"resize-none")} />
      </Field>
      <div className="grid grid-cols-2 gap-4">
        <Field label="Difficulty">
          <select value={diff} onChange={e=>setDiff(e.target.value)} className={fieldCls}>
            {["beginner","intermediate","advanced","expert"].map(d=><option key={d} value={d}>{d}</option>)}
          </select>
        </Field>
        <Field label="Status">
          <select value={status} onChange={e=>setStatus(e.target.value as ItemStatus)} className={fieldCls}>
            <option value="published">Published</option><option value="draft">Draft</option>
          </select>
        </Field>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded border border-[#2a3555] bg-[#0a0e1a] px-3 py-2.5 text-center">
          <p className="font-mono text-xl font-bold text-white">{displayEvents.length}</p>
          <p className="text-[10px] text-slate-500 mt-0.5">Log Events</p>
        </div>
        <div className="rounded border border-[#2a3555] bg-[#0a0e1a] px-3 py-2.5 text-center">
          <p className="font-mono text-xl font-bold text-white">{bundle?.questions.length ?? "--"}</p>
          <p className="text-[10px] text-slate-500 mt-0.5">Questions</p>
        </div>
        <div className="rounded border border-[#2a3555] bg-[#0a0e1a] px-3 py-2.5 text-center">
          <p className="font-mono text-xl font-bold text-white">{bundle?.iocs.length ?? "--"}</p>
          <p className="text-[10px] text-slate-500 mt-0.5">IOCs</p>
        </div>
      </div>

      {/* Log Events --" expandable field view */}
      {displayEvents.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Log Events ({displayEvents.length})
              <span className="ml-2 text-[10px] normal-case text-slate-600 font-normal">click any row to see all fields</span>
            </label>
            {!scenario.isGenerated && (
              <a
                href={`/scenarios/${scenario.slug}`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 text-[10px] text-violet-400 hover:text-violet-300 transition"
              >
                <ExternalLink className="h-3 w-3" /> View live scenario
              </a>
            )}
          </div>
          <div className="rounded border border-[#2a3555] bg-[#080c15] p-1.5 space-y-0.5">
            {displayEvents.map((ev, i) => (
              <AdminEventRow key={ev.id ?? i} ev={ev} idx={i} />
            ))}
          </div>
        </div>
      )}
      {displayEvents.length === 0 && scenario.isGenerated && (
        <div className="rounded border border-dashed border-[#2a3555] py-6 text-center text-[11px] text-slate-600">
          Log events not available --" this scenario was published before event storage was added.
        </div>
      )}

      {/* IOCs */}
      {bundle && bundle.iocs.length > 0 && (
        <div>
          <label className="mb-2 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            IOCs ({bundle.iocs.length})
          </label>
          <div className="rounded border border-[#2a3555] bg-[#080c15] p-2 space-y-1.5">
            {bundle.iocs.map((ioc, ii) => (
              <div key={`${ioc.value}-${ii}`} className="flex items-center gap-2.5 rounded border border-[#1e2841] px-2.5 py-1.5">
                <span className={cn("shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase",
                  ioc.type==="ip"?"bg-blue-500/10 text-blue-400 border-blue-500/20":
                  ioc.type==="domain"?"bg-violet-500/10 text-violet-400 border-violet-500/20":
                  ioc.type==="sha256"?"bg-orange-500/10 text-orange-400 border-orange-500/20":
                  ioc.type==="email"?"bg-cyan-500/10 text-cyan-400 border-cyan-500/20":
                  "bg-slate-500/10 text-slate-400 border-slate-500/20"
                )}>{ioc.type}</span>
                <span className="flex-1 truncate font-mono text-[11px] text-slate-200">{ioc.value}</span>
                {ioc.reputation && (
                  <span className={cn("shrink-0 text-[9px] font-bold uppercase",
                    ioc.reputation==="malicious"?"text-rose-400":
                    ioc.reputation==="suspicious"?"text-amber-400":
                    ioc.reputation==="clean"?"text-emerald-400":"text-slate-500"
                  )}>{ioc.reputation}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-3 pt-2 border-t border-[#2a3555]">
        <button onClick={save} className="flex-1 flex items-center justify-center gap-2 rounded bg-teal-600 hover:bg-teal-500 py-2.5 text-sm font-semibold text-white transition">
          {saved?<><Check className="h-4 w-4"/>Saved!</>:<><Save className="h-4 w-4"/>Save Changes</>}
        </button>
        <button onClick={onClose} className="flex items-center justify-center gap-2 rounded border border-[#2a3555] px-5 py-2.5 text-sm text-slate-300 hover:border-slate-500 transition">Cancel</button>
      </div>
    </>
  );
}

// -------------------------------------------------------------------------------
// QUIZZES TAB
// -------------------------------------------------------------------------------

type AnyQuiz = (Quiz | GeneratedQuiz) & { id?: string };

function QuizzesTab() {
  const [search, setSearch]   = useState("");
  const [levelF, setLevelF]   = useState("");
  const [catF,   setCatF]     = useState("");
  const [statusF, setStatusF] = useState("");
  const [hidden,  setHidden]  = useState<string[]>([]);
  const [statusMap, setStatusMap] = useState<Record<string,ItemStatus>>({});
  const [genQuizzes, setGenQuizzes] = useState<GeneratedQuiz[]>([]);
  const [drawer, setDrawer]   = useState<AnyQuiz|null>(null);
  const [showGen, setShowGen] = useState(false);
  const [form, setForm] = useState<{title:string;topic:string;difficulty:"Beginner"|"Intermediate"|"Advanced";count:number;focus:string}>({title:"",topic:"Incident Response",difficulty:"Intermediate",count:8,focus:""});
  const [loading, setLoading]   = useState(false);
  const [genError, setGenError] = useState<string|null>(null);
  const [preview, setPreview]   = useState<GeneratedQuiz|null>(null);
  const [pubIds, setPubIds]     = useState<Set<string>>(new Set());

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_quizzes")??"[]"));
      setStatusMap(JSON.parse(localStorage.getItem("admin_quiz_status")??"{}"));
      setGenQuizzes(JSON.parse(localStorage.getItem("generated_quizzes")??"[]"));
    } catch {}
  }, []);

  const builtIn: AnyQuiz[] = QUIZZES.filter(q=>!hidden.includes(q.slug));
  const all: AnyQuiz[] = [...genQuizzes, ...builtIn];

  const filtered = all.filter(q => {
    if (search && !q.title.toLowerCase().includes(search.toLowerCase())) return false;
    if (levelF && q.difficulty.toLowerCase() !== levelF) return false;
    if (catF && !q.category.toLowerCase().includes(catF)) return false;
    const qStatus = statusMap[(q as GeneratedQuiz).id??(q as Quiz).slug] ?? "published";
    if (statusF && qStatus !== statusF) return false;
    return true;
  });

  function setStatus(id: string, s: ItemStatus) {
    const next={...statusMap,[id]:s}; setStatusMap(next);
    localStorage.setItem("admin_quiz_status",JSON.stringify(next));
  }

  function hideQuiz(slug: string) {
    const next=[...hidden,slug]; setHidden(next);
    localStorage.setItem("admin_hidden_quizzes",JSON.stringify(next));
  }

  function deleteGenerated(id: string) {
    const next=genQuizzes.filter(q=>q.id!==id); setGenQuizzes(next);
    localStorage.setItem("generated_quizzes",JSON.stringify(next));
  }

  function randomizeTopic() {
    const t = TOPICS[Math.floor(Math.random() * TOPICS.length)];
    setForm(f => ({ ...f, topic: t, title: "" }));
  }

  async function generate() {
    setLoading(true);setGenError(null);setPreview(null);
    const payload = { ...form, title: form.title.trim() || `${form.topic} --" ${form.difficulty}` };
    try {
      const res=await fetch("/api/quizzes/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
      const data=await res.json();
      if(!res.ok||data.error) throw new Error(data.error??"Failed");
      setPreview(data);
    } catch(e){setGenError(e instanceof Error?e.message:"Error");}
    finally{setLoading(false);}
  }

  function publish(q: GeneratedQuiz) {
    const next=[q,...genQuizzes]; setGenQuizzes(next);
    localStorage.setItem("generated_quizzes",JSON.stringify(next));
    setPubIds(p=>new Set([...p,q.id]));
    setPreview(null); setShowGen(false);
  }

  const levels = [...new Set(all.map(q=>q.difficulty))];
  const categories = [...new Set(all.map(q=>q.category))];

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2841] shrink-0">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <HelpCircle className="h-4 w-4 text-amber-400"/>Quiz Management
          </h2>
          <p className="text-[11px] text-slate-500 mt-0.5">{filtered.length} quizzes · {filtered.filter(q=>( statusMap[(q as GeneratedQuiz).id??(q as Quiz).slug]??"published")==="published").length} published</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 rounded border border-[#2a3555] bg-transparent px-4 py-2 text-sm text-slate-300 hover:border-slate-400 transition">
            <Download className="h-3.5 w-3.5"/> Export ({filtered.length})
          </button>
          <button onClick={()=>setShowGen(v=>!v)} className="flex items-center gap-2 rounded bg-violet-600 hover:bg-violet-500 px-4 py-2 text-sm font-semibold text-white transition">
            <Sparkles className="h-3.5 w-3.5"/> Generate with AI
          </button>
          <button className="flex items-center gap-2 rounded bg-teal-600 hover:bg-teal-500 px-4 py-2 text-sm font-semibold text-white transition">
            <Plus className="h-3.5 w-3.5"/> Create Quiz
          </button>
        </div>
      </div>

      {/* Generator */}
      {showGen && (
        <div className="shrink-0 border-b border-[#1e2841] bg-[#0a0e1a] px-6 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Form */}
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2 flex gap-2">
              <div className="flex-1">
                <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Quiz Title <span className="normal-case text-slate-600">(optional --" auto-generated if blank)</span></label>
                <input value={form.title} onChange={e=>setForm(f=>({...f,title:e.target.value}))} placeholder="e.g. Advanced Threat Hunting" className={fieldCls} />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-[10px] uppercase tracking-wider text-slate-500">Topic</label>
                <button onClick={randomizeTopic} className="flex items-center gap-1 text-[10px] text-violet-400 hover:text-violet-300 transition">
                  <RotateCcw className="h-3 w-3"/>Random
                </button>
              </div>
              <select value={form.topic} onChange={e=>setForm(f=>({...f,topic:e.target.value}))} className={fieldCls}>
                {TOPICS.map(t=><option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Difficulty</label>
              <select value={form.difficulty} onChange={e=>setForm(f=>({...f,difficulty:e.target.value as typeof form.difficulty}))} className={fieldCls}>
                <option>Beginner</option><option>Intermediate</option><option>Advanced</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Focus Areas <span className="normal-case text-slate-600">(optional)</span></label>
              <input value={form.focus} onChange={e=>setForm(f=>({...f,focus:e.target.value}))} placeholder="e.g. Kerberoasting, DCSync, Pass-the-Hash" className={fieldCls} />
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Number of Questions</label>
              <select value={form.count} onChange={e=>setForm(f=>({...f,count:Number(e.target.value)}))} className={fieldCls}>
                {[5,6,7,8,10,12,15].map(n=><option key={n}>{n}</option>)}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button onClick={generate} disabled={loading} className="flex items-center gap-2 rounded bg-violet-600 hover:bg-violet-500 disabled:opacity-50 px-5 py-2.5 text-sm font-semibold text-white transition">
              {loading?<><Loader2 className="h-3.5 w-3.5 animate-spin"/>Generating--¦</>:<><Sparkles className="h-3.5 w-3.5"/>Generate Quiz</>}
            </button>
            <button onClick={()=>{setShowGen(false);setPreview(null);}} className="rounded p-2.5 text-slate-500 hover:bg-[#1a2035] transition"><X className="h-4 w-4"/></button>
          </div>

          {genError && <p className="text-xs text-rose-400 flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5"/>{genError}</p>}

          {/* Preview --" show full question list */}
          {preview && (
            <div className="rounded border border-violet-500/20 bg-violet-500/5 space-y-4 p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="rounded border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[10px] font-bold uppercase text-violet-400">AI Generated</span>
                    <DiffBadge d={preview.difficulty} />
                  </div>
                  <p className="text-base font-bold text-white">{preview.title}</p>
                  <p className="text-[11px] text-slate-400 mt-0.5">{preview.questions.length} questions · {preview.category} · ~{preview.estimatedMinutes} min</p>
                </div>
                <button onClick={()=>publish(preview)} disabled={pubIds.has(preview.id)} className="shrink-0 flex items-center gap-2 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 px-4 py-2.5 text-sm font-semibold text-white transition">
                  {pubIds.has(preview.id)?<><Check className="h-3.5 w-3.5"/>Published!</>:<><Plus className="h-3.5 w-3.5"/>Publish</>}
                </button>
              </div>

              {/* Question list preview */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                  Questions ({preview.questions.length}) --" review before publishing
                </p>
                <div className="space-y-2">
                  {preview.questions.map((q, i) => (
                    <div key={q.id} className="rounded border border-[#2a3555] bg-[#080c15] px-3 py-2.5">
                      <div className="flex items-start gap-2">
                        <span className="font-mono text-[10px] text-slate-600 shrink-0 mt-0.5">{i+1}.</span>
                        <div className="min-w-0 flex-1">
                          <p className="text-[11px] text-slate-200 leading-snug">{q.question}</p>
                          <p className="mt-1 text-[10px] text-emerald-400">
                            ג" {typeof q.answer === "number" ? q.options[q.answer] : (Array.isArray(q.answer) ? (q.answer as string[]).join(", ") : String(q.answer))}
                          </p>
                          {q.explanation && (
                            <p className="mt-0.5 text-[10px] text-slate-500 italic">{q.explanation}</p>
                          )}
                        </div>
                        <span className="shrink-0 rounded border border-violet-500/20 bg-violet-500/5 px-1.5 py-0.5 font-mono text-[10px] text-violet-400">+{q.xp} XP</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filter bar */}
      <div className="px-6 py-3 border-b border-[#1e2841] shrink-0">
        <FilterBar search={search} onSearch={setSearch} filters={{ levels, categories }}
          onFilter={(k,v)=>{if(k==="level")setLevelF(v);else if(k==="category")setCatF(v);else setStatusF(v);}} />
      </div>

      {/* Table header */}
      <div className="grid grid-cols-[2.5fr_1.5fr_1fr_80px_140px_80px] gap-2 border-b border-[#1e2841] bg-[#0a0e1a] px-6 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 shrink-0">
        <span>Title</span><span>Category</span><span>Difficulty</span><span>Questions</span><span>Status</span><span className="text-right">Actions</span>
      </div>

      {/* Rows */}
      <div className="flex-1 overflow-y-auto">
        {filtered.map(quiz => {
          const qId = (quiz as GeneratedQuiz).id ?? (quiz as Quiz).slug;
          const isGen = !!((quiz as GeneratedQuiz).id);
          const qStatus = statusMap[qId] ?? "published";
          return (
            <div key={qId} className="grid grid-cols-[2.5fr_1.5fr_1fr_80px_140px_80px] gap-2 border-b border-[#1e2841] px-6 py-3.5 items-center hover:bg-[#0f1728] transition">
              <div className="min-w-0 cursor-pointer" onClick={()=>setDrawer(quiz)}>
                <div className="flex items-center gap-2">
                  <span className="text-lg leading-none">{quiz.icon}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-white truncate hover:text-violet-300 transition">{quiz.title}</p>
                    <p className="text-[11px] text-slate-500 truncate mt-0.5">{quiz.description?.slice(0,55)}{(quiz.description?.length??0)>55?"--¦":""}</p>
                  </div>
                </div>
                {isGen && <span className="ml-8 inline-block mt-1 rounded border border-violet-500/25 bg-violet-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase text-violet-400">AI Generated</span>}
              </div>
              <CategoryBadge label={quiz.category} />
              <DiffBadge d={quiz.difficulty} />
              <span className="font-mono text-sm text-slate-300">{quiz.questions.length}</span>
              <StatusDropdown status={qStatus as ItemStatus} onChange={v=>setStatus(qId,v)} />
              <div className="flex items-center justify-end gap-1">
                <button onClick={()=>setDrawer(quiz)} className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-violet-400 transition"><Eye className="h-3.5 w-3.5"/></button>
                <button onClick={()=>setDrawer(quiz)} className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-violet-400 transition"><Edit2 className="h-3.5 w-3.5"/></button>
                <button onClick={()=>isGen?deleteGenerated((quiz as GeneratedQuiz).id):hideQuiz((quiz as Quiz).slug)} className="rounded p-1.5 text-slate-600 hover:bg-rose-500/10 hover:text-rose-400 transition"><Trash2 className="h-3.5 w-3.5"/></button>
              </div>
            </div>
          );
        })}
        <p className="px-6 py-3 text-[11px] text-slate-600">Showing {filtered.length} of {all.length} quizzes · Published: {all.filter(q=>(statusMap[(q as GeneratedQuiz).id??(q as Quiz).slug]??"published")==="published").length} · Draft: {all.filter(q=>(statusMap[(q as GeneratedQuiz).id??(q as Quiz).slug]??"published")==="draft").length}</p>
      </div>

      {/* Quiz edit drawer */}
      <Drawer open={!!drawer} onClose={()=>setDrawer(null)} title={drawer ? `Edit: ${drawer.title}` : "Edit Quiz"}>
        {drawer && <QuizDrawerContent key={(drawer as GeneratedQuiz).id??(drawer as Quiz).slug} quiz={drawer} genQuizzes={genQuizzes} setGenQuizzes={setGenQuizzes} onClose={()=>setDrawer(null)} />}
      </Drawer>
    </div>
  );
}

function QuizDrawerContent({ quiz, genQuizzes, setGenQuizzes, onClose }: {
  quiz: AnyQuiz; genQuizzes: GeneratedQuiz[];
  setGenQuizzes: (q: GeneratedQuiz[]) => void; onClose: () => void;
}) {
  const isGen = !!((quiz as GeneratedQuiz).id);
  const [title, setTitle] = useState(quiz.title);
  const [desc, setDesc]   = useState(quiz.description);
  const [questions, setQuestions] = useState<QuizQuestion[]>(() => {
    if (isGen) return quiz.questions;
    const edits = JSON.parse(localStorage.getItem("admin_quiz_edits")??"{}");
    return edits[(quiz as Quiz).slug]?.questions ?? quiz.questions;
  });
  const [editingQid, setEditingQid] = useState<string|null>(null);
  const [qDraft, setQDraft] = useState<QuizQuestion|null>(null);
  const [saved, setSaved] = useState(false);

  function saveAll() {
    if (isGen) {
      const next = genQuizzes.map(gq => gq.id===(quiz as GeneratedQuiz).id ? {...gq,title,description:desc,questions} : gq);
      setGenQuizzes(next); localStorage.setItem("generated_quizzes",JSON.stringify(next));
    } else {
      const edits = JSON.parse(localStorage.getItem("admin_quiz_edits")??"{}");
      edits[(quiz as Quiz).slug] = { title, description: desc, questions };
      localStorage.setItem("admin_quiz_edits", JSON.stringify(edits));
    }
    setSaved(true); setTimeout(onClose, 800);
  }

  function saveQ() {
    if (!qDraft) return;
    setQuestions(prev => prev.map(q => q.id===qDraft.id ? qDraft : q));
    setEditingQid(null); setQDraft(null);
  }

  return (
    <>
      <Field label="Quiz Title" required><input value={title} onChange={e=>setTitle(e.target.value)} className={fieldCls} /></Field>
      <Field label="Description"><textarea value={desc} onChange={e=>setDesc(e.target.value)} rows={2} className={cn(fieldCls,"resize-none")} /></Field>

      <Field label={`Questions (${questions.length})`}>
        <div className="space-y-2">
          {questions.map((q, qi) => (
            <div key={q.id} className="rounded border border-[#2a3555] bg-[#0a0e1a] overflow-hidden">
              {editingQid===q.id && qDraft ? (
                <div className="p-4 space-y-3">
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1">Q{qi+1}</label>
                    <textarea value={qDraft.question} onChange={e=>setQDraft(f=>f?{...f,question:e.target.value}:f)} rows={2} className={cn(fieldCls,"resize-none")} />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {qDraft.options.map((opt,oi)=>(
                      <div key={oi}>
                        <label className={cn("block text-[10px] uppercase tracking-wider mb-1", oi===qDraft.answer?"text-emerald-400":"text-slate-500")}>
                          Option {String.fromCharCode(65+oi)}{oi===qDraft.answer?" ✓ correct":""}
                        </label>
                        <input value={opt} onChange={e=>{const o=[...qDraft.options];o[oi]=e.target.value;setQDraft(f=>f?{...f,options:o}:f);}} className={fieldCls} />
                      </div>
                    ))}
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1">Correct Answer</label>
                      <select value={qDraft.answer} onChange={e=>setQDraft(f=>f?{...f,answer:Number(e.target.value)}:f)} className={fieldCls}>
                        {qDraft.options.map((_,oi)=><option key={oi} value={oi}>Option {String.fromCharCode(65+oi)}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1">XP</label>
                      <input type="number" value={qDraft.xp} onChange={e=>setQDraft(f=>f?{...f,xp:Number(e.target.value)}:f)} className={fieldCls} />
                    </div>
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider text-slate-500 mb-1">Explanation</label>
                    <textarea value={qDraft.explanation} onChange={e=>setQDraft(f=>f?{...f,explanation:e.target.value}:f)} rows={2} className={cn(fieldCls,"resize-none")} />
                  </div>
                  <div className="flex gap-2">
                    <button onClick={saveQ} className="flex items-center gap-1.5 rounded bg-teal-600 hover:bg-teal-500 px-3 py-1.5 text-xs text-white transition"><Save className="h-3.5 w-3.5"/>Save</button>
                    <button onClick={()=>{setEditingQid(null);setQDraft(null);}} className="flex items-center gap-1.5 rounded border border-[#2a3555] px-3 py-1.5 text-xs text-slate-400 hover:text-white transition"><X className="h-3.5 w-3.5"/>Cancel</button>
                  </div>
                </div>
              ) : (
                <div className="flex items-start gap-3 px-4 py-2.5">
                  <span className="font-mono text-[10px] text-slate-500 shrink-0 w-5 mt-0.5">Q{qi+1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] text-slate-200 leading-snug">{q.question}</p>
                    <p className="text-[11px] text-emerald-400/80 mt-0.5">ג" {q.options[q.answer]}</p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 mt-0.5">
                    <button onClick={()=>{setEditingQid(q.id);setQDraft({...q,options:[...q.options]});}} className="rounded p-1 text-slate-500 hover:bg-[#1a2035] hover:text-violet-400 transition"><Edit2 className="h-3 w-3"/></button>
                    <button onClick={()=>setQuestions(prev=>prev.filter(pq=>pq.id!==q.id))} className="rounded p-1 text-slate-600 hover:bg-rose-500/10 hover:text-rose-400 transition"><Trash2 className="h-3 w-3"/></button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Field>

      <div className="flex gap-3 pt-2 border-t border-[#2a3555]">
        <button onClick={saveAll} className="flex-1 flex items-center justify-center gap-2 rounded bg-teal-600 hover:bg-teal-500 py-2.5 text-sm font-semibold text-white transition">
          {saved?<><Check className="h-4 w-4"/>Saved!</>:<><Save className="h-4 w-4"/>Save All Changes</>}
        </button>
        <button onClick={onClose} className="flex items-center justify-center gap-2 rounded border border-[#2a3555] px-5 py-2.5 text-sm text-slate-300 hover:border-slate-500 transition">Cancel</button>
      </div>
    </>
  );
}

// -------------------------------------------------------------------------------
// LESSONS TAB
// -------------------------------------------------------------------------------

// Syllabus-generated lesson (mirrors /api/lessons/generate/route.ts)
interface SyllabusLesson {
  id:               string;
  slug:             string;
  title:            string;
  topic:            string;
  difficulty:       string;
  kind?:            "lesson";
  intro:            string;
  sections:         { heading: string; content: string; codeExample?: string }[];
  keyTakeaways:     string[];
  quiz?:            { question: string; options: { label: string; value: string }[]; answer: string; explanation: string }[];
  references?:      string[];
  xp:               number;
  estimatedMinutes: number;
  published_at:     string;
  createdAt?:       string;
  researchUsed?:    boolean;
  // legacy fields kept for backwards compat
  pathSlug?:        string;
  moduleSlug?:      string;
}

// --------- Generator phases ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const TOTAL_SECTIONS = 8;

const DIFF_OPTIONS = ["beginner", "intermediate", "advanced", "expert"] as const;

// ── Bulk generation types ──────────────────────────────────────────────────────

interface BulkValidation {
  score: number;
  recommendation: "publish" | "review" | "regenerate";
  issues: string[];
  strengths: string[];
}

interface BulkItem {
  topic:       string;
  difficulty:  string;
  status:      "pending" | "generating" | "validating" | "done" | "error";
  lesson?:     SyllabusLesson;
  validation?: BulkValidation;
  error?:      string;
  sections?:   number; // live section progress count during generation
  outlineTitle?: string;
}

function parseSyllabus(text: string, defaultDiff: string): BulkItem[] {
  return text
    .split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"))
    .slice(0, 20)
    .map(l => {
      const [rawTopic, rawDiff] = l.split("|").map(s => s.trim());
      const diff = (DIFF_OPTIONS as readonly string[]).includes(rawDiff ?? "") ? rawDiff : defaultDiff;
      return {
        topic: rawTopic,
        difficulty: diff,
        status: "pending" as const,
      };
    });
}

function LessonsTab() {
  // Library state
  const [lessons,    setLessons]    = useState<SyllabusLesson[]>([]);
  const [search,     setSearch]     = useState("");
  const [diffFilter, setDiffFilter] = useState("all");

  // Generator panel state
  const [showGen,    setShowGen]    = useState(false);
  const [genTopic,   setGenTopic]   = useState("");
  const [genDiff,    setGenDiff]    = useState<typeof DIFF_OPTIONS[number]>("intermediate");
  const [genCtx,     setGenCtx]     = useState("");
  const [genLoading, setGenLoading] = useState(false);
  const [genStatus,  setGenStatus]  = useState("");
  const [genOutlineTitle, setGenOutlineTitle] = useState("");
  const [genPartialSections, setGenPartialSections] = useState<{ heading: string; content: string; codeExample?: string }[]>([]);
  const [genError,   setGenError]   = useState<string|null>(null);

  // Bulk generation state
  const [showBulk,     setShowBulk]     = useState(false);
  const [bulkSyllabus, setBulkSyllabus] = useState("");
  const [bulkDiff,     setBulkDiff]     = useState<typeof DIFF_OPTIONS[number]>("intermediate");
  const [bulkQueue,    setBulkQueue]    = useState<BulkItem[]>([]);
  const [bulkRunning,  setBulkRunning]  = useState(false);
  const [bulkDone,     setBulkDone]     = useState(false);
  const [bulkExpanded, setBulkExpanded] = useState<number|null>(null);
  const bulkRunningRef = useRef(false);

  // Preview modal
  const [preview, setPreview] = useState<SyllabusLesson|null>(null);
  // Editor modal
  const [editLesson, setEditLesson] = useState<SyllabusLesson|null>(null);

  useEffect(() => {
    try {
      const saved: SyllabusLesson[] = JSON.parse(localStorage.getItem("generated_lessons")  ?? "[]");
      const deleted: string[]       = JSON.parse(localStorage.getItem("deleted_lesson_ids") ?? "[]");
      const deletedSet = new Set(deleted);
      const savedIds   = new Set(saved.map(l => l.id));
      const builtins   = (BUILTIN_LESSONS as unknown as SyllabusLesson[])
        .filter(l => !savedIds.has(l.id) && !deletedSet.has(l.id));
      setLessons([...saved, ...builtins]);
    } catch {
      setLessons(BUILTIN_LESSONS as unknown as SyllabusLesson[]);
    }
  }, []);

  function persist(next: SyllabusLesson[]) {
    const builtinIds = new Set(BUILTIN_LESSONS.map(l => l.id));
    // Save only user-generated lessons (never persist builtins)
    const userLessons = next.filter(l => !builtinIds.has(l.id as typeof BUILTIN_LESSONS[number]["id"]));
    localStorage.setItem("generated_lessons", JSON.stringify(userLessons));
    setLessons(next);
  }

  function deleteLesson(id: string) {
    const builtinIds = new Set(BUILTIN_LESSONS.map(l => l.id));
    // If deleting a builtin, record its ID so learn page can hide it too
    if (builtinIds.has(id as typeof BUILTIN_LESSONS[number]["id"])) {
      const deleted: string[] = JSON.parse(localStorage.getItem("deleted_lesson_ids") ?? "[]");
      if (!deleted.includes(id)) {
        localStorage.setItem("deleted_lesson_ids", JSON.stringify([...deleted, id]));
      }
    }
    persist(lessons.filter(l => l.id !== id));
  }

  const filtered = lessons.filter(l => {
    if (search && !l.title.toLowerCase().includes(search.toLowerCase()) &&
        !l.topic.toLowerCase().includes(search.toLowerCase())) return false;
    if (diffFilter !== "all" && l.difficulty !== diffFilter) return false;
    return true;
  });

  async function handleGenerate() {
    if (!genTopic.trim()) return;
    setGenLoading(true);
    setGenError(null);
    setGenStatus("🔍 Initialising...");
    setGenOutlineTitle("");
    setGenPartialSections([]);

    try {
      const res = await fetch("/api/lessons/generate-stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          topic: genTopic,
          difficulty: genDiff,
          kind: "lesson",
          syllabus: genCtx,
          sections: TOTAL_SECTIONS,
        }),
      });

      if (!res.ok || !res.body) throw new Error("Stream request failed");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let finalLesson: SyllabusLesson | null = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;

          // Parse JSON separately so malformed lines are skipped
          // but valid server errors propagate to the outer catch
          type SSEEvent = {
            type: string;
            message?: string;
            data?: { title?: string; sectionHeadings?: string[] };
            index?: number;
            section?: { heading: string; content: string; codeExample?: string };
            lesson?: SyllabusLesson;
          };
          let event: SSEEvent;
          try {
            event = JSON.parse(line.slice(6)) as SSEEvent;
          } catch {
            continue; // Truly malformed JSON — skip silently
          }

          // Handle events OUTSIDE try-catch so server errors propagate correctly
          if (event.type === "phase" && event.message) {
            setGenStatus(event.message);
          }
          if (event.type === "outline" && event.data?.title) {
            setGenOutlineTitle(event.data.title);
          }
          if (event.type === "section_done" && event.section) {
            setGenPartialSections(prev => [...prev, event.section!]);
          }
          if (event.type === "done" && event.lesson) {
            finalLesson = { ...event.lesson, kind: "lesson", createdAt: new Date().toISOString() };
          }
          if (event.type === "error") {
            // Propagates to the outer catch — shows the real server error
            throw new Error(event.message ?? "Generation failed on server");
          }
        }
      }

      if (!finalLesson) {
        // Stream ended without a lesson — fall back to the regular (non-streaming) endpoint
        setGenStatus("Falling back to standard generation...");
        const fallback = await fetch("/api/lessons/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ topic: genTopic, difficulty: genDiff, kind: "lesson", syllabus: genCtx, sections: 5 }),
        });
        const fallbackData = await fallback.json();
        if (!fallbackData?.title) throw new Error("Generation failed — please try again");
        finalLesson = { ...fallbackData, kind: "lesson", createdAt: new Date().toISOString() };
      }

      if (!finalLesson) throw new Error("Generation failed — please try again");
      const next = [finalLesson, ...lessons];
      persist(next);
      setShowGen(false);
      setGenTopic("");
      setGenCtx("");
      setGenPartialSections([]);
      setGenStatus("");
      setGenOutlineTitle("");
      setPreview(finalLesson);
    } catch (e) {
      setGenError(e instanceof Error ? e.message : "Error generating lesson");
    } finally {
      setGenLoading(false);
    }
  }

  // ── Bulk helpers ────────────────────────────────────────────────────────────

  /** Stream-generate a single lesson; calls onSection for live progress updates */
  async function generateLessonStreaming(
    topic: string,
    difficulty: string,
    onSection: (s: { heading: string; content: string; codeExample?: string }, idx: number) => void,
    onTitle: (title: string) => void,
  ): Promise<SyllabusLesson> {
    const res = await fetch("/api/lessons/generate-stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ topic, difficulty, kind: "lesson", sections: TOTAL_SECTIONS }),
    });
    if (!res.ok || !res.body) throw new Error("Stream request failed");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let finalLesson: SyllabusLesson | null = null;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        type SSEEvent = {
          type: string; message?: string;
          data?: { title?: string; sectionHeadings?: string[] };
          index?: number;
          section?: { heading: string; content: string; codeExample?: string };
          lesson?: SyllabusLesson;
        };
        let event: SSEEvent;
        try { event = JSON.parse(line.slice(6)) as SSEEvent; } catch { continue; }

        if (event.type === "outline" && event.data?.title) onTitle(event.data.title);
        if (event.type === "section_done" && event.section != null) {
          onSection(event.section, event.index ?? 0);
        }
        if (event.type === "done" && event.lesson) {
          finalLesson = { ...event.lesson, kind: "lesson", createdAt: new Date().toISOString() };
        }
        if (event.type === "error") throw new Error(event.message ?? "Generation failed on server");
      }
    }

    if (!finalLesson) {
      // Fallback
      const fallback = await fetch("/api/lessons/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ topic, difficulty, kind: "lesson", sections: 5 }),
      });
      const data = await fallback.json();
      if (!data?.title) throw new Error("Generation failed — please try again");
      finalLesson = { ...data, kind: "lesson", createdAt: new Date().toISOString() };
    }

    return finalLesson!;
  }

  async function runBulkGeneration(items: BulkItem[], currentLessons: SyllabusLesson[]) {
    bulkRunningRef.current = true;
    setBulkRunning(true);
    setBulkDone(false);

    // Work with a local mutable copy of the queue — reflects live state
    const queue: BulkItem[] = items.map(it => ({ ...it, status: "pending" as const }));
    setBulkQueue([...queue]);

    // Track lessons added so far for correct ordering
    let runningLessons = [...currentLessons];

    for (let i = 0; i < queue.length; i++) {
      if (!bulkRunningRef.current) break; // cancelled

      // Mark generating
      queue[i] = { ...queue[i], status: "generating", sections: 0 };
      setBulkQueue([...queue]);

      try {
        const lesson = await generateLessonStreaming(
          queue[i].topic,
          queue[i].difficulty,
          (_section, _idx) => {
            // Update live section count
            queue[i] = { ...queue[i], sections: (_idx + 1) };
            setBulkQueue([...queue]);
          },
          (title) => {
            queue[i] = { ...queue[i], outlineTitle: title };
            setBulkQueue([...queue]);
          },
        );

        // Persist immediately so the grid updates
        runningLessons = [lesson, ...runningLessons];
        persist(runningLessons);

        // Mark validating
        queue[i] = { ...queue[i], status: "validating", lesson };
        setBulkQueue([...queue]);

        // Call validation agent
        let validation: BulkValidation | undefined;
        try {
          const vRes = await fetch("/api/lessons/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ lesson }),
          });
          if (vRes.ok) validation = await vRes.json() as BulkValidation;
        } catch {
          // Validation failure is non-fatal
        }

        queue[i] = { ...queue[i], status: "done", validation };
        setBulkQueue([...queue]);

      } catch (e) {
        queue[i] = {
          ...queue[i],
          status: "error",
          error: e instanceof Error ? e.message : "Failed",
        };
        setBulkQueue([...queue]);
      }
    }

    bulkRunningRef.current = false;
    setBulkRunning(false);
    setBulkDone(true);
  }

  async function rerunBulkItem(idx: number) {
    const item = bulkQueue[idx];
    if (!item || bulkRunning) return;

    setBulkRunning(true);
    bulkRunningRef.current = true;
    const queue = [...bulkQueue];
    queue[idx] = { ...item, status: "generating", sections: 0, lesson: undefined, validation: undefined, error: undefined };
    setBulkQueue(queue);

    try {
      const lesson = await generateLessonStreaming(
        item.topic, item.difficulty,
        (_s, _i) => { queue[idx] = { ...queue[idx], sections: (_i + 1) }; setBulkQueue([...queue]); },
        (title)  => { queue[idx] = { ...queue[idx], outlineTitle: title }; setBulkQueue([...queue]); },
      );

      // If a previous version existed, replace it in lessons; otherwise prepend
      const existing = lessons.find(l => l.id === item.lesson?.id);
      const updated = existing
        ? lessons.map(l => l.id === item.lesson?.id ? lesson : l)
        : [lesson, ...lessons];
      persist(updated);

      queue[idx] = { ...queue[idx], status: "validating", lesson };
      setBulkQueue([...queue]);

      let validation: BulkValidation | undefined;
      try {
        const vRes = await fetch("/api/lessons/validate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ lesson }),
        });
        if (vRes.ok) validation = await vRes.json() as BulkValidation;
      } catch { /* non-fatal */ }

      queue[idx] = { ...queue[idx], status: "done", validation };
      setBulkQueue([...queue]);
    } catch (e) {
      queue[idx] = { ...queue[idx], status: "error", error: e instanceof Error ? e.message : "Failed" };
      setBulkQueue([...queue]);
    } finally {
      bulkRunningRef.current = false;
      setBulkRunning(false);
    }
  }

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden relative">

      {/* ------ Header ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2841] shrink-0">
        <div className="flex items-center gap-1">
          <span className="flex items-center gap-1.5 px-4 py-2 text-sm font-semibold text-cyan-300">
            <BookOpen className="h-3.5 w-3.5" />Lessons
            <span className="text-[10px] opacity-70">({lessons.length})</span>
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* Generate from Syllabus */}
          <button onClick={() => { setShowBulk(true); setBulkQueue([]); setBulkDone(false); }}
            className="flex items-center gap-2 rounded border border-violet-500/30 bg-violet-600/15 px-4 py-2 text-sm font-semibold text-violet-300 hover:bg-violet-600/25 transition">
            <BookOpen className="h-4 w-4" />Syllabus
          </button>
          {/* Generate with AI */}
          <button onClick={() => { setShowGen(v => !v); setGenError(null); }}
            className={cn("flex items-center gap-2 rounded px-4 py-2 text-sm font-semibold transition",
              showGen ? "bg-cyan-600/20 border border-cyan-500/30 text-cyan-300" : "bg-cyan-600 hover:bg-cyan-500 text-white"
            )}>
            <Sparkles className="h-4 w-4" />Generate with AI
          </button>
        </div>
      </div>

      {/* ------ Search + Filter bar ------------------------------------------------------------------- */}
      <div className="px-6 py-3 border-b border-[#1e2841] shrink-0 flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search by title or topic..."
              className="w-full rounded border border-[#2a3555] bg-[#0f1423] py-2 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none" />
          </div>
          <div className="flex items-center gap-1">
            {(["all", ...DIFF_OPTIONS] as const).map(d => (
              <button key={d} onClick={() => setDiffFilter(d)}
                className={cn("rounded px-3 py-1.5 text-[11px] font-semibold capitalize transition",
                  diffFilter === d
                    ? "bg-cyan-600 text-white"
                    : "border border-[#2a3555] text-slate-400 hover:border-slate-500 hover:text-slate-200"
                )}>
                {d === "all" ? "All" : d.charAt(0).toUpperCase() + d.slice(1)}
              </button>
            ))}
          </div>
        </div>

      {/* ------ Lesson Grid -------------------------------------------------------------------- */}
      <div className="flex-1 overflow-y-auto p-6">

        {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-24 text-center">
              {lessons.length === 0 ? (
                <>
                  <div className="h-16 w-16 rounded-full bg-cyan-500/10 flex items-center justify-center mb-4">
                    <Sparkles className="h-7 w-7 text-cyan-400" />
                  </div>
                  <p className="text-sm font-semibold text-white mb-1">No lessons yet</p>
                  <p className="text-[11px] text-slate-500 mb-5">Click &quot;Generate with AI&quot; to create your first research-backed lesson</p>
                  <button onClick={() => setShowGen(true)}
                    className="flex items-center gap-2 rounded bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-sm font-semibold text-white transition">
                    <Sparkles className="h-3.5 w-3.5" />Generate First Lesson
                  </button>
                </>
              ) : (
                <>
                  <Search className="h-8 w-8 text-slate-700 mb-3" />
                  <p className="text-sm text-slate-500">No lessons match your filters.</p>
                  <button onClick={() => { setSearch(""); setDiffFilter("all"); }}
                    className="mt-3 text-[11px] text-cyan-400 hover:text-cyan-300 underline">Clear filters</button>
                </>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {filtered.map(lesson => (
                <LessonCard key={lesson.id} lesson={lesson}
                  onPreview={() => setPreview(lesson)}
                  onEdit={() => setEditLesson(JSON.parse(JSON.stringify(lesson)))}
                  onDelete={() => deleteLesson(lesson.id)} />
              ))}
            </div>
          )
        }

      </div>

      {/* ------ Bulk Syllabus Modal ------------------------------------------------------------------------------------------------------------------------------------- */}
      {showBulk && (
        <>
          <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm" onClick={() => !bulkRunning && setShowBulk(false)} />
          <div className="fixed inset-4 md:inset-x-[15%] md:inset-y-[5%] z-50 flex flex-col rounded-xl border border-[#2a3555] bg-[#0b0f1e] shadow-2xl overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-[#2a3555] px-6 py-4 shrink-0">
              <div className="flex items-center gap-3">
                <div className="h-8 w-8 rounded-lg bg-violet-500/15 border border-violet-500/25 flex items-center justify-center">
                  <BookOpen className="h-4 w-4 text-violet-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Generate from Syllabus</h3>
                  <p className="text-[10px] text-slate-500">Paste a syllabus — lessons generate one by one with AI validation</p>
                </div>
              </div>
              <button onClick={() => !bulkRunning && setShowBulk(false)}
                className="rounded-lg p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-white transition">
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-6">

              {/* ── Phase 1: Input ── */}
              {bulkQueue.length === 0 && (
                <div className="space-y-5">
                  <div>
                    <label className="block text-[11px] font-semibold uppercase tracking-widest text-slate-400 mb-2">
                      Syllabus — one topic per line
                    </label>
                    <textarea
                      autoFocus
                      value={bulkSyllabus}
                      onChange={e => setBulkSyllabus(e.target.value)}
                      rows={10}
                      disabled={bulkRunning}
                      placeholder={"Introduction to SOC Operations\nNetwork Protocol Analysis | intermediate\nDNS Tunneling Detection | advanced\nPhishing Email Investigation | beginner\nWindows Event Log Analysis\nSIEM and SPL Queries | intermediate"}
                      className="w-full rounded-xl border border-[#2a3555] bg-[#0d1322] px-4 py-3 text-sm text-slate-200 placeholder:text-slate-600 font-mono leading-relaxed focus:border-violet-500/60 focus:outline-none resize-none transition"
                    />
                    <p className="mt-1.5 text-[10px] text-slate-600">
                      Tip: add <code className="text-slate-500">| difficulty</code> after any topic to override the default. Max 20 lessons.
                    </p>
                  </div>

                  <div>
                    <label className="block text-[11px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Default difficulty</label>
                    <div className="grid grid-cols-4 gap-1.5">
                      {DIFF_OPTIONS.map(d => (
                        <button key={d} onClick={() => setBulkDiff(d)}
                          className={cn(
                            "rounded-lg py-2 text-[11px] font-semibold capitalize transition",
                            bulkDiff === d
                              ? "bg-violet-600 text-white shadow-lg shadow-violet-900/40"
                              : "border border-[#2a3555] bg-[#0d1322] text-slate-400 hover:border-slate-500 hover:text-slate-200"
                          )}>
                          {d}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Detected count */}
                  {(() => {
                    const items = parseSyllabus(bulkSyllabus, bulkDiff);
                    return items.length > 0 ? (
                      <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 px-4 py-3 text-[12px] text-violet-300">
                        <span className="font-bold">{items.length}</span> lesson{items.length !== 1 ? "s" : ""} detected
                        {items.length > 10 && <span className="text-violet-400/60 ml-2">· only first 20 will run</span>}
                      </div>
                    ) : bulkSyllabus.trim() ? (
                      <div className="rounded-xl border border-slate-700/30 bg-slate-800/10 px-4 py-3 text-[12px] text-slate-500">
                        No valid topics found yet
                      </div>
                    ) : null;
                  })()}
                </div>
              )}

              {/* ── Phase 2: Queue progress ── */}
              {bulkQueue.length > 0 && (
                <div className="space-y-3">
                  {/* Summary bar */}
                  <div className="flex items-center justify-between text-[12px] text-slate-400 pb-2 border-b border-[#1e2841]">
                    <span>
                      <span className="text-white font-semibold">{bulkQueue.length}</span> lessons
                      {" · "}
                      <span className="text-emerald-400">{bulkQueue.filter(i => i.status === "done").length} done</span>
                      {bulkRunning && <span className="text-cyan-400"> · generating...</span>}
                      {bulkDone && <span className="text-violet-400"> · complete</span>}
                    </span>
                    {bulkDone && (
                      <span className="text-[11px] text-slate-500">
                        {bulkQueue.filter(i => i.validation?.recommendation === "publish").length} ready to publish
                        {" · "}
                        {bulkQueue.filter(i => i.validation?.recommendation === "review").length} need review
                      </span>
                    )}
                  </div>

                  {/* Queue items */}
                  <div className="space-y-2">
                    {bulkQueue.map((item, idx) => {
                      const isExpanded = bulkExpanded === idx;
                      const rec = item.validation?.recommendation;
                      const score = item.validation?.score;

                      return (
                        <div key={idx} className={cn(
                          "rounded-xl border transition",
                          item.status === "done" && rec === "publish"     ? "border-emerald-500/25 bg-emerald-500/5"  :
                          item.status === "done" && rec === "review"      ? "border-amber-500/25   bg-amber-500/5"    :
                          item.status === "done" && rec === "regenerate"  ? "border-rose-500/25    bg-rose-500/5"     :
                          item.status === "error"                         ? "border-rose-500/25    bg-rose-500/5"     :
                          item.status === "generating"                    ? "border-cyan-500/25    bg-cyan-500/5"     :
                          item.status === "validating"                    ? "border-violet-500/25  bg-violet-500/5"   :
                          "border-[#2a3555] bg-[#0a0e1a]"
                        )}>
                          {/* Row */}
                          <div className="flex items-center gap-3 px-4 py-3">
                            {/* Status icon */}
                            <div className="shrink-0 w-5 flex items-center justify-center">
                              {item.status === "pending"    && <span className="h-2 w-2 rounded-full bg-slate-600" />}
                              {item.status === "generating" && <Loader2 className="h-4 w-4 text-cyan-400 animate-spin" />}
                              {item.status === "validating" && <Loader2 className="h-4 w-4 text-violet-400 animate-spin" />}
                              {item.status === "done" && rec === "publish"    && <CheckCircle2 className="h-4 w-4 text-emerald-400" />}
                              {item.status === "done" && rec === "review"     && <AlertTriangle className="h-4 w-4 text-amber-400" />}
                              {item.status === "done" && rec === "regenerate" && <AlertTriangle className="h-4 w-4 text-rose-400" />}
                              {item.status === "error"      && <AlertTriangle className="h-4 w-4 text-rose-400" />}
                            </div>

                            {/* Title */}
                            <div className="flex-1 min-w-0">
                              <p className="text-[13px] font-semibold text-white truncate">
                                {item.outlineTitle ?? item.topic}
                              </p>
                              <p className="text-[10px] text-slate-500 mt-0.5">
                                {item.status === "pending"    && "Waiting..."}
                                {item.status === "generating" && `Writing section ${item.sections ?? 0}/${TOTAL_SECTIONS}...`}
                                {item.status === "validating" && "Validating content..."}
                                {item.status === "done" && item.validation && `Score ${score}/10 · ${rec}`}
                                {item.status === "error" && (item.error ?? "Generation failed")}
                              </p>
                            </div>

                            {/* Score badge */}
                            {item.status === "done" && score != null && (
                              <span className={cn(
                                "shrink-0 rounded border px-2 py-0.5 text-[11px] font-bold",
                                rec === "publish"    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" :
                                rec === "review"     ? "border-amber-500/30   bg-amber-500/10   text-amber-400"   :
                                                       "border-rose-500/30    bg-rose-500/10    text-rose-400"
                              )}>
                                {score}/10
                              </span>
                            )}

                            {/* Expand / re-run */}
                            <div className="shrink-0 flex items-center gap-1">
                              {(item.status === "error" || (item.status === "done" && rec === "regenerate")) && !bulkRunning && (
                                <button onClick={() => rerunBulkItem(idx)}
                                  className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-cyan-400 transition"
                                  title="Regenerate this lesson">
                                  <RefreshCw className="h-3.5 w-3.5" />
                                </button>
                              )}
                              {item.status === "done" && (
                                <button onClick={() => setBulkExpanded(isExpanded ? null : idx)}
                                  className="rounded p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-slate-200 transition">
                                  {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                                </button>
                              )}
                            </div>
                          </div>

                          {/* Progress bar during generation */}
                          {item.status === "generating" && (
                            <div className="px-4 pb-3">
                              <div className="h-1.5 w-full rounded-full bg-[#1a2035] overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-gradient-to-r from-cyan-600 to-cyan-400 transition-all duration-700"
                                  style={{ width: `${Math.min(100, ((item.sections ?? 0) / TOTAL_SECTIONS) * 100)}%` }}
                                />
                              </div>
                            </div>
                          )}

                          {/* Expanded validation card */}
                          {isExpanded && item.validation && (
                            <div className="border-t border-[#1e2841] px-4 pb-4 pt-3 space-y-3">
                              {item.validation.issues.length > 0 && (
                                <div>
                                  <p className="text-[10px] font-semibold uppercase tracking-wider text-rose-400 mb-1.5">Issues</p>
                                  <ul className="space-y-1">
                                    {item.validation.issues.map((issue, ii) => (
                                      <li key={ii} className="flex items-start gap-1.5 text-[12px] text-slate-300">
                                        <span className="text-rose-400 shrink-0 mt-0.5">•</span>{issue}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {item.validation.strengths.length > 0 && (
                                <div>
                                  <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400 mb-1.5">Strengths</p>
                                  <ul className="space-y-1">
                                    {item.validation.strengths.map((s, si) => (
                                      <li key={si} className="flex items-start gap-1.5 text-[12px] text-slate-300">
                                        <span className="text-emerald-400 shrink-0 mt-0.5">•</span>{s}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              <div className="flex gap-2 pt-1">
                                {item.lesson && (
                                  <button onClick={() => setPreview(item.lesson!)}
                                    className="flex items-center gap-1.5 rounded border border-[#2a3555] px-3 py-1.5 text-[11px] text-slate-300 hover:border-cyan-500/30 hover:text-cyan-400 transition">
                                    <Eye className="h-3 w-3" />Preview
                                  </button>
                                )}
                                {!bulkRunning && (
                                  <button onClick={() => rerunBulkItem(idx)}
                                    className="flex items-center gap-1.5 rounded border border-[#2a3555] px-3 py-1.5 text-[11px] text-slate-300 hover:border-violet-500/30 hover:text-violet-400 transition">
                                    <RefreshCw className="h-3 w-3" />Regenerate
                                  </button>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="border-t border-[#1e2841] px-6 py-4 shrink-0">
              {bulkQueue.length === 0 ? (
                <button
                  onClick={() => {
                    const items = parseSyllabus(bulkSyllabus, bulkDiff);
                    if (items.length === 0) return;
                    runBulkGeneration(items, lessons);
                  }}
                  disabled={parseSyllabus(bulkSyllabus, bulkDiff).length === 0}
                  className="w-full flex items-center justify-center gap-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 active:bg-violet-700 disabled:opacity-40 disabled:cursor-not-allowed py-3.5 text-sm font-bold text-white transition shadow-lg shadow-violet-900/30"
                >
                  <BookOpen className="h-4 w-4" />
                  Generate All ({parseSyllabus(bulkSyllabus, bulkDiff).length} lessons) →
                </button>
              ) : (
                <div className="flex items-center justify-between">
                  {bulkRunning ? (
                    <div className="flex items-center gap-2 text-[12px] text-cyan-300">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Generating lessons — do not close this window
                    </div>
                  ) : (
                    <div className="text-[12px] text-slate-500">
                      {bulkDone ? "All lessons generated and saved." : "Queue paused."}
                    </div>
                  )}
                  <button onClick={() => !bulkRunning && setShowBulk(false)}
                    className="flex items-center gap-2 rounded border border-[#2a3555] px-4 py-2 text-sm text-slate-300 hover:border-slate-500 transition">
                    {bulkRunning ? "Running..." : "Close"}
                  </button>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* ------ Generator Panel --------------------------------------------------------------------------------------------------------------------------------- */}
      {showGen && <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={() => !genLoading && setShowGen(false)} />}
      <div className={cn(
        "fixed right-0 top-0 z-50 h-full w-[460px] border-l border-[#2a3555] bg-[#090d1a] shadow-2xl flex flex-col transition-transform duration-300",
        showGen ? "translate-x-0" : "translate-x-full"
      )}>
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#1e2841] px-6 py-4 shrink-0">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-cyan-500/15 border border-cyan-500/25 flex items-center justify-center">
              <Sparkles className="h-4 w-4 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Generate SOC Lesson</h3>
              <p className="text-[10px] text-slate-500">Agent searches the web and builds a full lesson</p>
            </div>
          </div>
          <button onClick={() => !genLoading && setShowGen(false)}
            className="rounded-lg p-1.5 text-slate-500 hover:bg-[#1a2035] hover:text-white transition">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form / Progress */}
        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-5">

          {/* ── Topic ── */}
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-widest text-slate-400 mb-2">
              Topic
            </label>
            <input
              autoFocus
              value={genTopic}
              onChange={e => setGenTopic(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !genLoading && genTopic.trim() && handleGenerate()}
              placeholder="e.g. Kerberoasting, Pass-the-Hash, Log4Shell..."
              disabled={genLoading}
              className="w-full rounded-xl border border-[#2a3555] bg-[#0d1322] px-4 py-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500/60 focus:outline-none focus:ring-1 focus:ring-cyan-500/20 disabled:opacity-40 transition"
            />
            <p className="mt-1 text-[10px] text-slate-600">Press Enter to generate instantly</p>
          </div>

          {/* ── Level ── */}
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Level</label>
            <div className="grid grid-cols-4 gap-1.5">
              {DIFF_OPTIONS.map(d => (
                <button key={d} onClick={() => setGenDiff(d)} disabled={genLoading}
                  className={cn(
                    "rounded-lg py-2 text-[11px] font-semibold capitalize transition",
                    genDiff === d
                      ? "bg-cyan-600 text-white shadow-lg shadow-cyan-900/40"
                      : "border border-[#2a3555] bg-[#0d1322] text-slate-400 hover:border-slate-500 hover:text-slate-200"
                  )}>
                  {d}
                </button>
              ))}
            </div>
          </div>

          {/* ── What the agent does ── */}
          {!genLoading && !genPartialSections.length && (
            <div className="rounded-xl border border-[#1e2841] bg-[#0d1322] p-4 space-y-2.5">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">What happens when you generate</p>
              {[
                { icon: "🔍", text: "Agent searches 5+ web sources on the topic" },
                { icon: "🧠", text: "Maps MITRE ATT&CK techniques and threat actors" },
                { icon: "✍️", text: "Writes 8 sections (~10 pages) with real code examples" },
                { icon: "📝", text: "Creates 4 scenario-based quiz questions" },
              ].map((item, i) => (
                <div key={i} className="flex items-center gap-2.5 text-[12px] text-slate-400">
                  <span className="text-base">{item.icon}</span>
                  <span>{item.text}</span>
                </div>
              ))}
            </div>
          )}

          {/* ── Live progress ── */}
          {genLoading && (
            <div className="space-y-3">
              {/* Status */}
              <div className="flex items-center gap-2.5 text-[12px] text-cyan-300">
                <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
                <span className="truncate">{genStatus || "Starting..."}</span>
              </div>

              {/* Progress bar */}
              <div>
                <div className="h-2 w-full rounded-full bg-[#1a2035] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-cyan-600 to-cyan-400 transition-all duration-700"
                    style={{ width: `${Math.min(100, (genPartialSections.length / TOTAL_SECTIONS) * 100)}%` }}
                  />
                </div>
                <div className="mt-1 flex justify-between text-[10px] text-slate-600">
                  <span>{genOutlineTitle ? genOutlineTitle.slice(0, 35) + (genOutlineTitle.length > 35 ? "..." : "") : "Building outline..."}</span>
                  <span>{genPartialSections.length}/{TOTAL_SECTIONS}</span>
                </div>
              </div>

              {/* Section cards */}
              <div className="space-y-1.5 max-h-60 overflow-y-auto">
                {genPartialSections.map((s, i) => (
                  <div key={i} className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <Check className="h-3 w-3 text-emerald-400 shrink-0" />
                      <span className="text-[11px] font-semibold text-emerald-300 truncate">{s.heading}</span>
                    </div>
                    <p className="mt-0.5 text-[10px] text-slate-500 line-clamp-1 pl-4">
                      {s.content.slice(0, 90)}...
                    </p>
                  </div>
                ))}
                {/* Skeleton for next section */}
                {genPartialSections.length < TOTAL_SECTIONS && (
                  <div className="rounded-lg border border-slate-700/40 bg-slate-800/20 px-3 py-2.5 animate-pulse">
                    <div className="h-2.5 w-2/3 rounded bg-slate-700/60" />
                    <div className="mt-1.5 h-2 w-4/5 rounded bg-slate-800/60" />
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Error */}
          {genError && (
            <div className="flex items-start gap-2 rounded-xl border border-rose-500/25 bg-rose-500/8 px-4 py-3 text-[12px] text-rose-300">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{genError}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-[#1e2841] px-6 py-4 shrink-0">
          <button
            onClick={handleGenerate}
            disabled={genLoading || !genTopic.trim()}
            className="w-full flex items-center justify-center gap-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed py-3.5 text-sm font-bold text-white transition shadow-lg shadow-cyan-900/30"
          >
            {genLoading
              ? <><Loader2 className="h-4 w-4 animate-spin" /> Generating lesson... (~2 min)</>
              : <><Sparkles className="h-4 w-4" /> Generate Lesson</>
            }
          </button>
          {!genLoading && (
            <p className="mt-2 text-center text-[10px] text-slate-600">
              8 sections with code examples + quiz questions
            </p>
          )}
        </div>
      </div>

      {/* ------ Preview Modal --------------------------------------------------------------------------------------------------------------------------------------------------------------------- */}
      {preview && (
        <LessonPreviewModal lesson={preview}
          onClose={() => setPreview(null)}
          onDelete={() => { deleteLesson(preview.id); setPreview(null); }} />
      )}

      {/* ------ Editor Modal --------------------------------------------------------------------------------------------------------------------------------------------------------------------- */}
      {editLesson && (
        <LessonEditorModal
          lesson={editLesson}
          onClose={() => setEditLesson(null)}
          onSave={(updated) => {
            const next = lessons.map(l => l.id === updated.id ? updated : l);
            persist(next);
            setEditLesson(null);
          }}
        />
      )}
    </div>
  );
}

// --------- Lesson card ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function LessonCard({ lesson, onPreview, onEdit, onDelete }: {
  lesson: SyllabusLesson;
  onPreview: () => void;
  onEdit: () => void;
  onDelete: () => void;

}) {
  const dc = DIFF_CONFIG[lesson.difficulty] ?? { label: lesson.difficulty, cls: "bg-slate-500/10 text-slate-400 border border-slate-500/25" };

  return (
    <div className="rounded-lg border border-[#2a3555] bg-[#0a0e1a] hover:border-cyan-500/30 hover:bg-[#0e1828] transition group flex flex-col">
      <div className="p-4 flex-1">
        <div className="flex items-center gap-1.5 mb-2.5 flex-wrap">
          <span className={cn("rounded px-2 py-0.5 text-[10px] font-semibold", dc.cls)}>{dc.label}</span>
          {lesson.researchUsed && (
            <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase text-emerald-400">✦ Researched</span>
          )}
        </div>
        <p className="text-sm font-bold text-white group-hover:text-cyan-300 transition line-clamp-2 leading-snug mb-2">{lesson.title}</p>
        <p className="text-[10px] text-slate-500 line-clamp-2 leading-relaxed">{lesson.topic}</p>
      </div>
      <div className="px-4 py-3 border-t border-[#1e2841] flex items-center justify-between">
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span>~{lesson.estimatedMinutes}m</span>
          <span className="text-amber-400 font-mono">+{lesson.xp} XP</span>
          <span>{lesson.sections.length} sec</span>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={onEdit}
            className="flex items-center gap-1 rounded border border-[#2a3555] px-2.5 py-1 text-[10px] font-semibold text-slate-400 hover:border-violet-500/40 hover:text-violet-400 transition">
            <Edit2 className="h-3 w-3" />Edit
          </button>
          <button onClick={onPreview}
            className="flex items-center gap-1 rounded border border-[#2a3555] px-2.5 py-1 text-[10px] font-semibold text-slate-400 hover:border-cyan-500/30 hover:text-cyan-400 transition">
            <Eye className="h-3 w-3" />Preview
          </button>
          <button onClick={onDelete} className="rounded p-1.5 text-slate-600 hover:bg-rose-500/10 hover:text-rose-400 transition">
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

// --------- Lesson preview modal ---------------------------------------------------------------------------------------------------------------------------------------------------------------

function LessonPreviewModal({ lesson, onClose, onDelete }: {
  lesson: SyllabusLesson;
  onClose: () => void;
  onDelete: () => void;

}) {
  const [openSection, setOpenSection] = useState<number|null>(0);

  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed inset-4 md:inset-x-[10%] md:inset-y-[5%] z-50 flex flex-col rounded-xl border border-[#2a3555] bg-[#0b0f1e] shadow-2xl overflow-hidden">
        <div className="flex items-start justify-between border-b border-[#2a3555] px-6 py-5 shrink-0">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <DiffBadge d={lesson.difficulty} />
              {lesson.researchUsed && (
                <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase text-emerald-400">נ"¬ Web Researched</span>
              )}
              <span className="text-[10px] text-slate-500">~{lesson.estimatedMinutes}m · +{lesson.xp} XP · {lesson.sections.length} sections</span>
            </div>
            <h2 className="text-lg font-bold text-white truncate">{lesson.title}</h2>
            <p className="text-[11px] text-slate-500 mt-0.5">{lesson.topic}</p>
          </div>
          <div className="flex items-center gap-2 ml-4 shrink-0">
            <button onClick={onDelete}
              className="flex items-center gap-1.5 rounded border border-rose-500/25 px-3 py-1.5 text-[11px] text-rose-400 hover:bg-rose-500/10 transition">
              <Trash2 className="h-3.5 w-3.5" />Delete
            </button>
            <button onClick={onClose} className="rounded p-1.5 text-slate-400 hover:bg-[#1a2035] hover:text-white transition">
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          <div className="px-6 py-5 border-b border-[#1e2841]">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-3">Introduction</p>
            <p className="text-[13px] text-slate-300 leading-relaxed whitespace-pre-wrap">{lesson.intro}</p>
          </div>

          <div className="border-b border-[#1e2841]">
            <div className="px-6 py-3 border-b border-[#1e2841]">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Sections ({lesson.sections.length})</p>
            </div>
            {lesson.sections.map((sec, i) => (
              <div key={i} className={cn("border-b border-[#1e2841] last:border-0 transition", openSection === i && "bg-[#080c15]")}>
                <button onClick={() => setOpenSection(openSection === i ? null : i)}
                  className="flex w-full items-center gap-3 px-6 py-3.5 text-left hover:bg-[#0f1728] transition">
                  <ChevronRight className={cn("h-3.5 w-3.5 text-slate-500 transition-transform shrink-0", openSection === i && "rotate-90")} />
                  <span className="font-mono text-[10px] text-slate-600 w-4 shrink-0">{i + 1}</span>
                  <span className="text-[13px] font-semibold text-slate-200 flex-1">{sec.heading}</span>
                  <span className="text-[10px] text-slate-600">{sec.content.split(" ").length}w</span>
                </button>
                {openSection === i && (
                  <div className="border-t border-[#1e2841] px-6 pb-5 pt-4 space-y-3">
                    <p className="text-[12px] text-slate-300 leading-relaxed whitespace-pre-wrap">{sec.content}</p>
                  </div>
                )}
              </div>
            ))}
          </div>


        </div>
      </div>
    </>
  );
}

// -------------------------------------------------------------------------------
// LESSON EDITOR MODAL
// -------------------------------------------------------------------------------

type QuizQ = { question: string; options: { label: string; value: string }[]; answer: string; explanation: string };

function LessonEditorModal({ lesson, onClose, onSave }: {
  lesson: SyllabusLesson;
  onClose: () => void;
  onSave: (updated: SyllabusLesson) => void;
}) {
  const [draft, setDraft] = useState<SyllabusLesson>(() => JSON.parse(JSON.stringify(lesson)));
  const [tab, setTab] = useState<"overview"|"sections">("overview");
  const [openSec, setOpenSec] = useState<number>(0);

  // Generic field updater
  function setField<K extends keyof SyllabusLesson>(key: K, val: SyllabusLesson[K]) {
    setDraft(d => ({ ...d, [key]: val }));
  }

  // Section helpers
  function updateSection(i: number, field: "heading"|"content"|"codeExample", val: string) {
    setDraft(d => {
      const secs = [...d.sections];
      secs[i] = { ...secs[i], [field]: val };
      return { ...d, sections: secs };
    });
  }
  function addSection() {
    setDraft(d => ({
      ...d,
      sections: [...d.sections, { heading: "New Section", content: "", codeExample: "" }],
    }));
    setOpenSec(draft.sections.length);
  }
  function removeSection(i: number) {
    setDraft(d => ({ ...d, sections: d.sections.filter((_, idx) => idx !== i) }));
    setOpenSec(Math.max(0, i - 1));
  }

  // Takeaway helpers
  function updateTakeaway(i: number, val: string) {
    setDraft(d => { const t = [...d.keyTakeaways]; t[i] = val; return { ...d, keyTakeaways: t }; });
  }
  function addTakeaway() { setDraft(d => ({ ...d, keyTakeaways: [...d.keyTakeaways, ""] })); }
  function removeTakeaway(i: number) { setDraft(d => ({ ...d, keyTakeaways: d.keyTakeaways.filter((_, idx) => idx !== i) })); }

  // Quiz helpers
  const quiz = draft.quiz ?? [];
  function updateQuiz(i: number, field: keyof QuizQ, val: string) {
    setDraft(d => {
      const q = [...(d.quiz ?? [])];
      q[i] = { ...q[i], [field]: val } as QuizQ;
      return { ...d, quiz: q };
    });
  }
  function updateQuizOption(qi: number, oi: number, val: string) {
    setDraft(d => {
      const q = [...(d.quiz ?? [])];
      const opts = [...q[qi].options];
      opts[oi] = { ...opts[oi], label: val };
      q[qi] = { ...q[qi], options: opts };
      return { ...d, quiz: q };
    });
  }
  function addQuizQ() {
    setDraft(d => ({
      ...d,
      quiz: [...(d.quiz ?? []), {
        question: "",
        options: [
          { label: "", value: "a" }, { label: "", value: "b" },
          { label: "", value: "c" }, { label: "", value: "d" },
        ],
        answer: "a",
        explanation: "",
      }],
    }));
  }
  function removeQuizQ(i: number) { setDraft(d => ({ ...d, quiz: (d.quiz ?? []).filter((_, idx) => idx !== i) })); }

  const inputCls = "w-full rounded-lg border border-[#2a3555] bg-[#070b14] px-3 py-2 text-[13px] text-white placeholder-slate-600 focus:border-cyan-500/60 focus:outline-none resize-none";
  const TABS: { id: "overview"|"sections"; label: string }[] = [
    { id: "overview",   label: "Overview" },
    { id: "sections",   label: `Sections (${draft.sections.length})` },
  ];

  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed inset-4 md:inset-x-[6%] md:inset-y-[3%] z-50 flex flex-col rounded-xl border border-[#2a3555] bg-[#0b0f1e] shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#2a3555] px-6 py-4 shrink-0">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-500/15 text-violet-400">
              <Edit2 className="h-4 w-4" />
            </div>
            <div>
              <p className="text-[11px] text-slate-500 uppercase tracking-widest font-semibold">Editing Lesson</p>
              <p className="text-sm font-bold text-white truncate max-w-[500px]">{draft.title}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onClose}
              className="rounded-lg border border-[#2a3555] px-4 py-1.5 text-[12px] text-slate-400 hover:text-white transition">
              Cancel
            </button>
            <button onClick={() => onSave(draft)}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-4 py-1.5 text-[12px] font-bold text-white transition">
              <Save className="h-3.5 w-3.5" />Save Changes
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[#2a3555] shrink-0 px-6">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={cn("px-4 py-3 text-[12px] font-semibold border-b-2 -mb-px transition",
                tab === t.id ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-500 hover:text-slate-300")}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">

          {/* ── OVERVIEW ── */}
          {tab === "overview" && (
            <div className="space-y-4 max-w-2xl">
              <div>
                <label className="block text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">Title</label>
                <input className={inputCls} value={draft.title} onChange={e => setField("title", e.target.value)} />
              </div>
              <div>
                <label className="block text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">Topic</label>
                <input className={inputCls} value={draft.topic} onChange={e => setField("topic", e.target.value)} />
              </div>
              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">Difficulty</label>
                  <div className="flex gap-2 flex-wrap">
                    {(["beginner","intermediate","advanced","expert"] as const).map(d => (
                      <button key={d} onClick={() => setField("difficulty", d)}
                        className={cn("rounded-lg border px-3 py-1.5 text-[11px] font-semibold capitalize transition",
                          draft.difficulty === d ? "border-cyan-500 bg-cyan-500/15 text-cyan-300" : "border-[#2a3555] text-slate-500 hover:border-slate-500")}>
                        {d}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div>
                <label className="block text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">
                  Introduction <span className="text-slate-600 font-normal normal-case">({draft.intro.length} chars)</span>
                </label>
                <textarea className={cn(inputCls, "min-h-[200px]")} value={draft.intro}
                  onChange={e => setField("intro", e.target.value)} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">Est. Minutes</label>
                  <input type="number" className={inputCls} value={draft.estimatedMinutes}
                    onChange={e => setField("estimatedMinutes", Number(e.target.value))} />
                </div>
                <div>
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">XP</label>
                  <input type="number" className={inputCls} value={draft.xp}
                    onChange={e => setField("xp", Number(e.target.value))} />
                </div>
              </div>
            </div>
          )}

          {/* ── SECTIONS ── */}
          {tab === "sections" && (
            <div className="space-y-3">
              {draft.sections.map((sec, i) => (
                <div key={i} className="rounded-xl border border-[#2a3555] bg-[#070b14] overflow-hidden">
                  {/* Section header */}
                  <button onClick={() => setOpenSec(openSec === i ? -1 : i)}
                    className="flex w-full items-center gap-3 px-4 py-3 hover:bg-[#0d1525] transition">
                    <ChevronRight className={cn("h-3.5 w-3.5 text-slate-500 transition-transform shrink-0", openSec === i && "rotate-90")} />
                    <span className="font-mono text-[10px] text-slate-600 w-5 shrink-0">{i + 1}</span>
                    <span className="text-[13px] font-semibold text-slate-200 flex-1 text-left truncate">{sec.heading || "Untitled"}</span>
                    <span className="text-[10px] text-slate-600 shrink-0">{sec.content.split(" ").length}w</span>
                    <button onClick={e => { e.stopPropagation(); removeSection(i); }}
                      className="rounded p-1 text-slate-600 hover:text-rose-400 hover:bg-rose-500/10 transition ml-1">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </button>
                  {/* Section body */}
                  {openSec === i && (
                    <div className="border-t border-[#2a3555] px-4 pb-4 pt-4 space-y-3">
                      <div>
                        <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">Heading</label>
                        <input className={inputCls} value={sec.heading}
                          onChange={e => updateSection(i, "heading", e.target.value)} />
                      </div>
                      <div>
                        <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">
                          Content <span className="text-slate-600 font-normal normal-case">({sec.content.split(" ").length} words)</span>
                        </label>
                        <textarea className={cn(inputCls, "min-h-[220px] font-mono text-[12px]")} value={sec.content}
                          onChange={e => updateSection(i, "content", e.target.value)} />
                      </div>
                      <div>
                        <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">Code Example</label>
                        <textarea className={cn(inputCls, "min-h-[100px] font-mono text-[12px] text-emerald-300")}
                          value={sec.codeExample ?? ""} onChange={e => updateSection(i, "codeExample", e.target.value)} />
                      </div>
                    </div>
                  )}
                </div>
              ))}
              <button onClick={addSection}
                className="flex items-center gap-2 rounded-xl border border-dashed border-[#2a3555] px-4 py-3 text-[12px] text-slate-500 hover:border-cyan-500/40 hover:text-cyan-400 w-full transition">
                <Plus className="h-4 w-4" />Add Section
              </button>
            </div>
          )}



        </div>
      </div>
    </>
  );
}

// -------------------------------------------------------------------------------
// LOG VALIDATOR TAB
// -------------------------------------------------------------------------------

const SEV_CFG: Record<IssueSeverity, { label: string; cls: string; icon: React.ElementType; dot: string }> = {
  error:   { label: "Error",   cls: "bg-rose-500/15 text-rose-400 border border-rose-500/25",     icon: XCircle,      dot: "bg-rose-400"    },
  warning: { label: "Warning", cls: "bg-amber-500/15 text-amber-400 border border-amber-500/25",  icon: AlertCircle,  dot: "bg-amber-400"   },
  info:    { label: "Info",    cls: "bg-sky-500/15   text-sky-400   border border-sky-500/25",    icon: Info,         dot: "bg-sky-400"     },
};

function SevBadge({ sev }: { sev: IssueSeverity }) {
  const c = SEV_CFG[sev];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-semibold", c.cls)}>
      <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", c.dot)} />
      {c.label}
    </span>
  );
}

function CodeBadge({ code }: { code: string }) {
  return (
    <span className="font-mono text-[9px] rounded border border-[#2a3555] bg-[#0a0f1e] px-1.5 py-0.5 text-slate-400">
      {code}
    </span>
  );
}

function IssueRow({ issue }: { issue: ValidationIssue }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      className="border-b border-[#1e2841] last:border-0 hover:bg-[#0d1326] transition-colors cursor-pointer"
      onClick={() => setExpanded(v => !v)}
    >
      <div className="grid grid-cols-[90px_140px_100px_80px_1fr_28px] gap-2 items-center px-4 py-2.5 text-[11px]">
        <SevBadge sev={issue.severity} />
        <span className="font-mono text-[10px] text-slate-300 truncate">{issue.event_id}</span>
        <span className="text-slate-400 truncate">{issue.vendor.slice(0, 22)}</span>
        <span className="rounded border border-[#2a3555] bg-[#0c1120] px-1.5 py-px text-[9px] text-slate-400 font-mono truncate">{issue.source}</span>
        <span className="text-slate-300">{issue.message}</span>
        <ChevronRight className={cn("h-3.5 w-3.5 text-slate-500 shrink-0 transition-transform", expanded && "rotate-90")} />
      </div>
      {expanded && (
        <div className="px-4 pb-3 pt-1 bg-[#0a0e1c]">
          <div className="flex flex-wrap gap-2 mb-2">
            <CodeBadge code={issue.code} />
            {issue.field && (
              <span className="font-mono text-[9px] rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 text-amber-400">
                field: {issue.field}
              </span>
            )}
            <span className="text-[10px] text-slate-500">event_type: {issue.event_type}</span>
          </div>
          {issue.suggestion && (
            <p className="text-[11px] text-emerald-300/80 mt-1 flex items-start gap-1.5">
              <span className="text-emerald-400 font-semibold shrink-0">-</span>
              {issue.suggestion}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function LogValidatorTab() {
  const [report, setReport] = useState<ValidationReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<IssueSeverity | "all">("all");
  const [search, setSearch] = useState("");

  async function runValidation() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/validate-logs");
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      const data: ValidationReport = await res.json();
      setReport(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  const filteredIssues = useMemo(() => {
    if (!report) return [];
    return report.issues.filter(issue => {
      if (sevFilter !== "all" && issue.severity !== sevFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          issue.event_id.toLowerCase().includes(q) ||
          issue.vendor.toLowerCase().includes(q) ||
          issue.code.toLowerCase().includes(q) ||
          issue.message.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [report, sevFilter, search]);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2841] shrink-0">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-5 w-5 text-violet-400" />
          <div>
            <h2 className="text-sm font-semibold text-white">Log Field Validator</h2>
            <p className="text-[11px] text-slate-400">Validates all telemetry events against real vendor log schemas</p>
          </div>
        </div>
        <button
          onClick={runValidation}
          disabled={loading}
          className="flex items-center gap-2 rounded-lg border border-violet-500/40 bg-violet-500/10 px-4 py-2 text-[12px] font-semibold text-violet-300 transition hover:bg-violet-500/20 disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
          {loading ? "Validating--¦" : "Run Validation"}
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="mx-6 mt-4 rounded border border-rose-500/25 bg-rose-500/10 p-3 text-[12px] text-rose-300 shrink-0">
          <span className="font-semibold">Error:</span> {error}
        </div>
      )}

      {/* Empty / call-to-action state */}
      {!report && !loading && !error && (
        <div className="flex flex-1 flex-col items-center justify-center gap-4 text-center px-8">
          <ShieldCheck className="h-12 w-12 text-slate-600" />
          <div>
            <p className="text-sm font-medium text-slate-300">Validate all platform logs</p>
            <p className="text-[12px] text-slate-500 mt-1 max-w-sm">
              Checks field naming conventions for 18 vendor schemas --" CrowdStrike, MDE, Okta, AWS CloudTrail, FortiGate, Palo Alto, and more.
            </p>
          </div>
          <button
            onClick={runValidation}
            className="flex items-center gap-2 rounded-lg border border-violet-500/40 bg-violet-500/15 px-5 py-2.5 text-[13px] font-semibold text-violet-300 transition hover:bg-violet-500/25"
          >
            <Play className="h-4 w-4" />
            Run Validation
          </button>
        </div>
      )}

      {/* Results */}
      {report && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-4 gap-3 px-6 py-4 shrink-0 border-b border-[#1e2841]">
            <div className="rounded-lg border border-[#1e2841] bg-[#0a0e1c] p-3">
              <div className="text-[10px] text-slate-500 mb-1">Total Events</div>
              <div className="text-2xl font-bold text-white">{report.total_events}</div>
              <div className="text-[10px] text-emerald-400 mt-0.5">{report.clean_events} clean</div>
            </div>
            <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3 cursor-pointer hover:bg-rose-500/10 transition"
              onClick={() => setSevFilter(sevFilter === "error" ? "all" : "error")}>
              <div className="text-[10px] text-rose-400/70 mb-1">Errors</div>
              <div className="text-2xl font-bold text-rose-400">{report.summary.errors}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">wrong field names</div>
            </div>
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 cursor-pointer hover:bg-amber-500/10 transition"
              onClick={() => setSevFilter(sevFilter === "warning" ? "all" : "warning")}>
              <div className="text-[10px] text-amber-400/70 mb-1">Warnings</div>
              <div className="text-2xl font-bold text-amber-400">{report.summary.warnings}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">missing required fields</div>
            </div>
            <div className="rounded-lg border border-sky-500/20 bg-sky-500/5 p-3 cursor-pointer hover:bg-sky-500/10 transition"
              onClick={() => setSevFilter(sevFilter === "info" ? "all" : "info")}>
              <div className="text-[10px] text-sky-400/70 mb-1">Info</div>
              <div className="text-2xl font-bold text-sky-400">{report.summary.infos}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">coverage hints</div>
            </div>
          </div>

          {/* Vendor breakdown */}
          <div className="px-6 py-3 border-b border-[#1e2841] shrink-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] text-slate-500 font-medium uppercase tracking-wide">By Vendor:</span>
              {Object.entries(report.by_vendor)
                .filter(([, v]) => v.issues > 0)
                .sort((a, b) => b[1].error_count - a[1].error_count)
                .slice(0, 8)
                .map(([vendor, v]) => (
                  <span key={vendor} className="inline-flex items-center gap-1.5 rounded border border-[#2a3555] bg-[#0a0e1c] px-2 py-1 text-[10px]">
                    <span className="text-slate-300">{vendor.slice(0, 28)}</span>
                    {v.error_count > 0 && (
                      <span className="rounded bg-rose-500/20 px-1 py-px text-[9px] text-rose-400 font-semibold">{v.error_count}E</span>
                    )}
                    <span className="rounded bg-slate-700/50 px-1 py-px text-[9px] text-slate-400">{v.issues}W</span>
                  </span>
                ))
              }
            </div>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 px-6 py-2.5 border-b border-[#1e2841] shrink-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search event, vendor, code--¦"
                className="h-8 w-64 rounded border border-[#2a3555] bg-[#0a0e1c] pl-8 pr-3 text-[11px] text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500/50"
              />
            </div>
            <div className="flex items-center gap-1">
              {(["all", "error", "warning", "info"] as const).map(s => (
                <button
                  key={s}
                  onClick={() => setSevFilter(s)}
                  className={cn(
                    "rounded px-3 py-1 text-[11px] font-medium transition",
                    sevFilter === s
                      ? "bg-[#161c2b] text-white"
                      : "text-slate-400 hover:text-slate-200"
                  )}
                >
                  {s === "all" ? `All (${report.issues.length})` : s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
            <div className="ml-auto flex items-center gap-2">
              <span className="text-[11px] text-slate-500">{filteredIssues.length} issue{filteredIssues.length !== 1 ? "s" : ""}</span>
              <button
                onClick={runValidation}
                className="flex items-center gap-1 rounded border border-[#2a3555] bg-[#0a0e1c] px-2.5 py-1 text-[10px] text-slate-400 hover:text-slate-200 transition"
              >
                <RefreshCw className="h-3 w-3" />
                Re-run
              </button>
              <span className="text-[10px] text-slate-600">
                Generated {new Date(report.generated_at).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {/* Issue list */}
          <div className="flex-1 min-h-0 overflow-y-auto">
            {/* Table header */}
            <div className="grid grid-cols-[90px_140px_100px_80px_1fr_28px] gap-2 px-4 py-2 border-b border-[#1e2841] bg-[#080c14] sticky top-0 z-10">
              {["Severity", "Event ID", "Vendor", "Source", "Message", ""].map(h => (
                <span key={h} className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">{h}</span>
              ))}
            </div>
            {filteredIssues.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <ShieldCheck className="h-8 w-8 text-emerald-400 mb-3" />
                <p className="text-sm font-medium text-emerald-300">No issues found</p>
                <p className="text-[11px] text-slate-500 mt-1">All events match their vendor schemas</p>
              </div>
            ) : (
              filteredIssues.map(issue => <IssueRow key={`${issue.event_id}-${issue.code}`} issue={issue} />)
            )}
          </div>
        </>
      )}
    </div>
  );
}

// -------------------------------------------------------------------------------
// MAIN PAGE
// -------------------------------------------------------------------------------

type AdminTab = "overview" | "users" | "scenarios" | "quizzes" | "lessons" | "log_validator";

const TABS: { id: AdminTab; icon: React.ElementType; label: string }[] = [
  { id:"overview",      icon:LayoutDashboard, label:"Overview"           },
  { id:"users",         icon:UsersIcon,       label:"User Management"    },
  { id:"scenarios",     icon:Shield,          label:"Scenario Management"},
  { id:"quizzes",       icon:HelpCircle,      label:"Quiz Management"    },
  { id:"lessons",       icon:BookOpen,        label:"Lesson Management"  },
  { id:"log_validator", icon:ShieldCheck,     label:"Log Validator"      },
];

export default function AdminPage() {
  const [tab, setTab] = useState<AdminTab>("scenarios");

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#080c14]">
      <Topbar title="Admin Panel" subtitle="Manage your organization: Cryotech" />

      <div className="flex flex-col flex-1 min-h-0 px-6 py-4 gap-4 max-w-[1600px] mx-auto w-full">

        {/* Tab bar */}
        <div className="flex items-center gap-1 rounded-lg border border-[#1e2841] bg-[#0c1120] p-1 shrink-0 self-start">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={()=>setTab(t.id)}
              className={cn(
                "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-all",
                tab===t.id
                  ? "bg-[#161c2b] text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#0f1423]"
              )}
            >
              <t.icon className={cn("h-4 w-4", tab===t.id?"text-violet-400":"text-slate-500")} />
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 min-h-0 overflow-hidden rounded-lg border border-[#1e2841] bg-[#0c1120]">
          {tab==="overview"      && <OverviewTab />}
          {tab==="users"         && <UsersTab />}
          {tab==="scenarios"     && <ScenariosTab />}
          {tab==="quizzes"       && <QuizzesTab />}
          {tab==="lessons"       && <LessonsTab />}
          {tab==="log_validator" && <LogValidatorTab />}
        </div>
      </div>
    </div>
  );
}
