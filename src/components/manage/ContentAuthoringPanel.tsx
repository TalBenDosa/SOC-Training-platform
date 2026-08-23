"use client";
/**
 * Per-org content authoring (Phase 2 — migration 0040). Lets an org admin write
 * lessons and quizzes that ONLY their college sees, alongside the global
 * built-ins. Manual authoring only — no AI generation (that stays global, in
 * /admin, for the super-admin). Talks to /api/org/content/[type]; the server
 * namespaces every id, allowlists every field, and pins the org from the JWT,
 * so this component never sends an org id and never sees an answer key it could
 * leak (drafts are read back through the same service-role route).
 */
import { useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { LOG_SOURCES, EVENT_TYPES, IOC_TYPES, COMMON_LOG_SOURCES } from "@/lib/scenarios/authoredConstants";
import {
  BookOpen, ClipboardList, Plus, Trash2, Eye, EyeOff, Pencil, Loader2, X, Target, DoorOpen, Building2,
} from "lucide-react";

type ContentTab = "lessons" | "quizzes" | "scenarios" | "rooms" | "companies";

interface Row {
  id: string;
  status: "draft" | "published";
  content: Record<string, unknown>;
  updated_at: string;
}

const inputCls =
  "w-full rounded border border-border bg-bg px-2.5 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/50 focus:outline-none";
const labelCls = "block text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-1";

// ─── shared list + CRUD hook ─────────────────────────────────────────────────
function useOrgContent(type: ContentTab) {
  const [items, setItems] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [rowBusy, setRowBusy] = useState<string | null>(null);

  async function load() {
    const res = await fetch(`/api/org/content/${type}`);
    if (res.ok) setItems((await res.json()).items ?? []);
    else setItems([]);
  }
  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [type]);

  async function save(body: Record<string, unknown>): Promise<boolean> {
    setError(null); setNotice(null);
    const res = await fetch(`/api/org/content/${type}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Save failed."); return false; }
    setNotice(body.status === "published" ? "Published to your students." : "Saved as a draft.");
    await load();
    return true;
  }

  async function setStatus(id: string, status: "draft" | "published") {
    setRowBusy(id); setError(null);
    const res = await fetch(`/api/org/content/${type}/${encodeURIComponent(id)}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }),
    });
    setRowBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Update failed."); return; }
    await load();
  }

  async function remove(id: string, title: string) {
    if (!confirm(`Delete "${title}"? This removes it for good.`)) return;
    setRowBusy(id); setError(null);
    const res = await fetch(`/api/org/content/${type}/${encodeURIComponent(id)}`, { method: "DELETE" });
    setRowBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Delete failed."); return; }
    await load();
  }

  return { items, error, notice, rowBusy, setError, setNotice, load, save, setStatus, remove };
}

// ─── shared row list ─────────────────────────────────────────────────────────
function ItemList({
  items, rowBusy, onEdit, onToggle, onDelete, emptyLabel,
}: {
  items: Row[] | null;
  rowBusy: string | null;
  onEdit: (r: Row) => void;
  onToggle: (r: Row) => void;
  onDelete: (r: Row) => void;
  emptyLabel: string;
}) {
  if (items === null) {
    return <div className="flex items-center gap-2 text-xs text-slate-400"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…</div>;
  }
  if (items.length === 0) return <p className="text-xs text-slate-500">{emptyLabel}</p>;
  return (
    <div className="space-y-2">
      {items.map(r => {
        const pub = r.status === "published";
        const title = String(r.content?.title ?? r.id);
        return (
          <div key={r.id} className="flex items-center gap-3 rounded-lg border border-border bg-bg px-3 py-2.5">
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-slate-100">{title}</p>
              <p className="text-[10px] text-slate-500">Updated {new Date(r.updated_at).toLocaleDateString()}</p>
            </div>
            <span className={cn("shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide border",
              pub ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-slate-500/40 bg-slate-500/10 text-slate-400")}>
              {pub ? "Published" : "Draft"}
            </span>
            <button onClick={() => onEdit(r)} title="Edit"
              className="rounded p-1.5 text-slate-400 transition hover:bg-cyber-500/10 hover:text-cyber-300 disabled:opacity-50"
              disabled={rowBusy === r.id}>
              <Pencil className="h-4 w-4" />
            </button>
            <button onClick={() => onToggle(r)} title={pub ? "Unpublish" : "Publish to students"}
              className="rounded p-1.5 text-slate-400 transition hover:bg-cyber-500/10 hover:text-cyber-300 disabled:opacity-50"
              disabled={rowBusy === r.id}>
              {pub ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
            <button onClick={() => onDelete(r)} title="Delete"
              className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high disabled:opacity-50"
              disabled={rowBusy === r.id}>
              <Trash2 className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}

function Banner({ error, notice }: { error: string | null; notice: string | null }) {
  return (
    <>
      {error && <div className="mt-3 rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">{error}</div>}
      {notice && <div className="mt-3 rounded border border-neon-green/30 bg-neon-green/10 px-3 py-2 text-xs text-neon-green">{notice}</div>}
    </>
  );
}

// ─── Lessons ─────────────────────────────────────────────────────────────────
interface LessonDraft {
  id?: string; title: string; topic: string; difficulty: string; xp: number; estimatedMinutes: number;
  intro: string; sections: { heading: string; content: string; codeExample: string }[];
  keyTakeaways: string; references: string;
}
const emptyLesson = (): LessonDraft => ({
  title: "", topic: "", difficulty: "beginner", xp: 50, estimatedMinutes: 10,
  intro: "", sections: [{ heading: "", content: "", codeExample: "" }], keyTakeaways: "", references: "",
});
function rowToLessonDraft(r: Row): LessonDraft {
  const c = r.content as Record<string, unknown>;
  const secs = Array.isArray(c.sections) ? c.sections as Record<string, unknown>[] : [];
  return {
    id: r.id,
    title: String(c.title ?? ""), topic: String(c.topic ?? ""), difficulty: String(c.difficulty ?? "beginner"),
    xp: Number(c.xp ?? 50), estimatedMinutes: Number(c.estimatedMinutes ?? 10), intro: String(c.intro ?? ""),
    sections: secs.length ? secs.map(s => ({ heading: String(s.heading ?? ""), content: String(s.content ?? ""), codeExample: String(s.codeExample ?? "") })) : [{ heading: "", content: "", codeExample: "" }],
    keyTakeaways: (Array.isArray(c.keyTakeaways) ? c.keyTakeaways as string[] : []).join("\n"),
    references: (Array.isArray(c.references) ? c.references as string[] : []).join("\n"),
  };
}

function LessonsTab() {
  const { items, error, notice, rowBusy, setError, save, setStatus, remove } = useOrgContent("lessons");
  const [draft, setDraft] = useState<LessonDraft | null>(null);
  const [busy, setBusy] = useState(false);

  function up<K extends keyof LessonDraft>(k: K, v: LessonDraft[K]) { setDraft(d => d ? { ...d, [k]: v } : d); }
  function upSection(i: number, k: "heading" | "content" | "codeExample", v: string) {
    setDraft(d => d ? { ...d, sections: d.sections.map((s, j) => j === i ? { ...s, [k]: v } : s) } : d);
  }

  async function submit(status: "draft" | "published") {
    if (!draft) return;
    setBusy(true);
    const ok = await save({
      id: draft.id, status,
      title: draft.title, topic: draft.topic, difficulty: draft.difficulty, xp: draft.xp, estimatedMinutes: draft.estimatedMinutes,
      intro: draft.intro,
      sections: draft.sections,
      keyTakeaways: draft.keyTakeaways.split("\n").map(s => s.trim()).filter(Boolean),
      references: draft.references.split("\n").map(s => s.trim()).filter(Boolean),
    });
    setBusy(false);
    if (ok) setDraft(null);
  }

  if (draft) {
    return (
      <div className="mt-3 space-y-3 rounded-lg border border-cyber-500/30 bg-bg-elevated p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">{draft.id ? "Edit lesson" : "New lesson"}</h3>
          <button onClick={() => setDraft(null)} className="rounded p-1 text-slate-400 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <Banner error={error} notice={null} />
        <div><label className={labelCls}>Title</label><input className={inputCls} value={draft.title} onChange={e => up("title", e.target.value)} placeholder="e.g. Reading a Windows 4624 logon event" /></div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div><label className={labelCls}>Topic</label><input className={inputCls} value={draft.topic} onChange={e => up("topic", e.target.value)} placeholder="Windows" /></div>
          <div><label className={labelCls}>Difficulty</label>
            <select className={inputCls} value={draft.difficulty} onChange={e => up("difficulty", e.target.value)}>
              <option value="beginner">Beginner</option><option value="intermediate">Intermediate</option><option value="advanced">Advanced</option><option value="expert">Expert</option>
            </select>
          </div>
          <div><label className={labelCls}>XP</label><input type="number" className={inputCls} value={draft.xp} onChange={e => up("xp", Number(e.target.value))} /></div>
          <div><label className={labelCls}>Minutes</label><input type="number" className={inputCls} value={draft.estimatedMinutes} onChange={e => up("estimatedMinutes", Number(e.target.value))} /></div>
        </div>
        <div><label className={labelCls}>Intro</label><textarea className={cn(inputCls, "min-h-[64px]")} value={draft.intro} onChange={e => up("intro", e.target.value)} placeholder="One or two sentences framing what this lesson covers." /></div>

        <div>
          <label className={labelCls}>Sections</label>
          <div className="space-y-3">
            {draft.sections.map((s, i) => (
              <div key={i} className="rounded border border-border bg-bg p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <input className={inputCls} value={s.heading} onChange={e => upSection(i, "heading", e.target.value)} placeholder={`Section ${i + 1} heading`} />
                  {draft.sections.length > 1 && (
                    <button onClick={() => up("sections", draft.sections.filter((_, j) => j !== i))} className="rounded p-1.5 text-slate-400 hover:text-severity-high" title="Remove section"><Trash2 className="h-4 w-4" /></button>
                  )}
                </div>
                <textarea className={cn(inputCls, "min-h-[72px]")} value={s.content} onChange={e => upSection(i, "content", e.target.value)} placeholder="Body text (Markdown supported)." />
                <textarea className={cn(inputCls, "min-h-[40px] font-mono text-xs")} value={s.codeExample} onChange={e => upSection(i, "codeExample", e.target.value)} placeholder="Optional code / log block" />
              </div>
            ))}
          </div>
          <Button variant="outline" size="sm" className="mt-2" onClick={() => up("sections", [...draft.sections, { heading: "", content: "", codeExample: "" }])}>
            <Plus className="h-4 w-4" /> Add section
          </Button>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div><label className={labelCls}>Key takeaways (one per line)</label><textarea className={cn(inputCls, "min-h-[64px]")} value={draft.keyTakeaways} onChange={e => up("keyTakeaways", e.target.value)} /></div>
          <div><label className={labelCls}>References (one per line)</label><textarea className={cn(inputCls, "min-h-[64px]")} value={draft.references} onChange={e => up("references", e.target.value)} /></div>
        </div>

        <div className="flex items-center gap-2 pt-1">
          <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("published")}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />} Publish</Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => submit("draft")}>Save draft</Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Banner error={error} notice={notice} />
      <div className="mt-3 mb-3">
        <Button variant="outline" size="sm" onClick={() => { setError(null); setDraft(emptyLesson()); }}><Plus className="h-4 w-4" /> New lesson</Button>
      </div>
      <ItemList items={items} rowBusy={rowBusy}
        onEdit={r => { setError(null); setDraft(rowToLessonDraft(r)); }}
        onToggle={r => setStatus(r.id, r.status === "published" ? "draft" : "published")}
        onDelete={r => remove(r.id, String(r.content?.title ?? r.id))}
        emptyLabel="No lessons authored yet. Your students still see all the global built-in lessons." />
    </>
  );
}

// ─── Quizzes ─────────────────────────────────────────────────────────────────
interface QDraft {
  id?: string; title: string; description: string; difficulty: string; category: string; icon: string; estimatedMinutes: number;
  questions: { question: string; options: string[]; answer: number; explanation: string; xp: number }[];
}
const emptyQuestion = () => ({ question: "", options: ["", ""], answer: 0, explanation: "", xp: 10 });
const emptyQuiz = (): QDraft => ({
  title: "", description: "", difficulty: "Beginner", category: "", icon: "📝", estimatedMinutes: 5,
  questions: [emptyQuestion()],
});
function rowToQuizDraft(r: Row): QDraft {
  const c = r.content as Record<string, unknown>;
  const qs = Array.isArray(c.questions) ? c.questions as Record<string, unknown>[] : [];
  return {
    id: r.id,
    title: String(c.title ?? ""), description: String(c.description ?? ""), difficulty: String(c.difficulty ?? "Beginner"),
    category: String(c.category ?? ""), icon: String(c.icon ?? "📝"), estimatedMinutes: Number(c.estimatedMinutes ?? 5),
    questions: qs.length ? qs.map(q => ({
      question: String(q.question ?? ""),
      options: Array.isArray(q.options) ? (q.options as string[]).map(String) : ["", ""],
      answer: Number(q.answer ?? 0), explanation: String(q.explanation ?? ""), xp: Number(q.xp ?? 10),
    })) : [emptyQuestion()],
  };
}

function QuizzesTab() {
  const { items, error, notice, rowBusy, setError, save, setStatus, remove } = useOrgContent("quizzes");
  const [draft, setDraft] = useState<QDraft | null>(null);
  const [busy, setBusy] = useState(false);

  function up<K extends keyof QDraft>(k: K, v: QDraft[K]) { setDraft(d => d ? { ...d, [k]: v } : d); }
  function upQ(i: number, patch: Partial<QDraft["questions"][number]>) {
    setDraft(d => d ? { ...d, questions: d.questions.map((q, j) => j === i ? { ...q, ...patch } : q) } : d);
  }
  function upOpt(qi: number, oi: number, v: string) {
    setDraft(d => d ? { ...d, questions: d.questions.map((q, j) => j === qi ? { ...q, options: q.options.map((o, k) => k === oi ? v : o) } : q) } : d);
  }

  async function submit(status: "draft" | "published") {
    if (!draft) return;
    setBusy(true);
    const ok = await save({ ...draft, status });
    setBusy(false);
    if (ok) setDraft(null);
  }

  if (draft) {
    return (
      <div className="mt-3 space-y-3 rounded-lg border border-cyber-500/30 bg-bg-elevated p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">{draft.id ? "Edit quiz" : "New quiz"}</h3>
          <button onClick={() => setDraft(null)} className="rounded p-1 text-slate-400 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <Banner error={error} notice={null} />
        <div><label className={labelCls}>Title</label><input className={inputCls} value={draft.title} onChange={e => up("title", e.target.value)} placeholder="e.g. Phishing triage fundamentals" /></div>
        <div><label className={labelCls}>Description</label><input className={inputCls} value={draft.description} onChange={e => up("description", e.target.value)} placeholder="One line shown on the quiz card." /></div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div><label className={labelCls}>Difficulty</label>
            <select className={inputCls} value={draft.difficulty} onChange={e => up("difficulty", e.target.value)}>
              <option>Beginner</option><option>Intermediate</option><option>Advanced</option>
            </select>
          </div>
          <div><label className={labelCls}>Category</label><input className={inputCls} value={draft.category} onChange={e => up("category", e.target.value)} placeholder="Email security" /></div>
          <div><label className={labelCls}>Icon</label><input className={inputCls} value={draft.icon} onChange={e => up("icon", e.target.value)} placeholder="📝" /></div>
          <div><label className={labelCls}>Minutes</label><input type="number" className={inputCls} value={draft.estimatedMinutes} onChange={e => up("estimatedMinutes", Number(e.target.value))} /></div>
        </div>

        <div>
          <label className={labelCls}>Questions</label>
          <div className="space-y-3">
            {draft.questions.map((q, qi) => (
              <div key={qi} className="rounded border border-border bg-bg p-3 space-y-2">
                <div className="flex items-start gap-2">
                  <textarea className={cn(inputCls, "min-h-[44px]")} value={q.question} onChange={e => upQ(qi, { question: e.target.value })} placeholder={`Question ${qi + 1}`} />
                  {draft.questions.length > 1 && (
                    <button onClick={() => up("questions", draft.questions.filter((_, j) => j !== qi))} className="mt-1 rounded p-1.5 text-slate-400 hover:text-severity-high" title="Remove question"><Trash2 className="h-4 w-4" /></button>
                  )}
                </div>
                <p className="text-[10px] text-slate-500">Select the radio next to the correct answer.</p>
                <div className="space-y-1.5">
                  {q.options.map((o, oi) => (
                    <div key={oi} className="flex items-center gap-2">
                      <input type="radio" name={`correct-${qi}`} checked={q.answer === oi} onChange={() => upQ(qi, { answer: oi })} className="accent-cyber-500" title="Mark correct" />
                      <input className={inputCls} value={o} onChange={e => upOpt(qi, oi, e.target.value)} placeholder={`Option ${oi + 1}`} />
                      {q.options.length > 2 && (
                        <button onClick={() => upQ(qi, { options: q.options.filter((_, k) => k !== oi), answer: q.answer > oi ? q.answer - 1 : q.answer })} className="rounded p-1 text-slate-400 hover:text-severity-high" title="Remove option"><X className="h-3.5 w-3.5" /></button>
                      )}
                    </div>
                  ))}
                </div>
                {q.options.length < 6 && (
                  <Button variant="ghost" size="sm" onClick={() => upQ(qi, { options: [...q.options, ""] })}><Plus className="h-3.5 w-3.5" /> Add option</Button>
                )}
                <textarea className={cn(inputCls, "min-h-[40px]")} value={q.explanation} onChange={e => upQ(qi, { explanation: e.target.value })} placeholder="Explanation shown after answering (optional)." />
              </div>
            ))}
          </div>
          <Button variant="outline" size="sm" className="mt-2" onClick={() => up("questions", [...draft.questions, emptyQuestion()])}>
            <Plus className="h-4 w-4" /> Add question
          </Button>
        </div>

        <div className="flex items-center gap-2 pt-1">
          <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("published")}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />} Publish</Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => submit("draft")}>Save draft</Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Banner error={error} notice={notice} />
      <div className="mt-3 mb-3">
        <Button variant="outline" size="sm" onClick={() => { setError(null); setDraft(emptyQuiz()); }}><Plus className="h-4 w-4" /> New quiz</Button>
      </div>
      <ItemList items={items} rowBusy={rowBusy}
        onEdit={r => { setError(null); setDraft(rowToQuizDraft(r)); }}
        onToggle={r => setStatus(r.id, r.status === "published" ? "draft" : "published")}
        onDelete={r => remove(r.id, String(r.content?.title ?? r.id))}
        emptyLabel="No quizzes authored yet. Your students still see all the global built-in quizzes." />
    </>
  );
}

// ─── shared event-list editor (used by the Environments tab) ─────────────────
interface CEvent { offsetMin: number; source: string; eventType: string; description: string; rawText: string; mitreTechnique?: string }
const emptyCEvent = (): CEvent => ({ offsetMin: 0, source: "edr", eventType: "process_create", description: "", rawText: "" });

function EventListEditor({ events, onChange, withMitre }: { events: CEvent[]; onChange: (e: CEvent[]) => void; withMitre?: boolean }) {
  const upd = (i: number, patch: Partial<CEvent>) => onChange(events.map((e, j) => j === i ? { ...e, ...patch } : e));
  return (
    <div>
      <div className="space-y-3">
        {events.map((ev, i) => (
          <div key={i} className="rounded border border-border bg-bg p-3 space-y-2">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div><span className="text-[10px] text-slate-500">+min</span><input type="number" className={inputCls} value={ev.offsetMin} onChange={e => upd(i, { offsetMin: Number(e.target.value) })} /></div>
              <div><span className="text-[10px] text-slate-500">source</span>
                <select className={inputCls} value={ev.source} onChange={e => upd(i, { source: e.target.value })}>{LOG_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}</select>
              </div>
              <div className="sm:col-span-2"><span className="text-[10px] text-slate-500">event type</span>
                <select className={inputCls} value={ev.eventType} onChange={e => upd(i, { eventType: e.target.value })}>{EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}</select>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <input className={inputCls} value={ev.description} onChange={e => upd(i, { description: e.target.value })} placeholder="Analyst-facing summary of this log line" />
              {events.length > 1 && <button onClick={() => onChange(events.filter((_, j) => j !== i))} className="rounded p-1.5 text-slate-400 hover:text-severity-high"><Trash2 className="h-4 w-4" /></button>}
            </div>
            {withMitre && <input className={inputCls} value={ev.mitreTechnique ?? ""} onChange={e => upd(i, { mitreTechnique: e.target.value })} placeholder="MITRE technique (optional, e.g. T1059.001)" />}
            <textarea className={cn(inputCls, "min-h-[36px] font-mono text-xs")} value={ev.rawText} onChange={e => upd(i, { rawText: e.target.value })} placeholder={"raw fields, one per line — e.g.\nsrc_ip: 10.0.0.5"} />
          </div>
        ))}
      </div>
      <Button variant="outline" size="sm" className="mt-2" onClick={() => onChange([...events, emptyCEvent()])}><Plus className="h-4 w-4" /> Add event</Button>
    </div>
  );
}

// ─── Scenarios ───────────────────────────────────────────────────────────────
interface SEvent { offsetMin: number; source: string; eventType: string; description: string; rawText: string }
interface SQuestion { prompt: string; kind: "single" | "multi"; options: string[]; correct: number[]; xp: number; explanation: string }
interface SDraft {
  id?: string; title: string; difficulty: string; isBenign: boolean; attackKindLabel: string; threatActor: string;
  briefing: string; narrative: string; learningObjectives: string;
  events: SEvent[]; iocs: { type: string; value: string }[]; questions: SQuestion[];
}
const emptySEvent = (): SEvent => ({ offsetMin: 0, source: "edr", eventType: "process_create", description: "", rawText: "" });
const emptySQuestion = (): SQuestion => ({ prompt: "", kind: "single", options: ["", ""], correct: [0], xp: 50, explanation: "" });
const emptyScenario = (): SDraft => ({
  title: "", difficulty: "intermediate", isBenign: false, attackKindLabel: "", threatActor: "",
  briefing: "", narrative: "", learningObjectives: "",
  events: [emptySEvent()], iocs: [], questions: [emptySQuestion()],
});

function ScenariosTab() {
  const { items, error, notice, rowBusy, setError, save, setStatus, remove } = useOrgContent("scenarios");
  const [draft, setDraft] = useState<SDraft | null>(null);
  const [busy, setBusy] = useState(false);

  function up<K extends keyof SDraft>(k: K, v: SDraft[K]) { setDraft(d => d ? { ...d, [k]: v } : d); }
  function upEvent(i: number, patch: Partial<SEvent>) { setDraft(d => d ? { ...d, events: d.events.map((e, j) => j === i ? { ...e, ...patch } : e) } : d); }
  function upQ(i: number, patch: Partial<SQuestion>) { setDraft(d => d ? { ...d, questions: d.questions.map((q, j) => j === i ? { ...q, ...patch } : q) } : d); }
  function upQOpt(qi: number, oi: number, v: string) { setDraft(d => d ? { ...d, questions: d.questions.map((q, j) => j === qi ? { ...q, options: q.options.map((o, k) => k === oi ? v : o) } : q) } : d); }
  function upIoc(i: number, patch: Partial<{ type: string; value: string }>) { setDraft(d => d ? { ...d, iocs: d.iocs.map((x, j) => j === i ? { ...x, ...patch } : x) } : d); }

  async function loadForEdit(id: string) {
    setError(null);
    const res = await fetch(`/api/org/content/scenarios/${encodeURIComponent(id)}`);
    if (!res.ok) { setError("Could not load scenario."); return; }
    const { item, answer_key } = await res.json();
    const c = (item?.content ?? {}) as Record<string, unknown>;
    const k = (answer_key ?? {}) as Record<string, unknown>;
    const evs = Array.isArray(c.events) ? c.events as Record<string, unknown>[] : [];
    const base = evs.length ? new Date(String(evs[0].ts)).getTime() : 0;
    const safeQs = Array.isArray(c.questions) ? c.questions as Record<string, unknown>[] : [];
    const keyQs = Array.isArray(k.questions) ? k.questions as Record<string, unknown>[] : [];
    const keyById = new Map(keyQs.map(q => [String(q.id), q]));
    setDraft({
      id: String(item.id),
      title: String(c.title ?? ""), difficulty: String(c.difficulty ?? "intermediate"),
      isBenign: k.attack_kind === "false_positive",
      attackKindLabel: k.attack_kind === "false_positive" ? "" : String(k.attack_kind ?? ""),
      threatActor: String(k.threat_actor ?? ""),
      briefing: String(c.briefing ?? ""), narrative: String(k.narrative ?? ""),
      learningObjectives: (Array.isArray(k.learning_objectives) ? k.learning_objectives as string[] : []).join("\n"),
      events: evs.length ? evs.map(e => ({
        offsetMin: base ? Math.round((new Date(String(e.ts)).getTime() - base) / 60000) : 0,
        source: String(e.source ?? "edr"), eventType: String(e.event_type ?? "process_create"),
        description: String(e.description ?? ""),
        rawText: Object.entries((e.raw ?? {}) as Record<string, unknown>).map(([kk, vv]) => `${kk}: ${vv}`).join("\n"),
      })) : [emptySEvent()],
      iocs: (Array.isArray(k.iocs) ? k.iocs as Record<string, unknown>[] : []).map(x => ({ type: String(x.type ?? "ip"), value: String(x.value ?? "") })),
      questions: safeQs.length ? safeQs.map(q => {
        const opts = Array.isArray(q.options) ? q.options as { value: string; label: string }[] : [];
        const kq = keyById.get(String(q.id));
        const ans = kq?.answer;
        const ansArr = Array.isArray(ans) ? ans as string[] : ans != null ? [String(ans)] : [];
        const correct = ansArr.map(v => opts.findIndex(o => o.value === v)).filter(i => i >= 0);
        return {
          prompt: String(q.prompt ?? ""), kind: q.kind === "multi" ? "multi" as const : "single" as const,
          options: opts.map(o => o.label), correct: correct.length ? correct : [0],
          xp: Number(q.xp ?? 50), explanation: String(kq?.explanation ?? ""),
        };
      }) : [emptySQuestion()],
    });
  }

  function setCorrect(qi: number, oi: number, kind: "single" | "multi") {
    setDraft(d => {
      if (!d) return d;
      return {
        ...d, questions: d.questions.map((q, j) => {
          if (j !== qi) return q;
          if (kind === "single") return { ...q, correct: [oi] };
          const has = q.correct.includes(oi);
          return { ...q, correct: has ? q.correct.filter(x => x !== oi) : [...q.correct, oi] };
        }),
      };
    });
  }

  async function submit(status: "draft" | "published") {
    if (!draft) return;
    setBusy(true);
    const ok = await save({
      id: draft.id, status,
      title: draft.title, difficulty: draft.difficulty, isBenign: draft.isBenign,
      attackKindLabel: draft.attackKindLabel, threatActor: draft.threatActor,
      briefing: draft.briefing, narrative: draft.narrative,
      learningObjectives: draft.learningObjectives.split("\n").map(s => s.trim()).filter(Boolean),
      events: draft.events,
      iocs: draft.iocs.filter(x => x.value.trim()),
      questions: draft.questions,
    });
    setBusy(false);
    if (ok) setDraft(null);
  }

  if (draft) {
    return (
      <div className="mt-3 space-y-3 rounded-lg border border-cyber-500/30 bg-bg-elevated p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">{draft.id ? "Edit scenario" : "New scenario"}</h3>
          <button onClick={() => setDraft(null)} className="rounded p-1 text-slate-400 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <Banner error={error} notice={null} />
        <div><label className={labelCls}>Title</label><input className={inputCls} value={draft.title} onChange={e => up("title", e.target.value)} placeholder="e.g. After-hours data staging on the file server" /></div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <div><label className={labelCls}>Difficulty</label>
            <select className={inputCls} value={draft.difficulty} onChange={e => up("difficulty", e.target.value)}>
              <option value="beginner">Beginner</option><option value="intermediate">Intermediate</option><option value="advanced">Advanced</option><option value="expert">Expert</option>
            </select>
          </div>
          <div><label className={labelCls}>Verdict truth</label>
            <select className={inputCls} value={draft.isBenign ? "benign" : "attack"} onChange={e => up("isBenign", e.target.value === "benign")}>
              <option value="attack">Real attack</option><option value="benign">Benign (false positive)</option>
            </select>
          </div>
          {!draft.isBenign && (
            <div><label className={labelCls}>Attack kind</label><input className={inputCls} value={draft.attackKindLabel} onChange={e => up("attackKindLabel", e.target.value)} placeholder="ransomware" /></div>
          )}
        </div>
        <div><label className={labelCls}>Threat actor (answer key)</label><input className={inputCls} value={draft.threatActor} onChange={e => up("threatActor", e.target.value)} placeholder="e.g. FIN7 affiliate — leave blank if benign" /></div>
        <div><label className={labelCls}>Briefing (what the analyst first sees)</label><textarea className={cn(inputCls, "min-h-[64px]")} value={draft.briefing} onChange={e => up("briefing", e.target.value)} placeholder="The alert / ticket text. No spoilers." /></div>
        <div><label className={labelCls}>Debrief narrative (answer key)</label><textarea className={cn(inputCls, "min-h-[64px]")} value={draft.narrative} onChange={e => up("narrative", e.target.value)} placeholder="What actually happened, revealed only after a full attempt." /></div>
        <div><label className={labelCls}>Learning objectives (one per line)</label><textarea className={cn(inputCls, "min-h-[48px]")} value={draft.learningObjectives} onChange={e => up("learningObjectives", e.target.value)} /></div>

        {/* Events */}
        <div>
          <label className={labelCls}>Telemetry events (the logs to investigate)</label>
          <div className="space-y-3">
            {draft.events.map((ev, i) => (
              <div key={i} className="rounded border border-border bg-bg p-3 space-y-2">
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <div><span className="text-[10px] text-slate-500">+min</span><input type="number" className={inputCls} value={ev.offsetMin} onChange={e => upEvent(i, { offsetMin: Number(e.target.value) })} /></div>
                  <div className="sm:col-span-1"><span className="text-[10px] text-slate-500">source</span>
                    <select className={inputCls} value={ev.source} onChange={e => upEvent(i, { source: e.target.value })}>{LOG_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}</select>
                  </div>
                  <div className="sm:col-span-2"><span className="text-[10px] text-slate-500">event type</span>
                    <select className={inputCls} value={ev.eventType} onChange={e => upEvent(i, { eventType: e.target.value })}>{EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}</select>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <input className={inputCls} value={ev.description} onChange={e => upEvent(i, { description: e.target.value })} placeholder="Analyst-facing summary of this log line" />
                  {draft.events.length > 1 && <button onClick={() => up("events", draft.events.filter((_, j) => j !== i))} className="rounded p-1.5 text-slate-400 hover:text-severity-high"><Trash2 className="h-4 w-4" /></button>}
                </div>
                <textarea className={cn(inputCls, "min-h-[40px] font-mono text-xs")} value={ev.rawText} onChange={e => upEvent(i, { rawText: e.target.value })} placeholder={"raw fields, one per line — e.g.\nprocess.name: powershell.exe\nsrc_ip: 10.0.0.5"} />
              </div>
            ))}
          </div>
          <Button variant="outline" size="sm" className="mt-2" onClick={() => up("events", [...draft.events, emptySEvent()])}><Plus className="h-4 w-4" /> Add event</Button>
        </div>

        {/* IOCs */}
        <div>
          <label className={labelCls}>IOCs (grading truth — the indicators that matter)</label>
          <div className="space-y-2">
            {draft.iocs.map((io, i) => (
              <div key={i} className="flex items-center gap-2">
                <select className={cn(inputCls, "max-w-[120px]")} value={io.type} onChange={e => upIoc(i, { type: e.target.value })}>{IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}</select>
                <input className={inputCls} value={io.value} onChange={e => upIoc(i, { value: e.target.value })} placeholder="value (must also appear in an event above)" />
                <button onClick={() => up("iocs", draft.iocs.filter((_, j) => j !== i))} className="rounded p-1 text-slate-400 hover:text-severity-high"><X className="h-3.5 w-3.5" /></button>
              </div>
            ))}
          </div>
          <Button variant="ghost" size="sm" className="mt-1" onClick={() => up("iocs", [...draft.iocs, { type: "ip", value: "" }])}><Plus className="h-3.5 w-3.5" /> Add IOC</Button>
        </div>

        {/* Questions */}
        <div>
          <label className={labelCls}>Questions</label>
          <div className="space-y-3">
            {draft.questions.map((q, qi) => (
              <div key={qi} className="rounded border border-border bg-bg p-3 space-y-2">
                <div className="flex items-start gap-2">
                  <textarea className={cn(inputCls, "min-h-[44px]")} value={q.prompt} onChange={e => upQ(qi, { prompt: e.target.value })} placeholder={`Question ${qi + 1}`} />
                  <select className={cn(inputCls, "max-w-[110px]")} value={q.kind} onChange={e => upQ(qi, { kind: e.target.value as "single" | "multi", correct: [] })}>
                    <option value="single">Single</option><option value="multi">Multi</option>
                  </select>
                  {draft.questions.length > 1 && <button onClick={() => up("questions", draft.questions.filter((_, j) => j !== qi))} className="mt-1 rounded p-1.5 text-slate-400 hover:text-severity-high"><Trash2 className="h-4 w-4" /></button>}
                </div>
                <p className="text-[10px] text-slate-500">Mark the correct {q.kind === "multi" ? "answers" : "answer"}.</p>
                <div className="space-y-1.5">
                  {q.options.map((o, oi) => (
                    <div key={oi} className="flex items-center gap-2">
                      <input type={q.kind === "multi" ? "checkbox" : "radio"} name={`s-correct-${qi}`} checked={q.correct.includes(oi)} onChange={() => setCorrect(qi, oi, q.kind)} className="accent-cyber-500" />
                      <input className={inputCls} value={o} onChange={e => upQOpt(qi, oi, e.target.value)} placeholder={`Option ${oi + 1}`} />
                      {q.options.length > 2 && <button onClick={() => upQ(qi, { options: q.options.filter((_, k) => k !== oi), correct: q.correct.filter(x => x !== oi).map(x => x > oi ? x - 1 : x) })} className="rounded p-1 text-slate-400 hover:text-severity-high"><X className="h-3.5 w-3.5" /></button>}
                    </div>
                  ))}
                </div>
                {q.options.length < 6 && <Button variant="ghost" size="sm" onClick={() => upQ(qi, { options: [...q.options, ""] })}><Plus className="h-3.5 w-3.5" /> Add option</Button>}
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-500">XP</span>
                  <input type="number" className={cn(inputCls, "max-w-[90px]")} value={q.xp} onChange={e => upQ(qi, { xp: Number(e.target.value) })} />
                </div>
                <textarea className={cn(inputCls, "min-h-[40px]")} value={q.explanation} onChange={e => upQ(qi, { explanation: e.target.value })} placeholder="Explanation shown after answering (optional)." />
              </div>
            ))}
          </div>
          <Button variant="outline" size="sm" className="mt-2" onClick={() => up("questions", [...draft.questions, emptySQuestion()])}><Plus className="h-4 w-4" /> Add question</Button>
        </div>

        <div className="flex items-center gap-2 pt-1">
          <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("published")}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />} Publish</Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => submit("draft")}>Save draft</Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Banner error={error} notice={notice} />
      <div className="mt-3 mb-3">
        <Button variant="outline" size="sm" onClick={() => { setError(null); setDraft(emptyScenario()); }}><Plus className="h-4 w-4" /> New scenario</Button>
      </div>
      <ItemList items={items} rowBusy={rowBusy}
        onEdit={r => loadForEdit(r.id)}
        onToggle={r => setStatus(r.id, r.status === "published" ? "draft" : "published")}
        onDelete={r => remove(r.id, String(r.content?.title ?? r.id))}
        emptyLabel="No scenarios authored yet. Your students still see all the global built-in scenarios." />
    </>
  );
}

// ─── Rooms ───────────────────────────────────────────────────────────────────
type RTaskKind = "reading" | "question" | "flag";
interface RTask {
  kind: RTaskKind;
  // reading
  heading?: string; body?: string; codeExample?: string;
  // question
  question?: string; options?: string[]; correct?: number; explanation?: string;
  // flag
  prompt?: string; answer?: string; hint?: string;
  xp?: number;
}
interface RDraft {
  id?: string; title: string; description: string; difficulty: string; category: string; icon: string; estimatedMinutes: number;
  tasks: RTask[];
}
const emptyRTask = (kind: RTaskKind): RTask =>
  kind === "reading" ? { kind, heading: "", body: "", codeExample: "", xp: 5 }
  : kind === "question" ? { kind, question: "", options: ["", ""], correct: 0, explanation: "", xp: 25 }
  : { kind, prompt: "", answer: "", hint: "", xp: 25 };
const emptyRoom = (): RDraft => ({
  title: "", description: "", difficulty: "beginner", category: "Custom", icon: "🎓", estimatedMinutes: 15,
  tasks: [emptyRTask("reading")],
});

function RoomsTab() {
  const { items, error, notice, rowBusy, setError, save, setStatus, remove } = useOrgContent("rooms");
  const [draft, setDraft] = useState<RDraft | null>(null);
  const [busy, setBusy] = useState(false);

  function up<K extends keyof RDraft>(k: K, v: RDraft[K]) { setDraft(d => d ? { ...d, [k]: v } : d); }
  function upTask(i: number, patch: Partial<RTask>) { setDraft(d => d ? { ...d, tasks: d.tasks.map((t, j) => j === i ? { ...t, ...patch } : t) } : d); }
  function upOpt(ti: number, oi: number, v: string) {
    setDraft(d => d ? { ...d, tasks: d.tasks.map((t, j) => j === ti ? { ...t, options: (t.options ?? []).map((o, k) => k === oi ? v : o) } : t) } : d);
  }

  async function loadForEdit(id: string) {
    setError(null);
    const res = await fetch(`/api/org/content/rooms/${encodeURIComponent(id)}`);
    if (!res.ok) { setError("Could not load room."); return; }
    const { item, answer_key } = await res.json();
    const c = (item?.content ?? {}) as Record<string, unknown>;
    const keyTasks = ((answer_key ?? {}) as Record<string, unknown>).tasks as Record<string, Record<string, unknown>> ?? {};
    const safeTasks = Array.isArray(c.tasks) ? c.tasks as Record<string, unknown>[] : [];
    setDraft({
      id: String(item.id),
      title: String(c.title ?? ""), description: String(c.description ?? ""), difficulty: String(c.difficulty ?? "beginner"),
      category: String(c.category ?? "Custom"), icon: String(c.icon ?? "🎓"), estimatedMinutes: Number(c.estimatedMinutes ?? 15),
      tasks: safeTasks.map(s => {
        const tid = String(s.id); const k = keyTasks[tid] ?? {};
        if (s.type === "reading") return { kind: "reading" as const, heading: String(s.heading ?? ""), body: String(s.content ?? ""), codeExample: String(s.codeExample ?? ""), xp: Number(s.xp ?? 5) };
        if (s.type === "flag") return { kind: "flag" as const, prompt: String(s.prompt ?? ""), answer: String(k.answer ?? ""), hint: String(s.hint ?? ""), xp: Number(s.xp ?? 25) };
        return { kind: "question" as const, question: String(s.question ?? ""), options: (s.options as string[]) ?? ["", ""], correct: Number(k.answer ?? 0), explanation: String(k.explanation ?? ""), xp: Number(s.xp ?? 25) };
      }),
    });
  }

  async function submit(status: "draft" | "published") {
    if (!draft) return;
    setBusy(true);
    const ok = await save({
      id: draft.id, status,
      title: draft.title, description: draft.description, difficulty: draft.difficulty,
      category: draft.category, icon: draft.icon, estimatedMinutes: draft.estimatedMinutes,
      tasks: draft.tasks.map(t =>
        t.kind === "reading" ? { kind: "reading", heading: t.heading, content: t.body, codeExample: t.codeExample, xp: t.xp }
        : t.kind === "question" ? { kind: "question", question: t.question, options: t.options, correct: t.correct, explanation: t.explanation, xp: t.xp }
        : { kind: "flag", prompt: t.prompt, answer: t.answer, hint: t.hint, xp: t.xp }),
    });
    setBusy(false);
    if (ok) setDraft(null);
  }

  if (draft) {
    return (
      <div className="mt-3 space-y-3 rounded-lg border border-cyber-500/30 bg-bg-elevated p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">{draft.id ? "Edit room" : "New room"}</h3>
          <button onClick={() => setDraft(null)} className="rounded p-1 text-slate-400 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <Banner error={error} notice={null} />
        <div><label className={labelCls}>Title</label><input className={inputCls} value={draft.title} onChange={e => up("title", e.target.value)} placeholder="e.g. Reading Windows logon events" /></div>
        <div><label className={labelCls}>Description</label><input className={inputCls} value={draft.description} onChange={e => up("description", e.target.value)} placeholder="One line shown on the room card." /></div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div><label className={labelCls}>Difficulty</label>
            <select className={inputCls} value={draft.difficulty} onChange={e => up("difficulty", e.target.value)}>
              <option value="beginner">Beginner</option><option value="intermediate">Intermediate</option><option value="advanced">Advanced</option>
            </select>
          </div>
          <div><label className={labelCls}>Category</label><input className={inputCls} value={draft.category} onChange={e => up("category", e.target.value)} /></div>
          <div><label className={labelCls}>Icon</label><input className={inputCls} value={draft.icon} onChange={e => up("icon", e.target.value)} placeholder="🎓" /></div>
          <div><label className={labelCls}>Minutes</label><input type="number" className={inputCls} value={draft.estimatedMinutes} onChange={e => up("estimatedMinutes", Number(e.target.value))} /></div>
        </div>

        <div>
          <label className={labelCls}>Tasks</label>
          <div className="space-y-3">
            {draft.tasks.map((t, i) => (
              <div key={i} className="rounded border border-border bg-bg p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="rounded bg-cyber-500/10 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-cyber-300">{t.kind}</span>
                  {draft.tasks.length > 1 && <button onClick={() => up("tasks", draft.tasks.filter((_, j) => j !== i))} className="rounded p-1 text-slate-400 hover:text-severity-high" title="Remove task"><Trash2 className="h-4 w-4" /></button>}
                </div>
                {t.kind === "reading" && (<>
                  <input className={inputCls} value={t.heading ?? ""} onChange={e => upTask(i, { heading: e.target.value })} placeholder="Section heading" />
                  <textarea className={cn(inputCls, "min-h-[72px]")} value={t.body ?? ""} onChange={e => upTask(i, { body: e.target.value })} placeholder="Reading content (Markdown supported)." />
                  <textarea className={cn(inputCls, "min-h-[40px] font-mono text-xs")} value={t.codeExample ?? ""} onChange={e => upTask(i, { codeExample: e.target.value })} placeholder="Optional code / log block" />
                </>)}
                {t.kind === "question" && (<>
                  <textarea className={cn(inputCls, "min-h-[40px]")} value={t.question ?? ""} onChange={e => upTask(i, { question: e.target.value })} placeholder="Question" />
                  <p className="text-[10px] text-slate-500">Select the radio next to the correct answer.</p>
                  <div className="space-y-1.5">
                    {(t.options ?? []).map((o, oi) => (
                      <div key={oi} className="flex items-center gap-2">
                        <input type="radio" name={`r-correct-${i}`} checked={t.correct === oi} onChange={() => upTask(i, { correct: oi })} className="accent-cyber-500" />
                        <input className={inputCls} value={o} onChange={e => upOpt(i, oi, e.target.value)} placeholder={`Option ${oi + 1}`} />
                        {(t.options ?? []).length > 2 && <button onClick={() => upTask(i, { options: (t.options ?? []).filter((_, k) => k !== oi), correct: (t.correct ?? 0) > oi ? (t.correct ?? 0) - 1 : t.correct })} className="rounded p-1 text-slate-400 hover:text-severity-high"><X className="h-3.5 w-3.5" /></button>}
                      </div>
                    ))}
                  </div>
                  {(t.options ?? []).length < 6 && <Button variant="ghost" size="sm" onClick={() => upTask(i, { options: [...(t.options ?? []), ""] })}><Plus className="h-3.5 w-3.5" /> Add option</Button>}
                  <textarea className={cn(inputCls, "min-h-[40px]")} value={t.explanation ?? ""} onChange={e => upTask(i, { explanation: e.target.value })} placeholder="Explanation shown after answering." />
                </>)}
                {t.kind === "flag" && (<>
                  <textarea className={cn(inputCls, "min-h-[40px]")} value={t.prompt ?? ""} onChange={e => upTask(i, { prompt: e.target.value })} placeholder="Prompt — what value should the analyst find?" />
                  <input className={inputCls} value={t.answer ?? ""} onChange={e => upTask(i, { answer: e.target.value })} placeholder="Exact flag value (matched case-insensitively)" />
                  <input className={inputCls} value={t.hint ?? ""} onChange={e => upTask(i, { hint: e.target.value })} placeholder="Optional hint" />
                </>)}
                {t.kind !== "reading" && (
                  <div className="flex items-center gap-2"><span className="text-[10px] text-slate-500">XP</span>
                    <input type="number" className={cn(inputCls, "max-w-[90px]")} value={t.xp ?? 25} onChange={e => upTask(i, { xp: Number(e.target.value) })} /></div>
                )}
              </div>
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => up("tasks", [...draft.tasks, emptyRTask("reading")])}><Plus className="h-4 w-4" /> Reading</Button>
            <Button variant="outline" size="sm" onClick={() => up("tasks", [...draft.tasks, emptyRTask("question")])}><Plus className="h-4 w-4" /> Question</Button>
            <Button variant="outline" size="sm" onClick={() => up("tasks", [...draft.tasks, emptyRTask("flag")])}><Plus className="h-4 w-4" /> Flag</Button>
          </div>
        </div>

        <div className="flex items-center gap-2 pt-1">
          <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("published")}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />} Publish</Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => submit("draft")}>Save draft</Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Banner error={error} notice={notice} />
      <div className="mt-3 mb-3">
        <Button variant="outline" size="sm" onClick={() => { setError(null); setDraft(emptyRoom()); }}><Plus className="h-4 w-4" /> New room</Button>
      </div>
      <ItemList items={items} rowBusy={rowBusy}
        onEdit={r => loadForEdit(r.id)}
        onToggle={r => setStatus(r.id, r.status === "published" ? "draft" : "published")}
        onDelete={r => remove(r.id, String(r.content?.title ?? r.id))}
        emptyLabel="No rooms authored yet. Your students still see all the global built-in rooms." />
    </>
  );
}

// ─── Environments (live-feed companies) ──────────────────────────────────────
interface CoDraft {
  id?: string; name: string; industry: string; tagline: string; hq: string; size: number; description: string;
  sources: string[]; benignEvents: CEvent[]; storyTitle: string; storyMitre: string; storyEvents: CEvent[];
}
const emptyCompany = (): CoDraft => ({
  name: "", industry: "", tagline: "", hq: "", size: 500, description: "",
  sources: ["edr", "o365", "firewall"], benignEvents: [emptyCEvent()],
  storyTitle: "", storyMitre: "", storyEvents: [emptyCEvent()],
});
function toCEvents(raw: unknown): CEvent[] {
  const evs = Array.isArray(raw) ? raw as Record<string, unknown>[] : [];
  if (!evs.length) return [emptyCEvent()];
  const base = new Date(String(evs[0].ts)).getTime();
  return evs.map(e => ({
    offsetMin: base ? Math.round((new Date(String(e.ts)).getTime() - base) / 60000) : 0,
    source: String(e.source ?? "edr"), eventType: String(e.event_type ?? "process_create"),
    description: String(e.description ?? ""),
    rawText: Object.entries((e.raw ?? {}) as Record<string, unknown>).map(([k, v]) => `${k}: ${v}`).join("\n"),
    mitreTechnique: String(e.mitre_technique ?? "") || undefined,
  }));
}

function CompaniesTab() {
  const { items, error, notice, rowBusy, setError, save, setStatus, remove } = useOrgContent("companies");
  const [draft, setDraft] = useState<CoDraft | null>(null);
  const [busy, setBusy] = useState(false);
  function up<K extends keyof CoDraft>(k: K, v: CoDraft[K]) { setDraft(d => d ? { ...d, [k]: v } : d); }
  function toggleSource(s: string) { setDraft(d => d ? { ...d, sources: d.sources.includes(s) ? d.sources.filter(x => x !== s) : [...d.sources, s] } : d); }

  async function loadForEdit(id: string) {
    setError(null);
    const res = await fetch(`/api/org/content/companies/${encodeURIComponent(id)}`);
    if (!res.ok) { setError("Could not load environment."); return; }
    const { item } = await res.json();
    const c = (item?.content ?? {}) as Record<string, unknown>;
    const p = (c.profile ?? {}) as Record<string, unknown>;
    const arch = (p.architecture ?? {}) as Record<string, unknown>;
    const story = (c.story ?? {}) as Record<string, unknown>;
    setDraft({
      id: String(item.id),
      name: String(p.name ?? ""), industry: String(p.industry ?? ""), tagline: String(p.tagline ?? ""),
      hq: String(p.hq ?? ""), size: Number(p.size ?? 500), description: String(p.description ?? ""),
      sources: Array.isArray(arch.sources) ? arch.sources as string[] : [],
      benignEvents: toCEvents(c.benignEvents),
      storyTitle: String(story.title ?? ""),
      storyMitre: (Array.isArray(story.mitre) ? story.mitre as string[] : []).join(", "),
      storyEvents: toCEvents(story.events),
    });
  }

  async function submit(status: "draft" | "published") {
    if (!draft) return;
    setBusy(true);
    const ok = await save({
      id: draft.id, status,
      name: draft.name, industry: draft.industry, tagline: draft.tagline, hq: draft.hq, size: draft.size, description: draft.description,
      sources: draft.sources,
      benignEvents: draft.benignEvents,
      story: { title: draft.storyTitle, mitre: draft.storyMitre.split(",").map(s => s.trim()).filter(Boolean), events: draft.storyEvents },
    });
    setBusy(false);
    if (ok) setDraft(null);
  }

  if (draft) {
    return (
      <div className="mt-3 space-y-3 rounded-lg border border-cyber-500/30 bg-bg-elevated p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">{draft.id ? "Edit environment" : "New environment"}</h3>
          <button onClick={() => setDraft(null)} className="rounded p-1 text-slate-400 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <Banner error={error} notice={null} />
        <p className="text-[11px] text-slate-500">A custom company your students monitor in the SOC Dashboard live feed: its profile, its benign background noise, and one hidden attack story.</p>
        <div><label className={labelCls}>Company name</label><input className={inputCls} value={draft.name} onChange={e => up("name", e.target.value)} placeholder="e.g. Acme College Health" /></div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div><label className={labelCls}>Industry</label><input className={inputCls} value={draft.industry} onChange={e => up("industry", e.target.value)} placeholder="Healthcare" /></div>
          <div><label className={labelCls}>HQ</label><input className={inputCls} value={draft.hq} onChange={e => up("hq", e.target.value)} placeholder="Tel Aviv, IL" /></div>
          <div><label className={labelCls}>Employees</label><input type="number" className={inputCls} value={draft.size} onChange={e => up("size", Number(e.target.value))} /></div>
          <div><label className={labelCls}>Tagline</label><input className={inputCls} value={draft.tagline} onChange={e => up("tagline", e.target.value)} placeholder="short blurb" /></div>
        </div>
        <div><label className={labelCls}>Description</label><input className={inputCls} value={draft.description} onChange={e => up("description", e.target.value)} placeholder="One line about this environment." /></div>
        <div>
          <label className={labelCls}>Active log sources (drives the feed's source filter)</label>
          <div className="flex flex-wrap gap-1.5">
            {COMMON_LOG_SOURCES.map(s => (
              <button key={s} onClick={() => toggleSource(s)}
                className={cn("rounded border px-2 py-1 text-[11px] font-mono transition",
                  draft.sources.includes(s) ? "border-cyber-500/60 bg-cyber-500/15 text-cyber-300" : "border-border bg-bg text-slate-400 hover:text-slate-200")}>
                {s}
              </button>
            ))}
          </div>
        </div>
        <div><label className={labelCls}>Benign background events (the noise the analyst sifts through)</label>
          <EventListEditor events={draft.benignEvents} onChange={e => up("benignEvents", e)} />
        </div>
        <div className="rounded border border-severity-high/30 bg-severity-high/5 p-3 space-y-2">
          <label className={labelCls}>Hidden attack story</label>
          <input className={inputCls} value={draft.storyTitle} onChange={e => up("storyTitle", e.target.value)} placeholder="Attack title (the ground truth graded against the report)" />
          <input className={inputCls} value={draft.storyMitre} onChange={e => up("storyMitre", e.target.value)} placeholder="MITRE techniques, comma-separated (optional — else derived from events)" />
          <EventListEditor events={draft.storyEvents} onChange={e => up("storyEvents", e)} withMitre />
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("published")}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />} Publish</Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => submit("draft")}>Save draft</Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Banner error={error} notice={notice} />
      <div className="mt-3 mb-3">
        <Button variant="outline" size="sm" onClick={() => { setError(null); setDraft(emptyCompany()); }}><Plus className="h-4 w-4" /> New environment</Button>
      </div>
      <ItemList items={items} rowBusy={rowBusy}
        onEdit={r => loadForEdit(r.id)}
        onToggle={r => setStatus(r.id, r.status === "published" ? "draft" : "published")}
        onDelete={r => remove(r.id, String((r.content?.profile as Record<string, unknown>)?.name ?? r.content?.name ?? r.id))}
        emptyLabel="No custom environments yet. Your students still see all the global built-in companies in the live feed." />
    </>
  );
}

// ─── wrapper ─────────────────────────────────────────────────────────────────
export function ContentAuthoringPanel() {
  const [tab, setTab] = useState<ContentTab>("lessons");
  const TABS: { id: ContentTab; label: string; icon: typeof BookOpen }[] = [
    { id: "lessons", label: "Lessons", icon: BookOpen },
    { id: "quizzes", label: "Quizzes", icon: ClipboardList },
    { id: "scenarios", label: "Scenarios", icon: Target },
    { id: "rooms", label: "Rooms", icon: DoorOpen },
    { id: "companies", label: "Environments", icon: Building2 },
  ];
  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white">
        <Pencil className="h-4 w-4 text-cyber-300" /> Course Content
      </h2>
      <p className="mt-1 text-xs text-slate-400">
        Write lessons, quizzes, scenarios, rooms and live-feed environments unique to your college. Published items appear to your students alongside the global built-in content. Drafts are visible only to you.
      </p>

      <div className="mt-3 flex gap-1 border-b border-border">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setTab(id)}
            className={cn("flex items-center gap-1.5 px-3 py-2 text-xs font-semibold transition -mb-px border-b-2",
              tab === id ? "border-cyber-400 text-cyber-300" : "border-transparent text-slate-400 hover:text-slate-200")}>
            <Icon className="h-3.5 w-3.5" /> {label}
          </button>
        ))}
      </div>

      {tab === "lessons" ? <LessonsTab /> : tab === "quizzes" ? <QuizzesTab /> : tab === "scenarios" ? <ScenariosTab /> : tab === "rooms" ? <RoomsTab /> : <CompaniesTab />}
    </Card>
  );
}
