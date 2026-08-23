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
import {
  BookOpen, ClipboardList, Plus, Trash2, Eye, EyeOff, Pencil, Loader2, X, Target,
} from "lucide-react";

type ContentTab = "lessons" | "quizzes";

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

// ─── wrapper ─────────────────────────────────────────────────────────────────
export function ContentAuthoringPanel() {
  const [tab, setTab] = useState<ContentTab>("lessons");
  const TABS: { id: ContentTab; label: string; icon: typeof BookOpen }[] = [
    { id: "lessons", label: "Lessons", icon: BookOpen },
    { id: "quizzes", label: "Quizzes", icon: ClipboardList },
  ];
  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white">
        <Pencil className="h-4 w-4 text-cyber-300" /> Course Content
      </h2>
      <p className="mt-1 text-xs text-slate-400">
        Write lessons and quizzes unique to your college. Published items appear to your students alongside the global built-in content. Drafts are visible only to you.
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

      {tab === "lessons" ? <LessonsTab /> : <QuizzesTab />}

      <div className="mt-4 flex items-center gap-2 rounded border border-border bg-bg px-3 py-2 text-[11px] text-slate-500">
        <Target className="h-3.5 w-3.5 shrink-0" /> Scenario authoring (custom live investigations) is coming in a later phase.
      </div>
    </Card>
  );
}
