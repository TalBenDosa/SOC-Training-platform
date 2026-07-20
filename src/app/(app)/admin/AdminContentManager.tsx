"use client";
import { useState, useEffect } from "react";
import {
  Trash2, RotateCcw, BookOpen, Shield, HelpCircle, Zap,
  Loader2, ChevronDown, ChevronUp, Check, Eye, Plus,
  AlertTriangle, ExternalLink, FileText, Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { ALL_QUIZZES as QUIZZES } from "@/lib/quizzes/data";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import type { GeneratedLesson } from "@/app/api/lessons/generate/route";
import type { GeneratedQuiz } from "@/app/api/quizzes/generate/route";

// ─── Types ─────────────────────────────────────────────────────────────────────

type ContentTab = "scenarios" | "lessons" | "quizzes";

interface PublishedScenario {
  id: string;
  title: string;
  threat_actor: string;
  attack_kind: string;
  difficulty: string;
  published_at: string;
}

// Flat lesson record
interface FlatLesson {
  slug: string;
  title: string;
  kind: string;
  difficulty: string;
  topic: string;
  xp: number;
  min: number;
  pathTitle: string;
  moduleTitle: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TOPICS = [
  "MITRE ATT&CK",
  "Incident Response",
  "Log Analysis & SIEM",
  "Threat Intelligence",
  "Network Security",
  "Cloud Security",
  "Identity & Access Management",
  "Malware Analysis",
  "Forensics & DFIR",
  "SOC Operations",
];

const DIFFICULTY_BADGE: Record<string, string> = {
  beginner:     "bg-neon-green/10 text-neon-green border-neon-green/30",
  intermediate: "bg-neon-amber/10 text-neon-amber border-neon-amber/30",
  advanced:     "bg-severity-high/10 text-severity-high border-severity-high/30",
  expert:       "bg-severity-critical/10 text-severity-critical border-severity-critical/30",
  Beginner:     "bg-neon-green/10 text-neon-green border-neon-green/30",
  Intermediate: "bg-neon-amber/10 text-neon-amber border-neon-amber/30",
  Advanced:     "bg-severity-high/10 text-severity-high border-severity-high/30",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getAllLessons(): FlatLesson[] {
  return LESSON_PATHS.flatMap(path =>
    path.modules.flatMap(mod =>
      mod.lessons.map(l => ({
        slug: l.slug,
        title: l.title,
        kind: l.kind,
        difficulty: l.difficulty,
        topic: l.topic.split(",")[0].trim().slice(0, 40),
        xp: l.xp,
        min: l.min,
        pathTitle: path.title,
        moduleTitle: mod.title,
      }))
    )
  );
}

function kindIcon(kind: string) {
  if (kind === "quiz")       return "🎯";
  if (kind === "lab")        return "🧪";
  if (kind === "simulation") return "🖥";
  return "📖";
}

// ─── Sub-tab button ────────────────────────────────────────────────────────────

function SubTab({ active, onClick, icon, label, count }: {
  active: boolean; onClick: () => void; icon: React.ReactNode; label: string; count?: number;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 border-b-2 px-5 py-3 text-xs font-semibold uppercase tracking-wider transition-colors",
        active
          ? "border-cyber-500 text-white"
          : "border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600"
      )}
    >
      {icon}
      {label}
      {count !== undefined && (
        <span className={cn(
          "rounded-full px-1.5 py-0.5 text-[10px] font-bold",
          active ? "bg-cyber-500/30 text-cyber-300" : "bg-slate-700 text-slate-400"
        )}>{count}</span>
      )}
    </button>
  );
}

// ─── Delete-able row ──────────────────────────────────────────────────────────

function ContentRow({
  title, meta, hidden, generated, onHide, onRestore, onDelete,
}: {
  title: string;
  meta?: React.ReactNode;
  hidden?: boolean;
  generated?: boolean;
  onHide?: () => void;
  onRestore?: () => void;
  onDelete?: () => void;
}) {
  return (
    <div className={cn(
      "flex items-center gap-3 border-b border-border/40 px-4 py-2.5 transition-colors hover:bg-bg-hover/30",
      hidden && "opacity-50"
    )}>
      <div className="min-w-0 flex-1">
        <p className={cn("text-[12px] font-medium", hidden ? "text-slate-500 line-through" : "text-slate-200")}>{title}</p>
        {meta && <div className="mt-0.5 flex items-center gap-1.5">{meta}</div>}
      </div>
      {generated && (
        <span className="rounded border border-neon-green/30 bg-neon-green/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-neon-green">
          Generated
        </span>
      )}
      <div className="flex items-center gap-1">
        {hidden ? (
          <button
            onClick={onRestore}
            title="Restore"
            className="rounded p-1.5 text-slate-500 hover:bg-neon-green/10 hover:text-neon-green transition-colors"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        ) : (
          <button
            onClick={onHide}
            title="Delete / Hide"
            className="rounded p-1.5 text-slate-600 hover:bg-severity-critical/10 hover:text-severity-critical transition-colors"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        )}
        {generated && onDelete && (
          <button
            onClick={onDelete}
            title="Permanently delete"
            className="rounded p-1.5 text-slate-600 hover:bg-severity-critical/10 hover:text-severity-critical transition-colors"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Scenarios tab ────────────────────────────────────────────────────────────

function ScenariosTab({
  hidden, onHide, onRestore,
  published, onDeletePublished,
}: {
  hidden: string[];
  onHide: (slug: string) => void;
  onRestore: (slug: string) => void;
  published: PublishedScenario[];
  onDeletePublished: (id: string) => void;
}) {
  const totalVisible = SCENARIOS.filter(s => !hidden.includes(s.slug)).length;
  const totalHidden  = hidden.length;

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* Built-in scenarios */}
      <div className="border-b border-border/60 bg-[#0a0f1a] px-4 py-2.5 shrink-0 flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-2">
          <Shield className="h-3 w-3" /> Built-in Scenarios
          <span className="text-slate-600">({totalVisible} visible · {totalHidden} hidden)</span>
        </p>
        <span className="text-[10px] text-slate-600">Use the Scenario Generator tab to create new</span>
      </div>
      <div className="overflow-y-auto flex-1">
        {SCENARIOS.map(s => (
          <ContentRow
            key={s.slug}
            title={s.title}
            hidden={hidden.includes(s.slug)}
            meta={
              <>
                <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", DIFFICULTY_BADGE[s.difficulty] ?? DIFFICULTY_BADGE.beginner)}>
                  {s.difficulty}
                </span>
                <span className="text-[10px] text-slate-500">{s.attack_kind.replace(/_/g, " ")}</span>
                <span className="text-[10px] text-slate-600 truncate">{s.threat_actor}</span>
              </>
            }
            onHide={() => onHide(s.slug)}
            onRestore={() => onRestore(s.slug)}
          />
        ))}

        {/* Published / AI-generated scenarios */}
        {published.length > 0 && (
          <>
            <div className="border-b border-t border-border/60 bg-[#0a0f1a] px-4 py-2 shrink-0">
              <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-2">
                <Zap className="h-3 w-3 text-neon-green" /> AI-Generated & Published
                <span className="text-slate-600">({published.length})</span>
              </p>
            </div>
            {published.map(s => (
              <ContentRow
                key={s.id}
                title={s.title}
                generated
                meta={
                  <>
                    <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", DIFFICULTY_BADGE[s.difficulty] ?? DIFFICULTY_BADGE.beginner)}>
                      {s.difficulty}
                    </span>
                    <span className="text-[10px] text-slate-500">{s.attack_kind?.replace(/_/g, " ")}</span>
                    <span className="text-[10px] text-slate-600">{new Date(s.published_at).toLocaleDateString()}</span>
                  </>
                }
                onHide={() => onDeletePublished(s.id)}
                onDelete={() => onDeletePublished(s.id)}
              />
            ))}
          </>
        )}

        {published.length === 0 && (
          <p className="py-3 text-center text-xs text-slate-600">No AI-generated scenarios published yet. Use the Scenario Generator tab.</p>
        )}
      </div>
    </div>
  );
}

// ─── Lessons tab ──────────────────────────────────────────────────────────────

function LessonsTab({
  hidden, onHide, onRestore,
  generated, onDeleteGenerated,
}: {
  hidden: string[];
  onHide: (slug: string) => void;
  onRestore: (slug: string) => void;
  generated: GeneratedLesson[];
  onDeleteGenerated: (id: string) => void;
}) {
  const allLessons = getAllLessons();
  const [filterPath, setFilterPath] = useState<string>("all");
  const [showGenerator, setShowGenerator] = useState(true);
  const [form, setForm] = useState({
    title: "", topic: "MITRE ATT&CK", difficulty: "intermediate", syllabus: "", sections: 4,
  });
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<GeneratedLesson | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [published, setPublished] = useState<Set<string>>(new Set());

  const paths = ["all", ...Array.from(new Set(allLessons.map(l => l.pathTitle)))];
  const filtered = filterPath === "all" ? allLessons : allLessons.filter(l => l.pathTitle === filterPath);

  async function generate() {
    if (!form.title.trim()) { setError("Please enter a lesson title"); return; }
    setLoading(true); setError(null); setPreview(null);
    try {
      const res = await fetch("/api/lessons/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error ?? "Generation failed");
      setPreview(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  function publish(lesson: GeneratedLesson) {
    const existing: GeneratedLesson[] = JSON.parse(localStorage.getItem("generated_lessons") ?? "[]");
    localStorage.setItem("generated_lessons", JSON.stringify([lesson, ...existing]));
    setPublished(prev => new Set([...prev, lesson.id]));
    // also refresh parent via storage event would be ideal, for now just reload state
    window.location.reload();
  }

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* Generator */}
      <div className="shrink-0 border-b border-border/60">
        <button
          onClick={() => setShowGenerator(v => !v)}
          className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-bg-hover/30 transition-colors"
        >
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-2">
            <Plus className="h-3 w-3 text-cyber-300" />
            <span className="text-cyber-300">Lesson Generator</span>
            <span className="text-slate-600">— AI creates lesson from syllabus</span>
          </p>
          {showGenerator ? <ChevronUp className="h-3.5 w-3.5 text-slate-500" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-500" />}
        </button>

        {showGenerator && (
          <div className="px-4 pb-4 space-y-3 bg-[#060b12]">
            <div className="grid grid-cols-2 gap-3">
              {/* Title */}
              <div className="col-span-2">
                <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Lesson Title *</label>
                <input
                  type="text"
                  value={form.title}
                  onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                  placeholder="e.g. Detecting Lateral Movement with Sysmon"
                  className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/40 focus:outline-none"
                />
              </div>
              {/* Topic */}
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Topic</label>
                <select
                  value={form.topic}
                  onChange={e => setForm(f => ({ ...f, topic: e.target.value }))}
                  className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 focus:border-cyber-500/40 focus:outline-none"
                >
                  {TOPICS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              {/* Difficulty + Sections */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Difficulty</label>
                  <select
                    value={form.difficulty}
                    onChange={e => setForm(f => ({ ...f, difficulty: e.target.value }))}
                    className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 focus:border-cyber-500/40 focus:outline-none"
                  >
                    <option value="beginner">Beginner</option>
                    <option value="intermediate">Intermediate</option>
                    <option value="advanced">Advanced</option>
                    <option value="expert">Expert</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Sections</label>
                  <select
                    value={form.sections}
                    onChange={e => setForm(f => ({ ...f, sections: Number(e.target.value) }))}
                    className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 focus:border-cyber-500/40 focus:outline-none"
                  >
                    {[3,4,5,6,7].map(n => <option key={n} value={n}>{n} sections</option>)}
                  </select>
                </div>
              </div>
              {/* Syllabus */}
              <div className="col-span-2">
                <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">
                  Syllabus / Learning Objectives <span className="text-slate-600">(one per line)</span>
                </label>
                <textarea
                  value={form.syllabus}
                  onChange={e => setForm(f => ({ ...f, syllabus: e.target.value }))}
                  placeholder={"Understand NTLM relay attack mechanics\nDetect lateral movement in Windows event logs\nBuild detection rules for PsExec usage"}
                  rows={4}
                  className="w-full resize-none rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 font-mono text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/40 focus:outline-none"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded border border-severity-critical/30 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> {error}
              </div>
            )}

            <Button variant="primary" size="sm" onClick={generate} disabled={loading} className="w-full justify-center">
              {loading
                ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Generating Lesson…</>
                : <><BookOpen className="h-3.5 w-3.5" /> Generate Lesson</>
              }
            </Button>

            {/* Preview */}
            {preview && (
              <div className="rounded border border-neon-green/20 bg-neon-green/5 px-4 py-3 space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-[11px] font-semibold text-neon-green flex items-center gap-1.5">
                    <Check className="h-3.5 w-3.5" /> Lesson generated — {preview.title}
                  </p>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span>~{preview.estimatedMinutes} min</span>
                    <span>+{preview.xp} XP</span>
                    <span>{preview.sections.length} sections</span>
                  </div>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2">{preview.intro}</p>
                <div className="flex gap-1.5 flex-wrap">
                  {preview.sections.map((s, i) => (
                    <span key={i} className="rounded border border-border/40 bg-[#0a0f1a] px-2 py-0.5 text-[10px] text-slate-400">
                      {i+1}. {s.heading}
                    </span>
                  ))}
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  className="w-full justify-center"
                  disabled={published.has(preview.id)}
                  onClick={() => publish(preview)}
                >
                  {published.has(preview.id)
                    ? <><Check className="h-3.5 w-3.5 text-neon-green" /> Published</>
                    : <><FileText className="h-3.5 w-3.5" /> Publish to Library</>
                  }
                </Button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Lesson list */}
      <div className="flex items-center justify-between border-b border-border/60 bg-[#0a0f1a] px-4 py-2 shrink-0">
        <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-1.5">
          <BookOpen className="h-3 w-3" /> Lesson Library
          <span className="text-slate-600">({filtered.filter(l => !hidden.includes(l.slug)).length} visible)</span>
        </p>
        <select
          value={filterPath}
          onChange={e => setFilterPath(e.target.value)}
          className="rounded border border-border/40 bg-transparent px-2 py-0.5 text-[10px] text-slate-400 focus:outline-none"
        >
          {paths.map(p => <option key={p} value={p}>{p === "all" ? "All paths" : p}</option>)}
        </select>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Generated lessons first */}
        {generated.length > 0 && (
          <>
            <div className="border-b border-border/40 bg-[#060b12] px-4 py-1.5">
              <p className="text-[9px] uppercase tracking-[0.15em] text-neon-green/60">AI-Generated ({generated.length})</p>
            </div>
            {generated.map(l => (
              <ContentRow
                key={l.id}
                title={l.title}
                generated
                meta={
                  <>
                    <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", DIFFICULTY_BADGE[l.difficulty] ?? DIFFICULTY_BADGE.beginner)}>
                      {l.difficulty}
                    </span>
                    <span className="text-[10px] text-slate-500">{l.topic}</span>
                    <span className="text-[10px] text-slate-600">+{l.xp} XP · ~{l.estimatedMinutes}min</span>
                  </>
                }
                onHide={() => onDeleteGenerated(l.id)}
                onDelete={() => onDeleteGenerated(l.id)}
              />
            ))}
            <div className="my-1 h-px bg-border/40" />
          </>
        )}

        {/* Built-in lessons */}
        {filtered.map(l => (
          <ContentRow
            key={l.slug}
            title={`${kindIcon(l.kind)} ${l.title}`}
            hidden={hidden.includes(l.slug)}
            meta={
              <>
                <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", DIFFICULTY_BADGE[l.difficulty] ?? DIFFICULTY_BADGE.beginner)}>
                  {l.difficulty}
                </span>
                <span className="text-[10px] text-slate-500 truncate max-w-[200px]">{l.moduleTitle}</span>
                <span className="text-[10px] text-slate-600">+{l.xp} XP · ~{l.min}min</span>
              </>
            }
            onHide={() => onHide(l.slug)}
            onRestore={() => onRestore(l.slug)}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Quizzes tab ──────────────────────────────────────────────────────────────

function QuizzesTab({
  hidden, onHide, onRestore,
  generated, onDeleteGenerated,
}: {
  hidden: string[];
  onHide: (slug: string) => void;
  onRestore: (slug: string) => void;
  generated: GeneratedQuiz[];
  onDeleteGenerated: (id: string) => void;
}) {
  const [showGenerator, setShowGenerator] = useState(true);
  const [form, setForm] = useState<{
    title: string; topic: string;
    difficulty: "Beginner" | "Intermediate" | "Advanced";
    count: number; focus: string;
  }>({ title: "", topic: "Incident Response", difficulty: "Intermediate", count: 8, focus: "" });
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<GeneratedQuiz | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [published, setPublished] = useState<Set<string>>(new Set());
  const [showQ, setShowQ] = useState(false);

  async function generate() {
    if (!form.title.trim()) { setError("Please enter a quiz title"); return; }
    setLoading(true); setError(null); setPreview(null); setShowQ(false);
    try {
      const res = await fetch("/api/quizzes/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error ?? "Generation failed");
      setPreview(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  function publish(quiz: GeneratedQuiz) {
    const existing: GeneratedQuiz[] = JSON.parse(localStorage.getItem("generated_quizzes") ?? "[]");
    localStorage.setItem("generated_quizzes", JSON.stringify([quiz, ...existing]));
    setPublished(prev => new Set([...prev, quiz.id]));
    window.location.reload();
  }

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* Generator */}
      <div className="shrink-0 border-b border-border/60">
        <button
          onClick={() => setShowGenerator(v => !v)}
          className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-bg-hover/30 transition-colors"
        >
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-2">
            <Plus className="h-3 w-3 text-cyber-300" />
            <span className="text-cyber-300">Quiz Generator</span>
            <span className="text-slate-600">— AI creates quiz questions by topic</span>
          </p>
          {showGenerator ? <ChevronUp className="h-3.5 w-3.5 text-slate-500" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-500" />}
        </button>

        {showGenerator && (
          <div className="px-4 pb-4 space-y-3 bg-[#060b12]">
            <div className="grid grid-cols-2 gap-3">
              {/* Title */}
              <div className="col-span-2">
                <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Quiz Title *</label>
                <input
                  type="text"
                  value={form.title}
                  onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                  placeholder="e.g. Advanced Threat Hunting Techniques"
                  className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/40 focus:outline-none"
                />
              </div>
              {/* Topic */}
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Topic</label>
                <select
                  value={form.topic}
                  onChange={e => setForm(f => ({ ...f, topic: e.target.value }))}
                  className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 focus:border-cyber-500/40 focus:outline-none"
                >
                  {TOPICS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              {/* Difficulty + count */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Difficulty</label>
                  <select
                    value={form.difficulty}
                    onChange={e => setForm(f => ({ ...f, difficulty: e.target.value as "Beginner"|"Intermediate"|"Advanced" }))}
                    className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 focus:border-cyber-500/40 focus:outline-none"
                  >
                    <option value="Beginner">Beginner</option>
                    <option value="Intermediate">Intermediate</option>
                    <option value="Advanced">Advanced</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">Questions</label>
                  <select
                    value={form.count}
                    onChange={e => setForm(f => ({ ...f, count: Number(e.target.value) }))}
                    className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 focus:border-cyber-500/40 focus:outline-none"
                  >
                    {[5,6,7,8,9,10,12].map(n => <option key={n} value={n}>{n} questions</option>)}
                  </select>
                </div>
              </div>
              {/* Focus areas */}
              <div className="col-span-2">
                <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1">
                  Focus Areas <span className="text-slate-600">(optional — specific subtopics to emphasize)</span>
                </label>
                <input
                  type="text"
                  value={form.focus}
                  onChange={e => setForm(f => ({ ...f, focus: e.target.value }))}
                  placeholder="e.g. Kerberoasting, DCSync, Pass-the-Hash, LSASS dumping"
                  className="w-full rounded border border-border/40 bg-[#0a0f1a] px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/40 focus:outline-none"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded border border-severity-critical/30 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> {error}
              </div>
            )}

            <Button variant="primary" size="sm" onClick={generate} disabled={loading} className="w-full justify-center">
              {loading
                ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Generating Quiz…</>
                : <><Target className="h-3.5 w-3.5" /> Generate Quiz</>
              }
            </Button>

            {/* Preview */}
            {preview && (
              <div className="rounded border border-neon-green/20 bg-neon-green/5 px-4 py-3 space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-[11px] font-semibold text-neon-green flex items-center gap-1.5">
                    <Check className="h-3.5 w-3.5" /> {preview.questions.length} questions generated
                  </p>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span>~{preview.estimatedMinutes} min</span>
                    <span>{preview.difficulty}</span>
                    <button
                      onClick={() => setShowQ(v => !v)}
                      className="flex items-center gap-1 text-cyber-300 hover:text-cyber-200 transition-colors"
                    >
                      <Eye className="h-3 w-3" />
                      {showQ ? "Hide" : "Preview"} questions
                    </button>
                  </div>
                </div>

                {showQ && (
                  <div className="max-h-60 overflow-y-auto space-y-2">
                    {preview.questions.map((q, i) => (
                      <div key={q.id} className="rounded border border-border/40 bg-[#080d14] px-3 py-2">
                        <p className="text-[11px] text-slate-200 font-medium">{i+1}. {q.question}</p>
                        <ul className="mt-1 space-y-0.5">
                          {q.options.map((opt, oi) => (
                            <li key={oi} className={cn(
                              "text-[10px] pl-3",
                              oi === q.answer ? "text-neon-green font-semibold" : "text-slate-500"
                            )}>
                              {String.fromCharCode(65+oi)}. {opt} {oi === q.answer && "✓"}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}

                <Button
                  variant="secondary"
                  size="sm"
                  className="w-full justify-center"
                  disabled={published.has(preview.id)}
                  onClick={() => publish(preview)}
                >
                  {published.has(preview.id)
                    ? <><Check className="h-3.5 w-3.5 text-neon-green" /> Published</>
                    : <><HelpCircle className="h-3.5 w-3.5" /> Publish to Quiz Library</>
                  }
                </Button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Quiz list */}
      <div className="border-b border-border/60 bg-[#0a0f1a] px-4 py-2 shrink-0">
        <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-1.5">
          <HelpCircle className="h-3 w-3" /> Quiz Library
          <span className="text-slate-600">({QUIZZES.filter(q => !hidden.includes(q.slug)).length + generated.length} active)</span>
        </p>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Generated quizzes */}
        {generated.length > 0 && (
          <>
            <div className="border-b border-border/40 bg-[#060b12] px-4 py-1.5">
              <p className="text-[9px] uppercase tracking-[0.15em] text-neon-green/60">AI-Generated ({generated.length})</p>
            </div>
            {generated.map(q => (
              <ContentRow
                key={q.id}
                title={`${q.icon} ${q.title}`}
                generated
                meta={
                  <>
                    <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", DIFFICULTY_BADGE[q.difficulty] ?? DIFFICULTY_BADGE.beginner)}>
                      {q.difficulty}
                    </span>
                    <span className="text-[10px] text-slate-500">{q.category}</span>
                    <span className="text-[10px] text-slate-600">{q.questions.length} Qs · ~{q.estimatedMinutes}min</span>
                  </>
                }
                onHide={() => onDeleteGenerated(q.id)}
                onDelete={() => onDeleteGenerated(q.id)}
              />
            ))}
            <div className="my-1 h-px bg-border/40" />
          </>
        )}

        {/* Built-in quizzes */}
        {QUIZZES.map(q => (
          <ContentRow
            key={q.slug}
            title={`${q.icon} ${q.title}`}
            hidden={hidden.includes(q.slug)}
            meta={
              <>
                <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", DIFFICULTY_BADGE[q.difficulty] ?? DIFFICULTY_BADGE.beginner)}>
                  {q.difficulty}
                </span>
                <span className="text-[10px] text-slate-500">{q.category}</span>
                <span className="text-[10px] text-slate-600">{q.questions.length} Qs · ~{q.estimatedMinutes}min</span>
              </>
            }
            onHide={() => onHide(q.slug)}
            onRestore={() => onRestore(q.slug)}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function AdminContentManagerContent() {
  const [tab, setTab] = useState<ContentTab>("scenarios");

  // Hidden items (localStorage-persisted)
  const [hiddenScenarios, setHiddenScenarios] = useState<string[]>([]);
  const [hiddenLessons,   setHiddenLessons]   = useState<string[]>([]);
  const [hiddenQuizzes,   setHiddenQuizzes]   = useState<string[]>([]);

  // Generated / published items
  const [publishedScenarios, setPublishedScenarios] = useState<PublishedScenario[]>([]);
  const [generatedLessons,   setGeneratedLessons]   = useState<GeneratedLesson[]>([]);
  const [generatedQuizzes,   setGeneratedQuizzes]   = useState<GeneratedQuiz[]>([]);

  useEffect(() => {
    setHiddenScenarios(JSON.parse(localStorage.getItem("admin_hidden_scenarios") ?? "[]"));
    setHiddenLessons(JSON.parse(localStorage.getItem("admin_hidden_lessons") ?? "[]"));
    setHiddenQuizzes(JSON.parse(localStorage.getItem("admin_hidden_quizzes") ?? "[]"));
    setPublishedScenarios(JSON.parse(localStorage.getItem("published_scenarios") ?? "[]"));
    setGeneratedLessons(JSON.parse(localStorage.getItem("generated_lessons") ?? "[]"));
    setGeneratedQuizzes(JSON.parse(localStorage.getItem("generated_quizzes") ?? "[]"));
  }, []);

  // ── Generic hide/restore/delete helpers ────────────────────────────────────

  function hide(type: "scenarios" | "lessons" | "quizzes", slug: string) {
    const key = `admin_hidden_${type}`;
    const updated = [...JSON.parse(localStorage.getItem(key) ?? "[]"), slug];
    localStorage.setItem(key, JSON.stringify(updated));
    if (type === "scenarios") setHiddenScenarios(updated);
    else if (type === "lessons") setHiddenLessons(updated);
    else setHiddenQuizzes(updated);
  }

  function restore(type: "scenarios" | "lessons" | "quizzes", slug: string) {
    const key = `admin_hidden_${type}`;
    const updated = (JSON.parse(localStorage.getItem(key) ?? "[]") as string[]).filter(s => s !== slug);
    localStorage.setItem(key, JSON.stringify(updated));
    if (type === "scenarios") setHiddenScenarios(updated);
    else if (type === "lessons") setHiddenLessons(updated);
    else setHiddenQuizzes(updated);
  }

  function deletePublishedScenario(id: string) {
    const updated = publishedScenarios.filter(s => s.id !== id);
    localStorage.setItem("published_scenarios", JSON.stringify(updated));
    setPublishedScenarios(updated);
  }

  function deleteGeneratedLesson(id: string) {
    const updated = generatedLessons.filter(l => l.id !== id);
    localStorage.setItem("generated_lessons", JSON.stringify(updated));
    setGeneratedLessons(updated);
  }

  function deleteGeneratedQuiz(id: string) {
    const updated = generatedQuizzes.filter(q => q.id !== id);
    localStorage.setItem("generated_quizzes", JSON.stringify(updated));
    setGeneratedQuizzes(updated);
  }

  const scenarioCount = SCENARIOS.filter(s => !hiddenScenarios.includes(s.slug)).length + publishedScenarios.length;
  const lessonCount   = getAllLessons().filter(l => !hiddenLessons.includes(l.slug)).length + generatedLessons.length;
  const quizCount     = QUIZZES.filter(q => !hiddenQuizzes.includes(q.slug)).length + generatedQuizzes.length;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded border border-border bg-[#050a10]">
      {/* Sub-tab bar */}
      <div className="flex items-center border-b border-border/60 shrink-0 px-2">
        <SubTab
          active={tab === "scenarios"}
          onClick={() => setTab("scenarios")}
          icon={<Shield className="h-3.5 w-3.5" />}
          label="Scenarios"
          count={scenarioCount}
        />
        <SubTab
          active={tab === "lessons"}
          onClick={() => setTab("lessons")}
          icon={<BookOpen className="h-3.5 w-3.5" />}
          label="Lessons"
          count={lessonCount}
        />
        <SubTab
          active={tab === "quizzes"}
          onClick={() => setTab("quizzes")}
          icon={<HelpCircle className="h-3.5 w-3.5" />}
          label="Quizzes"
          count={quizCount}
        />
        <div className="ml-auto pr-4">
          <p className="text-[10px] text-slate-600">
            🗑 Hidden items still exist in source — use Restore to re-enable
          </p>
        </div>
      </div>

      {/* Tab panels */}
      <div className="flex-1 min-h-0 overflow-hidden">
        {tab === "scenarios" && (
          <ScenariosTab
            hidden={hiddenScenarios}
            onHide={s  => hide("scenarios", s)}
            onRestore={s => restore("scenarios", s)}
            published={publishedScenarios}
            onDeletePublished={deletePublishedScenario}
          />
        )}
        {tab === "lessons" && (
          <LessonsTab
            hidden={hiddenLessons}
            onHide={s  => hide("lessons", s)}
            onRestore={s => restore("lessons", s)}
            generated={generatedLessons}
            onDeleteGenerated={deleteGeneratedLesson}
          />
        )}
        {tab === "quizzes" && (
          <QuizzesTab
            hidden={hiddenQuizzes}
            onHide={s  => hide("quizzes", s)}
            onRestore={s => restore("quizzes", s)}
            generated={generatedQuizzes}
            onDeleteGenerated={deleteGeneratedQuiz}
          />
        )}
      </div>
    </div>
  );
}
