"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { BUILTIN_LESSONS } from "@/data/builtinLessons";
import { Search, Clock, FileText, ChevronLeft, ChevronRight, CheckCircle2, X } from "lucide-react";
import { MermaidDiagram } from "@/components/rooms/MermaidDiagram";
import { isMermaidSource } from "@/lib/lessons/mermaid";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Lesson {
  id: string;
  slug: string;
  title: string;
  topic: string;
  difficulty: string;
  kind: "lesson";
  intro: string;
  sections: { heading: string; content: string; codeExample?: string; imageQuery?: string }[];
  keyTakeaways: string[];
  quiz: { question: string; options: { label: string; value: string }[]; answer: string; explanation: string }[];
  references: string[];
  xp: number;
  estimatedMinutes: number;
  researchUsed?: boolean;
  createdAt?: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const DIFF_COLORS: Record<string, string> = {
  beginner:     "bg-sky-500/20     text-sky-300     border-sky-500/40",
  intermediate: "bg-yellow-500/20  text-yellow-300  border-yellow-500/40",
  advanced:     "bg-orange-500/20  text-orange-300  border-orange-500/40",
  expert:       "bg-red-500/20     text-red-300     border-red-500/40",
};

function capitalize(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function tagsForLesson(l: Lesson): string[] {
  const topic = (l.topic + " " + l.title).toLowerCase();
  const tags: string[] = [];
  if (/protocol|network|dns|tcp|smb|http/.test(topic))  tags.push("Network Analysis");
  if (/phish|email|mail|bec/.test(topic))               tags.push("Email Security");
  if (/windows|event.?log|sysmon|registry/.test(topic)) tags.push("Log Analysis");
  if (/threat|intel|hunt|ioc/.test(topic))              tags.push("Threat Intelligence");
  if (/siem|splunk|sentinel|kql|spl/.test(topic))       tags.push("SIEM");
  if (/malware|endpoint|edr|av/.test(topic))            tags.push("Endpoint Security");
  if (/kerberos|active.?dir|ldap|ntlm/.test(topic))     tags.push("Active Directory");
  if (/cloud|aws|azure|s3|iam/.test(topic))             tags.push("Cloud Security");
  if (/vuln|cve|patch|exploit/.test(topic))             tags.push("Vulnerability Mgmt");
  if (/incident|response|forensic/.test(topic))         tags.push("Incident Response");
  tags.push("SOC Analysts");
  if (tags.length < 3) tags.push(capitalize(l.difficulty));
  return tags.slice(0, 5);
}

// ─── Image helpers ────────────────────────────────────────────────────────────

function topicImageQuery(lesson: Lesson, sectionHeading?: string): string {
  const text = ((lesson.topic ?? "") + " " + (sectionHeading ?? "")).toLowerCase();
  if (/edr|endpoint.detect|crowdstrike|sentinelone|defender/.test(text)) return "endpoint security threat detection";
  if (/phish|spear.?phish|email.?attack|bec/.test(text))                 return "phishing email cybersecurity";
  if (/kerbero|active.?direct|ldap|ntlm|golden.?ticket/.test(text))     return "active directory network authentication";
  if (/windows|event.?log|sysmon|registry|powershell/.test(text))       return "windows server security monitoring";
  if (/protocol|tcp|dns|http|smb|network.?traffic/.test(text))          return "network traffic protocol analysis";
  if (/malware|ransomware|trojan|virus|worm/.test(text))                return "malware cybersecurity threat";
  if (/cloud|aws|azure|s3|iam|bucket/.test(text))                       return "cloud security data infrastructure";
  if (/incident.?response|forensic|triage/.test(text))                  return "cybersecurity incident response team";
  if (/siem|splunk|sentinel|elastic|kql|spl/.test(text))               return "security operations center SIEM";
  if (/threat.?hunt|threat.?intel|ioc|ttp/.test(text))                 return "threat intelligence cyber";
  if (/vuln|cve|patch|exploit|zero.?day/.test(text))                    return "vulnerability security patch";
  if (/social.?engin|pretex/.test(text))                               return "social engineering cyber attack";
  return "cybersecurity analyst SOC professional";
}

function SectionImage({ query }: { query: string }) {
  const url = `https://source.unsplash.com/800x280/?${encodeURIComponent(query)}`;
  return (
    <div className="rounded-xl overflow-hidden border border-[#1e2d4a] mb-2">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={url}
        alt={query}
        className="w-full object-cover"
        style={{ maxHeight: 200 }}
        onError={(e) => { (e.currentTarget.parentElement as HTMLElement).style.display = "none"; }}
      />
    </div>
  );
}

// ─── Content Renderer ─────────────────────────────────────────────────────────
// Visual hierarchy:
//   H1 = section title (rendered separately, big white text + thick cyan border)
//   H2 = ### sub-heading  (medium teal, thin left accent)
//   H3 = ## fallback      (small cyan, no border)
//   P  = paragraph        (slate-300, 14px, leading-relaxed)

function renderContent(text: string) {
  const blocks = text.split(/\n\n+/);
  return (
    <div className="space-y-4">
      {blocks.map((block, i) => {
        const trimmed = block.trim();
        if (!trimmed) return null;

        // H2 — ### Sub-heading: clearly subordinate to section title
        if (trimmed.startsWith("### ")) {
          return (
            <div key={i} className="flex items-start gap-3 mt-7 mb-1">
              <span className="mt-1 shrink-0 w-[3px] h-5 rounded-full bg-teal-400/70" />
              <h4 className="text-[15px] font-bold text-teal-200 leading-snug">
                {trimmed.replace(/^### /, "")}
              </h4>
            </div>
          );
        }

        // H3 — ## heading (fallback)
        if (trimmed.startsWith("## ")) {
          return (
            <h3 key={i} className="text-[13px] font-bold uppercase tracking-widest text-slate-400 mt-6">
              {trimmed.replace(/^## /, "")}
            </h3>
          );
        }

        // Paragraph — inline **bold** support
        const parts = trimmed.split(/(\*\*[^*]+\*\*)/g);
        return (
          <p key={i} className="text-[14px] text-slate-300 leading-[1.8]">
            {parts.map((part, j) =>
              part.startsWith("**") && part.endsWith("**")
                ? <strong key={j} className="text-white font-semibold">{part.slice(2, -2)}</strong>
                : part
            )}
          </p>
        );
      })}
    </div>
  );
}

// ─── Lesson Card ──────────────────────────────────────────────────────────────

function LessonCard({ lesson, onClick }: { lesson: Lesson; onClick: () => void }) {
  const diffCls = DIFF_COLORS[lesson.difficulty] ?? DIFF_COLORS.intermediate;
  const tags     = tagsForLesson(lesson);
  const pages    = lesson.sections.length + 1; // intro + sections

  return (
    <button
      onClick={onClick}
      className="group text-left w-full rounded-2xl border border-[#1e2d4a] bg-[#0d1322] p-5 hover:border-cyan-500/40 hover:bg-[#0f1830] transition-all duration-200 flex flex-col gap-3"
    >
      {/* title + badge */}
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-base font-bold leading-snug line-clamp-3 transition-colors text-white group-hover:text-cyan-100">
          {lesson.title}
        </h3>
        <span className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase whitespace-nowrap shrink-0 mt-0.5 ${diffCls}`}>
          {capitalize(lesson.difficulty)}
        </span>
      </div>

      {/* description */}
      {lesson.intro && (
        <p className="text-[13px] text-slate-400 leading-relaxed line-clamp-4">
          {lesson.intro.replace(/\*\*/g, "").split("\n")[0]}
        </p>
      )}

      {/* tags */}
      <div className="flex flex-wrap gap-1.5">
        {tags.map(tag => (
          <span key={tag} className="rounded-full border border-[#2a3555] bg-[#111828] px-2.5 py-0.5 text-[11px] text-slate-400">
            {tag}
          </span>
        ))}
      </div>

      {/* stats */}
      <div className="flex items-center gap-4 text-[12px] text-slate-500 border-t border-[#1e2d4a] pt-3">
        <span className="flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5" />
          {lesson.estimatedMinutes} min
        </span>
        <span className="flex items-center gap-1.5">
          <FileText className="h-3.5 w-3.5" />
          {pages} pages
        </span>
      </div>
    </button>
  );
}

// ─── Section Page Content (combined slide + text) ────────────────────────────

function SectionPageContent({
  lesson, section,
}: {
  lesson:  Lesson;
  section: { heading: string; content: string; codeExample?: string; imageQuery?: string };
}) {
  return (
    <div className="space-y-6">

      {/* ── Cover image ────────────────────────────────────────── */}
      <SectionImage query={section.imageQuery ?? topicImageQuery(lesson, section.heading)} />

      {/* ── Section heading ────────────────────────────────────── */}
      <div className="pb-5 border-b border-[#1e2d4a]">
        <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-500/70 block mb-2">
          Section
        </span>
        <h1 className="text-[22px] font-bold text-white leading-snug">{section.heading}</h1>
      </div>

      {/* ── Body text ──────────────────────────────────────────── */}
      {renderContent(section.content)}

      {/* ── Code example / diagram ─────────────────────────────────
          This modal reader used to stop at section.content, silently
          dropping codeExample — which 98 of the platform's 115 lesson
          sections carry. The other reader
          (learn/[slug]/[lesson]/page.tsx) rendered it, so the same
          lesson taught different material depending on which route you
          reached it through: every SPL/KQL query and comparison table
          was invisible here.

          Mermaid source is detected and rendered as an actual diagram
          rather than dumped as code — MermaidDiagram already existed but
          was wired only into rooms, so a diagram in a lesson displayed
          as raw `flowchart TD` text. */}
      {section.codeExample && (
        isMermaidSource(section.codeExample)
          ? <MermaidDiagram chart={section.codeExample} />
          : (
            <div className="overflow-x-auto rounded-lg border border-[#1e2d4a] bg-[#0a1020]">
              <pre className="p-4 font-mono text-xs leading-relaxed text-neon-green">{section.codeExample}</pre>
            </div>
          )
      )}

    </div>
  );
}

// ─── Paginated Lesson Reader ───────────────────────────────────────────────────

function LessonModal({ lesson, onClose }: { lesson: Lesson; onClose: () => void }) {
  const [page, setPage]             = useState(0);

  // Page layout:  0 = intro,  1..N = sections
  const totalPages = 1 + lesson.sections.length;

  const goTo   = useCallback((p: number) => setPage(Math.max(0, Math.min(p, totalPages - 1))), [totalPages]);
  const onNext = () => goTo(page + 1);
  const onPrev = () => goTo(page - 1);

  // Keyboard nav
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") onNext();
      if (e.key === "ArrowLeft")  onPrev();
      if (e.key === "Escape")     onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  });

  const diffCls = DIFF_COLORS[lesson.difficulty] ?? DIFF_COLORS.intermediate;
  const progress = ((page + 1) / totalPages) * 100;

  // Current content
  const isIntro = page === 0;
  const section = !isIntro ? lesson.sections[page - 1] : null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-2xl max-h-[90vh] flex flex-col rounded-2xl border border-[#1e2d4a] bg-[#0b0f1e] shadow-2xl overflow-hidden">

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between border-b border-[#1e2d4a] px-6 py-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
              <FileText className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <h2 className="text-sm font-bold text-white truncate">{lesson.title}</h2>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Page {page + 1} of {totalPages} · {lesson.estimatedMinutes} min read
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 ml-3">
            <span className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase ${diffCls}`}>
              {capitalize(lesson.difficulty)}
            </span>
            <button onClick={onClose} className="rounded-lg border border-slate-700 bg-slate-800 p-1.5 text-slate-400 hover:text-white transition-colors">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* ── Content ────────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto px-6 py-6">

          {/* Intro page */}
          {isIntro && (
            <div className="space-y-6">
              <SectionImage query={topicImageQuery(lesson)} />

              {/* H1 — Main topic title */}
              <div className="pb-5 border-b border-[#1e2d4a]">
                <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-500/70 block mb-2">
                  Introduction
                </span>
                <h1 className="text-[22px] font-bold text-white leading-snug">
                  {lesson.title}
                </h1>
              </div>

              {renderContent(lesson.intro)}
            </div>
          )}

          {/* Section page */}
          {section && (
            <SectionPageContent lesson={lesson} section={section} />
          )}
        </div>

        {/* ── Footer nav ─────────────────────────────────────────────────── */}
        <div className="border-t border-[#1e2d4a] px-6 py-4 shrink-0 space-y-3">
          {/* Dot pagination */}
          <div className="flex items-center justify-center gap-1.5">
            {Array.from({ length: totalPages }).map((_, i) => (
              <button
                key={i}
                onClick={() => goTo(i)}
                className={`rounded-full transition-all duration-200 ${
                  i === page
                    ? "w-5 h-2 bg-cyan-400"
                    : "w-2 h-2 bg-slate-700 hover:bg-slate-500"
                }`}
                aria-label={`Go to page ${i + 1}`}
              />
            ))}
          </div>

          {/* Prev / Next */}
          <div className="flex items-center justify-between gap-3">
            <button
              onClick={onPrev}
              disabled={page === 0}
              className="flex items-center gap-1.5 rounded-xl border border-[#2a3555] bg-[#0d1322] px-4 py-2 text-[13px] font-semibold text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronLeft className="h-4 w-4" /> Previous
            </button>

            <span className="text-[11px] text-slate-600">{page + 1} / {totalPages}</span>

            <button
              onClick={page === totalPages - 1 ? onClose : onNext}
              className="flex items-center gap-1.5 rounded-xl px-4 py-2 text-[13px] font-semibold text-white transition-all bg-cyan-600 hover:bg-cyan-500"
            >
              {page === totalPages - 1 ? "Finish" : "Next"}
              {page !== totalPages - 1 && <ChevronRight className="h-4 w-4" />}
            </button>
          </div>

          {/* Progress bar */}
          <div className="h-1 w-full rounded-full bg-[#1a2035] overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500 bg-gradient-to-r from-cyan-600 to-cyan-400"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}


// ─── Main Page ────────────────────────────────────────────────────────────────

export default function LearnPage() {
  const [lessons,    setLessons]    = useState<Lesson[]>([]);
  const [search,     setSearch]     = useState("");
  const [level,      setLevel]      = useState("all");
  const [openLesson, setOpenLesson] = useState<Lesson | null>(null);
  const [mounted,    setMounted]    = useState(false);

  function loadLessons() {
    try {
      const saved: Lesson[]   = JSON.parse(localStorage.getItem("generated_lessons")  ?? "[]");
      const deleted: string[] = JSON.parse(localStorage.getItem("deleted_lesson_ids") ?? "[]");
      const deletedSet = new Set(deleted);
      const savedIds   = new Set(saved.map(l => l.id));
      const builtins   = (BUILTIN_LESSONS as unknown as Lesson[])
        .filter(l => !savedIds.has(l.id) && !deletedSet.has(l.id));
      setLessons([...saved, ...builtins]);
    } catch {
      setLessons(BUILTIN_LESSONS as unknown as Lesson[]);
    }
  }

  useEffect(() => {
    setMounted(true);
    loadLessons();
    // Sync when admin modifies localStorage (same tab or different tab)
    const onStorage = () => loadLessons();
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return lessons.filter(l => {
      if (level !== "all" && l.difficulty !== level) return false;
      if (q && !l.title.toLowerCase().includes(q) && !l.topic.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [lessons, search, level]);

  return (
    <div className="min-h-screen bg-[#0b0f1e]">
      <Topbar title="Learning Path" subtitle="Explore cybersecurity knowledge through interactive lessons" />

      <div className="container mx-auto max-w-[1400px] px-6 py-8">

        {/* ── Search + filter ─────────────────────────── */}
        <div className="mb-8 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search lessons..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full rounded-xl border border-[#2a3555] bg-[#0d1322] py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60"
            />
          </div>
          <div className="relative">
            <select
              value={level}
              onChange={e => setLevel(e.target.value)}
              className="appearance-none rounded-xl border border-[#2a3555] bg-[#0d1322] pl-4 pr-10 py-2.5 text-sm text-slate-300 focus:outline-none focus:border-cyan-500/60 cursor-pointer min-w-[160px]"
            >
              <option value="all">All Levels</option>
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="advanced">Advanced</option>
              <option value="expert">Expert</option>
            </select>
            <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 rotate-90 pointer-events-none" />
          </div>
        </div>

        {!mounted ? null : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <FileText className="h-12 w-12 text-slate-700 mb-4" />
            <p className="text-base font-semibold text-slate-400">
              {lessons.length === 0 ? "No lessons yet" : "No lessons match your filters"}
            </p>
            <p className="mt-1 text-sm text-slate-600">
              {lessons.length === 0
                ? "Go to Admin → Lesson Management to generate lessons"
                : <button onClick={() => { setSearch(""); setLevel("all"); }} className="text-cyan-400 hover:text-cyan-300 underline">Clear filters</button>
              }
            </p>
          </div>
        ) : (
          <>
            <p className="mb-4 text-[12px] text-slate-500">{filtered.length} item{filtered.length !== 1 ? "s" : ""}</p>
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {filtered.map(l => (
                <LessonCard key={l.id} lesson={l} onClick={() => setOpenLesson(l)} />
              ))}
            </div>
          </>
        )}

      </div>

      {openLesson && <LessonModal lesson={openLesson} onClose={() => setOpenLesson(null)} />}
    </div>
  );
}
