"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { X, ChevronRight, ChevronLeft } from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Storage keys (bump version when steps change) ────────────────────────────
const DASHBOARD_TOUR_KEY = "soc-dashboard-tour-v8-done";
const LOG_TOUR_KEY       = "soc-log-tour-v8-done";

// ─── Types ────────────────────────────────────────────────────────────────────
interface TourStep {
  title:    string;
  icon:     string;
  content:  string;
  example?: string;
  /** DOM element id to highlight with spotlight */
  targetId?: string;
}

// ─── Dashboard tour steps ─────────────────────────────────────────────────────
const DASHBOARD_STEPS: TourStep[] = [
  {
    title: "Welcome to your SIEM",
    icon: "🛡️",
    content:
      "This is a Security Information and Event Management system — the command center of a real SOC. Security events from across the company flow in here in real time. Your job: read them, spot the threats, classify them.",
  },
  {
    title: "Every row = one security event",
    icon: "📋",
    content:
      "Each row in this table is one log entry recorded by a security tool — benign events mixed with real attacks. You won't know in advance which is which. Click any row to expand it and see the full log.",
    targetId: "ef-event-table",
  },
  {
    title: "TIME — When did it happen?",
    icon: "🕐",
    content:
      "Always ask: is this a normal time for this activity? A VPN login at 3 AM from a Finance employee is suspicious. A DNS query at 9 AM is routine. Time context is free information — use it.",
    example: "14:22:45  ← normal business hour\n03:17:02  ← investigate this",
    targetId: "ef-th-time",
  },
  {
    title: "AGENT NAME — Which computer?",
    icon: "🖥️",
    content:
      "The hostname of the machine where the event was recorded. Naming patterns matter: WS = workstation, SRV = server, LT = laptop. Multiple events on the same host in a short window = possible active attack.",
    example: "WS-FIN-2847   → Finance workstation\nSRV-NXC-DC01  → Domain Controller\nLT-DEV-0931   → Developer laptop",
    targetId: "ef-th-agent",
  },
  {
    title: "SOURCE — Which security tool?",
    icon: "🔍",
    content:
      "Different tools see different layers of activity. EDR sees processes and files. Firewall sees network traffic. Active Directory sees logins. Knowing the source tells you what type of activity to look for in the raw fields.",
    example: "EDR      → process.name, process.parent.name\nFirewall → source.ip, destination.ip, action\nAD       → user.name, event.code, logon.type",
    targetId: "ef-th-source",
  },
  {
    title: "RULE LEVEL — How serious?",
    icon: "⚡",
    content:
      "A severity score from 1 to 10, calculated automatically from the event fields. Start every shift by scanning for level 7+ events first — those are the ones that need immediate attention.",
    example: "1  → DNS query for slack.com (routine)\n5  → Inbound SSH blocked (investigate)\n9  → PowerShell with encoded command\n10 → LSASS credential dump detected",
    targetId: "ef-th-level",
  },
  {
    title: "RULE ID & MITRE Techniques",
    icon: "🎯",
    content:
      "The Rule ID is the detection rule that fired. When you see a purple badge like T1059.001 — that's a MITRE ATT&CK technique ID. Click it to learn exactly what this attacker technique does, what to look for in logs, and how to detect it.",
    example: "RULE_92400    → generic process creation\nT1059.001     → PowerShell execution\nT1003.001     → LSASS credential dump",
    targetId: "ef-th-ruleid",
  },
  {
    title: "Filters — focus your investigation",
    icon: "🔎",
    content:
      "Filters narrow the event feed without deleting anything. Investigating one machine? Press '+ More filters' for HOST, USER, IP and MITRE filters. Too much noise? Set LEVEL to 7-10 HIGH. Filters stack — you can combine them.",
    targetId: "ef-filter-row",
  },
  {
    title: "Reporting the incident",
    icon: "📝",
    content:
      "This is the goal of your shift. There are no hints and nothing gets flagged for you — you decide when you've found the attack. Once you have, press REPORT INCIDENT (top-right) and write what happened: which attack, the evidence you found in the logs, and what to do about it. Your report is graded against the real evidence.",
    targetId: "report-incident-btn",
  },
  {
    title: "You're ready — click any row",
    icon: "🎓",
    content:
      "Click any row in the table to expand it and read the full raw log. Look at the source, the fields, the actor and the time, and decide for yourself whether it's normal activity or part of an attack. When you've pieced the attack together, report it.",
  },
];

// ─── Log reading tour steps ───────────────────────────────────────────────────
const LOG_STEPS: TourStep[] = [
  {
    title: "You opened a raw log event",
    icon: "📄",
    content:
      "This is what your SIEM actually receives from the security tool. Everything you see is structured data — each field has a name (key) and a value. Real analysts read exactly this when investigating alerts.",
  },
  {
    title: "Basic Information — start here",
    icon: "🔑",
    content:
      "The most important fields summarized: who (username), where (hostname), when (timestamp), severity, and what action the tool took. Always start here before diving into raw fields.",
    targetId: "ef-detail-basic-info",
  },
  {
    title: "Detailed Log Data — the raw fields",
    icon: "🔬",
    content:
      "All original fields from the security tool in ECS (Elastic Common Schema) format — the same standard used by Splunk, Microsoft Sentinel, and CrowdStrike. For process events, find process.name and process.parent.name first — that relationship reveals most attacks.",
    example: "process.name         → what ran\nprocess.parent.name  → what launched it\nprocess.command_line → exact command\nsource.ip / dest.ip  → network context",
    targetId: "ef-detail-log-data",
  },
];

// ─── Hook: track element bounding rect by id ──────────────────────────────────
function useElementRect(id: string | undefined) {
  const [rect, setRect] = useState<DOMRect | null>(null);

  const measure = useCallback(() => {
    if (!id) { setRect(null); return; }
    const el = document.getElementById(id);
    if (!el) { setRect(null); return; }
    setRect(el.getBoundingClientRect());
  }, [id]);

  useEffect(() => {
    measure();
    window.addEventListener("resize",  measure);
    window.addEventListener("scroll",  measure, true);
    return () => {
      window.removeEventListener("resize",  measure);
      window.removeEventListener("scroll",  measure, true);
    };
  }, [measure]);

  return rect;
}

// ─── Spotlight + overlay ──────────────────────────────────────────────────────
function Spotlight({ rect }: { rect: DOMRect | null }) {
  if (!rect) {
    // No target — just a dark overlay that doesn't block interaction
    return (
      <div className="fixed inset-0 bg-black/50 z-[58] pointer-events-none" />
    );
  }
  const PAD = 6;
  return (
    <div
      className="fixed z-[58] pointer-events-none rounded-md"
      style={{
        top:    rect.top    - PAD,
        left:   rect.left   - PAD,
        width:  rect.width  + PAD * 2,
        height: rect.height + PAD * 2,
        // Dark overlay everywhere EXCEPT this element — the "box-shadow hole" trick
        boxShadow: "0 0 0 9999px rgba(0,0,0,0.65), 0 0 0 2px rgba(56,189,248,0.85)",
      }}
    />
  );
}

// ─── Tour Card ────────────────────────────────────────────────────────────────
// Docked in one fixed corner for the ENTIRE tour — it never repositions itself
// relative to a target, so it can never end up off-screen or unclickable
// (a target near a screen edge used to push the old target-relative card out
// of the viewport). The spotlight still moves to highlight each target; only
// the card's own box stays put.
const DOCK_STYLE: React.CSSProperties = {
  position: "fixed",
  right: 20,
  bottom: 20,
  width: "min(400px, calc(100vw - 40px))",
  maxHeight: "calc(100vh - 40px)",
};

function TourCard({
  steps,
  onDone,
  tourTitle,
}: {
  steps:     TourStep[];
  onDone:    () => void;
  tourTitle: string;
}) {
  const [step, setStep] = useState(0);
  const current  = steps[step];
  const isFirst  = step === 0;
  const isLast   = step === steps.length - 1;

  const rect = useElementRect(current.targetId);

  // Scroll target into view when step changes
  useEffect(() => {
    if (current.targetId) {
      document.getElementById(current.targetId)
        ?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
    }
  }, [step, current.targetId]);

  // Portal straight to <body> — EventFeed renders inside a Card that uses
  // backdrop-blur (backdrop-filter), which per spec creates a new containing
  // block for position:fixed descendants. Without the portal, "fixed" here
  // silently behaves like "absolute relative to the Card" instead of the
  // viewport, so the card can end up scrolled off-screen and unclickable.
  return createPortal(
    <>
      <Spotlight rect={current.targetId ? rect : null} />

      <motion.div
        key={step}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        exit={   { opacity: 0, y: 4 }}
        transition={{ type: "spring", damping: 24, stiffness: 300 }}
        style={{ ...DOCK_STYLE, zIndex: 60 }}
        className="fixed flex flex-col"
      >
        <div className="flex flex-col rounded-2xl border border-cyber-500/30 bg-[#07111f] shadow-2xl shadow-black/70 overflow-hidden max-h-full">

          {/* Header bar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-border/40 bg-cyber-500/[0.07] shrink-0">
            <span className="text-[9px] font-bold uppercase tracking-[0.18em] text-cyber-500 shrink-0">
              {tourTitle}
            </span>
            <div className="flex items-center gap-3 ml-3">
              {/* Progress dots */}
              <div className="flex items-center gap-1">
                {steps.map((_, i) => (
                  <button
                    key={i}
                    onClick={() => setStep(i)}
                    className={cn(
                      "rounded-full transition-all duration-200",
                      i === step ? "w-4 h-1.5 bg-cyber-400"
                      : i < step  ? "w-1.5 h-1.5 bg-cyber-700"
                      :             "w-1.5 h-1.5 bg-slate-700"
                    )}
                  />
                ))}
              </div>
              <span className="font-mono text-[9px] text-slate-600 shrink-0">{step + 1}/{steps.length}</span>
              <button
                onClick={onDone}
                title="Skip tour"
                className="text-slate-600 hover:text-slate-400 transition p-0.5 shrink-0"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Body — scrolls internally if content is tall, card box never grows off-screen */}
          <div className="px-5 py-4 space-y-3 overflow-y-auto">
            <div className="flex items-start gap-3">
              <span className="text-[22px] shrink-0 leading-none mt-0.5">{current.icon}</span>
              <div className="min-w-0 flex-1">
                <h3 className="text-[13px] font-bold text-white mb-1.5 leading-snug">{current.title}</h3>
                <p className="text-[11px] leading-relaxed text-slate-300">{current.content}</p>
              </div>
            </div>

            {current.example && (
              <pre className="rounded border border-border/50 bg-[#0a0f1a] px-3 py-2 font-mono text-[10px] leading-relaxed text-cyber-300 overflow-x-auto whitespace-pre">
                {current.example}
              </pre>
            )}
          </div>

          {/* Nav */}
          <div className="flex items-center justify-between px-5 py-3 border-t border-border/30 shrink-0">
            <button
              onClick={() => setStep(s => Math.max(0, s - 1))}
              disabled={isFirst}
              className={cn(
                "inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition",
                isFirst
                  ? "border-transparent text-slate-700 pointer-events-none"
                  : "border-slate-600/50 text-slate-300 hover:bg-slate-700/40"
              )}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
              Back
            </button>

            <button
              onClick={onDone}
              className="text-[10px] text-slate-600 hover:text-slate-400 transition"
            >
              Skip
            </button>

            <button
              onClick={() => isLast ? onDone() : setStep(s => s + 1)}
              className="inline-flex items-center gap-1 rounded-lg border border-cyber-500/50 bg-cyber-500/15 px-4 py-1.5 text-[11px] font-semibold text-cyber-300 hover:bg-cyber-500/25 transition"
            >
              {isLast ? "Got it!" : "Next"}
              {!isLast && <ChevronRight className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      </motion.div>
    </>,
    document.body
  );
}

// ─── Dashboard Tour ────────────────────────────────────────────────────────────
export function DashboardTour() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    try {
      if (!localStorage.getItem(DASHBOARD_TOUR_KEY)) {
        const t = setTimeout(() => setVisible(true), 900);
        return () => clearTimeout(t);
      }
    } catch { /* localStorage unavailable */ }
  }, []);

  function handleDone() {
    setVisible(false);
    try { localStorage.setItem(DASHBOARD_TOUR_KEY, "1"); } catch {}
  }

  return (
    <AnimatePresence>
      {visible && (
        <TourCard steps={DASHBOARD_STEPS} onDone={handleDone} tourTitle="SIEM Dashboard Tour" />
      )}
    </AnimatePresence>
  );
}

// ─── Log Reading Tour ──────────────────────────────────────────────────────────
export function LogReadingTour() {
  const [visible, setVisible] = useState(false);
  const shownRef = useRef(false);

  useEffect(() => {
    if (shownRef.current) return;
    try {
      if (!localStorage.getItem(LOG_TOUR_KEY)) {
        shownRef.current = true;
        const t = setTimeout(() => setVisible(true), 400);
        return () => clearTimeout(t);
      }
    } catch {}
  }, []);

  function handleDone() {
    setVisible(false);
    try { localStorage.setItem(LOG_TOUR_KEY, "1"); } catch {}
  }

  return (
    <AnimatePresence>
      {visible && (
        <TourCard steps={LOG_STEPS} onDone={handleDone} tourTitle="Reading a Log Event" />
      )}
    </AnimatePresence>
  );
}
