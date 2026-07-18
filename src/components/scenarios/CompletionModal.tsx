"use client";
import { useState } from "react";
import { ShieldCheck, ShieldX, Trophy, RotateCcw, ArrowRight, Download, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { levelFromXp, xpForLevel } from "@/lib/utils";

export interface GradeResult {
  score: number;
  xpEarned: number;
  timeBonusXp: number;
  perQuestion: {
    id: string;
    correct: boolean;
    yourAnswer: string | string[];
    correctAnswer: string | string[];
    explanation: string;
    prompt: string;
    xp: number;
  }[];
  aiFeedback: string;
  passed: boolean;
}

interface Props {
  result: GradeResult;
  scenarioTitle: string;
  timeTaken: number;
  onRetry: () => void;
  onClose: () => void;
}

function formatTime(s: number) {
  const m = Math.floor(s / 60).toString().padStart(2, "0");
  const sec = (s % 60).toString().padStart(2, "0");
  return `${m}:${sec}`;
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-neon-green" : score >= 60 ? "bg-severity-medium" : "bg-severity-critical";
  return (
    <div className="h-2 w-full rounded-full bg-slate-700">
      <div className={cn("h-2 rounded-full transition-all duration-700", color)} style={{ width: `${score}%` }} />
    </div>
  );
}

export function CompletionModal({ result, scenarioTitle, timeTaken, onRetry, onClose }: Props) {
  const [downloading, setDownloading] = useState(false);
  const totalXp = result.xpEarned + result.timeBonusXp;
  const today = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });

  const handleDownloadCert = async () => {
    setDownloading(true);
    try {
      const { jsPDF } = await import("jspdf");

      // A4 landscape, mm units
      const pdf = new jsPDF({ orientation: "landscape", unit: "mm", format: "a4" });
      const W = 297;
      const H = 210;

      // ── Background ───────────────────────────────────────────────────────────
      pdf.setFillColor(13, 21, 32);           // #0d1520
      pdf.rect(0, 0, W, H, "F");

      // ── Outer border ─────────────────────────────────────────────────────────
      pdf.setDrawColor(34, 211, 238);         // cyan
      pdf.setLineWidth(1.0);
      pdf.roundedRect(10, 10, W - 20, H - 20, 6, 6, "S");

      // ── Inner accent border ───────────────────────────────────────────────────
      pdf.setDrawColor(34, 211, 238, 0.3);
      pdf.setLineWidth(0.3);
      pdf.roundedRect(14, 14, W - 28, H - 28, 4, 4, "S");

      // ── Decorative corner marks ───────────────────────────────────────────────
      const markLen = 8;
      pdf.setDrawColor(34, 211, 238);
      pdf.setLineWidth(0.6);
      const corners: [number, number, number, number][] = [
        [20, 20, 20 + markLen, 20],
        [20, 20, 20, 20 + markLen],
        [W - 20, 20, W - 20 - markLen, 20],
        [W - 20, 20, W - 20, 20 + markLen],
        [20, H - 20, 20 + markLen, H - 20],
        [20, H - 20, 20, H - 20 - markLen],
        [W - 20, H - 20, W - 20 - markLen, H - 20],
        [W - 20, H - 20, W - 20, H - 20 - markLen],
      ];
      corners.forEach(([x1, y1, x2, y2]) => pdf.line(x1, y1, x2, y2));

      // ── HACK THE SOC header ───────────────────────────────────────────────────
      pdf.setTextColor(34, 211, 238);
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(26);
      pdf.text("HACK THE SOC", W / 2, 42, { align: "center" });

      // Underline header
      pdf.setDrawColor(34, 211, 238);
      pdf.setLineWidth(0.4);
      pdf.line(W / 2 - 44, 45, W / 2 + 44, 45);

      // ── Subtitle ─────────────────────────────────────────────────────────────
      pdf.setTextColor(148, 163, 184);       // slate-400
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(9);
      pdf.text("C E R T I F I C A T E   O F   C O M P L E T I O N", W / 2, 53, { align: "center" });

      // ── "This certifies that" ─────────────────────────────────────────────────
      pdf.setFontSize(11);
      pdf.setTextColor(148, 163, 184);
      pdf.text("This certifies that", W / 2, 72, { align: "center" });

      // ── Analyst name ──────────────────────────────────────────────────────────
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(28);
      pdf.setTextColor(255, 255, 255);
      pdf.text("Tal Ben Dosa", W / 2, 88, { align: "center" });

      // Name underline
      pdf.setDrawColor(100, 116, 139);      // slate-500
      pdf.setLineWidth(0.3);
      pdf.line(W / 2 - 52, 91, W / 2 + 52, 91);

      // ── "has successfully completed" ─────────────────────────────────────────
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(11);
      pdf.setTextColor(148, 163, 184);
      pdf.text("has successfully completed the scenario", W / 2, 101, { align: "center" });

      // ── Scenario title ────────────────────────────────────────────────────────
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(20);
      pdf.setTextColor(34, 211, 238);
      const title = scenarioTitle.length > 48 ? scenarioTitle.slice(0, 45) + "…" : scenarioTitle;
      pdf.text(title, W / 2, 116, { align: "center" });

      // ── Stats row ─────────────────────────────────────────────────────────────
      const statsY = 140;
      const stats: { label: string; value: string }[] = [
        { label: "Score",    value: `${result.score}%`         },
        { label: "XP Earned", value: `+${totalXp} XP`         },
        { label: "Time",      value: formatTime(timeTaken)     },
        { label: "Date",      value: today                     },
      ];
      const colW = 50;
      const startX = W / 2 - (colW * stats.length) / 2 + colW / 2;

      stats.forEach((s, i) => {
        const cx = startX + i * colW;

        // Stat box
        pdf.setFillColor(14, 26, 45);        // slightly lighter than bg
        pdf.setDrawColor(30, 42, 56);        // border
        pdf.setLineWidth(0.3);
        pdf.roundedRect(cx - colW / 2 + 2, statsY - 10, colW - 4, 22, 3, 3, "FD");

        // Value
        pdf.setFont("helvetica", "bold");
        pdf.setFontSize(14);
        pdf.setTextColor(226, 232, 240);     // slate-200
        pdf.text(s.value, cx, statsY + 1, { align: "center" });

        // Label
        pdf.setFont("helvetica", "normal");
        pdf.setFontSize(7.5);
        pdf.setTextColor(100, 116, 139);     // slate-500
        pdf.text(s.label.toUpperCase(), cx, statsY + 8, { align: "center" });
      });

      // ── Footer ────────────────────────────────────────────────────────────────
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(8);
      pdf.setTextColor(71, 85, 105);         // slate-600
      pdf.text("SOC Analyst Training Platform  •  hack-the-soc.vercel.app", W / 2, H - 16, { align: "center" });

      // ── Save ─────────────────────────────────────────────────────────────────
      const safeName = scenarioTitle.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      pdf.save(`certificate-${safeName}.pdf`);
    } catch (err) {
      console.error("Certificate generation failed:", err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-xl border border-border bg-[#0d1520] shadow-2xl">
        {/* Header */}
        <div className={cn(
          "rounded-t-xl px-6 py-5 text-center",
          result.passed ? "bg-neon-green/10 border-b border-neon-green/20" : "bg-severity-high/10 border-b border-severity-high/20"
        )}>
          {result.passed
            ? <Trophy className="mx-auto h-10 w-10 text-neon-green mb-2" />
            : <ShieldX className="mx-auto h-10 w-10 text-severity-high mb-2" />
          }
          <h2 className="text-xl font-bold text-white">
            {result.passed ? "Investigation Complete" : "Investigation Closed"}
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            {result.passed ? "Well done — you cleared the case." : "Review the feedback and retry to improve your score."}
          </p>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Score strip */}
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded border border-border bg-[#080d14] px-3 py-3 text-center">
              <p className="font-mono text-2xl font-bold text-white">{result.score}%</p>
              <p className="mt-1 text-[10px] uppercase tracking-widest text-slate-500">Score</p>
            </div>
            <div className="rounded border border-border bg-[#080d14] px-3 py-3 text-center">
              <p className="font-mono text-2xl font-bold text-cyber-300">+{totalXp}</p>
              <p className="mt-1 text-[10px] uppercase tracking-widest text-slate-500">XP Earned</p>
            </div>
            <div className="rounded border border-border bg-[#080d14] px-3 py-3 text-center">
              <p className="font-mono text-2xl font-bold text-slate-200">{formatTime(timeTaken)}</p>
              <p className="mt-1 text-[10px] uppercase tracking-widest text-slate-500">Time</p>
            </div>
          </div>

          {/* Progress bar */}
          <div>
            <div className="mb-1.5 flex justify-between text-[10px] text-slate-500">
              <span>Score Progress</span>
              <span>{result.score >= 70 ? "Passed ✓" : "Need 70% to pass"}</span>
            </div>
            <ScoreBar score={result.score} />
          </div>

          {result.timeBonusXp > 0 && (
            <div className="rounded border border-neon-green/20 bg-neon-green/5 px-3 py-2 text-xs text-neon-green">
              Time bonus: +{result.timeBonusXp} XP for completing in {formatTime(timeTaken)}
            </div>
          )}

          {/* Question breakdown */}
          <div>
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
              Question Breakdown
            </p>
            <div className="space-y-2">
              {result.perQuestion.map((q, i) => (
                <div key={q.id} className={cn(
                  "rounded border px-3 py-2.5",
                  q.correct ? "border-neon-green/20 bg-neon-green/5" : "border-severity-high/20 bg-severity-high/5"
                )}>
                  <div className="flex items-start gap-2">
                    {q.correct
                      ? <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-neon-green" />
                      : <ShieldX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-severity-high" />
                    }
                    <div className="min-w-0">
                      <p className="text-xs text-slate-200">
                        <span className="font-mono text-[10px] text-slate-500 mr-1.5">Q{i + 1}.</span>
                        {q.prompt}
                      </p>
                      {!q.correct && (
                        <p className="mt-1 text-[10px] text-slate-400">
                          Correct: <span className="text-neon-green font-mono">
                            {Array.isArray(q.correctAnswer) ? q.correctAnswer.join(", ") : q.correctAnswer}
                          </span>
                        </p>
                      )}
                      <p className="mt-1 text-[10px] text-slate-500">{q.explanation}</p>
                      {q.correct && (
                        <p className="mt-0.5 text-[10px] text-neon-green/70">+{q.xp} XP</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* AI Feedback */}
          {result.aiFeedback && (
            <div>
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                AI Analyst Feedback
              </p>
              <div className="rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
                <p className="text-xs leading-relaxed text-slate-300">{result.aiFeedback}</p>
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="border-t border-border px-6 py-4 flex flex-wrap gap-2 justify-end">
          <button
            onClick={onRetry}
            className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-white/5 transition"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Retry
          </button>
          {result.passed && (
            <button
              onClick={handleDownloadCert}
              disabled={downloading}
              className="flex items-center gap-1.5 rounded border border-neon-green/30 bg-neon-green/10 px-3 py-1.5 text-xs font-medium text-neon-green hover:bg-neon-green/20 transition disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {downloading
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <Download className="h-3.5 w-3.5" />
              }
              {downloading ? "Generating…" : "Certificate (PDF)"}
            </button>
          )}
          <button
            onClick={onClose}
            className="flex items-center gap-1.5 rounded bg-cyber-500/20 border border-cyber-500/30 px-3 py-1.5 text-xs font-medium text-cyber-300 hover:bg-cyber-500/30 transition"
          >
            Continue <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
