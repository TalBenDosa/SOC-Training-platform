"use client";
/**
 * The rank-up moment made shareable.
 *
 * When a learner crosses a rank threshold, EarnMoment opens this modal with the
 * rank they just earned. It shows ONE certificate — the one they just reached,
 * never a gallery — rendered to a canvas so the on-screen preview and the
 * downloaded PNG are literally the same pixels. Share routes: native share
 * (attaches the image on mobile), LinkedIn, X, or copy-link; on desktop the
 * social buttons open a composer and the learner attaches the downloaded image,
 * so the caption explains that.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { motion } from "framer-motion";
import { format } from "date-fns";
import { Download, Share2, Linkedin, Copy, Check, X, PartyPopper } from "lucide-react";
import type { Rank } from "@/lib/progression/ranks";
import { certMetaForRank, drawCertificate, canvasToPng, type CertMeta } from "@/lib/certificate/renderCertificate";

interface Props {
  rank: Rank;
  xp: number;
  name: string;
  onClose: () => void;
}

export function RankCertificateModal({ rank, xp, name, onClose }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [copied, setCopied] = useState(false);
  const [ready, setReady] = useState(false);
  const meta: CertMeta = certMetaForRank(rank);
  // The rank's own threshold is the milestone — not the learner's live total,
  // which may already be higher by the time they dismiss the modal.
  const milestoneXp = rank.minXp;
  const filename = `HackTheSOC-${meta.title.replace(/\s+/g, "")}-${rank.id}.png`;
  const site = typeof window !== "undefined" ? window.location.origin : "https://hack-the-soc.vercel.app";
  const shortTier = meta.tier.split(" · ")[0];
  const shareText = `I just reached ${meta.title} · ${shortTier} on HACK THE SOC 🛡️ — training to become a SOC analyst.`;

  // Draw once the fonts are ready. Re-draw if the rank/name changes.
  useEffect(() => {
    let cancelled = false;
    const canvas = canvasRef.current;
    if (!canvas) return;
    setReady(false);
    drawCertificate(canvas, { meta, name, xp: milestoneXp, date: format(new Date(), "d MMM yyyy") }).then(() => {
      if (!cancelled) setReady(true);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rank.id, name]);

  // ESC closes, matching every other overlay on the platform.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const triggerDownload = (blob: Blob) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const downloadPng = useCallback(async () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const blob = await canvasToPng(canvas);
    if (blob) triggerDownload(blob);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filename]);

  const nativeShare = useCallback(async () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const blob = await canvasToPng(canvas);
    if (!blob) return;
    const file = new File([blob], filename, { type: "image/png" });
    const nav = navigator as Navigator & {
      canShare?: (d: ShareData & { files?: File[] }) => boolean;
      share?: (d: ShareData & { files?: File[] }) => Promise<void>;
    };
    if (nav.canShare?.({ files: [file] }) && nav.share) {
      try {
        await nav.share({ files: [file], title: "HACK THE SOC", text: shareText });
      } catch {
        /* user dismissed the share sheet — nothing to do */
      }
    } else {
      triggerDownload(blob);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filename, shareText]);

  const openLinkedIn = () =>
    window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(site)}`, "_blank", "noopener,noreferrer");

  const openX = () =>
    window.open(
      `https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(site)}`,
      "_blank",
      "noopener,noreferrer",
    );

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(`${shareText} ${site}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked — the download button is always available */
    }
  };

  return createPortal(
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={`Certificate earned: ${meta.title}`}
    >
      <motion.div
        initial={{ opacity: 0, y: 16, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: "spring", damping: 22, stiffness: 240 }}
        className="w-full max-w-2xl overflow-hidden rounded-2xl border border-border bg-bg-elevated shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="h-1 w-full bg-gradient-to-r from-cyber-500 via-neon-purple to-neon-amber" />

        <div className="flex items-start justify-between gap-4 px-6 pt-5">
          <div className="flex items-center gap-2">
            <PartyPopper className="h-5 w-5 text-neon-amber" />
            <div>
              <p className="text-[11px] font-black uppercase tracking-[0.2em] text-neon-amber">Rank Up</p>
              <h2 className="text-lg font-bold text-white">
                You reached {meta.title} · {shortTier}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-md border border-border px-2 py-1 text-xs text-slate-400 transition hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* The certificate itself */}
        <div className="px-6 pt-4">
          <div className="relative overflow-hidden rounded-xl border border-border/60 shadow-[0_0_40px_-12px_rgba(6,182,212,0.35)]">
            <canvas ref={canvasRef} className="block h-auto w-full" aria-label={`${meta.title} certificate for ${name}`} />
            {!ready && (
              <div className="absolute inset-0 flex items-center justify-center bg-[#070b14] text-xs text-slate-500" aria-hidden>
                Rendering certificate…
              </div>
            )}
          </div>
          <p className="mt-2 text-center text-[11px] text-slate-500">
            The image shows your name and rank only — never your account or email.
          </p>
        </div>

        {/* Share bar */}
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2 border-t border-border/60 bg-bg/40 px-6 py-4">
          <button
            onClick={nativeShare}
            className="inline-flex items-center gap-2 rounded-lg border border-cyber-500/40 bg-cyber-500/15 px-3.5 py-2 text-xs font-bold text-cyber-300 transition hover:bg-cyber-500/25"
          >
            <Share2 className="h-4 w-4" /> Share
          </button>
          <button
            onClick={downloadPng}
            className="inline-flex items-center gap-2 rounded-lg border border-neon-green/30 bg-neon-green/12 px-3.5 py-2 text-xs font-bold text-neon-green transition hover:bg-neon-green/20"
          >
            <Download className="h-4 w-4" /> Download PNG
          </button>
          <button
            onClick={openLinkedIn}
            className="inline-flex items-center gap-2 rounded-lg bg-[#0a66c2] px-3.5 py-2 text-xs font-bold text-white transition hover:brightness-110"
          >
            <Linkedin className="h-4 w-4" /> LinkedIn
          </button>
          <button
            onClick={openX}
            className="inline-flex items-center gap-2 rounded-lg border border-[#333] bg-[#111] px-3.5 py-2 text-xs font-bold text-white transition hover:brightness-125"
          >
            <svg viewBox="0 0 24 24" fill="currentColor" className="h-3.5 w-3.5">
              <path d="M18.9 2H22l-7.3 8.3L23 22h-6.6l-5.2-6.8L5.3 22H2l7.8-8.9L1.5 2h6.8l4.7 6.2zm-1.2 18h1.7L7.1 3.7H5.3z" />
            </svg>
            Post on X
          </button>
          <button
            onClick={copyLink}
            className="inline-flex items-center gap-2 rounded-lg border border-border bg-bg px-3.5 py-2 text-xs font-bold text-slate-300 transition hover:text-white"
          >
            {copied ? <Check className="h-4 w-4 text-neon-green" /> : <Copy className="h-4 w-4" />}
            {copied ? "Copied" : "Copy link"}
          </button>
        </div>
        <p className="pb-4 text-center text-[10px] text-slate-500">
          On desktop, LinkedIn and X open a new post — attach the downloaded image there.
        </p>
      </motion.div>
    </div>,
    document.body,
  );
}
