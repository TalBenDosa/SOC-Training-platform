"use client";
import React, { useRef, useState } from "react";
import { RotateCcw } from "lucide-react";
import { useBrand } from "@/lib/brand/BrandContext";

/**
 * Explainer videos end with a 4-second HACK THE SOC logo outro burned into the file
 * (motion-studio/add-outro.mjs, DUR = 4.0). On a white-label organization's platform the
 * player stops just before it and shows the organization's own animated end card instead
 * (logo, name, its theme colours), so every video ends on the customer's brand.
 */
export const OUTRO_SECONDS = 4;

/**
 * A self-hosted explainer video inside a lesson reading — the moving-picture
 * sibling of LessonFigure. Shown as a supplement to the text, never a
 * replacement for it, and strictly same-origin: the mp4 and its WebVTT subtitle
 * tracks are served from /public. No external/embedded players (YouTube and
 * friends were deliberately removed from the platform).
 *
 * SHARED ON PURPOSE, exactly like LessonFigure: both lesson readers (the /learn
 * modal and the /learn/[slug]/[lesson] route, plus the room ReadingBody) import
 * this one component so a video can never render in one surface and silently
 * vanish in another.
 */
export interface LessonVideoData {
  /** Either a same-origin path under /public (e.g. "/lesson-videos/ids-vs-ips/ids-vs-ips.mp4")
   *  or an absolute https URL in THIS project's Supabase Storage bucket. */
  src: string;
  /** Optional poster image shown before play. */
  poster?: string;
  caption?: string;
  /** Selectable subtitle tracks (same-origin /public or Supabase WebVTT). Mark one `default`. */
  tracks?: { srclang: string; label: string; src: string; default?: boolean }[];
}

export function LessonVideo({ video }: { video: LessonVideoData }) {
  const brand = useBrand();
  const ref = useRef<HTMLVideoElement>(null);
  const [endCard, setEndCard] = useState(false);
  if (!video?.src) return null;
  // White label: hold playback (and any seek) before the platform outro, and end on the
  // organization's own card instead.
  const stopBeforeOutro = brand.whiteLabel
    ? () => {
        const v = ref.current;
        if (!v || !Number.isFinite(v.duration) || v.duration <= OUTRO_SECONDS + 1) return;
        const end = v.duration - OUTRO_SECONDS;
        if (v.currentTime >= end) { v.pause(); v.currentTime = end - 0.05; setEndCard(true); }
      }
    : undefined;
  const replay = () => {
    const v = ref.current;
    setEndCard(false);
    if (v) { v.currentTime = 0; void v.play().catch(() => {}); }
  };
  return (
    <figure className="relative overflow-hidden rounded-lg border border-border bg-black">
      {/* eslint-disable-next-line jsx-a11y/media-has-caption -- captions ARE provided via <track>; this lint can't see them through the map */}
      <video
        ref={ref}
        onTimeUpdate={stopBeforeOutro}
        onSeeked={stopBeforeOutro}
        onPlay={() => setEndCard(false)}
        controls
        preload="metadata"
        playsInline
        // Required so cross-origin subtitle <track>s (served from this project's
        // Supabase Storage bucket) are allowed to load; harmless for same-origin
        // /public videos. Supabase public objects send Access-Control-Allow-Origin.
        crossOrigin="anonymous"
        poster={video.poster}
        className="mx-auto w-full max-h-[min(78vh,calc(100dvh-200px))] bg-black"
      >
        {/* Without a poster, append a #t media fragment so the browser seeks to the
            first frame and paints it as the still — otherwise preload="metadata"
            shows only a black box until the viewer presses play. */}
        <source src={video.poster ? video.src : `${video.src}#t=0.1`} type="video/mp4" />
        {/* The narration is English, so the English track is same-language captions
            (WCAG 1.2.2); translations (he/es) stay "subtitles". */}
        {(video.tracks ?? []).map((t) => (
          <track
            key={t.srclang}
            kind={/^en\b/i.test(t.srclang) ? "captions" : "subtitles"}
            srcLang={t.srclang}
            label={t.label}
            src={t.src}
            default={t.default}
          />
        ))}
      </video>
      {endCard && brand.whiteLabel && (
        // The organization's end card: its logo and name on its own colours (theme tokens).
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 bg-bg [container-type:size]"
          style={{ backgroundImage: "radial-gradient(ellipse 60% 55% at 50% 45%, rgb(var(--cyber-400) / 0.16), transparent 70%)" }}>
          <div className="wl-endcard-in flex flex-col items-center gap-3">
            {brand.logoSrc && (
              // eslint-disable-next-line @next/next/no-img-element -- same-origin logo route
              <img src={brand.logoSrc} alt={brand.logoHasName ? brand.productName : ""}
                className="h-[clamp(88px,42cqh,260px)] w-auto max-w-[70%] object-contain drop-shadow-[0_0_30px_rgb(var(--cyber-400)/0.25)]" />
            )}
            {!brand.logoHasName && <p className="text-[clamp(20px,9cqh,44px)] font-bold tracking-wide text-white">{brand.productName}</p>}
          </div>
          <button type="button" onClick={replay}
            className="wl-endcard-in-late mt-2 inline-flex items-center gap-1.5 rounded-md border border-border-strong bg-bg-elevated/80 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:border-cyber-500/60 hover:text-white">
            <RotateCcw className="h-3.5 w-3.5" /> Watch again
          </button>
        </div>
      )}
      {video.caption && (
        <figcaption className="border-t border-border px-3 py-2 text-center text-[11px] text-slate-400">
          {video.caption}
        </figcaption>
      )}
    </figure>
  );
}
