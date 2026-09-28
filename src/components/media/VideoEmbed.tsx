"use client";
/**
 * Explainer-video embed for long reading content (feedback FB-008).
 *
 * Click-to-load: nothing is fetched from YouTube until the learner presses
 * play (a poster button stands in), so pages stay fast and no third-party
 * request happens for learners who never watch. The player itself is the
 * privacy-enhanced youtube-nocookie.com embed from `embedUrl()`.
 *
 * CSP: needs `frame-src https://www.youtube-nocookie.com` (next.config.mjs).
 * The poster is local (gradient + title) — no i.ytimg.com thumbnail — so the
 * "nothing until play" promise really holds.
 */
import React, { useState } from "react";
import { ExternalLink, Play, Youtube } from "lucide-react";
import { cn } from "@/lib/utils";
import { embedUrl, isYouTubeId, type VideoRef } from "@/lib/media/videos";

function watchUrl(v: VideoRef): string {
  const t = v.startSec && v.startSec > 0 ? `&t=${Math.floor(v.startSec)}s` : "";
  return `https://www.youtube.com/watch?v=${v.youtubeId}${t}`;
}

export function VideoEmbed({ video, className }: { video: VideoRef; className?: string }) {
  const [active, setActive] = useState(false);
  if (!isYouTubeId(video.youtubeId)) return null;

  const base = embedUrl(video);
  const src = `${base}${base.includes("?") ? "&" : "?"}autoplay=1&rel=0`;

  return (
    <figure className={cn("overflow-hidden rounded-lg border border-border bg-[#080d14]", className)}>
      <div className="relative aspect-video w-full bg-black">
        {active ? (
          <iframe
            src={src}
            title={video.title}
            loading="lazy"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
            referrerPolicy="strict-origin-when-cross-origin"
            allowFullScreen
            className="absolute inset-0 h-full w-full border-0"
          />
        ) : (
          <button
            type="button"
            onClick={() => setActive(true)}
            aria-label={`Play video: ${video.title}`}
            className="group absolute inset-0 flex h-full w-full flex-col items-center justify-center gap-3 bg-gradient-to-br from-[#0d1520] to-[#05080d] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-500/60"
          >
            {/* No remote poster: a YouTube thumbnail would contact Google before the learner
                chooses to play. The title stands in for it. */}
            <span className="relative max-w-[85%] text-center text-sm font-medium text-slate-200 line-clamp-2">{video.title}</span>
            <span className="relative flex h-14 w-14 items-center justify-center rounded-full bg-red-600/90 shadow-lg shadow-black/50 transition-transform group-hover:scale-105">
              <Play className="h-6 w-6 translate-x-0.5 fill-white text-white" aria-hidden />
            </span>
            <span className="relative rounded bg-black/60 px-2 py-0.5 text-[11px] text-slate-200">
              Click to load video{video.minutes ? ` · ${video.minutes} min` : ""}
            </span>
          </button>
        )}
      </div>
      <figcaption className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border/60 px-4 py-2.5 text-xs">
        <Youtube className="h-3.5 w-3.5 shrink-0 text-red-400" aria-hidden />
        <span className="font-semibold text-slate-200">{video.title}</span>
        <span className="text-slate-400">{video.channel}{video.minutes ? ` · ${video.minutes} min` : ""}</span>
        <a
          href={watchUrl(video)}
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto inline-flex items-center gap-1 text-cyber-300 hover:text-cyber-200"
        >
          Watch on YouTube <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
      </figcaption>
    </figure>
  );
}

/** A "Watch" block for one or more videos. Renders nothing when there are none. */
export function VideoSection({
  videos, heading = "Watch", className,
}: { videos: readonly VideoRef[] | undefined; heading?: string; className?: string }) {
  const list = (videos ?? []).filter(v => isYouTubeId(v.youtubeId));
  if (list.length === 0) return null;
  return (
    <section aria-label={heading} className={cn("space-y-3", className)}>
      <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{heading}</p>
      {list.map(v => <VideoEmbed key={`${v.youtubeId}:${v.startSec ?? 0}`} video={v} />)}
    </section>
  );
}

export default VideoEmbed;
