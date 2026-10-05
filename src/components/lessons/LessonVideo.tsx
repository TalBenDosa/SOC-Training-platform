import React from "react";

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
  /** Same-origin path under /public, e.g. "/lesson-videos/ids-vs-ips/ids-vs-ips.mp4". */
  src: string;
  /** Optional same-origin poster image shown before play. */
  poster?: string;
  caption?: string;
  /** Selectable subtitle tracks (same-origin WebVTT). Mark one `default`. */
  tracks?: { srclang: string; label: string; src: string; default?: boolean }[];
}

export function LessonVideo({ video }: { video: LessonVideoData }) {
  if (!video?.src) return null;
  return (
    <figure className="overflow-hidden rounded-lg border border-border bg-black">
      {/* eslint-disable-next-line jsx-a11y/media-has-caption -- captions ARE provided via <track>; this lint can't see them through the map */}
      <video
        controls
        preload="metadata"
        playsInline
        poster={video.poster}
        className="mx-auto w-full max-h-[520px] bg-black"
      >
        {/* Without a poster, append a #t media fragment so the browser seeks to the
            first frame and paints it as the still — otherwise preload="metadata"
            shows only a black box until the viewer presses play. */}
        <source src={video.poster ? video.src : `${video.src}#t=0.1`} type="video/mp4" />
        {(video.tracks ?? []).map((t) => (
          <track
            key={t.srclang}
            kind="subtitles"
            srcLang={t.srclang}
            label={t.label}
            src={t.src}
            default={t.default}
          />
        ))}
      </video>
      {video.caption && (
        <figcaption className="border-t border-border px-3 py-2 text-center text-[11px] text-slate-400">
          {video.caption}
        </figcaption>
      )}
    </figure>
  );
}
