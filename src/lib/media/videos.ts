/**
 * Explainer videos shown next to long reading content (feedback FB-008).
 *
 * The rendering (rooms reading tasks, Learning Path lessons) lives in the UI;
 * the curated data lives in `src/data/roomVideos.ts` and `src/data/lessonVideos.ts`.
 * Every entry must be a real, embeddable YouTube video verified via YouTube's
 * oEmbed endpoint (title + channel captured from it), from a reputable channel.
 * Embeds use youtube-nocookie.com (privacy-enhanced mode).
 */
export interface VideoRef {
  /** 11-char YouTube video id. */
  youtubeId: string;
  /** Title exactly as returned by YouTube oEmbed. */
  title: string;
  /** Channel name (oEmbed author_name). */
  channel: string;
  /** Approximate length in minutes, if known. */
  minutes?: number;
  /** Optional start offset in seconds (jump to the relevant part). */
  startSec?: number;
}

/** A valid YouTube id: 11 chars of [A-Za-z0-9_-]. */
export const isYouTubeId = (id: string): boolean => /^[A-Za-z0-9_-]{11}$/.test(id);

/** Privacy-enhanced embed URL for a video (no tracking cookies until play). */
export function embedUrl(v: VideoRef): string {
  const start = v.startSec && v.startSec > 0 ? `?start=${Math.floor(v.startSec)}` : "";
  return `https://www.youtube-nocookie.com/embed/${v.youtubeId}${start}`;
}
