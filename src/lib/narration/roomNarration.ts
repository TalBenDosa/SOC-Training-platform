import { toSpeechText, speechHash } from "@/components/media/speechText";
import { ROOM_NARRATION, NARRATION_BASE } from "@/data/roomNarration";

/**
 * The neural-voice recording for a room reading (same voices as the lesson videos),
 * or undefined when there is none or the reading changed since it was recorded
 * (then the Listen button uses the browser voice).
 */
export function roomNarrationSrc(roomId: string, taskId: string, spokenMarkdown: string): string | undefined {
  const entry = ROOM_NARRATION[`${roomId}/${taskId}`];
  if (!entry) return undefined;
  if (speechHash(toSpeechText(spokenMarkdown)) !== entry.h) return undefined;
  return `${NARRATION_BASE}/${encodeURIComponent(roomId)}/${encodeURIComponent(taskId)}-${entry.h}.mp3`;
}
