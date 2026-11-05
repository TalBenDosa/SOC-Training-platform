import { toSpeechText, speechHash } from "@/components/media/speechText";
import { ROOM_NARRATION, NARRATION_BASE } from "@/data/roomNarration";

/**
 * The neural-voice recording for a room reading (same voices as the lesson videos),
 * or undefined when there is none or a word of the reading changed since it was recorded
 * (then the Listen button uses the browser voice). A punctuation fix keeps the recording:
 * the audio still says exactly what is on the page.
 */
export function roomNarrationSrc(roomId: string, taskId: string, spokenMarkdown: string): string | undefined {
  const entry = ROOM_NARRATION[`${roomId}/${taskId}`];
  if (!entry) return undefined;
  const speech = toSpeechText(spokenMarkdown);
  const sameWords = entry.w === speechHash(speech.toLowerCase().replace(/[^a-z0-9]+/g, ""));
  if (speechHash(speech) !== entry.h && !sameWords) return undefined;
  return `${NARRATION_BASE}/${encodeURIComponent(roomId)}/${encodeURIComponent(taskId)}-${entry.h}.mp3`;
}
