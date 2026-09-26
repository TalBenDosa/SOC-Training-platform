/**
 * Contiguous watermark for the team event log (audit C1). The room used to track
 * only the HIGHEST seq it had seen and pull `seq > max` — so if seq 50 was missed
 * (socket blip, backgrounded tab, a failed broadcast) and seq 51 arrived, seq 50
 * was gone until a reload, and each client's log (and AAR) could differ.
 * Now the pull cursor is the contiguous watermark: the highest seq such that every
 * lower seq has been seen. A broadcast that jumps past it reveals a gap, and the
 * next pull (`seq > watermark`) fills it. Pure helpers.
 */
export function advanceWatermark(seen: ReadonlySet<number>, watermark: number): number {
  let w = watermark;
  while (seen.has(w + 1)) w++;
  return w;
}

/** True when an incoming seq leaves a hole above the watermark. */
export function revealsGap(watermark: number, incomingSeq: number): boolean {
  return incomingSeq > watermark + 1;
}
