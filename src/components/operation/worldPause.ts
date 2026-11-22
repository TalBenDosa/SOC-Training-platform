/**
 * While a story film plays, the 3D room world behind it is hidden but would keep rendering every
 * frame (WebGL + post-processing) and compete with the video decoder. On an average laptop that
 * made films stutter (learner feedback 2026-11-21). A film holds a pause while it is open; every
 * world's frame loop skips its work while any pause is held.
 *
 * Kept free of three.js so the film player can import it without pulling the 3D bundle in.
 */
let holds = 0;

export function worldsPaused(): boolean {
  return holds > 0;
}

/** Pause every room world until the returned release is called (safe to call release twice). */
export function pauseWorlds(): () => void {
  holds++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    holds = Math.max(0, holds - 1);
  };
}
