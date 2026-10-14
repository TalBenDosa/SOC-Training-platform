import type { AuthoredPathLesson } from "./types";
import { lessons_sa1 } from "./group-sa1";
import { lessons_sa2 } from "./group-sa2";
import { lessons_th1 } from "./group-th1";
import { lessons_th2 } from "./group-th2";
import { lessons_ir1 } from "./group-ir1";
import { lessons_ir2 } from "./group-ir2";
import { lessons_de } from "./group-de";
import { lessons_pt } from "./group-pt";

/**
 * Hand-written content for every Learning Path lesson, keyed by
 * `${pathSlug}--${lessonSlug}`. The lesson resolver serves this FIRST — no AI
 * key needed, and every learner gets the same pages and the same quiz (so a
 * quiz graded on another server instance can never mismatch).
 */
export const PATH_LESSON_CONTENT: Record<string, AuthoredPathLesson> = {
  ...lessons_sa1, ...lessons_sa2,
  ...lessons_th1, ...lessons_th2,
  ...lessons_ir1, ...lessons_ir2,
  ...lessons_de,
  ...lessons_pt,
};
export type { AuthoredPathLesson };
