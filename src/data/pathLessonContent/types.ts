import type { LessonPage, LessonQuizQuestion } from "@/lib/lessons/lessonContent";

/** A hand-written Learning Path lesson: pages + knowledge-check quiz (answer key server-side). */
export interface AuthoredPathLesson {
  pages: LessonPage[];
  quiz: LessonQuizQuestion[];
}
