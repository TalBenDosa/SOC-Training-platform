import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { notFound } from "next/navigation";
import { CheckCircle2, Circle, Lock, PlayCircle } from "lucide-react";
import { LESSON_PATHS } from "@/lib/lessons/paths";

const kindLabel: Record<string, string> = {
  lesson:     "lesson",
  lab:        "lab",
  quiz:       "quiz",
  simulation: "sim",
};

const kindColor: Record<string, string> = {
  lesson:     "text-slate-400 border-slate-500/30 bg-slate-500/10",
  lab:        "text-neon-blue border-neon-blue/30 bg-neon-blue/10",
  quiz:       "text-neon-amber border-neon-amber/30 bg-neon-amber/10",
  simulation: "text-neon-purple border-neon-purple/30 bg-neon-purple/10",
};

export default function PathDetail({ params }: { params: { slug: string } }) {
  const path = LESSON_PATHS.find(p => p.slug === params.slug);
  if (!path) notFound();

  const totalLessons = path.modules.reduce((n, m) => n + m.lessons.length, 0);
  const totalXp      = path.modules.reduce((n, m) => n + m.lessons.reduce((x, l) => x + l.xp, 0), 0);

  // Simulate first two lessons as "completed" so the UI shows a progress example.
  // In production this comes from Supabase lesson_progress table.
  const completedSlugs = new Set<string>([
    path.modules[0]?.lessons[0]?.slug ?? "",
  ]);

  let globalIdx = 0;

  return (
    <div>
      <Topbar
        title={path.title}
        subtitle={`${totalLessons} lessons · ${totalXp.toLocaleString()} XP`}
      />
      <div className="container mx-auto max-w-4xl px-6 py-6 space-y-4">
        {/* Path summary bar */}
        <div className="rounded-lg border border-border bg-bg-elevated px-5 py-3 flex items-center gap-4 text-sm text-slate-300">
          <span className="text-slate-500">Progress</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyber-500 to-neon-green transition-all"
              style={{ width: `${Math.round((completedSlugs.size / totalLessons) * 100)}%` }}
            />
          </div>
          <span className="font-mono text-xs text-slate-400">
            {completedSlugs.size}/{totalLessons} complete
          </span>
          <span className="font-mono text-xs text-cyber-300">
            {completedSlugs.size * 75} / {totalXp} XP earned
          </span>
        </div>

        {path.modules.map((m, mi) => (
          <Card key={m.slug}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Module {mi + 1}</p>
                <h3 className="text-base font-semibold text-white">{m.title}</h3>
              </div>
              <Badge variant="outline">{m.lessons.length} lessons</Badge>
            </div>

            <ul className="mt-3 divide-y divide-border">
              {m.lessons.map((l, li) => {
                const isFirst    = globalIdx === 0;
                const isDone     = completedSlugs.has(l.slug);
                const isLocked   = globalIdx > completedSlugs.size + 1;
                const lessonPath = `/learn/${path.slug}/${l.slug}`;
                globalIdx++;

                return (
                  <li key={l.slug} className={cn("flex items-center justify-between py-2.5 text-sm", isLocked && "opacity-50")}>
                    <div className="flex items-center gap-3 min-w-0">
                      {isDone  ? <CheckCircle2 className="h-4 w-4 shrink-0 text-neon-green" /> :
                       isFirst  ? <PlayCircle   className="h-4 w-4 shrink-0 text-cyber-300"  /> :
                       isLocked ? <Lock         className="h-4 w-4 shrink-0 text-slate-600"  /> :
                                  <Circle       className="h-4 w-4 shrink-0 text-slate-600"  />}
                      <span className={cn("truncate", isDone ? "text-slate-400 line-through" : "text-slate-200")}>
                        {l.title}
                      </span>
                      <span className={cn("rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-widest shrink-0", kindColor[l.kind])}>
                        {kindLabel[l.kind]}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-slate-500 shrink-0 ml-3">
                      <span>{l.min} min</span>
                      <span className="font-mono text-cyber-300">+{l.xp} XP</span>
                      {!isLocked && (
                        <Link href={lessonPath}>
                          <Button size="sm" variant={isFirst && !isDone ? "primary" : "ghost"}>
                            {isDone ? "Review" : "Open"}
                          </Button>
                        </Link>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </Card>
        ))}
      </div>
    </div>
  );
}

