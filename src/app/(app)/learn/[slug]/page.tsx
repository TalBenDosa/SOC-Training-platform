import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Circle, PlayCircle } from "lucide-react";
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

export default async function PathDetail({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const path = LESSON_PATHS.find(p => p.slug === slug);
  if (!path) notFound();

  const totalLessons = path.modules.reduce((n, m) => n + m.lessons.length, 0);
  const totalXp      = path.modules.reduce((n, m) => n + m.lessons.reduce((x, l) => x + l.xp, 0), 0);

  // No fabricated progress: there is no lesson-progress store yet, and this is a
  // server component that can't read client state anyway. Showing a made-up
  // "1/N complete · 75 XP earned" bar is exactly the fake-gamification the
  // platform forbids — so the path renders as an honest, fully-browsable outline.
  let globalIdx = 0;

  return (
    <div>
      <Topbar
        title={path.title}
        subtitle={`${totalLessons} lessons · ${totalXp.toLocaleString()} XP`}
      />
      <div className="container mx-auto max-w-4xl px-6 py-6 space-y-4">
        {/* Honest path summary — the Topbar already carries the lesson/XP totals. */}
        <p className="rounded-lg border border-border bg-bg-elevated px-5 py-3 text-sm text-slate-400">
          {totalLessons} lessons · {totalXp.toLocaleString()} XP available. Work through the modules in order — start with the first lesson below.
        </p>

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
              {m.lessons.map((l) => {
                const isFirst    = globalIdx === 0;
                const lessonPath = `/learn/${path.slug}/${l.slug}`;
                globalIdx++;

                return (
                  <li key={l.slug} className="flex items-center justify-between py-2.5 text-sm">
                    <div className="flex items-center gap-3 min-w-0">
                      {isFirst
                        ? <PlayCircle className="h-4 w-4 shrink-0 text-cyber-300" />
                        : <Circle className="h-4 w-4 shrink-0 text-slate-400" />}
                      <span className="truncate text-slate-200">{l.title}</span>
                      <span className={cn("rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-widest shrink-0", kindColor[l.kind])}>
                        {kindLabel[l.kind]}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-slate-400 shrink-0 ml-3">
                      <span>{l.min} min</span>
                      <span className="font-mono text-cyber-300">+{l.xp} XP</span>
                      <Link href={lessonPath}>
                        <Button size="sm" variant={isFirst ? "primary" : "ghost"}>
                          {isFirst ? "Start" : "Open"}
                        </Button>
                      </Link>
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

