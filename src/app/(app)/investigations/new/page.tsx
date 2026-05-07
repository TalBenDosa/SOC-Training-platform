import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input, Textarea } from "@/components/ui/Input";

export const metadata = { title: "New Investigation" };

export default function NewInvestigationPage() {
  return (
    <div>
      <Topbar title="New Investigation" subtitle="Open a case for tracking your IR work" />
      <div className="container mx-auto max-w-3xl px-6 py-6">
        <Card className="space-y-4">
          <label className="block">
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">Title</span>
            <Input className="mt-1" placeholder="e.g., WS-FIN-3041 — phishing-to-LSASS chain" />
          </label>
          <label className="block">
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">Severity</span>
            <select className="mt-1 h-10 w-full rounded-md border border-border bg-bg-elevated px-3 text-sm text-slate-100">
              {["critical","high","medium","low","informational"].map(s => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">Summary</span>
            <Textarea className="mt-1" placeholder="One-paragraph summary of what you're investigating." />
          </label>
          <label className="block">
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">Affected assets (comma-separated)</span>
            <Input className="mt-1" placeholder="WS-FIN-3041, a.park@cryotech.io, s3://cryotech-fin-bucket" />
          </label>
          <div className="flex justify-end gap-2">
            <Button variant="secondary">Cancel</Button>
            <Button variant="primary">Create</Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
