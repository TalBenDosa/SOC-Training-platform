import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";

export const metadata = { title: "IR Playbooks" };

const PLAYBOOKS = [
  {
    title: "Phishing email reported by user",
    steps: [
      "Acquire .eml; extract sender, headers, links, attachments.",
      "Detonate attachments in sandbox; record SHA256 verdict.",
      "If malicious: purge across mailboxes, block sender domain.",
      "Identify clickers via URL telemetry; force password reset & SSO revoke.",
      "Hunt EDR for child-process spawn from Office on clickers' hosts.",
      "Document in investigation; close as TP/FP.",
    ],
    tags: ["T1566.001","T1566.002"],
  },
  {
    title: "Suspected credential theft (LSASS)",
    steps: [
      "Confirm sysmon Event 10 ProcessAccess to lsass.exe with suspicious GrantedAccess.",
      "Network-isolate the host via EDR.",
      "Force-rotate credentials of all users with active sessions on host.",
      "Hunt for lateral movement using rotated creds across hosts.",
      "Re-image host. Restore from known-good baseline.",
    ],
    tags: ["T1003.001"],
  },
  {
    title: "BEC mailbox rule on M365",
    steps: [
      "Identify the rule via Get-InboxRule; capture conditions/actions.",
      "Disable & remove the rule; preserve evidence.",
      "Reset password; revoke active SSO/refresh tokens.",
      "Review last 30d sign-ins for the user; block known attacker IPs.",
      "Notify finance approvers; verify any pending wire requests out-of-band.",
    ],
    tags: ["T1078","T1098.005"],
  },
  {
    title: "Ransomware on a single host",
    steps: [
      "Isolate immediately via EDR.",
      "Identify ransomware family (note left, file extension, observed binaries).",
      "Check shadow copies & backups; assess restore feasibility.",
      "Hunt for fan-out: SMB writes, scheduled tasks, RDP from this host.",
      "Engage IR retainer if required; legal/insurance comms.",
    ],
    tags: ["T1486","T1490"],
  },
];

export default function PlaybooksPage() {
  return (
    <div>
      <Topbar title="IR Playbooks" subtitle="Step-by-step procedures for common incidents" />
      <div className="container mx-auto max-w-[1400px] px-6 py-6 grid grid-cols-1 gap-4 md:grid-cols-2">
        {PLAYBOOKS.map(p => (
          <Card key={p.title}>
            <h3 className="text-base font-semibold text-white">{p.title}</h3>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {p.tags.map(t => <Badge key={t}>{t}</Badge>)}
            </div>
            <ol className="mt-3 space-y-2 text-sm text-slate-300">
              {p.steps.map((s, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-cyber-500/40 bg-cyber-500/10 font-mono text-[10px] font-bold text-cyber-300">{i + 1}</span>
                  <span>{s}</span>
                </li>
              ))}
            </ol>
          </Card>
        ))}
      </div>
    </div>
  );
}
