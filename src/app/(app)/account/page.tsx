"use client";
/**
 * Account page — identity, and the right-to-deletion controls.
 *
 * Exists because the privacy policy promised a deletion right the product had
 * no mechanism for (docs/PPA-COMPLIANCE-ASSESSMENT.md §5.1). Two paths, decided
 * by the server from the account's org, not by anything the client asserts:
 * a solo learner deletes immediately; a student enrolled through a college
 * files a request their institution actions, because their results are also the
 * college's assessment record.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/lib/auth/AuthContext";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { AlertTriangle, Building2, Clock, ShieldCheck } from "lucide-react";

interface AccountInfo {
  handle: string | null;
  display_name: string | null;
  xp: number;
  enrolled: boolean;
  org_name: string | null;
  deletion_request: { id: string; status: string; requested_at: string } | null;
}

export default function AccountPage() {
  usePageTitle("Account");
  const { user, signOut } = useAuth();
  const router = useRouter();

  const [info, setInfo] = useState<AccountInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filed, setFiled] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/account");
        if (!res.ok) throw new Error("Could not load your account.");
        const data = await res.json();
        if (!cancelled) setInfo(data);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Could not load your account.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  async function submitDeletion() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/account", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: "DELETE", reason: reason.trim() || undefined }),
      });
      const data = await res.json().catch(() => ({}));

      if (res.status === 202) {
        // Enrolled student — request filed, account still live.
        setFiled(true);
        setConfirmOpen(false);
        setInfo(prev => prev ? { ...prev, deletion_request: { id: data.request_id, status: "pending", requested_at: data.requested_at } } : prev);
        return;
      }
      if (!res.ok) throw new Error(data.error ?? "Could not complete the request.");

      // Solo learner — the account is gone; the session is now orphaned, so
      // sign out before routing or the app renders as a phantom logged-in user.
      await signOut();
      router.push("/");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not complete the request.");
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return <main className="mx-auto max-w-2xl px-6 py-12"><p className="text-sm text-slate-400">Loading…</p></main>;
  }

  const pending = info?.deletion_request ?? null;

  return (
    <main className="mx-auto max-w-2xl px-6 py-12">
      <h1 className="text-2xl font-bold text-white">Account</h1>
      <p className="mt-1 text-sm text-slate-400">{user?.email}</p>

      <Card className="mt-8">
        <h2 className="text-sm font-bold text-white">Your details</h2>
        <dl className="mt-4 space-y-3 text-sm">
          <div className="flex justify-between gap-4">
            <dt className="text-slate-400">Handle</dt>
            <dd className="text-slate-200">{info?.handle ?? "—"}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-400">Display name</dt>
            <dd className="text-slate-200">{info?.display_name ?? "—"}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-400">XP</dt>
            <dd className="text-slate-200 tabular-nums">{info?.xp ?? 0}</dd>
          </div>
          {info?.enrolled && (
            <div className="flex justify-between gap-4">
              <dt className="flex items-center gap-1.5 text-slate-400"><Building2 className="h-3.5 w-3.5" /> Institution</dt>
              <dd className="text-slate-200">{info.org_name ?? "Your college"}</dd>
            </div>
          )}
        </dl>
        <p className="mt-5 flex items-start gap-2 text-xs text-slate-400">
          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-300" />
          <span>
            This is everything we hold about you, besides your learning progress.{" "}
            <Link href="/privacy" className="text-cyber-300 hover:underline">Privacy &amp; data</Link>
          </span>
        </p>
      </Card>

      {/* ── Deletion ─────────────────────────────────────────────────────── */}
      <Card className="mt-6 border-red-500/30">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <AlertTriangle className="h-4 w-4 text-red-400" /> Delete your account
        </h2>

        {pending || filed ? (
          <div className="mt-4 rounded-lg border border-neon-amber/30 bg-neon-amber/5 p-4">
            <p className="flex items-center gap-2 text-sm font-semibold text-neon-amber">
              <Clock className="h-4 w-4" /> Deletion requested
            </p>
            <p className="mt-2 text-sm text-slate-300">
              Your request is with {info?.org_name ?? "your institution"}. They administer your
              account and will action it — you&apos;ll receive an answer within 30 days. Your
              account stays usable until then.
            </p>
          </div>
        ) : (
          <>
            <p className="mt-3 text-sm text-slate-300">
              {info?.enrolled
                ? `You study through ${info.org_name ?? "an institution"}, and your results are part of their course record. Requesting deletion sends the request to your course administrator, who will action it within 30 days.`
                : "This erases your account and all of your learning progress. It cannot be undone."}
            </p>

            {!confirmOpen ? (
              <Button variant="danger" className="mt-4" onClick={() => setConfirmOpen(true)}>
                {info?.enrolled ? "Request deletion" : "Delete my account"}
              </Button>
            ) : (
              <div className="mt-4 space-y-3">
                {info?.enrolled && (
                  <div>
                    <label htmlFor="reason" className="block text-xs text-slate-400">Reason (optional)</label>
                    <textarea
                      id="reason" rows={2} value={reason} onChange={e => setReason(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm text-white focus:border-neon-cyan focus:outline-none"
                    />
                  </div>
                )}
                <div>
                  <label htmlFor="confirm" className="block text-xs text-slate-400">
                    Type <span className="font-mono font-bold text-red-300">DELETE</span> to confirm
                  </label>
                  <input
                    id="confirm" type="text" autoComplete="off" value={confirmText}
                    onChange={e => setConfirmText(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm text-white focus:border-red-500 focus:outline-none"
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="danger"
                    disabled={confirmText.trim().toUpperCase() !== "DELETE" || busy}
                    onClick={submitDeletion}
                  >
                    {busy ? "Working…" : info?.enrolled ? "Send request" : "Permanently delete"}
                  </Button>
                  <Button variant="ghost" onClick={() => { setConfirmOpen(false); setConfirmText(""); }} disabled={busy}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </>
        )}

        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      </Card>
    </main>
  );
}
