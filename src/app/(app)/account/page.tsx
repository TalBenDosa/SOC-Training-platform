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
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { AlertTriangle, Building2, Clock, ShieldCheck, Pencil, KeyRound, Check } from "lucide-react";

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

  // FB-011: edit display name + change password.
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [savingName, setSavingName] = useState(false);
  const [nameMsg, setNameMsg] = useState<string | null>(null);
  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");
  const [savingPw, setSavingPw] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function saveDisplayName() {
    const next = nameDraft.trim();
    if (next.length < 2) { setNameMsg("Name must be at least 2 characters."); return; }
    setSavingName(true); setNameMsg(null);
    try {
      const res = await fetch("/api/account", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ display_name: next }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? "Could not update your name.");
      setInfo(prev => prev ? { ...prev, display_name: data.display_name } : prev);
      setEditingName(false);
    } catch (e) {
      setNameMsg(e instanceof Error ? e.message : "Could not update your name.");
    } finally {
      setSavingName(false);
    }
  }

  async function changePassword() {
    if (pw1.length < 8) { setPwMsg({ ok: false, text: "Password must be at least 8 characters." }); return; }
    if (pw1 !== pw2) { setPwMsg({ ok: false, text: "The two passwords don't match." }); return; }
    setSavingPw(true); setPwMsg(null);
    try {
      // Session-authenticated: the logged-in user updates their own password;
      // Supabase requires a valid session, no admin key involved.
      const supabase = getSupabaseBrowserClient();
      if (!supabase) throw new Error("Auth is not available right now. Please reload and try again.");
      const { error: err } = await supabase.auth.updateUser({ password: pw1 });
      if (err) throw new Error(err.message);
      setPw1(""); setPw2("");
      setPwMsg({ ok: true, text: "Password updated." });
    } catch (e) {
      setPwMsg({ ok: false, text: e instanceof Error ? e.message : "Could not update your password." });
    } finally {
      setSavingPw(false);
    }
  }

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
          <div className="flex items-start justify-between gap-4">
            <dt className="text-slate-400 pt-1.5">Display name</dt>
            <dd className="text-slate-200">
              {editingName ? (
                <div className="flex flex-col items-end gap-1.5">
                  <input
                    autoFocus value={nameDraft} onChange={e => setNameDraft(e.target.value)} maxLength={60}
                    onKeyDown={e => { if (e.key === "Enter") saveDisplayName(); if (e.key === "Escape") setEditingName(false); }}
                    className="w-56 rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-sm text-white focus:border-cyber-500 focus:outline-none"
                  />
                  <div className="flex gap-2">
                    <Button size="sm" variant="primary" disabled={savingName} onClick={saveDisplayName}>{savingName ? "Saving…" : "Save"}</Button>
                    <Button size="sm" variant="ghost" disabled={savingName} onClick={() => { setEditingName(false); setNameMsg(null); }}>Cancel</Button>
                  </div>
                  {nameMsg && <p className="text-[11px] text-red-400">{nameMsg}</p>}
                </div>
              ) : (
                <button onClick={() => { setNameDraft(info?.display_name ?? ""); setEditingName(true); setNameMsg(null); }} className="inline-flex items-center gap-1.5 text-slate-200 hover:text-cyber-300 transition-colors">
                  {info?.display_name ?? "—"} <Pencil className="h-3 w-3 opacity-60" />
                </button>
              )}
            </dd>
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

      {/* ── Change password (FB-011) ────────────────────────────────────── */}
      <Card className="mt-6">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <KeyRound className="h-4 w-4 text-cyber-300" /> Change password
        </h2>
        <p className="mt-2 text-xs text-slate-400">Set a new password for {user?.email}. At least 8 characters.</p>
        <div className="mt-3 space-y-2 max-w-sm">
          <input
            type="password" autoComplete="new-password" placeholder="New password" value={pw1}
            onChange={e => { setPw1(e.target.value); setPwMsg(null); }}
            className="w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm text-white focus:border-cyber-500 focus:outline-none"
          />
          <input
            type="password" autoComplete="new-password" placeholder="Confirm new password" value={pw2}
            onChange={e => { setPw2(e.target.value); setPwMsg(null); }}
            onKeyDown={e => { if (e.key === "Enter") changePassword(); }}
            className="w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm text-white focus:border-cyber-500 focus:outline-none"
          />
          <Button variant="primary" disabled={savingPw || !pw1 || !pw2} onClick={changePassword}>
            {savingPw ? "Updating…" : "Update password"}
          </Button>
          {pwMsg && (
            <p className={`flex items-center gap-1.5 text-xs ${pwMsg.ok ? "text-neon-green" : "text-red-400"}`}>
              {pwMsg.ok && <Check className="h-3.5 w-3.5" />}{pwMsg.text}
            </p>
          )}
        </div>
        <p className="mt-4 text-[11px] text-slate-500">Your handle ({info?.handle ?? "—"}) and login email are fixed identifiers and can&apos;t be changed here.</p>
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
