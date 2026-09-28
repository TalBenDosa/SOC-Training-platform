"use client";
/**
 * Account page — identity, self-service profile edits, password change, and
 * the right-to-deletion controls.
 *
 * Deletion exists because the privacy policy promised a deletion right the
 * product had no mechanism for (docs/PPA-COMPLIANCE-ASSESSMENT.md §5.1). Two
 * paths, decided by the server from the account's org, not by anything the
 * client asserts: a solo learner deletes immediately; a student enrolled through
 * a college files a request their institution actions, because their results
 * are also the college's assessment record.
 *
 * FB-011 — editable details. Full name and handle are saved via PATCH
 * /api/account (whitelisted columns only); the password via POST
 * /api/account/password, which re-verifies the CURRENT password first. Both
 * share validation with the server (./accountValidation) so the form and the
 * API can never disagree. Email stays read-only.
 */
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/lib/auth/AuthContext";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { AlertTriangle, Building2, Clock, ShieldCheck, Pencil, KeyRound, Check, Mail } from "lucide-react";
import {
  validateFullName, validateHandle, validatePasswordChange,
  FULL_NAME_MAX, PASSWORD_MIN, type Validation,
} from "./accountValidation";

interface AccountInfo {
  handle: string | null;
  display_name: string | null;
  xp: number;
  enrolled: boolean;
  org_name: string | null;
  deletion_request: { id: string; status: string; requested_at: string } | null;
}

const INPUT_CLS =
  "w-full rounded-lg border bg-slate-900/60 px-3 py-2 text-sm text-white focus:outline-none";
const inputBorder = (invalid: boolean) =>
  invalid ? "border-red-500/70 focus:border-red-400" : "border-slate-700 focus:border-cyber-500";

/**
 * One inline-editable profile field: read view with an Edit button, and an
 * accessible edit form (label, hint, aria-invalid, aria-describedby, focus on
 * open/error, focus back to the Edit button on close).
 */
function EditableField({
  id, label, value, hint, maxLength, validate, onSave, inputProps,
}: {
  id: string;
  label: string;
  value: string | null;
  hint: string;
  maxLength: number;
  validate: (raw: string) => Validation<string>;
  /** Resolves to an error message, or null on success. */
  onSave: (value: string) => Promise<string | null>;
  inputProps?: React.InputHTMLAttributes<HTMLInputElement>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const editBtnRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef(false);

  useEffect(() => {
    if (editing) inputRef.current?.focus();
    else if (returnFocus.current) { editBtnRef.current?.focus(); returnFocus.current = false; }
  }, [editing]);

  function close() { returnFocus.current = true; setEditing(false); setError(null); }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const v = validate(draft);
    if (!v.ok) { setError(v.error); inputRef.current?.focus(); return; }
    setSaving(true); setError(null);
    const err = await onSave(v.value);
    setSaving(false);
    if (err) { setError(err); inputRef.current?.focus(); return; }
    close();
  }

  const hintId = `${id}-hint`;
  const errId = `${id}-error`;

  if (!editing) {
    return (
      <div className="flex items-start justify-between gap-4">
        <dt className="text-slate-400">{label}</dt>
        <dd className="flex items-center gap-2 text-right text-slate-200">
          <span className="break-all">{value ?? "—"}</span>
          <button
            ref={editBtnRef} type="button"
            onClick={() => { setDraft(value ?? ""); setError(null); setEditing(true); }}
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-cyber-300 hover:bg-cyber-500/10 focus:outline-none focus:ring-2 focus:ring-cyber-400/50"
            aria-label={`Edit ${label.toLowerCase()}`}
          >
            <Pencil className="h-3 w-3" aria-hidden="true" /> Edit
          </button>
        </dd>
      </div>
    );
  }

  return (
    <div>
      <dt className="sr-only">{label}</dt>
      <dd>
        <form onSubmit={submit} noValidate className="rounded-lg border border-slate-700/60 bg-slate-900/30 p-3">
          <label htmlFor={id} className="block text-xs font-semibold text-slate-300">{label}</label>
          <input
            ref={inputRef} id={id} value={draft} maxLength={maxLength}
            onChange={e => { setDraft(e.target.value); if (error) setError(null); }}
            onKeyDown={e => { if (e.key === "Escape") close(); }}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? `${errId} ${hintId}` : hintId}
            className={`mt-1 ${INPUT_CLS} ${inputBorder(!!error)}`}
            {...inputProps}
          />
          <p id={hintId} className="mt-1 text-[11px] text-slate-500">{hint}</p>
          {error && <p id={errId} role="alert" className="mt-1 text-xs text-red-400">{error}</p>}
          <div className="mt-2 flex gap-2">
            <Button type="submit" size="sm" variant="primary" disabled={saving}>{saving ? "Saving…" : "Save"}</Button>
            <Button type="button" size="sm" variant="ghost" disabled={saving} onClick={close}>Cancel</Button>
          </div>
        </form>
      </dd>
    </div>
  );
}

type PwField = "current_password" | "new_password" | "confirm_password";

/** Map a password-validation message to the field it concerns (for focus + aria-invalid). */
function pwFieldFor(msg: string): PwField {
  if (/current/i.test(msg) && !/different/i.test(msg)) return "current_password";
  if (/match/i.test(msg)) return "confirm_password";
  return "new_password";
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

  // FB-011: success toast (auto-hides; announced politely to screen readers).
  const [toast, setToast] = useState<string | null>(null);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  // FB-011: change password.
  const [pwCurrent, setPwCurrent] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [savingPw, setSavingPw] = useState(false);
  const [pwError, setPwError] = useState<{ field: PwField | null; text: string } | null>(null);
  const pwCurrentRef = useRef<HTMLInputElement>(null);
  const pwNewRef = useRef<HTMLInputElement>(null);
  const pwConfirmRef = useRef<HTMLInputElement>(null);
  const pwRefs: Record<PwField, React.RefObject<HTMLInputElement | null>> = {
    current_password: pwCurrentRef,
    new_password: pwNewRef,
    confirm_password: pwConfirmRef,
  };

  /** PATCH one profile field; returns an error message or null. */
  async function saveProfile(field: "display_name" | "handle", value: string): Promise<string | null> {
    try {
      const res = await fetch("/api/account", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [field]: value }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return data.error ?? "Could not save your changes.";
      setInfo(prev => prev ? { ...prev, display_name: data.display_name ?? prev.display_name, handle: data.handle ?? prev.handle } : prev);
      if (!data.unchanged) setToast(field === "handle" ? "Handle updated." : "Name updated.");
      return null;
    } catch {
      return "Network error — check your connection and try again.";
    }
  }

  function failPw(field: PwField | null, text: string) {
    setPwError({ field, text });
    if (field) pwRefs[field].current?.focus();
  }

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    const v = validatePasswordChange({ current: pwCurrent, next: pwNew, confirm: pwConfirm });
    if (!v.ok) { failPw(pwFieldFor(v.error), v.error); return; }
    setSavingPw(true); setPwError(null);
    try {
      const res = await fetch("/api/account/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: pwCurrent, new_password: pwNew, confirm_password: pwConfirm }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg: string = data.error ?? "Could not update your password.";
        const field = (data.field as PwField | undefined) ?? (res.status === 400 ? pwFieldFor(msg) : null);
        failPw(field, msg);
        return;
      }
      setPwCurrent(""); setPwNew(""); setPwConfirm("");
      setToast("Password updated. Use your new password next time you sign in.");
    } catch {
      failPw(null, "Network error — check your connection and try again.");
    } finally {
      setSavingPw(false);
    }
  }

  const pwInvalid = (f: PwField) => pwError?.field === f;
  const pwDescribedBy = (f: PwField, hintId?: string) =>
    [pwInvalid(f) ? "pw-error" : null, hintId].filter(Boolean).join(" ") || undefined;

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
      <p className="mt-1 text-sm text-slate-400">Manage your profile, password and data.</p>

      <Card className="mt-8">
        <h2 className="text-sm font-bold text-white">Your details</h2>
        <dl className="mt-4 space-y-3 text-sm">
          <div className="flex items-start justify-between gap-4">
            <dt className="flex items-center gap-1.5 text-slate-400"><Mail className="h-3.5 w-3.5" aria-hidden="true" /> Email</dt>
            <dd className="text-right">
              <span className="break-all text-slate-200">{user?.email ?? "—"}</span>
              <span className="mt-0.5 block text-[11px] text-slate-500">
                Your login email can&apos;t be changed here.{info?.enrolled ? " Ask your course administrator if it needs to change." : ""}
              </span>
            </dd>
          </div>
          <EditableField
            id="account-handle" label="Handle" value={info?.handle ?? null} maxLength={20}
            hint="Your public nickname on the leaderboard. 3–20 characters: lowercase letters, numbers and underscores. Must be unique."
            validate={validateHandle}
            onSave={v => saveProfile("handle", v)}
            inputProps={{ autoComplete: "username", autoCapitalize: "none", spellCheck: false }}
          />
          <EditableField
            id="account-name" label="Full name" value={info?.display_name ?? null} maxLength={FULL_NAME_MAX}
            hint={`Printed on the rank certificates you earn. 2–${FULL_NAME_MAX} characters.`}
            validate={validateFullName}
            onSave={v => saveProfile("display_name", v)}
            inputProps={{ autoComplete: "name" }}
          />
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
          <KeyRound className="h-4 w-4 text-cyber-300" aria-hidden="true" /> Change password
        </h2>
        <p className="mt-2 text-xs text-slate-400">
          For your security, confirm your current password first. The new one must be at least {PASSWORD_MIN} characters.
        </p>
        <form onSubmit={changePassword} noValidate className="mt-4 max-w-sm space-y-3">
          {/* Hidden username so password managers file the new password under the right account. */}
          <input type="email" name="username" autoComplete="username" value={user?.email ?? ""} readOnly hidden />
          <div>
            <label htmlFor="pw-current" className="mb-1 block text-xs font-semibold text-slate-400">Current password</label>
            <input
              ref={pwCurrentRef} id="pw-current" type="password" autoComplete="current-password"
              value={pwCurrent} onChange={e => { setPwCurrent(e.target.value); setPwError(null); }}
              aria-invalid={pwInvalid("current_password") || undefined}
              aria-describedby={pwDescribedBy("current_password")}
              className={`${INPUT_CLS} ${inputBorder(pwInvalid("current_password"))}`}
            />
          </div>
          <div>
            <label htmlFor="pw-new" className="mb-1 block text-xs font-semibold text-slate-400">New password</label>
            <input
              ref={pwNewRef} id="pw-new" type="password" autoComplete="new-password" minLength={PASSWORD_MIN}
              value={pwNew} onChange={e => { setPwNew(e.target.value); setPwError(null); }}
              aria-invalid={pwInvalid("new_password") || undefined}
              aria-describedby={pwDescribedBy("new_password", "pw-new-hint")}
              className={`${INPUT_CLS} ${inputBorder(pwInvalid("new_password"))}`}
            />
            <p id="pw-new-hint" className="mt-1 text-[11px] text-slate-500">At least {PASSWORD_MIN} characters, different from your current password.</p>
          </div>
          <div>
            <label htmlFor="pw-confirm" className="mb-1 block text-xs font-semibold text-slate-400">Confirm new password</label>
            <input
              ref={pwConfirmRef} id="pw-confirm" type="password" autoComplete="new-password"
              value={pwConfirm} onChange={e => { setPwConfirm(e.target.value); setPwError(null); }}
              aria-invalid={pwInvalid("confirm_password") || undefined}
              aria-describedby={pwDescribedBy("confirm_password")}
              className={`${INPUT_CLS} ${inputBorder(pwInvalid("confirm_password"))}`}
            />
          </div>
          {pwError && <p id="pw-error" role="alert" className="text-xs text-red-400">{pwError.text}</p>}
          <div className="flex flex-wrap items-center gap-4">
            <Button type="submit" variant="primary" disabled={savingPw || !pwCurrent || !pwNew || !pwConfirm}>
              {savingPw ? "Updating…" : "Update password"}
            </Button>
            <Link href="/reset-password" className="text-xs text-cyber-300 hover:underline">Forgot your password?</Link>
          </div>
        </form>
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

      {/* Success toast (FB-011). The live region stays mounted so it is registered before it speaks. */}
      <div role="status" aria-live="polite" className="pointer-events-none fixed bottom-6 right-6 z-50">
        {toast && (
          <div className="flex items-center gap-2 rounded-lg border border-neon-green/40 bg-bg-elevated px-4 py-3 text-sm text-neon-green shadow-glow">
            <Check className="h-4 w-4" aria-hidden="true" /> {toast}
          </div>
        )}
      </div>
    </main>
  );
}
