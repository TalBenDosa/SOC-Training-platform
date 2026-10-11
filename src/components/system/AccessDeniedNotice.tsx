"use client";
import { Suspense, useEffect, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ShieldAlert, X } from "lucide-react";

/**
 * A clear, dismissible notice when the middleware bounced the user off an area they
 * lack permission for (`?reason=forbidden`). Before this, a non-admin who reached a
 * staff-only route was redirected to the PUBLIC landing page with no explanation —
 * which read as a silent logout (client feedback). The redirect now lands in-app and
 * this says, plainly, what happened and who to ask.
 */
function Inner() {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const [show, setShow] = useState(false);

  useEffect(() => { setShow(sp.get("reason") === "forbidden"); }, [sp]);
  if (!show) return null;

  const dismiss = () => {
    setShow(false);
    const params = new URLSearchParams(Array.from(sp.entries()));
    params.delete("reason");
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname);   // drop the param so a refresh won't re-show it
  };

  return (
    <div
      role="alert"
      className="fixed left-1/2 top-4 z-[60] flex w-[min(92vw,32rem)] -translate-x-1/2 items-start gap-3 rounded-lg border border-neon-amber/40 bg-bg-elevated/95 px-4 py-3 shadow-lg backdrop-blur"
    >
      <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-neon-amber" />
      <div className="min-w-0 flex-1 text-sm">
        <p className="font-semibold text-white">You don&apos;t have permission to open that area</p>
        <p className="mt-0.5 text-slate-300">
          It&apos;s limited to administrators. You&apos;re still signed in — if you think this is a
          mistake, contact your course administrator or support.
        </p>
      </div>
      <button
        onClick={dismiss}
        aria-label="Dismiss"
        className="shrink-0 rounded p-1 text-slate-400 hover:bg-white/5 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-neon-amber"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

export function AccessDeniedNotice() {
  // useSearchParams needs a Suspense boundary to avoid de-opting the whole route.
  return (
    <Suspense fallback={null}>
      <Inner />
    </Suspense>
  );
}
