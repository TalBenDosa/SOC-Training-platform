"use client";
/**
 * Client-side view of the signed-in user's tenant context, decoded from the
 * session JWT (the claims the access-token hook stamps). Used for conditional
 * UI — showing the super-admin link, org-scoped views — never as a security
 * boundary: the real enforcement is middleware + RLS + the API guards.
 *
 * All fields are null/false until the multi-tenancy hook is live, so any UI
 * gated on them simply stays hidden pre-migration.
 */
import { useEffect, useState } from "react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { useAuth } from "./AuthContext";
import { decodeOrgClaim, type OrgClaim } from "./orgClaim";

const EMPTY: OrgClaim = { orgId: null, orgName: null, orgRole: null, isPlatformAdmin: false, orgActive: null };

export function useOrgContext(): OrgClaim & { loading: boolean } {
  const { user } = useAuth();
  const [claim, setClaim] = useState<OrgClaim>(EMPTY);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const supabase = getSupabaseBrowserClient();
    if (!supabase || !user) {
      setClaim(EMPTY);
      setLoading(false);
      return;
    }
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (cancelled) return;
      setClaim(decodeOrgClaim(session?.access_token));
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [user]);

  return { ...claim, loading };
}
