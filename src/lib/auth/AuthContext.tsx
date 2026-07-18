"use client";
/**
 * Client-side auth state. Wraps Supabase's onAuthStateChange so any component
 * can read `useAuth()` for the current user without prop-drilling. When
 * Supabase isn't configured, this resolves immediately to a signed-out
 * "guest" state — the rest of the app (localStorage progress) keeps working
 * exactly as it does today; nothing is auth-gated by default.
 */
import { createContext, useContext, useEffect, useState } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

interface AuthState {
  user: User | null;
  session: Session | null;
  /** True until the initial session check resolves. */
  loading: boolean;
  /** True once Supabase env vars are present (does NOT imply signed-in). */
  authEnabled: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null,
  session: null,
  loading: false,
  authEnabled: false,
  signOut: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(isSupabaseConfigured);

  useEffect(() => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setLoading(false); return; }

    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setLoading(false);
    });

    const { data: subscription } = supabase.auth.onAuthStateChange((_event, next) => {
      setSession(next);
    });

    return () => subscription.subscription.unsubscribe();
  }, []);

  async function signOut() {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;
    await supabase.auth.signOut();
    setSession(null);
  }

  return (
    <AuthContext.Provider value={{
      user: session?.user ?? null,
      session,
      loading,
      authEnabled: isSupabaseConfigured,
      signOut,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
