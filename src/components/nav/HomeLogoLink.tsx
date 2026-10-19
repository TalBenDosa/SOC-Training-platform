"use client";
import Link from "next/link";
import { Logo } from "@/components/Logo";
import { useAuth } from "@/lib/auth/AuthContext";

/**
 * The logo on the auth pages (/renew, /license, /mfa, /update-password are reachable
 * while signed in). "/" is the public landing page and always shows "Sign in", so a
 * signed-in learner goes to the rooms instead, the same rule as the in-app Sidebar
 * (learner report #4).
 */
export function HomeLogoLink() {
  const { user } = useAuth();
  return <Link href={user ? "/rooms" : "/"}><Logo /></Link>;
}
