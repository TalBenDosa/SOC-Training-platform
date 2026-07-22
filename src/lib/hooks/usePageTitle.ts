import { useEffect } from "react";

/**
 * Sets a descriptive, unique document.title for a client page (WCAG 2.4.2).
 *
 * Client components ("use client") can't export Next `metadata`, so pages that
 * need their own title — the auth flow, mainly — set it here instead of falling
 * back to the app-wide template title ("HACK THE SOC // Enterprise SOC Training"),
 * which is not descriptive of the current page.
 */
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} // HACK THE SOC`;
  }, [title]);
}
