import { useEffect } from "react";
import { useBrand } from "@/lib/brand/BrandContext";

/**
 * Sets a descriptive, unique document.title for a client page (WCAG 2.4.2).
 *
 * Client components ("use client") can't export Next `metadata`, so pages that
 * need their own title — the auth flow, mainly — set it here instead of falling
 * back to the app-wide default title, which is not descriptive of the current
 * page. The suffix is the current brand (white label, src/lib/brand).
 */
export function usePageTitle(title: string): void {
  const { productName } = useBrand();
  useEffect(() => {
    document.title = `${title} // ${productName}`;
  }, [title, productName]);
}
