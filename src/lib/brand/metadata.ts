import "server-only";
import type { Metadata } from "next";
import { brandTitle } from "./brand";
import { getRequestBrand } from "./server";

/**
 * A route layout's tab title (WCAG 2.4.2): "<page> // <brand>". Absolute, so nested layouts
 * keep the brand suffix (c12ecc7), and computed per request so a white-label domain shows its
 * own name instead of HACK THE SOC.
 */
export function brandMetadata(page: string): () => Promise<Metadata> {
  return async () => ({ title: { absolute: brandTitle(page, await getRequestBrand()) } });
}
