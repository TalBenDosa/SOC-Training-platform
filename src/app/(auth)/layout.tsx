import Link from "next/link";
import { HomeLogoLink } from "@/components/nav/HomeLogoLink";
import { Logo } from "@/components/Logo";
import { getRequestBrand } from "@/lib/brand/server";

export default async function AuthLayout({ children }: { children: React.ReactNode }) {
  // White label (src/lib/brand): the organization's logo sits large and centered above the
  // form, the way a college's own sign-in page would look; the platform keeps its header logo.
  const { whiteLabel, links } = await getRequestBrand();
  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-glow" />
      {!whiteLabel && (
        <header className="container mx-auto flex max-w-7xl items-center px-6 py-5">
          <HomeLogoLink />
        </header>
      )}
      <main id="main-content" className={whiteLabel ? "flex flex-col items-center justify-center gap-8 px-6 pb-12 pt-16" : "flex items-center justify-center px-6 py-12"}>
        {whiteLabel && <Logo stacked />}
        {children}
      </main>
      {/* Accessibility statement — reachable from every auth page. */}
      <footer className="flex flex-wrap justify-center gap-x-4 gap-y-1 px-6 pb-8 text-center">
        <Link href="/accessibility" className="text-xs text-slate-400 underline underline-offset-2 hover:text-slate-200">
          Accessibility
        </Link>
        {/* The tenant's own privacy notice / terms / help (tenant config links). */}
        <Link href={links.privacy} className="text-xs text-slate-400 underline underline-offset-2 hover:text-slate-200">
          Privacy
        </Link>
        {links.terms && <a href={links.terms} target="_blank" rel="noopener noreferrer" className="text-xs text-slate-400 underline underline-offset-2 hover:text-slate-200">Terms of use</a>}
        {links.help && <a href={links.help} target="_blank" rel="noopener noreferrer" className="text-xs text-slate-400 underline underline-offset-2 hover:text-slate-200">Help</a>}
      </footer>
    </div>
  );
}
