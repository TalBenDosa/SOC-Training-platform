import Link from "next/link";
import { Logo } from "@/components/Logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-glow" />
      <header className="container mx-auto flex max-w-7xl items-center px-6 py-5">
        <Link href="/"><Logo /></Link>
      </header>
      <main className="flex items-center justify-center px-6 py-12">
        {children}
      </main>
    </div>
  );
}
