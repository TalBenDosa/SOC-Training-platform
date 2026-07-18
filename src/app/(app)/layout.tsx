import { Sidebar } from "@/components/nav/Sidebar";
import { MotionProvider } from "@/components/MotionProvider";
import { EarnMoment } from "@/components/EarnMoment";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <MotionProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="flex-1 min-w-0">{children}</main>
      </div>
      <EarnMoment />
    </MotionProvider>
  );
}
