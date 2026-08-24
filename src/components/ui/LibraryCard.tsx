"use client";
/**
 * LibraryCard — the shared, image-forward card used across the content
 * libraries (Scenarios, Learning Rooms, College Materials) so they share one
 * eye-catching visual standard: a hero image on top (a real thumbnail when one
 * exists, otherwise deterministic generated cover art), a type badge, an
 * optional corner badge (e.g. difficulty), then title / summary / meta / CTA.
 */
import Link from "next/link";
import { coverArt } from "@/lib/ui/coverArt";
import { cn } from "@/lib/utils";

export type LibraryCardProps = {
  /** Stable string that drives the generated art (slug / id). */
  seed: string;
  /** Card position in its list — rotates the scene family so a page doesn't
   *  cluster on one composition. */
  index?: number;
  title: string;
  subtitle?: string;
  /** Motif icon shown large in the hero and small in the type badge. */
  icon: React.ElementType;
  /** Small type label in the hero (e.g. "Simulation", "Room", "PDF"). */
  typeLabel?: string;
  /** Optional real hero image (overrides generated art when present). */
  image?: string | null;
  /** Top-right corner badge, e.g. a difficulty pill. */
  cornerBadge?: React.ReactNode;
  /** Bottom-left metadata (e.g. "+250 XP · ~45 min"). */
  meta?: React.ReactNode;
  /** Bottom-right action (e.g. a Launch button). */
  cta?: React.ReactNode;
  /** Extra content between the summary and the footer (e.g. a prep hint). */
  children?: React.ReactNode;
  /** Navigation target. Provide this OR onClick. */
  href?: string;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
};

function Hero({ seed, index, icon: Icon, typeLabel, image }: Pick<LibraryCardProps, "seed" | "index" | "icon" | "typeLabel" | "image">) {
  const art = coverArt(seed, index ?? 0);
  return (
    <div className="relative aspect-[16/9] w-full overflow-hidden">
      {image ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img src={image} alt="" className="h-full w-full object-cover transition duration-300 group-hover:scale-[1.04]" />
      ) : (
        // Generated SVG scene (varied composition per item) as the hero.
        <div
          className="absolute inset-0 transition duration-300 group-hover:scale-[1.05]"
          style={{ backgroundImage: art.dataUri, backgroundSize: "cover", backgroundPosition: "center" }}
        />
      )}
      {typeLabel && (
        <span className="absolute left-3 top-3 flex items-center gap-1.5 rounded-full border border-white/20 bg-black/40 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-white backdrop-blur-sm">
          <Icon className="h-3 w-3" /> {typeLabel}
        </span>
      )}
    </div>
  );
}

export function LibraryCard(props: LibraryCardProps) {
  const { seed, index, title, subtitle, icon, typeLabel, image, cornerBadge, meta, cta, children, href, onClick, disabled, className } = props;

  const shell = cn(
    "group relative flex flex-col overflow-hidden rounded-2xl border border-border bg-bg-elevated text-left",
    "transition duration-200 hover:-translate-y-0.5 hover:border-cyber-500/50 hover:shadow-xl hover:shadow-black/30",
    disabled && "pointer-events-none opacity-60",
    className,
  );

  const inner = (
    <>
      <div className="relative">
        <Hero seed={seed} index={index} icon={icon} typeLabel={typeLabel} image={image} />
        {cornerBadge && <div className="absolute right-3 top-3">{cornerBadge}</div>}
      </div>
      <div className="flex flex-1 flex-col p-4">
        <h3 className="line-clamp-2 text-base font-bold text-white group-hover:text-cyber-300">{title}</h3>
        {subtitle && <p className="mt-1 line-clamp-2 flex-1 text-sm text-slate-400">{subtitle}</p>}
        {children}
        {(meta || cta) && (
          <div className="mt-4 flex items-center justify-between gap-3">
            <div className="min-w-0 text-[11px] text-slate-400">{meta}</div>
            {cta}
          </div>
        )}
      </div>
    </>
  );

  if (href) return <Link href={href} className={shell}>{inner}</Link>;
  return (
    <button type="button" onClick={onClick} disabled={disabled} className={shell}>
      {inner}
    </button>
  );
}
