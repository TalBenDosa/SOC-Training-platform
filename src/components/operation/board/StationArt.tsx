"use client";
import React, { useId } from "react";
import type { BuildingKind } from "@/lib/rooms/experience";

// Hand-drawn 2.5D scene art for the mission board cards, one per station kind.
// Colours come from the board's CSS variables (--op-a primary, --op-b secondary,
// --op-w warning) so each room can re-tint the same art. Motion lives in the
// op-* keyframes in MissionBoard and stops under prefers-reduced-motion.

const INK = "#0a1322";
const PANEL = "#0f1b30";
const EDGE = "#22324f";

function Floor({ id }: { id: string }) {
  return (
    <>
      <defs>
        <radialGradient id={`${id}-floor`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="var(--op-a)" stopOpacity="0.45" />
          <stop offset="100%" stopColor="var(--op-a)" stopOpacity="0" />
        </radialGradient>
      </defs>
      <ellipse cx="130" cy="132" rx="112" ry="15" fill={`url(#${id}-floor)`} />
    </>
  );
}

// Archive: a case dossier with the suspect envelope, the raw headers on a screen.
function ArchiveArt({ id }: { id: string }) {
  return (
    <>
      <Floor id={id} />
      {/* monitor with the header listing and a scan bar */}
      <g transform="translate(142 16) skewY(6)">
        <rect width="98" height="70" rx="5" fill={INK} stroke="var(--op-a)" strokeOpacity="0.7" />
        <rect x="6" y="6" width="86" height="58" rx="2" fill="#06101f" />
        {[0, 1, 2, 3, 4, 5].map(i => (
          <rect key={i} x="11" y={12 + i * 8.5} width={[54, 70, 46, 64, 38, 58][i]} height="3.2" rx="1.2"
            fill={i === 3 ? "var(--op-w)" : "var(--op-a)"} opacity={i === 3 ? 0.95 : 0.45} />
        ))}
        <rect className="op-scan" x="7" y="8" width="84" height="7" fill="var(--op-a)" opacity="0.18" />
        <rect x="40" y="70" width="18" height="10" fill={EDGE} />
        <rect x="30" y="80" width="38" height="4" rx="2" fill={EDGE} />
      </g>
      {/* dossier folder */}
      <g transform="translate(22 62) skewY(-9)">
        <path d="M0 6 h28 l6 -6 h56 v62 h-90 z" fill="#15233b" stroke={EDGE} />
        <rect x="6" y="10" width="78" height="52" rx="2" fill="#dbe7f5" opacity="0.92" />
        {[0, 1, 2, 3].map(i => <rect key={i} x="12" y={18 + i * 9} width={[50, 62, 40, 56][i]} height="3" rx="1.5" fill="#7a8ca6" />)}
        <rect x="0" y="20" width="96" height="50" rx="3" fill="#1c2d4b" stroke="var(--op-a)" strokeOpacity="0.5" />
        {/* envelope */}
        <g className="op-float">
          <rect x="16" y="28" width="62" height="36" rx="2" fill="#eef4fb" />
          <path d="M16 30 l31 19 l31 -19" fill="none" stroke="#9aaac2" strokeWidth="1.5" />
          <g transform="translate(46 50) rotate(-12)">
            <rect x="-2" y="-8" width="34" height="13" rx="2" fill="none" stroke="var(--op-w)" strokeWidth="1.6" />
            <text x="15" y="1.6" textAnchor="middle" fontSize="7" fontWeight="800" fontFamily="ui-monospace,monospace" fill="var(--op-w)">SUSPECT</text>
          </g>
        </g>
      </g>
    </>
  );
}

// Sorting plant: envelopes on a belt through a scanner arch, sorted into bins.
function FactoryArt({ id }: { id: string }) {
  return (
    <>
      <Floor id={id} />
      <g transform="translate(14 40) skewY(8)">
        {/* belt */}
        <rect x="0" y="58" width="200" height="16" rx="3" fill={PANEL} stroke={EDGE} />
        <line x1="4" y1="66" x2="196" y2="66" stroke="var(--op-a)" strokeOpacity="0.5" strokeWidth="2" strokeDasharray="6 8" className="op-belt" />
        <rect x="0" y="74" width="200" height="8" fill="#0b1526" />
        {/* envelopes riding the belt */}
        {[0, 1, 2].map(i => (
          <g key={i} className="op-ride" style={{ animationDelay: `${-i * 1.6}s` }}>
            <rect x="0" y="44" width="30" height="18" rx="2" fill="#e8eef8" />
            <path d="M0 45 l15 9 l15 -9" fill="none" stroke="#91a1ba" strokeWidth="1.2" />
          </g>
        ))}
        {/* scanner arch */}
        <rect x="96" y="12" width="8" height="64" fill="#1a2944" stroke={EDGE} />
        <rect x="140" y="12" width="8" height="64" fill="#1a2944" stroke={EDGE} />
        <rect x="92" y="4" width="60" height="12" rx="3" fill="#1f3152" stroke="var(--op-a)" strokeOpacity="0.6" />
        <rect x="104" y="16" width="36" height="42" fill="var(--op-a)" opacity="0.08" />
        <line x1="122" y1="16" x2="122" y2="58" stroke="var(--op-a)" strokeWidth="2" className="op-blink" />
        <circle cx="100" cy="10" r="2.4" fill="#34d399" />
        <circle cx="144" cy="10" r="2.4" fill="var(--op-w)" className="op-blink" />
      </g>
      {/* bins */}
      <g transform="translate(214 86)">
        <rect width="30" height="26" rx="3" fill="#0f2a22" stroke="#34d399" strokeOpacity="0.7" />
        <text x="15" y="17" textAnchor="middle" fontSize="7" fontWeight="800" fill="#34d399" fontFamily="ui-monospace,monospace">OK</text>
      </g>
      <g transform="translate(214 116)">
        <rect width="30" height="14" rx="3" fill="#2a0f17" stroke="var(--op-w)" strokeOpacity="0.8" />
        <text x="15" y="10" textAnchor="middle" fontSize="6.5" fontWeight="800" fill="var(--op-w)" fontFamily="ui-monospace,monospace">PHISH</text>
      </g>
    </>
  );
}

// Evidence lab: a raw log under a magnifier, the decisive fields pinned.
function LabArt({ id }: { id: string }) {
  return (
    <>
      <Floor id={id} />
      <g transform="translate(26 22) skewY(-6)">
        <rect width="168" height="96" rx="6" fill={INK} stroke="var(--op-a)" strokeOpacity="0.55" />
        <rect x="0" y="0" width="168" height="14" rx="6" fill="#132341" />
        {[0, 1, 2].map(i => <circle key={i} cx={10 + i * 8} cy="7" r="2.2" fill={["#f87171", "#fbbf24", "#34d399"][i]} opacity="0.8" />)}
        {[0, 1, 2, 3, 4, 5, 6].map(i => (
          <g key={i}>
            <rect x="10" y={22 + i * 10} width="26" height="3.4" rx="1.5" fill="#64748b" opacity="0.7" />
            <rect x="42" y={22 + i * 10} width={[80, 60, 96, 70, 88, 52, 74][i]} height="3.4" rx="1.5"
              fill={i === 2 || i === 4 ? "var(--op-w)" : "var(--op-a)"} opacity={i === 2 || i === 4 ? 0.95 : 0.4} />
          </g>
        ))}
        {/* pins on the decisive rows */}
        <circle cx="150" cy="44" r="4" fill="var(--op-w)" className="op-pulse" />
        <circle cx="150" cy="64" r="4" fill="var(--op-w)" className="op-pulse" style={{ animationDelay: "0.6s" }} />
      </g>
      {/* magnifier */}
      <g className="op-float" style={{ animationDuration: "5s" }}>
        <circle cx="170" cy="78" r="30" fill="var(--op-a)" fillOpacity="0.12" stroke="#cbd5e1" strokeWidth="5" />
        <circle cx="170" cy="78" r="30" fill="none" stroke="var(--op-a)" strokeOpacity="0.6" strokeWidth="1.5" />
        <rect x="150" y="70" width="40" height="5" rx="2" fill="var(--op-w)" />
        <rect x="150" y="82" width="28" height="4" rx="2" fill="var(--op-a)" opacity="0.6" />
        <path d="M192 100 l26 24" stroke="#cbd5e1" strokeWidth="9" strokeLinecap="round" />
        <path d="M192 100 l26 24" stroke="#64748b" strokeWidth="3" strokeLinecap="round" />
      </g>
    </>
  );
}

// Triage office: the alert on the laptop, a running clock and the two calls.
function OfficeArt({ id }: { id: string }) {
  return (
    <>
      <Floor id={id} />
      {/* laptop */}
      <g transform="translate(30 18)">
        <path d="M14 0 h120 a6 6 0 0 1 6 6 v76 h-132 v-76 a6 6 0 0 1 6 -6 z" fill={INK} stroke="var(--op-a)" strokeOpacity="0.55" />
        <rect x="16" y="8" width="116" height="66" rx="2" fill="#120a14" />
        <rect x="16" y="8" width="116" height="66" rx="2" fill="var(--op-w)" opacity="0.08" className="op-blink" />
        <path d="M74 22 l20 34 h-40 z" fill="none" stroke="var(--op-w)" strokeWidth="3.5" strokeLinejoin="round" />
        <rect x="72.4" y="33" width="3.2" height="12" rx="1.4" fill="var(--op-w)" />
        <circle cx="74" cy="50" r="2" fill="var(--op-w)" />
        <path d="M-4 82 h156 l10 12 h-176 z" fill="#1a2944" stroke={EDGE} />
      </g>
      {/* countdown ring */}
      <g transform="translate(212 44)">
        <circle r="22" fill={INK} stroke={EDGE} strokeWidth="4" />
        <circle r="22" fill="none" stroke="var(--op-a)" strokeWidth="4" strokeDasharray="138" strokeLinecap="round" className="op-countdown" transform="rotate(-90)" />
        <line x1="0" y1="0" x2="0" y2="-13" stroke="#e2e8f0" strokeWidth="2.4" strokeLinecap="round" className="op-spin" />
        <circle r="2.6" fill="#e2e8f0" />
      </g>
      {/* verdict chips */}
      <g transform="translate(178 86)">
        <rect width="64" height="17" rx="8.5" fill="#2a0f17" stroke="var(--op-w)" />
        <text x="32" y="11.8" textAnchor="middle" fontSize="8" fontWeight="800" fill="var(--op-w)" fontFamily="ui-monospace,monospace">PHISHING</text>
      </g>
      <g transform="translate(178 108)">
        <rect width="64" height="17" rx="8.5" fill="#0f2a22" stroke="#34d399" strokeOpacity="0.7" />
        <text x="32" y="11.8" textAnchor="middle" fontSize="8" fontWeight="800" fill="#34d399" fontFamily="ui-monospace,monospace">BENIGN</text>
      </g>
    </>
  );
}

// Vault: the final lock, a turning dial and the code keypad.
function VaultArt({ id }: { id: string }) {
  return (
    <>
      <defs>
        <radialGradient id={`${id}-door`} cx="40%" cy="35%" r="70%">
          <stop offset="0%" stopColor="#2b3a5c" />
          <stop offset="100%" stopColor="#0e1628" />
        </radialGradient>
      </defs>
      <Floor id={id} />
      <rect x="52" y="10" width="120" height="118" rx="10" fill="#111b30" stroke={EDGE} />
      <g transform="translate(112 69)">
        <circle r="50" fill={`url(#${id}-door)`} stroke="var(--op-b)" strokeOpacity="0.8" strokeWidth="2.5" />
        <circle r="40" fill="none" stroke="var(--op-b)" strokeOpacity="0.35" strokeDasharray="3 5" />
        {Array.from({ length: 8 }, (_, i) => {
          const a = (i * Math.PI) / 4;
          return <circle key={i} cx={Math.cos(a) * 45} cy={Math.sin(a) * 45} r="3" fill="#475569" />;
        })}
        <g className="op-spin-slow">
          <circle r="20" fill="#1c2945" stroke="var(--op-b)" strokeWidth="2" />
          {[0, 60, 120].map(d => <rect key={d} x="-2" y="-28" width="4" height="56" rx="2" fill="var(--op-b)" opacity="0.85" transform={`rotate(${d})`} />)}
          <circle r="6" fill="var(--op-b)" />
        </g>
      </g>
      {/* keypad */}
      <g transform="translate(186 34)">
        <rect width="52" height="70" rx="6" fill={INK} stroke="var(--op-b)" strokeOpacity="0.6" />
        <rect x="6" y="6" width="40" height="11" rx="2" fill="#160d26" />
        <text x="26" y="14.5" textAnchor="middle" fontSize="7.5" fontWeight="800" fill="var(--op-b)" fontFamily="ui-monospace,monospace" className="op-blink">_ _ _</text>
        {Array.from({ length: 9 }, (_, i) => (
          <rect key={i} x={7 + (i % 3) * 13.5} y={23 + Math.floor(i / 3) * 14} width="10" height="10" rx="2"
            fill={i === 4 ? "var(--op-b)" : "#1e2a44"} opacity={i === 4 ? 0.9 : 1} />
        ))}
      </g>
    </>
  );
}

const ART: Record<BuildingKind, React.FC<{ id: string }>> = {
  archive: ArchiveArt,
  factory: FactoryArt,
  lab: LabArt,
  office: OfficeArt,
  vault: VaultArt,
};

export function StationArt({ kind, className }: { kind: BuildingKind; className?: string }) {
  const id = useId().replace(/:/g, "");
  const Art = ART[kind];
  return (
    <svg viewBox="0 0 260 150" className={className} role="img" aria-hidden>
      <Art id={id} />
    </svg>
  );
}
