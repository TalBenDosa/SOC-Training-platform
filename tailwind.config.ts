import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  /**
   * The parentheses in Next.js route-group folders — src/app/(app), src/app/(auth)
   * — are glob syntax to fast-glob, so a plain "./src/**\/*" pattern silently
   * skips every file inside them. That meant any utility used ONLY in those
   * folders was never emitted: the whole main application section was quietly
   * missing styles (verified: w-[480px], max-w-[30rem] and py-[7vh] all resolved
   * to nothing). Escaping the parentheses makes those directories match.
   */
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/\\(app\\)/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/\\(auth\\)/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // Theme token: a white-label org can pick another UI font (src/lib/brand/theme.ts FONTS).
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "ui-monospace", "monospace"],
      },
      colors: {
        // Cyber dark palette inspired by CrowdStrike Falcon / Sentinel
        // Theme tokens (src/lib/brand/theme.ts): a white-label org's theme recolours these.
        bg: {
          DEFAULT: "rgb(var(--bg) / <alpha-value>)",
          elevated: "rgb(var(--bg-elevated) / <alpha-value>)",
          panel: "rgb(var(--bg-panel) / <alpha-value>)",
          hover: "rgb(var(--bg-hover) / <alpha-value>)",
        },
        // WCAG 1.4.3: stock slate-500 (#64748b) is only 3.6-4.1:1 on our dark surfaces, and it is the
        // default "secondary text" colour (~370 uses). Lifted so it clears 4.5:1 on every surface up to #1e293b.
        slate: { 500: "#8190a5" },
        border: {
          DEFAULT: "rgb(var(--border) / <alpha-value>)",
          strong: "rgb(var(--border-strong) / <alpha-value>)",
        },
        cyber: {
          // primary accent (default: electric cyan), a theme token
          50: "rgb(var(--cyber-50) / <alpha-value>)",
          100: "rgb(var(--cyber-100) / <alpha-value>)",
          200: "rgb(var(--cyber-200) / <alpha-value>)",
          300: "rgb(var(--cyber-300) / <alpha-value>)",
          400: "rgb(var(--cyber-400) / <alpha-value>)",
          500: "rgb(var(--cyber-500) / <alpha-value>)",
          600: "rgb(var(--cyber-600) / <alpha-value>)",
          700: "rgb(var(--cyber-700) / <alpha-value>)",
          800: "rgb(var(--cyber-800) / <alpha-value>)",
          900: "rgb(var(--cyber-900) / <alpha-value>)",
        },
        // Text on an accent-filled control: dark or white, picked for contrast with the accent.
        "on-accent": "rgb(var(--on-accent) / <alpha-value>)",
        neon: {
          green: "#00ff9d",
          red: "#ff3860",
          amber: "#ffb020",
          purple: "#a855f7",
          // referenced by focus styles on the invite/renew code fields but never defined
          cyan: "#22d3ee",
          blue: "#3b82f6",
        },
        severity: {
          critical: "#ff2d55",
          high: "#ff6b35",
          medium: "#ffb020",
          low: "#3b82f6",
          info: "#64748b",
        },
      },
      backgroundImage: {
        "grid-fade":
          "linear-gradient(to bottom, transparent, rgb(var(--bg))), linear-gradient(to right, rgb(var(--border)) 1px, transparent 1px), linear-gradient(to bottom, rgb(var(--border)) 1px, transparent 1px)",
        "cyber-glow":
          "radial-gradient(ellipse 80% 50% at 50% -20%, rgb(var(--cyber-400) / 0.15), transparent)",
      },
      // Corner radius scale as theme tokens (sharp / standard / rounded); rounded-full is untouched.
      borderRadius: {
        sm: "var(--radius-sm)",
        DEFAULT: "var(--radius)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
        "2xl": "var(--radius-2xl)",
      },
      backgroundSize: {
        grid: "100% 100%, 32px 32px, 32px 32px",
      },
      boxShadow: {
        // Accent glow; its strength is a theme token (0 = the "flat" button style).
        glow: "0 0 24px -4px rgb(var(--cyber-400) / var(--glow-alpha))",
        "glow-red": "0 0 24px -4px rgba(255,45,85,0.55)",
        "glow-green": "0 0 24px -4px rgba(0,255,157,0.45)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        scan: "scan 2.5s linear infinite",
        flicker: "flicker 3s linear infinite",
      },
      keyframes: {
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        flicker: {
          "0%, 100%": { opacity: "1" },
          "33%": { opacity: "0.85" },
          "66%": { opacity: "0.95" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
