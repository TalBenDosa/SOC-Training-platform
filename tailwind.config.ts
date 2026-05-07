import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "ui-monospace", "monospace"],
      },
      colors: {
        // Cyber dark palette inspired by CrowdStrike Falcon / Sentinel
        bg: {
          DEFAULT: "#070b14",
          elevated: "#0b1220",
          panel: "#0f172a",
          hover: "#131c2f",
        },
        border: {
          DEFAULT: "#1e293b",
          strong: "#334155",
        },
        cyber: {
          // primary neon - electric cyan
          50: "#ecfeff",
          100: "#cffafe",
          200: "#a5f3fc",
          300: "#67e8f9",
          400: "#22d3ee",
          500: "#06b6d4",
          600: "#0891b2",
          700: "#0e7490",
          800: "#155e75",
          900: "#164e63",
        },
        neon: {
          green: "#00ff9d",
          red: "#ff3860",
          amber: "#ffb020",
          purple: "#a855f7",
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
          "linear-gradient(to bottom, transparent, #070b14), linear-gradient(to right, #1e293b 1px, transparent 1px), linear-gradient(to bottom, #1e293b 1px, transparent 1px)",
        "cyber-glow":
          "radial-gradient(ellipse 80% 50% at 50% -20%, rgba(34,211,238,0.15), transparent)",
      },
      backgroundSize: {
        grid: "100% 100%, 32px 32px, 32px 32px",
      },
      boxShadow: {
        glow: "0 0 24px -4px rgba(34,211,238,0.45)",
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
