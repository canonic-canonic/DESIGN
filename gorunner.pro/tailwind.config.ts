import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // CANONIC governance tokens
        canonic: {
          green: "#00ff88",
          purple: "#7c3aed",
          blue: "#60a5fa",
          accent: "#bf5af2",
        },
        // RUNNER role colors (from STATUS_COLORS in runner.js)
        status: {
          posted: "#3b82f6",
          assigned: "#8b5cf6",
          accepted: "#6366f1",
          in_progress: "#f59e0b",
          completed: "#22c55e",
          rated: "#10b981",
          cancelled: "#ef4444",
        },
        // Robert's design accents
        runner: {
          orange: "#f97316",
          complete: "#22c55e",
          proof: "#3b82f6",
          rate: "#8b5cf6",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      backgroundImage: {
        "gradient-pro": "linear-gradient(135deg, #3b82f6, #8b5cf6)",
        "gradient-runner": "linear-gradient(135deg, #f97316, #ef4444)",
        "gradient-ops": "linear-gradient(135deg, #6b7280, #374151)",
        "gradient-coin": "linear-gradient(135deg, #f59e0b, #eab308)",
        "gradient-hero": "linear-gradient(135deg, #0f172a, #1e293b)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "slide-up": "slideUp 0.3s ease-out",
      },
      keyframes: {
        slideUp: {
          "0%": { transform: "translateY(100%)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
