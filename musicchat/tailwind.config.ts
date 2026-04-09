import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0a0c",
        "bg-raised": "#141418",
        "bg-card": "#1a1a20",
        "bg-hover": "#222228",
        border: "#2a2a32",
        "border-subtle": "#1e1e26",
        accent: "#00ff88",
        "accent-dim": "rgba(0,255,136,0.15)",
        gold: "#ffd700",
        purple: "#a78bfa",
        rank: {
          listener: "#8e8e9a",
          selector: "#00ff88",
          curator: "#a78bfa",
          archivist: "#ffd700",
          elder: "#ff6b6b",
        },
      },
      fontFamily: {
        sans: ["-apple-system", "BlinkMacSystemFont", "SF Pro Display", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["SF Mono", "Fira Code", "Cascadia Code", "monospace"],
      },
      animation: {
        "eq-bounce": "eq-bounce 1.2s ease-in-out infinite",
        blink: "blink 1.5s ease-in-out infinite",
      },
      keyframes: {
        "eq-bounce": {
          "0%, 100%": { transform: "scaleY(1)" },
          "50%": { transform: "scaleY(0.3)" },
        },
        blink: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.3" },
        },
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
