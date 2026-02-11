import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "var(--base)",
        panel: "var(--panel)",
        panelElev: "var(--panel-elev)",
        border: "var(--border)",
        text: "var(--text)",
        muted: "var(--muted)",
        teal: "var(--teal)",
        amber: "var(--amber)",
        red: "var(--red)",
        purple: "var(--purple)"
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "ui-sans-serif", "system-ui"],
        display: ["Space Grotesk", "ui-sans-serif", "system-ui"]
      },
      boxShadow: {
        soft: "0 12px 30px rgba(0, 0, 0, 0.35)",
        glow: "0 0 0 1px rgba(45, 212, 191, 0.25), 0 12px 20px rgba(14, 116, 144, 0.25)"
      }
    }
  },
  plugins: []
} satisfies Config;
