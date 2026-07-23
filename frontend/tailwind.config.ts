import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "monospace"],
        display: ["var(--font-display)", "sans-serif"],
      },
      colors: {
        // Brand -- every stop is a fixed hue except 400 (used as text/icon
        // color; needs a darker per-theme value to stay legible on a light
        // background -- see --brand-400 in globals.css). Stops used only as
        // fills/tints (500-900) keep one hue across both themes.
        brand: {
          50: "#f0f9ff",
          100: "#e0f2fe",
          200: "#bae6fd",
          300: "#7dd3fc",
          400: "hsl(var(--brand-400))",
          500: "#0ea5e9",
          600: "#0284c7",
          700: "#0369a1",
          800: "#075985",
          900: "#0c4a6e",
          950: "#082f49",
        },
        // Severity colors (theme-aware, see globals.css)
        critical: "hsl(var(--severity-critical))",
        high: "hsl(var(--severity-high))",
        medium: "hsl(var(--severity-medium))",
        low: "hsl(var(--severity-low))",
        info: "hsl(var(--severity-info))",
        // Grades (theme-aware, see globals.css)
        "grade-a": "hsl(var(--grade-a))",
        "grade-b": "hsl(var(--grade-b))",
        "grade-c": "hsl(var(--grade-c))",
        "grade-d": "hsl(var(--grade-d))",
        "grade-f": "hsl(var(--grade-f))",
        // Surface scale, theme-aware except 950 (always dark -- terminal /
        // code panes and the attack-surface graph canvas keep a fixed dark
        // backdrop by design, see globals.css).
        surface: {
          950: "#030712",
          900: "hsl(var(--surface-900))",
          800: "hsl(var(--surface-800))",
          700: "hsl(var(--surface-700))",
          600: "hsl(var(--surface-600))",
          500: "hsl(var(--surface-500))",
        },
        // Semantic
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease-in-out",
        "slide-in": "slideIn 0.2s ease-out",
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanLine 2s linear infinite",
        "counter": "counter 1s ease-out forwards",
        "collapsible-down": "collapsibleDown 0.15s ease-out",
        "collapsible-up": "collapsibleUp 0.15s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideIn: {
          "0%": { opacity: "0", transform: "translateX(-8px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        scanLine: {
          "0%": { top: "0%" },
          "100%": { top: "100%" },
        },
        collapsibleDown: {
          from: { height: "0" },
          to: { height: "var(--radix-collapsible-content-height)" },
        },
        collapsibleUp: {
          from: { height: "var(--radix-collapsible-content-height)" },
          to: { height: "0" },
        },
      },
      backgroundImage: {
        "grid-pattern": "linear-gradient(rgba(14,165,233,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.05) 1px, transparent 1px)",
        "radial-gradient": "radial-gradient(ellipse at top, rgba(14,165,233,0.15) 0%, transparent 70%)",
        "hero-gradient": "linear-gradient(135deg, #030712 0%, #0a0f1a 50%, #082f49 100%)",
      },
      backgroundSize: {
        "grid": "32px 32px",
      },
    },
  },
  plugins: [
    require("@tailwindcss/typography"),
    require("@tailwindcss/forms"),
  ],
};

export default config;
