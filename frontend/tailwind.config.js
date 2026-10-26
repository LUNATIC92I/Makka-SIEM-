/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#05070b", 900: "#0a0e15", 850: "#0e131c", 800: "#121926", 700: "#1a2333", 600: "#243047", 500: "#33415c" },
        electric: { 400: "#4c8dff", 500: "#2f6bff", 600: "#1f55e0" },
        cyanx: { 300: "#67e8f9", 400: "#22d3ee", 500: "#06b6d4" },
        neon: { 300: "#8affc1", 400: "#22ff88", 500: "#00d26a", 600: "#00a854" },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "-apple-system", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
