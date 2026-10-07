/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: "#7f1d1d",
          high: "#dc2626",
          medium: "#d97706",
          low: "#65a30d",
          info: "#0891b2",
          unknown: "#6b7280",
        },
        status: {
          open: "#dc2626",
          triaged: "#ca8a04",
          false_positive: "#64748b",
          fixed: "#16a34a",
          accepted_risk: "#6b7280",
        },
        risk: {
          low: "#16a34a",
          moderate: "#84cc16",
          elevated: "#eab308",
          high: "#f97316",
          critical: "#dc2626",
        },
      },
    },
  },
  plugins: [],
};
