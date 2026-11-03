/** Every color here resolves to a CSS variable defined in src/index.css — that file is the
 * single source of truth for token values. */
const token = (name) => `rgb(var(--color-${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    // Two weights only, by design (400 body / 600 emphasis).
    fontWeight: {
      normal: "400",
      semibold: "600",
    },
    extend: {
      colors: {
        surface: {
          page: token("surface-page"),
          panel: token("surface-panel"),
          card: token("surface-card"),
          raised: token("surface-raised"),
        },
        line: {
          DEFAULT: token("line"),
          strong: token("line-strong"),
        },
        fg: {
          DEFAULT: token("fg"),
          secondary: token("fg-secondary"),
          muted: token("fg-muted"),
          "on-fill": token("fg-on-fill"),
        },
        accent: {
          DEFAULT: token("accent"),
          hover: token("accent-hover"),
          fill: token("accent-fill"),
          "fill-hover": token("accent-fill-hover"),
        },
        danger: {
          DEFAULT: token("danger"),
          fill: token("danger-fill"),
          "fill-hover": token("danger-fill-hover"),
        },
        success: token("success"),
        warning: token("warning"),
        caution: token("caution"),
        violet: token("violet"),
      },
      // `text-accent` uses the AA-safe text step; bg/border/ring-accent keep the base accent.
      textColor: {
        accent: {
          DEFAULT: token("accent-text"),
          hover: token("accent-text-hover"),
        },
      },
      borderRadius: {
        control: "8px",
        card: "12px",
      },
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          '"Segoe UI"',
          "Roboto",
          '"Helvetica Neue"',
          "Arial",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};
