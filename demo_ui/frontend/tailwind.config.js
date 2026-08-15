/** @type {import('tailwindcss').Config} */
// Colour values mirror src/design/tokens.ts — see that file for the palette
// validation results that constrain them.
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          page: "#0b0f14",
          panel: "#0f1419",
          raised: "#151c24",
          hairline: "#1f2933",
        },
        ink: {
          primary: "#f2f5f8",
          secondary: "#a8b3bf",
          muted: "#6b7785",
        },
        entity: {
          rsu: "#3987e5",
          controller: "#199e70",
          vehicle: "#7d8894",
          ghost: "#d55181",
        },
        status: {
          good: "#0ca30c",
          caught: "#fab219",
          serious: "#ec835a",
          missed: "#d03b3b",
        },
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
