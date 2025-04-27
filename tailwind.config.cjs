/** @type {import('tailwindcss').Config} */
export default {
    content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
    theme: {
      extend: {},
    },
    plugins: [],
    daisyui: {
      themes: ['light', 'dark'], // Enable light and dark themes,
      logs: false,
    },
  };
  