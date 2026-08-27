/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        navy:  { DEFAULT: '#1A2B4A', 50: '#EBF0F8', 700: '#142240', 900: '#0D1829' },
        brand: { DEFAULT: '#2471A3', light: '#D6E4F0' },
      },
    },
  },
  plugins: [],
}
