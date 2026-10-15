/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          950: '#070A0F',
          900: '#0B0F17',
          850: '#101726',
          800: '#162035',
          750: '#1D2A45',
          700: '#273656',
        },
        brand: {
          red: '#EF4444',
          accent: '#3B82F6',
          emerald: '#10B981',
          amber: '#F59E0B',
          purple: '#8B5CF6'
        }
      }
    },
  },
  plugins: [],
}
