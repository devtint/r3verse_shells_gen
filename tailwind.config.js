/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                background: '#0a0a0a',
                surface: '#121212',
                primary: '#00ff41', // Matrix green/Cyberpunk green
                secondary: '#008f11',
                accent: '#ff003c', // Cyberpunk red
                text: '#e0e0e0',
                muted: '#a0a0a0',
                border: '#333333',
            },
            fontFamily: {
                mono: ['"Fira Code"', 'monospace'], // We might need to import this font
                sans: ['Inter', 'sans-serif'],
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
            },
        },
    },
    plugins: [],
}
