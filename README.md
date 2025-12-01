# SAFESPACE Reverse Shell Generator (Enterprise Edition)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-green.svg)
![React](https://img.shields.io/badge/react-18.x-61DAFB.svg)
![Vite](https://img.shields.io/badge/vite-6.x-646CFF.svg)

A premium, cyber-security themed reverse shell generator designed for penetration testers and security professionals. Features **150+ unique payloads**, advanced obfuscation, and a sleek, hacker-centric UI.

## 🚀 Features

- **Massive Database**: 150+ reverse shells across Bash, PowerShell, Python, PHP, Ruby, Perl, Golang, Rust, and more.
- **Advanced Payloads**:
  - **Bypass**: Polyglots, Obfuscated Bash, Encoded PowerShell.
  - **Premium**: AMSI Bypass, SSL/TLS Encrypted Shells, FUD-style techniques.
  - **LOLBins**: Windows binaries (Certutil, Regsvr32, Mshta, etc.).
  - **DNS Tunneling**: Dnscat2, Iodine, Tunshell.
- **Obfuscation Engine**: Built-in Base64, URL, and Hex encoding.
- **Enterprise UI**:
  - Dark mode with glassmorphism and matrix aesthetics.
  - Advanced filtering by OS, Language, and Tags.
  - One-click payload copying.

## 🛠️ Installation & Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/devtint/r3verse_shells_gen.git
    cd r3verse_shells_gen
    ```

2.  **Install dependencies**:
    ```bash
    npm install
    ```

3.  **Run Development Server**:
    ```bash
    npm run dev
    ```

## 📦 Deployment

### Vercel
This project is optimized for Vercel.
1.  Push to GitHub.
2.  Import project in Vercel.
3.  Deploy (Zero config required, `vercel.json` included for routing).

## 🛡️ Disclaimer
This tool is for **educational and authorized security testing purposes only**. Misuse of this software for malicious purposes is strictly prohibited.

---
Developed by **SAFESPACE Security**.
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## React Compiler

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
