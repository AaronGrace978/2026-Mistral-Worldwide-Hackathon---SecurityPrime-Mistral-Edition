# 🛡️ Cyber Security Prime

<div align="center">

![Cyber Security Prime](https://img.shields.io/badge/Cyber%20Security-Prime-00d9ff?style=for-the-badge&logo=shield&logoColor=white)
![Tauri](https://img.shields.io/badge/Tauri-1.5-ffc131?style=for-the-badge&logo=tauri&logoColor=white)
![Svelte](https://img.shields.io/badge/Svelte-4.0-ff3e00?style=for-the-badge&logo=svelte&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-2021-000000?style=for-the-badge&logo=rust&logoColor=white)

**A powerful, modular, all-in-one cybersecurity desktop application**

*Cyberpunk 2077 inspired design • Built with Tauri & Svelte • Cross-platform*

</div>

---

## ✨ Features

### 🔒 Security Modules

- **🛡️ Real-time Malware Scanner** - Continuous protection against malware, viruses, and threats
- **🔥 Advanced Firewall Manager** - Control network traffic and block suspicious connections  
- **🔐 File Encryption** - AES-256-GCM encryption for sensitive files and folders
- **🐛 Vulnerability Scanner** - Detect security weaknesses and outdated software
- **🌐 Network Monitor** - Real-time view of all network connections
- **🤖 AI Security Assistant** - *(Coming Soon)* AI-powered threat analysis

### 🎨 Design

- Cyberpunk 2077 inspired dark theme with neon accents
- Glassmorphism cards and smooth animations
- Professional, modern dashboard with real-time updates
- Light/Dark mode support

### 🔧 Technical

- **Cross-platform** - Windows, macOS, and Linux support
- **Native performance** - Rust backend for security operations
- **Secure by design** - Tauri's security-first architecture
- **Modular architecture** - Enable/disable features as needed

---

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or later)
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites)

### Installation

```bash
# Clone the repository
git clone https://github.com/AaronGrace978/SecurityPrime.git
cd SecurityPrime

# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

### Development

```bash
# Run frontend only (for UI development)
npm run dev

# Run with Tauri (full app)
npm run tauri dev

# Build production release
npm run tauri build

# Type checking
npm run check
```

---

## 📁 Project Structure

```
SecurityPrime/
├── src-tauri/                 # Rust/Tauri backend
│   ├── src/
│   │   ├── main.rs           # App entry point
│   │   ├── cmd.rs            # Tauri command handlers
│   │   ├── utils.rs          # Shared utilities
│   │   └── modules/          # Security modules
│   │       ├── scanner.rs    # Malware scanner
│   │       ├── firewall.rs   # Firewall manager
│   │       ├── encryption.rs # File encryption
│   │       ├── vulnerability.rs
│   │       ├── network.rs    # Network monitor
│   │       └── agent.rs      # AI assistant (placeholder)
│   └── tauri.conf.json       # Tauri configuration
│
├── src/                       # SvelteKit frontend
│   ├── lib/
│   │   ├── api.ts            # Tauri API wrappers
│   │   ├── utils.ts          # Utility functions
│   │   ├── stores/           # Svelte stores
│   │   └── components/       # UI components
│   │       └── ui/           # shadcn-svelte components
│   └── routes/               # SvelteKit pages
│       ├── +page.svelte      # Dashboard
│       ├── scanner/          # Scanner module
│       ├── firewall/         # Firewall module
│       ├── encryption/       # Encryption module
│       ├── vulnerability/    # Vulnerability scanner
│       ├── network/          # Network monitor
│       ├── agent/            # AI assistant
│       └── settings/         # App settings
│
├── package.json
├── tailwind.config.js        # Tailwind + Cyberpunk theme
└── README.md
```

---

## 🎯 Roadmap

### Phase 1: Foundation ✅
- [x] Project setup with Tauri + SvelteKit
- [x] Cyberpunk UI design system
- [x] Dashboard with security score
- [x] Module architecture
- [x] Stubbed security modules

### Phase 2: Core Features 🚧
- [ ] Real malware scanning engine integration
- [ ] Windows Firewall API integration
- [ ] AES-256 encryption implementation
- [ ] CVE database integration
- [ ] Network packet analysis

### Phase 3: Advanced Features 📋
- [ ] AI-powered threat analysis
- [ ] Secure password vault
- [ ] Browser extension
- [ ] Cloud sync (optional)
- [ ] Plugin system

---

## 🛡️ Security

Cyber Security Prime is built with security in mind:

- **Secure IPC** - All frontend-backend communication uses Tauri's secure invoke system
- **Allowlist** - Explicit permissions for filesystem, network, and system access
- **Rust Backend** - All sensitive operations run in memory-safe Rust
- **No Telemetry** - Your data stays on your device

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 💖 Acknowledgments

- [Tauri](https://tauri.app/) - For the amazing framework
- [SvelteKit](https://kit.svelte.dev/) - For the reactive frontend
- [shadcn-svelte](https://www.shadcn-svelte.com/) - For beautiful components
- [Cyberpunk 2077](https://www.cyberpunk.net/) - For design inspiration

---

<div align="center">

**Made with ❤️ by the Cyber Security Prime Team**

[Website](https://cybersecurityprime.dev) • [Documentation](https://docs.cybersecurityprime.dev) • [Discord](https://discord.gg/cybersecurityprime)

</div>
