# 🚀 Quick Start Guide

## Prerequisites

Before running Cyber Security Prime, make sure you have:

| Requirement | Version | Download |
|-------------|---------|----------|
| Node.js | v18+ | [nodejs.org](https://nodejs.org/) |
| Rust | Latest | [rustup.rs](https://rustup.rs/) |
| Visual Studio Build Tools | 2019+ | [VS Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) |

> **Windows Users**: Install "Desktop development with C++" workload from VS Build Tools

---

## 🎯 Quick Start (Windows)

### First Time Setup
```batch
setup.bat
```

### Development Mode
```batch
dev.bat
```

### Production Build
```batch
build.bat
```

### Frontend Only (No Rust)
```batch
frontend-only.bat
```

---

## 📦 npm Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start frontend dev server (port 5173) |
| `npm run tauri dev` | Start full Tauri app in dev mode |
| `npm run tauri build` | Build production release |
| `npm run check` | TypeScript type checking |
| `npm run format` | Format code with Prettier |

---

## 📁 Build Output

After running `npm run tauri build`, find installers at:

```
src-tauri/target/release/bundle/
├── msi/           # Windows MSI installer
├── nsis/          # Windows NSIS installer
└── ...
```

---

## 🔧 Troubleshooting

### "Rust not found"
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows: Download from https://rustup.rs
```

### "WebView2 not found" (Windows)
Download from: https://developer.microsoft.com/en-us/microsoft-edge/webview2/

### Build fails with linker errors
Install Visual Studio Build Tools with C++ workload.

### Port 5173 already in use
```bash
# Kill process on port
npx kill-port 5173
```

---

## 🎨 Development Tips

- **Hot Reload**: Frontend changes reload instantly
- **Rust Changes**: Require recompilation (automatic in dev mode)
- **Mock Data**: Frontend works without Tauri using mock API data
- **Theme**: Toggle dark/light in Settings or press the theme switch

---

## 📚 Resources

- [Tauri Docs](https://tauri.app/v1/guides/)
- [SvelteKit Docs](https://kit.svelte.dev/docs)
- [Tailwind CSS](https://tailwindcss.com/docs)
- [Lucide Icons](https://lucide.dev/icons/)

