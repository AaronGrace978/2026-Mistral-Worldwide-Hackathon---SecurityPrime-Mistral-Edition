# SecurityPrime

**AI-native desktop cybersecurity suite powered by Mistral models.**

SecurityPrime is a full-featured endpoint security application built with a Rust backend (Tauri) and a SvelteKit frontend, featuring deep integration with Mistral AI for intelligent threat analysis, behavioral detection, and security automation.

Built for the **2026 Mistral Global Online Hackathon**.

---

## Why Mistral?

SecurityPrime uses Mistral models as the brain of its security engine — not as a bolt-on chatbot, but as a core reasoning layer that understands threats, analyzes file systems, predicts attack patterns, and generates remediation scripts.

### Multi-Model Routing Architecture

| Model | Role | Use Case |
|-------|------|----------|
| **Mistral Large 3** (675B) | Deep Analyst | Full threat assessment, security audits, CVE analysis |
| **Ministral** (8B) | Fast Triage | Quick risk classification, alert prioritization |
| **Devstral Small 2** (24B) | Code & Remediation | Firewall rule generation, script-based fixes, agentic tasks |
| **Pixtral** (12B) | Visual Inspector | Screenshot analysis, phishing page detection |

The routing engine automatically selects the right model for each task — fast models for simple questions, large models for deep analysis — optimizing for both speed and cost.

## Features

### Core Security Modules
- **Malware Scanner** — Quick, full, and custom scans with memory forensics and behavioral analysis
- **Firewall Management** — Windows Firewall integration via `netsh`, rule import/export
- **File Encryption** — AES-256-GCM encryption with secure key management
- **Vulnerability Scanner** — CVE-aware scanning with remediation guidance
- **Network Monitor** — Real-time connection tracking and traffic analysis
- **Tamper Detection** — File integrity checking, anomaly detection, secure boot verification
- **Process Isolation** — Sandboxing and containerization for untrusted processes
- **Security Hardening** — Memory protection (DEP/ASLR/CFG), secure logging, rate limiting

### AI-Powered Features
- **Mistral Security Copilot** — Streaming chat interface with markdown rendering and context-aware analysis
- **Directory Scanning** — AI analyzes file system structure for threats, health issues, and suspicious patterns
- **Threat Prediction** — Behavioral pattern analysis to predict emerging threats
- **Security Intelligence** — Aggregated threat indicators and recommended actions
- **Comprehensive AI Analysis** — Full system audit combining all data sources

### Enterprise & Compliance
- **MSP Management Server** — Multi-endpoint management with PostgreSQL backend
- **GDPR & HIPAA Compliance** — Data inventory, consent tracking, breach reporting
- **Licensing System** — Per-endpoint licensing with secure activation
- **Windows Service** — Background monitoring with MSP heartbeat reporting
- **Plugin System** — Extensible architecture for third-party integrations

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | SvelteKit 2, TypeScript, Tailwind CSS (cyberpunk theme) |
| Backend | Rust, Tauri 1.6, Tokio async runtime |
| AI | Mistral models via Ollama (cloud + local) |
| Database | SQLite (local), PostgreSQL (MSP server) |
| Security | OS keychain (keyring), AES-256-GCM, bcrypt, JWT |
| Desktop | System tray, Windows Service, custom protocol handler |

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) (stable)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites) (`cargo install tauri-cli`)
- [Ollama](https://ollama.com/) (for AI features)

### Setup

```bash
# Clone the repository
git clone https://github.com/AaronGrace978/SecurityPrime.git
cd SecurityPrime

# Install frontend dependencies
npm install

# Copy environment config
cp .env.example .env

# Pull a Mistral model (for local inference)
ollama pull mistral:7b

# Start development
npm run tauri:dev
```

### Configuration

1. **API Key** — Set your Ollama Cloud API key via the in-app Settings panel (stored in your OS keychain, never in files)
2. **Models** — Configure model routing in `config/ollama_cloud_config.json`
3. **MSP Server** — Set `DATABASE_URL`, `JWT_SECRET`, and `PORT` in `.env` for managed deployments

## Architecture

```
SecurityPrime/
├── src/                    # SvelteKit frontend
│   ├── routes/             # Page components (dashboard, agent, scanner, etc.)
│   ├── lib/
│   │   ├── api.ts          # Type-safe Tauri API layer
│   │   ├── components/     # UI components (shadcn/ui + custom)
│   │   └── stores/         # Svelte stores (security, modules, theme)
│   └── app.css             # Cyberpunk theme (Tailwind)
├── src-tauri/              # Rust backend
│   └── src/
│       ├── main.rs         # Tauri app entry + command registration
│       ├── cmd.rs          # Core Tauri commands
│       ├── database/       # SQLite persistence + migrations
│       └── modules/        # Security modules
│           ├── agent.rs    # Mistral AI integration (streaming, multi-model)
│           ├── scanner.rs  # Malware scanner
│           ├── firewall.rs # Windows Firewall management
│           ├── encryption.rs # AES-256-GCM file encryption
│           ├── network.rs  # Network monitoring
│           ├── compliance.rs # GDPR/HIPAA
│           ├── flagship.rs # Advanced features (playbooks, attack surface)
│           └── ...
├── server/                 # MSP management server (Axum + PostgreSQL)
├── config/                 # Ollama Cloud model configuration
└── docs/                   # Documentation
```

## Security

- API keys are stored in the OS-native keychain (Windows Credential Manager / macOS Keychain / Linux Secret Service)
- All file encryption uses AES-256-GCM with unique IVs
- MSP server uses bcrypt password hashing and JWT authentication
- SQL injection protection via parameterized queries throughout
- No secrets are stored in configuration files or source code

## License

MIT

---

*Built with Rust, Svelte, and Mistral AI.*
