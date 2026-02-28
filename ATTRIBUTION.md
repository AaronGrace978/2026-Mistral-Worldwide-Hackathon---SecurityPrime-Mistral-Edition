# Attribution & Credits

SecurityPrime uses the following open-source libraries, APIs, and services. All are properly credited below.

## AI & Models

- **Mistral AI** — Mistral Large, Ministral, Devstral Small, Pixtral, and Codestral models used for threat analysis, security audits, remediation scripts, and visual inspection. Supported via direct API (`api.mistral.ai`) and via Ollama. [mistral.ai](https://mistral.ai)
- **Ollama** — Model serving infrastructure (cloud + local) for Mistral models. [ollama.com](https://ollama.com)

## Rust Dependencies (Desktop Backend)

| Crate | License | Purpose |
|-------|---------|---------|
| Tauri | MIT/Apache-2.0 | Desktop app framework |
| Tokio | MIT | Async runtime |
| Serde / serde_json | MIT/Apache-2.0 | Serialization |
| Reqwest | MIT/Apache-2.0 | HTTP client (Ollama API) |
| Rusqlite | MIT | SQLite database |
| aes-gcm, sha2, pbkdf2 | MIT/Apache-2.0 | Cryptography |
| Keyring | MIT | OS keychain storage |
| Chrono | MIT/Apache-2.0 | Date/time |
| Sysinfo | MIT | System information |
| Thiserror | MIT/Apache-2.0 | Error handling |
| Linfa | MIT | ML/behavioral detection |

## JavaScript/TypeScript Dependencies (Frontend)

| Package | License | Purpose |
|---------|---------|---------|
| SvelteKit | MIT | Web framework |
| Svelte | MIT | UI framework |
| Tailwind CSS | MIT | Styling |
| @tauri-apps/api | Apache-2.0 | Tauri bindings |
| Marked | MIT | Markdown rendering |
| Lucide Svelte | ISC | Icons |
| Bits-UI | MIT | Accessible components |

## Server Dependencies (MSP)

| Crate | License | Purpose |
|-------|---------|---------|
| Axum | MIT | Web framework |
| SQLx | MIT/Apache-2.0 | PostgreSQL |
| jsonwebtoken | MIT | JWT auth |
| bcrypt | MIT | Password hashing |

## Contributors

- Aaron Grace — [@AaronGrace978](https://github.com/AaronGrace978) | [BostonAI.io](https://bostonai.io)
- Cyber Security Prime Team

---

*Built for the 2026 Mistral Global Online Hackathon.*
