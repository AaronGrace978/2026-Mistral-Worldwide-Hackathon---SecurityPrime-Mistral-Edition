# Little Snitch Integration

SecurityPrime integrates with [Little Snitch](https://obdev.at/products/littlesnitch/index.html) as a network-transparency companion for macOS users.

## Why This Helps

- Adds user-verifiable outbound control for app traffic.
- Lets judges validate that SecurityPrime does not phone home unexpectedly.
- Supports a "trust through observability" story in demos.

## Implementation Status

### Phase 1 — Complete

- macOS-only UI card: **Little Snitch Companion** in the Network Monitor page.
- Auto-detect Little Snitch at `/Applications/Little Snitch.app` and Setapp path.
- Link to Little Snitch docs.

### Phase 2 — Complete

- **Recommended Rules Engine** (`get_little_snitch_rules`):
  - Curated allow rules for AI model endpoints (OpenAI, Anthropic, Gemini, Mistral, Groq, Cohere).
  - Allow rules for local model servers (Ollama, LM Studio).
  - Allow rules for OS update domains.
  - Deny rules for known telemetry domains (Microsoft, Apple, Google).
  - Dynamic rules generated from live connections for unknown destinations.
  - Filterable rules table in the UI with action/allow/deny views.

- **Domain Trust Classification** (`get_little_snitch_domain_trust`):
  - Every unique destination IP/domain from active connections is classified as **trusted**, **unknown**, or **suspicious** using a built-in domain registry.
  - Trust summary badges with counts.
  - Filterable domain list with category labels.

- **`.lsrules` Profile Export** (`export_little_snitch_profile`):
  - Generates a valid Little Snitch Rule Group JSON file.
  - Copy to clipboard or download as `SecurityPrime.lsrules`.
  - Import into Little Snitch via **File → New Rule Group From File**.

## Backend Commands

| Command | Description |
|---|---|
| `get_little_snitch_status` | Detect Little Snitch installation (macOS only) |
| `get_little_snitch_rules` | Generate recommended allow/deny rules |
| `get_little_snitch_domain_trust` | Classify active connection domains by trust level |
| `export_little_snitch_profile` | Export `.lsrules` JSON for Little Snitch import |

## Known Domain Registry

The backend maintains a curated list of known domains in `cmd.rs` (`KNOWN_DOMAINS`):

- **AI endpoints**: api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.mistral.ai, api.groq.com, api.cohere.ai
- **Local**: localhost, 127.0.0.1
- **OS updates**: update.microsoft.com, download.windowsupdate.com, swscan.apple.com, swdist.apple.com
- **CDNs**: cdn.jsdelivr.net, cdnjs.cloudflare.com
- **Telemetry (deny)**: telemetry.microsoft.com, vortex.data.microsoft.com, settings-win.data.microsoft.com, watson.telemetry.microsoft.com, metrics.apple.com, xp.apple.com, analytics.google.com, firebaselogging.googleapis.com

## Platform Notes

- Little Snitch is macOS-specific.
- The feature is optional and labeled as macOS-only.
- Windows users continue using built-in firewall and network monitor flows.
- The recommended rules and domain trust features work on all platforms even without Little Snitch installed, providing value as a network policy reference.

## Submission Language

> "SecurityPrime pairs with Little Snitch on macOS for process-level outbound visibility and consent-driven network control. Users can independently verify every network destination our AI features use."
