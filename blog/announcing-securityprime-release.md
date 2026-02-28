---
title: "SecurityPrime is coming soon: an all-in-one cybersecurity desktop app that actually works"
description: "SecurityPrime is almost here — an all-in-one cybersecurity desktop app (Rust, Tauri, Svelte) that actually works. No big vendor. It's coming soon."
date: 2025-02-10
author: Aaron Grace
slug: securityprime-coming-soon
tags:
  - security
  - open-source
  - rust
  - tauri
  - cybersecurity
  - coming-soon
---

I've been working on a desktop security app for a while now, and it's getting close. Really close. So I figured it's time to talk about it: [SecurityPrime](https://aarongrace978.github.io/SecurityPrime-Coming-soon/) is coming soon.

It's an all-in-one solution — malware scanning, firewall management, file encryption, vulnerability checks, network monitoring, tamper detection, some compliance-style tooling, and an optional AI assistant that hooks into Ollama. I built it with Rust on the backend and Svelte on the frontend, with Tauri gluing everything together. It runs on Windows, macOS, and Linux.

No big vendor. No enterprise security team. Just something that actually works — and that you'll be able to clone and build yourself when it drops.

BostonAI.io is where I'm posting this because I care about tools that ship. SecurityPrime is mine — [Aaron Grace](https://github.com/AaronGrace978) / AaronGrace978 — and I'm proud of where it's headed.

---

## What's actually in it

I wanted one app that didn't make you install five different products. So SecurityPrime does a lot under one roof:

You get a **malware scanner** with quick/full/custom scans, memory forensics, behavioral stuff, and YARA rules. The **firewall** bit talks to the real Windows Firewall (via `netsh`) — so you can see what's on, toggle profiles, and manage rules. There's **file encryption** (AES-256-GCM), a **vulnerability scanner** that's CVE-aware, and a **network monitor** so you can see what's talking to what. I also added **tamper detection** (integrity checks, anomaly detection, secure boot), some **compliance and isolation** concepts for GDPR/HIPAA-minded folks, and an **MSP-style backend** (Rust server + SvelteKit dashboard) if you want to manage multiple machines. Oh, and the **AI assistant** — optional, runs against Ollama so you can get triage-style help without sending data out.

The UI is a single dashboard. Everything's in Rust where it matters. No telemetry. Your data stays on your machine.

---

## Why I'm saying "it works"

I get it — "another security app" sounds like marketing. So here's the boring truth. The firewall code really does call `netsh advfirewall`; I didn't fake it. The heavy lifting lives in 17+ Rust modules under `src-tauri/src/modules/`. There are integration tests (compliance, isolation, management, tamper detection) and Playwright E2E for the UI. You can run `npm run tauri build` and get MSI and NSIS installers, and the repo has a real user guide, API reference, and an MSP deployment guide. So when I say it works, I mean: clone it, build it, run the tests, deploy it. It's not a demo.

---

## What's coming with the full release

I'm not just polishing what's there. The release will include stuff I'm actively building right now:

**Autonomous response playbooks** — so when a threat score crosses a threshold you can one-click (or auto) isolate a process, block an IP, quarantine a file, or kill a startup item. **Attack surface dashboard** — one screen that mashes vuln scan, firewall state, running services, and open ports into a single "exposure map" with a live risk score. **Behavior-based detection** — not just signatures; think "PowerShell spawns something, then it writes persistence, then it beacons out" and flag the whole chain. **Threat timeline** — EDR-lite, per-device: what happened first, in order, so you can actually investigate. **Zero-trust app control** — allow/deny by executable hash, signer, and parent process. **Tamper protection** — lock settings behind admin + a PIN and alert if something tries to turn it off. **Audit-ready reports** — export SOC-style PDF/JSON for incidents and remediation. And a **local-first AI copilot** for "what happened and what to do next" on-device, with optional cloud assist.

There's more on the list too: compliance profiles (CIS/NIST-lite), signed rule packs, a secure key vault for the encryption keys, and a "First 10 Minutes" hardening wizard so new users can lock down their machine without reading a manual. The goal is to push this toward something you'd actually call EDR-class.

---

## Stay in the loop

SecurityPrime is coming soon. If you want to see where it's at and get notified when it launches, check the landing page:

**[aarongrace978.github.io/SecurityPrime-Coming-soon](https://aarongrace978.github.io/SecurityPrime-Coming-soon/)**

The source lives at [github.com/AaronGrace978/SecurityPrime](https://github.com/AaronGrace978/SecurityPrime) — star it, watch it, or just poke around. And if you're building something in the same spirit — serious, open, and built to work — I'd love to hear about it over at [BostonAI.io](https://bostonai.io).

— [Aaron Grace](https://github.com/AaronGrace978)
