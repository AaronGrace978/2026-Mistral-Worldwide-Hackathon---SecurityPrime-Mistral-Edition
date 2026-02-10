# Security Prime - User Guide

## Getting Started

Welcome to Security Prime, your comprehensive cybersecurity solution. This guide will help you get started with the desktop application.

## Installation

### System Requirements
- Windows 10/11 (64-bit)
- 4 GB RAM minimum (8 GB recommended)
- 500 MB disk space
- Internet connection for updates and MSP features

### Installing the Application

1. Download the installer from your MSP or the official website
2. Run `SecurityPrime-Setup.exe` or `SecurityPrime.msi`
3. Follow the installation wizard
4. Launch Security Prime from the Start Menu

### First Launch

On first launch, you'll be prompted to:
1. Accept the license agreement
2. Enter your license key (provided by your MSP)
3. Configure initial settings

---

## Dashboard

The dashboard provides an overview of your system's security status:

### Security Score
A 0-100 score based on:
- Threat detections
- Unresolved issues
- Scan frequency
- System updates

### Module Status
Quick view of all security modules:
- **Green**: Active and protected
- **Yellow**: Needs attention
- **Red**: Critical issues

### Recent Activity
Log of recent security events and actions.

### Quick Actions
- Run Quick Scan
- Check Vulnerabilities
- Encrypt Files
- View Settings

---

## Security Modules

### Malware Scanner

The scanner protects against malware, viruses, and other threats.

**Scan Types:**
- **Quick Scan**: Scans common threat locations (5-10 minutes)
- **Full Scan**: Comprehensive system scan (30-60 minutes)
- **Custom Scan**: Scan specific folders

**Running a Scan:**
1. Go to Scanner module
2. Select scan type
3. Click "Start Scan"
4. Review results when complete

**Handling Threats:**
- **Quarantine**: Isolate threat (recommended)
- **Delete**: Permanently remove
- **Ignore**: Allow file (use with caution)

### Firewall Manager

Control network traffic and block suspicious connections.

**Features:**
- View current firewall status
- Manage firewall rules
- See blocked connections
- Export/import rules

**Creating a Rule:**
1. Go to Firewall module
2. Click "Add Rule"
3. Configure:
   - Name
   - Direction (Inbound/Outbound)
   - Action (Allow/Block)
   - Protocol and ports
4. Save rule

### File Encryption

Protect sensitive files with AES-256 encryption.

**Encrypting Files:**
1. Go to Encryption module
2. Click "Encrypt File"
3. Select file(s) to encrypt
4. Enter a strong password
5. Confirm encryption

**Decrypting Files:**
1. Go to Encryption module
2. Select encrypted file
3. Enter the password
4. Choose destination

**Important:** Store your password securely. Lost passwords cannot be recovered.

### Network Monitor

Monitor all network connections from your computer.

**Features:**
- View active connections
- See bandwidth usage
- Identify suspicious connections
- Block connections

**Understanding the Display:**
- **Process**: Application making the connection
- **Local/Remote**: Source and destination
- **State**: Connection status
- **Data**: Bytes sent/received

### Vulnerability Scanner

Check for security weaknesses in your system.

**What It Checks:**
- Outdated software
- Missing security patches
- Insecure configurations
- Known vulnerabilities (CVEs)

**Running a Vulnerability Scan:**
1. Go to Vulnerability module
2. Click "Scan Now"
3. Review findings
4. Apply recommended fixes

### AI Security Assistant

Get intelligent security analysis powered by AI.

**Capabilities:**
- Analyze system health
- Explain threats
- Provide recommendations
- Answer security questions

**Using the Assistant:**
1. Go to AI Agent module
2. Configure Ollama connection (if needed)
3. Type your question or request
4. Review the analysis

---

## System Tray

Security Prime runs in the system tray for quick access:

- **Left-click**: Open main window
- **Right-click**: Quick menu
  - Show Window
  - Run Quick Scan
  - Check for Updates
  - Quit

---

## Settings

### General
- Theme (Dark/Light)
- Start with Windows
- Notifications
- Language

### Protection
- Real-time protection
- Scan on startup
- Automatic updates

### MSP Connection
- Server URL
- API Key
- Heartbeat interval

### Advanced
- Database location
- Log level
- Service mode

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quick Scan |
| `Ctrl+R` | Refresh |
| `Ctrl+,` | Settings |
| `Ctrl+H` | Dashboard |
| `F5` | Refresh current view |
| `Esc` | Close dialogs |

---

## Troubleshooting

### Application Won't Start
1. Check Windows Event Viewer for errors
2. Run as Administrator
3. Reinstall the application

### Scan Taking Too Long
1. Close unnecessary applications
2. Exclude large data folders
3. Try a Quick Scan instead

### Connection Issues
1. Check internet connectivity
2. Verify MSP server URL
3. Check firewall settings
4. Contact your MSP

### High CPU Usage
1. Pause real-time protection temporarily
2. Check for ongoing scans
3. Restart the service

### License Issues
1. Verify license key format (XXXX-XXXX-XXXX-XXXX)
2. Check expiration date
3. Contact your MSP

---

## Getting Help

### Self-Help Resources
- This User Guide
- In-app help (F1)
- Knowledge Base: https://kb.securityprime.io

### Contact Support
- Email: support@securityprime.io
- Portal: https://support.securityprime.io
- Contact your MSP administrator

### Reporting Issues
When reporting issues, include:
- Application version
- Windows version
- Steps to reproduce
- Screenshots if applicable
- Error messages

---

## Privacy & Data

### What We Collect
- System information (OS, hardware)
- Security events and threats
- Application usage statistics

### What We Don't Collect
- Personal files
- Browsing history
- Passwords
- Financial information

### Data Storage
- Local data: SQLite database in AppData
- MSP data: Transmitted securely to MSP server
- All data encrypted in transit (TLS)

---

## Updates

Security Prime automatically checks for updates. When an update is available:

1. Notification appears in system tray
2. Click to review update details
3. Click "Install Update"
4. Application restarts automatically

To check manually:
1. Go to Settings
2. Click "Check for Updates"
