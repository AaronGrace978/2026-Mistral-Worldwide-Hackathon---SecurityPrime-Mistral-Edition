# Little Snitch Integration Plan (Hackathon)

SecurityPrime can integrate with Little Snitch as a network-transparency companion for macOS users.

## Why This Helps

- Adds user-verifiable outbound control for app traffic.
- Lets judges validate that SecurityPrime does not phone home unexpectedly.
- Supports a "trust through observability" story in demos.

## Integration Scope

- **Phase 1 (immediate):**
  - Add a macOS-only UI card: "Little Snitch Ready".
  - Detect if Little Snitch is installed and show setup instructions.
  - Show recommended allow/deny domains based on active SecurityPrime features.
- **Phase 2 (post-hackathon):**
  - Export a suggested rule profile for manual import.
  - Add a one-click "Open in Little Snitch" deep-link workflow where supported.
  - Correlate SecurityPrime network alerts with Little Snitch block events.

## Suggested UX

- New section under network monitoring:
  - `Little Snitch Status: Installed / Not Installed`
  - `Recommended Rules`
  - `Open Little Snitch`
- Suggested default policy:
  - Allow only required model endpoint domains.
  - Deny unknown telemetry domains by default.
  - Warn when new destination domains appear.

## Platform Notes

- Little Snitch is macOS-specific.
- SecurityPrime should keep this feature optional and clearly labeled as "macOS only".
- Windows users continue using built-in firewall and network monitor flows.

## Submission Language

Use this wording in your demo notes:

> "SecurityPrime pairs with Little Snitch on macOS for process-level outbound visibility and consent-driven network control. Users can independently verify every network destination our AI features use."
