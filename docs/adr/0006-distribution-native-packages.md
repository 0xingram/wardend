# ADR-006: Distribution — Native Packages Only for the Privileged Component

**Status:** Accepted

## Context
AppImage/Flatpak sandboxing conflicts with security-tool requirements: filesystem access to
`/proc`/`/sys`/`/etc`, raw socket capabilities, eBPF, rkhunter integration. A sandboxed security
tool cannot see the full system.

## Decision
The privileged component (`wardend-core`) is distributed as native packages only: AUR (primary),
`.deb`, `.rpm`. The CLI client may be an AppImage in future. The privileged component must never
be sandboxed.

## Consequences
Per-distro packaging work required. AUR is the natural first target given CachyOS/Arch origin.
Debian and RPM packages follow. See ADR-016 for the two-binary layout this distributes.
