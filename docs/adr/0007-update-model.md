# ADR-007: Update Model — Feeds via Systemd Timer, Tool via Package Manager

**Status:** Accepted

## Context
Threat-intel feeds must stay current. Tool self-updating is a security antipattern (the update
mechanism becomes attack surface).

## Decision
- Threat-intel feeds (ClamAV CVD, YARA, NVD CVE, abuse.ch, etc.) updated via a systemd timer,
  daily, stored under `/var/lib/wardend/feeds/`.
- The wardend binaries are updated exclusively via the distro package manager (pacman, apt, dnf).
- A self-update mechanism is explicitly prohibited.

## Consequences
Clean separation of data updates vs. code updates. The package manager is the trusted update
path for code. The systemd timer also covers the "scheduled scanning" interim need without a
resident daemon (see ADR-010).
