# ADR-010: MVP Process Model — On-Demand, No Resident Daemon

**Status:** Accepted

## Context
The project is named `wardend` and earlier design docs describe a persistent systemd daemon that
the CLI talks to over a Unix socket. But the MVP scope is purely **on-demand** (`wardend scan`).
Nothing in Phase 1 needs persistence: feed updates are a systemd *timer* (ADR-007), not an
in-process scheduler, and there is no realtime monitoring yet. An always-running privileged
process is itself attack surface — which directly contradicts wardend's security mission — with
zero MVP payoff.

## Decision
For the MVP there is **no resident daemon**. `wardend scan` runs as a short-lived privileged
process (`wardend-core`) that performs the scan and exits. The `-d` in the name describes the
project's *destination*, not its current state.

The resident daemon and its Unix-socket IPC are **reserved for the future realtime phase**
(continuous file monitoring, network IDS), where persistence is genuinely required.

## Consequences
- Smallest possible attack surface in the MVP: no privileged process running between scans.
- No IPC lifecycle/auth/socket protocol to build or maintain yet.
- "Daemon" in older MVP-era docs should be read as **core** (the privileged engine).
- Privilege acquisition is per-invocation via polkit, not a long-held capability set (ADR-016).
- When realtime lands, the daemon is *added*; the on-demand path remains.
