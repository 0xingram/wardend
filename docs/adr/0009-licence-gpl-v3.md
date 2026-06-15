# ADR-009: Licence — GPL v3

**Status:** Accepted

## Context
The project is community-driven desktop Linux security tooling. It must prevent commercial forks
from closing source. Matches the ethos of existing Linux security tools (rkhunter, ClamAV, Wazuh).

## Decision
GPL v3.

## Consequences
Community contributions remain open. Commercial use is permitted but must remain GPL. The SaaS
loophole is not closed (AGPL would be required for that — deferred decision). Source files carry
the SPDX header `GPL-3.0-or-later` so the AGPL door stays openable without relicensing churn.
