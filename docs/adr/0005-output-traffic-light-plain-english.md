# ADR-005: Output Model — Traffic Light + Plain English + `--verbose`

**Status:** Accepted

## Context
The primary user is a non-technical Windows migrant who must understand results without security
domain knowledge. Power users (e.g. Arch users) need full technical detail.

## Decision
- Default output: `[PASS]`/`[WARN]`/`[FAIL]` per module + a plain-English summary line per
  finding + an overall narrative at the bottom.
- `--verbose`: expands findings with technical `detail` and `remediation` fields.
- `--json`: raw aggregated result JSON for scripting.

## Consequences
Two distinct audiences served from one output stream. The CLI renderer is the only layer that
changes; **core always speaks JSON internally** (see ADR-016 for the two-binary split that
preserves this). Status-to-traffic-light mapping is defined in ADR-015.
