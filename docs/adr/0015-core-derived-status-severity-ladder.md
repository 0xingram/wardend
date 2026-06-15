# ADR-015: Core-Derived Status via Severity Ladder

**Status:** Accepted

## Context
ADR-005 defines the *shape* of output (a `status` per module, a narrative at the bottom) but no
*rule* for how findings become a status, nor how module statuses become the overall narrative.
Without a deterministic rule, two modules will compute status inconsistently and the narrative
becomes a vibe. For a security tool, "what makes it say FAIL" must be a spec. Worse, a plugin
that self-asserts its status could claim PASS while emitting a critical finding.

## Decision
**Status is core-derived, not plugin-asserted.** The wire `ScanResult` has **no `status`
field** — plugins emit `summary` + `findings` + `metadata` only. Core computes the module
`Status` from the highest-severity finding present, by a fixed ladder:

| Highest severity present | Status |
|---|---|
| `critical` or `high` | `FAIL` |
| `medium` | `WARN` |
| `low` / `info` only | `PASS` (with notes) |
| none | `PASS` |
| crash / timeout / bad protocol | `ERROR` |

**Overall narrative**, from module-status counts:
- any `FAIL` → "X issues need your attention." (red)
- else any `WARN` → "X things worth a look." (amber)
- else all `PASS` → "Your system looks healthy." (green)
- `ERROR` is always surfaced **prominently and separately** — a broken module must never
  silently masquerade as PASS.

## Consequences
- One auditable place defines the verdict rule; a plugin can't lie about its own status.
- The protocol is simpler (one fewer field) and harder to misuse.
- Renderer maps `Status` → traffic-light per ADR-005.
