# protosource-auth v2 Implementation Plan

**Status**: Active. **Tracking has moved to beads.** Design rationale and open decisions live in [V2_FEDERATION.md](./V2_FEDERATION.md).

## Quick resume after compaction or new session (low token cost)

```bash
bd prime
bd ready                 # shows immediately actionable work with no blockers
bd show protosource-auth-miy   # root epic with full mission, invariants, current snapshot, key files, verification gates, risks
bd memories v2           # the 7 compact "v2:..." facts (mission, invariants, current-phase, key-files, risks, verification, open-design)
bd list --status=open
bd stats
```

See the root epic **DESCRIPTION** (mission), **DESIGN** (invariants + open design calls + risks), and **NOTES** (current state snapshot as of migration, key files, next, verification gates). Historical session details are in the closed child issues + their close reasons.

All prior checklists, detailed task breakdowns, per-session "what we landed", and the long resume summary have been migrated into structured beads issues (with dependencies, priorities, acceptance criteria, design/notes fields).

## Beads structure (as of migration 2026-06-08)

- **protosource-auth-miy** (epic, P0): root for the entire V2 arc. See `bd show` for everything needed to resume.
- Closed (foundation, captured so future sessions don't re-read history):
  - miy.1 Phase 1 core: Issuer OIDCConfig proto + configurator + tests + minimal UI + generator bridge
  - miy.2 Prep: dep bump v0.6.1 + cookie config + discovery stub + real JWKS
- Open / in progress (use `bd ready`, `bd update <id> --claim` when starting):
  - miy.3 (P2): Remaining Phase 1 minimal (mgr external register, fuller frontend OIDC forms)
  - miy.7 (P1): Phase 3 PKCE handlers + signed state cookie + IdP exchange (the main next slice)
  - miy.4 (P2): Phase 2 User LinkedIdentity + JIT (depends on Phase 1 core)
  - miy.6 (P2): Access JWT delivery + authorizer evolution (depends on PKCE)
  - miy.10 (P2): Tests, verification gates, and e2e (depends on PKCE)
  - miy.5 (P3): Evolve loginpage + frontend IdP picker (depends on PKCE)
  - miy.8 (P3): Docs, examples, positioning (depends on PKCE)
  - miy.9 (P4): Mgr CLI external issuer registration (depends on remaining Phase 1 + PKCE)

Dependencies express sequencing (`bd dep add`, visible in `bd show` and `bd blocked`).

## Workflow (per project rules + bd prime)

- Create issues before coding (`bd create ... --parent protosource-auth-miy`).
- Claim: `bd update <id> --claim`
- Close with reason when done: `bd close <id> --reason="..."`
- End of every session: follow the full close protocol (git status/add/commit/push). Beads data (embedded Dolt + auto-exported issues.jsonl) goes with the push.
- Cross-session knowledge: `bd remember "v2:..."` (searchable via `bd memories v2`); never use markdown TODO/MEMORY files for this.

## Original large content

The previous ~8600-token version of this file (with full per-phase checklists, historical narrative from 2026-06 sessions, repeated sections, etc.) has been archived as `V2_IMPLEMENTATION_PLAN.md.pre-beads-migration`. It is no longer needed for day-to-day work or context restoration. The beads epic + children + memories are the live source of truth for tasks and resume state (per AGENTS.md / CLAUDE.md: use bd for ALL task tracking).

## References

- Design + open decisions: V2_FEDERATION.md
- Live work: `bd ready`, `bd show protosource-auth-miy`, `bd memories v2`
- Full project bd context: `bd prime`
- Code exploration: resolve_repo first (jcodemunch), then native reads for .md files.

This plan is living in beads — update issues as you implement.
