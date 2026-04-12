# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->


## Build & Test

```bash
zig build          # build library
zig build test     # run tests (cert-dependent tests skipped if no certs dir resolved)
```

### wolfSSL test certificates

22 TLS and x509 tests require wolfSSL's certificate files (in the wolfSSL source tree
under `certs/`). The build resolves the source tree and certs directory automatically.

**wolfSSL source tree** — resolved in priority order:
1. `-Dwolfssl-src=<path>` build option
2. `WOLFSSL_SRC` environment variable
3. pkg-config `pcfiledir` heuristic (for uninstalled source builds only)

**wolfSSL certs directory** — resolved in priority order:
1. `-Dwolfssl-certs-dir=<path>` build option (overrides everything)
2. `WOLFSSL_CERTS_DIR` environment variable
3. `$wolfssl_src/certs/` derived from the source tree above
4. `$(pkg-config --variable=prefix wolfssl)/share/wolfssl/certs/` (if it exists)

Typical usage when you have a wolfSSL source checkout:
```bash
# Using the source tree (certs derived automatically)
zig build test -Dwolfssl-src=/path/to/wolfssl

# Or via environment variable
export WOLFSSL_SRC=/path/to/wolfssl
zig build test
```

If none of the above resolves, the build still succeeds — cert-dependent tests
fail at runtime with a file-not-found error rather than aborting the build.

## Architecture Overview

_Add a brief overview of your project architecture_

## Conventions & Patterns

_Add your project-specific conventions here_
