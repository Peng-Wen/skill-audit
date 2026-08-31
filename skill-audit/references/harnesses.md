# Harness notes

Where each agent harness keeps skills, and what differs between them.
The audit searches all of these locations by default, reports which ones exist, and skips the rest.

## Default search locations

User level, applying to every project:

| Harness | Path |
| --- | --- |
| Claude Code | `$CLAUDE_CONFIG_DIR/skills`, default `~/.claude/skills` |
| Codex | `$CODEX_HOME/skills`, default `~/.codex/skills` |
| OpenCode | `$XDG_CONFIG_HOME/opencode/skills`, usually `~/.config/opencode/skills` |
| Shared convention | `~/.agents/skills`, plus `$XDG_CONFIG_HOME/agents/skills` (where the skills CLI installs its global scope) |
| OpenClaw | `$OPENCLAW_STATE_DIR/skills`, default `~/.openclaw/skills`, plus the former `~/.clawdbot/skills` |
| Gemini CLI | `~/.gemini/skills` |
| Cursor | `~/.cursor/skills` |

When `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, or `OPENCLAW_STATE_DIR` is set, the default location is searched as well as the override: skills installed before a move can still sit there, and an audit should surface them rather than assume the move was clean.
`~/.clawdbot` is searched for the same reason.
It is OpenClaw's former state directory, and OpenClaw still falls back to it when `~/.openclaw` is absent.

System level:

| Harness | Path |
| --- | --- |
| Codex | `/etc/codex/skills`, the administrator-managed location Codex documents |

Project level, relative to the working directory:

| Harness | Path |
| --- | --- |
| Claude Code | `.claude/skills` |
| Codex | `.codex/skills` |
| OpenCode | `.opencode/skills` |
| Shared convention | `.agents/skills` |
| Cursor | `.cursor/skills` |
| Gemini CLI | `.gemini/skills` |
| Generic | `skills/` (checked in the working directory only) |

The dot-prefixed project directories are also checked in every parent of the working directory up to the repository root.
Codex documents exactly that scan for `.agents/skills`, and a skill sitting in any parent loads for whoever launches there, so the audit walks the same span.
Ancestor entries appear in the search-path list only when the directory exists, and the walk stops at the repository root, the home directory, or ten levels, whichever comes first.

OpenClaw is the exception to "relative to the working directory".
Each of its agents has a workspace of its own, usually somewhere under the state directory rather than under the directory a session was launched from, and `<workspace>/skills` outranks every user-level root OpenClaw reads.
The audit resolves the default workspace the way OpenClaw does, from `OPENCLAW_WORKSPACE_DIR`, then `OPENCLAW_PROFILE` (which names `<state dir>/workspace-<profile>`), then `<state dir>/workspace`, and searches `skills` and `.agents/skills` beneath it.
Additional agents take their workspaces from `openclaw.json`, which the audit does not parse, so state-directory siblings named `workspace*` are picked up from disk when they exist.
A workspace configured somewhere else entirely is reachable with `--paths`.

Plugin bundles:

| Harness | Path |
| --- | --- |
| Claude Code | `~/.claude/plugins` (walked in full) |
| OpenClaw | `~/.openclaw/plugin-skills` (`$OPENCLAW_STATE_DIR/plugin-skills` under an override) |

OpenClaw materializes the skills its plugins ship into `plugin-skills`, a directory it owns outright and rewrites, separate from the managed skills a user installs into `skills`.
It loads both, so the audit reports both, and `plugin-skills` carries the plugin scope for the same reason the Claude Code cache does.

The Claude Code plugin cache has carried several layouts, and a marketplace
plugin nests its skills several directories down, at
`~/.claude/plugins/marketplaces/<marketplace>/plugins/<plugin>/skills/<skill>`,
with external plugins under an `external_plugins/` sibling. Rather than encode
one shape, the audit walks the whole `~/.claude/plugins` root and reports every
skill it finds there, including cached-but-disabled plugins: the cache is what
the harness loads from, so a skill sitting in it is one toggle away from live.

## Overriding the search

Two overrides exist, both useful for auditing something that is not installed yet.

- `--paths` on `discover_skills.py`, or the `SKILL_AUDIT_PATHS` environment variable, takes a list of roots separated by the platform path separator.
- `--skill <dir>` audits exactly one skill directory, which is the right way to vet a downloaded or cloned skill before installing it.

## Why several harnesses share directories

Many harnesses read more than their own directory.
OpenCode documents that it also loads `.claude/skills`, `~/.claude/skills`, `.agents/skills`, and `~/.agents/skills`, and Codex's current documentation centers on the shared `.agents/skills` convention rather than a private directory.
Gemini CLI treats `.agents/skills` and `~/.agents/skills` as aliases of its own two directories, and OpenClaw reads `~/.agents/skills` as personal agent skills alongside its managed directory.
The Agent Skills format started under `.claude/skills`, so a large body of skills lives at that path whatever harness reads it.
The audit deduplicates by resolved real path, so a skill reachable from several harnesses is inventoried once rather than repeatedly.
Symbolic links between harness directories are common and resolve to the same entry for the same reason.

## Delivering the result on each harness

The audit always writes `report.md` and `findings.json`. The interactive summary is one self-contained HTML page, and the harness decides only how that page reaches the user.

| Harness | `build_dashboard.py --format` | Delivery |
| --- | --- | --- |
| Claude, Claude Code, Claude Cowork | `artifact` | Publish the page as an artifact; hand the user the link. |
| ChatGPT, Codex | `standalone` | Write the file; hand the user the path to open. |
| OpenCode, Gemini CLI, Cursor, OpenClaw, anything else | `standalone` | Same as above. |

Test capability rather than the harness name: a session that can publish an artifact should get `artifact`, and everything else gets a file that opens in any browser.

The two formats differ only in the document wrapper. `artifact` omits `<!doctype>`, `<html>`, `<head>`, and `<body>` for a host that supplies its own; `standalone` is a complete document.
Neither loads anything over the network, which matters for an audit tool: a page that fetched a font or a script from a remote host would contradict the guarantee the audit itself makes.

## Cross-platform reuse, and why it matters for a security review

The Agent Skills format is portable, but the security context around it is not.
This is the risk OWASP records as AST10.

- Tool permissions are granted per harness. The `allowed-tools` field is explicitly experimental in the spec and support for it varies, so a skill constrained on one harness may be unconstrained on another.
- Some harnesses execute skill scripts inside a sandbox or container while others run them directly on the host, which changes the impact of the same file entirely.
- Approval prompts differ. A harness that asks before each shell command gives a user the chance to stop something that runs unattended elsewhere.

A finding's severity in this report reflects what the skill content makes possible, not what a particular harness would permit.
The harness a skill actually runs under determines whether that possibility is realized.

## Practical checks that live outside a file scan

These cannot be determined by reading skill files, so they belong to a review of the environment.

- Whether skill scripts execute in an isolated environment or directly on the host.
- Which tools the harness exposes by default, and whether a skill can widen that set.
- Whether skill installs and updates are recorded anywhere, so a change can be noticed after the fact.
- Whether an approval step exists before a skill becomes available to a whole team.
