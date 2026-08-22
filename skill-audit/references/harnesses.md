# Harness notes

Where each agent harness keeps skills, and what differs between them.
The audit searches all of these locations by default, reports which ones exist, and skips the rest.

## Default search locations

User level, applying to every project:

| Harness | Path |
| --- | --- |
| Claude Code | `~/.claude/skills` |
| Codex | `~/.codex/skills` |
| OpenCode | `$XDG_CONFIG_HOME/opencode/skills`, usually `~/.config/opencode/skills` |
| Shared convention | `~/.agents/skills` |
| OpenClaw | `~/.claw/skills` |
| Gemini CLI | `~/.gemini/skills` |
| Cursor | `~/.cursor/skills` |

Project level, relative to the working directory:

| Harness | Path |
| --- | --- |
| Claude Code | `.claude/skills` |
| Codex | `.codex/skills` |
| OpenCode | `.opencode/skills` |
| Shared convention | `.agents/skills` |
| Cursor | `.cursor/skills` |
| Generic | `skills/` |

Plugin bundles:

| Harness | Path |
| --- | --- |
| Claude Code | `~/.claude/plugins/<plugin>/skills` |

## Overriding the search

Two overrides exist, both useful for auditing something that is not installed yet.

- `--paths` on `discover_skills.py`, or the `SKILL_AUDIT_PATHS` environment variable, takes a list of roots separated by the platform path separator.
- `--skill <dir>` audits exactly one skill directory, which is the right way to vet a downloaded or cloned skill before installing it.

## Why several harnesses share directories

Many harnesses read `.claude/skills` in addition to their own directory, because the Agent Skills format started there and a large body of skills already lives at that path.
The audit deduplicates by resolved real path, so a skill reachable from several harnesses is inventoried once rather than repeatedly.
Symbolic links between harness directories are common and resolve to the same entry for the same reason.

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
