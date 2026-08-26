# What this cannot tell you

Stated plainly, because a security tool that oversells itself is worse than none.

- **A clean report means nothing was detected, not that a skill is safe.**
  Absence of evidence is the weakest result any scanner produces, and it is the one people most want to over-read.
- **Nothing is executed, so a skill that misbehaves only at run time can still read clean.**
  This is static analysis by design. That design is what makes it safe to point at hostile content, and it is also its ceiling.
- **Sandboxing and isolation belong to your harness, not to any skill file.**
  No audit of a Markdown file changes what your agent is actually permitted to do.
- **Governance is organizational.**
  Inventory, approval, and audit logging are decisions a team makes. The inventory this produces is a starting point for that, not an answer to it.
- **The same skill can behave differently on another harness**, because each one grants tools its own way.
  [harnesses.md](../skill-audit/references/harnesses.md) covers what differs.

The audit tells you what it found and shows you the evidence.
Deciding what to do about a skill is still yours.
