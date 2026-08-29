# What it checks

Thirty-five rules in five categories, each mapped to the relevant OWASP Agentic Skills risk.
The full catalog, with every rule id, its severity, and what triggers it, is in [report-format.md](../skill-audit/references/report-format.md#rule-catalog).

| Category | Rules | Covers |
| --- | --- | --- |
| SEC | 13 | Prompt injection, hidden text, data exfiltration, pipe-to-shell, credential access, hardcoded secrets, obfuscated payloads, destructive commands, persistence, cross-file logic splitting, bundled binaries, remote instruction loading, dynamic execution. |
| SPEC | 10 | Every constraint the Agent Skills specification places on frontmatter, plus broken and over-nested references. |
| COST | 5 | Oversized bodies, long descriptions, large bundled files, and the always-on context cost of your whole collection. |
| TRUST | 4 | Typosquatted names, brand impersonation, missing license, unpinned remote content. |
| QUAL | 3 | Vague descriptions, descriptions that collide with another skill's, and privileges wider than the stated purpose. |

Findings carry a severity from critical to info.
Each skill is then graded A through F by its worst finding, so one critical problem is an F no matter how tidy the rest of the skill is.

## Two design choices worth knowing about

**Obfuscation is decoded, not just noticed.**
Reporting that a file contains base64 is close to useless, because plenty of harmless skills embed encoded data.
The scanner decodes one level and re-runs the dangerous-pattern set on the result.
So it does not report "encoded blob found"; it reports that a blob decodes to a pipe-to-shell command, and puts the decoded text in the evidence.

**Precision is treated as a feature.**
A tool that flags ordinary skills trains you to ignore it, and an ignored security tool is worse than none.
Destructive-command severity is graded by target, so wiping the filesystem root is critical while clearing a scratch directory is low, and a line that warns against a dangerous command drops to info instead of being mistaken for it.
Persistence rules require a write context rather than a mention, so a skill about managing services is not accused of installing itself.
Reading a checked-in `.env.example` template is treated as the bootstrap idiom it is, not as credential access.
Description-length rules fire near the specification cap rather than penalizing the keyword-rich descriptions that make triggering work in the first place.
And where structure alone still misreads a skill, the reading pass can adjudicate a finding down, on the record, so a known false positive stops grading a skill without being hidden.

That is a claim the repo has to back up, so five of the thirteen eval fixtures are clean controls whose only job is to catch false positives, three of them built from the real-world idioms above.
See [evals/README.md](../evals/README.md).

## What a rule cannot see

Some real risks live outside any file scan: what tools the harness actually grants, how isolated a session is, and whether anyone approved the skill in the first place.
Those are properties of your environment rather than of a skill file, and [report-format.md](../skill-audit/references/report-format.md#risks-that-a-file-scan-cannot-answer) says so explicitly rather than pretending otherwise.
[Limitations](limitations.md) is the short version.
