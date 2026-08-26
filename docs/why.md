# Why audit your skills

Skills install as plain Markdown from public repositories, usually with no signing, no sandbox, and no review.
Your agent then reads them as instructions.
The published research on what that means is not reassuring.

- A February 2026 Snyk study scanned 3,984 skills across ClawHub and skills.sh: 36.8% carried at least one flaw and 13.4% carried something critical, including malware, prompt injection, and exposed secrets.
- The ClawHavoc campaign placed 341 malicious skills in a single registry, using typosquatted names, credential exfiltration to webhooks, and behavior split across files so that a benign-looking SKILL.md hid the real payload.
- OWASP now publishes an Agentic Skills Top 10, and every rule in this skill maps onto one of its categories.

One finding shapes the whole design.

**Pattern matching alone misses most of the critical cases**, because the dangerous instructions are written in ordinary prose rather than in code.
A regular expression finds `curl | sh`.
It does not find a paragraph that politely asks the agent to read your SSH key "for context" before it continues.

So the audit runs in two layers, and the reading layer is not optional.
See [How it works](how-it-works.md).

## The quieter cost

There is a second problem that has nothing to do with malice.

Every installed skill keeps its name and description in your context permanently, whether you use it or not.
Twenty skills with generous descriptions is a standing tax on every session, paid before you type anything.
Most people have never seen that number.
The report puts one on it, per skill and in total.

A vague description is worse than a tax.
It either fails to trigger when you need it, or triggers on work it has no business touching.
Both are graded here, because a skill that intrudes on unrelated sessions has a real cost even when it is completely benign.
