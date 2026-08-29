# Why audit your skills

Skills install as plain Markdown from public repositories, usually with no signing, no sandbox, and no review.
Your agent then reads them as instructions.
The published research on what that means is not reassuring.

- Snyk's [ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) scanned 3,984 skills across ClawHub and skills.sh as of 5 February 2026: 36.8% carried at least one flaw and 13.4% carried something critical, including malware, prompt injection, and exposed secrets.
- The [ClawHavoc campaign](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) placed at least 341 malicious skills in a single registry, using typosquatted names, credential exfiltration to webhooks, and behavior split across files so that a benign-looking SKILL.md hid the real payload. Follow-up reporting put the count past 800 as the sweep continued.
- OWASP now publishes an [Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/), and every rule in this skill maps onto one of its categories.

These figures are current as of the dates above; treat every count as a floor rather than a total, since the registries and the sweeps against them are both still moving.

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
