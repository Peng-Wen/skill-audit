# Report format, schemas, and rule catalog

This file defines the data shapes the audit produces and the full catalog of rules.
Read it when writing semantic findings, when interpreting a report, or when performing an audit by hand because python3 is unavailable.

## Severity levels

Severity describes how much harm a finding could cause, not how confident the detector is.

- `critical`: the skill can take data off the machine, execute arbitrary code, or destroy data. Stop using it until resolved.
- `high`: the skill can reach sensitive material, keep itself running beyond a task, or manipulate the agent reading it.
- `medium`: a real problem that needs a decision, such as broad privileges or a spec violation that changes how the skill loads.
- `low`: hygiene and cost issues worth fixing but not urgent.
- `info`: observations that carry no direct risk.

## Grades

A grade summarizes a skill by its most severe finding.

- `A`: no findings.
- `B`: low findings only.
- `C`: at least one medium finding, review recommended.
- `D`: at least one high finding, review before continuing to use it.
- `F`: at least one critical finding, stop using it until resolved.

## inventory.json

Produced by `scripts/discover_skills.py`.

```json
{
  "schema_version": "1.1",
  "generated_at": "2026-08-21T00:00:00Z",
  "host": {"os": "darwin", "python": "3.13.0"},
  "search_paths": [
    {"path": "/Users/me/.claude/skills", "scope": "user", "harness": "claude", "exists": true}
  ],
  "skills": [
    {
      "id": "claude::example-skill",
      "name": "example-skill",
      "dir_name": "example-skill",
      "path": "/Users/me/.claude/skills/example-skill",
      "skill_md_path": "/Users/me/.claude/skills/example-skill/SKILL.md",
      "harness": "claude",
      "scope": "user",
      "frontmatter": {"raw": {}, "parse_ok": true, "parse_error": null},
      "body": {"chars": 1200, "lines": 60, "token_estimate": 300, "truncated": false},
      "files": [{"path_rel": "SKILL.md", "bytes": 1400, "kind": "text", "ext": ".md"}],
      "total_bytes": 1400,
      "resource_token_estimate": 0
    }
  ]
}
```

`scope` is one of `user`, `project`, `plugin`, `system`, `override`, or `explicit`.

`id` is `harness::name`, and is the stable key every later stage groups by. When
two discovered skills would produce the same id, the later one in the
deterministic sort order gets a numeric suffix (`harness::name::2`) so distinct
skills never collapse into one entry.

### Naming the harness a skill is installed for

`harness` is a slug, and every reader-facing surface prints the name that harness goes by instead, from `HARNESS_LABELS` in `scripts/skill_audit_lib.py`.
`claude` is Claude Code, `codex` is Codex, `opencode` is OpenCode, `cursor` is Cursor, `gemini` is Gemini CLI, `openclaw` is OpenClaw, and `shared` is the shared convention several harnesses read in common.
A slug outside that table prints as it stands, since discovery can be pointed at any root and a slug says more than a placeholder.
Where there is no harness to name, the scope answers instead: a directory passed with `--skill` is `Not installed`, one from `--paths` is `Custom path`, and anything else is `Unknown`.

`report.md` names it in the header breakdown, in the summary table, on every skill in "Next steps" and "Findings by skill", in the context cost table, and in the agent prompt.
`dashboard.html` names it in the masthead, on a badge on every skill card, on every step, and on every context cost row, and turns it into a filter when more than one harness is installed.
The scope qualifies the name wherever one skill needs separating from another install of itself, as in `Claude Code (plugin)` against `Claude Code (user)`.

The harness named is the one whose directory the skill was found in.
Several harnesses also read each other's skill directories, as [harnesses.md](harnesses.md) records, so a skill installed for one can load in another.
Both surfaces say so among their stated limits.

## findings.json

The same shape is used by the deterministic scan, the semantic review, and the merged report.
Only `source` and `detector` differ.

```json
{
  "schema_version": "1.1",
  "generated_at": "2026-08-21T00:00:00Z",
  "source": "deterministic",
  "findings": [
    {
      "rule_id": "SEC001",
      "category": "SEC",
      "severity": "high",
      "skill": "example-skill",
      "skill_id": "claude::example-skill",
      "file": "references/notes.md",
      "line": 42,
      "evidence": "quoted text from the file, at most 240 characters",
      "recommendation": "what to do about it",
      "detector": "deterministic",
      "owasp": ["AST01"],
      "confidence": "high"
    }
  ],
  "summary": {
    "by_skill": {"claude::example-skill": {"name": "example-skill", "grade": "D", "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}, "resolved": 0}},
    "by_category": {"SEC": 1},
    "totals": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
  }
}
```

`summary.by_skill` is keyed by `skill_id`, not by name, because two installed
skills can legitimately share a directory name across scopes and pooling them
under one name would let a clean skill inherit another's grade. Each entry
carries the display `name` and a `resolved` count of findings an adjudication
took out of grading.

A merged finding may also carry, when the semantic review adjudicated it:

- `status`: `"resolved"` when the review judged it benign and took it out of
  grading. The finding stays in the document; it just no longer counts.
- `original_severity`: the severity before a downgrade or resolution.
- `resolution`: `{"verdict", "reason", "evidence"}`, the recorded justification.

Nothing is suppressed silently. An adjudicated finding is still present, still
shows its original severity, and every adjudication is echoed in `notes`.

### Writing semantic findings

The semantic review writes `llm_findings.json` with `"source": "llm"`, a
`findings` list, and an optional `adjudications` list. Each finding carries
`"detector": "llm"`.

Requirements, because `build_report.py` validates every entry and drops the ones that do not conform:

- `rule_id` has to be one of the ids in the catalog below.
- `severity` has to be one of the five levels above.
- `skill` has to match the `name` of a skill in the inventory. When a name is
  shared across scopes it is ambiguous, so give `skill_id` instead; a name or
  id that is not in the inventory is dropped rather than turned into a phantom
  report row.
- `evidence` has to quote or closely paraphrase the actual file content that triggered the finding, so a reader can verify it. Whitespace is normalized on load.
- `file` and `line` are optional but make a finding far more useful.
- Set `confidence` to `high`, `medium`, or `low` to reflect how certain the judgment is.

Dropped entries are recorded in the report's notes, so a malformed finding is visible rather than silent.

### Adjudicating a deterministic finding

The scanner reports structure and cannot weigh context; the reading pass can.
When the review judges a deterministic finding benign, it says so in the
`adjudications` list rather than staying silent, and the finding is lowered or
resolved with the reason on record. This is the visible resolution channel for
a false positive: without it, a finding the review knows is wrong would keep
grading the skill forever.

Each adjudication is an object:

- `rule_id`, `skill` (or `skill_id`), and `file` and `line` to select which
  deterministic finding it applies to.
- `verdict`: `"downgrade"` or `"resolve"`.
- `severity`: the new, lower severity, required for a `downgrade`.
- `reason`: why, required. An adjudication without a reason is dropped.
- `evidence`: optional supporting quote.

An adjudication has to name exactly one finding.
`file` and `line` may be left out when the rule fired once for that skill, but if the selectors match more than one finding the adjudication is refused rather than applied to all of them: the same rule fires on a benign line and on a dangerous one in the same skill often enough that a broad selector would carry a real finding out of the grade alongside the false positive.
Adjudicate each line separately when several need it.

Only deterministic findings can be adjudicated, a downgrade must actually
lower the severity, and every application, refusal, and drop is written to
`notes`. A `resolve` sets `status: "resolved"` so the finding stops grading
but stays in the report.

## notes

Both `scan_findings.json` and the merged `findings.json` carry a `notes` list, and `report.md` prints it under "Method and limitations".
Notes record anything a reader needs in order to judge coverage rather than risk: a semantic entry that was dropped, a semantic adjudication that lowered or resolved a finding, an adjudication that was refused or dropped, a missing semantic findings file, or a file the scan deliberately skipped.

The scan skips one category of file: the source of the auditor that is executing, together with any file byte-identical to one of its scripts, which is what a second install of the same auditor is made of.
Its rule tables contain the literal strings it searches for, so scanning them would report the detector's own vocabulary as findings, once per installed copy.
The skipped files are listed by name in the note, the exclusion is decided by resolved path or byte equality rather than by skill name, and a file that differs from the running auditor at all is scanned in full.

## The action section and the agent prompt

`report.md` and the dashboard both carry a **Next steps** section built from the merged findings: one entry per skill that has a finding, ordered by severity, giving the decision that skill needs and, under it, every finding as a change to make with its rule, location, and recommendation.
On both surfaces it sits after the per-skill findings and before the context cost table, so the actions follow the evidence they draw on.

The decision and the edits that carry it out are the same work at two zoom levels, so they sit in one entry.
Splitting them across two sections made the reader cross-reference two lists that were ordered the same way and grouped the same way, and the per-finding half duplicated the fixes already printed under "Findings by skill".

It comes with the text to hand an agent, so a user can act on the audit without retyping it.
That text embeds evidence quoted from audited skills, which makes it an injection path by construction, so it is built with three defences: it opens by stating that everything inside the markers is data rather than instructions, the quoted content sits inside explicit `BEGIN`/`END AUDIT DATA` markers, and any text trying to write those markers or close a code block is neutralized before embedding.

When the semantic review reaches a different conclusion from the rule's generic recommendation, both are kept, the reviewer's judgment appended after the rule's.
A scanner reporting broad permissions from structure and a review finding that breadth justified is a disagreement worth showing rather than hiding, and dropping the second half would produce a fix list asking for changes nobody wants.

## dashboard.html

`scripts/build_dashboard.py` renders the merged `findings.json` as a single self-contained HTML page: severity totals, a grade per skill with its findings and evidence, the harness each skill is installed for, filters, and the context cost table.

- `--format standalone` writes a complete HTML document to open in a browser.
- `--format artifact` writes the same page without the document wrapper, for a host that supplies its own `<head>` and `<body>`.

Its action section carries a button that delivers it to an agent.
Where the host exposes a way for the page to reach the agent the button sends; otherwise it copies to the clipboard, and it is labelled with whichever it will do rather than promising a delivery the runtime cannot make.
The text is also rendered on the page, so a blocked clipboard is never a dead end.

The page loads nothing over the network and executes nothing from an audited skill.
Values taken from audited skills are embedded as escaped JSON and written into the DOM as text, never as markup, so a skill that plants a closing script tag or an event handler in its content cannot get it rendered as HTML.

## Rule catalog

Detector column values: `det` means the deterministic scanner finds it, `llm` means the semantic pass finds it, and `det+llm` means both contribute.

### SEC: malicious or dangerous behavior

| Rule | Severity | Detector | What it means |
| --- | --- | --- | --- |
| SEC001 | high, critical when hidden | det+llm | Text that tries to override, redirect, or manipulate the agent reading the skill. |
| SEC002 | high, critical when the hidden text gives orders | det | Content concealed from a human reader, in comments or through invisible characters. |
| SEC003 | critical | det+llm | Local data sent to an outside host, including collection endpoints and chat webhooks. |
| SEC004 | critical | det | Remote content downloaded and executed in a single step. |
| SEC005 | high, medium for a plain `.env` read, critical alongside a send or execute finding | det | Reads of credential stores, private keys, or environment secret files. Reading a checked-in template such as `.env.example` is the bootstrap idiom and is not flagged. |
| SEC006 | medium, high for a recognizable provider key | det | A secret value written directly into the skill's files. |
| SEC007 | medium, critical when the decoded content is dangerous | det | Encoded content that hides what the skill actually does. |
| SEC008 | graded by target: critical for a root or home wipe, high for another absolute or home-rooted path, low for a scratch or relative target, info in advisory or defensive prose | det | Commands that destroy data or force-overwrite history. Both `-rf` and `-fr` flag orders count. A line that argues against such a command, or blocks or warns about it, is advisory context and drops to info. |
| SEC009 | high | det | Changes that make something run outside the current task, such as startup files, scheduled jobs, or hooks. |
| SEC010 | medium, high alongside manipulation | det+llm | Instructions aimed at the agent placed outside SKILL.md, so a reviewer reading only SKILL.md misses them. The deterministic rule fires only when the file also carries another security signal or injection phrasing, since second-person imperatives alone are ordinary reference-file style. |
| SEC011 | medium, high alongside network activity | det | A compiled executable bundled with the skill instead of readable source, including Python bytecode caches, which Python loads in place of the source they sit beside. |
| SEC012 | high | det+llm | Behavior fetched from a remote source at run time, which can change after review. |
| SEC013 | medium, high with interpolated input | det | Dynamic evaluation of code or shell strings. |

### TRUST: supply chain and provenance

| Rule | Severity | Detector | What it means |
| --- | --- | --- | --- |
| TRUST001 | high, medium between two installed skills | det | A name one small edit away from a well-known skill, the classic typosquat shape. |
| TRUST002 | medium, high with a brand claim | det+llm | A claim of official or verified status with no provenance behind it. |
| TRUST003 | low | det | No license stated, so terms and origin are unclear. |
| TRUST004 | low, medium when the content is used as instructions | det+llm | Remote content referenced by a mutable pointer rather than a pinned version. |

### SPEC: Agent Skills format conformance

| Rule | Severity | Detector | What it means |
| --- | --- | --- | --- |
| SPEC001 | medium | det | Frontmatter is missing or cannot be parsed. |
| SPEC002 | high | det | A required field, `name` or `description`, is absent. |
| SPEC003 | high | det | The frontmatter name differs from the directory name, which the spec forbids. |
| SPEC004 | medium | det | The name breaks the character or length rules. |
| SPEC005 | medium | det | The description is empty or longer than 1024 characters. |
| SPEC006 | low | det | `compatibility` exceeds 500 characters. |
| SPEC007 | low | det | `metadata` is not a flat map of strings to strings. |
| SPEC008 | low, medium when the target is missing | det | A relative reference is broken or nested more than one level deep. |
| SPEC009 | info | det | A frontmatter key outside the portable spec. A recognized harness extension (such as `argument-hint` or `user-invocable`) is reported as harness-specific rather than as a misspelling; a genuinely unknown key is flagged as one the harness ignores without warning. |
| SPEC010 | low | det | `allowed-tools` is malformed. |

### COST: context economy

| Rule | Severity | Detector | What it means |
| --- | --- | --- | --- |
| COST001 | medium | det | The SKILL.md body exceeds about 5000 tokens, so every activation is expensive. |
| COST002 | low | det | The body exceeds 500 lines. |
| COST003 | low | det | A long description, which occupies context permanently for every session. |
| COST004 | low, medium when the skill forces a load | det | A large bundled file that costs significant context when opened. |
| COST005 | info | det | A large total bundle size. |

### QUALITY: triggering and privilege

| Rule | Severity | Detector | What it means |
| --- | --- | --- | --- |
| QUAL001 | low | llm with a deterministic prefilter | A description too vague to trigger the skill reliably. |
| QUAL002 | low, medium when nearly identical | det+llm | Two skills competing for the same triggers. Two installs sharing a name and an exact description are one skill installed twice, not a competition, and are not flagged. |
| QUAL003 | medium, high when unjustified | det+llm | Privileges wider than the stated purpose requires. |

## Risks that a file scan cannot answer

Three items in the OWASP Agentic Skills Top 10 are properties of the environment rather than of any skill file, so they appear as report sections rather than per-skill findings.

- Weak isolation (AST06) depends on whether the harness sandboxes execution. Check the harness configuration, not the skill.
- Missing governance (AST09) is organizational: inventory, approval, and audit logging. The inventory this audit produces is the raw material for it.
- Cross-platform reuse (AST10) matters because each harness grants tools differently, so a skill reviewed on one harness may behave differently on another.
