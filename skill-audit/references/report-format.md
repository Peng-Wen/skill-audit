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
  "schema_version": "1.0",
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

`scope` is one of `user`, `project`, `plugin`, `override`, or `explicit`.

## findings.json

The same shape is used by the deterministic scan, the semantic review, and the merged report.
Only `source` and `detector` differ.

```json
{
  "schema_version": "1.0",
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
    "by_skill": {"example-skill": {"grade": "D", "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}}},
    "by_category": {"SEC": 1},
    "totals": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
  }
}
```

### Writing semantic findings

The semantic review writes `llm_findings.json` in exactly this shape with `"source": "llm"` and `"detector": "llm"` on each entry.

Requirements, because `build_report.py` validates every entry and drops the ones that do not conform:

- `rule_id` has to be one of the ids in the catalog below.
- `severity` has to be one of the five levels above.
- `skill` has to match the `name` of a skill in the inventory.
- `evidence` has to quote or closely paraphrase the actual file content that triggered the finding, so a reader can verify it.
- `file` and `line` are optional but make a finding far more useful.
- Set `confidence` to `high`, `medium`, or `low` to reflect how certain the judgment is.

Dropped entries are recorded in the report's notes, so a malformed finding is visible rather than silent.

## Rule catalog

Detector column values: `det` means the deterministic scanner finds it, `llm` means the semantic pass finds it, and `det+llm` means both contribute.

### SEC: malicious or dangerous behavior

| Rule | Severity | Detector | What it means |
| --- | --- | --- | --- |
| SEC001 | high, critical when hidden | det+llm | Text that tries to override, redirect, or manipulate the agent reading the skill. |
| SEC002 | high, critical when the hidden text gives orders | det | Content concealed from a human reader, in comments or through invisible characters. |
| SEC003 | critical | det+llm | Local data sent to an outside host, including collection endpoints and chat webhooks. |
| SEC004 | critical | det | Remote content downloaded and executed in a single step. |
| SEC005 | high, critical alongside a send or execute finding | det | Reads of credential stores, private keys, or environment secret files. |
| SEC006 | medium, high for a recognizable provider key | det | A secret value written directly into the skill's files. |
| SEC007 | medium, critical when the decoded content is dangerous | det | Encoded content that hides what the skill actually does. |
| SEC008 | high, critical for a root or home wipe | det | Commands that destroy data or force-overwrite history. |
| SEC009 | high | det | Changes that make something run outside the current task, such as startup files, scheduled jobs, or hooks. |
| SEC010 | medium, high alongside manipulation | det+llm | Instructions aimed at the agent placed outside SKILL.md, so a reviewer reading only SKILL.md misses them. |
| SEC011 | medium, high alongside network activity | det | A compiled executable bundled with the skill instead of readable source. |
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
| SPEC009 | info | det | A frontmatter key outside the spec, often a misspelling that the harness ignores without warning. |
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
| QUAL002 | low, medium when nearly identical | det+llm | Two skills competing for the same triggers. |
| QUAL003 | medium, high when unjustified | det+llm | Privileges wider than the stated purpose requires. |

## Risks that a file scan cannot answer

Three items in the OWASP Agentic Skills Top 10 are properties of the environment rather than of any skill file, so they appear as report sections rather than per-skill findings.

- Weak isolation (AST06) depends on whether the harness sandboxes execution. Check the harness configuration, not the skill.
- Missing governance (AST09) is organizational: inventory, approval, and audit logging. The inventory this audit produces is the raw material for it.
- Cross-platform reuse (AST10) matters because each harness grants tools differently, so a skill reviewed on one harness may behave differently on another.
