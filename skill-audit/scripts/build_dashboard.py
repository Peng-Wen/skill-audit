#!/usr/bin/env python3
"""Render the audit result as an interactive, self-contained dashboard.

report.md carries the full detail. This produces the companion a person
actually scans: grades and severities at a glance, filters, and evidence one
click away.

The page makes no network requests of any kind. An audit tool that promises it
never contacts a remote host has no business shipping a page that fetches a
font from one, so the type is system stacks and every byte is inline.

Two output shapes, because the harness the audit ran in decides how the result
is delivered:

  standalone  A complete HTML document, for opening in a browser.
  artifact    The same page without the document wrapper, for a harness that
              supplies its own <head>, such as a Claude artifact.

Usage:
  python3 build_dashboard.py --findings skill-audit-report/findings.json \
      --inventory skill-audit-work/inventory.json \
      --out skill-audit-report/dashboard.html --format standalone
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_audit_lib import (  # noqa: E402
    RULES,
    SEVERITIES,
    build_agent_prompt,
    build_fix_plan,
    build_next_steps,
    iso_now,
    read_json,
    severity_rank,
)

GRADE_MEANING = {
    "A": "no findings",
    "B": "minor issues only",
    "C": "review recommended",
    "D": "serious issues, review before continuing to use",
    "F": "critical issues, stop using until resolved",
}

GRADE_ORDER = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}


def build_data(findings_doc, inventory, title):
    """Reshape the merged findings and inventory into what the page renders."""
    findings = findings_doc.get("findings", [])
    summary = findings_doc.get("summary", {})
    cost = findings_doc.get("context_cost", {})

    paths = {}
    file_counts = {}
    for skill in (inventory or {}).get("skills", []):
        paths[skill["name"]] = skill.get("path")
        file_counts[skill["name"]] = len(skill.get("files", []))

    cost_rows = {row["skill"]: row for row in cost.get("rows", [])}

    grouped = {}
    for f in findings:
        grouped.setdefault(f["skill"], []).append(f)

    skills = []
    for name, info in summary.get("by_skill", {}).items():
        row = cost_rows.get(name, {})
        entries = sorted(grouped.get(name, []),
                         key=lambda f: (-severity_rank(f["severity"]), f["rule_id"]))
        skills.append({
            "name": name,
            "grade": info.get("grade", "A"),
            "counts": info.get("counts", {}),
            "harness": row.get("harness", "unknown"),
            "path": paths.get(name),
            "files": file_counts.get(name),
            "always_on_tokens": row.get("always_on_tokens", 0),
            "body_tokens": row.get("body_tokens", 0),
            "resource_tokens": row.get("resource_tokens", 0),
            "findings": [{
                "rule_id": f["rule_id"],
                "title": RULES.get(f["rule_id"], {}).get("title", f["rule_id"]),
                "category": f.get("category", ""),
                "severity": f["severity"],
                "file": f.get("file"),
                "line": f.get("line"),
                "evidence": f.get("evidence", ""),
                "recommendation": f.get("recommendation", ""),
                "detector": f.get("detector", ""),
                "owasp": f.get("owasp") or [],
                "confidence": f.get("confidence", ""),
            } for f in entries],
        })

    skills.sort(key=lambda s: (GRADE_ORDER.get(s["grade"], 5), s["name"]))

    steps = build_next_steps(findings, summary)
    plan = build_fix_plan(findings)

    return {
        "title": title,
        "generated_at": iso_now(),
        "totals": summary.get("totals", {sev: 0 for sev in SEVERITIES}),
        "always_on_total": cost.get("always_on_total", 0),
        "skill_count": len(skills),
        "skills": skills,
        "notes": findings_doc.get("notes") or [],
        "next_steps": steps,
        "fix_plan": plan,
        "prompts": {
            "next-steps": build_agent_prompt("next-steps", steps, None, len(skills)),
            "fixes": build_agent_prompt("fixes", None, plan, len(skills)),
        },
    }


def embed_json(data):
    """Serialize for embedding in a script tag with no way out of it.

    Evidence strings are quoted from audited skills, which is exactly the
    content most likely to contain a closing script tag on purpose. Escaping
    the characters that could end the element early, or break a JavaScript
    string, keeps the payload data no matter what a skill put in its files.
    """
    text = json.dumps(data, ensure_ascii=False, sort_keys=False)
    return (text.replace("&", "\\u0026")
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace(u"\u2028", "\\u2028")
                .replace(u"\u2029", "\\u2029"))


def escape_html(text):
    return (str(text).replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))


STYLE = """
:root {
  color-scheme: light dark;
  /* Neutrals carry a slight blue bias so the page reads as an instrument
     rather than as unstyled default grey. */
  --ground: #f4f6f9;
  --surface: #ffffff;
  --surface-sunk: #eef1f6;
  --line: #d7dde6;
  --line-soft: #e6eaf1;
  --text: #151a23;
  --text-muted: #5b6575;
  --accent: #33408c;
  --critical: #a81f16;
  --high: #a2570a;
  --medium: #7c6413;
  --low: #35637a;
  --info: #4d5768;
  --clean: #2c6549;
  --shadow: 0 1px 2px rgba(20, 26, 38, .06), 0 8px 24px -16px rgba(20, 26, 38, .28);
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground: #0e1117;
    --surface: #161b24;
    --surface-sunk: #1c222d;
    --line: #2a323f;
    --line-soft: #222933;
    --text: #e4e8ef;
    --text-muted: #96a0b1;
    --accent: #94a0e8;
    --critical: #f08a82;
    --high: #e5a85f;
    --medium: #d3bb64;
    --low: #85b6cb;
    --info: #9aa4b4;
    --clean: #7cc49f;
    --shadow: 0 1px 2px rgba(0, 0, 0, .4), 0 8px 24px -18px rgba(0, 0, 0, .8);
  }
}
:root[data-theme="dark"] {
  --ground: #0e1117;
  --surface: #161b24;
  --surface-sunk: #1c222d;
  --line: #2a323f;
  --line-soft: #222933;
  --text: #e4e8ef;
  --text-muted: #96a0b1;
  --accent: #94a0e8;
  --critical: #f08a82;
  --high: #e5a85f;
  --medium: #d3bb64;
  --low: #85b6cb;
  --info: #9aa4b4;
  --clean: #7cc49f;
  --shadow: 0 1px 2px rgba(0, 0, 0, .4), 0 8px 24px -18px rgba(0, 0, 0, .8);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--ground);
  color: var(--text);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}

.wrap {
  max-width: 1080px;
  margin: 0 auto;
  padding: 40px 24px 72px;
  display: flex;
  flex-direction: column;
  gap: 34px;
}

.eyebrow {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin: 0;
}

h1 {
  font-family: var(--mono);
  font-size: clamp(24px, 4vw, 33px);
  font-weight: 700;
  letter-spacing: -.01em;
  text-wrap: balance;
  margin: 6px 0 0;
}

h2 {
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .13em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin: 0 0 14px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--line);
}

.masthead .verdict {
  margin: 14px 0 0;
  font-size: 17px;
  max-width: 64ch;
  text-wrap: pretty;
}
.masthead .meta {
  margin: 10px 0 0;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

/* Severity gauge ------------------------------------------------------- */

.gauge {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(128px, 1fr));
  gap: 10px;
}
.tile {
  appearance: none;
  text-align: left;
  cursor: pointer;
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid var(--sev, var(--info));
  border-radius: 6px;
  padding: 12px 14px;
  color: inherit;
  font: inherit;
  box-shadow: var(--shadow);
  transition: transform .12s ease, border-color .12s ease;
}
.tile:hover { transform: translateY(-1px); }
.tile[aria-pressed="true"] {
  border-color: var(--sev, var(--accent));
  background: var(--surface-sunk);
}
.tile .n {
  display: block;
  font-family: var(--mono);
  font-size: 26px;
  font-weight: 700;
  line-height: 1.1;
  font-variant-numeric: tabular-nums;
  color: var(--sev, var(--text));
}
.tile .k {
  display: block;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-top: 2px;
}
.tile.is-zero .n { color: var(--text-muted); opacity: .5; }

/* Controls ------------------------------------------------------------- */

.controls {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  margin-bottom: 14px;
}
.controls input[type="search"] {
  flex: 1 1 220px;
  min-width: 0;
  font-family: var(--mono);
  font-size: 13px;
  padding: 8px 11px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: var(--surface);
  color: var(--text);
}
.controls input[type="search"]::placeholder { color: var(--text-muted); }
.btn {
  appearance: none;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .1em;
  text-transform: uppercase;
  padding: 8px 12px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: var(--surface);
  color: var(--text-muted);
}
.btn:hover { color: var(--text); border-color: var(--accent); }
.count-note {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 4px;
}

/* Skill roster --------------------------------------------------------- */

.roster { display: flex; flex-direction: column; gap: 12px; }

.skill {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: var(--shadow);
  overflow: hidden;
}
.skill > summary {
  cursor: pointer;
  list-style: none;
  padding: 14px 16px;
  display: grid;
  grid-template-columns: 44px 1fr auto;
  gap: 14px;
  align-items: center;
}
.skill > summary::-webkit-details-marker { display: none; }
.skill > summary:hover { background: var(--surface-sunk); }

.grade {
  font-family: var(--mono);
  font-size: 20px;
  font-weight: 700;
  width: 44px;
  height: 44px;
  display: grid;
  place-items: center;
  border-radius: 6px;
  border: 1px solid var(--sev, var(--line));
  color: var(--sev, var(--text));
  background: var(--surface-sunk);
}

.skill-name {
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 700;
  overflow-wrap: anywhere;
}
.skill-sub {
  font-family: var(--mono);
  font-size: 11.5px;
  color: var(--text-muted);
  margin-top: 3px;
  overflow-wrap: anywhere;
}

.pills { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
.pill {
  font-family: var(--mono);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--sev, var(--line));
  color: var(--sev, var(--text-muted));
  white-space: nowrap;
}
.pill.plain { border-color: var(--line); color: var(--text-muted); }

.findings { border-top: 1px solid var(--line-soft); }

.finding {
  padding: 14px 16px 14px 19px;
  border-left: 3px solid var(--sev, var(--info));
  border-top: 1px solid var(--line-soft);
}
.finding:first-child { border-top: none; }
.finding-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 8px;
  font-family: var(--mono);
  font-size: 12px;
}
.sev {
  font-weight: 700;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--sev, var(--text));
}
.rule { font-weight: 700; }
.where { color: var(--text-muted); overflow-wrap: anywhere; }
.finding-title { margin-top: 3px; font-size: 14px; }

.evidence {
  margin: 10px 0 0;
  padding: 10px 12px;
  background: var(--surface-sunk);
  border-radius: 6px;
  font-family: var(--mono);
  font-size: 12.5px;
  line-height: 1.5;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  color: var(--text);
}
.fix { margin: 10px 0 0; font-size: 14px; max-width: 74ch; text-wrap: pretty; }
.fix b {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 700;
}
.tags { margin-top: 9px; display: flex; gap: 6px; flex-wrap: wrap; }
.tag {
  font-family: var(--mono);
  font-size: 10.5px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--text-muted);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 1px 6px;
}
.clean-line {
  padding: 14px 16px;
  border-top: 1px solid var(--line-soft);
  font-size: 14px;
  color: var(--text-muted);
  max-width: 78ch;
}

/* Context cost --------------------------------------------------------- */

.cost { display: flex; flex-direction: column; gap: 14px; }
.cost-headline { display: flex; flex-direction: column; gap: 2px; }
.cost-headline .big {
  font-family: var(--mono);
  font-size: clamp(28px, 5vw, 38px);
  font-weight: 700;
  line-height: 1.05;
  color: var(--accent);
  font-variant-numeric: tabular-nums;
}
.cost-note { margin: 6px 0 0; font-size: 14px; max-width: 74ch; text-wrap: pretty; }
.cost-rows { display: flex; flex-direction: column; gap: 7px; }
.cost-row {
  display: grid;
  grid-template-columns: minmax(120px, 1.1fr) 3fr minmax(150px, auto);
  gap: 12px;
  align-items: center;
  font-family: var(--mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.cost-row .label { overflow-wrap: anywhere; }
.bar {
  height: 9px;
  background: var(--surface-sunk);
  border-radius: 999px;
  overflow: hidden;
  border: 1px solid var(--line-soft);
}
.bar span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
.cost-row .n { text-align: right; color: var(--text-muted); }

/* Action sections ------------------------------------------------------ */

.section-head {
  display: flex;
  align-items: baseline;
  gap: 12px;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--line);
  padding-bottom: 8px;
  margin-bottom: 14px;
}
.section-head h2 { border: none; padding: 0; margin: 0; flex: 1 1 auto; }
.send {
  appearance: none;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .1em;
  text-transform: uppercase;
  padding: 7px 13px;
  border-radius: 6px;
  border: 1px solid var(--accent);
  background: var(--accent);
  color: var(--surface);
  font-weight: 700;
}
.send:hover { filter: brightness(1.08); }
.send:disabled { opacity: .5; cursor: default; }
.send-status {
  font-family: var(--mono);
  font-size: 11.5px;
  color: var(--text-muted);
}

.steps { display: flex; flex-direction: column; gap: 8px; margin: 0; padding: 0; list-style: none; }
.step {
  display: grid;
  grid-template-columns: 26px 1fr;
  gap: 12px;
  align-items: baseline;
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid var(--sev, var(--info));
  border-radius: 6px;
  padding: 11px 14px;
}
.step .idx {
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 700;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}
.step .who { font-family: var(--mono); font-weight: 700; font-size: 14px; overflow-wrap: anywhere; }
.step .what { margin-top: 2px; font-size: 14px; max-width: 76ch; text-wrap: pretty; }
.step .tagline {
  margin-top: 5px;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--sev, var(--text-muted));
}

.fixgroups { display: flex; flex-direction: column; gap: 12px; }
.fixgroup {
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid var(--sev, var(--info));
  border-radius: 6px;
  padding: 12px 14px;
}
.fixgroup h3 {
  margin: 0 0 8px;
  font-family: var(--mono);
  font-size: 14px;
  font-weight: 700;
  overflow-wrap: anywhere;
}
.fixgroup ul { margin: 0; padding-left: 16px; display: flex; flex-direction: column; gap: 7px; }
.fixgroup li { font-size: 14px; max-width: 78ch; text-wrap: pretty; }
.fixgroup code {
  font-family: var(--mono);
  font-size: 12px;
  background: var(--surface-sunk);
  border-radius: 4px;
  padding: 1px 5px;
}

.prompt-peek { margin-top: 12px; }
.prompt-peek > summary {
  cursor: pointer;
  font-family: var(--mono);
  font-size: 11.5px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--text-muted);
}
.prompt-peek > summary:hover { color: var(--text); }
.prompt-peek pre {
  margin: 10px 0 0;
  padding: 12px;
  background: var(--surface-sunk);
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 320px;
  overflow-y: auto;
}
.nothing-to-do { font-size: 14px; color: var(--text-muted); max-width: 74ch; }

/* Footer --------------------------------------------------------------- */

.notes { display: flex; flex-direction: column; gap: 24px; }
.notes ul { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 7px; }
.notes li { max-width: 80ch; text-wrap: pretty; }
.legend {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 8px;
  font-size: 13.5px;
}
.legend div { display: flex; gap: 9px; align-items: baseline; }
.legend b {
  font-family: var(--mono);
  color: var(--sev, var(--text));
  border: 1px solid var(--sev, var(--line));
  border-radius: 4px;
  padding: 0 6px;
}
.colophon {
  font-family: var(--mono);
  font-size: 11.5px;
  line-height: 1.6;
  color: var(--text-muted);
  border-top: 1px solid var(--line);
  padding-top: 16px;
  margin: 0;
  max-width: 80ch;
}

.empty {
  padding: 22px 16px;
  text-align: center;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 13px;
  border: 1px dashed var(--line);
  border-radius: 8px;
}

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
@media (max-width: 640px) {
  .wrap { padding: 28px 16px 56px; }
  .skill > summary { grid-template-columns: 40px 1fr; }
  .pills { grid-column: 1 / -1; justify-content: flex-start; }
  .cost-row { grid-template-columns: 1fr; gap: 3px; }
  .cost-row .n { text-align: left; }
}
"""


BODY = """
<div class="wrap">
  <header class="masthead">
    <p class="eyebrow">Agent Skills &middot; static audit</p>
    <h1 id="page-title"></h1>
    <p class="verdict" id="verdict"></p>
    <p class="meta" id="meta"></p>
  </header>

  <section aria-labelledby="gauge-h">
    <h2 id="gauge-h">Findings by severity</h2>
    <div class="gauge" id="gauge"></div>
  </section>

  <section aria-labelledby="steps-h">
    <div class="section-head">
      <h2 id="steps-h">Next steps</h2>
      <button class="send" id="send-steps" type="button"></button>
      <span class="send-status" id="status-steps" role="status" aria-live="polite"></span>
    </div>
    <ol class="steps" id="steps"></ol>
    <details class="prompt-peek" id="peek-steps">
      <summary>Show the exact text</summary>
      <pre id="prompt-steps"></pre>
    </details>
  </section>

  <section aria-labelledby="roster-h">
    <h2 id="roster-h">Skills, worst first</h2>
    <div class="controls">
      <input type="search" id="q" placeholder="filter by skill, rule, file, or evidence"
             aria-label="Filter skills and findings">
      <button class="btn" id="toggle-all" type="button">Expand all</button>
      <button class="btn" id="reset" type="button">Reset</button>
      <span class="count-note" id="count-note"></span>
    </div>
    <div class="roster" id="roster"></div>
  </section>

  <section aria-labelledby="fixes-h">
    <div class="section-head">
      <h2 id="fixes-h">Suggested fixes</h2>
      <button class="send" id="send-fixes" type="button"></button>
      <span class="send-status" id="status-fixes" role="status" aria-live="polite"></span>
    </div>
    <div class="fixgroups" id="fixgroups"></div>
    <details class="prompt-peek" id="peek-fixes">
      <summary>Show the exact text</summary>
      <pre id="prompt-fixes"></pre>
    </details>
  </section>

  <section aria-labelledby="cost-h">
    <h2 id="cost-h">Context cost</h2>
    <div class="cost">
      <div class="cost-headline">
        <span class="big" id="cost-big"></span>
        <span class="eyebrow" id="cost-label"></span>
      </div>
      <p class="cost-note" id="cost-note"></p>
      <div class="cost-rows" id="cost-rows"></div>
    </div>
  </section>

  <section class="notes" aria-labelledby="method-h">
    <h2 id="method-h">Grades, method, and limits</h2>
    <div class="legend" id="legend"></div>
    <ul id="limits"></ul>
    <div id="run-notes"></div>
    <p class="colophon" id="colophon"></p>
  </section>
</div>
"""


SCRIPT = r"""
(function () {
  var data = JSON.parse(document.getElementById("audit-data").textContent);

  var SEV = ["critical", "high", "medium", "low", "info"];
  var SEV_VAR = {
    critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)",
    low: "var(--low)", info: "var(--info)"
  };
  var GRADE_VAR = {
    A: "var(--clean)", B: "var(--low)", C: "var(--medium)",
    D: "var(--high)", F: "var(--critical)"
  };
  var GRADE_MEANING = {
    A: "no findings",
    B: "minor issues only",
    C: "review recommended",
    D: "serious issues, review before continuing to use",
    F: "critical issues, stop using until resolved"
  };

  var active = {};
  var query = "";
  var expanded = false;

  /* Every string below arrives from an audited skill, so it is written with
     textContent and never with innerHTML. */
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function plural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }

  function sevFilterOn() {
    return SEV.some(function (s) { return active[s]; });
  }

  /* Masthead ---------------------------------------------------------- */

  document.getElementById("page-title").textContent = data.title;

  var totals = data.totals || {};
  var urgent = (totals.critical || 0) + (totals.high || 0);
  var flagged = data.skills.filter(function (s) { return s.grade !== "A"; }).length;
  var verdict;
  if (urgent > 0) {
    verdict = plural(urgent, "finding") + " at high severity or above, across " +
      plural(flagged, "skill") + " that need a decision. Work down from the top.";
  } else if (flagged > 0) {
    verdict = "Nothing critical or high. " + plural(flagged, "skill") +
      " carry findings worth a decision.";
  } else {
    verdict = "No findings across " + plural(data.skill_count, "skill") + ".";
  }
  document.getElementById("verdict").textContent = verdict;
  document.getElementById("meta").textContent =
    plural(data.skill_count, "skill") + " audited · generated " + data.generated_at;

  /* Severity gauge ---------------------------------------------------- */

  var gauge = document.getElementById("gauge");
  SEV.forEach(function (sev) {
    var n = totals[sev] || 0;
    var tile = el("button", "tile" + (n === 0 ? " is-zero" : ""));
    tile.type = "button";
    tile.style.setProperty("--sev", SEV_VAR[sev]);
    tile.setAttribute("aria-pressed", "false");
    tile.appendChild(el("span", "n", n));
    tile.appendChild(el("span", "k", sev));
    tile.addEventListener("click", function () {
      active[sev] = !active[sev];
      tile.setAttribute("aria-pressed", active[sev] ? "true" : "false");
      render();
    });
    gauge.appendChild(tile);
  });

  /* Roster ------------------------------------------------------------ */

  function textMatch(parts) {
    if (!query) { return true; }
    return parts.join("  ").toLowerCase().indexOf(query) !== -1;
  }

  function findingMatches(skill, f) {
    if (sevFilterOn() && !active[f.severity]) { return false; }
    return textMatch([skill.name, skill.harness, skill.path || "", f.rule_id, f.title,
                      f.file || "", f.evidence, f.recommendation, f.detector]);
  }

  function findingNode(f) {
    var node = el("div", "finding");
    node.style.setProperty("--sev", SEV_VAR[f.severity] || "var(--info)");

    var head = el("div", "finding-head");
    head.appendChild(el("span", "sev", f.severity));
    head.appendChild(el("span", "rule", f.rule_id));
    var where = f.file || "skill";
    if (f.line) { where += ":" + f.line; }
    head.appendChild(el("span", "where", where));
    node.appendChild(head);

    node.appendChild(el("div", "finding-title", f.title));

    if (f.evidence) { node.appendChild(el("pre", "evidence", f.evidence)); }

    if (f.recommendation) {
      var fix = el("p", "fix");
      fix.appendChild(el("b", null, "Fix "));
      fix.appendChild(document.createTextNode(f.recommendation));
      node.appendChild(fix);
    }

    var tags = el("div", "tags");
    if (f.detector) { tags.appendChild(el("span", "tag", "found by " + f.detector)); }
    if (f.confidence) { tags.appendChild(el("span", "tag", f.confidence + " confidence")); }
    (f.owasp || []).forEach(function (o) { tags.appendChild(el("span", "tag", o)); });
    if (tags.childNodes.length) { node.appendChild(tags); }

    return node;
  }

  function skillNode(skill, shown) {
    var box = el("details", "skill");
    box.open = expanded || (query !== "" && shown.length > 0);

    var summary = document.createElement("summary");
    var grade = el("div", "grade", skill.grade);
    grade.style.setProperty("--sev", GRADE_VAR[skill.grade] || "var(--info)");
    grade.title = "Grade " + skill.grade + ": " + (GRADE_MEANING[skill.grade] || "");
    summary.appendChild(grade);

    var mid = el("div");
    mid.appendChild(el("div", "skill-name", skill.name));
    var sub = [skill.harness];
    if (skill.path) { sub.push(skill.path); }
    mid.appendChild(el("div", "skill-sub", sub.join("  ·  ")));
    summary.appendChild(mid);

    var pills = el("div", "pills");
    SEV.forEach(function (sev) {
      var n = (skill.counts || {})[sev] || 0;
      if (!n) { return; }
      var pill = el("span", "pill", n + " " + sev);
      pill.style.setProperty("--sev", SEV_VAR[sev]);
      pills.appendChild(pill);
    });
    if (!pills.childNodes.length) { pills.appendChild(el("span", "pill plain", "clean")); }
    pills.appendChild(el("span", "pill plain", skill.always_on_tokens + " tok always on"));
    summary.appendChild(pills);
    box.appendChild(summary);

    if (!skill.findings.length) {
      box.appendChild(el("div", "clean-line",
        "No findings. Nothing was detected by a static read, which is not the same as proven safe."));
    } else if (!shown.length) {
      box.appendChild(el("div", "clean-line",
        plural(skill.findings.length, "finding") + ", none matching the current filter."));
    } else {
      var list = el("div", "findings");
      shown.forEach(function (f) { list.appendChild(findingNode(f)); });
      box.appendChild(list);
    }
    return box;
  }

  function render() {
    var roster = document.getElementById("roster");
    roster.textContent = "";

    var filtering = query !== "" || sevFilterOn();
    var visible = 0;
    var shownFindings = 0;

    data.skills.forEach(function (skill) {
      var shown = skill.findings.filter(function (f) { return findingMatches(skill, f); });
      if (filtering && !shown.length) {
        // A text search still keeps a skill whose own name or path matches, so
        // searching for a skill shows it even when it has no findings at all.
        var keepByName = !sevFilterOn() &&
          textMatch([skill.name, skill.harness, skill.path || ""]);
        if (!keepByName) { return; }
      }
      visible += 1;
      shownFindings += shown.length;
      roster.appendChild(skillNode(skill, shown));
    });

    if (!visible) { roster.appendChild(el("div", "empty", "Nothing matches that filter.")); }

    document.getElementById("count-note").textContent =
      "showing " + plural(visible, "skill") + " · " + plural(shownFindings, "finding");
  }

  document.getElementById("q").addEventListener("input", function (e) {
    query = e.target.value.trim().toLowerCase();
    render();
  });

  var toggleAll = document.getElementById("toggle-all");
  toggleAll.addEventListener("click", function () {
    expanded = !expanded;
    toggleAll.textContent = expanded ? "Collapse all" : "Expand all";
    render();
  });

  document.getElementById("reset").addEventListener("click", function () {
    active = {};
    query = "";
    expanded = false;
    toggleAll.textContent = "Expand all";
    document.getElementById("q").value = "";
    Array.prototype.forEach.call(gauge.querySelectorAll(".tile"), function (tile) {
      tile.setAttribute("aria-pressed", "false");
    });
    render();
  });

  /* Next steps and suggested fixes ------------------------------------ */

  /* A host that lets an embedded page talk to the agent that produced it
     exposes a send hook on the window. The artifact runtime does not offer
     one, so the button is labelled with what it will actually do here rather
     than promising a delivery it cannot make. The prompt text is always on
     the page too, so there is never a dead end. */
  function agentSend() {
    return (typeof window.sendPrompt === "function") ? window.sendPrompt : null;
  }

  function legacyCopy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (err) {
      return false;
    }
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(
        function () { return true; },
        function () { return legacyCopy(text); });
    }
    return Promise.resolve(legacyCopy(text));
  }

  function wireSend(kind, btn, status, peek, pre, hasWork) {
    pre.textContent = (data.prompts || {})[kind] || "";

    if (!hasWork) {
      btn.textContent = "Nothing to send";
      btn.disabled = true;
      return;
    }

    btn.textContent = agentSend() ? "Send to agent" : "Copy for your agent";
    btn.addEventListener("click", function () {
      var text = pre.textContent;
      var send = agentSend();
      if (send) {
        try {
          send(text);
          status.textContent = "Sent to your agent.";
          return;
        } catch (err) {
          /* fall through to the clipboard */
        }
      }
      copyText(text).then(function (ok) {
        if (ok) {
          status.textContent = "Copied. Paste it to the agent that ran this audit.";
        } else {
          status.textContent = "Could not reach the clipboard. Copy the text below by hand.";
          peek.open = true;
        }
      });
    });
  }

  var stepsEl = document.getElementById("steps");
  var steps = data.next_steps || [];
  steps.forEach(function (step, i) {
    var li = el("li", "step");
    li.style.setProperty("--sev", SEV_VAR[step.severity] || "var(--info)");
    li.appendChild(el("span", "idx", (i + 1) + "."));
    var body = el("div");
    body.appendChild(el("div", "who", step.skill));
    body.appendChild(el("div", "what", step.headline + ". " + step.action));
    body.appendChild(el("div", "tagline",
      step.severity + " · grade " + step.grade + " · " + (step.rules || []).join(", ")));
    li.appendChild(body);
    stepsEl.appendChild(li);
  });
  if (!steps.length) {
    stepsEl.parentNode.insertBefore(
      el("p", "nothing-to-do", "No findings, so there is nothing to act on."), stepsEl);
  }

  var groupsEl = document.getElementById("fixgroups");
  var plan = data.fix_plan || [];
  plan.forEach(function (group) {
    var box = el("div", "fixgroup");
    box.style.setProperty("--sev", SEV_VAR[group.severity] || "var(--info)");
    box.appendChild(el("h3", null, group.skill));
    var ul = document.createElement("ul");
    group.items.forEach(function (item) {
      var li = document.createElement("li");
      li.appendChild(el("code", null, item.rule_id));
      li.appendChild(document.createTextNode(" " + item.severity + " at "));
      li.appendChild(el("code", null, item.where));
      li.appendChild(document.createTextNode(" - " + item.recommendation));
      ul.appendChild(li);
    });
    box.appendChild(ul);
    groupsEl.appendChild(box);
  });
  if (!plan.length) {
    groupsEl.appendChild(el("p", "nothing-to-do", "No findings, so there is nothing to fix."));
  }

  wireSend("next-steps",
    document.getElementById("send-steps"),
    document.getElementById("status-steps"),
    document.getElementById("peek-steps"),
    document.getElementById("prompt-steps"),
    steps.length > 0);

  wireSend("fixes",
    document.getElementById("send-fixes"),
    document.getElementById("status-fixes"),
    document.getElementById("peek-fixes"),
    document.getElementById("prompt-fixes"),
    plan.length > 0);

  /* Context cost ------------------------------------------------------ */

  document.getElementById("cost-big").textContent = data.always_on_total + " tokens";
  document.getElementById("cost-label").textContent = "always on, every session";
  document.getElementById("cost-note").textContent =
    "The name and description of every installed skill sit in context whether or not any skill is used. " +
    "The body figure is what a skill adds when it activates; resources are read on demand.";

  var peak = data.skills.reduce(function (m, s) {
    return Math.max(m, s.always_on_tokens || 0);
  }, 1);
  var costRows = document.getElementById("cost-rows");
  data.skills.slice().sort(function (a, b) {
    return (b.always_on_tokens || 0) - (a.always_on_tokens || 0);
  }).forEach(function (skill) {
    var row = el("div", "cost-row");
    row.appendChild(el("div", "label", skill.name));
    var bar = el("div", "bar");
    var fill = el("span");
    fill.style.width = Math.max(2, Math.round((skill.always_on_tokens / peak) * 100)) + "%";
    bar.appendChild(fill);
    bar.title = skill.always_on_tokens + " always-on tokens";
    row.appendChild(bar);
    row.appendChild(el("div", "n",
      skill.always_on_tokens + " on · " + skill.body_tokens + " body · " +
      skill.resource_tokens + " res"));
    costRows.appendChild(row);
  });

  /* Legend, limits, notes --------------------------------------------- */

  var legend = document.getElementById("legend");
  ["A", "B", "C", "D", "F"].forEach(function (g) {
    var row = el("div");
    var badge = el("b", null, g);
    badge.style.setProperty("--sev", GRADE_VAR[g]);
    row.appendChild(badge);
    row.appendChild(el("span", null, GRADE_MEANING[g]));
    legend.appendChild(row);
  });

  var limitsEl = document.getElementById("limits");
  [
    "A clean result is evidence of no detected problems, not proof of safety.",
    "Nothing was executed. A skill that misbehaves only at run time can still read clean here.",
    "Sandboxing and isolation belong to the harness, not to a skill file, so they cannot be judged by reading skill content.",
    "Governance questions such as approval workflow and audit logging are organizational; this inventory is where they start.",
    "A skill may behave differently on another harness, since each grants tools its own way."
  ].forEach(function (line) { limitsEl.appendChild(el("li", null, line)); });

  if (data.notes && data.notes.length) {
    var wrap = document.getElementById("run-notes");
    wrap.appendChild(el("p", "eyebrow", "Notes from this run"));
    var ul = document.createElement("ul");
    data.notes.forEach(function (n) { ul.appendChild(el("li", null, n)); });
    wrap.appendChild(ul);
  }

  document.getElementById("colophon").textContent =
    "Static analysis only: skill files were read as text and analyzed. No audited script, command, or URL was " +
    "executed, imported, or contacted, and no instruction found inside a skill was followed. This page loads " +
    "nothing from the network and sends nothing anywhere; every value shown is inserted as text, never as markup.";

  render();
})();
"""


def render_page(data, fmt):
    payload = embed_json(data)
    parts = []
    if fmt == "standalone":
        parts.append("<!doctype html>")
        parts.append('<html lang="en">')
        parts.append("<head>")
        parts.append('<meta charset="utf-8">')
        parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<title>%s</title>" % escape_html(data["title"]))
    parts.append("<style>%s</style>" % STYLE)
    if fmt == "standalone":
        parts.append("</head>")
        parts.append("<body>")
    parts.append(BODY)
    parts.append('<script type="application/json" id="audit-data">%s</script>' % payload)
    parts.append("<script>%s</script>" % SCRIPT)
    if fmt == "standalone":
        parts.append("</body>")
        parts.append("</html>")
    return "\n".join(parts) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Render an interactive dashboard from a merged findings document.")
    parser.add_argument("--findings", required=True,
                        help="Path to findings.json written by build_report.py.")
    parser.add_argument("--inventory", help="Path to inventory.json, for paths and file counts.")
    parser.add_argument("--out", required=True, help="Where to write the HTML.")
    parser.add_argument("--format", choices=("standalone", "artifact"), default="standalone",
                        help="standalone writes a full HTML document; artifact omits the "
                             "document wrapper for a harness that supplies its own head.")
    parser.add_argument("--title", default="Installed Skills Audit", help="Page title.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    findings_doc = read_json(args.findings)
    inventory = read_json(args.inventory) if args.inventory else None
    data = build_data(findings_doc, inventory, args.title)
    html = render_page(data, args.format)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)

    if not args.quiet:
        print("Dashboard (%s) written to %s: %d KB, self-contained, no network requests."
              % (args.format, args.out, len(html.encode("utf-8")) // 1024))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
