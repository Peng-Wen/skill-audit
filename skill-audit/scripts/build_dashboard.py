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

# Set before any local import: importing a sibling module is what writes
# __pycache__, and when these scripts run from an installed skill directory
# that cache lands inside the very bundle the audit inspects, where the next
# audit rightly reports it as opaque bytecode (SEC011).
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_audit_lib import (  # noqa: E402
    HARNESS_NOTE,
    RULES,
    SEVERITIES,
    build_action_plan,
    build_agent_prompt,
    harness_breakdown,
    harness_label,
    iso_local_now,
    local_now,
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

    # Everything is keyed by skill id: names can collide across scopes, and a
    # page that pooled two skills under one name would hand one skill the
    # other's grade.
    paths = {}
    file_counts = {}
    installed_for = {}
    for skill in (inventory or {}).get("skills", []):
        paths[skill["id"]] = skill.get("path")
        file_counts[skill["id"]] = len(skill.get("files", []))
        installed_for[skill["id"]] = {"harness": skill.get("harness"),
                                      "scope": skill.get("scope")}

    cost_rows = {row.get("skill_id") or row["skill"]: row
                 for row in cost.get("rows", [])}

    grouped = {}
    for f in findings:
        grouped.setdefault(f.get("skill_id") or f.get("skill"), []).append(f)

    skills = []
    where_by_id = {}
    for sid, info in summary.get("by_skill", {}).items():
        row = cost_rows.get(sid, {})
        # The inventory is the better source, but the page is also built from
        # findings.json alone, and the cost rows carry the same two fields.
        where = installed_for.get(sid) or {"harness": row.get("harness"),
                                           "scope": row.get("scope")}
        where_by_id[sid] = where
        entries = sorted(grouped.get(sid, []),
                         key=lambda f: (f.get("status") == "resolved",
                                        -severity_rank(f["severity"]),
                                        f["rule_id"]))
        skills.append({
            "id": sid,
            "name": info.get("name") or sid,
            "grade": info.get("grade", "A"),
            "counts": info.get("counts", {}),
            "resolved": info.get("resolved", 0),
            "harness": where.get("harness") or "unknown",
            # The label is what the page shows and filters on; the scope
            # separates two installs of one skill under the same harness.
            "harness_label": harness_label(where.get("harness"), where.get("scope")),
            "scope": where.get("scope"),
            "path": paths.get(sid),
            "files": file_counts.get(sid),
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
                "status": f.get("status", "active"),
                "original_severity": f.get("original_severity"),
                "resolution_reason": (f.get("resolution") or {}).get("reason", ""),
            } for f in entries],
        })

    skills.sort(key=lambda s: (GRADE_ORDER.get(s["grade"], 5), s["name"], s["id"]))

    plan = build_action_plan(findings, summary, {
        sid: {"path": paths.get(sid), "harness": where.get("harness"),
              "scope": where.get("scope")}
        for sid, where in where_by_id.items()})

    return {
        "title": title,
        # ISO with the local offset so the page can render it in the reader's
        # own zone and format; the rendered string is the fallback for a client
        # that cannot parse it.
        "generated_at": iso_local_now(),
        "generated_display": local_now(),
        "totals": summary.get("totals", {sev: 0 for sev in SEVERITIES}),
        "always_on_total": cost.get("always_on_total", 0),
        "skill_count": len(skills),
        "harnesses": harness_breakdown(skills),
        "harness_note": HARNESS_NOTE,
        "skills": skills,
        "notes": findings_doc.get("notes") or [],
        "action_plan": plan,
        "prompt": build_agent_prompt(plan, len(skills)),
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
.tile:not(:disabled):hover { transform: translateY(-1px); }
.tile:disabled { cursor: default; opacity: .5; }
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

/* Harness facet: which agent each skill is installed for, as a filter. */
.facets {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin: -4px 0 14px;
}
.facet-label {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--text-muted);
}
.chip {
  appearance: none;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 11.5px;
  font-variant-numeric: tabular-nums;
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--surface);
  color: var(--text-muted);
}
.chip:hover { color: var(--text); border-color: var(--accent); }
.chip[aria-pressed="true"] {
  border-color: var(--accent);
  background: var(--surface-sunk);
  color: var(--accent);
  font-weight: 700;
}
.chip .n { color: var(--text-muted); font-weight: 400; }

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

.skill-headline {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 9px;
}
.skill-name {
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 700;
  overflow-wrap: anywhere;
}
/* The harness a skill is installed for reads as part of its identity, not as
   another metric, so it sits beside the name rather than among the pills. */
.harness-badge {
  font-family: var(--mono);
  font-size: 10.5px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--accent);
  border: 1px solid var(--accent);
  border-radius: 999px;
  padding: 1px 8px;
  white-space: nowrap;
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

/* A resolved finding stays on the page, dimmed: visible is the whole point
   of recording adjudications instead of suppressing findings. */
.finding.resolved { opacity: .62; }
.finding.resolved .finding-title { text-decoration: line-through; text-decoration-thickness: 1px; }
.resolved-label { color: var(--clean); }

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
.cost-row .label .harness { display: block; color: var(--text-muted); font-size: 11px; }
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
.step .what { margin-top: 4px; font-size: 14px; max-width: 76ch; text-wrap: pretty; }

.step-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 9px; }
.step-loc {
  margin-top: 3px;
  font-family: var(--mono);
  font-size: 11.5px;
  color: var(--text-muted);
  overflow-wrap: anywhere;
}
.step-grade, .step-count {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .06em;
  text-transform: uppercase;
  border: 1px solid var(--sev, var(--line));
  color: var(--sev, var(--text-muted));
  border-radius: 999px;
  padding: 1px 8px;
  white-space: nowrap;
}
.step-count { border-color: var(--line); color: var(--text-muted); }

.fixes {
  margin: 9px 0 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.fixes li {
  font-size: 13.5px;
  max-width: 78ch;
  text-wrap: pretty;
  padding-left: 11px;
  border-left: 2px solid var(--sev, var(--line));
}
.fixes code {
  font-family: var(--mono);
  font-size: 11.5px;
  background: var(--surface-sunk);
  border-radius: 4px;
  padding: 1px 5px;
}

.step-note {
  margin: 12px 0 0;
  font-size: 13.5px;
  color: var(--text-muted);
  max-width: 76ch;
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

  <section aria-labelledby="roster-h">
    <h2 id="roster-h">Skills, worst first</h2>
    <div class="controls">
      <input type="search" id="q" placeholder="filter by skill, rule, file, or evidence"
             aria-label="Filter skills and findings">
      <button class="btn" id="toggle-all" type="button">Expand all</button>
      <button class="btn" id="reset" type="button">Reset</button>
      <span class="count-note" id="count-note"></span>
    </div>
    <div class="facets" id="harness-facets" hidden>
      <span class="facet-label">Installed for</span>
    </div>
    <div class="roster" id="roster"></div>
  </section>

  <section aria-labelledby="steps-h">
    <div class="section-head">
      <h2 id="steps-h">Next steps</h2>
      <button class="send" id="send-steps" type="button"></button>
      <span class="send-status" id="status-steps" role="status" aria-live="polite"></span>
    </div>
    <ol class="steps" id="steps"></ol>
    <p class="step-note" id="step-note"></p>
    <details class="prompt-peek" id="peek-steps">
      <summary>Show the exact text</summary>
      <pre id="prompt-steps"></pre>
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
  /* Harness labels the reader has narrowed to. Empty means every harness. */
  var harnessOn = {};
  var query = "";
  var expanded = false;
  /* Cards the reader opened or closed by hand. Kept across re-renders so
     changing a filter does not undo what they just opened. */
  var manualOpen = {};

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

  function harnessFilterOn() {
    return Object.keys(harnessOn).some(function (h) { return harnessOn[h]; });
  }

  /* Which harness a skill is installed for is a property of the skill, so it
     narrows the roster before any per-finding filter is considered. The label
     indexes a plain object, so the lookup is guarded the way every other
     lookup keyed by audited data is. */
  function harnessMatches(skill) {
    if (!harnessFilterOn()) { return true; }
    return Object.prototype.hasOwnProperty.call(harnessOn, skill.harness_label) &&
      !!harnessOn[skill.harness_label];
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
  function localStamp() {
    var parsed = new Date(data.generated_at);
    if (isNaN(parsed.getTime())) { return data.generated_display || data.generated_at; }
    try {
      return parsed.toLocaleString(undefined, {
        dateStyle: "medium", timeStyle: "medium"
      });
    } catch (err) {
      return parsed.toLocaleString();
    }
  }

  var harnesses = data.harnesses || [];
  /* A skill audited straight from a path has no harness to count, so the
     masthead says nothing rather than counting a placeholder. */
  var harnessSummary = harnesses.filter(function (h) {
    return h.harness && h.harness !== "unknown";
  }).map(function (h) {
    return h.label + " " + h.count;
  }).join(", ");
  document.getElementById("meta").textContent =
    plural(data.skill_count, "skill") + " audited" +
    (harnessSummary ? " · " + harnessSummary : "") + " · generated " + localStamp();

  /* Severity gauge ---------------------------------------------------- */

  var gauge = document.getElementById("gauge");
  var tileEls = {};
  SEV.forEach(function (sev) {
    var tile = el("button", "tile");
    tile.type = "button";
    tile.style.setProperty("--sev", SEV_VAR[sev]);
    tile.setAttribute("aria-pressed", "false");
    var count = el("span", "n", totals[sev] || 0);
    tile.appendChild(count);
    tile.appendChild(el("span", "k", sev));
    tile.addEventListener("click", function () {
      active[sev] = !active[sev];
      render();
    });
    gauge.appendChild(tile);
    tileEls[sev] = {button: tile, count: count};
  });

  /* Tile counts follow the text search but not the severity buttons: a facet
     that zeroed out its siblings the moment you picked one would make a second
     severity impossible to add. */
  function facetCounts() {
    var counts = {};
    SEV.forEach(function (sev) { counts[sev] = 0; });
    data.skills.forEach(function (skill) {
      if (!harnessMatches(skill)) { return; }
      skill.findings.forEach(function (f) {
        if (f.status === "resolved") { return; }
        if (textMatchesFinding(skill, f)) { counts[f.severity] = (counts[f.severity] || 0) + 1; }
      });
    });
    return counts;
  }

  function renderTiles() {
    var counts = facetCounts();
    SEV.forEach(function (sev) {
      var entry = tileEls[sev];
      var n = counts[sev] || 0;
      var on = !!active[sev];
      entry.count.textContent = n;
      entry.button.className = "tile" + (n === 0 ? " is-zero" : "");
      entry.button.setAttribute("aria-pressed", on ? "true" : "false");
      /* Nothing to select is not a filter, it is a dead end. An active tile
         stays live even at zero so it can always be switched back off. */
      entry.button.disabled = (n === 0 && !on);
      entry.button.title = entry.button.disabled
        ? ("No " + sev + " findings" + (query ? " match this search" : ""))
        : (on ? ("Showing " + sev + " findings. Click to stop filtering by it.")
              : ("Show only " + sev + " findings"));
    });
  }

  /* Roster ------------------------------------------------------------ */

  function textMatch(parts) {
    if (!query) { return true; }
    return parts.join("  ").toLowerCase().indexOf(query) !== -1;
  }

  function skillText(skill) {
    return [skill.name, skill.harness, skill.harness_label || "",
            skill.scope || "", skill.path || ""];
  }

  function textMatchesFinding(skill, f) {
    return textMatch(skillText(skill).concat(
      [f.rule_id, f.title, f.file || "", f.evidence, f.recommendation, f.detector]));
  }

  function findingMatches(skill, f) {
    /* A resolved finding grades nothing, so it never answers a severity
       filter; it stays reachable through text search and the plain view. */
    if (f.status === "resolved") {
      return !sevFilterOn() && textMatchesFinding(skill, f);
    }
    if (sevFilterOn() && !active[f.severity]) { return false; }
    return textMatchesFinding(skill, f);
  }

  function activeFilterLabel() {
    var parts = [];
    var chosen = SEV.filter(function (s) { return active[s]; });
    if (chosen.length) { parts.push(chosen.join(" or ")); }
    var onHarness = Object.keys(harnessOn).filter(function (h) { return harnessOn[h]; });
    if (onHarness.length) { parts.push(onHarness.join(" or ")); }
    if (query) { parts.push("\u201c" + query + "\u201d"); }
    return parts.join(" and ");
  }

  function findingNode(f) {
    var resolved = f.status === "resolved";
    var node = el("div", "finding" + (resolved ? " resolved" : ""));
    node.style.setProperty("--sev", resolved ? "var(--line)"
                                             : (SEV_VAR[f.severity] || "var(--info)"));

    var head = el("div", "finding-head");
    if (resolved) {
      head.appendChild(el("span", "sev resolved-label", "resolved"));
    } else {
      head.appendChild(el("span", "sev", f.severity));
    }
    head.appendChild(el("span", "rule", f.rule_id));
    var where = f.file || "skill";
    if (f.line) { where += ":" + f.line; }
    head.appendChild(el("span", "where", where));
    node.appendChild(head);

    node.appendChild(el("div", "finding-title", f.title));

    if (f.evidence) { node.appendChild(el("pre", "evidence", f.evidence)); }

    if (resolved) {
      var res = el("p", "fix");
      res.appendChild(el("b", null, "Resolved "));
      res.appendChild(document.createTextNode(
        "by the semantic review, originally " + (f.original_severity || "?") +
        ": " + (f.resolution_reason || "")));
      node.appendChild(res);
      return node;
    }

    if (f.recommendation) {
      var fix = el("p", "fix");
      fix.appendChild(el("b", null, "Fix "));
      fix.appendChild(document.createTextNode(f.recommendation));
      node.appendChild(fix);
    }
    if (f.original_severity) {
      var adj = el("p", "fix");
      adj.appendChild(el("b", null, "Adjudicated "));
      adj.appendChild(document.createTextNode(
        "down from " + f.original_severity + " by the semantic review: " +
        (f.resolution_reason || "")));
      node.appendChild(adj);
    }

    var tags = el("div", "tags");
    if (f.detector) { tags.appendChild(el("span", "tag", "found by " + f.detector)); }
    if (f.confidence) { tags.appendChild(el("span", "tag", f.confidence + " confidence")); }
    (f.owasp || []).forEach(function (o) { tags.appendChild(el("span", "tag", o)); });
    if (tags.childNodes.length) { node.appendChild(tags); }

    return node;
  }

  function skillNode(skill, shown, filtering) {
    var box = el("details", "skill");
    /* Filtering to something and then having to open every card to see what
       matched is the filter not doing its job. A hand-set card wins, because
       the reader set it more recently than the filter did. */
    if (Object.prototype.hasOwnProperty.call(manualOpen, skill.id)) {
      box.open = manualOpen[skill.id];
    } else {
      box.open = expanded || (filtering && shown.length > 0);
    }

    var summary = document.createElement("summary");
    summary.addEventListener("click", function () {
      /* The click flips the details after this handler runs, so the state the
         reader is asking for is the opposite of the current one. */
      manualOpen[skill.id] = !box.open;
    });
    var grade = el("div", "grade", skill.grade);
    grade.style.setProperty("--sev", GRADE_VAR[skill.grade] || "var(--info)");
    grade.title = "Grade " + skill.grade + ": " + (GRADE_MEANING[skill.grade] || "");
    summary.appendChild(grade);

    var mid = el("div");
    var headline = el("div", "skill-headline");
    headline.appendChild(el("span", "skill-name", skill.name));
    var badge = el("span", "harness-badge", skill.harness_label);
    badge.title = "Installed for " + skill.harness_label +
      (skill.scope ? ", " + skill.scope + " scope" : "") + ". " + (data.harness_note || "");
    headline.appendChild(badge);
    mid.appendChild(headline);
    var sub = [];
    if (skill.scope) { sub.push(skill.scope + " scope"); }
    if (skill.path) { sub.push(skill.path); }
    if (sub.length) { mid.appendChild(el("div", "skill-sub", sub.join("  ·  "))); }
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
    if (skill.resolved) { pills.appendChild(el("span", "pill plain", skill.resolved + " resolved")); }
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
    var totalFindings = 0;

    data.skills.forEach(function (skill) {
      /* Counted before the harness facet narrows the roster, so the note
         below compares what is on screen against the whole audit. */
      totalFindings += skill.findings.length;
      if (!harnessMatches(skill)) { return; }
      var shown = skill.findings.filter(function (f) { return findingMatches(skill, f); });
      if (filtering && !shown.length) {
        // A text search still keeps a skill whose own name or path matches, so
        // searching for a skill shows it even when it has no findings at all.
        var keepByName = !sevFilterOn() && textMatch(skillText(skill));
        if (!keepByName) { return; }
      }
      visible += 1;
      shownFindings += shown.length;
      roster.appendChild(skillNode(skill, shown, filtering));
    });

    if (!visible) {
      var label = activeFilterLabel();
      roster.appendChild(el("div", "empty",
        label ? ("No findings match " + label + ".") : "Nothing to show."));
    }

    document.getElementById("count-note").textContent = (filtering || harnessFilterOn())
      ? (shownFindings + " of " + plural(totalFindings, "finding") + " · " +
         visible + " of " + plural(data.skills.length, "skill"))
      : (plural(visible, "skill") + " · " + plural(shownFindings, "finding"));

    renderTiles();
    renderChips();
  }

  /* Harness facet ----------------------------------------------------- */

  /* One harness is not a choice, so the row only appears when a machine
     actually runs more than one. The badge on every card still names it. */
  var facets = document.getElementById("harness-facets");
  var chipEls = [];
  if (harnesses.length > 1) {
    facets.hidden = false;
    harnesses.forEach(function (h) {
      var chip = el("button", "chip");
      chip.type = "button";
      chip.setAttribute("aria-pressed", "false");
      chip.appendChild(document.createTextNode(h.label + " "));
      chip.appendChild(el("span", "n", h.count));
      chip.addEventListener("click", function () {
        harnessOn[h.label] = !harnessOn[h.label];
        render();
      });
      facets.appendChild(chip);
      chipEls.push({button: chip, label: h.label, count: h.count});
    });
  }

  function renderChips() {
    chipEls.forEach(function (entry) {
      var on = !!harnessOn[entry.label];
      entry.button.setAttribute("aria-pressed", on ? "true" : "false");
      entry.button.title = on
        ? ("Showing skills installed for " + entry.label + ". Click to stop filtering by it.")
        : ("Show only the " + entry.count + " skill(s) installed for " + entry.label);
    });
  }

  document.getElementById("q").addEventListener("input", function (e) {
    query = e.target.value.trim().toLowerCase();
    render();
  });

  var toggleAll = document.getElementById("toggle-all");
  toggleAll.addEventListener("click", function () {
    expanded = !expanded;
    manualOpen = {};
    toggleAll.textContent = expanded ? "Collapse all" : "Expand all";
    render();
  });

  document.getElementById("reset").addEventListener("click", function () {
    active = {};
    harnessOn = {};
    query = "";
    expanded = false;
    manualOpen = {};
    toggleAll.textContent = "Expand all";
    document.getElementById("q").value = "";
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

  function wireSend(btn, status, peek, pre, hasWork) {
    pre.textContent = data.prompt || "";

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
  var plan = data.action_plan || [];
  plan.forEach(function (group, i) {
    var li = el("li", "step");
    li.style.setProperty("--sev", SEV_VAR[group.severity] || "var(--info)");
    li.appendChild(el("span", "idx", (i + 1) + "."));

    var body = el("div");
    var head = el("div", "step-head");
    head.appendChild(el("span", "who", group.skill));
    var grade = el("span", "step-grade", "grade " + group.grade);
    grade.style.setProperty("--sev", GRADE_VAR[group.grade] || "var(--info)");
    head.appendChild(grade);
    head.appendChild(el("span", "step-count", plural(group.count, "finding")));
    body.appendChild(head);

    var loc = [];
    if (group.harness_label) { loc.push(group.harness_label); }
    if (group.path) { loc.push(group.path); }
    if (loc.length) { body.appendChild(el("div", "step-loc", loc.join("  ·  "))); }
    body.appendChild(el("div", "what", group.decision));

    var ul = el("ul", "fixes");
    group.items.forEach(function (item) {
      var row = document.createElement("li");
      row.style.setProperty("--sev", SEV_VAR[item.severity] || "var(--info)");
      row.appendChild(el("code", null, item.rule_id));
      row.appendChild(document.createTextNode(" " + item.severity + " at "));
      row.appendChild(el("code", null, item.where));
      row.appendChild(document.createTextNode(" - " + item.recommendation));
      ul.appendChild(row);
    });
    body.appendChild(ul);

    li.appendChild(body);
    stepsEl.appendChild(li);
  });
  if (!plan.length) {
    stepsEl.parentNode.insertBefore(
      el("p", "nothing-to-do", "No findings, so there is nothing to act on."), stepsEl);
  } else {
    document.getElementById("step-note").textContent =
      "Each entry is the decision a skill needs and the changes that carry it out.";
  }

  wireSend(
    document.getElementById("send-steps"),
    document.getElementById("status-steps"),
    document.getElementById("peek-steps"),
    document.getElementById("prompt-steps"),
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
    var label = el("div", "label", skill.name);
    label.appendChild(el("span", "harness", skill.harness_label));
    row.appendChild(label);
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
  ].concat(data.harness_note ? [data.harness_note] : [])
   .forEach(function (line) { limitsEl.appendChild(el("li", null, line)); });

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
