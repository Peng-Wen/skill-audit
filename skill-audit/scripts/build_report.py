#!/usr/bin/env python3
"""Merge deterministic and semantic findings into a report.

Takes the scanner's findings, optionally the semantic findings the agent wrote
during its review pass, and the inventory, then writes findings.json plus a
human-readable report.md.

Usage:
  python3 build_report.py --scan scan_findings.json --inventory inventory.json \
      --llm llm_findings.json --out skill-audit-report/2026-08-21T12-00-00/
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_audit_lib import (  # noqa: E402
    RULES,
    SEVERITIES,
    build_action_plan,
    build_agent_prompt,
    estimate_tokens,
    local_now,
    read_json,
    severity_rank,
    summarize_findings,
    write_json,
)

REQUIRED_FINDING_KEYS = ("rule_id", "severity", "skill", "evidence")

ADJUDICATION_VERDICTS = ("downgrade", "resolve")

GRADE_MEANING = {
    "A": "no findings",
    "B": "minor issues only",
    "C": "review recommended",
    "D": "serious issues, review before continuing to use",
    "F": "critical issues, stop using until resolved",
}


def build_skill_resolver(inventory):
    """Map a semantic entry onto exactly one inventory skill.

    Names can legitimately collide across scopes, so an ambiguous name is an
    error rather than a guess, and a name outside the inventory is rejected:
    accepting it would let a hallucinated name conjure a graded report row.
    With no inventory at all there is nothing to check against, and names
    pass through as their own ids.
    """
    skills = inventory.get("skills") or []
    by_id = {s["id"]: s for s in skills}
    by_name = {}
    for s in skills:
        by_name.setdefault(s["name"], []).append(s)

    def resolve(entry):
        """Return (skill_id, display_name, error_or_None)."""
        sid = entry.get("skill_id")
        if sid:
            if sid in by_id:
                return sid, by_id[sid]["name"], None
            return None, None, "skill_id '%s' is not in the inventory" % sid
        name = entry.get("skill")
        matches = by_name.get(name) or []
        if len(matches) == 1:
            return matches[0]["id"], name, None
        if not skills:
            return name, name, None
        if not matches:
            return None, None, "skill '%s' is not in the inventory" % name
        return None, None, ("skill name '%s' matches %d installed skills; "
                            "give skill_id" % (name, len(matches)))

    return resolve


def validate_llm_finding(entry, resolve):
    """Check one semantic finding. Returns (normalized_entry, error_or_None).

    The semantic pass is written by an agent reading untrusted content, so its
    output is validated rather than trusted: unknown rule ids, bad severities,
    missing fields, and skills outside the inventory are dropped and reported
    instead of flowing into the report.
    """
    if not isinstance(entry, dict):
        return None, "entry is not an object"
    missing = [k for k in REQUIRED_FINDING_KEYS if not entry.get(k)]
    if missing:
        return None, "missing required field(s): %s" % ", ".join(missing)
    rule_id = entry["rule_id"]
    if rule_id not in RULES:
        return None, "unknown rule_id '%s'" % rule_id
    if entry["severity"] not in SEVERITIES:
        return None, "invalid severity '%s' for %s" % (entry["severity"], rule_id)
    skill_id, skill_name, error = resolve(entry)
    if error:
        return None, error

    meta = RULES[rule_id]
    normalized = {
        "rule_id": rule_id,
        "category": meta["category"],
        "severity": entry["severity"],
        "skill": skill_name,
        "skill_id": skill_id,
        "file": entry.get("file"),
        "line": entry.get("line"),
        # Evidence lands inside Markdown structure and prompts, so newlines
        # are collapsed here the same way the scanner collapses its own.
        "evidence": " ".join(str(entry["evidence"]).split())[:240],
        "recommendation": entry.get("recommendation") or meta["recommendation"],
        "detector": "llm",
        "owasp": list(meta["owasp"]),
        "confidence": entry.get("confidence", "medium"),
    }
    return normalized, None


def merge(scan_findings, llm_findings, resolve):
    """Combine the two passes, keeping the more severe view of any duplicate."""
    merged = []
    notes = []
    index = {}

    def key_of(f):
        return (f["rule_id"], f.get("skill_id") or f.get("skill"),
                f.get("file"), f.get("line"))

    for f in scan_findings:
        index[key_of(f)] = f
        merged.append(f)

    for raw in llm_findings:
        entry, error = validate_llm_finding(raw, resolve)
        if error:
            notes.append("dropped a semantic finding: %s" % error)
            continue
        key = key_of(entry)
        existing = index.get(key)
        if existing is None and entry.get("line"):
            # The scanner reports some rules at file level, with no line. When
            # the semantic pass reaches the same conclusion about the same rule
            # and file and happens to cite a line, that is the same finding
            # seen twice, not two findings.
            existing = index.get((entry["rule_id"], entry["skill_id"],
                                  entry.get("file"), None))
        if existing:
            if severity_rank(entry["severity"]) > severity_rank(existing["severity"]):
                existing["severity"] = entry["severity"]
            if entry["evidence"] not in existing["evidence"]:
                existing["evidence"] = "%s | semantic review: %s" % (
                    existing["evidence"], entry["evidence"])
            # Keep the reviewer's recommendation as well as the rule's generic
            # one. They can disagree, and the disagreement is the useful part:
            # the scanner says "narrow this permission" from structure alone,
            # while the review may have found the breadth justified. Dropping
            # the second leaves a fix list that asks for changes nobody wants.
            reviewed = (entry.get("recommendation") or "").strip()
            default = RULES.get(entry["rule_id"], {}).get("recommendation", "")
            if reviewed and reviewed != default and reviewed not in existing["recommendation"]:
                existing["recommendation"] = "%s Semantic review: %s" % (
                    existing["recommendation"].rstrip(), reviewed)
            existing["detector"] = "deterministic+llm"
            continue
        index[key] = entry
        merged.append(entry)

    merged.sort(key=lambda f: (
        f.get("skill_id") or f["skill"],
        -severity_rank(f["severity"]),
        f["rule_id"],
        f.get("file") or "",
        f.get("line") or 0,
    ))
    return merged, notes


def validate_adjudication(adj, resolve):
    """Check one adjudication. Returns (normalized, error_or_None).

    An adjudication is the semantic pass lowering or resolving a deterministic
    finding it judged benign, with the reason on record. It is validated as
    strictly as a finding, because it subtracts from the report.
    """
    if not isinstance(adj, dict):
        return None, "entry is not an object"
    rule_id = adj.get("rule_id")
    if rule_id not in RULES:
        return None, "unknown rule_id '%s'" % rule_id
    verdict = adj.get("verdict")
    if verdict not in ADJUDICATION_VERDICTS:
        return None, "verdict must be one of %s" % ", ".join(ADJUDICATION_VERDICTS)
    reason = " ".join(str(adj.get("reason") or "").split())
    if not reason:
        return None, "an adjudication without a reason is dropped; state why"
    severity = adj.get("severity")
    if verdict == "downgrade" and severity not in SEVERITIES:
        return None, "downgrade of %s needs a valid target severity" % rule_id
    skill_id, skill_name, error = resolve(adj)
    if error:
        return None, error
    return {
        "rule_id": rule_id,
        "skill_id": skill_id,
        "skill": skill_name,
        "file": adj.get("file"),
        "line": adj.get("line"),
        "verdict": verdict,
        "severity": severity,
        "reason": reason[:400],
        "evidence": " ".join(str(adj.get("evidence") or "").split())[:240],
    }, None


def apply_adjudications(findings, adjudications, resolve):
    """Apply semantic adjudications to the merged findings. Returns notes.

    Every application, skip, and drop lands in the notes: a finding that
    stops grading must be visible as exactly that, never silently gone. Only
    deterministic findings are eligible, since the semantic pass has no
    business adjudicating its own output, and a downgrade must actually go
    down, or it is refused.
    """
    notes = []
    by_key = {}
    for f in findings:
        if "deterministic" not in (f.get("detector") or ""):
            continue
        by_key.setdefault((f["rule_id"], f.get("skill_id") or f.get("skill")),
                          []).append(f)

    for raw in adjudications or []:
        adj, error = validate_adjudication(raw, resolve)
        if error:
            notes.append("dropped an adjudication: %s" % error)
            continue
        targets = by_key.get((adj["rule_id"], adj["skill_id"]), [])
        if adj.get("file"):
            targets = [f for f in targets if f.get("file") == adj["file"]]
        if adj.get("line"):
            targets = [f for f in targets
                       if f.get("line") in (adj["line"], None)]
        targets = [f for f in targets if f.get("status") != "resolved"]
        if not targets:
            notes.append(
                "dropped an adjudication: no deterministic %s finding on %s "
                "matches it" % (adj["rule_id"], adj["skill"]))
            continue
        for f in targets:
            where = f.get("file") or "SKILL.md"
            if f.get("line"):
                where = "%s:%s" % (where, f["line"])
            if adj["verdict"] == "downgrade":
                if severity_rank(adj["severity"]) >= severity_rank(f["severity"]):
                    notes.append(
                        "refused an adjudication: %s on %s at %s is %s and a "
                        "downgrade to %s does not lower it"
                        % (adj["rule_id"], adj["skill"], where, f["severity"],
                           adj["severity"]))
                    continue
                f["original_severity"] = f["severity"]
                f["severity"] = adj["severity"]
                action = "downgraded to %s" % adj["severity"]
            else:
                f["original_severity"] = f["severity"]
                f["status"] = "resolved"
                action = "resolved"
            f["resolution"] = {
                "verdict": adj["verdict"],
                "reason": adj["reason"],
                "evidence": adj["evidence"],
            }
            notes.append(
                "adjudicated by the semantic review: %s %s on %s at %s, "
                "originally %s: %s"
                % (adj["rule_id"], action, adj["skill"], where,
                   f["original_severity"], adj["reason"]))
    return notes


def context_tax(inventory):
    """Work out what the installed skills cost in context.

    The name and description of every skill sit in context at all times. The
    body is read whenever a skill activates. Resources are read on demand.
    """
    rows = []
    always_on_total = 0
    for skill in inventory.get("skills", []):
        raw = skill["frontmatter"].get("raw") or {}
        metadata_text = "%s %s" % (raw.get("name") or skill["name"],
                                   raw.get("description") or "")
        always_on = estimate_tokens(metadata_text)
        always_on_total += always_on
        rows.append({
            "skill_id": skill["id"],
            "skill": skill["name"],
            "harness": skill["harness"],
            "always_on_tokens": always_on,
            "body_tokens": skill["body"]["token_estimate"],
            "resource_tokens": skill["resource_token_estimate"],
        })
    rows.sort(key=lambda r: -r["always_on_tokens"])
    return {
        "always_on_total": always_on_total,
        "skill_count": len(rows),
        "rows": rows,
    }


def top_action(findings_for_skill):
    """Pick the single most useful next step for a skill."""
    active = [f for f in findings_for_skill if f.get("status") != "resolved"]
    if not active:
        return "none"
    worst = max(active, key=lambda f: severity_rank(f["severity"]))
    return RULES.get(worst["rule_id"], {}).get("title", worst["rule_id"])


def render_report_md(findings, summary, tax, inventory, notes):
    """Render the Markdown report."""
    lines = []
    skills = inventory.get("skills", [])
    totals = summary["totals"]

    lines.append("# Skill audit report")
    lines.append("")
    lines.append("Generated %s." % local_now())
    lines.append("")
    lines.append("Audited %d skill(s) across %d search path(s)."
                 % (len(skills),
                    sum(1 for p in inventory.get("search_paths", []) if p.get("exists"))))
    lines.append("")
    lines.append("Findings: **%d critical**, %d high, %d medium, %d low, %d info."
                 % (totals["critical"], totals["high"], totals["medium"],
                    totals["low"], totals["info"]))
    lines.append("")

    # Summary table.
    lines.append("## Summary")
    lines.append("")
    lines.append("| Skill | Harness | Grade | Critical | High | Medium | Low | Top issue |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")

    by_id = {s["id"]: s for s in skills}
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    entries = sorted(
        summary["by_skill"].items(),
        key=lambda kv: (grade_order.get(kv[1]["grade"], 5),
                        kv[1].get("name") or kv[0], kv[0]))

    # Two skills may share a name across scopes; where that happens the scope
    # disambiguates the row.
    name_counts = {}
    for _, info in entries:
        n = info.get("name") or ""
        name_counts[n] = name_counts.get(n, 0) + 1

    def display_name(sid, info):
        name = info.get("name") or sid
        if name_counts.get(name, 0) > 1:
            scope = by_id.get(sid, {}).get("scope")
            if scope:
                return "%s (%s)" % (name, scope)
        return name

    def findings_of(sid):
        return [f for f in findings if (f.get("skill_id") or f.get("skill")) == sid]

    for sid, info in entries:
        counts = info["counts"]
        harness = by_id.get(sid, {}).get("harness", "unknown")
        lines.append("| %s | %s | %s | %d | %d | %d | %d | %s |" % (
            display_name(sid, info), harness, info["grade"], counts["critical"],
            counts["high"], counts["medium"], counts["low"],
            top_action(findings_of(sid))))
    lines.append("")

    # One action section: the decision a skill needs and the edits that carry
    # it out are the same work at two zoom levels, so they sit in one entry
    # rather than in two lists a reader has to cross-reference.
    plan = build_action_plan(findings, summary,
                             {s["id"]: s.get("path") for s in skills})
    lines.append("## Next steps")
    lines.append("")
    if not plan:
        lines.append("Nothing to act on. No skill produced a finding.")
        lines.append("")
    else:
        lines.append("In order, most severe first. Each entry is the decision a skill needs "
                     "and the changes that carry it out.")
        lines.append("")
        for i, group in enumerate(plan, 1):
            lines.append("%d. **%s** - grade %s, %d finding(s). %s"
                         % (i, group["skill"], group["grade"], group["count"],
                            group["decision"]))
            if group.get("path"):
                lines.append("   - Location: `%s`" % group["path"])
            for item in group["items"]:
                lines.append("   - `%s` %s at `%s`: %s"
                             % (item["rule_id"], item["severity"], item["where"],
                                item["recommendation"]))
            lines.append("")
        lines.append("To hand this to an agent, copy the block below. It carries its own "
                     "instruction that the quoted content is data rather than instructions, "
                     "which matters because the evidence comes from the audited skills "
                     "themselves. The interactive summary carries the same section with a "
                     "button that delivers it in one step; Markdown has no button, so here "
                     "it is a block to copy.")
        lines.append("")
        lines.append("```text")
        lines.append(build_agent_prompt(plan, len(skills)).rstrip())
        lines.append("```")
        lines.append("")

    # Per-skill detail.
    lines.append("## Findings by skill")
    lines.append("")
    for sid, info in entries:
        skill_findings = findings_of(sid)
        skill = by_id.get(sid, {})
        lines.append("### %s (grade %s)" % (display_name(sid, info), info["grade"]))
        lines.append("")
        if skill.get("path"):
            lines.append("Location: `%s`" % skill["path"])
            lines.append("")
        if not skill_findings:
            lines.append("No findings.")
            lines.append("")
            continue
        for f in skill_findings:
            where = f.get("file") or "skill"
            if f.get("line"):
                where = "%s:%s" % (where, f["line"])
            owasp = (" [%s]" % ", ".join(f["owasp"])) if f.get("owasp") else ""
            title = RULES.get(f["rule_id"], {}).get("title", "")
            resolution = f.get("resolution") or {}
            if f.get("status") == "resolved":
                lines.append("- **RESOLVED %s** (%s)%s at `%s`"
                             % (f["rule_id"], title, owasp, where))
                lines.append("  - Evidence: `%s`" % f["evidence"].replace("`", "'"))
                lines.append("  - Resolved by the semantic review, originally %s: %s"
                             % (f.get("original_severity", "?"),
                                resolution.get("reason", "")))
                continue
            lines.append("- **%s %s** (%s)%s at `%s`"
                         % (f["severity"].upper(), f["rule_id"], title, owasp, where))
            lines.append("  - Evidence: `%s`" % f["evidence"].replace("`", "'"))
            lines.append("  - Fix: %s" % f["recommendation"])
            lines.append("  - Detected by: %s" % f["detector"])
            if f.get("original_severity"):
                lines.append("  - Adjudicated down from %s by the semantic review: %s"
                             % (f["original_severity"], resolution.get("reason", "")))
        lines.append("")

    # Context cost.
    lines.append("## Context cost")
    lines.append("")
    lines.append("Every installed skill keeps its name and description in context at all "
                 "times, whether or not it is used.")
    lines.append("Across %d skill(s) that permanent cost is about **%d tokens** per session."
                 % (tax["skill_count"], tax["always_on_total"]))
    lines.append("")
    lines.append("| Skill | Always on | Body when activated | Bundled resources |")
    lines.append("| --- | --- | --- | --- |")
    for row in tax["rows"]:
        lines.append("| %s | %d | %d | %d |" % (
            row["skill"], row["always_on_tokens"], row["body_tokens"],
            row["resource_tokens"]))
    lines.append("")

    # Grades.
    lines.append("## How to read this report")
    lines.append("")
    lines.append("Grades reflect the most severe finding for a skill.")
    lines.append("")
    for grade in ("A", "B", "C", "D", "F"):
        lines.append("- **%s**: %s" % (grade, GRADE_MEANING[grade]))
    lines.append("")

    # Methodology and limits.
    lines.append("## Method and limitations")
    lines.append("")
    lines.append("This audit combines deterministic pattern and structure rules with a "
                 "semantic review pass, because pattern matching alone misses instructions "
                 "written in ordinary prose.")
    lines.append("")
    lines.append("The semantic pass can also adjudicate a deterministic finding it judged "
                 "benign, lowering its severity or resolving it. Nothing is suppressed "
                 "silently: an adjudicated finding stays in this report with its original "
                 "severity and the recorded reason, and every adjudication is listed in "
                 "the notes below.")
    lines.append("")
    lines.append("Known limits of this report:")
    lines.append("")
    lines.append("- A clean result is evidence of no detected problems, not proof of safety.")
    lines.append("- Runtime behavior is out of scope. Nothing here was executed, so a skill "
                 "that behaves badly only when run may still look clean.")
    lines.append("- Sandboxing and isolation are properties of the harness, not of a skill "
                 "file, so they cannot be assessed by reading skill content.")
    lines.append("- Governance questions such as approval workflow and audit logging are "
                 "organizational. The inventory in this report is the starting point for them.")
    lines.append("- A skill may behave differently on another harness, since each harness "
                 "grants tools and permissions its own way.")
    lines.append("- The scanner does not run its pattern rules over its own executing "
                 "source, because its rule tables spell out the strings it searches for. "
                 "Any file skipped for that reason is named in the notes below, and any "
                 "other copy of the audit tool is scanned in full.")
    if notes:
        lines.append("")
        lines.append("Notes from this run:")
        lines.append("")
        for note in notes:
            lines.append("- %s" % note)
    lines.append("")

    # Transparency.
    lines.append("## What this audit did")
    lines.append("")
    lines.append("- Read skill files as text and analyzed them.")
    lines.append("- Did not execute, import, or source any audited script or command.")
    lines.append("- Did not open any URL or endpoint referenced by an audited skill.")
    lines.append("- Did not follow any instruction found inside an audited skill.")
    lines.append("")

    return "\n".join(lines) + "\n"


def print_terminal_summary(findings, summary, tax, out_dir):
    totals = summary["totals"]
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    entries = sorted(summary["by_skill"].items(),
                     key=lambda kv: (grade_order.get(kv[1]["grade"], 5),
                                     kv[1].get("name") or kv[0], kv[0]))

    print("")
    print("Skill audit: %d critical, %d high, %d medium, %d low, %d info"
          % (totals["critical"], totals["high"], totals["medium"],
             totals["low"], totals["info"]))
    print("")
    print("%-32s %-6s %s" % ("SKILL", "GRADE", "TOP ISSUE"))
    for sid, info in entries:
        name = info.get("name") or sid
        skill_findings = [f for f in findings
                          if (f.get("skill_id") or f.get("skill")) == sid]
        print("%-32s %-6s %s" % (name[:32], info["grade"], top_action(skill_findings)))
    print("")
    print("Always-on context cost of installed skills: about %d tokens."
          % tax["always_on_total"])
    print("Full report: %s" % os.path.join(out_dir, "report.md"))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Merge scanner and semantic findings into an audit report.")
    parser.add_argument("--scan", required=True, help="Path to scan_findings.json.")
    parser.add_argument("--llm", help="Path to llm_findings.json from the semantic review.")
    parser.add_argument("--inventory", help="Path to inventory.json.")
    parser.add_argument("--out", required=True, help="Directory to write the report into.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    scan_doc = read_json(args.scan)
    scan_findings = scan_doc.get("findings", [])

    llm_findings = []
    llm_adjudications = []
    # Notes from the scan come first: they describe the coverage the rest of
    # the report rests on, such as any file the scan deliberately skipped.
    notes = list(scan_doc.get("notes") or [])
    if args.llm:
        if os.path.exists(args.llm):
            try:
                llm_doc = read_json(args.llm)
                if isinstance(llm_doc, dict):
                    llm_findings = llm_doc.get("findings", [])
                    llm_adjudications = llm_doc.get("adjudications", [])
                else:
                    llm_findings = llm_doc
                if not isinstance(llm_findings, list):
                    notes.append("semantic findings file did not contain a findings list")
                    llm_findings = []
                if not isinstance(llm_adjudications, list):
                    notes.append("semantic adjudications were not a list and were ignored")
                    llm_adjudications = []
            except ValueError as exc:
                notes.append("semantic findings file was not valid JSON: %s" % exc)
        else:
            notes.append("no semantic findings file at %s; report covers the deterministic "
                         "scan only" % args.llm)

    inventory = read_json(args.inventory) if args.inventory else {"skills": [], "search_paths": []}
    resolve = build_skill_resolver(inventory)

    findings, merge_notes = merge(scan_findings, llm_findings, resolve)
    notes.extend(merge_notes)
    notes.extend(apply_adjudications(findings, llm_adjudications, resolve))

    summary = summarize_findings(
        findings,
        [{"id": s["id"], "name": s["name"]} for s in inventory.get("skills", [])])
    tax = context_tax(inventory)

    os.makedirs(args.out, exist_ok=True)
    write_json(os.path.join(args.out, "findings.json"), {
        "source": "merged",
        "findings": findings,
        "summary": summary,
        "context_cost": tax,
        "notes": notes,
    })

    report_md = render_report_md(findings, summary, tax, inventory, notes)
    with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report_md)

    if not args.quiet:
        print_terminal_summary(findings, summary, tax, args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
