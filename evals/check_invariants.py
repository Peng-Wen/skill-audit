#!/usr/bin/env python3
"""Repository invariants for skill-audit.

These are the properties that are easy to break by accident and expensive to
notice later, so they are checked mechanically rather than by memory.

Usage:
  python3 evals/check_invariants.py
"""

import io
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SKILL_DIR = os.path.join(REPO, "skill-audit")
SCRIPTS = os.path.join(SKILL_DIR, "scripts")

sys.path.insert(0, SCRIPTS)

from skill_audit_lib import RULES, parse_frontmatter  # noqa: E402

ALLOWED_SHIPPED_ENTRIES = {"SKILL.md", "scripts", "references", "assets"}


def check_shipped_contents(failures):
    """Nothing development-only may sit inside the directory users install."""
    entries = {e for e in os.listdir(SKILL_DIR) if not e.startswith(".")}
    unexpected = entries - ALLOWED_SHIPPED_ENTRIES
    if unexpected:
        failures.append(
            "the shipped skill directory contains unexpected entries: %s. "
            "`npx skills add` copies this directory verbatim, so development "
            "files here would land on user machines."
            % ", ".join(sorted(unexpected)))


def check_rules_documented(failures):
    """Every rule in the registry has to be documented for humans."""
    doc_path = os.path.join(SKILL_DIR, "references", "report-format.md")
    doc = io.open(doc_path, encoding="utf-8").read()
    missing = [rule_id for rule_id in sorted(RULES) if rule_id not in doc]
    if missing:
        failures.append(
            "rules missing from references/report-format.md: %s" % ", ".join(missing))


def check_skill_frontmatter(failures):
    """The skill has to satisfy the spec constraints it audits others against."""
    text = io.open(os.path.join(SKILL_DIR, "SKILL.md"), encoding="utf-8").read()
    frontmatter, body, error = parse_frontmatter(text)
    if error:
        failures.append("SKILL.md frontmatter does not parse: %s" % error)
        return
    name = frontmatter.get("name")
    if name != os.path.basename(SKILL_DIR):
        failures.append("SKILL.md name %r does not match its directory name" % name)
    description = frontmatter.get("description") or ""
    if not 1 <= len(description) <= 1024:
        failures.append("SKILL.md description is %d characters, outside the 1 to 1024 range"
                        % len(description))
    lines = body.count("\n")
    if lines > 500:
        failures.append("SKILL.md body is %d lines, above the 500 the spec recommends" % lines)
    if len(body) // 4 > 5000:
        failures.append("SKILL.md body is about %d tokens, above the recommended 5000"
                        % (len(body) // 4))


def check_self_audit_location(failures):
    """The self-audit baseline is about where findings appear, not how many.

    Findings inside scripts/ are expected, because the detection strings live
    there. A finding in SKILL.md or references/ means the skill now breaks a
    rule it enforces on others, which is the thing worth catching.
    """
    scratch = os.environ.get("TMPDIR", "/tmp")
    out = os.path.join(scratch, "skill-audit-self-check.json")
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "scan_skill.py"),
         "--skill", SKILL_DIR, "--out", out, "--quiet"],
        check=True)
    import json
    with io.open(out, encoding="utf-8") as fh:
        findings = json.load(fh).get("findings", [])
    stray = [f for f in findings if not (f.get("file") or "").startswith("scripts/")]
    if stray:
        failures.append(
            "self-audit found %d finding(s) outside scripts/: %s. Fix the wording "
            "in that file rather than weakening the rule."
            % (len(stray), "; ".join("%s %s in %s" % (f["severity"], f["rule_id"],
                                                      f.get("file")) for f in stray)))
    return len(findings), len(stray)


def check_fixture_banners(failures):
    """Every planted fixture file has to be labeled as inert test data."""
    fixtures = os.path.join(HERE, "fixtures", "skills")
    for dirpath, dirnames, filenames in os.walk(fixtures):
        for name in filenames:
            if not name.endswith((".md", ".py")):
                continue
            path = os.path.join(dirpath, name)
            # Read generously: a SKILL.md banner sits after the frontmatter, and
            # one fixture has a deliberately oversized frontmatter block.
            text = io.open(path, encoding="utf-8", errors="replace").read(8000)
            if "FIXTURE - INERT TEST DATA" not in text:
                failures.append(
                    "fixture file lacks the inert-test-data banner: %s"
                    % os.path.relpath(path, REPO))


def main():
    failures = []
    check_shipped_contents(failures)
    check_rules_documented(failures)
    check_skill_frontmatter(failures)
    total, stray = check_self_audit_location(failures)
    check_fixture_banners(failures)

    print("Checked: shipped contents, rule documentation, skill frontmatter, "
          "self-audit location, fixture banners.")
    print("Self-audit baseline: %d finding(s), %d outside scripts/ (must be 0)."
          % (total, stray))

    if failures:
        print("")
        for failure in failures:
            print("FAIL: %s" % failure)
        return 1
    print("All invariants hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
