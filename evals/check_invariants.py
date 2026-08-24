#!/usr/bin/env python3
"""Repository invariants for skill-audit.

These are the properties that are easy to break by accident and expensive to
notice later, so they are checked mechanically rather than by memory.

Usage:
  python3 evals/check_invariants.py
"""

import io
import os
import shutil
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


def _scan(scanner_dir, target_dir, out_name):
    """Run one scanner over one skill directory and return its findings."""
    import json
    scratch = os.environ.get("TMPDIR", "/tmp")
    out = os.path.join(scratch, out_name)
    subprocess.run(
        [sys.executable, os.path.join(scanner_dir, "scan_skill.py"),
         "--skill", target_dir, "--out", out, "--quiet"],
        check=True)
    with io.open(out, encoding="utf-8") as fh:
        return json.load(fh).get("findings", [])


def check_self_audit_clean(failures):
    """The shipped skill has to pass the audit it performs on everything else.

    A tool that grades other skills while failing its own rules has no standing.
    The scanner does not pattern-scan its own executing source, so the findings
    counted here are the ones any user would see: zero is the only acceptable
    number, and the fix is always the skill's own wording, never a weaker rule.
    """
    findings = _scan(SCRIPTS, SKILL_DIR, "skill-audit-self-check.json")
    if findings:
        failures.append(
            "the shipped skill does not audit clean, %d finding(s): %s. Fix the "
            "skill rather than weakening the rule."
            % (len(findings), "; ".join(
                "%s %s in %s" % (f["severity"], f["rule_id"], f.get("file"))
                for f in findings)))
    return len(findings)


def check_self_exclusion_is_identity_based(failures):
    """A copy of this skill must still be scanned in full.

    The scanner skipping its own source is safe only while the test is "is this
    the code I am executing", decided by resolved path. If it ever degrades into
    "is this named skill-audit", any skill could take the name and buy silence.
    Copying the skill elsewhere and scanning it with the original proves the
    difference: the copy is a different path, so its rule tables get reported.
    """
    scratch = os.environ.get("TMPDIR", "/tmp")
    copy_dir = os.path.join(scratch, "skill-audit-copy-check", "skill-audit")
    if os.path.exists(os.path.dirname(copy_dir)):
        shutil.rmtree(os.path.dirname(copy_dir))
    shutil.copytree(SKILL_DIR, copy_dir,
                    ignore=shutil.ignore_patterns("__pycache__"))
    try:
        findings = _scan(SCRIPTS, copy_dir, "skill-audit-copy-check.json")
    finally:
        shutil.rmtree(os.path.dirname(copy_dir), ignore_errors=True)

    in_scripts = [f for f in findings if (f.get("file") or "").startswith("scripts/")]
    if not in_scripts:
        failures.append(
            "a separate copy of this skill scanned clean. The self-exclusion is "
            "supposed to cover only the executing scanner's own path, so a copy "
            "must still report the pattern strings in its scripts/ directory. "
            "Check that is_auditor_own_source() compares resolved paths and not "
            "skill names.")
    return len(in_scripts)


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


def check_rubric_weights(failures):
    """The rubric's stated weights and the scoring code must agree.

    The rubric is prose a model reads; judge_report.py is the arithmetic that
    turns its dimensions into a number. If they drift, E3 keeps producing a
    score while that score quietly stops meaning what the rubric says.
    """
    sys.path.insert(0, os.path.join(HERE, "graders"))
    import judge_report

    rubric_path = os.path.join(HERE, "graders", "llm_rubric.md")
    with open(rubric_path, "r", encoding="utf-8") as fh:
        mismatched, missing = judge_report.check_rubric_sync(fh.read())
    for problem in mismatched:
        failures.append("rubric weight drift, %s" % problem)
    for name in missing:
        failures.append("llm_rubric.md states no weight for the %r dimension" % name)

    total = sum(judge_report.WEIGHTS.values())
    if abs(total - 1.0) > 1e-9:
        failures.append("rubric weights sum to %.4f rather than 1.0" % total)


def main():
    failures = []
    check_shipped_contents(failures)
    check_rules_documented(failures)
    check_skill_frontmatter(failures)
    own = check_self_audit_clean(failures)
    copied = check_self_exclusion_is_identity_based(failures)
    check_fixture_banners(failures)
    check_rubric_weights(failures)

    print("Checked: shipped contents, rule documentation, skill frontmatter, "
          "self-audit cleanliness, self-exclusion scope, fixture banners, "
          "rubric weights.")
    print("Self-audit: %d finding(s) against the running scanner (must be 0); "
          "%d finding(s) when a copy is scanned (must be above 0)."
          % (own, copied))

    if failures:
        print("")
        for failure in failures:
            print("FAIL: %s" % failure)
        return 1
    print("All invariants hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
