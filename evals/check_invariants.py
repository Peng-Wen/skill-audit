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


def _write_min_skill(skill_dir, name):
    os.makedirs(skill_dir, exist_ok=True)
    with io.open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
        fh.write("---\nname: %s\ndescription: Invariant probe skill. "
                 "Use when checking discovery reach.\n---\n# %s\n" % (name, name))


def check_discovery_reach(failures):
    """Discovery has to find skills the way harnesses actually store them.

    Two layouts broke silently once: plugin caches nest skills several levels
    below the root (marketplaces/<mp>/plugins/<plugin>/skills/<skill>), and
    skills installed as symlinks into a harness directory are only reachable
    when the walk follows links. Both are reproduced here synthetically so a
    depth cap or walk option cannot quietly reintroduce the miss.
    """
    import shutil as _shutil
    import discover_skills

    scratch = os.environ.get("TMPDIR", "/tmp")
    base = os.path.join(scratch, "skill-audit-discovery-check")
    if os.path.exists(base):
        _shutil.rmtree(base)
    root = os.path.join(base, "root")
    _write_min_skill(os.path.join(
        root, "marketplaces", "mp", "plugins", "plug", "skills", "deep-probe"),
        "deep-probe")
    _write_min_skill(os.path.join(base, "elsewhere", "linked-probe"), "linked-probe")

    link_ok = True
    try:
        os.symlink(os.path.join(base, "elsewhere", "linked-probe"),
                   os.path.join(root, "linked-probe"))
    except OSError:
        link_ok = False

    try:
        inventory = discover_skills.build_inventory(
            [{"path": root, "scope": "override", "harness": "unknown"}])
        names = {s["name"] for s in inventory["skills"]}
        if "deep-probe" not in names:
            failures.append(
                "discovery missed a skill nested plugin-cache deep "
                "(marketplaces/<mp>/plugins/<plugin>/skills/<skill>); check "
                "MAX_DEPTH in discover_skills.py")
        if link_ok and "linked-probe" not in names:
            failures.append(
                "discovery missed a skill installed as a symlink; check that "
                "the walk follows links")
    finally:
        _shutil.rmtree(base, ignore_errors=True)


def check_default_search_coverage(failures):
    """The default search table has to cover every documented harness layout.

    A synthetic home and project are built with one probe skill in each
    location the mainstream harnesses document (Claude Code including its
    plugin cache and CLAUDE_CONFIG_DIR override, Codex including CODEX_HOME
    and its legacy default, OpenCode under XDG, the shared .agents and XDG
    agents conventions, Gemini CLI, Cursor, OpenClaw, and project-level
    directories from the working directory up to the repository root).
    Discovery then runs exactly as a user would run it, with no --paths, in
    that environment. Every probe has to come back, or a harness's skills
    have silently fallen out of the audit.
    """
    import json
    import shutil as _shutil

    scratch = os.environ.get("TMPDIR", "/tmp")
    base = os.path.join(scratch, "skill-audit-harness-coverage")
    if os.path.exists(base):
        _shutil.rmtree(base)
    fake_home = os.path.join(base, "home")
    codex_home = os.path.join(base, "codex-home")
    claude_home = os.path.join(base, "claude-home")

    expected = {
        # name -> harness the entry should be attributed to
        "probe-claude-user": "claude",        # $CLAUDE_CONFIG_DIR/skills
        "probe-claude-legacy": "claude",      # ~/.claude/skills, override set
        "probe-claude-plugin": "claude",      # plugin cache, marketplace deep
        "probe-codex-home": "codex",          # $CODEX_HOME/skills
        "probe-codex-legacy": "codex",        # ~/.codex/skills, override set
        "probe-opencode": "opencode",         # $XDG_CONFIG_HOME/opencode/skills
        "probe-agents-home": "shared",        # ~/.agents/skills
        "probe-agents-xdg": "shared",         # $XDG_CONFIG_HOME/agents/skills
        "probe-gemini": "gemini",
        "probe-cursor": "cursor",
        "probe-claw": "openclaw",
        "probe-repo-root": "shared",          # .agents/skills at the repo root
        "probe-mid-ancestor": "codex",        # .codex/skills in a mid ancestor
        "probe-cwd": "opencode",              # .opencode/skills in cwd
    }

    _write_min_skill(os.path.join(claude_home, "skills", "probe-claude-user"),
                     "probe-claude-user")
    _write_min_skill(os.path.join(fake_home, ".claude", "skills", "probe-claude-legacy"),
                     "probe-claude-legacy")
    _write_min_skill(os.path.join(
        claude_home, "plugins", "marketplaces", "mp", "plugins", "pl",
        "skills", "probe-claude-plugin"), "probe-claude-plugin")
    _write_min_skill(os.path.join(codex_home, "skills", "probe-codex-home"),
                     "probe-codex-home")
    _write_min_skill(os.path.join(fake_home, ".codex", "skills", "probe-codex-legacy"),
                     "probe-codex-legacy")
    _write_min_skill(os.path.join(fake_home, ".config", "opencode", "skills",
                                  "probe-opencode"), "probe-opencode")
    _write_min_skill(os.path.join(fake_home, ".agents", "skills", "probe-agents-home"),
                     "probe-agents-home")
    _write_min_skill(os.path.join(fake_home, ".config", "agents", "skills",
                                  "probe-agents-xdg"), "probe-agents-xdg")
    _write_min_skill(os.path.join(fake_home, ".gemini", "skills", "probe-gemini"),
                     "probe-gemini")
    _write_min_skill(os.path.join(fake_home, ".cursor", "skills", "probe-cursor"),
                     "probe-cursor")
    _write_min_skill(os.path.join(fake_home, ".claw", "skills", "probe-claw"),
                     "probe-claw")

    # Project tree: repo-root/.agents, a mid-level ancestor, and the cwd, with
    # discovery launched from the deepest directory.
    repo = os.path.join(base, "work", "repo")
    os.makedirs(os.path.join(repo, ".git"), exist_ok=True)
    _write_min_skill(os.path.join(repo, ".agents", "skills", "probe-repo-root"),
                     "probe-repo-root")
    _write_min_skill(os.path.join(repo, "mid", ".codex", "skills", "probe-mid-ancestor"),
                     "probe-mid-ancestor")
    leaf = os.path.join(repo, "mid", "leaf")
    _write_min_skill(os.path.join(leaf, ".opencode", "skills", "probe-cwd"),
                     "probe-cwd")

    env = dict(os.environ)
    env["HOME"] = fake_home
    env["USERPROFILE"] = fake_home
    env["XDG_CONFIG_HOME"] = os.path.join(fake_home, ".config")
    env["CODEX_HOME"] = codex_home
    env["CLAUDE_CONFIG_DIR"] = claude_home
    env.pop("SKILL_AUDIT_PATHS", None)

    out = os.path.join(base, "inventory.json")
    try:
        subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "discover_skills.py"),
             "--out", out, "--quiet"],
            cwd=leaf, env=env, check=True)
        with io.open(out, encoding="utf-8") as fh:
            inventory = json.load(fh)
        found = {s["name"]: s["harness"] for s in inventory["skills"]}
        for name, harness in sorted(expected.items()):
            if name not in found:
                failures.append(
                    "default search paths missed %s (expected under the %s "
                    "harness layout)" % (name, harness))
            elif found[name] != harness:
                failures.append(
                    "%s was attributed to harness %r rather than %r"
                    % (name, found[name], harness))
    finally:
        _shutil.rmtree(base, ignore_errors=True)


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
    check_discovery_reach(failures)
    check_default_search_coverage(failures)
    check_rubric_weights(failures)

    print("Checked: shipped contents, rule documentation, skill frontmatter, "
          "self-audit cleanliness, self-exclusion scope, fixture banners, "
          "discovery reach, per-harness search coverage, rubric weights.")
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
