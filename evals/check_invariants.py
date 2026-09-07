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

# Importing the shipped scripts is what writes __pycache__, and writing it into
# the shipped skill directory would plant the very bytecode bundle (SEC011)
# that the self-audit below must find absent.
sys.dont_write_bytecode = True

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
    """Run one scanner over one skill directory and return the findings doc."""
    import json
    scratch = os.environ.get("TMPDIR", "/tmp")
    out = os.path.join(scratch, out_name)
    subprocess.run(
        [sys.executable, os.path.join(scanner_dir, "scan_skill.py"),
         "--skill", target_dir, "--out", out, "--quiet"],
        check=True)
    with io.open(out, encoding="utf-8") as fh:
        return json.load(fh)


def check_self_audit_clean(failures):
    """The shipped skill has to pass the audit it performs on everything else.

    A tool that grades other skills while failing its own rules has no standing.
    The scanner does not pattern-scan its own executing source, so the findings
    counted here are the ones any user would see: zero is the only acceptable
    number, and the fix is always the skill's own wording, never a weaker rule.
    """
    findings = _scan(SCRIPTS, SKILL_DIR,
                     "skill-audit-self-check.json").get("findings", [])
    if findings:
        failures.append(
            "the shipped skill does not audit clean, %d finding(s): %s. Fix the "
            "skill rather than weakening the rule."
            % (len(findings), "; ".join(
                "%s %s in %s" % (f["severity"], f["rule_id"], f.get("file"))
                for f in findings)))
    return len(findings)


def check_self_exclusion_is_identity_based(failures):
    """The self-exclusion must track content identity, never the name.

    The scanner skips its own executing source and any byte-identical copy of
    its scripts, because both are the code the user already chose to run. That
    is safe only while the test really is identity: if it ever degrades into
    "is this named skill-audit", any skill could take the name and buy silence.
    Two probes pin the boundary from both sides. An untouched copy has to come
    back with no pattern findings in scripts/ but with every skipped file named
    in the notes, so the skip is visible rather than silent. The same copy with
    one script modified has to report that script's rule tables in full, which
    is what makes vetting a fork with --skill a real check.
    """
    scratch = os.environ.get("TMPDIR", "/tmp")
    copy_dir = os.path.join(scratch, "skill-audit-copy-check", "skill-audit")
    if os.path.exists(os.path.dirname(copy_dir)):
        shutil.rmtree(os.path.dirname(copy_dir))
    shutil.copytree(SKILL_DIR, copy_dir,
                    ignore=shutil.ignore_patterns("__pycache__"))
    try:
        doc = _scan(SCRIPTS, copy_dir, "skill-audit-copy-check.json")
        identical = [f for f in doc.get("findings", [])
                     if (f.get("file") or "").startswith("scripts/")]
        if identical:
            failures.append(
                "a byte-identical copy of this skill reported pattern findings "
                "in scripts/: %s. Files equal to the running auditor's own "
                "scripts are supposed to be skipped as detector vocabulary."
                % "; ".join(sorted({f["rule_id"] for f in identical})))
        noted = [n for n in doc.get("notes", []) if "byte-identical" in n]
        if not noted:
            failures.append(
                "the scan of a byte-identical copy did not name the skipped "
                "files in its notes; the skip has to be visible, never silent.")

        # One changed byte has to void the exemption for that file.
        probe = os.path.join(copy_dir, "scripts", "scan_skill.py")
        with io.open(probe, "a", encoding="utf-8") as fh:
            fh.write("\n# fork probe: this copy differs from the running auditor\n")
        doc = _scan(SCRIPTS, copy_dir, "skill-audit-fork-check.json")
        in_scripts = [f for f in doc.get("findings", [])
                      if (f.get("file") or "").startswith("scripts/")]
        if not in_scripts:
            failures.append(
                "a modified copy of this skill scanned clean. A file that "
                "differs from the running auditor must be scanned in full, so "
                "its rule tables have to be reported. Check that the identity "
                "test compares content hashes and not skill names.")
    finally:
        shutil.rmtree(os.path.dirname(copy_dir), ignore_errors=True)
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


def check_only_the_shipped_skill_is_publishable(failures):
    """Nothing but skill-audit may reach a user through `npx skills add`.

    The skills CLI treats a repository as a collection. It walks the repo root
    one level deep and every agent skill container (`skills/`, `.claude/skills`,
    `.codex/skills`, and the rest) three levels deep, and `--full-depth`, along
    with the fallback it takes when it finds nothing, scans the whole tree. So
    every SKILL.md committed here is a candidate for someone else's machine,
    not only the one directory this project ships.

    Two things must never travel that way. `.claude/skills/ship-pr` is written
    for this repository alone, and at user level it would sit in context in
    every project while its instructions pointed at this one. The fixtures
    under evals/ matter more: several are working attack payloads, and a
    `--full-depth` install once carried all of them.

    The CLI's own exemption is `metadata.internal: true`, which it tests as
    `metadata?.internal === true`, so the value has to be an unquoted YAML
    boolean; quoted, it is a string and does not match. The test below reads
    the raw frontmatter because the parser in this repo renders both forms as
    the string "true" and cannot tell them apart.
    """
    import re
    import subprocess as _subprocess

    shipped = "skill-audit/SKILL.md"
    tracked = _subprocess.run(
        ["git", "-C", REPO, "ls-files", "*SKILL.md"],
        capture_output=True, text=True, check=True).stdout.split()
    if shipped not in tracked:
        failures.append(
            "the shipped skill is not tracked at %s, so this check cannot tell "
            "what would be published" % shipped)
        return
    if len(tracked) < 2:
        failures.append(
            "no SKILL.md besides the shipped one is tracked, so this check is "
            "proving nothing; confirm the fixtures are still committed")
        return

    def metadata_block(frontmatter):
        """The lines under a top-level `metadata:` key, and their indent.

        The flag only counts where the CLI reads it. An `internal: true`
        indented under some other key, or nested a level deeper inside
        metadata, is a different path than `metadata.internal` and would not
        exempt the skill, so the search is confined to this block.
        """
        lines = frontmatter.split("\n")
        for i, line in enumerate(lines):
            if not re.match(r"^metadata:[ \t]*(#.*)?$", line):
                continue
            block = []
            for rest in lines[i + 1:]:
                if rest.strip() and not rest[:1].isspace():
                    break
                block.append(rest)
            entries = [b for b in block if b.strip()]
            if not entries:
                return [], None
            indent = len(entries[0]) - len(entries[0].lstrip())
            return entries, indent
        return None, None

    def flag_state(frontmatter):
        """One of 'ok', 'quoted', 'continued', 'malformed', 'misparented', 'absent'.

        YAML only reads `key: value` as a mapping entry when whitespace or a
        line end follows the colon. `internal:true` is therefore the plain
        scalar "internal:true", which makes metadata a string rather than a
        record, and the installer's `metadata?.internal === true` never sees a
        flag at all. A check that accepted that spelling would approve a skill
        the CLI publishes, so it is called out separately from a value that
        parses but is not the boolean.
        """
        entries, indent = metadata_block(frontmatter)
        if entries:
            own = [e for e in entries
                   if len(e) - len(e.lstrip()) == indent and e.strip().startswith("internal:")]
            if own:
                # A plain scalar keeps going onto the following lines while
                # they are more indented, blank lines included, so
                # `internal: true` with `    false` under it is the string
                # "true false" and the installer publishes the skill. Reading
                # one physical line cannot see that, so a continuation is
                # rejected outright.
                position = entries.index(own[0])
                following = entries[position + 1:position + 2]
                if following and (len(following[0]) - len(following[0].lstrip())) > indent:
                    return "continued"
                entry = own[0].strip()
                # One rule, written the way YAML reads the line: a colon then
                # whitespace, one of the boolean tokens, and a comment only
                # where a `#` is itself preceded by whitespace. Splitting the
                # value out by hand is what let `internal:true` and
                # `internal: true#c` through, and both are strings to a real
                # parser. The three spellings are the YAML 1.2 core booleans,
                # and each was confirmed against the installer itself by
                # listing a repository that plants every shape below.
                if re.match(r"^internal:[ \t]+(?:true|True|TRUE)(?:[ \t]+#.*)?[ \t]*$",
                            entry):
                    return "ok"
                if not re.match(r"^internal:(?:[ \t]|$)", entry):
                    return "malformed"
                return "quoted"
        if re.search(r"^[ \t]+internal:", frontmatter, re.M):
            return "misparented"
        return "absent"

    reasons = {
        "quoted": ("sets metadata.internal to something other than the bare token "
                   "`true`. The CLI compares against the boolean, so anything "
                   "else is published anyway: a quoted string, an empty value, "
                   "or a `#` with no whitespace before it, which YAML keeps as "
                   "part of the scalar rather than starting a comment. Only "
                   "`true`, `True` and `TRUE` are booleans."),
        "continued": ("writes the flag with a more indented line under it. YAML "
                      "folds that into the value, so it becomes a string rather "
                      "than a boolean and the skill is published; keep the value "
                      "on one line."),
        "malformed": ("writes the flag with no space after the colon. YAML reads "
                      "`internal:true` as a plain string, so metadata is not a "
                      "mapping at all and the CLI finds no flag; write "
                      "`internal: true`."),
        "misparented": ("sets an `internal` key, but not directly under `metadata`. "
                        "The CLI reads `metadata.internal` and nothing else, so the "
                        "skill is published anyway."),
        "absent": ("would be published by `npx skills add`, which walks every skill "
                   "directory in this repo. Add `internal: true` under metadata, "
                   "unquoted, so the CLI keeps it out of user installs while it "
                   "still loads here."),
    }
    # The detector is the whole value of this check, so it is exercised before
    # it is trusted. Each case is a way a flag can look right and still leave
    # the skill publishable, which is exactly how the first version of this
    # check passed a skill whose flag sat under the wrong parent.
    probes = [
        ("metadata:\n  internal: true", "ok"),
        ('metadata:\n  version: "1"\n  internal: true', "ok"),
        ("metadata:\n  internal: true  # comment", "ok"),
        ("config:\n  internal: true", "misparented"),
        ("metadata:\n  config:\n    internal: true", "misparented"),
        ('metadata:\n  internal: "true"', "quoted"),
        ("metadata:\n  internal: 'true'", "quoted"),
        ("metadata:\n  internal:", "quoted"),
        ("metadata:\n  internal:true", "malformed"),
        ("metadata:\n  internal:true  # looks right, parses as a string", "malformed"),
        ("metadata:\n  internal: true #comment", "ok"),
        ("metadata:\n  internal: true\t# tabbed comment", "ok"),
        ("metadata:\n  internal: true#comment", "quoted"),
        ("metadata:\n  internal: true\n    false", "continued"),
        ("metadata:\n  internal: true\n\n    folded", "continued"),
        ('metadata:\n  internal: true\n  version: "1"', "ok"),
        ("metadata:\n  internal: true\n  nested:\n    a: b", "ok"),
        ("metadata:\n  internal: truthy", "quoted"),
        ("metadata:\n  internal: True", "ok"),
        ("metadata:\n  internal: TRUE", "ok"),
        ('metadata:\n  version: "1"', "absent"),
        ("name: x", "absent"),
    ]
    for frontmatter, want in probes:
        got = flag_state(frontmatter)
        if got != want:
            failures.append(
                "the publishable-skill detector read %r as %r rather than %r, so "
                "it cannot be trusted to tell a working internal flag from one "
                "the CLI would ignore" % (frontmatter, got, want))

    # The guard cuts both ways. Marking the shipped skill internal would hide
    # the one skill users are meant to get, and because the CLI only falls back
    # to a full-tree scan when it finds nothing, and everything else here is
    # internal too, the result is an install with no skills at all rather than
    # a loud failure.
    # The two directions need opposite biases. For a skill that must stay
    # unpublished, demanding the plain spelling is safe: the worst case is a
    # build failure telling the author to write it plainly. For the shipped
    # skill that strictness is the bug, because anything resolving to a true
    # `metadata.internal` hides the only skill this repo publishes and the
    # install silently carries nothing.
    #
    # Enumerating the spellings does not converge. The installer honours the
    # bare key, a double or single quoted key, the explicit `? internal` form
    # and a flow mapping written inline on the `metadata:` line, each verified
    # by listing a repo that plants them. So the rule here is not about
    # spelling at all: the shipped skill's metadata may not contain the word,
    # which no quoting or key syntax can get around. Its metadata holds a
    # version and a repository URL and has no use for it.
    shipped_text = io.open(os.path.join(REPO, shipped), encoding="utf-8").read()
    if shipped_text.startswith("---\n") and "\n---" in shipped_text:
        shipped_fm = shipped_text[4:shipped_text.index("\n---", 4)]
        region = []
        lines = shipped_fm.split("\n")
        for i, line in enumerate(lines):
            if not re.match(r"^metadata[ \t]*:", line):
                continue
            region.append(line)
            for rest in lines[i + 1:]:
                if rest.strip() and not rest[:1].isspace():
                    break
                region.append(rest)
        guilty = [r for r in region if "internal" in r.lower()]
        if guilty:
            failures.append(
                "%s mentions `internal` in its metadata (%r). Any spelling that "
                "resolves to a true `metadata.internal` hides the only skill "
                "this repo publishes, and `npx skills add` then installs nothing "
                "at all, so the shipped skill's metadata does not use the word. "
                "The flag belongs on everything else."
                % (shipped, guilty[0].strip()))
    else:
        failures.append("%s has no frontmatter to check" % shipped)

    for rel in sorted(tracked):
        if rel == shipped:
            continue
        text = io.open(os.path.join(REPO, rel), encoding="utf-8").read()
        marker = "\n---"
        if not text.startswith("---\n") or marker not in text:
            failures.append("%s has no frontmatter to carry the internal flag" % rel)
            continue
        frontmatter = text[4:text.index(marker, 4)]
        state = flag_state(frontmatter)
        if state != "ok":
            failures.append("%s %s" % (rel, reasons[state]))


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
    plugin cache and CLAUDE_CONFIG_DIR override, Codex including CODEX_HOME,
    its legacy default, and the built-in skills it ships under .system,
    OpenCode under XDG, the shared .agents and XDG agents conventions, Gemini
    CLI, Cursor, OpenClaw, and project-level directories from the working
    directory up to the repository root). Discovery then runs exactly as a
    user would run it, with no --paths, in that environment. Every probe has
    to come back, or a harness's skills have silently fallen out of the
    audit.

    Each probe also has to be credited to every harness that loads its
    directory, and only to those. Every harness home exists in the synthetic
    home, so a directory several harnesses read credits all of them, while
    the override forms are read by their own harness alone. The last probe
    reproduces an `npx skills add` install, one real copy under the shared
    convention and a symlink to it from the Claude Code directory: that has
    to be one entry, credited to both sides, never two.
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

    agents_readers = {"codex", "opencode", "gemini", "cursor", "openclaw"}
    expected = {
        # name -> every harness the entry has to be credited to
        "probe-claude-user": {"claude"},                  # $CLAUDE_CONFIG_DIR/skills
        "probe-claude-legacy": {"claude", "opencode", "cursor"},  # ~/.claude/skills
        "probe-claude-plugin": {"claude"},                # plugin cache, marketplace deep
        "probe-codex-home": {"codex"},                    # $CODEX_HOME/skills
        "probe-codex-builtin": {"codex"},                 # $CODEX_HOME/skills/.system
        "probe-codex-legacy": {"codex", "cursor"},        # ~/.codex/skills, override set
        "probe-codex-legacy-builtin": {"codex"},          # ~/.codex/skills/.system
        "probe-opencode": {"opencode"},                   # $XDG_CONFIG_HOME/opencode/skills
        "probe-agents-home": agents_readers,              # ~/.agents/skills
        "probe-agents-xdg": {"shared"},                   # $XDG_CONFIG_HOME/agents/skills
        "probe-gemini": {"gemini"},
        "probe-cursor": {"cursor"},
        "probe-claw-managed": {"openclaw"},               # ~/.openclaw/skills
        "probe-claw-legacy": {"openclaw"},                # ~/.clawdbot/skills
        "probe-claw-plugin": {"openclaw"},                # ~/.openclaw/plugin-skills
        "probe-claw-workspace": {"openclaw"},             # default agent workspace
        "probe-claw-agent": {"openclaw"},                 # a sibling agent's workspace
        # Every OpenClaw root hangs off a state directory, so the former one
        # has to carry its plugin and workspace directories too, not just its
        # skills directory.
        "probe-claw-legacy-plugin": {"openclaw"},
        "probe-claw-legacy-workspace": {"openclaw"},
        "probe-repo-root": {"codex", "opencode", "gemini", "cursor"},  # .agents/skills at the repo root
        "probe-mid-ancestor": {"codex", "cursor"},        # .codex/skills in a mid ancestor
        "probe-cwd": {"opencode"},                        # .opencode/skills in cwd
        "probe-cwd-gemini": {"gemini"},                   # .gemini/skills in cwd
        # Real copy under ~/.agents/skills, symlink from ~/.claude/skills.
        "probe-linked": {"claude", "opencode", "cursor"} | agents_readers,
    }
    # Skills a harness ships with itself carry their own scope, so a reader
    # can tell them from what the user installed.
    expected_scope = {
        "probe-codex-builtin": "builtin",
        "probe-codex-legacy-builtin": "builtin",
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
    _write_min_skill(os.path.join(codex_home, "skills", ".system", "probe-codex-builtin"),
                     "probe-codex-builtin")
    _write_min_skill(os.path.join(fake_home, ".codex", "skills", "probe-codex-legacy"),
                     "probe-codex-legacy")
    _write_min_skill(os.path.join(fake_home, ".codex", "skills", ".system",
                                  "probe-codex-legacy-builtin"),
                     "probe-codex-legacy-builtin")
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
    _write_min_skill(os.path.join(fake_home, ".openclaw", "skills", "probe-claw-managed"),
                     "probe-claw-managed")
    _write_min_skill(os.path.join(fake_home, ".clawdbot", "skills", "probe-claw-legacy"),
                     "probe-claw-legacy")
    _write_min_skill(os.path.join(fake_home, ".openclaw", "plugin-skills",
                                  "probe-claw-plugin"), "probe-claw-plugin")
    _write_min_skill(os.path.join(fake_home, ".openclaw", "workspace", "skills",
                                  "probe-claw-workspace"), "probe-claw-workspace")
    _write_min_skill(os.path.join(fake_home, ".openclaw", "workspace-ops", ".agents",
                                  "skills", "probe-claw-agent"), "probe-claw-agent")
    _write_min_skill(os.path.join(fake_home, ".clawdbot", "plugin-skills",
                                  "probe-claw-legacy-plugin"), "probe-claw-legacy-plugin")
    _write_min_skill(os.path.join(fake_home, ".clawdbot", "workspace", "skills",
                                  "probe-claw-legacy-workspace"),
                     "probe-claw-legacy-workspace")

    # The layout `npx skills add --agent claude-code codex` produces: one real
    # copy in the shared directory, and Claude Code's entry a link to it.
    _write_min_skill(os.path.join(fake_home, ".agents", "skills", "probe-linked"),
                     "probe-linked")
    link_ok = True
    try:
        os.symlink(os.path.join(fake_home, ".agents", "skills", "probe-linked"),
                   os.path.join(fake_home, ".claude", "skills", "probe-linked"))
    except OSError:
        link_ok = False
        expected.pop("probe-linked")

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
    _write_min_skill(os.path.join(leaf, ".gemini", "skills", "probe-cwd-gemini"),
                     "probe-cwd-gemini")

    env = dict(os.environ)
    env["HOME"] = fake_home
    env["USERPROFILE"] = fake_home
    env["XDG_CONFIG_HOME"] = os.path.join(fake_home, ".config")
    env["CODEX_HOME"] = codex_home
    env["CLAUDE_CONFIG_DIR"] = claude_home
    env.pop("SKILL_AUDIT_PATHS", None)
    # The probes below sit under the synthetic home, so an OpenClaw variable
    # inherited from the shell running this check would point discovery at a
    # real state directory and fail the run for reasons that have nothing to
    # do with the code under test.
    for var in ("OPENCLAW_STATE_DIR", "OPENCLAW_WORKSPACE_DIR",
                "OPENCLAW_PROFILE", "OPENCLAW_HOME"):
        env.pop(var, None)

    out = os.path.join(base, "inventory.json")
    try:
        subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "discover_skills.py"),
             "--out", out, "--quiet"],
            cwd=leaf, env=env, check=True)
        with io.open(out, encoding="utf-8") as fh:
            inventory = json.load(fh)
        found = {}
        for s in inventory["skills"]:
            found.setdefault(s["name"], []).append(s)
        for name, harnesses in sorted(expected.items()):
            entries = found.get(name) or []
            if not entries:
                failures.append(
                    "default search paths missed %s (expected under the %s "
                    "harness layout)" % (name, ", ".join(sorted(harnesses))))
                continue
            if len(entries) > 1:
                failures.append(
                    "%s was inventoried %d times; a directory reached from more "
                    "than one root has to be one entry with every reach listed "
                    "under installs" % (name, len(entries)))
                continue
            entry = entries[0]
            credited = {site.get("harness") for site in entry.get("installs") or []}
            if credited != harnesses:
                failures.append(
                    "%s was credited to %s rather than %s"
                    % (name, sorted(credited), sorted(harnesses)))
            if entry.get("harness") not in harnesses:
                failures.append(
                    "%s carries primary harness %r, which is not among the "
                    "harnesses that read it" % (name, entry.get("harness")))
            scope = expected_scope.get(name)
            if scope and (entry.get("scope") != scope or any(
                    site.get("scope") != scope for site in entry.get("installs") or [])):
                failures.append(
                    "%s was inventoried under scope %r rather than %r"
                    % (name, entry.get("scope"), scope))
        if link_ok and len(found.get("probe-linked") or []) == 1:
            reached = {site.get("path")
                       for site in found["probe-linked"][0].get("installs") or []}
            if len(reached) < 2:
                failures.append(
                    "the symlinked probe lists only %s under installs; both the "
                    "link and its target have to be recorded" % sorted(reached))
    finally:
        _shutil.rmtree(base, ignore_errors=True)


def check_shared_root_without_readers(failures):
    """A shared directory none of whose readers is present keeps its name.

    Crediting is gated on a harness being present, so a skill under the
    shared convention is never counted for a session nobody runs. With no
    harness home on the machine at all, the honest answer is the convention
    itself, and the entry has to say so rather than guess at a reader.
    """
    import json
    import shutil as _shutil

    scratch = os.environ.get("TMPDIR", "/tmp")
    base = os.path.join(scratch, "skill-audit-shared-orphan")
    if os.path.exists(base):
        _shutil.rmtree(base)
    fake_home = os.path.join(base, "home")
    _write_min_skill(os.path.join(fake_home, ".agents", "skills", "probe-orphan"),
                     "probe-orphan")
    work = os.path.join(base, "work")
    os.makedirs(os.path.join(work, ".git"), exist_ok=True)

    env = dict(os.environ)
    env["HOME"] = fake_home
    env["USERPROFILE"] = fake_home
    env["XDG_CONFIG_HOME"] = os.path.join(fake_home, ".config")
    for var in ("SKILL_AUDIT_PATHS", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
                "OPENCLAW_STATE_DIR", "OPENCLAW_WORKSPACE_DIR",
                "OPENCLAW_PROFILE", "OPENCLAW_HOME"):
        env.pop(var, None)

    out = os.path.join(base, "inventory.json")
    try:
        subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "discover_skills.py"),
             "--out", out, "--quiet"],
            cwd=work, env=env, check=True)
        with io.open(out, encoding="utf-8") as fh:
            inventory = json.load(fh)
        entries = [s for s in inventory["skills"] if s["name"] == "probe-orphan"]
        if len(entries) != 1:
            failures.append(
                "the shared-only probe was inventoried %d times rather than once"
                % len(entries))
            return
        credited = {site.get("harness") for site in entries[0].get("installs") or []}
        if credited != {"shared"} or entries[0].get("harness") != "shared":
            failures.append(
                "a skill under ~/.agents/skills on a machine with no harness "
                "present was credited to %s rather than to the shared "
                "convention; presence has to gate the credit" % sorted(credited))
    finally:
        _shutil.rmtree(base, ignore_errors=True)


def check_openclaw_legacy_state_skips_personal_skills(failures):
    """OpenClaw is credited for ~/.agents/skills only from its default state.

    OpenClaw's loader adds the personal skills root only while its
    isDefaultStateDir() holds, and that compares the state directory it
    resolved against ~/.openclaw. A machine still running from the legacy
    ~/.clawdbot fallback fails that test with nothing overridden, so it does
    not load ~/.agents/skills at all. The credit has to follow the loader:
    OpenClaw's own roots under the legacy directory count for it, and the
    shared home directory does not, so with no other reader present it keeps
    the shared label.
    """
    import json
    import shutil as _shutil

    scratch = os.environ.get("TMPDIR", "/tmp")
    base = os.path.join(scratch, "skill-audit-claw-legacy-state")
    if os.path.exists(base):
        _shutil.rmtree(base)
    fake_home = os.path.join(base, "home")
    _write_min_skill(os.path.join(fake_home, ".clawdbot", "skills", "probe-claw-only"),
                     "probe-claw-only")
    _write_min_skill(os.path.join(fake_home, ".agents", "skills", "probe-personal"),
                     "probe-personal")
    work = os.path.join(base, "work")
    os.makedirs(os.path.join(work, ".git"), exist_ok=True)

    env = dict(os.environ)
    env["HOME"] = fake_home
    env["USERPROFILE"] = fake_home
    env["XDG_CONFIG_HOME"] = os.path.join(fake_home, ".config")
    for var in ("SKILL_AUDIT_PATHS", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
                "OPENCLAW_STATE_DIR", "OPENCLAW_WORKSPACE_DIR",
                "OPENCLAW_PROFILE", "OPENCLAW_HOME"):
        env.pop(var, None)

    out = os.path.join(base, "inventory.json")
    try:
        subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "discover_skills.py"),
             "--out", out, "--quiet"],
            cwd=work, env=env, check=True)
        with io.open(out, encoding="utf-8") as fh:
            inventory = json.load(fh)
        credited = {}
        for s in inventory["skills"]:
            credited[s["name"]] = {site.get("harness")
                                   for site in s.get("installs") or []}
        if credited.get("probe-claw-only") != {"openclaw"}:
            failures.append(
                "a skill under the legacy ~/.clawdbot/skills was credited to %s "
                "rather than to OpenClaw" % sorted(credited.get("probe-claw-only") or []))
        if credited.get("probe-personal") != {"shared"}:
            failures.append(
                "a skill under ~/.agents/skills was credited to %s on a machine "
                "running OpenClaw from the legacy ~/.clawdbot fallback; OpenClaw "
                "loads that root only from ~/.openclaw, and no other reader is "
                "present" % sorted(credited.get("probe-personal") or []))
    finally:
        _shutil.rmtree(base, ignore_errors=True)


def check_backstop_not_mutable(failures):
    """A skill must not be able to talk its own findings down.

    The deterministic pass is the backstop under the reading pass, so every
    place it softens a finding is a place a payload will try to reach. Four
    softeners exist, and each one is probed here with the evasion it invites:
    the advisory downgrade with a warning word written after the command
    instead of before it, the graded delete target with the end-of-options
    marker in front of it, the environment-template exemption with a template
    named alongside the real file, and the cross-signal escalation with a
    second skill of the same name in another scope. The report pass has a
    fifth, the semantic adjudication, probed with a selector broad enough to
    carry a real finding out of the grade beside a benign one.
    """
    import scan_skill
    from build_report import apply_adjudications
    from skill_audit_lib import make_finding

    probe = {"name": "probe", "id": "unknown::probe"}

    def severities(line, rule_id):
        found = scan_skill.escalate(
            scan_skill.scan_text_rules(probe, "SKILL.md", line))
        return [f["severity"] for f in found if f["rule_id"] == rule_id]

    wipe = "rm -rf / # dangerous"
    if "critical" not in severities(wipe, "SEC008"):
        failures.append(
            "a warning word after a whole-disk delete downgraded it; the "
            "advisory cue has to precede the command it describes")

    marked = "rm -rf -- /"
    if scan_skill.rm_severity(marked) != "critical":
        failures.append(
            "a whole-disk delete written with the end-of-options marker "
            "graded as %s rather than critical; RM_RE has to consume the "
            "marker instead of capturing it as the target"
            % scan_skill.rm_severity(marked))

    mixed = "cat .env # compare with .env.example"
    if not severities(mixed, "SEC005"):
        failures.append(
            "naming a checked-in template elsewhere on the line suppressed a "
            "read of the real environment file; the exemption has to apply to "
            "the matched path, not the whole line")

    one = make_finding("SEC005", "dup", "claude-code::dup", "SKILL.md", 1,
                       "cat ~/.aws/credentials", detector="deterministic")
    two = make_finding("SEC003", "dup", "claude-code::dup::2", "SKILL.md", 1,
                       "nc probe.invalid 4444", detector="deterministic",
                       severity="medium")
    scan_skill.escalate([one, two])
    if two["severity"] != "medium":
        failures.append(
            "a finding in one skill escalated a finding in a different skill "
            "of the same name; escalate() has to group by skill_id")

    benign = make_finding("SEC008", "adj", "claude-code::adj", "SKILL.md", 12,
                          "rm -rf build", detector="deterministic",
                          severity="low")
    genuine = make_finding("SEC008", "adj", "claude-code::adj", "SKILL.md", 40,
                           "rm -rf /", detector="deterministic",
                           severity="critical")
    apply_adjudications(
        [benign, genuine],
        [{"rule_id": "SEC008", "skill": "adj", "verdict": "resolve",
          "reason": "the delete at line 12 only clears build artifacts"}],
        lambda adj: ("claude-code::adj", "adj", None))
    if genuine.get("status") == "resolved" or genuine["severity"] != "critical":
        failures.append(
            "an adjudication written for one finding also took out a second "
            "one; an ambiguous selector has to be refused")


def check_skill_ids_unique(failures):
    """Generated ids stay unique whatever the directories are named.

    Ids are the key everything downstream is grouped by, so a collision merges
    two skills and lets one inherit the other's grade. Directory names are
    attacker controlled and invalid ones stay in the inventory for auditing,
    so a name carrying the id delimiter must not be able to claim the id
    minted for a same-named skill in another scope.
    """
    import shutil as _shutil
    import discover_skills

    scratch = os.environ.get("TMPDIR", "/tmp")
    base = os.path.join(scratch, "skill-audit-id-check")
    if os.path.exists(base):
        _shutil.rmtree(base)

    scopes = ("user", "project")
    names = ("probe", "probe::2")
    for scope in scopes:
        for name in names:
            _write_min_skill(os.path.join(base, scope, name), "probe")

    try:
        inventory = discover_skills.build_inventory(
            [{"path": os.path.join(base, scope), "scope": scope,
              "harness": "claude-code"} for scope in scopes])
        ids = [s["id"] for s in inventory["skills"]]
        if len(ids) != len(scopes) * len(names):
            failures.append(
                "the id-collision probe inventoried %d skills rather than %d"
                % (len(ids), len(scopes) * len(names)))
        if len(set(ids)) != len(ids):
            failures.append(
                "discovery minted duplicate skill ids for distinct skills: %s. "
                "Check each candidate id against the ones already issued."
                % ", ".join(sorted(ids)))
    finally:
        _shutil.rmtree(base, ignore_errors=True)


def check_empty_inventory_reports_cost(failures):
    """The report must still answer "what does this cost" when nothing was found.

    The context cost section is built by iterating the per-harness groups, and
    an empty inventory produces no groups at all. That is exactly the shape
    where a loop silently emits nothing, leaving a heading and an explanation
    of the cost model with no cost anywhere under it. Zero is a real answer and
    has to be rendered as one.

    Only report.md is asserted on here. The dashboard builds its cost section
    in the browser, so its zero state cannot be checked by rendering the page;
    the guard for it lives in the page script and is exercised by hand.
    """
    import build_report

    inventory = {"skills": [], "search_paths": []}
    tax = build_report.context_tax(inventory)
    summary = {"totals": {sev: 0 for sev in ("critical", "high", "medium",
                                             "low", "info")},
               "by_skill": {}}
    markdown = build_report.render_report_md([], summary, tax, inventory, [])
    section = markdown.split("## Context cost", 1)[-1].split("\n## ", 1)[0]
    if "0 tokens" not in section:
        failures.append(
            "report.md's context cost section states no figure for an empty "
            "inventory: %r. An empty by_harness must still render a zero state."
            % section.strip())


def check_multi_harness_cost_adds_up(failures):
    """A skill loaded by two harnesses is billed to both, and the total agrees.

    The per-harness subtotals are what a reader acts on, and the pooled
    always_on_total is documented as the sum across every install, so the two
    have to stay consistent: a skill credited to two harnesses through its
    installs belongs in both subtotals and twice in the pooled total. A skill
    with no installs list is the older single-site shape and still has to be
    billed once.
    """
    import build_report

    def entry(sid, name, harness, tokens_text, installs=None):
        e = {
            "id": sid, "name": name, "harness": harness, "scope": "user",
            "path": "/x/%s/skills/%s" % (harness, name),
            "frontmatter": {"raw": {"name": name, "description": tokens_text}},
            "body": {"token_estimate": 10},
            "resource_token_estimate": 5,
        }
        if installs is not None:
            e["installs"] = installs
        return e

    shared = entry("claude::both", "both", "claude", "shared " * 40, installs=[
        {"harness": "claude", "scope": "user", "path": "/x/claude/skills/both"},
        {"harness": "codex", "scope": "user", "path": "/x/agents/skills/both"},
    ])
    only = entry("codex::alone", "alone", "codex", "alone " * 20)
    # A plugin-cache skill that a user install also reaches loads whether or
    # not the plugin is enabled, so it is not part of the plugin share; one
    # only reachable through the cache is.
    linked = entry("claude::linked", "linked", "claude", "linked " * 20, installs=[
        {"harness": "claude", "scope": "plugin", "path": "/x/claude/plugins/p/skills/linked"},
        {"harness": "claude", "scope": "user", "path": "/x/claude/skills/linked"},
    ])
    cached = entry("claude::cached", "cached", "claude", "cached " * 20, installs=[
        {"harness": "claude", "scope": "plugin", "path": "/x/claude/plugins/p/skills/cached"},
    ])
    tax = build_report.context_tax(
        {"skills": [shared, only, linked, cached], "search_paths": []})

    groups = {g["harness"]: g for g in tax["by_harness"]}
    cost_of = {r["skill"]: r["always_on_tokens"] for r in tax["rows"]}
    if set(groups) != {"claude", "codex"}:
        failures.append("multi-harness cost grouped into %s rather than claude and codex"
                        % sorted(groups))
        return
    if groups["claude"]["always_on_tokens"] != (
            cost_of["both"] + cost_of["linked"] + cost_of["cached"]):
        failures.append("the Claude Code subtotal does not carry every skill installed for it")
    if groups["codex"]["always_on_tokens"] != cost_of["both"] + cost_of["alone"]:
        failures.append("the Codex subtotal does not carry both skills installed for it")
    if groups["claude"]["skill_count"] != 3 or groups["codex"]["skill_count"] != 2:
        failures.append("per-harness skill counts do not count a shared skill for each harness")
    if groups["claude"]["plugin_count"] != 1 or \
            groups["claude"]["plugin_tokens"] != cost_of["cached"]:
        failures.append(
            "the plugin share counts %d skill(s) worth %d tokens; only the skill "
            "reachable through the plugin cache alone belongs in it, since a user "
            "install of the same directory loads whether or not the plugin is enabled"
            % (groups["claude"]["plugin_count"], groups["claude"]["plugin_tokens"]))
    total = sum(g["always_on_tokens"] for g in tax["by_harness"])
    if tax["always_on_total"] != total:
        failures.append(
            "always_on_total is %d but the subtotals sum to %d; the pooled figure "
            "is documented as the sum across every install, so a skill credited "
            "to two harnesses has to be in it twice"
            % (tax["always_on_total"], total))
    heaviest = max(g["always_on_tokens"] for g in tax["by_harness"])
    if tax["always_on_per_session"] != heaviest:
        failures.append("always_on_per_session is %d but the heaviest subtotal is %d"
                        % (tax["always_on_per_session"], heaviest))
    if len(tax["rows"]) != 4:
        failures.append("cost rows list a skill more than once; rows are per skill, "
                        "with harness_labels naming every harness")


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
    check_only_the_shipped_skill_is_publishable(failures)
    check_discovery_reach(failures)
    check_default_search_coverage(failures)
    check_shared_root_without_readers(failures)
    check_openclaw_legacy_state_skips_personal_skills(failures)
    check_skill_ids_unique(failures)
    check_backstop_not_mutable(failures)
    check_empty_inventory_reports_cost(failures)
    check_multi_harness_cost_adds_up(failures)
    check_rubric_weights(failures)

    print("Checked: shipped contents, rule documentation, skill frontmatter, "
          "self-audit cleanliness, self-exclusion scope, fixture banners, "
          "publishable skills, "
          "discovery reach, per-harness search coverage and crediting, "
          "shared-root fallback, OpenClaw legacy-state credit, id uniqueness, "
          "backstop evasions, empty-inventory cost state, multi-harness cost "
          "totals, rubric weights.")
    print("Self-audit: %d finding(s) against the running scanner (must be 0); "
          "%d finding(s) when a modified copy is scanned (must be above 0)."
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
