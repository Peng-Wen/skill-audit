#!/usr/bin/env python3
"""Discover every Agent Skill reachable from this machine and build an inventory.

Searches the skill directories used by mainstream agent harnesses (Claude Code,
Codex, OpenCode, Cursor, Gemini CLI, OpenClaw, and the shared ~/.agents
convention), plus any explicit paths given on the command line or in the
SKILL_AUDIT_PATHS environment variable.

Reads files only. Never executes anything it finds.

Usage:
  python3 discover_skills.py --out inventory.json
  python3 discover_skills.py --paths /path/a:/path/b --out inventory.json
  python3 discover_skills.py --skill /path/to/one-skill --out inventory.json
"""

import argparse
import os
import platform
import sys

# Set before any local import: importing a sibling module is what writes
# __pycache__, and when these scripts run from an installed skill directory
# that cache lands inside the very bundle the audit inspects, where the next
# audit rightly reports it as opaque bytecode (SEC011).
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_audit_lib import (  # noqa: E402
    classify_file,
    count_lines,
    estimate_tokens,
    parse_frontmatter,
    read_text_capped,
    write_json,
)

# Deep enough for real plugin caches: Claude Code stores marketplace plugins at
# plugins/marketplaces/<marketplace>/{plugins,external_plugins}/<plugin>/skills/<skill>,
# five levels below the plugins root. The cap exists only to bound a walk over
# a mistakenly huge --paths root, not to encode any layout.
MAX_DEPTH = 8
MAX_SKILLS = 2000
MAX_FILES_PER_SKILL = 500

# Directories that never contain skill content worth inventorying.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}

# When listing the files a skill actually bundles, __pycache__ is not noise:
# Python loads a cached .pyc in place of its source when the recorded mtime and
# size line up, so a planted or stale cache is executable payload the source
# never shows. It stays out of SKIP_DIRS above only for the walk that looks
# for skill directories, where descending into it cannot find one.
COLLECT_SKIP_DIRS = SKIP_DIRS - {"__pycache__"}


# Project-level skill directories, relative to a directory being considered.
# The generic bare "skills" directory is deliberately absent here: it is
# checked in the working directory only (below), because matching it in every
# ancestor would sweep in unrelated directories that merely have that name.
PROJECT_SKILL_DIRS = [
    (os.path.join(".claude", "skills"), "claude"),
    (os.path.join(".codex", "skills"), "codex"),
    (os.path.join(".opencode", "skills"), "opencode"),
    (os.path.join(".agents", "skills"), "shared"),
    (os.path.join(".cursor", "skills"), "cursor"),
    (os.path.join(".gemini", "skills"), "gemini"),
]

MAX_ANCESTOR_LEVELS = 10


def _project_ancestors(cwd, home, limit=MAX_ANCESTOR_LEVELS):
    """Parent directories of cwd, nearest first, up to the repository root.

    Codex documents scanning .agents/skills in every directory from the
    working directory up to the repository root, and a skill in any parent
    loads for whoever launches there, so the audit walks the same span. The
    walk stops once it has included the repository root (the first ancestor
    holding a .git entry), and stops without including the home directory,
    its parents, or the filesystem root.
    """
    def is_or_contains(parent, target):
        return target == parent or target.startswith(os.path.join(parent, ""))

    out = []
    cur = os.path.abspath(cwd)
    home = os.path.abspath(home)
    if os.path.exists(os.path.join(cur, ".git")):
        return out
    for _ in range(limit):
        parent = os.path.dirname(cur)
        if parent == cur or is_or_contains(parent, home):
            break
        cur = parent
        out.append(cur)
        if os.path.exists(os.path.join(cur, ".git")):
            break
    return out


def _openclaw_state_dirs(home):
    """OpenClaw state directories, the one it would actually use first.

    OpenClaw takes OPENCLAW_STATE_DIR when it is set. Otherwise it prefers
    `~/.openclaw` and falls back to `~/.clawdbot`, the directory's former
    name, only when `~/.openclaw` is absent. Every root OpenClaw reads hangs
    off whichever of those wins, so a fallback has to carry its plugin and
    workspace directories too rather than only its skills directory. The ones
    that did not win are searched as well, on the same reasoning as the other
    harness-home overrides: skills installed before a move or a rename sit
    there, and an audit should surface them rather than assume the move was
    clean.

    An override naming a directory that is already a default collapses into
    one entry, so pointing OPENCLAW_STATE_DIR at `~/.openclaw` does not report
    the same root twice.
    """
    current = os.path.join(home, ".openclaw")
    legacy = os.path.join(home, ".clawdbot")
    override = (os.environ.get("OPENCLAW_STATE_DIR") or "").strip()
    if override:
        ordered = [os.path.abspath(os.path.expanduser(override)), current, legacy]
    elif not os.path.isdir(current) and os.path.isdir(legacy):
        ordered = [legacy, current]
    else:
        ordered = [current, legacy]

    out = []
    for state_dir in ordered:
        if state_dir not in out:
            out.append(state_dir)
    return out


def _openclaw_workspaces(state_dirs):
    """Agent workspace directories OpenClaw loads skills from.

    OpenClaw gives each agent a workspace and reads `<workspace>/skills` and
    `<workspace>/.agents/skills` from it, at higher precedence than anything
    user-level. The default workspace is `<state dir>/workspace`, renamed to
    `workspace-<profile>` when OPENCLAW_PROFILE names a non-default profile
    and replaced outright by OPENCLAW_WORKSPACE_DIR. Additional agents get
    their workspaces from openclaw.json, which this script does not parse, so
    every state directory is scanned for siblings matching the `workspace*`
    naming convention instead. The resolved default comes first and is
    returned whether or not it exists; the rest are returned only when they do.
    """
    override = (os.environ.get("OPENCLAW_WORKSPACE_DIR") or "").strip()
    if override:
        default = os.path.abspath(os.path.expanduser(override))
    else:
        profile = (os.environ.get("OPENCLAW_PROFILE") or "").strip()
        name = "workspace"
        if profile and profile.lower() != "default":
            name = "workspace-%s" % profile
        default = os.path.join(state_dirs[0], name)

    out = [default]
    for state_dir in state_dirs:
        try:
            siblings = sorted(os.listdir(state_dir))
        except OSError:
            continue
        for entry in siblings:
            if not entry.startswith("workspace"):
                continue
            candidate = os.path.join(state_dir, entry)
            if candidate not in out and os.path.isdir(candidate):
                out.append(candidate)
    return out


def default_search_paths():
    """Built-in skill roots for mainstream harnesses.

    Each entry is {"path", "scope", "harness"}. Paths that do not exist are
    still reported (with exists=false) so users can see what was checked.

    Three environment variables relocate harness homes and are honored the way
    the harnesses themselves honor them: CLAUDE_CONFIG_DIR for Claude Code,
    CODEX_HOME for Codex, and OPENCLAW_STATE_DIR for OpenClaw. When one is
    set, the default location is still searched as well, because skills
    installed before the move can sit there and an audit should surface them
    rather than assume the move was clean.
    """
    home = os.path.expanduser("~")
    cwd = os.getcwd()
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    claude_home = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    codex_home = os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")
    # Every OpenClaw root hangs off a state directory, and more than one can
    # hold skills, so they are resolved together rather than one root at a
    # time. The first is the one OpenClaw would use.
    openclaw_state_dirs = _openclaw_state_dirs(home)

    user_roots = [
        (os.path.join(claude_home, "skills"), "claude"),
        (os.path.join(codex_home, "skills"), "codex"),
        (os.path.join(xdg, "opencode", "skills"), "opencode"),
        (os.path.join(home, ".agents", "skills"), "shared"),
        # The skills CLI's universal install target for its "global" scope.
        (os.path.join(xdg, "agents", "skills"), "shared"),
        (os.path.join(home, ".gemini", "skills"), "gemini"),
        (os.path.join(home, ".cursor", "skills"), "cursor"),
    ]
    user_roots.extend((os.path.join(state_dir, "skills"), "openclaw")
                      for state_dir in openclaw_state_dirs)
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        user_roots.append((os.path.join(home, ".claude", "skills"), "claude"))
    if os.environ.get("CODEX_HOME"):
        user_roots.append((os.path.join(home, ".codex", "skills"), "codex"))

    paths = []
    for path, harness in user_roots:
        paths.append({"path": path, "scope": "user", "harness": harness})

    # Codex also loads administrator-managed skills from a system location.
    if os.name == "posix":
        paths.append({"path": os.path.join(os.sep, "etc", "codex", "skills"),
                      "scope": "system", "harness": "codex"})

    # OpenClaw materializes the skills its plugins ship into a directory it
    # owns outright, separate from the managed skills a user installs, and
    # loads both. It is the plugin cache's counterpart, so it is reported
    # under the same scope. The state directory OpenClaw would use is always
    # listed; a directory it has moved on from is listed only when it exists,
    # so the search-path list is not padded with roots nobody has.
    for i, state_dir in enumerate(openclaw_state_dirs):
        candidate = os.path.join(state_dir, "plugin-skills")
        if i == 0 or os.path.isdir(candidate):
            paths.append({"path": candidate, "scope": "plugin", "harness": "openclaw"})

    # An OpenClaw agent's own workspace outranks every user-level root it
    # reads, so a skill there is the one that actually loads. The resolved
    # default workspace is always listed; the others are listed only when they
    # exist, on the same reasoning as the ancestor walk below.
    for i, workspace in enumerate(_openclaw_workspaces(openclaw_state_dirs)):
        for rel in ("skills", os.path.join(".agents", "skills")):
            candidate = os.path.join(workspace, rel)
            if i == 0 or os.path.isdir(candidate):
                paths.append({"path": candidate,
                              "scope": "project", "harness": "openclaw"})

    for rel, harness in PROJECT_SKILL_DIRS:
        paths.append({"path": os.path.join(cwd, rel),
                      "scope": "project", "harness": harness})
    paths.append({"path": os.path.join(cwd, "skills"),
                  "scope": "project", "harness": "shared"})

    # Ancestors are added only when the directory actually exists, so the
    # reported search-path list stays readable: the working directory's own
    # candidates are always listed, existing or not, but a ten-level walk of
    # mostly absent parents would bury them.
    for ancestor in _project_ancestors(cwd, home):
        for rel, harness in PROJECT_SKILL_DIRS:
            candidate = os.path.join(ancestor, rel)
            if os.path.isdir(candidate):
                paths.append({"path": candidate,
                              "scope": "project", "harness": harness})

    # Claude Code plugins bundle skills inside the plugin cache. The cache has
    # carried several layouts (marketplaces/<mp>/{plugins,external_plugins}/
    # <plugin>/skills, repos/<repo>/skills, and older flat ones), so the whole
    # root is walked rather than guessing one shape. Cached-but-disabled
    # plugins are inventoried too: the cache is what the harness loads from,
    # and a skill sitting there is one toggle away from being live.
    paths.append({
        "path": os.path.join(claude_home, "plugins"),
        "scope": "plugin",
        "harness": "claude",
    })
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        paths.append({
            "path": os.path.join(home, ".claude", "plugins"),
            "scope": "plugin",
            "harness": "claude",
        })

    return paths


def resolve_paths(args, env):
    """Decide which roots to search.

    Priority: --skill (a single skill directory) > --paths / SKILL_AUDIT_PATHS
    > the built-in defaults.
    """
    if args.skill:
        return [{
            "path": os.path.abspath(os.path.expanduser(args.skill)),
            "scope": "explicit",
            "harness": "unknown",
            "single": True,
        }]

    raw = args.paths or env.get("SKILL_AUDIT_PATHS")
    if raw:
        out = []
        for part in raw.split(os.pathsep):
            part = part.strip()
            if not part:
                continue
            out.append({
                "path": os.path.abspath(os.path.expanduser(part)),
                "scope": "override",
                "harness": "unknown",
            })
        return out

    return default_search_paths()


def find_skill_dirs(root, max_depth=MAX_DEPTH, cap=MAX_SKILLS):
    """Return directories that directly contain a SKILL.md, bounded by depth.

    Symbolic links are followed, because installing a skill as a symlink into
    a harness directory is a common pattern and a walk that stops at the link
    would silently drop that skill from the audit. The visited set of resolved
    paths keeps a link cycle from looping the walk.
    """
    found = []
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return found

    visited = set()
    root_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in visited:
            dirnames[:] = []
            continue
        visited.add(real)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        depth = dirpath.rstrip(os.sep).count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        if "SKILL.md" in filenames:
            found.append(dirpath)
            # A skill directory is a leaf for discovery purposes. Nested skills
            # inside a skill are not part of the format.
            dirnames[:] = []
        if len(found) >= cap:
            break
    return sorted(found)


def collect_files(skill_dir):
    """List the files bundled with a skill, classified and sized."""
    files = []
    visited = set()
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in visited:
            dirnames[:] = []
            continue
        visited.add(real)
        dirnames[:] = sorted(d for d in dirnames if d not in COLLECT_SKIP_DIRS)
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, skill_dir)
            info = classify_file(full)
            files.append({
                "path_rel": rel,
                "bytes": info["bytes"],
                "kind": info["kind"],
                "ext": info["ext"],
            })
            if len(files) >= MAX_FILES_PER_SKILL:
                return files
    return files


def build_skill_entry(skill_dir, scope, harness):
    """Build one inventory entry for a skill directory."""
    skill_md = os.path.join(skill_dir, "SKILL.md")
    text, truncated = read_text_capped(skill_md)
    frontmatter, body, parse_error = parse_frontmatter(text)

    # The directory name is the canonical identity. The frontmatter name is
    # attacker-controlled and need not be unique, so two skills could otherwise
    # collapse into one row of the report by declaring the same name. Any
    # disagreement between the two is itself reported, as SPEC003.
    dir_name = os.path.basename(os.path.normpath(skill_dir))
    name = dir_name

    files = collect_files(skill_dir)
    total_bytes = sum(f["bytes"] for f in files)
    # Resource tokens estimate what a skill can add to context on demand, so
    # only reference and asset text counts. Scripts are executed in a
    # subprocess rather than read into the model's context, and binaries are
    # not loaded as text at all, so both are excluded from this figure.
    resource_bytes = sum(
        f["bytes"] for f in files
        if f["path_rel"] != "SKILL.md" and f["kind"] == "text"
    )

    return {
        "id": "%s::%s" % (harness, name),
        "name": name,
        "dir_name": dir_name,
        "path": skill_dir,
        "skill_md_path": skill_md,
        "harness": harness,
        "scope": scope,
        "frontmatter": {
            "raw": frontmatter,
            "parse_ok": parse_error is None,
            "parse_error": parse_error,
        },
        "body": {
            "chars": len(body),
            "lines": count_lines(body),
            "token_estimate": estimate_tokens(body),
            "truncated": truncated,
        },
        "files": files,
        "total_bytes": total_bytes,
        "resource_token_estimate": resource_bytes // 4,
    }


def build_inventory(search_paths):
    """Walk the search paths and build the full inventory document."""
    resolved_paths = []
    seen_dirs = set()
    skills = []

    for entry in search_paths:
        path = entry["path"]
        exists = os.path.isdir(path)
        resolved_paths.append({
            "path": path,
            "scope": entry["scope"],
            "harness": entry["harness"],
            "exists": exists,
        })
        if not exists:
            continue

        if entry.get("single"):
            # The path itself is expected to be a skill directory.
            candidates = [path] if os.path.isfile(os.path.join(path, "SKILL.md")) else []
        else:
            candidates = find_skill_dirs(path)

        for skill_dir in candidates:
            real = os.path.realpath(skill_dir)
            if real in seen_dirs:
                continue
            seen_dirs.add(real)
            skills.append(build_skill_entry(skill_dir, entry["scope"], entry["harness"]))

    skills.sort(key=lambda s: (s["harness"], s["scope"], s["name"], s["path"]))

    # Ids must be unique even when two distinct skills share a directory name
    # across scopes, or every consumer keyed by id pools them into one entry.
    # Counting per base name is not enough: directory names are attacker
    # controlled and invalid ones stay in the inventory, so a directory
    # literally named "foo::2" could claim the suffixed id minted for the
    # second "foo". Each candidate is therefore checked against the ids
    # already issued. The sort above is deterministic, so the result is
    # stable across runs.
    used_ids = set()
    for s in skills:
        base = "%s::%s" % (s["harness"], s["name"])
        candidate = base
        n = 1
        while candidate in used_ids:
            n += 1
            candidate = "%s::%d" % (base, n)
        used_ids.add(candidate)
        s["id"] = candidate

    return {
        "host": {
            "os": sys.platform,
            "python": platform.python_version(),
        },
        "search_paths": resolved_paths,
        "skills": skills,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inventory the Agent Skills installed on this machine.")
    parser.add_argument("--paths", help="Explicit roots to search, separated by the OS path separator.")
    parser.add_argument("--skill", help="Audit a single skill directory instead of searching roots.")
    parser.add_argument("--out", default="inventory.json", help="Where to write the inventory JSON.")
    parser.add_argument("--quiet", action="store_true", help="Suppress the human-readable summary.")
    args = parser.parse_args(argv)

    search_paths = resolve_paths(args, os.environ)
    inventory = build_inventory(search_paths)
    write_json(args.out, inventory)

    if not args.quiet:
        skills = inventory["skills"]
        searched = [p for p in inventory["search_paths"] if p["exists"]]
        print("Discovered %d skill(s) across %d existing search path(s)."
              % (len(skills), len(searched)))
        for p in inventory["search_paths"]:
            if p["exists"]:
                count = sum(1 for s in skills if s["path"].startswith(p["path"]))
                print("  %-60s %s/%s  %d skill(s)"
                      % (p["path"], p["harness"], p["scope"], count))
        print("Inventory written to %s" % args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
