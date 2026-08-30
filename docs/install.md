# Installing

## The one-liner

```bash
npx skills add Peng-Wen/skill-audit
```

That is the whole install for any harness that reads a standard skills directory.

## By hand

Copy the `skill-audit/` directory into any skills location your harness reads, such as `~/.claude/skills/`, `~/.codex/skills/`, `~/.config/opencode/skills/`, or the shared `~/.agents/skills/`.

Install it at the user level rather than per project, since it audits everything the machine can load:

```bash
rsync -a --delete skill-audit/ ~/.claude/skills/skill-audit/
```

The same command updates an existing installation, and `--delete` removes files dropped since the previous version, including any `scripts/__pycache__/` an older version left behind.
The scripts refuse to write bytecode caches, precisely so that running the audit never plants opaque `.pyc` files inside the installed bundle for the next audit to flag as SEC011.

## Verifying the installed copy

To confirm the installed copy is the one you meant to install:

```bash
diff -rq --exclude=__pycache__ skill-audit/ ~/.claude/skills/skill-audit/ && echo "in sync"
```

The scanner excludes the copy that is currently executing, decided by resolved path, and any file byte-identical to one of its own scripts, which is what a second install of this auditor is made of; never anything by name.
So you can point it at a fork you are thinking about installing and get a real audit rather than a formality, because every file that differs at all is scanned in full:

```bash
python3 skill-audit/scripts/scan_skill.py --skill ~/Downloads/some-skill-audit-fork --out findings.json
```

## Requirements

`python3`, which the bundled scripts use with the standard library only.
There is nothing else to install, and the scripts make no network requests.

If `python3` is unavailable, the skill falls back to a documented manual procedure and states plainly in the report that the deterministic scan was skipped, because manual review covers less than the scanner does.

## Where it looks for skills

By default, every user, project, and plugin skills directory used by the mainstream harnesses.
The full table of paths, and how to override the search with `--paths` or `SKILL_AUDIT_PATHS`, is in [harnesses.md](../skill-audit/references/harnesses.md).

## Once it is installed

The skill audits itself along with everything else, and grades A against its own rules.
Why the scanner skips the pattern rules for the copy that is executing, and what stops that from being a loophole, is covered in [How it works](how-it-works.md#auditing-this-skill).
