#!/usr/bin/env python3
"""Deterministic scanner for Agent Skills.

Applies pattern and structural rules to an inventory of skills and writes a
findings document. Pattern matching alone cannot catch natural-language
manipulation, so this scanner is one half of the audit: the agent performs a
semantic review pass as well (see references/security-review.md).

This scanner reads files as text. It never imports, runs, sources, or evaluates
anything belonging to an audited skill.

Usage:
  python3 scan_skill.py --inventory inventory.json --out scan_findings.json
  python3 scan_skill.py --paths /path/to/skills --out scan_findings.json
  python3 scan_skill.py --skill /path/to/one-skill --out scan_findings.json
"""

import argparse
import base64
import binascii
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import discover_skills  # noqa: E402
from skill_audit_lib import (  # noqa: E402
    DEFAULT_CAP_BYTES,
    load_known_skills,
    make_finding,
    normalize_name,
    osa_distance,
    read_json,
    read_text_capped,
    summarize_findings,
    typosquat_threshold,
    write_json,
)

# Limits that keep a scan bounded on machines with many large skills.
MAX_FINDINGS_PER_RULE_PER_FILE = 3
MAX_DECODED_BLOBS_PER_FILE = 20
MAX_DECODED_BYTES = 8192
LARGE_RESOURCE_BYTES = 100 * 1024
LARGE_TOTAL_BYTES = 1024 * 1024
BODY_TOKEN_LIMIT = 5000
BODY_LINE_LIMIT = 500
# The spec caps descriptions at 1024 characters, and well-built skills routinely
# use 700 to 900 of them because trigger keywords drive activation accuracy.
# Flagging at a lower number would penalize good descriptions, so COST003 fires
# only near the cap. The report's context cost table carries the per-skill
# figure for every skill, which is the more useful signal.
DESCRIPTION_SOFT_LIMIT = 900
DESCRIPTION_HARD_LIMIT = 1024
COMPATIBILITY_LIMIT = 500
NAME_LIMIT = 64

KNOWN_FRONTMATTER_KEYS = {
    "name", "description", "license", "compatibility", "metadata", "allowed-tools",
}

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _c(pattern):
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Pattern tables.
#
# Each entry is (rule_id, compiled_pattern). Escalation to a higher severity is
# handled after matching, in escalate(), where file-level context is available.
# ---------------------------------------------------------------------------

# Attempts to override or manipulate the reading agent.
INJECTION_PATTERNS = [
    _c(r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+"
       r"(?:instructions?|prompts?|rules?|directions?|guidance)"),
    _c(r"disregard\s+(?:all\s+|any\s+|your\s+)?(?:previous\s+|prior\s+)?"
       r"(?:instructions?|rules?|guidelines?|guardrails?)"),
    _c(r"do\s+not\s+(?:tell|inform|mention|reveal|disclose|notify|report)\b[^\n]{0,40}"
       r"\b(?:user|human|operator|owner)\b"),
    _c(r"without\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|operator)"),
    _c(r"keep\s+this\s+(?:secret|hidden|confidential|between\s+us)"),
    _c(r"you\s+are\s+now\s+(?:a|an|the)\s+"),
    _c(r"new\s+(?:system\s+)?instructions?\s*:"),
    _c(r"override\s+(?:your\s+|the\s+)?(?:system\s+prompt|safety|guardrails?|restrictions?)"),
    _c(r"(?:reveal|print|show|output|leak|dump|repeat)\s+(?:your\s+|the\s+)?system\s+prompt"),
    _c(r"<\s*(?:system|important[_\- ]instructions?|admin)\s*>"),
    _c(r"this\s+(?:message|instruction)\s+is\s+from\s+(?:the\s+)?"
       r"(?:system|administrator|anthropic|openai)"),
]

# Second-person directives aimed at the agent rather than at a human reader.
AGENT_DIRECTIVE_PATTERNS = [
    _c(r"\byou\s+must\b"),
    _c(r"\byou\s+(?:should\s+)?always\b"),
    _c(r"\bbefore\s+(?:you\s+)?(?:respond|responding|answering|replying)\b"),
    _c(r"\bas\s+the\s+(?:assistant|agent|ai|model)\b"),
    _c(r"\byour\s+instructions?\s+(?:are|is)\b"),
    _c(r"\balways\s+run\b"),
    _c(r"\bsilently\b"),
]

# Sending local data to an outside host.
EXFIL_SEND_PATTERNS = [
    _c(r"curl\s[^\n|]*(?:-d\b|--data\b|--data-\w+|-F\b|--form\b|-T\b|--upload-file)"),
    _c(r"wget\s[^\n|]*--post-(?:data|file)"),
    _c(r"requests\.(?:post|put|patch)\s*\("),
    _c(r"fetch\s*\([^\n]*method\s*:\s*[\"']POST"),
    _c(r"urlopen\s*\([^\n]*data\s*="),
    _c(r"\bnc\s+(?:-\w+\s+)*[\w.\-]+\s+\d+"),
]

EXFIL_HOST_PATTERNS = [
    _c(r"webhook\.site"),
    _c(r"hooks\.slack\.com/services"),
    _c(r"discord(?:app)?\.com/api/webhooks"),
    _c(r"pastebin\.com"),
    _c(r"requestb(?:in|ucket)"),
    _c(r"\.ngrok(?:-free)?\.(?:io|app)"),
    _c(r"\bcollector\.[\w.\-]*example\.invalid"),
]

URL_RE = _c(r"https?://[^\s\"'<>)\]]+")

PIPE_TO_SHELL_PATTERNS = [
    _c(r"(?:curl|wget)\s[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|d|c)?sh\b"),
    _c(r"(?:curl|wget)\s[^\n]*\|\s*python[0-9.]*\b"),
    _c(r"(?:ba)?sh\s+<\(\s*(?:curl|wget)"),
    _c(r"eval\s+\"?\$\("),
    _c(r"\biex\s*\(\s*(?:new-object|iwr|invoke-)"),
]

CREDENTIAL_PATH_PATTERNS = [
    _c(r"~?/?\.aws/credentials"),
    _c(r"\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)"),
    _c(r"\bid_rsa\b"),
    _c(r"~?/?\.netrc\b"),
    _c(r"~?/?\.config/gh/hosts\.yml"),
    _c(r"~?/?\.docker/config\.json"),
    _c(r"security\s+find-(?:generic|internet)-password"),
    _c(r"login\.keychain"),
    _c(r"~?/?\.claude\.json\b"),
    _c(r"~?/?\.config/gcloud/[\w.]*credentials"),
    _c(r"(?:cat|cp|mv|curl|open|read|send|upload|exfil\w*)\b[^\n]{0,40}\.env\b"),
]

SECRET_ASSIGN_PATTERNS = [
    _c(r"(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)"
       r"\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"),
]

DESTRUCTIVE_PATTERNS = [
    _c(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\$HOME|\$\{HOME\})(?:\s|/?$|/\*)"),
    _c(r"rm\s+-[a-z]*f[a-z]*r[a-z]*\s+(?:/|~|\$HOME|\$\{HOME\})(?:\s|/?$|/\*)"),
    _c(r"\brm\s+-[a-z]*r[a-z]*f\b"),
    _c(r"\bsudo\s+rm\b"),
    _c(r"\bdd\s+[^\n]*of=/dev/"),
    _c(r"\bmkfs(?:\.\w+)?\s"),
    _c(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    _c(r"chmod\s+-R\s+777"),
    _c(r"git\s+push\s[^\n]*--force(?!-with-lease)"),
]

HOME_WIPE_PATTERNS = [
    _c(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\$HOME|\$\{HOME\})(?:\s|/?$|/\*)"),
    _c(r"rm\s+-[a-z]*f[a-z]*r[a-z]*\s+(?:/|~|\$HOME|\$\{HOME\})(?:\s|/?$|/\*)"),
    _c(r"\bdd\s+[^\n]*of=/dev/"),
    _c(r"\bmkfs(?:\.\w+)?\s"),
]

# Persistence requires a write or install context. Merely naming a startup file
# is what a skill about service management legitimately does; writing to one is
# how a skill arranges to keep running after the task ends.
_WRITE_CONTEXT = r"(?:>>?|\bcp\b|\bmv\b|\btee\b|\bln\s+-s|\becho\b[^\n]*>|\bwrite_text\b|open\s*\([^\n]*[\"']w)"

PERSISTENCE_PATTERNS = [
    _c(r">>?\s*[^\n]{0,40}\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b"),
    _c(r"\bcrontab\s+-(?:e|l\s*\||\s*<)"),
    _c(r"launchctl\s+(?:load|bootstrap|enable)"),
    _c(_WRITE_CONTEXT + r"[^\n]{0,60}LaunchAgents/"),
    _c(r"systemctl\s+(?:enable|--user\s+enable)"),
    _c(_WRITE_CONTEXT + r"[^\n]{0,60}\.git/hooks/"),
    _c(r"\.git/hooks/(?:pre|post)-\w+[^\n]{0,20}(?:<<|chmod\s+\+x)"),
    _c(_WRITE_CONTEXT + r"[^\n]{0,60}\.claude/settings(?:\.local)?\.json"),
]

REMOTE_INSTRUCTION_PATTERNS = [
    _c(r"(?:fetch|download|curl|wget|retrieve)\b[^\n]{0,60}\b(?:and|then)\b[^\n]{0,30}"
       r"\b(?:follow|execute|run|obey|apply|do)\b"),
    _c(r"(?:follow|obey|apply|read)\s+(?:the\s+)?instructions?\s+(?:at|from|in|on)\s+https?://"),
    _c(r"read\s+https?://[^\s]+\s+and\s+(?:follow|do|apply)"),
]

DYNAMIC_EXEC_PATTERNS = [
    _c(r"\beval\s*\("),
    _c(r"\bexec\s*\("),
    _c(r"\bos\.system\s*\("),
    _c(r"subprocess\.\w+\([^\n]*shell\s*=\s*True"),
    _c(r"\bnew\s+Function\s*\("),
    _c(r"child_process\.\w*exec"),
]

INTERPOLATION_HINT = _c(r"(?:f[\"']|\.format\s*\(|%\s*[\(\w]|\+\s*\w+|\$\{|`\$\{)")

UNPINNED_PATTERNS = [
    _c(r"@latest\b"),
    _c(r"raw\.githubusercontent\.com/[^\s/]+/[^\s/]+/(?:main|master)/"),
    _c(r"(?:curl|wget)\s[^\n]*/(?:main|master)/[^\s]+"),
]

FORCE_LOAD_PATTERNS = [
    _c(r"always\s+read\s+(?:all\s+)?(?:the\s+)?(?:files?|references?)"),
    _c(r"read\s+(?:all|every)\s+(?:the\s+)?files?\s+in\s+(?:the\s+)?references?"),
    _c(r"load\s+(?:all|every)\s+reference"),
]

OFFICIAL_CLAIM_PATTERNS = [
    _c(r"\b(?:the\s+)?official\b"),
    _c(r"\bverified\s+(?:by|publisher|skill)\b"),
    _c(r"\bendorsed\s+by\b"),
    _c(r"\bauthori[sz]ed\s+(?:by|version)\b"),
]

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HEX_BLOB_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){30,}\b")
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")

# Pattern groups applied line by line to every text file of a skill.
LINE_RULES = [
    ("SEC001", INJECTION_PATTERNS),
    ("SEC003", EXFIL_SEND_PATTERNS),
    ("SEC004", PIPE_TO_SHELL_PATTERNS),
    ("SEC005", CREDENTIAL_PATH_PATTERNS),
    ("SEC006", SECRET_ASSIGN_PATTERNS),
    ("SEC008", DESTRUCTIVE_PATTERNS),
    ("SEC009", PERSISTENCE_PATTERNS),
    ("SEC012", REMOTE_INSTRUCTION_PATTERNS),
    ("SEC013", DYNAMIC_EXEC_PATTERNS),
    ("TRUST004", UNPINNED_PATTERNS),
]


def _matches_any(patterns, text):
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m
    return None


def _line_of(text, index):
    return text.count("\n", 0, index) + 1


def _snippet(line):
    return line.strip()


# ---------------------------------------------------------------------------
# Per-file text rules.
# ---------------------------------------------------------------------------

def scan_text_rules(skill, rel_path, text):
    """Apply line-oriented pattern rules to one text file."""
    findings = []
    counts = {}
    name = skill["name"]
    sid = skill["id"]

    lines = text.split("\n")
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        for rule_id, patterns in LINE_RULES:
            key = (rule_id, rel_path)
            if counts.get(key, 0) >= MAX_FINDINGS_PER_RULE_PER_FILE:
                continue
            m = _matches_any(patterns, line)
            if not m:
                continue
            counts[key] = counts.get(key, 0) + 1
            findings.append(make_finding(
                rule_id, name, sid, rel_path, lineno, _snippet(line),
                detector="deterministic"))

    # Exfiltration hosts are worth flagging even without an explicit send verb.
    host_counts = 0
    for lineno, line in enumerate(lines, start=1):
        if host_counts >= MAX_FINDINGS_PER_RULE_PER_FILE:
            break
        m = _matches_any(EXFIL_HOST_PATTERNS, line)
        if m:
            host_counts += 1
            findings.append(make_finding(
                "SEC003", name, sid, rel_path, lineno, _snippet(line),
                detector="deterministic",
                recommendation="Remove the reference to this collection endpoint. "
                               "Skills must not send local data to outside hosts."))

    findings.extend(scan_hidden_text(skill, rel_path, text))
    findings.extend(scan_cross_file(skill, rel_path, text))
    return findings


def scan_hidden_text(skill, rel_path, text):
    """SEC002: text hidden from a human reader.

    A plain HTML comment is ordinary Markdown, so a comment alone is not a
    finding. What matters is a comment that carries instructions, and any
    zero-width character, which has no legitimate use in skill text.
    """
    findings = []
    name = skill["name"]
    sid = skill["id"]

    for m in HTML_COMMENT_RE.finditer(text):
        content = m.group(1)
        if not content.strip():
            continue
        injection = _matches_any(INJECTION_PATTERNS, content)
        directive = _matches_any(AGENT_DIRECTIVE_PATTERNS, content)
        if not injection and not directive:
            continue
        severity = "critical" if injection else "high"
        findings.append(make_finding(
            "SEC002", name, sid, rel_path, _line_of(text, m.start()),
            "hidden comment: " + " ".join(content.split())[:180],
            detector="deterministic", severity=severity))
        if len(findings) >= MAX_FINDINGS_PER_RULE_PER_FILE:
            break

    zw = ZERO_WIDTH_RE.search(text)
    if zw:
        findings.append(make_finding(
            "SEC002", name, sid, rel_path, _line_of(text, zw.start()),
            "zero-width character U+%04X present in file text" % ord(zw.group(0)),
            detector="deterministic"))

    return findings


def scan_cross_file(skill, rel_path, text):
    """SEC010: agent-directed instructions living outside SKILL.md.

    Splitting behavior across files, with a benign SKILL.md and the real
    instructions in a reference or script, is a known evasion pattern.
    """
    if rel_path == "SKILL.md":
        return []
    m = _matches_any(AGENT_DIRECTIVE_PATTERNS, text)
    if not m:
        return []
    injection = _matches_any(INJECTION_PATTERNS, text)
    # Quote the whole line the match sits on. Slicing a fixed window around the
    # match produced evidence that began mid-word and read as garbled.
    lineno = _line_of(text, m.start())
    line = text.split("\n")[lineno - 1]
    return [make_finding(
        "SEC010", skill["name"], skill["id"], rel_path, lineno,
        "instructions addressed to the agent outside SKILL.md: " + _snippet(line),
        detector="deterministic",
        severity="high" if injection else "medium")]


def decode_and_rescan(skill, rel_path, text):
    """SEC007: decode one level of encoding and re-run the dangerous patterns.

    Reporting "this file contains base64" is weak. Reporting "this base64
    decodes to a pipe-to-shell command" is actionable, so decode once and look.
    """
    findings = []
    name = skill["name"]
    sid = skill["id"]
    blobs = 0

    candidates = []
    for m in BASE64_BLOB_RE.finditer(text):
        candidates.append(("base64", m))
    for m in HEX_BLOB_RE.finditer(text):
        candidates.append(("hex", m))

    for kind, m in candidates:
        if blobs >= MAX_DECODED_BLOBS_PER_FILE:
            break
        blob = m.group(0)
        blobs += 1
        decoded = ""
        try:
            if kind == "base64":
                pad = "=" * (-len(blob) % 4)
                raw = base64.b64decode(blob + pad, validate=True)
            else:
                raw = binascii.unhexlify(blob[:len(blob) - len(blob) % 2])
        except (binascii.Error, ValueError):
            continue
        if not raw or len(raw) > MAX_DECODED_BYTES:
            raw = raw[:MAX_DECODED_BYTES]
        decoded = raw.decode("utf-8", errors="replace")

        # Decoded content that is mostly unprintable is not readable payload.
        printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\t")
        if not decoded or printable / max(1, len(decoded)) < 0.85:
            continue

        dangerous = None
        for rule_id, patterns in LINE_RULES:
            hit = _matches_any(patterns, decoded)
            if hit:
                dangerous = (rule_id, hit)
                break
        if dangerous is None:
            hit = _matches_any(EXFIL_HOST_PATTERNS, decoded)
            if hit:
                dangerous = ("SEC003", hit)

        lineno = _line_of(text, m.start())
        if dangerous:
            rule_id, hit = dangerous
            findings.append(make_finding(
                "SEC007", name, sid, rel_path, lineno,
                "%s blob decodes to: %s" % (kind, " ".join(decoded.split())[:160]),
                detector="deterministic", severity="critical"))
            findings.append(make_finding(
                rule_id, name, sid, rel_path, lineno,
                "found in decoded %s content: %s" % (kind, " ".join(decoded.split())[:160]),
                detector="deterministic"))
        elif kind == "base64" and len(blob) >= 80:
            findings.append(make_finding(
                "SEC007", name, sid, rel_path, lineno,
                "%s blob of %d characters decodes to text" % (kind, len(blob)),
                detector="deterministic", severity="low"))

    return findings


# ---------------------------------------------------------------------------
# Structural rules.
# ---------------------------------------------------------------------------

def check_spec(skill):
    """SPEC rules: conformance with the Agent Skills format."""
    findings = []
    name = skill["name"]
    sid = skill["id"]
    fm = skill["frontmatter"]
    raw = fm.get("raw") or {}

    def add(rule_id, evidence, severity=None):
        findings.append(make_finding(
            rule_id, name, sid, "SKILL.md", None, evidence,
            detector="deterministic", severity=severity))

    if not fm.get("parse_ok") or not raw:
        add("SPEC001", "frontmatter problem: %s" % (fm.get("parse_error") or "no fields parsed"))
        # Without frontmatter the remaining field checks have nothing to inspect.
        if not raw:
            return findings

    fm_name = raw.get("name")
    description = raw.get("description")

    if not fm_name:
        add("SPEC002", "required field 'name' is missing")
    if not description:
        add("SPEC002", "required field 'description' is missing")

    if fm_name:
        if fm_name != skill["dir_name"]:
            add("SPEC003", "frontmatter name '%s' does not match directory name '%s'"
                % (fm_name, skill["dir_name"]))
        if len(fm_name) > NAME_LIMIT:
            add("SPEC004", "name is %d characters, the limit is %d" % (len(fm_name), NAME_LIMIT))
        elif not NAME_RE.match(fm_name):
            add("SPEC004", "name '%s' is not lowercase alphanumeric with single hyphens" % fm_name)

    if isinstance(description, str) and description:
        if len(description) > DESCRIPTION_HARD_LIMIT:
            add("SPEC005", "description is %d characters, the limit is %d"
                % (len(description), DESCRIPTION_HARD_LIMIT))
    elif "description" in raw:
        add("SPEC005", "description is empty")

    compat = raw.get("compatibility")
    if isinstance(compat, str) and len(compat) > COMPATIBILITY_LIMIT:
        add("SPEC006", "compatibility is %d characters, the limit is %d"
            % (len(compat), COMPATIBILITY_LIMIT))

    metadata = raw.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        add("SPEC007", "metadata is not a mapping")
    elif isinstance(metadata, dict):
        bad = [k for k, v in metadata.items() if not isinstance(v, str)]
        if bad:
            add("SPEC007", "metadata values are not all strings: %s" % ", ".join(sorted(bad)))

    tools = raw.get("allowed-tools")
    if tools is not None and not isinstance(tools, (str, list)):
        add("SPEC010", "allowed-tools is neither a string nor a list")
    elif isinstance(tools, str) and tools.strip() == "":
        add("SPEC010", "allowed-tools is present but empty")

    for key in sorted(raw.keys()):
        if key not in KNOWN_FRONTMATTER_KEYS:
            add("SPEC009", "unknown frontmatter key '%s'" % key)

    findings.extend(check_references(skill))
    return findings


def check_references(skill):
    """SPEC008: relative links that are broken or nested too deeply."""
    findings = []
    text, _ = read_text_capped(skill["skill_md_path"])
    seen = set()
    for m in MD_LINK_RE.finditer(text):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        clean = target.split("#")[0].strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        full = os.path.normpath(os.path.join(skill["path"], clean))
        lineno = _line_of(text, m.start())
        if not os.path.exists(full):
            findings.append(make_finding(
                "SPEC008", skill["name"], skill["id"], "SKILL.md", lineno,
                "reference '%s' does not exist" % clean,
                detector="deterministic", severity="medium"))
        elif clean.count("/") > 1:
            findings.append(make_finding(
                "SPEC008", skill["name"], skill["id"], "SKILL.md", lineno,
                "reference '%s' is more than one level deep" % clean,
                detector="deterministic"))
    return findings


def check_cost(skill):
    """COST rules: what this skill charges against the context budget."""
    findings = []
    name = skill["name"]
    sid = skill["id"]
    body = skill["body"]
    raw = skill["frontmatter"].get("raw") or {}

    if body["token_estimate"] > BODY_TOKEN_LIMIT:
        findings.append(make_finding(
            "COST001", name, sid, "SKILL.md", None,
            "body is about %d tokens, above the recommended %d"
            % (body["token_estimate"], BODY_TOKEN_LIMIT),
            detector="deterministic"))

    if body["lines"] > BODY_LINE_LIMIT:
        findings.append(make_finding(
            "COST002", name, sid, "SKILL.md", None,
            "SKILL.md body is %d lines, above the recommended %d"
            % (body["lines"], BODY_LINE_LIMIT),
            detector="deterministic"))

    description = raw.get("description")
    if isinstance(description, str) and len(description) > DESCRIPTION_SOFT_LIMIT:
        findings.append(make_finding(
            "COST003", name, sid, "SKILL.md", None,
            "description is %d characters and is loaded at all times" % len(description),
            detector="deterministic"))

    body_text, _ = read_text_capped(skill["skill_md_path"])
    force_load = _matches_any(FORCE_LOAD_PATTERNS, body_text)

    for f in skill["files"]:
        if f["path_rel"] == "SKILL.md" or f["kind"] == "binary":
            continue
        if f["bytes"] > LARGE_RESOURCE_BYTES:
            findings.append(make_finding(
                "COST004", name, sid, f["path_rel"], None,
                "bundled file is %d KB (about %d tokens if loaded)"
                % (f["bytes"] // 1024, f["bytes"] // 4),
                detector="deterministic",
                severity="medium" if force_load else "low"))

    if skill["total_bytes"] > LARGE_TOTAL_BYTES:
        findings.append(make_finding(
            "COST005", name, sid, None, None,
            "skill bundle totals %d KB" % (skill["total_bytes"] // 1024),
            detector="deterministic"))

    return findings


def check_quality_solo(skill):
    """QUALITY rules that need only this skill."""
    findings = []
    name = skill["name"]
    sid = skill["id"]
    raw = skill["frontmatter"].get("raw") or {}
    description = raw.get("description")

    if isinstance(description, str) and description:
        lowered = description.lower()
        if len(description) < 40:
            findings.append(make_finding(
                "QUAL001", name, sid, "SKILL.md", None,
                "description is only %d characters and may not trigger reliably"
                % len(description),
                detector="deterministic"))
        elif "when" not in lowered:
            findings.append(make_finding(
                "QUAL001", name, sid, "SKILL.md", None,
                "description does not say when to use the skill",
                detector="deterministic"))

    tools = raw.get("allowed-tools")
    if tools:
        entries = tools.split() if isinstance(tools, str) else list(tools)
        broad = [t for t in entries
                 if t.lower() in ("bash", "shell", "terminal", "execute", "run", "*")]
        if broad:
            findings.append(make_finding(
                "QUAL003", name, sid, "SKILL.md", None,
                "allowed-tools grants unrestricted %s (full list: %s)"
                % (", ".join(broad), " ".join(entries)),
                detector="deterministic"))

    return findings


def check_binaries(skill):
    """SEC011: opaque executables shipped inside a skill."""
    findings = []
    for f in skill["files"]:
        if f["kind"] != "binary":
            continue
        if f["ext"] in (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".webp"):
            continue
        findings.append(make_finding(
            "SEC011", skill["name"], skill["id"], f["path_rel"], None,
            "binary file of %d bytes bundled with the skill" % f["bytes"],
            detector="deterministic"))
    return findings


# ---------------------------------------------------------------------------
# Cross-skill rules.
# ---------------------------------------------------------------------------

def check_typosquat(inventory, known_names):
    """TRUST001: names that sit one small edit away from a well-known skill."""
    findings = []
    skills = inventory["skills"]
    installed = [(normalize_name(s["name"]), s) for s in skills]

    for norm, skill in installed:
        if not norm:
            continue
        threshold = typosquat_threshold(norm)
        for target in sorted(known_names):
            if norm == target:
                continue
            distance = osa_distance(norm, target)
            if 0 < distance <= threshold:
                findings.append(make_finding(
                    "TRUST001", skill["name"], skill["id"], "SKILL.md", None,
                    "name '%s' is %d edit(s) from the well-known skill '%s'"
                    % (skill["name"], distance, target),
                    detector="deterministic"))
                break

    # Two installed skills with nearly identical names are also worth a look.
    for i in range(len(installed)):
        for j in range(i + 1, len(installed)):
            a_norm, a = installed[i]
            b_norm, b = installed[j]
            if not a_norm or not b_norm or a_norm == b_norm:
                continue
            threshold = min(typosquat_threshold(a_norm), typosquat_threshold(b_norm))
            distance = osa_distance(a_norm, b_norm)
            if 0 < distance <= threshold:
                findings.append(make_finding(
                    "TRUST001", b["name"], b["id"], "SKILL.md", None,
                    "name '%s' is %d edit(s) from another installed skill '%s'"
                    % (b["name"], distance, a["name"]),
                    detector="deterministic", severity="medium"))
    return findings


def check_impersonation(inventory):
    """TRUST002: claims of official status without provenance to back them."""
    findings = []
    for skill in inventory["skills"]:
        raw = skill["frontmatter"].get("raw") or {}
        description = raw.get("description")
        if not isinstance(description, str) or not description:
            continue
        claim = _matches_any(OFFICIAL_CLAIM_PATTERNS, description)
        if not claim:
            continue
        has_license = bool(raw.get("license")) or _has_license_file(skill)
        if has_license:
            continue
        findings.append(make_finding(
            "TRUST002", skill["name"], skill["id"], "SKILL.md", None,
            "description claims official or verified status ('%s') but the skill "
            "carries no license or provenance" % claim.group(0).strip(),
            detector="deterministic"))
    return findings


def _has_license_file(skill):
    for f in skill["files"]:
        base = os.path.basename(f["path_rel"]).lower()
        if base.startswith("license") or base.startswith("copying"):
            return True
    return False


def check_license(inventory):
    """TRUST003: no stated license."""
    findings = []
    for skill in inventory["skills"]:
        raw = skill["frontmatter"].get("raw") or {}
        if raw.get("license") or _has_license_file(skill):
            continue
        findings.append(make_finding(
            "TRUST003", skill["name"], skill["id"], "SKILL.md", None,
            "no license field in frontmatter and no license file in the skill directory",
            detector="deterministic"))
    return findings


_WORD_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "for", "in", "on", "with", "when",
    "use", "this", "that", "it", "is", "are", "be", "by", "as", "from", "at",
    "user", "asks", "skill", "using", "into", "your", "you",
}


def _description_tokens(description):
    words = _WORD_RE.findall(description.lower())
    return {w for w in words if w not in _STOPWORDS and len(w) > 2}


def check_description_collisions(inventory, threshold=0.6):
    """QUAL002: two skills whose descriptions compete for the same triggers."""
    findings = []
    entries = []
    for skill in inventory["skills"]:
        raw = skill["frontmatter"].get("raw") or {}
        description = raw.get("description")
        if isinstance(description, str) and len(description) >= 20:
            entries.append((skill, _description_tokens(description)))

    for i in range(len(entries)):
        for j in range(i + 1, len(entries)):
            a, ta = entries[i]
            b, tb = entries[j]
            if not ta or not tb:
                continue
            overlap = len(ta & tb)
            union = len(ta | tb)
            similarity = overlap / union if union else 0.0
            if similarity >= threshold:
                findings.append(make_finding(
                    "QUAL002", a["name"], a["id"], "SKILL.md", None,
                    "description overlaps '%s' at %.0f%% token similarity"
                    % (b["name"], similarity * 100),
                    detector="deterministic",
                    severity="medium" if similarity >= 0.85 else "low"))
    return findings


# ---------------------------------------------------------------------------
# Severity escalation using file-level context.
# ---------------------------------------------------------------------------

def escalate(findings):
    """Raise severities where several signals in one file reinforce each other."""
    by_file = {}
    for f in findings:
        by_file.setdefault((f["skill"], f["file"]), []).append(f)

    for (_, _), group in by_file.items():
        rules = {f["rule_id"] for f in group}
        for f in group:
            if f["rule_id"] == "SEC005" and ("SEC003" in rules or "SEC004" in rules):
                f["severity"] = "critical"
                f["evidence"] += " (in a file that also sends data off the machine)"
            elif f["rule_id"] == "SEC011" and "SEC003" in rules:
                f["severity"] = "high"
            elif f["rule_id"] == "SEC001" and "SEC002" in rules:
                f["severity"] = "critical"

    for f in findings:
        if f["rule_id"] == "SEC008" and _matches_any(HOME_WIPE_PATTERNS, f["evidence"]):
            f["severity"] = "critical"
        elif f["rule_id"] == "SEC013" and INTERPOLATION_HINT.search(f["evidence"]):
            f["severity"] = "high"
            f["evidence"] += " (with interpolated input)"

    return findings


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------

def scan_inventory(inventory, cap_bytes=DEFAULT_CAP_BYTES, known_names=None):
    """Run every deterministic rule over an inventory of skills."""
    findings = []
    known_names = known_names if known_names is not None else set()

    for skill in inventory["skills"]:
        findings.extend(check_spec(skill))
        findings.extend(check_cost(skill))
        findings.extend(check_quality_solo(skill))
        findings.extend(check_binaries(skill))

        for f in skill["files"]:
            if f["kind"] == "binary":
                continue
            full = os.path.join(skill["path"], f["path_rel"])
            text, _ = read_text_capped(full, cap_bytes)
            if not text:
                continue
            findings.extend(scan_text_rules(skill, f["path_rel"], text))
            findings.extend(decode_and_rescan(skill, f["path_rel"], text))

    findings.extend(check_typosquat(inventory, known_names))
    findings.extend(check_impersonation(inventory))
    findings.extend(check_license(inventory))
    findings.extend(check_description_collisions(inventory))

    escalate(findings)
    findings = dedupe(findings)
    findings.sort(key=lambda f: (
        f["skill"],
        -{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[f["severity"]],
        f["rule_id"],
        f["file"] or "",
        f["line"] or 0,
    ))
    return findings


def dedupe(findings):
    """Collapse identical findings that several rules produced for one line."""
    seen = {}
    out = []
    for f in findings:
        key = (f["rule_id"], f["skill"], f["file"], f["line"])
        if key in seen:
            existing = seen[key]
            order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if order[f["severity"]] > order[existing["severity"]]:
                existing["severity"] = f["severity"]
                existing["evidence"] = f["evidence"]
            continue
        seen[key] = f
        out.append(f)
    return out


def load_inventory(args):
    """Get an inventory either from a file or by discovering one now."""
    if args.inventory:
        return read_json(args.inventory)
    ns = argparse.Namespace(paths=args.paths, skill=args.skill)
    search_paths = discover_skills.resolve_paths(ns, os.environ)
    return discover_skills.build_inventory(search_paths)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run deterministic security, spec, cost, and quality rules over installed skills.")
    parser.add_argument("--inventory", help="Path to an inventory.json produced by discover_skills.py.")
    parser.add_argument("--paths", help="Roots to search if no inventory is given.")
    parser.add_argument("--skill", help="Scan a single skill directory.")
    parser.add_argument("--out", default="scan_findings.json", help="Where to write findings JSON.")
    parser.add_argument("--cap-bytes", type=int, default=DEFAULT_CAP_BYTES,
                        help="Maximum bytes read per file.")
    parser.add_argument("--known-skills", help="Override the known-skill-names list.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    known_path = args.known_skills or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "known_skills.txt")
    known_names = load_known_skills(known_path)

    inventory = load_inventory(args)
    findings = scan_inventory(inventory, args.cap_bytes, known_names)
    summary = summarize_findings(findings, [s["name"] for s in inventory["skills"]])

    write_json(args.out, {
        "source": "deterministic",
        "findings": findings,
        "summary": summary,
    })

    if not args.quiet:
        totals = summary["totals"]
        print("Scanned %d skill(s). Findings: %d critical, %d high, %d medium, %d low, %d info."
              % (len(inventory["skills"]), totals["critical"], totals["high"],
                 totals["medium"], totals["low"], totals["info"]))
        print("Findings written to %s" % args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
