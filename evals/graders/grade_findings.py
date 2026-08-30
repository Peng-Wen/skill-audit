#!/usr/bin/env python3
"""Grade a findings document against the fixture ground truth.

Produces detection metrics plus the grading.json and benchmark.json shapes the
Agent Skills eval convention uses.

Scoring rules, stated plainly because an eval that flatters itself is worthless:

- Recall counts enumerated expected findings that were detected. In the
  scanner-only lane, only the expectations tagged 'deterministic' are counted,
  since that lane has no semantic pass and grading it on semantic expectations
  would report a miss that is not one.
- False positives are counted only on clean-control fixtures, where any finding
  above the fixture's threshold is a mistake by definition.
- Extra findings on deliberately malicious fixtures are not counted either way.
  A malicious fixture may legitimately trip rules beyond those enumerated, and
  labeling every one of them by hand would be guesswork.

Usage:
  python3 grade_findings.py --findings scan_findings.json \
      --ground-truth ../fixtures/ground_truth.json --lane scanner-only --out results/
"""

import argparse
import json
import os
import sys

# Keep imports of the shipped scripts from writing __pycache__ into the
# shipped skill directory, where the audit would report it as bytecode.
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "skill-audit", "scripts"))

from skill_audit_lib import severity_at_least, write_json  # noqa: E402

DEFAULT_THRESHOLDS = {"recall": 0.95, "fp": 0.0, "f1": 0.85}


def matches(finding, expected):
    """Decide whether one finding satisfies one expected item.

    The rule id has to match exactly, unless the expectation names
    `accepted_rule_ids`. A blanket fallback to category matching was tried and
    removed: with several rules of one category firing on the same file, it let
    an unrelated finding satisfy an expectation and inflated recall. Where one
    piece of evidence genuinely maps to more than one rule, the expectation says
    so explicitly instead, which keeps the judgment visible in the ground truth
    rather than hidden in the matcher.

    An expectation tagged for the semantic pass has to be satisfied by a finding
    that the semantic pass actually produced. Otherwise a deterministic finding
    on the same skill would answer for work the reading pass never did, and the
    live lane would report a score it did not earn.
    """
    if finding["skill"] != expected["skill_name"]:
        return False
    accepted = expected.get("accepted_rule_ids") or [expected["rule_id"]]
    if finding["rule_id"] not in accepted:
        return False
    if not severity_at_least(finding["severity"], expected["min_severity"]):
        return False
    if expected.get("detector") == "llm" and "llm" not in (finding.get("detector") or ""):
        return False
    return True


def grade(findings, ground_truth, lane):
    """Compare findings against ground truth and return metrics plus assertions."""
    counted_detectors = {"deterministic"} if lane == "scanner-only" else {"deterministic", "llm"}

    assertions = []
    matched = 0
    total_expected = 0
    false_positives = 0
    by_category = {}

    findings_by_skill = {}
    for f in findings:
        findings_by_skill.setdefault(f["skill"], []).append(f)

    for fixture in ground_truth["fixtures"]:
        skill_name = fixture["skill"]
        skill_findings = findings_by_skill.get(skill_name, [])

        # Detection expectations.
        for expected in fixture.get("expected", []):
            if expected.get("detector") not in counted_detectors:
                continue
            expected = dict(expected, skill_name=skill_name)
            total_expected += 1
            category = expected.get("category", "SEC")
            bucket = by_category.setdefault(category, {"expected": 0, "matched": 0})
            bucket["expected"] += 1

            hit = next((f for f in skill_findings if matches(f, expected)), None)
            if hit:
                matched += 1
                bucket["matched"] += 1
                where = hit.get("file") or "skill"
                if hit.get("line"):
                    where = "%s:%s" % (where, hit["line"])
                evidence = "found %s at %s severity %s (%s)" % (
                    hit["rule_id"], where, hit["severity"], hit["detector"])
            else:
                evidence = "no finding matched %s at or above %s on %s" % (
                    expected["rule_id"], expected["min_severity"], skill_name)

            assertions.append({
                "text": "%s: detects %s at or above %s (%s)" % (
                    skill_name, expected["rule_id"], expected["min_severity"],
                    expected["detector"]),
                "passed": hit is not None,
                "evidence": evidence,
            })

        # False-positive control on clean fixtures.
        if fixture.get("clean"):
            threshold = fixture.get("forbidden_above") or "info"
            offenders = [f for f in skill_findings
                         if severity_at_least(f["severity"], threshold)
                         and f["severity"] != threshold]
            false_positives += len(offenders)
            assertions.append({
                "text": "%s: clean control has no finding above %s" % (skill_name, threshold),
                "passed": not offenders,
                "evidence": ("no findings above %s" % threshold) if not offenders else
                            "; ".join("%s %s on %s" % (f["severity"], f["rule_id"],
                                                       f.get("file") or "skill")
                                      for f in offenders),
            })

    # Cost accuracy expectations.
    for skill_name, expectation in (ground_truth.get("cost_expectations") or {}).items():
        skill_findings = findings_by_skill.get(skill_name, [])
        cost_hit = next((f for f in skill_findings if f["rule_id"] == "COST001"), None)
        assertions.append({
            "text": "%s: body size flagged as an oversized skill body" % skill_name,
            "passed": cost_hit is not None,
            "evidence": cost_hit["evidence"] if cost_hit else "no COST001 finding",
        })

    recall = matched / total_expected if total_expected else 0.0
    true_positives = matched
    precision = (true_positives / (true_positives + false_positives)
                 if (true_positives + false_positives) else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    passed = sum(1 for a in assertions if a["passed"])
    metrics = {
        "overall": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "by_category": {
            cat: {
                "expected": b["expected"],
                "matched": b["matched"],
                "recall": round(b["matched"] / b["expected"], 4) if b["expected"] else 0.0,
            }
            for cat, b in sorted(by_category.items())
        },
        "false_positives_on_clean": false_positives,
        "expected_total": total_expected,
        "matched_total": matched,
    }
    summary = {
        "passed": passed,
        "failed": len(assertions) - passed,
        "total": len(assertions),
        "pass_rate": round(passed / len(assertions), 4) if assertions else 0.0,
    }
    return metrics, assertions, summary


def parse_thresholds(raw):
    thresholds = dict(DEFAULT_THRESHOLDS)
    if not raw:
        return thresholds
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        thresholds[key.strip()] = float(value)
    return thresholds


def check_thresholds(metrics, thresholds):
    """Return the list of threshold violations, empty when everything passes."""
    failures = []
    overall = metrics["overall"]
    if overall["recall"] < thresholds.get("recall", 0):
        failures.append("recall %.4f is below the required %.2f"
                        % (overall["recall"], thresholds["recall"]))
    if overall["f1"] < thresholds.get("f1", 0):
        failures.append("f1 %.4f is below the required %.2f"
                        % (overall["f1"], thresholds["f1"]))
    if metrics["false_positives_on_clean"] > thresholds.get("fp", 0):
        failures.append("%d false positive(s) on clean controls, the limit is %d"
                        % (metrics["false_positives_on_clean"], int(thresholds.get("fp", 0))))
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description="Grade audit findings against fixture ground truth.")
    parser.add_argument("--findings", required=True, help="findings.json to grade.")
    parser.add_argument("--ground-truth", required=True, help="ground_truth.json.")
    parser.add_argument("--lane", default="scanner-only", choices=["scanner-only", "live"])
    parser.add_argument("--eval-id", default="E1")
    parser.add_argument("--out", required=True, help="Directory for grading.json and benchmark.json.")
    parser.add_argument("--thresholds", help="Comma-separated, e.g. recall=0.95,fp=0,f1=0.85.")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--agent", default="scanner")
    parser.add_argument("--ci", action="store_true", help="Exit nonzero when a threshold is missed.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    with open(args.findings, "r", encoding="utf-8") as fh:
        findings_doc = json.load(fh)
    findings = findings_doc.get("findings", findings_doc if isinstance(findings_doc, list) else [])

    with open(args.ground_truth, "r", encoding="utf-8") as fh:
        ground_truth = json.load(fh)

    metrics, assertions, summary = grade(findings, ground_truth, args.lane)
    thresholds = parse_thresholds(args.thresholds)
    failures = check_thresholds(metrics, thresholds)

    os.makedirs(args.out, exist_ok=True)
    write_json(os.path.join(args.out, "grading.json"), {
        "eval_id": args.eval_id,
        "lane": args.lane,
        "assertion_results": assertions,
        "summary": summary,
    })
    write_json(os.path.join(args.out, "benchmark.json"), {
        "run_summary": {
            "with_skill": {
                "pass_rate": {"mean": summary["pass_rate"], "stddev": 0.0},
                "time_seconds": None,
                "tokens": None,
            },
            "without_skill": None,
            "delta": None,
        },
        "detection_metrics": metrics,
        "config": {
            "lane": args.lane,
            "trials": args.trials,
            "agent": args.agent,
            "thresholds": thresholds,
        },
        "threshold_failures": failures,
    })

    if not args.quiet:
        overall = metrics["overall"]
        print("Lane: %s" % args.lane)
        print("Assertions: %d passed, %d failed (%.1f%%)"
              % (summary["passed"], summary["failed"], summary["pass_rate"] * 100))
        print("Detection: precision %.3f, recall %.3f, f1 %.3f"
              % (overall["precision"], overall["recall"], overall["f1"]))
        print("Matched %d of %d expected finding(s); %d false positive(s) on clean controls."
              % (metrics["matched_total"], metrics["expected_total"],
                 metrics["false_positives_on_clean"]))
        for category, stats in metrics["by_category"].items():
            print("  %-8s recall %.2f (%d/%d)"
                  % (category, stats["recall"], stats["matched"], stats["expected"]))
        failed = [a for a in assertions if not a["passed"]]
        if failed:
            print("")
            print("Failed assertions:")
            for a in failed:
                print("  - %s" % a["text"])
                print("    %s" % a["evidence"])
        print("")
        print("Results written to %s" % args.out)
        if failures:
            print("")
            for failure in failures:
                print("THRESHOLD MISS: %s" % failure)

    if args.ci and failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
