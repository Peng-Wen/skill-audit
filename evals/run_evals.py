#!/usr/bin/env python3
"""Eval runner for the skill-audit skill.

Two lanes:

  scanner-only  Runs the bundled scripts directly against the fixture corpus and
                grades the result. Hermetic, fast, no model involved, no network.
                This is the lane CI should gate on, because it is the only one
                that gives the same answer every time.

  live          Runs a real agent harness end to end: stages the skill and the
                fixtures in an isolated workspace, asks the agent to perform an
                audit, and grades what it produced. This lane measures what the
                scanner-only lane cannot: whether the skill triggers on the
                prompts users actually write, and whether the semantic pass
                catches manipulation written in prose.

Adapters for the live lane:

  claude              The Claude Code CLI in headless mode.
  <command template>  Any other CLI, given as a template containing {prompt},
                      for example "codex exec {prompt}" or "opencode run {prompt}".

Usage:
  python3 evals/run_evals.py --lane scanner-only --ci
  python3 evals/run_evals.py --lane live --agent claude --cases E1,E4,E5 --trials 3
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SKILL_DIR = os.path.join(REPO, "skill-audit")
SCRIPTS = os.path.join(SKILL_DIR, "scripts")

sys.path.insert(0, SCRIPTS)

from skill_audit_lib import write_json  # noqa: E402

import graders.grade_findings as grader  # noqa: E402
import graders.judge_report as judge  # noqa: E402

# The live lane is graded a little more loosely than the deterministic one,
# because a model gives slightly different answers on identical input. The
# scanner-only lane has no such excuse and is held to a higher bar.
LANE_THRESHOLDS = {
    "scanner-only": {"recall": 0.95, "fp": 0.0, "f1": 0.85},
    # "rubric" is the report-quality floor for E3, on the rubric's weighted
    # 0-1 scale. It sits below the detection bars because it aggregates five
    # dimensions and a single soft one should not sink an otherwise sound
    # report, while a disqualifying behavior caps the total at 0.3 and so
    # fails the case outright regardless of this number.
    "live": {"recall": 0.90, "fp": 0.0, "f1": 0.80, "rubric": 0.75},
}

CLAUDE_DEFAULT_ARGS = [
    "--output-format", "json",
    "--permission-mode", "acceptEdits",
    "--allowedTools", "Bash", "Read", "Write", "Edit", "Glob", "Grep",
]


# ---------------------------------------------------------------------------
# Scanner-only lane.
# ---------------------------------------------------------------------------

def run_scanner(fixtures_dir, out_dir):
    """Run discovery and the deterministic scan over the fixture corpus."""
    os.makedirs(out_dir, exist_ok=True)
    inventory = os.path.join(out_dir, "inventory.json")
    findings = os.path.join(out_dir, "scan_findings.json")

    started = time.time()
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "discover_skills.py"),
         "--paths", fixtures_dir, "--out", inventory, "--quiet"],
        check=True)
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "scan_skill.py"),
         "--inventory", inventory, "--out", findings, "--quiet"],
        check=True)
    duration = time.time() - started

    # Produce the report too, so the lane exercises the whole pipeline rather
    # than just the scanner.
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "build_report.py"),
         "--scan", findings, "--inventory", inventory,
         "--out", os.path.join(out_dir, "report"), "--quiet"],
        check=True)

    return findings, duration


# ---------------------------------------------------------------------------
# Live lane.
# ---------------------------------------------------------------------------

def stage_workspace(workspace, fixtures_dir):
    """Build an isolated workspace holding the skill and a copy of the fixtures.

    The fixtures are copied rather than referenced so a run cannot modify the
    corpus, and SKILL_AUDIT_PATHS points at the copy so the audit never reaches
    the host's real skills.
    """
    if os.path.exists(workspace):
        shutil.rmtree(workspace)
    os.makedirs(workspace)

    staged_skill = os.path.join(workspace, ".claude", "skills", "skill-audit")
    shutil.copytree(SKILL_DIR, staged_skill)

    staged_fixtures = os.path.join(workspace, "fixture-skills")
    shutil.copytree(fixtures_dir, staged_fixtures)

    return staged_skill, staged_fixtures


def build_command(agent, prompt, extra_args):
    """Turn an adapter name or command template into an argv list."""
    if agent == "claude":
        return ["claude", "-p", prompt] + CLAUDE_DEFAULT_ARGS + list(extra_args or [])
    if "{prompt}" not in agent:
        raise SystemExit(
            "The --agent value has to be 'claude' or a command template containing "
            "{prompt}, for example \"codex exec {prompt}\".")
    # Split the template first, then substitute, so a prompt containing spaces
    # stays a single argument instead of being reparsed as shell words.
    import shlex
    parts = shlex.split(agent)
    return [p.replace("{prompt}", prompt) for p in parts] + list(extra_args or [])


def parse_agent_output(stdout):
    """Pull token and duration figures out of an agent's output when present.

    Every CLI reports these differently and some report nothing at all, so this
    returns None for anything it cannot find rather than inventing a number.
    """
    tokens = None
    duration_ms = None
    try:
        doc = json.loads(stdout)
    except (ValueError, TypeError):
        return tokens, duration_ms

    if isinstance(doc, dict):
        usage = doc.get("usage") or {}
        if isinstance(usage, dict):
            given = [usage.get(k) for k in
                     ("input_tokens", "output_tokens",
                      "cache_read_input_tokens", "cache_creation_input_tokens")]
            numbers = [n for n in given if isinstance(n, int)]
            if numbers:
                tokens = sum(numbers)
        for key in ("total_tokens", "num_tokens"):
            if isinstance(doc.get(key), int):
                tokens = doc[key]
        for key in ("duration_ms", "durationMs"):
            if isinstance(doc.get(key), (int, float)):
                duration_ms = doc[key]
    return tokens, duration_ms


def run_live_trial(case, agent, extra_args, fixtures_dir, workspace, timeout):
    """Run one agent invocation and collect what it produced."""
    staged_skill, staged_fixtures = stage_workspace(workspace, fixtures_dir)

    env = dict(os.environ)
    env["SKILL_AUDIT_PATHS"] = staged_fixtures

    prompt = case["prompt"].replace("{fixtures}", staged_fixtures)
    command = build_command(agent, prompt, extra_args)

    started = time.time()
    try:
        completed = subprocess.run(
            command, cwd=workspace, env=env, capture_output=True,
            text=True, timeout=timeout)
        stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, code = "", "timed out after %ds" % timeout, -1
    except FileNotFoundError as exc:
        raise SystemExit("Could not run the agent command %r: %s" % (command[0], exc))
    wall_seconds = time.time() - started

    tokens, duration_ms = parse_agent_output(stdout)
    report_dir = find_report_dir(workspace)
    findings_path = os.path.join(report_dir, "findings.json") if report_dir else None
    produced_report = bool(findings_path and os.path.exists(findings_path))

    return {
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
        "wall_seconds": wall_seconds,
        "tokens": tokens,
        "duration_ms": duration_ms if duration_ms is not None else int(wall_seconds * 1000),
        "report_dir": report_dir,
        "findings_path": findings_path if produced_report else None,
        "produced_report": produced_report,
        "staged_fixtures": staged_fixtures,
    }


def isolation_leaks(findings_path, ground_truth):
    """Report any audited skill that is not part of the fixture corpus.

    A live trial is supposed to stay inside the staged fixtures. If the agent
    widens the search to the host's real skills, the metrics are unaffected,
    since grading only considers fixtures named in the ground truth, but the run
    costs more and the report mixes in skills nobody asked about. Surfacing it
    beats letting it pass unnoticed.
    """
    fixture_names = {f["skill"] for f in ground_truth["fixtures"]}
    try:
        with open(findings_path, "r", encoding="utf-8") as fh:
            findings = json.load(fh).get("findings", [])
    except (OSError, ValueError):
        return set()
    return {f.get("skill") for f in findings if f.get("skill") not in fixture_names}


def find_report_dir(workspace):
    """Locate the report directory the agent wrote, wherever it chose to put it."""
    for dirpath, dirnames, filenames in os.walk(workspace):
        # Do not mistake the staged copy of the skill for a produced report.
        dirnames[:] = [d for d in dirnames if d != ".claude"]
        if "findings.json" in filenames and "report.md" in filenames:
            return dirpath
    return None


# ---------------------------------------------------------------------------
# Case execution.
# ---------------------------------------------------------------------------

def applicable(case, lane):
    return case.get("lane") in (lane, "both")


def grade_detection(findings_path, ground_truth, lane, eval_id, out_dir, thresholds,
                    trials, agent):
    with open(findings_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    findings = doc.get("findings", [])
    metrics, assertions, summary = grader.grade(findings, ground_truth, lane)
    failures = grader.check_thresholds(metrics, thresholds)

    os.makedirs(out_dir, exist_ok=True)
    write_json(os.path.join(out_dir, "grading.json"), {
        "eval_id": eval_id,
        "lane": lane,
        "assertion_results": assertions,
        "summary": summary,
    })
    return metrics, assertions, summary, failures


# The judge sees the report, not the machine that produced it. Capping the
# excerpt keeps a runaway report from overflowing the command line, and the cap
# is disclosed to the judge so a truncated tail is never mistaken for an
# omission.
JUDGE_REPORT_CAP = 60000


def scan_baseline(fixtures_dir, out_dir):
    """Deterministic findings for the same corpus the agent audited.

    This is the floor the report is measured against. Running the scanner here
    rather than trusting the agent's own scan output means a report cannot lose
    a critical finding and also hide the loss.
    """
    findings_path, _ = run_scanner(fixtures_dir, out_dir)
    with open(findings_path, "r", encoding="utf-8") as fh:
        return json.load(fh).get("findings", [])


def judge_report_quality(case, run, args, out_dir, threshold):
    """Score one report against the rubric. Returns (assertions, passed, verdict).

    The model is a second, separate invocation with no memory of the audit, so
    it is not grading its own work. Everything mechanically checkable is settled
    before the model is asked anything.
    """
    os.makedirs(out_dir, exist_ok=True)

    def fail(reason):
        return ([{"text": "%s: the report could be judged" % case["id"],
                  "passed": False, "evidence": reason}], False, None)

    report_path = os.path.join(run["report_dir"] or "", "report.md")
    if not run["findings_path"] or not os.path.exists(report_path):
        return fail("no report.md and findings.json pair was produced; exit code %s"
                    % run["exit_code"])

    with open(run["findings_path"], "r", encoding="utf-8") as fh:
        findings = json.load(fh).get("findings", [])
    with open(report_path, "r", encoding="utf-8") as fh:
        report_md = fh.read()

    truncated = len(report_md) > JUDGE_REPORT_CAP
    if truncated:
        report_md = (report_md[:JUDGE_REPORT_CAP]
                     + "\n\n[excerpt ends here; the report continued beyond the "
                       "size this judge was given, so do not treat the missing "
                       "tail as an omission]")

    corpus = run["staged_fixtures"]
    evidence_score, evidence_detail = judge.verify_evidence(findings, corpus)
    dropped = judge.missing_critical(
        findings, scan_baseline(corpus, os.path.join(out_dir, "baseline")))

    with open(os.path.join(HERE, "graders", "llm_rubric.md"), "r", encoding="utf-8") as fh:
        rubric_text = fh.read()

    mismatched, missing = judge.check_rubric_sync(rubric_text)
    if mismatched or missing:
        return fail("the rubric and the scoring code disagree on weights: %s"
                    % "; ".join(mismatched + ["%s has no stated weight" % m for m in missing]))

    prompt = judge.build_judge_prompt(
        rubric_text, report_md, findings, evidence_detail, dropped)

    command = build_command(args.judge_agent or args.agent, prompt, None)
    try:
        completed = subprocess.run(
            command, cwd=out_dir, capture_output=True, text=True, timeout=args.timeout)
        stdout, code = completed.stdout, completed.returncode
    except subprocess.TimeoutExpired:
        return fail("the judge timed out after %ds" % args.timeout)
    except FileNotFoundError as exc:
        raise SystemExit("Could not run the judge command %r: %s" % (command[0], exc))

    with open(os.path.join(out_dir, "judge_stdout.txt"), "w", encoding="utf-8") as fh:
        fh.write(stdout or "")

    raw, error = judge.extract_json(stdout)
    if raw is None:
        return fail("%s (judge exit code %s)" % (error, code))

    verdict = judge.normalize_verdict(raw, evidence_score, dropped)
    verdict["evidence_detail"] = evidence_detail
    verdict["report_truncated"] = truncated
    assertions = judge.assertions_for(case["id"], verdict, threshold)

    write_json(os.path.join(out_dir, "grading.json"), {
        "eval_id": case["id"],
        "lane": "live",
        "assertion_results": assertions,
        "verdict": verdict,
        "summary": {
            "passed": sum(1 for a in assertions if a["passed"]),
            "failed": sum(1 for a in assertions if not a["passed"]),
            "pass_rate": round(
                sum(1 for a in assertions if a["passed"]) / len(assertions), 4),
        },
    })

    passed = verdict["total"] >= threshold and not verdict["disqualified"]
    return assertions, passed, verdict


def run_scanner_lane(args, ground_truth, cases):
    """Run every case that the deterministic lane can answer."""
    results = []
    out_dir = os.path.join(args.out, "scanner-only")
    findings_path, duration = run_scanner(args.fixtures, out_dir)
    thresholds = dict(LANE_THRESHOLDS["scanner-only"])
    thresholds.update(grader.parse_thresholds(args.thresholds) if args.thresholds else {})

    metrics, assertions, summary, failures = grade_detection(
        findings_path, ground_truth, "scanner-only", "E1", out_dir, thresholds,
        1, "scanner")

    for case in cases:
        # The deterministic lane is judged strictly, on every assertion rather
        # than on thresholds. Nothing varies between runs here, so a single
        # missed rule is a regression, not noise, and the tolerance the live
        # lane needs would only hide it.
        case_assertions = select_assertions(case, assertions)
        passed = all(a["passed"] for a in case_assertions) if case_assertions else None
        results.append({
            "case": case["id"],
            "name": case["name"],
            "lane": "scanner-only",
            "passed": passed,
            "assertions": case_assertions,
        })

    write_json(os.path.join(out_dir, "benchmark.json"), {
        "run_summary": {
            "with_skill": {
                "pass_rate": {"mean": summary["pass_rate"], "stddev": 0.0},
                "time_seconds": round(duration, 2),
                "tokens": None,
            },
            "without_skill": None,
            "delta": None,
        },
        "detection_metrics": metrics,
        "config": {"lane": "scanner-only", "trials": 1, "agent": "scanner",
                   "thresholds": thresholds},
        "threshold_failures": failures,
    })
    return results, metrics, summary, failures, out_dir


def case_verdict(case, case_assertions, threshold_failures):
    """Decide whether a case passed.

    Detection cases are judged against the lane's thresholds rather than on
    every assertion, because a model gives slightly different answers on
    identical input and the thresholds are where that tolerance is declared.
    Failing a whole case over one differently-classified finding would make the
    live lane read as broken while the skill worked.

    The false-positive control is judged strictly. Its whole purpose is that a
    clean skill stays clean, so there is no tolerance to spend there.
    """
    if not case_assertions:
        return False
    if case.get("grader") == "detection":
        return not threshold_failures
    return all(a["passed"] for a in case_assertions)


def select_assertions(case, assertions):
    """Pick out the assertions belonging to one case."""
    kind = case.get("grader")
    if kind == "detection":
        return [a for a in assertions if ": detects " in a["text"]]
    if kind == "false-positive":
        return [a for a in assertions if "clean control" in a["text"]]
    if kind == "cost":
        return [a for a in assertions if "oversized skill body" in a["text"]]
    return []


def rubric_summary(records):
    """Mean and spread of the rubric total across a case's trials."""
    totals = [r["rubric_total"] for r in records if "rubric_total" in r]
    if not totals:
        return None
    return {
        "mean": round(statistics.mean(totals), 4),
        "stddev": round(statistics.stdev(totals), 4) if len(totals) > 1 else 0.0,
        "min": round(min(totals), 4),
        "trials": len(totals),
        "disqualified_trials": sum(1 for r in records if r.get("disqualified")),
    }


def run_live_lane(args, ground_truth, cases):
    """Run the cases that need a real agent."""
    results = []
    thresholds = dict(LANE_THRESHOLDS["live"])
    thresholds.update(grader.parse_thresholds(args.thresholds) if args.thresholds else {})
    all_failures = []
    latest_metrics = None
    latest_summary = None
    out_root = os.path.join(args.out, "live")

    for case in cases:
        trial_records = []
        for trial in range(1, args.trials + 1):
            workspace = os.path.join(args.workspace, case["id"], "trial-%d" % trial)
            trial_out = os.path.join(out_root, "eval-%s" % case["id"],
                                     "trial-%d" % trial, "with_skill")
            os.makedirs(trial_out, exist_ok=True)

            print("  %s trial %d/%d ..." % (case["id"], trial, args.trials))
            run = run_live_trial(case, args.agent, args.agent_args, args.fixtures,
                                 workspace, args.timeout)

            write_json(os.path.join(trial_out, "timing.json"), {
                "total_tokens": run["tokens"],
                "duration_ms": run["duration_ms"],
            })
            with open(os.path.join(trial_out, "stdout.txt"), "w", encoding="utf-8") as fh:
                fh.write(run["stdout"] or "")
            if run["stderr"]:
                with open(os.path.join(trial_out, "stderr.txt"), "w", encoding="utf-8") as fh:
                    fh.write(run["stderr"])

            record = {"trial": trial, "tokens": run["tokens"],
                      "duration_ms": run["duration_ms"],
                      "produced_report": run["produced_report"]}

            grader_kind = case.get("grader")
            if grader_kind == "trigger-positive":
                record["passed"] = run["produced_report"]
                record["assertions"] = [{
                    "text": "%s: the skill activates and produces a report" % case["id"],
                    "passed": run["produced_report"],
                    "evidence": ("report written to %s" % run["report_dir"])
                                if run["produced_report"] else "no report was produced",
                }]
            elif grader_kind == "trigger-negative":
                record["passed"] = not run["produced_report"]
                record["assertions"] = [{
                    "text": "%s: an unrelated request does not trigger an audit" % case["id"],
                    "passed": not run["produced_report"],
                    "evidence": "no report was produced" if not run["produced_report"]
                                else "an unwanted report appeared at %s" % run["report_dir"],
                }]
            elif grader_kind == "llm-rubric":
                if run["findings_path"]:
                    shutil.copy(run["findings_path"],
                                os.path.join(trial_out, "findings.json"))
                assertions, passed, verdict = judge_report_quality(
                    case, run, args, trial_out, thresholds["rubric"])
                record["passed"] = passed
                record["assertions"] = assertions
                if verdict:
                    record["rubric_total"] = verdict["total"]
                    record["disqualified"] = verdict["disqualified"]
                    if verdict["verdict_problems"]:
                        print("    note: the judge's verdict had %d formatting "
                              "problem(s): %s" % (len(verdict["verdict_problems"]),
                                                  "; ".join(verdict["verdict_problems"])))
                    if verdict["disqualified"]:
                        print("    disqualified: %s" % verdict["disqualification_reason"])
                    else:
                        print("    rubric total %.3f (threshold %.2f)"
                              % (verdict["total"], thresholds["rubric"]))
            elif run["findings_path"]:
                shutil.copy(run["findings_path"], os.path.join(trial_out, "findings.json"))
                leaked = isolation_leaks(run["findings_path"], ground_truth)
                if leaked:
                    record["isolation_leak"] = sorted(leaked)
                    print("    note: the audit also covered %d skill(s) outside the "
                          "fixture corpus: %s" % (len(leaked), ", ".join(sorted(leaked))))
                metrics, assertions, summary, failures = grade_detection(
                    run["findings_path"], ground_truth, "live", case["id"],
                    trial_out, thresholds, args.trials, args.agent)
                case_assertions = select_assertions(case, assertions)
                record["passed"] = case_verdict(case, case_assertions, failures)
                record["assertions"] = case_assertions
                record["metrics"] = metrics
                latest_metrics, latest_summary = metrics, summary
                all_failures.extend(failures)
            else:
                record["passed"] = False
                record["assertions"] = [{
                    "text": "%s: an audit report is produced" % case["id"],
                    "passed": False,
                    "evidence": "no findings.json was found in the workspace; exit code %s"
                                % run["exit_code"],
                }]

            trial_records.append(record)

        passes = [1.0 if r["passed"] else 0.0 for r in trial_records]
        entry = {
            "case": case["id"],
            "name": case["name"],
            "lane": "live",
            "passed": all(r["passed"] for r in trial_records),
            "pass_rate": sum(passes) / len(passes) if passes else 0.0,
            "trials": trial_records,
        }
        rubric = rubric_summary(trial_records)
        if rubric:
            entry["rubric"] = rubric
            print("  %s rubric mean %.3f, stddev %.3f, lowest %.3f across %d trial(s)"
                  % (case["id"], rubric["mean"], rubric["stddev"],
                     rubric["min"], rubric["trials"]))
        results.append(entry)

        # A rubric case carries its own thresholds, so its failures have to be
        # added to the CI list explicitly. Detection cases go through
        # grade_detection, which already reports its own threshold misses.
        if case.get("grader") == "llm-rubric" and not entry["passed"]:
            all_failures.extend(
                a["text"] for r in trial_records
                for a in r["assertions"] if not a["passed"])

    aggregate_live(out_root, results, latest_metrics, latest_summary, thresholds,
                   args, all_failures)
    return results, latest_metrics, latest_summary, all_failures, out_root


def aggregate_live(out_root, results, metrics, summary, thresholds, args, failures):
    """Write the benchmark aggregate for a live run."""
    rates, durations, tokens = [], [], []
    for result in results:
        rates.append(result.get("pass_rate", 0.0))
        for trial in result.get("trials", []):
            if trial.get("duration_ms"):
                durations.append(trial["duration_ms"] / 1000.0)
            if trial.get("tokens"):
                tokens.append(trial["tokens"])

    def stats(values):
        if not values:
            return {"mean": None, "stddev": None}
        return {
            "mean": round(statistics.mean(values), 3),
            "stddev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        }

    os.makedirs(out_root, exist_ok=True)
    write_json(os.path.join(out_root, "benchmark.json"), {
        "run_summary": {
            "with_skill": {
                "pass_rate": stats(rates),
                "time_seconds": stats(durations)["mean"],
                "tokens": stats(tokens)["mean"],
            },
            "without_skill": None,
            "delta": None,
        },
        "detection_metrics": metrics,
        "config": {
            "lane": "live",
            "trials": args.trials,
            "agent": args.agent,
            "thresholds": thresholds,
        },
        "threshold_failures": sorted(set(failures)),
    })


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the skill-audit eval suite.")
    parser.add_argument("--lane", default="scanner-only", choices=["scanner-only", "live"])
    parser.add_argument("--agent", default="claude",
                        help="'claude', or a command template containing {prompt}.")
    parser.add_argument("--agent-args", nargs="*", default=None,
                        help="Extra arguments appended to the agent command.")
    parser.add_argument("--judge-agent", default=None,
                        help="Agent used to judge report quality in E3. Defaults to "
                             "--agent. Set a different one to keep the model that "
                             "wrote the report from also grading it.")
    parser.add_argument("--cases", help="Comma-separated case ids. Default: all for the lane.")
    parser.add_argument("--trials", type=int, default=5,
                        help="Live-lane trials per case: 5 smoke, 15 reliable, 30 regression.")
    parser.add_argument("--fixtures", default=os.path.join(HERE, "fixtures", "skills"))
    parser.add_argument("--ground-truth", default=os.path.join(HERE, "fixtures", "ground_truth.json"))
    parser.add_argument("--evals", default=os.path.join(HERE, "evals.json"))
    parser.add_argument("--workspace", default=os.path.join(HERE, ".workspace"))
    parser.add_argument("--out", default=os.path.join(HERE, "results"))
    parser.add_argument("--timeout", type=int, default=600, help="Seconds per live trial.")
    parser.add_argument("--thresholds", help="Override, e.g. recall=0.95,fp=0,f1=0.85.")
    parser.add_argument("--ci", action="store_true", help="Exit nonzero on any failure.")
    args = parser.parse_args(argv)

    with open(args.evals, "r", encoding="utf-8") as fh:
        suite = json.load(fh)
    with open(args.ground_truth, "r", encoding="utf-8") as fh:
        ground_truth = json.load(fh)

    cases = [c for c in suite["evals"] if applicable(c, args.lane)]
    if args.cases:
        wanted = {c.strip() for c in args.cases.split(",")}
        cases = [c for c in cases if c["id"] in wanted]
    if not cases:
        print("No cases apply to the %s lane with the given selection." % args.lane)
        return 1

    print("Running %d case(s) in the %s lane." % (len(cases), args.lane))
    if args.lane == "scanner-only":
        results, metrics, summary, failures, out_dir = run_scanner_lane(
            args, ground_truth, cases)
    else:
        print("Agent: %s, %d trial(s) per case." % (args.agent, args.trials))
        results, metrics, summary, failures, out_dir = run_live_lane(
            args, ground_truth, cases)

    print("")
    print("%-6s %-34s %s" % ("CASE", "NAME", "RESULT"))
    failed_cases = 0
    for result in results:
        if result["passed"] is None:
            verdict = "not applicable"
        elif result["passed"]:
            verdict = "pass"
        else:
            verdict = "FAIL"
            failed_cases += 1
        if "pass_rate" in result and result["passed"] is not None:
            verdict += " (%.0f%% of trials)" % (result["pass_rate"] * 100)
        print("%-6s %-34s %s" % (result["case"], result["name"][:34], verdict))

    if metrics:
        overall = metrics["overall"]
        print("")
        print("Detection: precision %.3f, recall %.3f, f1 %.3f; %d false positive(s) on clean controls."
              % (overall["precision"], overall["recall"], overall["f1"],
                 metrics["false_positives_on_clean"]))

    for result in results:
        for assertion in result.get("assertions", []):
            if not assertion["passed"]:
                print("  FAILED %s" % assertion["text"])
                print("         %s" % assertion["evidence"])

    if failures:
        print("")
        for failure in sorted(set(failures)):
            print("THRESHOLD MISS: %s" % failure)

    print("")
    print("Results written to %s" % out_dir)

    if args.ci and (failed_cases or failures):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
