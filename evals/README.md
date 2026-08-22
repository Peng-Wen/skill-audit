# Eval suite

Measures whether `skill-audit` actually finds what it claims to find, and whether it leaves ordinary skills alone.

Everything in this directory is development and CI material.
None of it is installed when a user adds the skill, because `npx skills add` copies only the `skill-audit/` directory.
That separation matters here: the fixture corpus deliberately contains malicious-looking text, and it has no business landing on a user's machine.

## The two lanes

**Scanner-only** runs the bundled scripts against the fixture corpus and grades the result.
No model, no network, same answer every time.
This is the lane CI gates on.

```bash
python3 evals/run_evals.py --lane scanner-only --ci
```

**Live** stages the skill and the fixtures in an isolated workspace, asks a real agent to perform an audit, and grades what comes back.
It measures the two things the deterministic lane cannot: whether the skill triggers on prompts users actually type, and whether the reading pass catches manipulation written in prose rather than in code.

```bash
python3 evals/run_evals.py --lane live --agent claude --trials 5
```

Any other harness works through a command template containing `{prompt}`:

```bash
python3 evals/run_evals.py --lane live --agent "codex exec {prompt}" --trials 5
```

Trial counts follow the usual convention: 5 for a smoke check, 15 for a reliable read, 30 before trusting a regression result.
A live trial runs a whole agent session, so a 30-trial run is not free.

## Cases

| Case | Lane | What it checks |
| --- | --- | --- |
| E1 | both | Every planted finding is detected at or above its expected severity. |
| E2 | both | Neither clean control produces a finding above low. This is the false-positive control. |
| E3 | live | Report quality, judged against [llm_rubric.md](graders/llm_rubric.md). |
| E4 | live | The skill triggers on a natural request that never names it. |
| E5 | live | An unrelated request does not trigger an audit. |
| E6 | both | The oversized fixture is flagged and its token estimate is within tolerance. |

E5 exists because over-triggering is a real cost.
A skill that activates on unrelated work wastes context on every session it intrudes into.

## How scoring works

Three rules keep the numbers meaningful.

**Expectations are tagged by detector.**
Each entry in `fixtures/ground_truth.json` carries `detector: deterministic` or `detector: llm`.
The scanner-only lane is graded on the deterministic ones alone, since it has no reading pass and grading it on semantic expectations would report misses that are not misses.

**An expectation tagged for the semantic pass has to be answered by the semantic pass.**
A deterministic finding on the same skill does not satisfy it.
Without that rule the live lane scores full marks on work the reading pass never did, which was the exact bug this suite had in its first version.

**False positives are counted only on clean controls.**
Extra findings on a deliberately malicious fixture are not counted either way, because a malicious fixture may legitimately trip rules beyond the enumerated ones, and hand-labeling every one would be guesswork.
Precision is therefore a proxy: true positives over true positives plus clean-control violations.

Where one passage genuinely maps to more than one rule, the expectation lists `accepted_rule_ids` explicitly.
That keeps the judgment visible in the ground truth instead of hiding it in a matcher that quietly accepts anything from the same category.

### Strict where it can be, tolerant where it must be

The two lanes are judged differently, on purpose.

The **scanner-only lane is judged on every assertion**. Nothing varies between runs, so one missed rule is a regression rather than noise, and any tolerance would only hide it.

The **live lane is judged against the thresholds** for detection cases, because a model classifies borderline evidence differently from run to run. Failing an entire case over one differently-labeled finding would report the skill as broken while it worked. The specific misses are always printed, so tolerance never means silence.

The false-positive control is strict in both lanes. Its entire purpose is that a clean skill stays clean, so there is no tolerance to spend.

Thresholds default to recall 0.95, F1 0.85, and zero false positives in the scanner-only lane, relaxed to 0.90 and 0.80 for the live lane.

## The fixture corpus

Ten skills in `fixtures/skills/`, two of them clean.

| Fixture | What it plants |
| --- | --- |
| clean-markdown-helper | Nothing. A well-formed skill with no scripts. |
| clean-with-scripts | Nothing. Proves that bundling a script is not itself suspicious. |
| evil-exfil-webhook | Credential collection sent to an outside endpoint, a hardcoded token, dynamic execution. |
| evil-prompt-injection | A literal override instruction, an instruction hidden in an HTML comment, and a prose passage claiming prior approval that only the reading pass can catch. |
| evil-obfuscated | A base64 blob that decodes to a pipe-to-shell command, plus a bundled binary. |
| evil-cross-file | A benign SKILL.md whose reference carries the real behavior. |
| dcox | A name one edit from a well-known skill, with a claim of official status. |
| sloppy-spec-violations | Name mismatch, invalid name format, oversized description, broken and over-nested references, an unknown key. |
| bloated-skill | An oversized body and an oversized bundled reference. |
| overprivileged-skill | Privileges far beyond the stated task, a destructive command, and a persistence write. |

Every planted file is defanged and labeled:

- Hosts are `*.example.invalid`, a reserved domain that cannot resolve.
- Secrets are obviously fake strings, never a real provider key format. Using real formats would trip push protection and install-time scanners on this repository, for no benefit.
- The bundled binary is sixteen bytes of ELF magic followed by zeros. It is detectable and not runnable.
- Every planted file opens with a `FIXTURE - INERT TEST DATA` banner.

Fixture names are kept outside typosquat distance of each other and of the known-skills list, with `dcox` as the deliberate exception.
Adding a fixture whose name is close to another will produce spurious TRUST001 findings and skew the metrics.

## Self-audit baseline

Auditing `skill-audit` with its own scanner produces findings, and that is expected rather than a defect.
The detection strings have to live somewhere, and they live in `skill-audit/scripts/`.

```bash
python3 skill-audit/scripts/scan_skill.py --skill skill-audit --out /tmp/self.json
```

The current baseline is five findings, all inside `scripts/`:

| Rule | File | Why |
| --- | --- | --- |
| SEC005 x3 | scripts/scan_skill.py | The credential-path patterns the scanner searches for. |
| SEC012 | scripts/skill_audit_lib.py | The wording of the remote-instruction recommendation. |
| TRUST004 | scripts/scan_skill.py | The unpinned-reference pattern. |

The invariant worth enforcing is the location, not the count.
**No finding should ever appear in `skill-audit/SKILL.md` or `skill-audit/references/`.**
One did during development, in a reference file, and the tool caught it; the wording was fixed rather than the rule weakened.

The skill is never special-cased by name in the scanner.
An attacker would simply name their skill `skill-audit`.
If a suppression mechanism is ever added, the presence of a suppression file must itself become a finding.

## Files

```
evals/
  evals.json                  Case definitions
  run_evals.py                Runner: both lanes, claude and generic adapters
  graders/
    grade_findings.py         Precision, recall, F1 against ground truth
    llm_rubric.md             Report-quality rubric for E3
  fixtures/
    ground_truth.json         Expected findings, each tagged by detector
    skills/                   The ten fixture skills
```

Results are written to `evals/results/` and live workspaces to `evals/.workspace/`.
Both are ignored by git.
