# Ryan's team — Software Quality Assurance

Course project for COMP 5710/6710, Fall 2026.

- **Team name:** Ryan's team
- **Team member:** Ryan Lunsford
- **Email:** rtl0019@auburn.edu
- **Repository name:** RyansTeam-FALL2026-SQA

## Project

This project applies software quality assurance activities to the supplied SLI-KUBE Python codebase, a static analyzer for Kubernetes YAML manifests. Original authors listed in the supplied project are Akond Rahman, Rahul Pandita, and Shazibul Islam Shamim. Their README is preserved in [README-UPSTREAM.md](README-UPSTREAM.md).

## Current status

- Project extracted and local Python environment configured.
- Startup imports and command-line invocation corrected in main.py; the supplied version is saved as main.py.original.
- Existing parsing tests: 23 passed during setup on October 26, 2026.
- Sample scan: CSV and SARIF reports generated successfully during setup.
- Fuzzing implemented for 10 parser methods; two seeds completed 6,000 cases and exposed nine documented defect categories. See [FUZZING.md](FUZZING.md) and [baseline evidence](evidence/fuzz-baseline/summary.json).
- Forensic instrumentation completed for 10 parser methods, with validated execution logs and five regression tests. See [FORENSICS.md](FORENSICS.md). Forensic CI integration and the final assignment report remain pending.

## Run locally on Windows

The existing setup is located at D:\KubeSec-master. From PowerShell:

```powershell
cd D:\KubeSec-master
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

To scan a different directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1 -ManifestDirectory 'D:\path\to\manifests'
```

The scanner writes slikube_results.csv into the scanned directory and SLIKUBE.sarif into the project directory. Repeated runs overwrite these files.

For setup details, see [LOCAL-SETUP.md](LOCAL-SETUP.md). The local .venv environment and tools/yq.exe are excluded from Git. A fresh clone requires Python dependencies from requirements-local-lock.txt and the Mike Farah yq executable described in LOCAL-SETUP.md.

## Existing parsing tests

```powershell
.\.venv\Scripts\python.exe TEST_PARSING.py
```

Some other original tests depend on paths from the original author's machine and have not been validated locally.

## Assignment deliverables still to complete

- Review the findings in FUZZING.md and incorporate the fuzzing results into the final report.
- Integrate forensic execution evidence into the existing parser-test/fuzz CI workflow after instrumentation.
- SQA-REPO.md describing completed activities and personal lessons learned.
- Code, logs, and screenshots demonstrating execution.

The supplied workflow is preserved at reference/python.build.yml. The active .github/workflows/fuzz.yml automatically runs the parsing tests and fuzz.py on pushes and pull requests to main. [The first run succeeded](https://github.com/rtl0019/RyansTeam-FALL2026-SQA/actions/runs/41898382445), with downloadable evidence and an explicit discovery-mode summary. Forensic instrumentation and local evidence are documented in [FORENSICS.md](FORENSICS.md); its CI integration remains pending.

## Publication preparation

A Grafana token in comments in the supplied helm.values.yaml and helm.stackgres.yaml test fixtures was replaced with an explicit dummy value after GitHub push protection flagged it. The 23 existing parsing tests passed again after this change.

## Fuzz ten methods

```powershell
.\.venv\Scripts\python.exe fuzz.py --seed 5710 --cases 300
```

This runs 300 cases per method and writes JSON summaries and replayable failures to fuzz-results/. Discovery mode reports bugs without failing solely on findings; timeouts and harness errors still fail. Use --fail-on-findings for strict mode. The baseline findings remain unfixed and can be reproduced using the commands in [FUZZING.md](FUZZING.md).