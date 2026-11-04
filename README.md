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
- Assignment fuzzing, forensic instrumentation, and updated GitHub Actions integration are still pending.

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

- Automatic fuzzing of 10 Python methods in fuzz.py and a report of discovered bugs.
- Forensic instrumentation of 10 Python methods.
- GitHub Actions that execute the required checks and fuzz.py.
- SQA-REPO.md describing completed activities and personal lessons learned.
- Code, logs, and screenshots demonstrating execution.

The supplied workflow is preserved at reference/python.build.yml. It is inactive; assignment CI integration is not yet complete. The current GitHub Git authentication lacks workflow upload permission, which will need to be addressed when CI is configured.

## Publication preparation

A Grafana token in comments in the supplied helm.values.yaml and helm.stackgres.yaml test fixtures was replaced with an explicit dummy value after GitHub push protection flagged it. The 23 existing parsing tests passed again after this change.
