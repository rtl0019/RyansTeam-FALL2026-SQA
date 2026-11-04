# Local Windows setup

Project folder: D:\KubeSec-master

This is a command-line scanner for Kubernetes YAML files; it does not start a website or require a Kubernetes cluster.

## Run the included sample

In PowerShell:

```powershell
cd D:\KubeSec-master
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

## Scan another folder

```powershell
powershell -ExecutionPolicy Bypass -File D:\KubeSec-master\run.ps1 -ManifestDirectory 'D:\path\to\manifests'
```

The tool writes slikube_results.csv into the manifest folder and SLIKUBE.sarif into the project folder. Subsequent scans overwrite these outputs.

## Run the existing parsing tests

```powershell
cd D:\KubeSec-master
.\.venv\Scripts\python.exe TEST_PARSING.py
```

## Setup details

- An isolated Python 3.12 environment lives in .venv. It was created using the Python runtime bundled with Codex; removing that runtime may require recreating this environment with a standalone Python installation.
- requirements-local.txt records the direct dependencies chosen for this setup. The original requirements.txt is preserved.
- tools\yq.exe is Mike Farah's yq v4.44.3 for Windows AMD64. run.ps1 adds it to PATH only for the current process.
- main.py was corrected to import pathlib.Path and typer and call typer.run(main). The original is saved as main.py.original.
- sample-manifests contains an unchanged copy of TEST_ARTIFACTS\test.sample.pod.yaml. It is only read by the scanner; no container is launched.
- Some original integration tests refer to the author's external filesystem and will require separate work later.

Today's scope is extraction and local execution. Assignment fuzzing, forensic instrumentation, GitHub setup, and CI changes have not been performed.

## Verified on October 26, 2026

- TEST_PARSING.py: all 23 tests passed (setup-parsing-tests.log).
- run.ps1: sample scan exited successfully (setup-sample-run.log).
- sample-manifests\slikube_results.csv: one manifest, 22 columns.
- SLIKUBE.sarif: JSON parsed successfully and includes the privileged-container rule SLIKUBE_11.
- requirements-local-lock.txt records installed package versions.
- Python 3.12 emits nonfatal invalid-escape SyntaxWarnings from the original parser regex strings on first import. These do not prevent the verified run.
