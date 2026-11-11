# Forensic instrumentation

The assignment asks to integrate forensics by modifying ten Python methods, without specifying a logging format or a particular library. This implementation interprets forensics as recording execution evidence that can reconstruct the order, nesting, results, and failures of parser calls. Confirm any additional lecture-specific requirements with the instructor.

## Modified methods

Each of these methods in `parser.py` now has an explicit `@forensic` decorator:

1. `keyMiner`
2. `getKeyRecursively`
3. `getValsFromKey`
4. `find_json_path_keys`
5. `update_json_paths`
6. `getSingleDict4MultiDocs`
7. `loadMultiYAML`
8. `checkParseError`
9. `checkIfValidK8SYaml`
10. `readYAMLAsStr`

Nine overlap the fuzz targets. `readYAMLAsStr` replaces the generator `getValuesRecursively` for this activity; generator lifetime and suspension would need different tracing semantics. Existing parser source line numbers are preserved so earlier fuzz reproducer signatures remain usable.

## Run and inspect

From the project directory in PowerShell:

```powershell
.\.venv\Scripts\python.exe TEST_FORENSICS.py
.\.venv\Scripts\python.exe forensics_demo.py --output forensic-results/my-run.jsonl
Get-Content forensic-results/my-run.summary.json
Get-Content forensic-results/my-run.jsonl
```

Use a new output filename for each run: existing evidence files are deliberately not overwritten. The demo returns a nonzero exit code if any evidence or behavior check fails. No additional dependencies beyond `requirements-fuzz.txt` are needed. Normal scanner and fuzz runs have logging disabled. To trace another synchronous operation, wrap it in `with forensic_session(path):` imported from `forensic_logging`.

## Evidence interpretation

The committed `evidence/forensics/validated-events.jsonl` contains 96 JSON lines: session start/end plus 47 call/outcome pairs covering all ten methods. The companion summary records validation results.

Each event contains a UTC timestamp, run ID and increasing sequence. Calls contain a unique call ID, parent call ID, method name, and argument type/length metadata. Outcomes contain the matching call ID, elapsed nanoseconds, return metadata, and argument metadata after execution. Boolean results are recorded to distinguish successful validation from rejection. Errors include exception class and bounded stack-frame file names, method names and line numbers; the original exception propagates to the caller.

Reconstruct a failure by finding an `outcome` with `status: error`, matching its `call_id` to the call record, and following `parent_call_id` to enclosing operations. Sort by sequence for within-run execution order; elapsed durations use a monotonic clock.

The demo exercises successful traversal and parsing, malformed YAML returning `False`, the known empty-document merge bug producing `IndexError`, and a missing file producing `FileNotFoundError`. These two exceptions are expected and caught by the demo. A `returned` outcome means the method returned normally, not that its answer was logically correct. In particular, malformed YAML is recorded as a normal `False` return.

## Validation and limits

The demo verifies coverage of ten methods, paired calls/outcomes, parent references, sequence continuity, nonnegative durations, expected error types, rejection evidence, and absence of a synthetic private value. `TEST_FORENSICS.py` checks default-disabled logging, preserved mutation/signature behavior, propagated errors, overwrite protection and context cleanup.

Logs exclude YAML contents, input values, exception messages, local variables and full paths. This limits exposure but also means logs alone cannot reproduce an input: use the synthetic demo fixtures or the separately saved fuzz reproducers. Instrumentation does not fix the documented parser bugs.

This is a synchronous, single-process educational trace, not a tamper-proof audit system or full digital-forensic acquisition tool. It does not hash/sign records or record source-file contents. Abrupt process termination can leave missing outcomes; a disk-write failure warns and marks the session incomplete, and the demo fails validation. Logging overhead affects measured timing. The evidence must be kept with its corresponding source revision.

Forensic CI execution and a CI screenshot are the next integration step; the existing workflow currently runs parsing tests and fuzzing only.
