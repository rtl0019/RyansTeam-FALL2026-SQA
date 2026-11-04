"""Bounded, reproducible generative fuzzing of ten supplied parser methods.

No network, Kubernetes cluster, yq, or scanner dependencies are needed.
Exit codes: 0 = completed discovery run, 1 = findings in strict/replay mode,
2 = incomplete run or harness failure. Findings are always saved and printed.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import traceback

import ruamel.yaml
import parser as subject


TARGETS = (
    "keyMiner", "getKeyRecursively", "getValuesRecursively", "getValsFromKey",
    "find_json_path_keys", "update_json_paths", "getSingleDict4MultiDocs",
    "loadMultiYAML", "checkParseError", "checkIfValidK8SYaml",
)
SCALARS = [None, False, True, -1, 0, 1, 1.5, "", "alpha", "needle", "List", "a.b"]
KEYS = ["a", "b", "target", "items", "spec", "a.b", "a*b", "0", None, 1, 1.5]


def pack(value):
    """Keep non-string YAML keys intact when saving JSON reproducers."""
    if isinstance(value, dict):
        return {"mapping": [[pack(k), pack(v)] for k, v in value.items()]}
    if isinstance(value, (list, tuple)):
        return [pack(v) for v in value]
    return value


def unpack(value):
    if isinstance(value, dict):
        return {unpack(k): unpack(v) for k, v in value["mapping"]}
    if isinstance(value, list):
        return [unpack(v) for v in value]
    return value


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


class ContractFailure(Exception):
    def __init__(self, code, expected, actual):
        super().__init__(code)
        self.code, self.expected, self.actual = code, expected, actual


def require(condition, code, expected, actual):
    if not condition:
        raise ContractFailure(code, expected, actual)


def tree(rng, depth=0):
    if depth >= 3 or rng.random() < 0.35:
        return copy.deepcopy(rng.choice(SCALARS))
    if rng.random() < 0.4:
        return [tree(rng, depth + 1) for _ in range(rng.randrange(4))]
    return {rng.choice(KEYS): tree(rng, depth + 1) for _ in range(rng.randrange(4))}


def as_mapping(value):
    return value if isinstance(value, dict) else {"items": value}


def yaml_text(value):
    stream = io.StringIO()
    yaml = ruamel.yaml.YAML()
    yaml.allow_unicode = False
    yaml.dump(value, stream)
    return stream.getvalue()


def reference_values(value):
    """Independent iterative traversal, preserving document order."""
    stack, leaves = [value], []
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend(reversed(node))
        else:
            leaves.append(node)
    return leaves


def reference_keys(value):
    stack, found = [(value, 0)], []
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            found.extend((key, depth) for key in node)
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth) for child in node)
    return found


def reference_matches(value, target):
    found = []
    def walk(node):
        if isinstance(node, dict):
            for key, child in node.items():
                if key == target:
                    found.append(child)
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(value)
    return found


def corpus(target):
    trees = [{}, {"a": []}, {"a": [1, 2]}, {"a": {}, "b": 1},
             {"a": {"x": 1}, "b": {"y": 2}},
             {"target": {"target": "needle"}},
             {"items": [[{"target": "needle"}]]},
             {"a.b": 1, "a*b": 2}, {None: "alpha"}, {1.5: "alpha"}]
    if target == "update_json_paths":
        return [{"paths": p} for p in [[], [""], ["[0]"], ["[12].spec"],
                                      ["[1].a[2].b", "[10].a", ".plain"]]]
    if target == "getSingleDict4MultiDocs":
        return [{"documents": d} for d in [[], [None], [[]], [[{}]],
                [{1: "a"}, {1: "b"}], [{"a": 1}, {"a": 2}],
                [{"a": 1, "a.YAML.DOC.1": 2}, {"a": 3}]]]
    if target in {"loadMultiYAML", "checkParseError", "checkIfValidK8SYaml"}:
        texts = ["", "---\n", "[", "a: [1, 2", "a: 1\na: 2\n",
                 "null: alpha\n", "1.5: alpha\n", "[]\n", "- []\n",
                 "apiVersion: v1\nkind: Pod\n", "apiVersion: ''\nkind: Pod\n",
                 "spec:\n  apiVersion: v1\n  kind: Pod\n",
                 "apiVersion: v1\nkind: Pod\nmetadata:\n  labels:\n    note: List\n",
                 "apiVersion: v1\nkind: Pod\n---\nkind: Service\n"]
        texts.extend(yaml_text(t) for t in trees)
        return [{"text": t} for t in texts]
    return [{"tree": t, "target": "target" if target == "getValsFromKey" else "needle"}
            for t in trees]


def generate(target, rng):
    if target == "update_json_paths":
        return {"paths": [f"[{rng.randrange(100)}].spec.items[{rng.randrange(4)}].name"
                          for _ in range(rng.randrange(8))]}
    if target == "getSingleDict4MultiDocs":
        documents = [rng.choice([None, [], as_mapping(tree(rng))])
                     for _ in range(rng.randrange(5))]
        return {"documents": documents}
    if target in {"loadMultiYAML", "checkParseError", "checkIfValidK8SYaml"}:
        value = tree(rng)
        if target == "checkIfValidK8SYaml" and rng.random() < 0.7:
            value = {"apiVersion": rng.choice(["v1", "apps/v1", "", None]),
                     "kind": rng.choice(["Pod", "Deployment", "ConfigMap", "List", ""]),
                     "metadata": {"name": "fuzz", "labels": {"note": rng.choice(["alpha", "List"])}}}
        text = yaml_text(value)
        # Mutate serialized YAML as well as generating new object structures.
        mutation = rng.randrange(6)
        if mutation == 0:
            text += "\n---\n" + yaml_text(as_mapping(tree(rng)))
        elif mutation == 1:
            text = text[:rng.randrange(len(text) + 1)]
        elif mutation == 2:
            text = "# fuzz input\n\n" + text
        elif mutation == 3:
            text += "\nunterminated: ["
        return {"text": text}
    value = tree(rng)
    if target in {"getKeyRecursively", "getValsFromKey", "find_json_path_keys"}:
        value = as_mapping(value)
    return {"tree": value, "target": rng.choice(["needle", "target", "absent"])}


def check(target, data, scratch):
    """Only the call and its documented-domain properties are finding candidates."""
    subject.key_jsonpath_mapping.clear()
    if target == "keyMiner":
        value, wanted = data["tree"], data["target"]
        actual = subject.keyMiner(value, wanted)
        exists = wanted in reference_values(value)
        require((actual is not None) == exists, "value-search-completeness", exists, actual)
        if actual is not None:
            node = value
            for part in actual[:-1]:
                node = node[int(part)] if isinstance(node, list) else node[part]
            require(node == wanted and actual[-1] == wanted,
                    "returned-path-reaches-value", wanted, node)
    elif target == "getKeyRecursively":
        actual = []
        subject.getKeyRecursively(data["tree"], actual)
        expected = reference_keys(data["tree"])
        # Order is unspecified. Separate missing keys from incorrect depths.
        key_counts = lambda pairs: sorted(json.dumps(pack(key)) for key, _ in pairs)
        normalize = lambda pairs: sorted(json.dumps(pack(list(p))) for p in pairs)
        require(key_counts(actual) == key_counts(expected), "all-key-occurrences", expected, actual)
        require(normalize(actual) == normalize(expected), "correct-key-depths", expected, actual)
    elif target == "getValuesRecursively":
        actual = list(subject.getValuesRecursively(data["tree"]))
        expected = reference_values(data["tree"])
        require(actual == expected, "all-leaf-values", expected, actual)
    elif target == "getValsFromKey":
        actual = []
        subject.getValsFromKey(data["tree"], data["target"], actual)
        expected = reference_matches(data["tree"], data["target"])
        require(actual == expected, "all-matching-key-values", expected, actual)
    elif target == "find_json_path_keys":
        before = copy.deepcopy(data["tree"])
        actual = subject.find_json_path_keys(data["tree"])
        require(isinstance(actual, list) and all(isinstance(p, str) for p in actual),
                "string-path-list", "list of strings", actual)
        require(data["tree"] == before, "input-not-mutated", before, data["tree"])
    elif target == "update_json_paths":
        expected = []
        for path in data["paths"]:
            if path.startswith("["):
                head, separator, tail = path[1:].partition("]")
                if separator and head.isdecimal():
                    path = tail
            if path:
                expected.append(path)
        actual = subject.update_json_paths(data["paths"])
        require(actual == expected, "remove-only-root-index", expected, actual)
    elif target == "getSingleDict4MultiDocs":
        documents = data["documents"]
        expected_count = 0
        for doc in documents:
            if isinstance(doc, list):
                doc = doc[0] if doc else None
            if isinstance(doc, dict):
                expected_count += len(doc)
        actual = subject.getSingleDict4MultiDocs(documents)
        require(len(actual) == expected_count, "merge-preserves-entry-count", expected_count, len(actual))
    else:
        path = scratch / "input.yaml"
        path.write_text(data["text"], encoding="utf-8")
        try:
            expected_docs = list(ruamel.yaml.YAML().load_all(data["text"]))
            valid_yaml = True
        except ruamel.yaml.error.YAMLError:
            expected_docs, valid_yaml = [], False
        if target == "checkParseError":
            actual = subject.checkParseError(str(path))
            require(actual == valid_yaml, "yaml-syntax-validity", valid_yaml, actual)
        elif target == "loadMultiYAML":
            actual = subject.loadMultiYAML(str(path))
            if valid_yaml:
                require(actual == expected_docs, "valid-yaml-roundtrip", expected_docs, actual)
        else:
            actual = subject.checkIfValidK8SYaml(str(path))
            # Deliberately a small contract, not a full Kubernetes schema validator.
            # Multiple documents have application-specific acceptance rules.
            if valid_yaml and len(expected_docs) == 1:
                doc = expected_docs[0]
                expected = (isinstance(doc, dict)
                            and isinstance(doc.get("apiVersion"), str) and bool(doc["apiVersion"])
                            and isinstance(doc.get("kind"), str) and bool(doc["kind"])
                            and doc["kind"] not in subject.constants.K8S_FORBIDDEN_KW_LIST)
                code = "validator-false-positive" if actual else "validator-false-negative"
                require(actual == expected, code, expected, actual)


def evaluate(target, data, scratch):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            check(target, copy.deepcopy(data), scratch)
    except ContractFailure as exc:
        return {"kind": "contract", "signature": exc.code,
                "expected": pack(exc.expected), "actual": pack(exc.actual)}
    except Exception as exc:
        frames = traceback.extract_tb(exc.__traceback__)
        location = frames[-1]
        return {"kind": "exception", "signature": f"{type(exc).__name__}:{Path(location.filename).name}:{location.lineno}",
                "exception": type(exc).__name__, "message": str(exc)[:500],
                "traceback": traceback.format_exc()}
    return None


def worker(target, seed, cases, output):
    # Each target owns its PRNG, so changing target order does not change inputs.
    rng = random.Random(seed + TARGETS.index(target) * 100003)
    seeds = corpus(target)
    findings = {}
    with tempfile.TemporaryDirectory(prefix="slikube-fuzz-") as temporary:
        scratch = Path(temporary)
        for index in range(cases):
            data = seeds[index] if index < len(seeds) else generate(target, rng)
            finding = evaluate(target, data, scratch)
            if finding is None:
                continue
            signature = finding["kind"] + ":" + finding["signature"]
            if signature in findings:
                findings[signature]["occurrences"] += 1
            else:
                finding.update(target="parser." + target, seed=seed, case_index=index,
                               input=pack(data), occurrences=1,
                               id=hashlib.sha256((target + signature).encode()).hexdigest()[:12])
                findings[signature] = finding
    write_json(output, {"target": "parser." + target, "cases_executed": cases,
                        "boundary_cases": min(cases, len(seeds)),
                        "generated_cases": max(0, cases - len(seeds)),
                        "findings": list(findings.values())})


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--seed", type=int, default=5710)
    cli.add_argument("--cases", type=int, default=300, help="cases per method, including boundary corpus")
    cli.add_argument("--timeout", type=float, default=30, help="wall-clock seconds per isolated method")
    cli.add_argument("--output", type=Path, default=Path("fuzz-results"))
    cli.add_argument("--replay", type=Path, help="reproduce one saved finding (trusted project JSON only)")
    cli.add_argument("--fail-on-findings", action="store_true", help="exit 1 when findings are discovered")
    cli.add_argument("--_worker", choices=TARGETS, help=argparse.SUPPRESS)
    args = cli.parse_args()
    if args.cases < 1 or args.timeout <= 0:
        cli.error("--cases and --timeout must be positive")
    if args._worker:
        worker(args._worker, args.seed, args.cases, args.output)
        return 0
    if args.replay:
        record = json.loads(args.replay.read_text(encoding="utf-8"))
        target = record["target"].removeprefix("parser.")
        if target not in TARGETS:
            cli.error("reproducer target is not in the fixed allowlist")
        with tempfile.TemporaryDirectory(prefix="slikube-replay-") as tmp:
            result = evaluate(target, unpack(record["input"]), Path(tmp))
        if result is None:
            print("Finding no longer reproduces.")
            return 0
        print(json.dumps(result, indent=2))
        return 1 if result["signature"] == record["signature"] else 2
    started, results, errors = time.monotonic(), [], []
    with tempfile.TemporaryDirectory(prefix="slikube-workers-") as tmp:
        for index, target in enumerate(TARGETS):
            result_path = Path(tmp) / f"{index}.json"
            command = [sys.executable, str(Path(__file__).resolve()), "--_worker", target,
                       "--seed", str(args.seed), "--cases", str(args.cases), "--output", str(result_path)]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
                if completed.returncode:
                    raise RuntimeError(completed.stderr[-2000:] or "worker exited without diagnostics")
                result = json.loads(result_path.read_text(encoding="utf-8"))
                results.append(result)
                print(f"parser.{target}: {result['cases_executed']} cases, {len(result['findings'])} finding groups", flush=True)
            except (subprocess.TimeoutExpired, RuntimeError, OSError, ValueError) as exc:
                errors.append({"target": "parser." + target, "error": str(exc)})
                print(f"parser.{target}: INCOMPLETE ({type(exc).__name__})", flush=True)
    findings = [f for result in results for f in result["findings"]]
    summary = {"schema_version": 1, "seed": args.seed, "cases_per_method": args.cases,
               "target_count": len(TARGETS), "completed_target_count": len(results),
               "total_cases": sum(r["cases_executed"] for r in results),
               "finding_groups": len(findings), "methods": results, "harness_errors": errors}
    write_json(args.output / "summary.json", summary)
    for finding in findings:
        write_json(args.output / "findings" / (finding["id"] + ".json"), finding)
    print(f"Completed {len(results)}/{len(TARGETS)} methods, {summary['total_cases']} cases, "
          f"{len(findings)} finding groups in {time.monotonic() - started:.1f}s.")
    print(f"Evidence: {args.output / 'summary.json'}")
    # Discovery mode saves findings without making known upstream defects break CI.
    # Infrastructure failures ALWAYS fail, even in discovery mode.
    return 2 if errors else (1 if findings and args.fail_on_findings else 0)


if __name__ == "__main__":
    raise SystemExit(main())
