"""Run deterministic forensic scenarios and validate the resulting evidence."""
import argparse
import json
from pathlib import Path
import tempfile

import parser
from forensic_logging import forensic_session

TARGETS = ('keyMiner', 'getKeyRecursively', 'getValsFromKey',
           'find_json_path_keys', 'update_json_paths', 'getSingleDict4MultiDocs',
           'loadMultiYAML', 'checkParseError', 'checkIfValidK8SYaml', 'readYAMLAsStr')


def run(output):
    secret = 'DEMO_PRIVATE_VALUE_MUST_NOT_APPEAR'
    with tempfile.TemporaryDirectory() as directory:
        valid = Path(directory) / 'valid.yaml'
        invalid = Path(directory) / 'invalid.yaml'
        valid.write_text('apiVersion: v1\nkind: Pod\nmetadata:\n  name: ' + secret + '\n', encoding='utf-8')
        invalid.write_text('broken: [\n', encoding='utf-8')
        with forensic_session(output) as session:
            parser.key_jsonpath_mapping.clear()
            assert parser.keyMiner({'a': secret}, secret) == ['a', secret]
            keys = []
            parser.getKeyRecursively({'a': secret}, keys)
            assert keys == [('a', 0)]
            values = []
            parser.getValsFromKey({'a': secret}, 'a', values)
            assert values == [secret]
            assert parser.find_json_path_keys({'a': secret}) == ['.a']
            assert parser.update_json_paths(['[0].a']) == ['.a']
            assert parser.getSingleDict4MultiDocs([{'a': 1}, {'b': 2}]) == {'a': 1, 'b': 2}
            assert len(parser.loadMultiYAML(valid)) == 1
            assert parser.checkParseError(valid) is True
            assert parser.checkIfValidK8SYaml(valid) is True
            assert secret in parser.readYAMLAsStr(valid)
            assert parser.checkParseError(invalid) is False
            try:
                parser.getSingleDict4MultiDocs([[]])
            except IndexError:
                pass
            else:
                raise AssertionError('Expected known empty-document defect')
            try:
                parser.loadMultiYAML(Path(directory) / 'missing.yaml')
            except FileNotFoundError:
                pass
            else:
                raise AssertionError('Expected missing-file error')
        assert not session.failed, 'Evidence writer failed'

    raw = Path(output).read_text(encoding='utf-8')
    assert secret not in raw
    records = [json.loads(line) for line in raw.splitlines()]
    assert [r['sequence'] for r in records] == list(range(1, len(records) + 1))
    assert len({r['run_id'] for r in records}) == 1
    assert records[0]['event'] == 'session_start'
    assert records[-1]['event'] == 'session_end'
    calls = {r['call_id']: r for r in records if r['event'] == 'call'}
    outcomes = [r for r in records if r['event'] == 'outcome']
    assert len(calls) == len(outcomes)
    assert {r['call_id'] for r in outcomes} == set(calls)
    assert set(TARGETS) == {r['method'] for r in calls.values()}
    for call in calls.values():
        parent = call['parent_call_id']
        assert parent is None or parent in calls
        if parent:
            assert calls[parent]['sequence'] < call['sequence']
    assert any(r['parent_call_id'] for r in calls.values())
    assert all(r['duration_ns'] >= 0 for r in outcomes)
    assert {r['exception_type'] for r in outcomes if r['status'] == 'error'} == {'IndexError', 'FileNotFoundError'}
    assert any(r['method'] == 'checkParseError' and r.get('result') == {'type': 'bool', 'value': False} for r in outcomes)
    summary = dict(instrumented_methods=list(TARGETS), method_count=len(TARGETS),
                   calls=len(calls), records=len(records),
                   error_outcomes=sum(r['status'] == 'error' for r in outcomes),
                   secret_value_absent=True, validation='passed')
    Path(output).with_suffix('.summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--output', default='forensic-results/events.jsonl')
    run(cli.parse_args().output)
