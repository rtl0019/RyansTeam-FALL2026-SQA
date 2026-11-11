"""Regression tests for evidence boundaries and unchanged parser behavior."""
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import parser
from forensic_logging import EvidenceSession, forensic_session


class ForensicTests(unittest.TestCase):
    def test_disabled_by_default(self):
        with patch.object(EvidenceSession, 'emit', side_effect=AssertionError('Unexpected logging')):
            self.assertEqual(parser.keyMiner({'a': 1}, 1), ['a', 1])

    def test_signature_and_mutation_preserved(self):
        self.assertEqual(inspect.signature(parser.getKeyRecursively), inspect.signature(parser.getKeyRecursively.__wrapped__))
        holder = []
        self.assertIsNone(parser.getKeyRecursively({'a': 1}, holder))
        self.assertEqual(holder, [('a', 0)])

    def test_exception_identity_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            with forensic_session(path):
                with self.assertRaises(IndexError):
                    parser.getSingleDict4MultiDocs([[]])
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            error = next(row for row in rows if row.get('status') == 'error')
            self.assertEqual(error['exception_type'], 'IndexError')
            self.assertEqual(error['frames'][-1]['method'], 'getSingleDict4MultiDocs')

    def test_evidence_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            path.write_text('original')
            with self.assertRaises(FileExistsError):
                with forensic_session(path):
                    pass
            self.assertEqual(path.read_text(), 'original')

    def test_session_reset_after_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            with self.assertRaises(IndexError):
                with forensic_session(path):
                    parser.getSingleDict4MultiDocs([[]])
            before = path.read_bytes()
            parser.keyMiner({'a': 1}, 1)
            self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
