"""Opt-in, structured execution evidence; never records argument values."""
import contextvars
import functools
import json
import time
import uuid
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

_session = contextvars.ContextVar('forensic_session', default=None)
_parent = contextvars.ContextVar('forensic_parent', default=None)


def shape(value):
    """Bounded metadata only, even for arbitrary objects and secret strings."""
    result = {'type': type(value).__name__}
    if type(value) in (dict, list, tuple, str, bytes):
        result['length'] = len(value)
    if type(value) is bool:
        result['value'] = value
    return result


class EvidenceSession:
    def __init__(self, stream):
        self.stream = stream
        self.run_id = uuid.uuid4().hex
        self.sequence = 0
        self.failed = False

    def emit(self, event, **fields):
        if self.failed:
            return
        self.sequence += 1
        record = dict(schema_version=1, run_id=self.run_id,
                      sequence=self.sequence,
                      timestamp=datetime.now(timezone.utc).isoformat(),
                      event=event, **fields)
        try:
            self.stream.write(json.dumps(record, sort_keys=True) + '\n')
            self.stream.flush()
        except OSError:
            self.failed = True
            warnings.warn('Forensic evidence write failed; evidence is incomplete.', RuntimeWarning)


@contextmanager
def forensic_session(path):
    """Create a NEW evidence file, never silently overwrite an earlier run."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        session = EvidenceSession(stream)
        token = _session.set(session)
        parent_token = _parent.set(None)
        session.emit('session_start')
        try:
            yield session
        finally:
            session.emit('session_end')
            _parent.reset(parent_token)
            _session.reset(token)


@contextmanager
def _call(function, args, kwargs):
    session = _session.get()
    if session is None:
        yield None
        return
    call_id = uuid.uuid4().hex
    session.emit('call', method=function.__name__, call_id=call_id,
                 parent_call_id=_parent.get(),
                 arguments=[shape(arg) for arg in args],
                 keyword_arguments={key: shape(value) for key, value in kwargs.items()})
    token = _parent.set(call_id)
    started = time.perf_counter_ns()
    outcome = {}
    try:
        yield outcome
    except GeneratorExit:
        outcome['status'] = 'closed'
        raise
    except BaseException as error:
        outcome['status'] = 'error'
        outcome['exception_type'] = type(error).__name__
        # No exception messages, source text, full paths, or local variables.
        frames = []
        traceback = error.__traceback__
        while traceback is not None:
            code = traceback.tb_frame.f_code
            if Path(code.co_filename).name != 'forensic_logging.py':
                frames.append(dict(file=Path(code.co_filename).name,
                                   method=code.co_name, line=traceback.tb_lineno))
            traceback = traceback.tb_next
        outcome['frames'] = frames[-12:]
        raise
    finally:
        outcome.setdefault('status', 'returned')
        session.emit('outcome', method=function.__name__, call_id=call_id,
                     duration_ns=time.perf_counter_ns() - started, **outcome)
        _parent.reset(token)


def forensic(function):
    """Instrument synchronous, non-generator parser functions."""
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        with _call(function, args, kwargs) as outcome:
            result = function(*args, **kwargs)
            if outcome is not None:
                outcome['result'] = shape(result)
                outcome['arguments_after'] = [shape(arg) for arg in args]
            return result
    return wrapped
