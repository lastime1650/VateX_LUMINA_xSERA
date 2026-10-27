"""Bounded pure computation reuse; no admissions, authorization or scores cached."""

import json
from collections import OrderedDict
from threading import RLock

from .research_behavior_graph import digest
from .storage import encode

MAX_ENTRIES=4096
MAX_BYTES=16*1024*1024
_values=OrderedDict()
_lock=RLock()
_bytes=0


def compute(namespace,inputs,calculate):
    """Key includes actual pure input bytes, never just a caller-provided ID.

    Callers must still read originals and validate current authority on every
    operation. JSON value copies ensure a result cannot contaminate callers.
    """
    global _bytes
    key=(namespace,digest(inputs))
    with _lock:
        if key in _values:
            value,size=_values.pop(key);_values[key]=(value,size)
            return json.loads(value)
    value=calculate()
    serialized=encode(value);size=len(serialized.encode())
    if size>MAX_BYTES:return value
    with _lock:
        if key in _values:_bytes-=_values.pop(key)[1]
        _values[key]=(serialized,size);_bytes+=size
        while len(_values)>MAX_ENTRIES or _bytes>MAX_BYTES:_bytes-=_values.popitem(last=False)[1][1]
    return value


def clear():
    global _bytes
    with _lock:_values.clear();_bytes=0


def status():
    with _lock:return {"entries":len(_values),"maximum_entries":MAX_ENTRIES,"bytes":_bytes,"maximum_bytes":MAX_BYTES,"authority_cached":False,"predictions_cached":False,"raw_facts_cached":False}
