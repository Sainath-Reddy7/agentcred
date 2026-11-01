"""Canonical JSON encoding — the shared byte-level foundation for signatures
and log hashing.

Exactly one canonical form exists so that any implementation, on any
platform, produces the same bytes for the same data. See docs/spec.md §7.
"""

from __future__ import annotations

import json
from typing import Any


def canonical(obj: Any) -> bytes:
    """Encode a JSON-serializable object to canonical bytes.

    Rules: UTF-8 output, keys sorted lexicographically, no insignificant
    whitespace (`,` and `:` separators only), non-ASCII preserved literally.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
