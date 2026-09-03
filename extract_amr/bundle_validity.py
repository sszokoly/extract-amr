"""Expiration enforcement for generated single-file bundles."""

from __future__ import annotations

import math
import sys
import time
from typing import Union


def _enforce_bundle_validity(validity: Union[int, float]) -> None:
    """Reject invalid or expired generated bundle validity metadata."""
    if isinstance(validity, bool) or not isinstance(validity, (int, float)):
        print("error: invalid bundle validity metadata", file=sys.stderr)
        raise SystemExit(1)
    if isinstance(validity, float) and not math.isfinite(validity):
        print("error: invalid bundle validity metadata", file=sys.stderr)
        raise SystemExit(1)
    if validity < time.time():
        print("error: this extract-amr bundle has expired", file=sys.stderr)
        raise SystemExit(1)
