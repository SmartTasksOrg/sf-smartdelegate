#!/usr/bin/env python3
"""`python harness/run.py ...` from anywhere: the same command line as
`python -m harness`, with the repository root and src/ put on the path."""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
