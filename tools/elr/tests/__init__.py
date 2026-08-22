"""ELR offline unit tests. No network access -- everything here mocks
urllib.request.urlopen or exercises pure functions directly.
"""

import sys
from pathlib import Path

# Make `elr_lib` and `elr_smoke` importable regardless of CWD, whether run
# via `python3 -m pytest tools/elr/tests` or `python3 -m unittest` from
# tools/elr/tests directly.
_ELR_ROOT = str(Path(__file__).resolve().parent.parent)
if _ELR_ROOT not in sys.path:
    sys.path.insert(0, _ELR_ROOT)
