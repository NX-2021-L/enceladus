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

# ENC-TSK-Q35 (ENC-ISS-831): hermetic credential defaults for the suite.
# Read scripts now refuse locally (exit 7) when no credential resolves, so
# the offline suite runs with a fixture internal key unless a test clears
# the environment itself; and the ELR key-file default points at a path
# that never exists, so a developer's real ~/.enceladus/internal_key can
# never leak into a test (tests that exercise the key file pass their own
# path via ENCELADUS_ELR_KEY_FILE).
import os as _os  # noqa: E402
import tempfile as _tempfile  # noqa: E402

from elr_lib import config as _elr_config  # noqa: E402

_elr_config.ELR_KEY_FILE_DEFAULT = str(
    Path(_tempfile.gettempdir()) / f"elr-tests-no-key-file-{_os.getpid()}"
)
_os.environ.setdefault("ENCELADUS_INTERNAL_API_KEY", "test-fixture-key-not-a-real-secret")
