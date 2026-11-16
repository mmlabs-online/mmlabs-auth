import tomllib
from pathlib import Path

import mmlabs_auth

PYTHON_DIR = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((PYTHON_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    assert mmlabs_auth.__version__ == pyproject["project"]["version"]


def test_core_does_not_import_fastapi() -> None:
    import subprocess
    import sys

    code = "import sys, mmlabs_auth; sys.exit('fastapi' in sys.modules)"
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0  # noqa: S603
