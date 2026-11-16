import json
import re
import tomllib
from pathlib import Path

import mmlabs_auth

PYTHON_DIR = Path(__file__).resolve().parents[1]
CONTRACT_DIR = PYTHON_DIR.parent / "contract"


def test_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((PYTHON_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    assert mmlabs_auth.__version__ == pyproject["project"]["version"]


def test_contract_files_parse() -> None:
    files = sorted(CONTRACT_DIR.glob("*.json"))
    assert {f.name for f in files} == {
        "catalog.example.json",
        "error-codes.json",
        "token-response.example.json",
    }
    for f in files:
        assert isinstance(json.loads(f.read_text(encoding="utf-8")), dict)
    first_line = (CONTRACT_DIR / "SOURCE").read_text(encoding="utf-8").splitlines()[0]
    assert re.fullmatch(r"[0-9a-f]{40}", first_line)
