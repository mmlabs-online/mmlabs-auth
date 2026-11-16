import json
import re
from pathlib import Path

CONTRACT_DIR = Path(__file__).resolve().parents[2] / "contract"


def test_contract_files_parse() -> None:
    files = sorted(CONTRACT_DIR.glob("*.json"))
    assert {f.name for f in files} == {
        "catalog.example.json",
        "error-codes.json",
        "token-response.example.json",
    }
    for f in files:
        assert isinstance(json.loads(f.read_text(encoding="utf-8")), dict)


def test_permission_denied_in_contract() -> None:
    contract = json.loads((CONTRACT_DIR / "error-codes.json").read_text(encoding="utf-8"))
    assert contract["codes"]["permission_denied"]["status"] == 403
    assert contract["library_codes"]["python"] == {
        "unauthorized": {"status": 401},
        "permission_denied": {"status": 403},
        "auth_unavailable": {"status": 503},
    }


def test_source_is_sha() -> None:
    first_line = (CONTRACT_DIR / "SOURCE").read_text(encoding="utf-8").splitlines()[0]
    assert re.fullmatch(r"[0-9a-f]{40}", first_line)
