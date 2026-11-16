import pytest

from mmlabs_auth import permits


def test_exact_match() -> None:
    assert permits({"ricotdin:notes:read"}, "ricotdin:notes:read")
    assert not permits({"ricotdin:notes:read"}, "ricotdin:notes:write")


def test_app_wildcard() -> None:
    assert permits(["ricotdin:*"], "ricotdin:notes:write")


def test_no_global_star() -> None:
    assert not permits({"*"}, "ricotdin:notes:read")


def test_no_resource_wildcard() -> None:
    assert not permits({"ricotdin:notes:*"}, "ricotdin:notes:read")


def test_other_app_wildcard_denied() -> None:
    assert not permits({"stoktok:*"}, "ricotdin:notes:read")


@pytest.mark.parametrize("required", ["", "ricotdin", "ricotdin:", ":notes:read"])
def test_malformed_required_false(required: str) -> None:
    assert not permits({"ricotdin:*", required}, required)


def test_str_granted_type_error() -> None:
    with pytest.raises(TypeError):
        permits("ricotdin:notes:read", "ricotdin:notes:read")
