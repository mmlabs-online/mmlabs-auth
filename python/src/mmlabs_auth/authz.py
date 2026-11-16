"""Permission matcher (ADR-0003).

Verbatim copy of `permits()` from org-admin-api `app/modules/rbac/authz.py` (commit in
`contract/SOURCE`). `tests/test_drift.py` compares the two.
"""

from collections.abc import Sequence
from collections.abc import Set as AbstractSet


def permits(granted: AbstractSet[str] | Sequence[str], required: str) -> bool:
    """True if `granted` holds `required` exactly or the wildcard `<app>:*` of its app.

    No global `*` and no `<app>:<resource>:*`. Kept free of ORM imports: ADM-002 and the
    `mmlabs-auth` library copy it as is.
    """
    if isinstance(granted, str):  # `in` on a str would match substrings
        raise TypeError("granted must be a collection of keys, not a str")
    app, sep, rest = required.partition(":")
    if not sep or not app or not rest:
        return False
    return required in granted or f"{app}:*" in granted
