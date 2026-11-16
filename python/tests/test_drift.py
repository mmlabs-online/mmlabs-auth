"""Drift guard: the verbatim copies against an org-admin-api checkout.

Looks in `$ORG_ADMIN_API_DIR`, else a sibling `org-admin-api` next to this repo. Skipped when no
checkout is available (CI). Compares ASTs, so formatting does not matter; only the planned
adaptations of `verify_access_token` are undone before comparing.
"""

import ast
import os
from pathlib import Path

import pytest

import mmlabs_auth.access_token as copy_token
import mmlabs_auth.authz as copy_authz

REPO = Path(__file__).resolve().parents[2]
SERVER = Path(os.environ.get("ORG_ADMIN_API_DIR", REPO.parent / "org-admin-api"))
SERVER_TOKEN = SERVER / "app" / "core" / "access_token.py"
SERVER_AUTHZ = SERVER / "app" / "modules" / "rbac" / "authz.py"
SERVER_KEYS = SERVER / "app" / "core" / "jwt_keys.py"

pytestmark = pytest.mark.skipif(
    not (SERVER_TOKEN.is_file() and SERVER_AUTHZ.is_file() and SERVER_KEYS.is_file()),
    reason="org-admin-api checkout not available",
)


def _tree(path: Path | str) -> ast.Module:
    return ast.parse(Path(path).read_text(encoding="utf-8"))


def _node(tree: ast.Module, name: str) -> ast.AST:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.ClassDef) and node.name == name:
            return node
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return node.value
    raise AssertionError(f"{name} not found")


def _reasons(node: ast.AST) -> list[object]:
    return [
        n.args[0].value
        for n in ast.walk(node)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "InvalidAccessTokenError"
        and n.args
        and isinstance(n.args[0], ast.Constant)
    ]


class _UndoAdaptations(ast.NodeTransformer):
    """The copy's planned changes, mapped back to the server's code."""

    def visit_If(self, node: ast.If) -> ast.AST | None:
        test = node.test
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
            if test.left.id == "leeway":  # `if leeway > MAX_LEEWAY: raise ValueError`
                return None
        self.generic_visit(node)
        return node

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        node.values = [  # drop `len(kid) > MAX_KID_LENGTH`
            v
            for v in node.values
            if not (
                isinstance(v, ast.Compare)
                and isinstance(v.left, ast.Call)
                and isinstance(v.left.func, ast.Name)
                and v.left.func.id == "len"
            )
        ]
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id == "keys":  # `keys` → `key_set.public_keys`
            return ast.Attribute(ast.Name("key_set", ast.Load()), "public_keys", ast.Load())
        return node


def _body(fn: ast.AST) -> str:
    assert isinstance(fn, ast.FunctionDef)
    return "\n".join(ast.unparse(stmt) for stmt in fn.body)


def test_invalid_access_token_error_identical() -> None:
    server = _node(_tree(SERVER_TOKEN), "InvalidAccessTokenError")
    copy = _node(_tree(copy_token.__file__), "InvalidAccessTokenError")
    assert ast.dump(copy) == ast.dump(server)


def test_verify_access_token_body_identical_modulo_planned_changes() -> None:
    server = _node(_tree(SERVER_TOKEN), "verify_access_token")
    copy = _UndoAdaptations().visit(_node(_tree(copy_token.__file__), "verify_access_token"))
    assert _body(copy) == _body(server)


def test_reason_codes_identical() -> None:
    server = _tree(SERVER_TOKEN)
    copy = _tree(copy_token.__file__)
    assert _reasons(copy) == _reasons(server)


def test_required_claims_and_constants_identical() -> None:
    server_claims = ast.literal_eval(_node(_tree(SERVER_TOKEN), "REQUIRED_CLAIMS"))
    assert server_claims == copy_token.REQUIRED_CLAIMS
    keys = _tree(SERVER_KEYS)
    assert ast.literal_eval(_node(keys, "ALGORITHM")) == copy_token.ALGORITHM
    assert ast.literal_eval(_node(keys, "TOKEN_TYP")) == copy_token.TOKEN_TYP


def test_permits_identical() -> None:
    server = _node(_tree(SERVER_AUTHZ), "permits")
    copy = _node(_tree(copy_authz.__file__), "permits")
    assert ast.dump(copy) == ast.dump(server)
