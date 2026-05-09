#!/usr/bin/env python3
"""
Lint: forbid reading ``tenant_id`` from request/message bodies.

The authoritative tenant_id always comes from the verified service JWT
(``services._runtime.tenant.get_tenant_id``). Any code that fishes
tenant_id out of a payload, body, message, or other client-supplied
field is a multi-tenant data-leak waiting to happen.

This script walks the Python AST of every file under the repo (minus
``services/_runtime/tenant.py``, ``schemas/``, and ``tests/``) and fails
CI on any of the following patterns:

    payload["tenant_id"]
    body["tenant_id"]
    msg.data["tenant_id"]
    request.json()["tenant_id"]
    raw_payload.get("tenant_id")
    payload.tenant_id            # only flagged for non-AuthContext receivers

Exit code 0 = clean. Non-zero = violations printed to stderr.

Usage:
    uv run python scripts/lint_tenant_id.py [path ...]
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXEMPT_FILES = {
    REPO_ROOT / "services" / "_runtime" / "tenant.py",
    REPO_ROOT / "scripts" / "lint_tenant_id.py",
}

EXEMPT_DIRS = {
    REPO_ROOT / "schemas",      # the schema field itself is fine
    REPO_ROOT / "tests",        # tests can synthesize payloads with tenant_id
    REPO_ROOT / ".venv",
    REPO_ROOT / "node_modules",
    REPO_ROOT / "build",
    REPO_ROOT / "dist",
}

# Receiver names that are unsafe if you read tenant_id from them. We
# deliberately include common variable names that wrap untrusted input.
UNSAFE_NAMES = {
    "payload",
    "body",
    "raw_payload",
    "raw",
    "data",
    "msg",
    "message",
    "request",
    "req",
    "alert_data",
    "json_body",
    "input_data",
}

# Attribute names that almost always wrap untrusted input.
UNSAFE_ATTRS = {"json", "data", "raw_payload", "body", "payload"}


class TenantIdViolation(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[tuple[int, int, str]] = []

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        # Pattern: <something>["tenant_id"]
        key = _const_str(node.slice)
        if key == "tenant_id":
            recv = _root_name(node.value)
            recv_chain = _attr_chain(node.value)
            if recv in UNSAFE_NAMES or any(a in UNSAFE_ATTRS for a in recv_chain):
                self.violations.append(
                    (node.lineno, node.col_offset, _src(node))
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Pattern: <something>.get("tenant_id")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and _const_str(node.args[0]) == "tenant_id"
        ):
            recv = _root_name(node.func.value)
            recv_chain = _attr_chain(node.func.value)
            if recv in UNSAFE_NAMES or any(a in UNSAFE_ATTRS for a in recv_chain):
                self.violations.append(
                    (node.lineno, node.col_offset, _src(node))
                )
        self.generic_visit(node)


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _attr_chain(node: ast.AST) -> list[str]:
    chain: list[str] = []
    while isinstance(node, ast.Attribute):
        chain.append(node.attr)
        node = node.value
    return chain


def _src(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return f"<line {getattr(node, 'lineno', '?')}>"


def _walk_targets(targets: Iterable[Path]) -> Iterable[Path]:
    for target in targets:
        if not target.exists():
            continue
        if target.is_file() and target.suffix == ".py":
            yield target
            continue
        for path in target.rglob("*.py"):
            if any(d in path.parents for d in EXEMPT_DIRS):
                continue
            if path in EXEMPT_FILES:
                continue
            yield path


def lint(paths: list[Path]) -> int:
    total = 0
    for py in _walk_targets(paths):
        try:
            tree = ast.parse(py.read_text(), filename=str(py))
        except SyntaxError as exc:
            print(f"{py}: parse error: {exc}", file=sys.stderr)
            total += 1
            continue
        v = TenantIdViolation(py)
        v.visit(tree)
        for lineno, col, src in v.violations:
            rel = py.relative_to(REPO_ROOT)
            print(
                f"{rel}:{lineno}:{col}: forbidden tenant_id read from untrusted source: {src}",
                file=sys.stderr,
            )
            total += 1
    if total:
        print(
            f"\n{total} tenant_id violation(s). "
            f"Use services._runtime.tenant.get_tenant_id() instead.",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    args = [Path(a).resolve() for a in sys.argv[1:]] or [REPO_ROOT]
    return lint(args)


if __name__ == "__main__":
    raise SystemExit(main())
