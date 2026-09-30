"""Architecture guard: models must stay free of GUI and scanner dependencies."""

from __future__ import annotations

from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parents[2] / "app" / "models"

FORBIDDEN_TOKENS = ("PySide6", "QtWidgets", "QtCore", "netsh", "subprocess", "sqlite3")


def test_models_have_no_gui_scanner_or_storage_imports() -> None:
    for source in sorted(MODEL_DIR.glob("*.py")):
        text = source.read_text(encoding="utf-8")
        for token in FORBIDDEN_TOKENS:
            assert token not in text, f"{source.name} must not reference {token!r}"


def test_models_only_import_stdlib_and_own_package() -> None:
    import ast

    for source in sorted(MODEL_DIR.glob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                assert root in {"app", "dataclasses", "datetime", "enum", "typing", "re", "__future__"}, (
                    f"{source.name} imports unexpected module {name!r}"
                )
