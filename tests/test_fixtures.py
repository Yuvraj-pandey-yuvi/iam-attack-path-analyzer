"""Fixture discovery and the fixture runner (Phase 2 step 2)."""

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REQUIRED_FILES = ("snapshot.json", "expected.json")
NOT_A_FOLDER = "fixtures must be folders (snapshot.json + expected.json)"


@dataclass(frozen=True)
class FoundFixture:
    name: str
    path: Path
    problems: tuple[str, ...]


def discover_fixtures(root: Path) -> list[FoundFixture]:
    if not root.is_dir():
        return []
    found = []
    for path in sorted(root.iterdir()):
        if path.is_dir():
            problems = tuple(
                f"missing {filename}"
                for filename in REQUIRED_FILES
                if not (path / filename).is_file()
            )
        else:
            problems = (NOT_A_FOLDER,)
        found.append(FoundFixture(name=path.name, path=path, problems=problems))
    return found


TOP_LEVEL_KEYS = frozenset({"rules", "edges", "admins", "shortest_paths", "can_reach"})
EDGE_KEYS = frozenset({"from", "to", "kind", "rule"})
JSON_TYPE_NAMES = {
    dict: "object",
    list: "array",
    str: "string",
    int: "number",
    float: "number",
    bool: "boolean",
    type(None): "null",
}


@dataclass(frozen=True)
class ExpectedEdge:
    source: str
    target: str
    kind: str
    rule: int


@dataclass(frozen=True)
class ExpectedResults:
    rules: frozenset[int]
    edges: frozenset[ExpectedEdge]
    admins: frozenset[str]
    shortest_paths: dict[str, frozenset[tuple[str, ...]]]
    can_reach: dict[str, frozenset[str]]


def json_type_name(value: object) -> str:
    return JSON_TYPE_NAMES[type(value)]


def check_keys(value: object, required_keys: frozenset[str], where: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{where}: must be an object, got {json_type_name(value)}")
    missing = sorted(required_keys - value.keys())
    unknown = sorted(value.keys() - required_keys)
    problems = []
    if missing:
        problems.append(f"missing keys {missing}")
    if unknown:
        problems.append(f"unknown keys {unknown}")
    if problems:
        raise ValueError(f"{where}: " + "; ".join(problems))
    return value


def make_fixture_folder(root: Path, name: str, files: tuple[str, ...]) -> None:
    folder = root / name
    folder.mkdir()
    for filename in files:
        (folder / filename).write_text("{}")


def test_discover_reports_every_item_in_name_order(tmp_path):
    make_fixture_folder(tmp_path, "b_case", REQUIRED_FILES)
    make_fixture_folder(tmp_path, "a_case", ("snapshot.json",))
    (tmp_path / "notes.txt").write_text("stray")
    found = discover_fixtures(tmp_path)
    assert [(entry.name, entry.problems) for entry in found] == [
        ("a_case", ("missing expected.json",)),
        ("b_case", ()),
        ("notes.txt", (NOT_A_FOLDER,)),
    ]


def test_discover_missing_folder_returns_nothing(tmp_path):
    assert discover_fixtures(tmp_path / "does_not_exist") == []


def test_discover_empty_folder_returns_nothing(tmp_path):
    assert discover_fixtures(tmp_path) == []


def test_discover_rejects_folder_named_like_required_file(tmp_path):
    make_fixture_folder(tmp_path, "case", ("snapshot.json",))
    (tmp_path / "case" / "expected.json").mkdir()
    assert discover_fixtures(tmp_path)[0].problems == ("missing expected.json",)


def test_fixtures_exist():
    assert FIXTURES_DIR.is_dir(), f"fixtures folder not found: {FIXTURES_DIR}"
    folders = [
        entry for entry in discover_fixtures(FIXTURES_DIR) if entry.path.is_dir()
    ]
    assert folders, f"no fixture folders found in {FIXTURES_DIR}"


CHECK_KEYS_FAILURES = [
    pytest.param(["a"], "where: must be an object, got array", id="not-object"),
    pytest.param(None, "where: must be an object, got null", id="null"),
    pytest.param(
        {"from": "a", "to": "b", "kind": "grant"},
        "where: missing keys ['rule']",
        id="missing",
    ),
    pytest.param(
        {"from": "a", "to": "b", "kind": "grant", "rule": 3, "note": "x"},
        "where: unknown keys ['note']",
        id="unknown",
    ),
    pytest.param(
        {"from": "a", "to": "b", "kind": "grant", "zeta": 1, "alpha": 2},
        "where: missing keys ['rule']; unknown keys ['alpha', 'zeta']",
        id="both-sorted",
    ),
]


@pytest.mark.parametrize(("value", "message"), CHECK_KEYS_FAILURES)
def test_check_keys_rejects(value, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        check_keys(value, EDGE_KEYS, "where")


def test_check_keys_returns_the_same_dict():
    value = {"from": "a", "to": "b", "kind": "grant", "rule": 3}
    assert check_keys(value, EDGE_KEYS, "where") is value
