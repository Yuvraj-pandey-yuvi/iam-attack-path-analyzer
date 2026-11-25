"""Fixture discovery and the fixture runner (Phase 2 step 2)."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from iampath.rules import RULE_KINDS

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


def read_rule_number(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where}: must be a whole number, got {json.dumps(value)}")
    if value not in RULE_KINDS:
        raise ValueError(f"{where}: unknown rule {value}")
    return value


def read_name(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"{where}: must be a non-empty string, got {json.dumps(value)}"
        )
    return value


def read_rules(value: object, where: str) -> frozenset[int]:
    if not isinstance(value, list):
        raise ValueError(f"{where}: must be an array, got {json_type_name(value)}")
    if not value:
        raise ValueError(f"{where}: must list at least one rule")
    for position, item in enumerate(value):
        read_rule_number(item, f"{where}[{position}]")
    reject_duplicates(value, where, "rules")
    return frozenset(value)


def reject_duplicates(items: list, where: str, what: str) -> None:
    texts = [json.dumps(item, sort_keys=True) for item in items]
    repeated = sorted({text for text in texts if texts.count(text) > 1})
    if repeated:
        raise ValueError(f"{where}: duplicate {what} [{', '.join(repeated)}]")


def read_names(value: object, where: str) -> frozenset[str]:
    if not isinstance(value, list):
        raise ValueError(f"{where}: must be an array, got {json_type_name(value)}")
    for position, item in enumerate(value):
        read_name(item, f"{where}[{position}]")
    reject_duplicates(value, where, "names")
    return frozenset(value)


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


READ_RULES_FAILURES = [
    pytest.param("3", "rules: must be an array, got string", id="not-array"),
    pytest.param([], "rules: must list at least one rule", id="empty"),
    pytest.param([3, True], "rules[1]: must be a whole number, got true", id="bool"),
    pytest.param([3.0], "rules[0]: must be a whole number, got 3.0", id="float"),
    pytest.param(["3"], 'rules[0]: must be a whole number, got "3"', id="string"),
    pytest.param([0], "rules[0]: unknown rule 0", id="zero"),
    pytest.param([22], "rules[0]: unknown rule 22", id="too-big"),
    pytest.param([10, 3, 10, 3], "rules: duplicate rules [10, 3]", id="duplicates"),
]


@pytest.mark.parametrize(("value", "message"), READ_RULES_FAILURES)
def test_read_rules_rejects(value, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        read_rules(value, "rules")


def test_read_rules_returns_a_frozenset():
    result = read_rules([10, 3], "rules")
    assert isinstance(result, frozenset)
    assert result == {3, 10}


READ_NAMES_FAILURES = [
    pytest.param({"a": 1}, "admins: must be an array, got object", id="not-array"),
    pytest.param(
        ["role/A", 5], "admins[1]: must be a non-empty string, got 5", id="number"
    ),
    pytest.param(
        [""], 'admins[0]: must be a non-empty string, got ""', id="empty-string"
    ),
    pytest.param([None], "admins[0]: must be a non-empty string, got null", id="null"),
    pytest.param(
        ["role/B", "role/A", "role/B", "role/A"],
        'admins: duplicate names ["role/A", "role/B"]',
        id="duplicates",
    ),
]


@pytest.mark.parametrize(("value", "message"), READ_NAMES_FAILURES)
def test_read_names_rejects(value, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        read_names(value, "admins")


def test_read_names_returns_a_frozenset():
    result = read_names(["role/A", "user/b"], "admins")
    assert isinstance(result, frozenset)
    assert result == {"role/A", "user/b"}


def test_read_names_allows_an_empty_list():
    assert read_names([], "admins") == frozenset()


def test_reject_duplicates_ignores_key_order():
    edges = [
        {"from": "user/erin", "to": "user/frank", "kind": "grant", "rule": 3},
        {"kind": "grant", "rule": 3, "from": "user/erin", "to": "user/frank"},
    ]
    message = (
        'edges: duplicate edges [{"from": "user/erin", "kind": "grant", '
        '"rule": 3, "to": "user/frank"}]'
    )
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        reject_duplicates(edges, "edges", "edges")
