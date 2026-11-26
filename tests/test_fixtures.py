"""Fixture discovery and the fixture runner (Phase 2 step 2)."""

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from iampath.rules import RULE_KINDS
from iampath.snapshot import Snapshot, load_snapshot

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


EDGE_KINDS = frozenset(RULE_KINDS.values())


def read_kind(value: object, where: str) -> str:
    if not isinstance(value, str) or value not in EDGE_KINDS:
        allowed = " or ".join(json.dumps(kind) for kind in sorted(EDGE_KINDS))
        raise ValueError(f"{where}: must be {allowed}, got {json.dumps(value)}")
    return value


def read_edges(value: object, where: str) -> frozenset[ExpectedEdge]:
    if not isinstance(value, list):
        raise ValueError(f"{where}: must be an array, got {json_type_name(value)}")
    edges = []
    for position, item in enumerate(value):
        item_where = f"{where}[{position}]"
        edge = check_keys(item, EDGE_KEYS, item_where)
        edges.append(
            ExpectedEdge(
                source=read_name(edge["from"], f"{item_where}.from"),
                target=read_name(edge["to"], f"{item_where}.to"),
                kind=read_kind(edge["kind"], f"{item_where}.kind"),
                rule=read_rule_number(edge["rule"], f"{item_where}.rule"),
            )
        )
    reject_duplicates(value, where, "edges")
    return frozenset(edges)


def read_path(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{where}: must be an array, got {json_type_name(value)}")
    if len(value) < 2:
        raise ValueError(f"{where}: a path needs at least 2 steps, got {len(value)}")
    for position, step in enumerate(value):
        read_name(step, f"{where}[{position}]")
    return tuple(value)


def check_principal_object(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{where}: must be an object, got {json_type_name(value)}")
    for principal in value:
        read_name(principal, f"{where} key")
    return value


def read_shortest_paths(
    value: object, where: str
) -> dict[str, frozenset[tuple[str, ...]]]:
    result = {}
    for principal, paths in check_principal_object(value, where).items():
        entry_where = f"{where}[{json.dumps(principal)}]"
        if not isinstance(paths, list):
            raise ValueError(
                f"{entry_where}: must be an array, got {json_type_name(paths)}"
            )
        if not paths:
            raise ValueError(
                f"{entry_where}: must list at least one path "
                "(leave the principal out if it has none)"
            )
        result[principal] = frozenset(
            read_path(path, f"{entry_where}[{position}]")
            for position, path in enumerate(paths)
        )
        reject_duplicates(paths, entry_where, "paths")
    return result


def read_can_reach(value: object, where: str) -> dict[str, frozenset[str]]:
    result = {}
    for principal, names in check_principal_object(value, where).items():
        entry_where = f"{where}[{json.dumps(principal)}]"
        reached = read_names(names, entry_where)
        if not reached:
            raise ValueError(
                f"{entry_where}: must list at least one name "
                "(leave the principal out if it reaches nobody)"
            )
        result[principal] = reached
    return result


def describe_edge(edge: ExpectedEdge) -> str:
    return f"{edge.source} -> {edge.target} (rule {edge.rule})"


def describe_path(path: tuple[str, ...]) -> str:
    return " -> ".join(path)


def check_consistency(results: ExpectedResults, where: str) -> None:
    problems = []
    for edge in results.edges:
        shown = describe_edge(edge)
        rule_kind = RULE_KINDS[edge.rule]
        if edge.kind != rule_kind:
            problems.append(
                f'edge {shown} has kind "{edge.kind}" but rule {edge.rule} '
                f"is a {rule_kind} rule"
            )
        if edge.rule not in results.rules:
            problems.append(
                f"edge {shown} uses rule {edge.rule}, which is not in rules"
            )
    for principal, paths in results.shortest_paths.items():
        label = f"shortest_paths[{json.dumps(principal)}]"
        if principal in results.admins:
            problems.append(f"{label}: {principal} is an admin; admins have no routes")
        reachable = results.can_reach.get(principal, frozenset())
        for path in paths:
            shown = describe_path(path)
            if path[0] != principal:
                problems.append(f"{label}: route {shown} does not start at {principal}")
            if path[-1] not in results.admins:
                problems.append(f"{label}: route {shown} does not end at an admin")
            if len(set(path)) != len(path):
                problems.append(f"{label}: route {shown} visits an identity twice")
            missing = sorted(set(path[1:]) - reachable)
            if missing:
                problems.append(
                    f"{label}: route {shown} passes {', '.join(missing)}, "
                    "missing from can_reach"
                )
    if problems:
        raise ValueError(f"{where}: " + "; ".join(sorted(problems)))


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    reject_duplicates([key for key, _ in pairs], "JSON object", "keys")
    return dict(pairs)


def read_expected(path: Path) -> ExpectedResults:
    label = f"{path.parent.name}/{path.name}"
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"{label}: not valid JSON: {error}") from error
    except ValueError as error:
        raise ValueError(f"{label}: {error}") from error
    data = check_keys(data, TOP_LEVEL_KEYS, label)
    results = ExpectedResults(
        rules=read_rules(data["rules"], f"{label}: rules"),
        edges=read_edges(data["edges"], f"{label}: edges"),
        admins=read_names(data["admins"], f"{label}: admins"),
        shortest_paths=read_shortest_paths(
            data["shortest_paths"], f"{label}: shortest_paths"
        ),
        can_reach=read_can_reach(data["can_reach"], f"{label}: can_reach"),
    )
    check_consistency(results, label)
    return results


SECTIONS = ("structure", "snapshot", "edges", "admins", "shortest_paths", "can_reach")
NOT_BUILT_YET = {
    "edges": "rules not built yet (steps 4-7)",
    "admins": "admin marking not built yet (step 9)",
    "shortest_paths": "path search not built yet (step 10)",
    "can_reach": "path search not built yet (step 10)",
}


def read_snapshot_file(path: Path) -> Snapshot:
    label = f"{path.parent.name}/{path.name}"
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
        return load_snapshot(data)
    except json.JSONDecodeError as error:
        raise ValueError(f"{label}: not valid JSON: {error}") from error
    except ValueError as error:
        raise ValueError(f"{label}: {error}") from error


def fixture_rows(root: Path) -> list:
    rows = []
    for found in discover_fixtures(root):
        sections = ("structure",) if found.problems else SECTIONS
        rows.extend(
            pytest.param(found, section, id=f"{found.name}-{section}")
            for section in sections
        )
    return rows


def check_section(found: FoundFixture, section: str) -> None:
    if found.problems:
        raise ValueError(f"{found.name}: " + "; ".join(found.problems))
    expected_path = found.path / "expected.json"
    snapshot_path = found.path / "snapshot.json"
    if section == "structure":
        read_expected(expected_path)
        return
    try:
        read_expected(expected_path)
    except ValueError:
        pytest.skip("answer key invalid: see structure row")
    if section == "snapshot":
        read_snapshot_file(snapshot_path)
        return
    try:
        read_snapshot_file(snapshot_path)
    except ValueError:
        pytest.skip("snapshot invalid: see snapshot row")
    pytest.skip(NOT_BUILT_YET[section])


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


GOOD_EDGE = {"from": "user/erin", "to": "user/frank", "kind": "grant", "rule": 3}

READ_EDGES_FAILURES = [
    pytest.param("x", "edges: must be an array, got string", id="not-array"),
    pytest.param([5], "edges[0]: must be an object, got number", id="not-object"),
    pytest.param(
        [{"from": "a", "to": "b", "kind": "grant"}],
        "edges[0]: missing keys ['rule']",
        id="missing-key",
    ),
    pytest.param(
        [{**GOOD_EDGE, "from": ""}],
        'edges[0].from: must be a non-empty string, got ""',
        id="empty-from",
    ),
    pytest.param(
        [GOOD_EDGE, {**GOOD_EDGE, "to": 7}],
        "edges[1].to: must be a non-empty string, got 7",
        id="bad-to-second-edge",
    ),
    pytest.param(
        [{**GOOD_EDGE, "kind": "Grant"}],
        'edges[0].kind: must be "grant" or "reach", got "Grant"',
        id="kind-wrong-case",
    ),
    pytest.param(
        [{**GOOD_EDGE, "kind": []}],
        'edges[0].kind: must be "grant" or "reach", got []',
        id="kind-array",
    ),
    pytest.param(
        [{**GOOD_EDGE, "rule": True}],
        "edges[0].rule: must be a whole number, got true",
        id="rule-bool",
    ),
    pytest.param(
        [{**GOOD_EDGE, "rule": 99}],
        "edges[0].rule: unknown rule 99",
        id="rule-unknown",
    ),
    pytest.param(
        [GOOD_EDGE, dict(GOOD_EDGE)],
        'edges: duplicate edges [{"from": "user/erin", "kind": "grant", '
        '"rule": 3, "to": "user/frank"}]',
        id="duplicates",
    ),
]


@pytest.mark.parametrize(("value", "message"), READ_EDGES_FAILURES)
def test_read_edges_rejects(value, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        read_edges(value, "edges")


def test_read_edges_converts_each_edge():
    assert read_edges([GOOD_EDGE], "edges") == frozenset(
        {ExpectedEdge(source="user/erin", target="user/frank", kind="grant", rule=3)}
    )


def test_read_edges_allows_an_empty_list():
    assert read_edges([], "edges") == frozenset()


SHORTEST_PATHS_FAILURES = [
    pytest.param([], "shortest_paths: must be an object, got array", id="not-object"),
    pytest.param(
        {"": [["a", "b"]]},
        'shortest_paths key: must be a non-empty string, got ""',
        id="empty-key",
    ),
    pytest.param(
        {"user/erin": "x"},
        'shortest_paths["user/erin"]: must be an array, got string',
        id="entry-not-array",
    ),
    pytest.param(
        {"user/frank": []},
        'shortest_paths["user/frank"]: must list at least one path '
        "(leave the principal out if it has none)",
        id="empty-entry",
    ),
    pytest.param(
        {"user/erin": ["user/erin"]},
        'shortest_paths["user/erin"][0]: must be an array, got string',
        id="path-not-array",
    ),
    pytest.param(
        {"user/erin": [["user/erin"]]},
        'shortest_paths["user/erin"][0]: a path needs at least 2 steps, got 1',
        id="path-too-short",
    ),
    pytest.param(
        {"user/erin": [["user/erin", 5]]},
        'shortest_paths["user/erin"][0][1]: must be a non-empty string, got 5',
        id="bad-step",
    ),
    pytest.param(
        {"user/erin": [["user/erin", "role/A"], ["user/erin", "role/A"]]},
        'shortest_paths["user/erin"]: duplicate paths [["user/erin", "role/A"]]',
        id="duplicate-paths",
    ),
]


@pytest.mark.parametrize(("value", "message"), SHORTEST_PATHS_FAILURES)
def test_read_shortest_paths_rejects(value, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        read_shortest_paths(value, "shortest_paths")


def test_read_shortest_paths_converts_paths_to_tuples():
    value = {"user/erin": [["user/erin", "role/A"]]}
    result = read_shortest_paths(value, "shortest_paths")
    assert result == {"user/erin": frozenset({("user/erin", "role/A")})}
    assert isinstance(result["user/erin"], frozenset)


def test_read_shortest_paths_allows_an_empty_object():
    assert read_shortest_paths({}, "shortest_paths") == {}


CAN_REACH_FAILURES = [
    pytest.param("x", "can_reach: must be an object, got string", id="not-object"),
    pytest.param(
        {"user/erin": ["role/A", ""]},
        'can_reach["user/erin"][1]: must be a non-empty string, got ""',
        id="bad-name",
    ),
    pytest.param(
        {"user/frank": []},
        'can_reach["user/frank"]: must list at least one name '
        "(leave the principal out if it reaches nobody)",
        id="empty-entry",
    ),
    pytest.param(
        {"user/erin": ["role/A", "role/A"]},
        'can_reach["user/erin"]: duplicate names ["role/A"]',
        id="duplicates",
    ),
]


@pytest.mark.parametrize(("value", "message"), CAN_REACH_FAILURES)
def test_read_can_reach_rejects(value, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        read_can_reach(value, "can_reach")


def test_read_can_reach_converts():
    result = read_can_reach({"user/erin": ["role/B", "role/A"]}, "can_reach")
    assert result == {"user/erin": frozenset({"role/A", "role/B"})}
    assert isinstance(result["user/erin"], frozenset)


def test_read_can_reach_allows_an_empty_object():
    assert read_can_reach({}, "can_reach") == {}


BASE_RESULTS = ExpectedResults(
    rules=frozenset({14}),
    edges=frozenset(
        {
            ExpectedEdge("user/erin", "role/RoleA", "reach", 14),
            ExpectedEdge("role/RoleA", "role/AdminRole", "reach", 14),
        }
    ),
    admins=frozenset({"role/AdminRole"}),
    shortest_paths={
        "user/erin": frozenset({("user/erin", "role/RoleA", "role/AdminRole")}),
        "role/RoleA": frozenset({("role/RoleA", "role/AdminRole")}),
    },
    can_reach={
        "user/erin": frozenset({"role/RoleA", "role/AdminRole"}),
        "role/RoleA": frozenset({"role/AdminRole"}),
    },
)


def with_paths(principal: str, *paths: tuple[str, ...]) -> dict:
    return {**BASE_RESULTS.shortest_paths, principal: frozenset(paths)}


def with_reach(principal: str, *names: str) -> dict:
    return {**BASE_RESULTS.can_reach, principal: frozenset(names)}


def with_edge(edge: ExpectedEdge) -> frozenset:
    return BASE_RESULTS.edges | {edge}


CONSISTENCY_FAILURES = [
    pytest.param(
        replace(
            BASE_RESULTS,
            rules=frozenset({3, 14}),
            edges=with_edge(ExpectedEdge("user/erin", "user/frank", "reach", 3)),
        ),
        'x: edge user/erin -> user/frank (rule 3) has kind "reach" '
        "but rule 3 is a grant rule",
        id="kind-mismatch",
    ),
    pytest.param(
        replace(
            BASE_RESULTS,
            edges=with_edge(ExpectedEdge("user/erin", "user/frank", "reach", 10)),
        ),
        "x: edge user/erin -> user/frank (rule 10) uses rule 10, which is not in rules",
        id="rule-not-in-rules",
    ),
    pytest.param(
        replace(
            BASE_RESULTS,
            shortest_paths=with_paths("user/erin", ("role/RoleA", "role/AdminRole")),
        ),
        'x: shortest_paths["user/erin"]: route role/RoleA -> role/AdminRole '
        "does not start at user/erin",
        id="route-wrong-start",
    ),
    pytest.param(
        replace(
            BASE_RESULTS,
            shortest_paths=with_paths("user/erin", ("user/erin", "role/RoleA")),
        ),
        'x: shortest_paths["user/erin"]: route user/erin -> role/RoleA '
        "does not end at an admin",
        id="route-wrong-end",
    ),
    pytest.param(
        replace(
            BASE_RESULTS,
            admins=frozenset({"role/AdminRole", "role/OtherAdmin"}),
            shortest_paths=with_paths(
                "role/AdminRole", ("role/AdminRole", "role/OtherAdmin")
            ),
            can_reach=with_reach("role/AdminRole", "role/OtherAdmin"),
        ),
        'x: shortest_paths["role/AdminRole"]: role/AdminRole is an admin; '
        "admins have no routes",
        id="admin-has-routes",
    ),
    pytest.param(
        replace(
            BASE_RESULTS,
            shortest_paths=with_paths(
                "user/erin", ("user/erin", "role/RoleA", "user/erin", "role/AdminRole")
            ),
            can_reach=with_reach(
                "user/erin", "user/erin", "role/RoleA", "role/AdminRole"
            ),
        ),
        'x: shortest_paths["user/erin"]: route user/erin -> role/RoleA -> '
        "user/erin -> role/AdminRole visits an identity twice",
        id="route-repeats",
    ),
    pytest.param(
        replace(BASE_RESULTS, can_reach=with_reach("user/erin", "role/AdminRole")),
        'x: shortest_paths["user/erin"]: route user/erin -> role/RoleA -> '
        "role/AdminRole passes role/RoleA, missing from can_reach",
        id="missing-from-can-reach",
    ),
]


@pytest.mark.parametrize(("results", "message"), CONSISTENCY_FAILURES)
def test_check_consistency_rejects(results, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        check_consistency(results, "x")


def test_check_consistency_accepts_a_consistent_answer_key():
    check_consistency(BASE_RESULTS, "x")


def test_check_consistency_reports_every_problem_sorted():
    results = replace(
        BASE_RESULTS,
        edges=with_edge(ExpectedEdge("user/erin", "user/frank", "reach", 10)),
        shortest_paths=with_paths("user/erin", ("user/erin", "role/RoleA")),
    )
    message = (
        "x: edge user/erin -> user/frank (rule 10) uses rule 10, "
        "which is not in rules; "
        'shortest_paths["user/erin"]: route user/erin -> role/RoleA '
        "does not end at an admin"
    )
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        check_consistency(results, "x")


VALID_EXPECTED = {
    "rules": [14],
    "edges": [
        {"from": "user/erin", "to": "role/RoleA", "kind": "reach", "rule": 14},
        {"from": "role/RoleA", "to": "role/AdminRole", "kind": "reach", "rule": 14},
    ],
    "admins": ["role/AdminRole"],
    "shortest_paths": {
        "user/erin": [["user/erin", "role/RoleA", "role/AdminRole"]],
        "role/RoleA": [["role/RoleA", "role/AdminRole"]],
    },
    "can_reach": {
        "user/erin": ["role/RoleA", "role/AdminRole"],
        "role/RoleA": ["role/AdminRole"],
    },
}
VALID_TEXT = json.dumps(VALID_EXPECTED)


def write_expected(root: Path, text: str) -> Path:
    folder = root / "case"
    folder.mkdir()
    path = folder / "expected.json"
    path.write_text(text, encoding="utf-8")
    return path


def test_read_expected_matches_the_hand_built_results(tmp_path):
    assert read_expected(write_expected(tmp_path, VALID_TEXT)) == BASE_RESULTS


def test_read_expected_reports_broken_json(tmp_path):
    prefix = re.escape("case/expected.json: not valid JSON: ")
    with pytest.raises(ValueError, match="^" + prefix):
        read_expected(write_expected(tmp_path, "{"))


READ_EXPECTED_FAILURES = [
    pytest.param(
        '{"rules": [3], ' + VALID_TEXT[1:],
        'case/expected.json: JSON object: duplicate keys ["rules"]',
        id="duplicate-top-key",
    ),
    pytest.param(
        VALID_TEXT.replace('"can_reach": {', '"can_reach": {"user/erin": ["role/A"], '),
        'case/expected.json: JSON object: duplicate keys ["user/erin"]',
        id="duplicate-nested-key",
    ),
    pytest.param(
        "{}",
        "case/expected.json: missing keys "
        "['admins', 'can_reach', 'edges', 'rules', 'shortest_paths']",
        id="missing-keys",
    ),
    pytest.param(
        json.dumps({**VALID_EXPECTED, "rules": []}),
        "case/expected.json: rules: must list at least one rule",
        id="reader-error",
    ),
    pytest.param(
        json.dumps(
            {
                **VALID_EXPECTED,
                "shortest_paths": {"user/erin": [["user/erin", "role/RoleA"]]},
            }
        ),
        'case/expected.json: shortest_paths["user/erin"]: '
        "route user/erin -> role/RoleA does not end at an admin",
        id="consistency-error",
    ),
]


@pytest.mark.parametrize(("text", "message"), READ_EXPECTED_FAILURES)
def test_read_expected_rejects(tmp_path, text, message):
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        read_expected(write_expected(tmp_path, text))


MINIMAL_SNAPSHOT = json.dumps({"account_id": "111122223333"})
BROKEN_SNAPSHOT = json.dumps({"account_id": "abc"})
BROKEN_EXPECTED = json.dumps({**VALID_EXPECTED, "rules": []})


def make_case(root: Path, expected_text: str, snapshot_text: str) -> FoundFixture:
    folder = root / "case"
    folder.mkdir()
    (folder / "expected.json").write_text(expected_text, encoding="utf-8")
    (folder / "snapshot.json").write_text(snapshot_text, encoding="utf-8")
    return discover_fixtures(root)[0]


def test_fixture_rows_give_broken_items_only_a_structure_row(tmp_path):
    make_fixture_folder(tmp_path, "a_case", REQUIRED_FILES)
    make_fixture_folder(tmp_path, "b_case", ("snapshot.json",))
    assert [row.id for row in fixture_rows(tmp_path)] == [
        "a_case-structure",
        "a_case-snapshot",
        "a_case-edges",
        "a_case-admins",
        "a_case-shortest_paths",
        "a_case-can_reach",
        "b_case-structure",
    ]


def test_check_section_fails_a_broken_folder(tmp_path):
    make_fixture_folder(tmp_path, "case", ("snapshot.json",))
    found = discover_fixtures(tmp_path)[0]
    with pytest.raises(ValueError, match=r"^case: missing expected\.json$"):
        check_section(found, "structure")


def test_check_section_structure_passes_a_valid_fixture(tmp_path):
    check_section(make_case(tmp_path, VALID_TEXT, MINIMAL_SNAPSHOT), "structure")


def test_check_section_structure_fails_a_bad_answer_key(tmp_path):
    found = make_case(tmp_path, BROKEN_EXPECTED, MINIMAL_SNAPSHOT)
    message = "case/expected.json: rules: must list at least one rule"
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        check_section(found, "structure")


def test_check_section_skips_later_rows_after_a_bad_answer_key(tmp_path):
    found = make_case(tmp_path, BROKEN_EXPECTED, MINIMAL_SNAPSHOT)
    with pytest.raises(pytest.skip.Exception, match="answer key invalid"):
        check_section(found, "snapshot")


def test_check_section_snapshot_passes_a_valid_snapshot(tmp_path):
    check_section(make_case(tmp_path, VALID_TEXT, MINIMAL_SNAPSHOT), "snapshot")


def test_check_section_snapshot_fails_a_bad_snapshot(tmp_path):
    found = make_case(tmp_path, VALID_TEXT, BROKEN_SNAPSHOT)
    with pytest.raises(ValueError, match="^" + re.escape("case/snapshot.json: ")):
        check_section(found, "snapshot")


def test_check_section_skips_later_rows_after_a_bad_snapshot(tmp_path):
    found = make_case(tmp_path, VALID_TEXT, BROKEN_SNAPSHOT)
    with pytest.raises(pytest.skip.Exception, match="snapshot invalid"):
        check_section(found, "edges")


@pytest.mark.parametrize("section", sorted(NOT_BUILT_YET))
def test_check_section_skips_sections_not_built_yet(tmp_path, section):
    found = make_case(tmp_path, VALID_TEXT, MINIMAL_SNAPSHOT)
    with pytest.raises(pytest.skip.Exception, match=re.escape(NOT_BUILT_YET[section])):
        check_section(found, section)


@pytest.mark.parametrize(("found", "section"), fixture_rows(FIXTURES_DIR))
def test_fixture(found, section):
    check_section(found, section)
