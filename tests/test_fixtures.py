"""Fixture discovery and the fixture runner (Phase 2 step 2)."""

from dataclasses import dataclass
from pathlib import Path

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
