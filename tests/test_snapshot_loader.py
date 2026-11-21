"""Phase 2 step 1: snapshot loader helpers (D31)."""

import re

import pytest

from iampath.snapshot import _string_tuple

WHO = "user/erin"
FIELD = "group_names"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(["Developers", "Admins"], ("Developers", "Admins"), id="list"),
        pytest.param([], (), id="empty-list"),
    ],
)
def test_string_tuple_accepts_lists_of_strings(value, expected):
    result = _string_tuple(value, WHO, FIELD)
    assert result == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            "Developers",
            "user/erin: group_names must be a list of strings, got str",
            id="bare-string",
        ),
        pytest.param(
            ["Developers", 42],
            "user/erin: group_names[1] must be a string, got int",
            id="non-string-item",
        ),
        pytest.param(
            None,
            "user/erin: group_names must be a list of strings, got NoneType",
            id="null",
        ),
    ],
)
def test_string_tuple_rejects_other_shapes(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _string_tuple(value, WHO, FIELD)
