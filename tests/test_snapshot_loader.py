"""Phase 2 step 1: snapshot loader helpers (D31)."""

import re

import pytest

from iampath.snapshot import (
    InlinePolicy,
    _check_object,
    _load_inline_policies,
    _optional_bool,
    _optional_key_count,
    _require_string,
    _string_tuple,
)

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


KEYS = "access_key_count"
PASSWORD = "has_console_password"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(None, None, id="missing-is-unknown"),
        pytest.param(0, 0, id="zero"),
        pytest.param(2, 2, id="max"),
    ],
)
def test_key_count_accepts_whole_numbers_in_range(value, expected):
    assert _optional_key_count(value, WHO, KEYS) == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            True,
            "user/erin: access_key_count must be a whole number or missing, got bool",
            id="bool",
        ),
        pytest.param(
            "1",
            "user/erin: access_key_count must be a whole number or missing, got str",
            id="text",
        ),
        pytest.param(
            1.0,
            "user/erin: access_key_count must be a whole number or missing, got float",
            id="decimal",
        ),
        pytest.param(
            -1,
            "user/erin: access_key_count must be between 0 and 2, got -1",
            id="negative",
        ),
        pytest.param(
            7,
            "user/erin: access_key_count must be between 0 and 2, got 7",
            id="above-max",
        ),
    ],
)
def test_key_count_rejects_everything_else(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _optional_key_count(value, WHO, KEYS)


@pytest.mark.parametrize("value", [None, True, False])
def test_bool_accepts_true_false_and_missing(value):
    assert _optional_bool(value, WHO, PASSWORD) is value


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            1,
            "user/erin: has_console_password must be true, false or missing, got int",
            id="number",
        ),
        pytest.param(
            "true",
            "user/erin: has_console_password must be true, false or missing, got str",
            id="text",
        ),
    ],
)
def test_bool_rejects_everything_else(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _optional_bool(value, WHO, PASSWORD)


ERIN_ARN = "arn:aws:iam::111122223333:user/erin"
REQUIRED = frozenset({"name", "arn"})
OPTIONAL = frozenset({"group_names", "access_key_count"})
POSITION = "users[0]"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param({"name": "erin", "arn": ERIN_ARN}, id="required-only"),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "group_names": []},
            id="with-optional",
        ),
    ],
)
def test_check_object_accepts_known_keys(data):
    assert _check_object(data, POSITION, REQUIRED, OPTIONAL) is None


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            ["erin"],
            "users[0]: must be a JSON object, got list",
            id="list",
        ),
        pytest.param(
            {"name": "erin"},
            "users[0]: missing required field(s): arn",
            id="no-arn",
        ),
        pytest.param(
            {},
            "users[0]: missing required field(s): arn, name",
            id="empty-sorted",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "acess_key_count": 1},
            "users[0]: unknown field(s): acess_key_count",
            id="typo",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "zeta": 1, "alpha": 2},
            "users[0]: unknown field(s): alpha, zeta",
            id="two-unknown-sorted",
        ),
    ],
)
def test_check_object_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _check_object(data, POSITION, REQUIRED, OPTIONAL)


EC2_DOC = {"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}


def test_require_string_accepts_text():
    assert _require_string("erin", POSITION, "name") == "erin"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            42,
            "users[0]: name must be non-empty text, got 42",
            id="number",
        ),
        pytest.param(
            "",
            "users[0]: name must be non-empty text, got ''",
            id="empty",
        ),
        pytest.param(
            None,
            "users[0]: name must be non-empty text, got None",
            id="null",
        ),
    ],
)
def test_require_string_rejects(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _require_string(value, POSITION, "name")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param([], (), id="none"),
        pytest.param(
            [{"name": "Ec2", "document": EC2_DOC}],
            (InlinePolicy(name="Ec2", document=EC2_DOC),),
            id="one",
        ),
        pytest.param(
            [{"name": "Odd", "document": {"Statement": "not checked here"}}],
            (InlinePolicy(name="Odd", document={"Statement": "not checked here"}),),
            id="contents-stay-raw",
        ),
    ],
)
def test_inline_policies_load(value, expected):
    assert _load_inline_policies(value, WHO) == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            "Ec2",
            "user/erin: inline_policies must be a list, got str",
            id="not-a-list",
        ),
        pytest.param(
            ["Ec2"],
            "user/erin inline_policies[0]: must be a JSON object, got str",
            id="item-not-object",
        ),
        pytest.param(
            [{"name": "Ec2"}],
            "user/erin inline_policies[0]: missing required field(s): document",
            id="no-document",
        ),
        pytest.param(
            [{"name": "", "document": EC2_DOC}],
            "user/erin inline_policies[0]: name must be non-empty text, got ''",
            id="empty-name",
        ),
        pytest.param(
            [{"name": "Ec2", "document": ["Statement"]}],
            "user/erin inline policy Ec2: document must be a JSON object, got list",
            id="document-not-object",
        ),
    ],
)
def test_inline_policies_reject(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_inline_policies(value, WHO)
