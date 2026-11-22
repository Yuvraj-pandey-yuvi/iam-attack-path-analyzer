"""Phase 2 step 1: snapshot loader helpers (D31)."""

import dataclasses
import re

import pytest

from iampath.snapshot import (
    Group,
    InlinePolicy,
    ManagedPolicy,
    PolicyVersion,
    Role,
    User,
    _check_object,
    _load_group,
    _load_inline_policies,
    _load_managed_policy,
    _load_policy_versions,
    _load_role,
    _load_user,
    _optional_bool,
    _optional_key_count,
    _require_document,
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


DEV_ARN = "arn:aws:iam::111122223333:policy/DevAccess"


def test_load_user_minimal_uses_defaults():
    loaded = _load_user({"name": "erin", "arn": ERIN_ARN}, POSITION)
    assert loaded == User(name="erin", arn=ERIN_ARN)


def test_load_user_reads_every_field():
    data = {
        "name": "erin",
        "arn": ERIN_ARN,
        "inline_policies": [{"name": "Ec2", "document": EC2_DOC}],
        "managed_arns": [DEV_ARN],
        "group_names": ["Developers"],
        "access_key_count": 1,
        "has_console_password": True,
    }
    assert _load_user(data, POSITION) == User(
        name="erin",
        arn=ERIN_ARN,
        inline_policies=(InlinePolicy(name="Ec2", document=EC2_DOC),),
        managed_arns=(DEV_ARN,),
        group_names=("Developers",),
        access_key_count=1,
        has_console_password=True,
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            ["erin"],
            "users[0]: must be a JSON object, got list",
            id="not-object",
        ),
        pytest.param(
            {"arn": ERIN_ARN},
            "users[0]: missing required field(s): name",
            id="no-name",
        ),
        pytest.param(
            {"name": 42, "arn": ERIN_ARN},
            "users[0]: name must be non-empty text, got 42",
            id="name-not-text",
        ),
        pytest.param(
            {"name": "erin", "arn": ""},
            "user/erin: arn must be non-empty text, got ''",
            id="empty-arn",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "acess_key_count": 1},
            "users[0]: unknown field(s): acess_key_count",
            id="typo",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "inline_policies": [{"name": "Ec2"}]},
            "user/erin inline_policies[0]: missing required field(s): document",
            id="bad-inline-policy",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "managed_arns": DEV_ARN},
            "user/erin: managed_arns must be a list of strings, got str",
            id="managed-not-list",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "group_names": "Developers"},
            "user/erin: group_names must be a list of strings, got str",
            id="groups-not-list",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "access_key_count": True},
            "user/erin: access_key_count must be a whole number or missing, got bool",
            id="key-count-bool",
        ),
        pytest.param(
            {"name": "erin", "arn": ERIN_ARN, "has_console_password": "yes"},
            "user/erin: has_console_password must be true, false or missing, got str",
            id="password-text",
        ),
    ],
)
def test_load_user_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_user(data, POSITION)


DEVELOPERS_ARN = "arn:aws:iam::111122223333:group/Developers"
DEPLOY_ARN = "arn:aws:iam::111122223333:role/DeployRole"
TRUST_DOC = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ERIN_ARN},
            "Action": "sts:AssumeRole",
        }
    ]
}


def test_require_document_returns_the_same_dict():
    result = _require_document(TRUST_DOC, "role/DeployRole", "trust_document")
    assert result is TRUST_DOC


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            ["Statement"],
            "role/DeployRole: trust_document must be a JSON object, got list",
            id="list",
        ),
        pytest.param(
            None,
            "role/DeployRole: trust_document must be a JSON object, got NoneType",
            id="null",
        ),
    ],
)
def test_require_document_rejects(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _require_document(value, "role/DeployRole", "trust_document")


def test_load_group_minimal_uses_defaults():
    loaded = _load_group({"name": "Developers", "arn": DEVELOPERS_ARN}, "groups[0]")
    assert loaded == Group(name="Developers", arn=DEVELOPERS_ARN)


def test_load_group_reads_every_field():
    data = {
        "name": "Developers",
        "arn": DEVELOPERS_ARN,
        "inline_policies": [{"name": "Ec2", "document": EC2_DOC}],
        "managed_arns": [DEV_ARN],
    }
    assert _load_group(data, "groups[0]") == Group(
        name="Developers",
        arn=DEVELOPERS_ARN,
        inline_policies=(InlinePolicy(name="Ec2", document=EC2_DOC),),
        managed_arns=(DEV_ARN,),
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {"name": "Developers"},
            "groups[0]: missing required field(s): arn",
            id="no-arn",
        ),
        pytest.param(
            {"name": "Developers", "arn": DEVELOPERS_ARN, "group_names": ["Admins"]},
            "groups[0]: unknown field(s): group_names",
            id="groups-cannot-contain-groups",
        ),
        pytest.param(
            {"name": "Developers", "arn": DEVELOPERS_ARN, "managed_arns": DEV_ARN},
            "group/Developers: managed_arns must be a list of strings, got str",
            id="label-says-group",
        ),
    ],
)
def test_load_group_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_group(data, "groups[0]")


def test_load_role_minimal_keeps_trust_document_raw():
    data = {"name": "DeployRole", "arn": DEPLOY_ARN, "trust_document": TRUST_DOC}
    assert _load_role(data, "roles[0]") == Role(
        name="DeployRole", arn=DEPLOY_ARN, trust_document=TRUST_DOC
    )


def test_load_role_reads_every_field():
    data = {
        "name": "DeployRole",
        "arn": DEPLOY_ARN,
        "trust_document": TRUST_DOC,
        "inline_policies": [{"name": "Ec2", "document": EC2_DOC}],
        "managed_arns": [DEV_ARN],
    }
    assert _load_role(data, "roles[0]") == Role(
        name="DeployRole",
        arn=DEPLOY_ARN,
        trust_document=TRUST_DOC,
        inline_policies=(InlinePolicy(name="Ec2", document=EC2_DOC),),
        managed_arns=(DEV_ARN,),
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {"name": "DeployRole", "arn": DEPLOY_ARN},
            "roles[0]: missing required field(s): trust_document",
            id="no-trust-document",
        ),
        pytest.param(
            {"name": "DeployRole", "arn": DEPLOY_ARN, "trust_document": ["x"]},
            "role/DeployRole: trust_document must be a JSON object, got list",
            id="trust-not-object",
        ),
        pytest.param(
            {
                "name": "DeployRole",
                "arn": DEPLOY_ARN,
                "trust_document": TRUST_DOC,
                "group_names": ["Developers"],
            },
            "roles[0]: unknown field(s): group_names",
            id="roles-have-no-groups",
        ),
    ],
)
def test_load_role_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_role(data, "roles[0]")


V1_DOC = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
POLICY_WHO = f"policy {DEV_ARN}"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param([], (), id="none"),
        pytest.param(
            [{"version_id": "v1", "document": V1_DOC}],
            (PolicyVersion(version_id="v1", document=V1_DOC),),
            id="one",
        ),
    ],
)
def test_policy_versions_load(value, expected):
    assert _load_policy_versions(value, POLICY_WHO) == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            {"version_id": "v1"},
            f"{POLICY_WHO}: inactive_versions must be a list, got dict",
            id="not-a-list",
        ),
        pytest.param(
            [{"version_id": "v1"}],
            f"{POLICY_WHO} inactive_versions[0]: missing required field(s): document",
            id="no-document",
        ),
        pytest.param(
            [{"version_id": "", "document": V1_DOC}],
            f"{POLICY_WHO} inactive_versions[0]: "
            "version_id must be non-empty text, got ''",
            id="empty-version-id",
        ),
        pytest.param(
            [{"version_id": "v1", "document": ["Statement"]}],
            f"{POLICY_WHO} version v1: document must be a JSON object, got list",
            id="document-not-object",
        ),
    ],
)
def test_policy_versions_reject(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_policy_versions(value, POLICY_WHO)


def test_load_managed_policy_minimal():
    data = {"arn": DEV_ARN, "default_document": EC2_DOC}
    loaded = _load_managed_policy(data, "managed_policies[0]")
    assert loaded.policy == ManagedPolicy(arn=DEV_ARN, default_document=EC2_DOC)
    assert loaded.inactive_versions == ()


def test_load_managed_policy_keeps_old_versions_apart():
    data = {
        "arn": DEV_ARN,
        "default_document": EC2_DOC,
        "inactive_versions": [{"version_id": "v1", "document": V1_DOC}],
    }
    loaded = _load_managed_policy(data, "managed_policies[0]")
    assert loaded.policy == ManagedPolicy(arn=DEV_ARN, default_document=EC2_DOC)
    assert loaded.inactive_versions == (
        PolicyVersion(version_id="v1", document=V1_DOC),
    )
    policy_fields = {field.name for field in dataclasses.fields(ManagedPolicy)}
    assert policy_fields == {"arn", "default_document"}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {"arn": DEV_ARN},
            "managed_policies[0]: missing required field(s): default_document",
            id="no-default-document",
        ),
        pytest.param(
            {"arn": 7, "default_document": EC2_DOC},
            "managed_policies[0]: arn must be non-empty text, got 7",
            id="arn-not-text",
        ),
        pytest.param(
            {"arn": DEV_ARN, "default_document": EC2_DOC, "inactive_version": []},
            "managed_policies[0]: unknown field(s): inactive_version",
            id="typo",
        ),
        pytest.param(
            {"arn": DEV_ARN, "default_document": ["Statement"]},
            f"{POLICY_WHO}: default_document must be a JSON object, got list",
            id="default-not-object",
        ),
    ],
)
def test_load_managed_policy_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_managed_policy(data, "managed_policies[0]")
