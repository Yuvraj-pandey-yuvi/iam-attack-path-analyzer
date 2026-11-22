"""Phase 2 step 1: snapshot loader helpers (D31)."""

import dataclasses
import re

import pytest

from iampath.snapshot import (
    Ec2Instance,
    Group,
    InlinePolicy,
    InstanceProfile,
    LambdaFunction,
    ManagedPolicy,
    PolicyVersion,
    Role,
    User,
    _check_object,
    _load_account_id,
    _load_ec2_instance,
    _load_group,
    _load_inline_policies,
    _load_instance_profile,
    _load_lambda_function,
    _load_list,
    _load_managed_policy,
    _load_policy_versions,
    _load_role,
    _load_user,
    _optional_bool,
    _optional_key_count,
    _optional_string,
    _reject_duplicates,
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


PROFILE_ARN = "arn:aws:iam::111122223333:instance-profile/WebProfile"
FUNCTION_ARN = "arn:aws:lambda:us-east-1:111122223333:function:Deployer"
INSTANCE_ARN = "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc123"


@pytest.mark.parametrize("value", [None, "x"])
def test_optional_string_accepts_missing_or_text(value):
    assert _optional_string(value, WHO, "field") == value


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            "",
            "user/erin: field must be non-empty text, got ''",
            id="empty",
        ),
        pytest.param(
            5,
            "user/erin: field must be non-empty text, got 5",
            id="number",
        ),
    ],
)
def test_optional_string_rejects(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _optional_string(value, WHO, "field")


def test_load_instance_profile_without_role():
    data = {"name": "WebProfile", "arn": PROFILE_ARN}
    loaded = _load_instance_profile(data, "instance_profiles[0]")
    assert loaded == InstanceProfile(name="WebProfile", arn=PROFILE_ARN)


def test_load_instance_profile_with_one_role():
    data = {"name": "WebProfile", "arn": PROFILE_ARN, "role_names": ["WebRole"]}
    loaded = _load_instance_profile(data, "instance_profiles[0]")
    assert loaded == InstanceProfile(
        name="WebProfile", arn=PROFILE_ARN, role_names=("WebRole",)
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {"name": "WebProfile", "arn": PROFILE_ARN, "role_names": ["A", "B"]},
            "instance-profile/WebProfile: role_names can hold at most 1 role, got 2",
            id="two-roles",
        ),
        pytest.param(
            {"name": "WebProfile"},
            "instance_profiles[0]: missing required field(s): arn",
            id="no-arn",
        ),
        pytest.param(
            {"name": "WebProfile", "arn": PROFILE_ARN, "role_names": "WebRole"},
            "instance-profile/WebProfile: "
            "role_names must be a list of strings, got str",
            id="roles-not-list",
        ),
    ],
)
def test_load_instance_profile_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_instance_profile(data, "instance_profiles[0]")


def test_load_lambda_function():
    data = {"name": "Deployer", "arn": FUNCTION_ARN, "role_arn": DEPLOY_ARN}
    assert _load_lambda_function(data, "lambda_functions[0]") == LambdaFunction(
        name="Deployer", arn=FUNCTION_ARN, role_arn=DEPLOY_ARN
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {"name": "Deployer", "arn": FUNCTION_ARN},
            "lambda_functions[0]: missing required field(s): role_arn",
            id="no-role",
        ),
        pytest.param(
            {"name": "Deployer", "arn": FUNCTION_ARN, "role_arn": ""},
            "function/Deployer: role_arn must be non-empty text, got ''",
            id="empty-role",
        ),
        pytest.param(
            {
                "name": "Deployer",
                "arn": FUNCTION_ARN,
                "role_arn": DEPLOY_ARN,
                "runtime": "python3.14",
            },
            "lambda_functions[0]: unknown field(s): runtime",
            id="unknown-field",
        ),
    ],
)
def test_load_lambda_function_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_lambda_function(data, "lambda_functions[0]")


def test_load_ec2_instance_minimal_means_no_profile_and_unknown_ssm():
    data = {"instance_id": "i-0abc123", "arn": INSTANCE_ARN}
    loaded = _load_ec2_instance(data, "ec2_instances[0]")
    assert loaded.instance_profile_arn is None
    assert loaded.ssm_managed is None


def test_load_ec2_instance_reads_every_field():
    data = {
        "instance_id": "i-0abc123",
        "arn": INSTANCE_ARN,
        "instance_profile_arn": PROFILE_ARN,
        "ssm_managed": True,
    }
    assert _load_ec2_instance(data, "ec2_instances[0]") == Ec2Instance(
        instance_id="i-0abc123",
        arn=INSTANCE_ARN,
        instance_profile_arn=PROFILE_ARN,
        ssm_managed=True,
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {"arn": INSTANCE_ARN},
            "ec2_instances[0]: missing required field(s): instance_id",
            id="no-instance-id",
        ),
        pytest.param(
            {"instance_id": "i-0abc123", "arn": INSTANCE_ARN, "ssm_managed": "yes"},
            "instance/i-0abc123: ssm_managed must be true, false or missing, got str",
            id="ssm-text",
        ),
        pytest.param(
            {
                "instance_id": "i-0abc123",
                "arn": INSTANCE_ARN,
                "instance_profile_arn": 42,
            },
            "instance/i-0abc123: instance_profile_arn must be non-empty text, got 42",
            id="profile-not-text",
        ),
    ],
)
def test_load_ec2_instance_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_ec2_instance(data, "ec2_instances[0]")


FRANK_ARN = "arn:aws:iam::111122223333:user/frank"
DEVANAGARI_TWELVE = "\u0967" * 12  # U+0967 = Devanagari digit one (not ASCII)


def test_load_list_missing_key_is_empty():
    assert _load_list({}, "users", _load_user) == ()


def test_load_list_passes_each_item_its_position():
    data = {"users": ["a", "b"]}
    loaded = _load_list(data, "users", lambda item, position: (position, item))
    assert loaded == (("users[0]", "a"), ("users[1]", "b"))


def test_load_list_rejects_non_list():
    message = "snapshot: users must be a list, got dict"
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_list({"users": {}}, "users", _load_user)


def test_load_list_errors_name_the_position():
    data = {"users": [{"name": "erin", "arn": ERIN_ARN}, {"name": "frank"}]}
    message = "users[1]: missing required field(s): arn"
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_list(data, "users", _load_user)


def test_reject_duplicates_accepts_unique_names():
    users = (User(name="erin", arn=ERIN_ARN), User(name="frank", arn=FRANK_ARN))
    assert _reject_duplicates(users, "users", "name") is None


def test_reject_duplicates_names_the_duplicate():
    users = (User(name="erin", arn=ERIN_ARN), User(name="erin", arn=ERIN_ARN))
    message = "snapshot: users has duplicate name 'erin'"
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _reject_duplicates(users, "users", "name")


def test_account_id_accepts_twelve_digits():
    assert _load_account_id("111122223333") == "111122223333"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            "12345",
            "snapshot: account_id must be exactly 12 digits, got '12345'",
            id="too-short",
        ),
        pytest.param(
            "1111222233334",
            "snapshot: account_id must be exactly 12 digits, got '1111222233334'",
            id="too-long",
        ),
        pytest.param(
            "11112222333a",
            "snapshot: account_id must be exactly 12 digits, got '11112222333a'",
            id="letter",
        ),
        pytest.param(
            DEVANAGARI_TWELVE,
            "snapshot: account_id must be exactly 12 digits, "
            f"got '{DEVANAGARI_TWELVE}'",
            id="devanagari-digits",
        ),
        pytest.param(
            111122223333,
            "snapshot: account_id must be non-empty text, got 111122223333",
            id="number-not-text",
        ),
    ],
)
def test_account_id_rejects(value, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        _load_account_id(value)
