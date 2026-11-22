"""Phase 2 step 1: load_snapshot, the whole file (D28, D31, D32)."""

import re

import pytest

from iampath.snapshot import (
    Ec2Instance,
    Group,
    InstanceProfile,
    LambdaFunction,
    ManagedPolicy,
    PolicyVersion,
    Role,
    Snapshot,
    User,
    load_snapshot,
)

ACCOUNT = "111122223333"
ERIN_ARN = f"arn:aws:iam::{ACCOUNT}:user/erin"
DEVS_ARN = f"arn:aws:iam::{ACCOUNT}:group/Developers"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/DeployRole"
DEV_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/DevAccess"
LOGS_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/ReadLogs"
PROFILE_ARN = f"arn:aws:iam::{ACCOUNT}:instance-profile/WebProfile"
FUNCTION_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:Deployer"
INSTANCE_ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc123"
DOC = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
OLD_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
TRUST = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ERIN_ARN},
            "Action": "sts:AssumeRole",
        }
    ]
}
ERIN = {"name": "erin", "arn": ERIN_ARN}
DEV_POLICY = {"arn": DEV_POLICY_ARN, "default_document": DOC}
FULL = {
    "account_id": ACCOUNT,
    "users": [{"name": "erin", "arn": ERIN_ARN, "group_names": ["Developers"]}],
    "groups": [{"name": "Developers", "arn": DEVS_ARN}],
    "roles": [{"name": "DeployRole", "arn": ROLE_ARN, "trust_document": TRUST}],
    "managed_policies": [
        {
            "arn": DEV_POLICY_ARN,
            "default_document": DOC,
            "inactive_versions": [{"version_id": "v1", "document": OLD_DOC}],
        },
        {"arn": LOGS_POLICY_ARN, "default_document": DOC},
    ],
    "instance_profiles": [
        {"name": "WebProfile", "arn": PROFILE_ARN, "role_names": ["DeployRole"]}
    ],
    "lambda_functions": [
        {"name": "Deployer", "arn": FUNCTION_ARN, "role_arn": ROLE_ARN}
    ],
    "ec2_instances": [
        {
            "instance_id": "i-0abc123",
            "arn": INSTANCE_ARN,
            "instance_profile_arn": PROFILE_ARN,
            "ssm_managed": True,
        }
    ],
}


def test_minimal_snapshot_is_empty():
    assert load_snapshot({"account_id": ACCOUNT}) == Snapshot(account_id=ACCOUNT)


def test_full_snapshot_loads_every_list():
    assert load_snapshot(FULL) == Snapshot(
        account_id=ACCOUNT,
        users=(User(name="erin", arn=ERIN_ARN, group_names=("Developers",)),),
        groups=(Group(name="Developers", arn=DEVS_ARN),),
        roles=(Role(name="DeployRole", arn=ROLE_ARN, trust_document=TRUST),),
        managed_policies=(
            ManagedPolicy(arn=DEV_POLICY_ARN, default_document=DOC),
            ManagedPolicy(arn=LOGS_POLICY_ARN, default_document=DOC),
        ),
        inactive_versions_by_arn={
            DEV_POLICY_ARN: (PolicyVersion(version_id="v1", document=OLD_DOC),),
        },
        instance_profiles=(
            InstanceProfile(
                name="WebProfile", arn=PROFILE_ARN, role_names=("DeployRole",)
            ),
        ),
        lambda_functions=(
            LambdaFunction(name="Deployer", arn=FUNCTION_ARN, role_arn=ROLE_ARN),
        ),
        ec2_instances=(
            Ec2Instance(
                instance_id="i-0abc123",
                arn=INSTANCE_ARN,
                instance_profile_arn=PROFILE_ARN,
                ssm_managed=True,
            ),
        ),
    )


def test_only_policies_with_old_versions_get_an_entry():
    snapshot = load_snapshot(FULL)
    assert set(snapshot.inactive_versions_by_arn) == {DEV_POLICY_ARN}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            ["x"],
            "snapshot: must be a JSON object, got list",
            id="not-object",
        ),
        pytest.param(
            {},
            "snapshot: missing required field(s): account_id",
            id="no-account-id",
        ),
        pytest.param(
            {"account_id": ACCOUNT, "user": []},
            "snapshot: unknown field(s): user",
            id="unknown-top-level",
        ),
        pytest.param(
            {"account_id": ACCOUNT, "users": [ERIN, ERIN]},
            "snapshot: users has duplicate name 'erin'",
            id="duplicate-user",
        ),
        pytest.param(
            {"account_id": ACCOUNT, "managed_policies": [DEV_POLICY, DEV_POLICY]},
            f"snapshot: managed_policies has duplicate arn '{DEV_POLICY_ARN}'",
            id="duplicate-policy",
        ),
        pytest.param(
            {"account_id": ACCOUNT, "roles": [{"name": "DeployRole", "arn": ROLE_ARN}]},
            "roles[0]: missing required field(s): trust_document",
            id="bad-role",
        ),
    ],
)
def test_load_snapshot_rejects(data, message):
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        load_snapshot(data)
