"""Phase 2 step 1: snapshot_to_dict and the full JSON round trip (D32, D33)."""

import json
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
    Snapshot,
    User,
    load_snapshot,
    snapshot_to_dict,
)

ACCOUNT = "111122223333"
DOC = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
OLD_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
TRUST = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ]
}
DEV_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/DevAccess"
LOGS_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/ReadLogs"
DEVS_ARN = f"arn:aws:iam::{ACCOUNT}:group/Developers"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/WebRole"
PROFILE_ARN = f"arn:aws:iam::{ACCOUNT}:instance-profile/WebProfile"
OLD_VERSION = PolicyVersion(version_id="v1", document=OLD_DOC)
FULL = Snapshot(
    account_id=ACCOUNT,
    users=(
        User(
            name="erin",
            arn=f"arn:aws:iam::{ACCOUNT}:user/erin",
            inline_policies=(InlinePolicy(name="Ec2", document=DOC),),
            managed_arns=(DEV_POLICY_ARN,),
            group_names=("Developers",),
            access_key_count=0,
            has_console_password=False,
        ),
    ),
    groups=(Group(name="Developers", arn=DEVS_ARN, managed_arns=(LOGS_POLICY_ARN,)),),
    roles=(Role(name="WebRole", arn=ROLE_ARN, trust_document=TRUST),),
    managed_policies=(
        ManagedPolicy(arn=DEV_POLICY_ARN, default_document=DOC),
        ManagedPolicy(arn=LOGS_POLICY_ARN, default_document=DOC),
    ),
    inactive_versions_by_arn={DEV_POLICY_ARN: (OLD_VERSION,)},
    instance_profiles=(
        InstanceProfile(name="WebProfile", arn=PROFILE_ARN, role_names=("WebRole",)),
    ),
    lambda_functions=(
        LambdaFunction(
            name="Deployer",
            arn=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:Deployer",
            role_arn=ROLE_ARN,
        ),
    ),
    ec2_instances=(
        Ec2Instance(
            instance_id="i-0abc123",
            arn=f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc123",
            instance_profile_arn=PROFILE_ARN,
            ssm_managed=None,
        ),
    ),
)


def test_empty_snapshot_round_trip():
    empty = Snapshot(account_id=ACCOUNT)
    assert load_snapshot(snapshot_to_dict(empty)) == empty


def test_full_snapshot_survives_real_json():
    text = json.dumps(snapshot_to_dict(FULL))
    assert load_snapshot(json.loads(text)) == FULL


def test_file_nests_versions_inside_their_policy():
    dumped = snapshot_to_dict(FULL)
    assert "inactive_versions_by_arn" not in dumped
    assert dumped["managed_policies"][0]["inactive_versions"] == [
        {"version_id": "v1", "document": OLD_DOC}
    ]
    assert dumped["managed_policies"][1]["inactive_versions"] == []


def test_orphan_versions_are_refused():
    ghost_arn = f"arn:aws:iam::{ACCOUNT}:policy/Ghost"
    orphaned = Snapshot(
        account_id=ACCOUNT, inactive_versions_by_arn={ghost_arn: (OLD_VERSION,)}
    )
    message = (
        f"snapshot: inactive versions for policies not in the snapshot: {ghost_arn}"
    )
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        snapshot_to_dict(orphaned)
