"""Phase 2 step 1: saving a snapshot back to plain JSON data (D32, D33)."""

from iampath.snapshot import (
    Group,
    InlinePolicy,
    Role,
    User,
    _dump_group,
    _dump_role,
    _dump_user,
    _load_group,
    _load_role,
    _load_user,
)

ACCOUNT = "111122223333"
DOC = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
DEV_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/DevAccess"
TRUST = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ]
}
FULL_USER = User(
    name="erin",
    arn=f"arn:aws:iam::{ACCOUNT}:user/erin",
    inline_policies=(InlinePolicy(name="Ec2", document=DOC),),
    managed_arns=(DEV_POLICY_ARN,),
    group_names=("Developers",),
    access_key_count=1,
    has_console_password=False,
)
FULL_GROUP = Group(
    name="Developers",
    arn=f"arn:aws:iam::{ACCOUNT}:group/Developers",
    inline_policies=(InlinePolicy(name="ReadLogs", document=DOC),),
    managed_arns=(DEV_POLICY_ARN,),
)
FULL_ROLE = Role(
    name="WebRole",
    arn=f"arn:aws:iam::{ACCOUNT}:role/WebRole",
    trust_document=TRUST,
    inline_policies=(InlinePolicy(name="S3", document=DOC),),
    managed_arns=(DEV_POLICY_ARN,),
)


def test_minimal_user_writes_every_field():
    user = User(name="erin", arn=FULL_USER.arn)
    assert _dump_user(user) == {
        "name": "erin",
        "arn": FULL_USER.arn,
        "inline_policies": [],
        "managed_arns": [],
        "group_names": [],
        "access_key_count": None,
        "has_console_password": None,
    }


def test_user_round_trip():
    assert _load_user(_dump_user(FULL_USER), "users[0]") == FULL_USER


def test_group_round_trip():
    assert _load_group(_dump_group(FULL_GROUP), "groups[0]") == FULL_GROUP


def test_role_round_trip():
    assert _load_role(_dump_role(FULL_ROLE), "roles[0]") == FULL_ROLE
