"""Phase 2 step 1: saving a snapshot back to plain JSON data (D32, D33)."""

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
    _dump_ec2_instance,
    _dump_group,
    _dump_instance_profile,
    _dump_lambda_function,
    _dump_managed_policy,
    _dump_role,
    _dump_user,
    _load_ec2_instance,
    _load_group,
    _load_instance_profile,
    _load_lambda_function,
    _load_managed_policy,
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


OLD_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
POLICY = ManagedPolicy(arn=DEV_POLICY_ARN, default_document=DOC)
VERSIONS = (
    PolicyVersion(version_id="v1", document=OLD_DOC),
    PolicyVersion(version_id="v2", document={"Statement": []}),
)
PROFILE = InstanceProfile(
    name="WebProfile",
    arn=f"arn:aws:iam::{ACCOUNT}:instance-profile/WebProfile",
    role_names=("WebRole",),
)
FUNCTION = LambdaFunction(
    name="Deployer",
    arn=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:Deployer",
    role_arn=FULL_ROLE.arn,
)
INSTANCE_ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc123"


def test_policy_without_old_versions_writes_empty_list():
    assert _dump_managed_policy(POLICY, ()) == {
        "arn": DEV_POLICY_ARN,
        "default_document": DOC,
        "inactive_versions": [],
    }


def test_managed_policy_round_trip_keeps_versions_apart():
    dumped = _dump_managed_policy(POLICY, VERSIONS)
    loaded = _load_managed_policy(dumped, "managed_policies[0]")
    assert loaded.policy == POLICY
    assert loaded.inactive_versions == VERSIONS


def test_instance_profile_round_trip():
    dumped = _dump_instance_profile(PROFILE)
    assert _load_instance_profile(dumped, "instance_profiles[0]") == PROFILE


def test_lambda_function_round_trip():
    dumped = _dump_lambda_function(FUNCTION)
    assert _load_lambda_function(dumped, "lambda_functions[0]") == FUNCTION


def test_minimal_ec2_instance_writes_nulls():
    instance = Ec2Instance(instance_id="i-0abc123", arn=INSTANCE_ARN)
    assert _dump_ec2_instance(instance) == {
        "instance_id": "i-0abc123",
        "arn": INSTANCE_ARN,
        "instance_profile_arn": None,
        "ssm_managed": None,
    }


def test_ec2_instance_round_trip_keeps_false():
    instance = Ec2Instance(
        instance_id="i-0abc123",
        arn=INSTANCE_ARN,
        instance_profile_arn=PROFILE.arn,
        ssm_managed=False,
    )
    dumped = _dump_ec2_instance(instance)
    assert _load_ec2_instance(dumped, "ec2_instances[0]") == instance
