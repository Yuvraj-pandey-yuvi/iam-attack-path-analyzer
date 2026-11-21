"""Principal-level gathering (Phase 1, step 6; D23-D26)."""

import re
from dataclasses import replace

import pytest

from iampath.evaluator import (
    Decision,
    evaluate_statements,
    gather_role_statements,
    gather_user_statements,
    normalize_policy_document,
)
from iampath.snapshot import Group, InlinePolicy, ManagedPolicy, Role, User

ACCOUNT = "arn:aws:iam::123456789012"
DEV = f"{ACCOUNT}:policy/DevAccess"
READ = f"{ACCOUNT}:policy/ReadLogs"
MISSING = f"{ACCOUNT}:policy/DevAcess"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action):
    return {"Effect": "Allow", "Action": action, "Resource": "*"}


def deny(action):
    return {"Effect": "Deny", "Action": action, "Resource": "*"}


BROKEN = doc(
    {"Effect": "Allow", "Action": "iam:*", "NotAction": "s3:*", "Resource": "*"}
)
EC2_DOC = doc(allow("ec2:*"))
DEV_DOC = doc(allow("iam:*"), deny("s3:*"))
NO_KEYS_DOC = doc(deny("iam:CreateAccessKey"))
READ_DOC = doc(allow("logs:Get*"))
DEPLOY_DOC = doc(allow("s3:*"))
TRUST_DOC = doc(
    {
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
)

POLICIES = {DEV: ManagedPolicy(DEV, DEV_DOC), READ: ManagedPolicy(READ, READ_DOC)}
DEVELOPERS = Group(
    name="Developers",
    arn=f"{ACCOUNT}:group/Developers",
    inline_policies=(InlinePolicy("NoKeys", NO_KEYS_DOC),),
    managed_arns=(READ,),
)
GROUPS = {"Developers": DEVELOPERS}
ERIN = User(
    name="erin",
    arn=f"{ACCOUNT}:user/erin",
    inline_policies=(InlinePolicy("Ec2", EC2_DOC),),
    managed_arns=(DEV,),
    group_names=("Developers",),
)
DEPLOY = Role(
    name="DeployRole",
    arn=f"{ACCOUNT}:role/DeployRole",
    trust_document=TRUST_DOC,
    inline_policies=(InlinePolicy("Deploy", DEPLOY_DOC),),
)


def test_user_pile_is_own_policies_then_group_policies():
    expected = (
        normalize_policy_document(EC2_DOC)
        + normalize_policy_document(DEV_DOC)
        + normalize_policy_document(NO_KEYS_DOC)
        + normalize_policy_document(READ_DOC)
    )
    assert gather_user_statements(ERIN, GROUPS, POLICIES) == expected


def test_group_deny_applies_to_member():
    pile = gather_user_statements(ERIN, GROUPS, POLICIES)
    keys = evaluate_statements(pile, "iam:CreateAccessKey", "*")
    attach = evaluate_statements(pile, "iam:AttachUserPolicy", "*")
    assert keys.decision is Decision.EXPLICIT_DENY
    assert attach.decision is Decision.ALLOW


def test_user_without_policies_is_implicitly_denied():
    nobody = User(name="nobody", arn=f"{ACCOUNT}:user/nobody")
    pile = gather_user_statements(nobody, GROUPS, POLICIES)
    assert pile == ()
    result = evaluate_statements(pile, "iam:CreateAccessKey", "*")
    assert result.decision is Decision.IMPLICIT_DENY


def test_role_pile_ignores_trust_policy():
    with pytest.raises(ValueError):
        normalize_policy_document(TRUST_DOC)
    expected = normalize_policy_document(DEPLOY_DOC)
    assert gather_role_statements(DEPLOY, POLICIES) == expected


ERROR_CASES = [
    pytest.param(
        lambda: gather_user_statements(
            replace(ERIN, group_names=("Develpers",)), GROUPS, POLICIES
        ),
        "user/erin: group Develpers not found in snapshot",
        id="missing-group",
    ),
    pytest.param(
        lambda: gather_user_statements(
            replace(ERIN, managed_arns=(MISSING,)), GROUPS, POLICIES
        ),
        f"user/erin: managed policy {MISSING} not found in snapshot",
        id="missing-user-managed",
    ),
    pytest.param(
        lambda: gather_user_statements(
            ERIN,
            {"Developers": replace(DEVELOPERS, managed_arns=(MISSING,))},
            POLICIES,
        ),
        f"user/erin via group/Developers: managed policy {MISSING} not found",
        id="missing-group-managed",
    ),
    pytest.param(
        lambda: gather_user_statements(
            replace(ERIN, inline_policies=(InlinePolicy("Ec2", BROKEN),)),
            GROUPS,
            POLICIES,
        ),
        "user/erin: inline policy Ec2: ",
        id="broken-user-inline",
    ),
    pytest.param(
        lambda: gather_user_statements(
            ERIN,
            {
                "Developers": replace(
                    DEVELOPERS, inline_policies=(InlinePolicy("NoKeys", BROKEN),)
                )
            },
            POLICIES,
        ),
        "user/erin via group/Developers: inline policy NoKeys: ",
        id="broken-group-inline",
    ),
    pytest.param(
        lambda: gather_user_statements(
            ERIN, GROUPS, {**POLICIES, DEV: ManagedPolicy(DEV, BROKEN)}
        ),
        f"user/erin: managed policy {DEV}: ",
        id="broken-user-managed",
    ),
    pytest.param(
        lambda: gather_role_statements(
            replace(DEPLOY, managed_arns=(MISSING,)), POLICIES
        ),
        f"role/DeployRole: managed policy {MISSING} not found in snapshot",
        id="missing-role-managed",
    ),
]


@pytest.mark.parametrize(("gather", "message_start"), ERROR_CASES)
def test_bad_input_raises_valueerror_naming_who_and_what(gather, message_start):
    with pytest.raises(ValueError, match="^" + re.escape(message_start)):
        gather()


# Test #1: the NotAction trap, through the full user path (Phase 1, step 7).
MALLORY_ARN = f"{ACCOUNT}:user/mallory"
TRAP_ARN = f"{ACCOUNT}:policy/AllButS3"
TRAP_DOC = doc({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"})
TRAP_INLINE = (InlinePolicy("AllButS3", TRAP_DOC),)
TRAP_POLICIES = {TRAP_ARN: ManagedPolicy(TRAP_ARN, TRAP_DOC)}

TRAP_ROUTES = {
    "user-inline": ({"inline_policies": TRAP_INLINE}, None),
    "user-managed": ({"managed_arns": (TRAP_ARN,)}, None),
    "group-inline": ({}, {"inline_policies": TRAP_INLINE}),
    "group-managed": ({}, {"managed_arns": (TRAP_ARN,)}),
}


@pytest.mark.parametrize(
    ("user_parts", "group_parts"), TRAP_ROUTES.values(), ids=TRAP_ROUTES.keys()
)
def test_notaction_trap_allows_attach_user_policy(user_parts, group_parts):
    groups = {}
    if group_parts is not None:
        group_arn = f"{ACCOUNT}:group/Contractors"
        groups["Contractors"] = Group("Contractors", group_arn, **group_parts)
        user_parts = {**user_parts, "group_names": ("Contractors",)}
    mallory = User("mallory", MALLORY_ARN, **user_parts)

    pile = gather_user_statements(mallory, groups, TRAP_POLICIES)
    attach = evaluate_statements(pile, "iam:AttachUserPolicy", MALLORY_ARN)
    s3 = evaluate_statements(pile, "s3:PutObject", "arn:aws:s3:::payroll/q4.csv")

    assert attach.decision == Decision.ALLOW
    assert attach.conditional is False
    assert len(attach.matched_statements) == 1
    assert attach.matched_statements[0].not_actions == ("s3:*",)
    assert s3.decision == Decision.IMPLICIT_DENY


def test_role_pile_includes_managed_policies():
    role = replace(DEPLOY, managed_arns=(DEV,))
    expected = normalize_policy_document(DEPLOY_DOC) + normalize_policy_document(
        DEV_DOC
    )
    assert gather_role_statements(role, POLICIES) == expected
