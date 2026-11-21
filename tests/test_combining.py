"""Step 5: combining statements into one decision (D17, D18)."""

import pytest

from iampath.evaluator import (
    Decision,
    Statement,
    evaluate_statements,
    normalize_statement,
)

KEY = "iam:CreateAccessKey"
MFA_TRUE = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
MFA_FALSE = {"Bool": {"aws:MultiFactorAuthPresent": "false"}}

ALLOW_IAM = {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
ALLOW_KEY_IF_MFA = {
    "Effect": "Allow",
    "Action": KEY,
    "Resource": "*",
    "Condition": MFA_TRUE,
}
DENY_KEY = {"Effect": "Deny", "Action": KEY, "Resource": "*"}
DENY_KEY_IF_NO_MFA = {
    "Effect": "Deny",
    "Action": KEY,
    "Resource": "*",
    "Condition": MFA_FALSE,
}
DENY_IAM = {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
DENY_S3 = {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}

# Each case: raw statements, action, expected decision, expected conditional,
# and the positions of the statements expected as evidence (in output order).
COMBINE_CASES = [
    pytest.param(
        [ALLOW_IAM, DENY_KEY],
        KEY,
        Decision.EXPLICIT_DENY,
        False,
        (1,),
        id="explicit-deny-beats-allow",
    ),
    pytest.param(
        [ALLOW_IAM, DENY_KEY],
        "iam:AttachUserPolicy",
        Decision.ALLOW,
        False,
        (0,),
        id="deny-about-other-action",
    ),
    pytest.param(
        [ALLOW_IAM, DENY_KEY],
        "s3:GetObject",
        Decision.IMPLICIT_DENY,
        False,
        (),
        id="nothing-matches",
    ),
    pytest.param(
        [ALLOW_IAM, ALLOW_KEY_IF_MFA],
        KEY,
        Decision.ALLOW,
        False,
        (0, 1),
        id="unconditional-allow-wins",
    ),
    pytest.param(
        [ALLOW_KEY_IF_MFA],
        KEY,
        Decision.ALLOW,
        True,
        (0,),
        id="conditional-allow-only",
    ),
    pytest.param(
        [ALLOW_IAM, DENY_KEY_IF_NO_MFA],
        KEY,
        Decision.ALLOW,
        True,
        (0, 1),
        id="d18a-allow-plus-soft-deny",
    ),
    pytest.param(
        [DENY_KEY_IF_NO_MFA],
        KEY,
        Decision.IMPLICIT_DENY,
        False,
        (),
        id="d18b-soft-deny-alone",
    ),
    pytest.param(
        [ALLOW_IAM, DENY_KEY_IF_NO_MFA, DENY_KEY],
        KEY,
        Decision.EXPLICIT_DENY,
        False,
        (2,),
        id="d18c-hard-deny-wins",
    ),
    pytest.param(
        [ALLOW_KEY_IF_MFA, DENY_KEY_IF_NO_MFA],
        KEY,
        Decision.ALLOW,
        True,
        (0, 1),
        id="conditional-allow-plus-soft-deny",
    ),
    pytest.param(
        [ALLOW_IAM, DENY_S3],
        KEY,
        Decision.ALLOW,
        False,
        (0,),
        id="non-matching-deny-ignored",
    ),
    pytest.param(
        [],
        KEY,
        Decision.IMPLICIT_DENY,
        False,
        (),
        id="no-statements",
    ),
    pytest.param(
        [ALLOW_IAM, DENY_KEY, DENY_IAM],
        KEY,
        Decision.EXPLICIT_DENY,
        False,
        (1, 2),
        id="all-hard-denies-are-evidence",
    ),
]


@pytest.mark.parametrize(
    ("raw_statements", "action", "decision", "conditional", "matched_positions"),
    COMBINE_CASES,
)
def test_combining(raw_statements, action, decision, conditional, matched_positions):
    statements = tuple(normalize_statement(raw) for raw in raw_statements)
    result = evaluate_statements(statements, action, "*")
    assert result.decision is decision
    assert result.conditional is conditional
    expected = tuple(statements[position] for position in matched_positions)
    assert result.matched_statements == expected


def test_empty_condition_counts_as_no_condition():
    """condition={} must be a hard Deny, or a real Deny would be ignored."""
    deny_with_empty_condition = Statement(
        effect="Deny", actions=("iam:*",), resources=("*",), condition={}
    )
    statements = (normalize_statement(ALLOW_IAM), deny_with_empty_condition)
    result = evaluate_statements(statements, KEY, "*")
    assert result.decision is Decision.EXPLICIT_DENY
    assert result.matched_statements == (deny_with_empty_condition,)


def test_broken_statement_after_a_deny_still_raises():
    """Option A: no early return, so every statement is checked (D19)."""
    statements = (normalize_statement(DENY_KEY), Statement(effect="Allow"))
    with pytest.raises(ValueError):
        evaluate_statements(statements, KEY, "*")
