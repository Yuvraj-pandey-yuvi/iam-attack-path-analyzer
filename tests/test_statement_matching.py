"""Phase 1, step 4: does a statement apply to a request (action + resource)?"""

import pytest

from iampath.evaluator import Statement, normalize_statement, statement_matches

LOGS_FILE = "arn:aws:s3:::logs/a.txt"
LOGS_FILE_UPPER = "arn:aws:s3:::LOGS/a.txt"
LOGS_PREFIX = "arn:aws:s3:::logs/*"
PROD_BUCKET = "arn:aws:s3:::prod"
ADMIN_ROLE = "arn:aws:iam::111122223333:role/admin"

MATCH_CASES = [
    pytest.param(
        {"Effect": "Allow", "Action": ["iam:*", "s3:Get*"], "Resource": "*"},
        "s3:GetObject",
        LOGS_FILE,
        True,
        id="A-action-list-one-pattern-matches",
    ),
    pytest.param(
        {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"},
        "s3:GetObject",
        LOGS_FILE,
        False,
        id="B-notaction-excludes-it",
    ),
    pytest.param(
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": LOGS_PREFIX},
        "s3:GetObject",
        LOGS_FILE,
        True,
        id="C-notaction-covers-it",
    ),
    pytest.param(
        {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": LOGS_PREFIX},
        "s3:GetObject",
        LOGS_FILE,
        False,
        id="D-notresource-excludes-it",
    ),
    pytest.param(
        {"Effect": "Allow", "Action": "S3:getobject", "Resource": LOGS_FILE_UPPER},
        "s3:GetObject",
        LOGS_FILE,
        False,
        id="E-action-ok-but-resource-case-differs",
    ),
    pytest.param(
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        "IAM:PassRole",
        ADMIN_ROLE,
        False,
        id="F-notaction-match-ignores-case",
    ),
    pytest.param(
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        "s3:DeleteBucket",
        PROD_BUCKET,
        True,
        id="G-allow-with-notaction-is-a-broad-grant",
    ),
]


@pytest.mark.parametrize(("raw", "action", "arn", "expected"), MATCH_CASES)
def test_statement_matches(raw, action, arn, expected):
    statement = normalize_statement(raw)
    assert statement_matches(statement, action, arn) is expected


BROKEN_CASES = [
    pytest.param(
        Statement(effect="Allow", resources=("*",)),
        id="neither-action-nor-notaction",
    ),
    pytest.param(
        Statement(
            effect="Allow",
            actions=("iam:*",),
            not_actions=("iam:Get*",),
            resources=("*",),
        ),
        id="both-action-and-notaction",
    ),
    pytest.param(
        Statement(effect="Allow", actions=("s3:*",)),
        id="no-resource-part-even-when-action-misses",
    ),
    pytest.param(
        Statement(
            effect="Allow",
            actions=("*",),
            resources=("*",),
            not_resources=("*",),
        ),
        id="both-resource-and-notresource",
    ),
]


@pytest.mark.parametrize("statement", BROKEN_CASES)
def test_broken_statement_raises(statement):
    with pytest.raises(ValueError):
        statement_matches(statement, "iam:PassRole", ADMIN_ROLE)


# Step 7 review: lists with more than one pattern ("any" vs "none" logic).
TWO_SERVICES_EXCLUDED = {"Effect": "Allow", "NotAction": ["s3:*", "iam:*"]}
LIST_CASES = [
    pytest.param(
        {**TWO_SERVICES_EXCLUDED, "Resource": "*"},
        "iam:CreateUser",
        ADMIN_ROLE,
        False,
        id="notaction-list-second-pattern-excludes",
    ),
    pytest.param(
        {**TWO_SERVICES_EXCLUDED, "Resource": "*"},
        "ec2:RunInstances",
        PROD_BUCKET,
        True,
        id="notaction-list-other-service-covered",
    ),
    pytest.param(
        {"Effect": "Allow", "Action": "s3:*", "Resource": [PROD_BUCKET, LOGS_PREFIX]},
        "s3:GetObject",
        LOGS_FILE,
        True,
        id="resource-list-second-pattern-matches",
    ),
    pytest.param(
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "NotResource": [PROD_BUCKET, LOGS_PREFIX],
        },
        "s3:GetObject",
        LOGS_FILE,
        False,
        id="notresource-list-second-pattern-excludes",
    ),
]


@pytest.mark.parametrize(("raw", "action", "arn", "expected"), LIST_CASES)
def test_statement_matches_with_pattern_lists(raw, action, arn, expected):
    statement = normalize_statement(raw)
    assert statement_matches(statement, action, arn) is expected
