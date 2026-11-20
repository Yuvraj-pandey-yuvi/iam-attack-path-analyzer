import pytest

from iampath.evaluator import _wildcard_match, action_matches, resource_matches


@pytest.mark.parametrize(
    ("pattern", "action", "expected"),
    [
        ("iam:*", "iam:CreateUser", True),
        ("iam:Attach*", "iam:DetachUserPolicy", False),
        ("iam:attach*", "IAM:AttachUserPolicy", True),
        ("iam:Get?", "iam:GetUser", False),
        ("*", "s3:GetObject", True),
        ("iam:*Policy", "iam:AttachRolePolicy", True),
    ],
)
def test_action_matches(pattern, action, expected):
    assert action_matches(pattern, action) is expected


@pytest.mark.parametrize(
    ("pattern", "arn", "expected"),
    [
        ("arn:aws:s3:::logs/*", "arn:aws:s3:::logs/2026/nov.txt", True),
        ("arn:aws:iam::*:user/Admin", "arn:aws:iam::123456789012:user/admin", False),
        ("arn:aws:s3:::my.bucket", "arn:aws:s3:::myXbucket", False),
        ("arn:aws:s3:::reports/[draft]", "arn:aws:s3:::reports/[draft]", True),
        ("arn:aws:s3:::reports/a+b.txt", "arn:aws:s3:::reports/a+b.txt", True),
        ("arn:aws:s3:::logs/?", "arn:aws:s3:::logs/a", True),
    ],
)
def test_resource_matches(pattern, arn, expected):
    assert resource_matches(pattern, arn) is expected


def test_ignore_case_is_keyword_only():
    with pytest.raises(TypeError):
        _wildcard_match("a", "a", True)
