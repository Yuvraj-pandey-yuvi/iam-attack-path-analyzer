"""Phase 1, step 2 tests: result types and statement normalisation."""

import dataclasses
import json

import pytest

from iampath.evaluator import (
    Decision,
    EvaluationResult,
    normalize_policy_document,
    normalize_statement,
)

MFA_CONDITION = {"Bool": {"aws:MultiFactorAuthPresent": "false"}}


# --- Decision enum (StrEnum) ---
def test_decision_equals_plain_string():
    assert Decision.ALLOW == "ALLOW"


def test_decision_serialises_to_json_without_converter():
    assert json.dumps({"decision": Decision.EXPLICIT_DENY}) == (
        '{"decision": "EXPLICIT_DENY"}'
    )


# --- EvaluationResult (frozen) ---
def test_result_defaults():
    result = EvaluationResult(decision=Decision.IMPLICIT_DENY)
    assert result.matched_statements == ()
    assert result.conditional is False


def test_result_cannot_be_changed():
    result = EvaluationResult(decision=Decision.ALLOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.decision = Decision.EXPLICIT_DENY


# --- Normalisation: string vs list ---
def test_string_action_becomes_tuple():
    statement = normalize_statement(
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
    )
    assert statement.actions == ("iam:*",)
    assert statement.resources == ("*",)


def test_list_action_becomes_tuple():
    statement = normalize_statement(
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}
    )
    assert statement.actions == ("s3:GetObject", "s3:PutObject")


def test_single_statement_object_becomes_one_statement():
    document = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
    }
    assert len(normalize_policy_document(document)) == 1


def test_statement_list_keeps_order():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:CreateAccessKey", "Resource": "*"},
        ]
    }
    statements = normalize_policy_document(document)
    assert [s.effect for s in statements] == ["Allow", "Deny"]


def test_not_action_and_not_resource_are_kept_separately():
    statement = normalize_statement(
        {"Effect": "Allow", "NotAction": "s3:*", "NotResource": "arn:aws:s3:::x"}
    )
    assert statement.actions == ()
    assert statement.not_actions == ("s3:*",)
    assert statement.not_resources == ("arn:aws:s3:::x",)


# --- Condition is kept, not evaluated (D8, D18) ---
def test_condition_is_kept_and_flagged():
    statement = normalize_statement(
        {
            "Effect": "Deny",
            "Action": "iam:CreateAccessKey",
            "Resource": "*",
            "Condition": MFA_CONDITION,
        }
    )
    assert statement.has_condition is True
    assert statement.condition == MFA_CONDITION


def test_no_condition_means_not_flagged():
    statement = normalize_statement(
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
    )
    assert statement.has_condition is False


# --- Invalid shapes are rejected ---
@pytest.mark.parametrize(
    "raw_statement",
    [
        {"Effect": "allow", "Action": "iam:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:*", "NotAction": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:*"},
        {"Effect": "Allow", "Action": 5, "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:*", 5], "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*", "NotResource": "*"},
    ],
    ids=[
        "lowercase-effect",
        "action-and-notaction",
        "no-resource",
        "action-not-str",
        "action-list-with-non-str",
        "resource-and-notresource",
    ],
)
def test_invalid_statement_raises(raw_statement):
    with pytest.raises(ValueError):
        normalize_statement(raw_statement)


# --- Gaps found in the walkthrough ---
def test_statement_that_is_not_object_or_list_raises():
    # Without the isinstance check this would loop over "o", "o", "p", "s"
    # and raise AttributeError, which the policy loop (D19) would not catch.
    with pytest.raises(ValueError):
        normalize_policy_document({"Statement": "oops"})


def test_empty_condition_becomes_none():
    statement = normalize_statement(
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*", "Condition": {}}
    )
    assert statement.condition is None
    assert statement.has_condition is False


def test_missing_statement_key_gives_no_statements():
    assert normalize_policy_document({"Version": "2012-10-17"}) == ()
