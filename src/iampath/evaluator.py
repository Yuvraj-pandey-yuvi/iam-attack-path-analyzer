"""Offline IAM policy evaluator (Phase 1).

Steps 2-3: result types (D17, D18), normalisation, wildcard matching (D20).
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """Answer to "can X do action A on resource R?" (AWS's own terms)."""

    ALLOW = "ALLOW"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    IMPLICIT_DENY = "IMPLICIT_DENY"


@dataclass(frozen=True)
class Statement:
    """One policy statement in a fixed shape: every list field is a tuple."""

    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    condition: dict[str, Any] | None = None
    sid: str | None = None

    @property
    def has_condition(self) -> bool:
        return bool(self.condition)


@dataclass(frozen=True)
class EvaluationResult:
    """Decision + evidence + whether it depends on an unevaluated condition."""

    decision: Decision
    matched_statements: tuple[Statement, ...] = ()
    conditional: bool = False


def _as_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    """IAM allows "x" or ["x", "y"]; always return a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ValueError(f"{field_name} must be a string or a list of strings")


def normalize_statement(raw_statement: dict[str, Any]) -> Statement:
    """Turn one raw JSON statement into a Statement, rejecting invalid shapes."""
    effect = raw_statement.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise ValueError(f"Effect must be 'Allow' or 'Deny', got {effect!r}")
    has_action = "Action" in raw_statement
    has_not_action = "NotAction" in raw_statement
    if has_action == has_not_action:
        raise ValueError("statement needs exactly one of Action / NotAction")

    has_resource = "Resource" in raw_statement
    has_not_resource = "NotResource" in raw_statement
    if has_resource == has_not_resource:
        raise ValueError("statement needs exactly one of Resource / NotResource")

    return Statement(
        effect=effect,
        actions=_as_tuple(raw_statement.get("Action"), "Action"),
        not_actions=_as_tuple(raw_statement.get("NotAction"), "NotAction"),
        resources=_as_tuple(raw_statement.get("Resource"), "Resource"),
        not_resources=_as_tuple(raw_statement.get("NotResource"), "NotResource"),
        condition=raw_statement.get("Condition") or None,
        sid=raw_statement.get("Sid"),
    )


def normalize_policy_document(document: dict[str, Any]) -> tuple[Statement, ...]:
    """A policy's "Statement" may be one object or a list; return a tuple."""
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise ValueError("Statement must be an object or a list of objects")
    return tuple(normalize_statement(raw) for raw in raw_statements)


def _wildcard_match(pattern: str, value: str, *, ignore_case: bool) -> bool:
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    flags = re.IGNORECASE if ignore_case else 0
    return re.fullmatch(regex, value, flags) is not None


def action_matches(pattern: str, action: str) -> bool:
    """IAM actions are case-insensitive: iam:attach* covers IAM:AttachUserPolicy."""
    return _wildcard_match(pattern, action, ignore_case=True)


def resource_matches(pattern: str, arn: str) -> bool:
    """ARNs are case-sensitive: user/Admin and user/admin are different users."""
    return _wildcard_match(pattern, arn, ignore_case=False)
