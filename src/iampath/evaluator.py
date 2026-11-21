"""Offline IAM policy evaluator (Phase 1).

Steps 2-5: result types (D17, D18), normalisation, matching (D20, D21), combining.
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


def _action_part_matches(statement: Statement, action: str) -> bool:
    """Is the request's action covered by Action (any match) or NotAction (none)?"""
    has_action = bool(statement.actions)
    has_not_action = bool(statement.not_actions)
    if has_action == has_not_action:
        raise ValueError("statement needs exactly one of Action / NotAction")
    if has_action:
        return any(action_matches(pattern, action) for pattern in statement.actions)
    return not any(action_matches(pattern, action) for pattern in statement.not_actions)


def _resource_part_matches(statement: Statement, arn: str) -> bool:
    """Is the request's ARN covered by Resource (any match) or NotResource (none)?"""
    has_resource = bool(statement.resources)
    has_not_resource = bool(statement.not_resources)
    if has_resource == has_not_resource:
        raise ValueError("statement needs exactly one of Resource / NotResource")
    if has_resource:
        return any(resource_matches(pattern, arn) for pattern in statement.resources)
    return not any(
        resource_matches(pattern, arn) for pattern in statement.not_resources
    )


def statement_matches(statement: Statement, action: str, arn: str) -> bool:
    """Does this statement apply to the request? (Effect is ignored here.)

    Both halves are always evaluated, so a malformed statement raises even
    when the action half alone would already give False (D19: loud, not silent).
    """
    action_covered = _action_part_matches(statement, action)
    resource_covered = _resource_part_matches(statement, arn)
    return action_covered and resource_covered


def evaluate_statements(
    statements: tuple[Statement, ...], action: str, arn: str
) -> EvaluationResult:
    """Combine statements: explicit Deny > Allow > implicit deny (D17, D18)."""
    allows: list[Statement] = []
    hard_denies: list[Statement] = []
    soft_denies: list[Statement] = []

    for statement in statements:
        if not statement_matches(statement, action, arn):
            continue
        if statement.effect == "Allow":
            allows.append(statement)
        elif statement.has_condition:
            soft_denies.append(statement)
        else:
            hard_denies.append(statement)

    if hard_denies:
        return EvaluationResult(
            decision=Decision.EXPLICIT_DENY, matched_statements=tuple(hard_denies)
        )
    if not allows:
        return EvaluationResult(decision=Decision.IMPLICIT_DENY)

    has_unconditional_allow = any(not allow.has_condition for allow in allows)
    conditional = (not has_unconditional_allow) or bool(soft_denies)
    return EvaluationResult(
        decision=Decision.ALLOW,
        matched_statements=tuple(allows + soft_denies),
        conditional=conditional,
    )
