"""Snapshot data: an AWS account's IAM data as small frozen dataclasses.

The collector (Phase 3) converts the raw AWS response into these.
Policy documents are stored raw, exactly as collected; the evaluator
normalises them when it needs them (D25).
"""

from dataclasses import dataclass, field
from typing import Any

PolicyDocument = dict[str, Any]


@dataclass(frozen=True)
class InlinePolicy:
    name: str
    document: PolicyDocument


@dataclass(frozen=True)
class ManagedPolicy:
    arn: str
    default_document: PolicyDocument


@dataclass(frozen=True)
class Group:
    name: str
    arn: str
    inline_policies: tuple[InlinePolicy, ...] = ()
    managed_arns: tuple[str, ...] = ()


@dataclass(frozen=True)
class User:
    name: str
    arn: str
    inline_policies: tuple[InlinePolicy, ...] = ()
    managed_arns: tuple[str, ...] = ()
    group_names: tuple[str, ...] = ()
    access_key_count: int | None = None
    has_console_password: bool | None = None


@dataclass(frozen=True)
class Role:
    name: str
    arn: str
    trust_document: PolicyDocument
    inline_policies: tuple[InlinePolicy, ...] = ()
    managed_arns: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyVersion:
    version_id: str
    document: PolicyDocument


@dataclass(frozen=True)
class InstanceProfile:
    name: str
    arn: str
    role_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class LambdaFunction:
    name: str
    arn: str
    role_arn: str


@dataclass(frozen=True)
class Ec2Instance:
    instance_id: str
    arn: str
    # None = no instance profile attached (always known from DescribeInstances)
    instance_profile_arn: str | None = None
    # None = unknown (D29/D30)
    ssm_managed: bool | None = None


@dataclass(frozen=True)
class Snapshot:
    account_id: str
    users: tuple[User, ...] = ()
    groups: tuple[Group, ...] = ()
    roles: tuple[Role, ...] = ()
    managed_policies: tuple[ManagedPolicy, ...] = ()
    # D28: never passed to gathering; read only by rule 2 and the what-if
    inactive_versions_by_arn: dict[str, tuple[PolicyVersion, ...]] = field(
        default_factory=dict
    )
    instance_profiles: tuple[InstanceProfile, ...] = ()
    lambda_functions: tuple[LambdaFunction, ...] = ()
    ec2_instances: tuple[Ec2Instance, ...] = ()


def _string_tuple(value: Any, who: str, field_name: str) -> tuple[str, ...]:
    """JSON list of strings -> tuple of strings (D31). Anything else: ValueError."""
    if not isinstance(value, list):
        raise ValueError(
            f"{who}: {field_name} must be a list of strings, got {type(value).__name__}"
        )
    for position, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(
                f"{who}: {field_name}[{position}] must be a string, "
                f"got {type(item).__name__}"
            )
    return tuple(value)


MAX_ACCESS_KEYS = 2  # AWS hard limit per IAM user (rule 10 will use it too)


def _optional_bool(value: Any, who: str, field_name: str) -> bool | None:
    """JSON true/false -> bool; missing/null -> None (unknown, D29)."""
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(
            f"{who}: {field_name} must be true, false or missing, "
            f"got {type(value).__name__}"
        )
    return value


def _optional_key_count(value: Any, who: str, field_name: str) -> int | None:
    """JSON whole number 0..MAX_ACCESS_KEYS -> int; missing/null -> None (D29)."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{who}: {field_name} must be a whole number or missing, "
            f"got {type(value).__name__}"
        )
    if not 0 <= value <= MAX_ACCESS_KEYS:
        raise ValueError(
            f"{who}: {field_name} must be between 0 and {MAX_ACCESS_KEYS}, got {value}"
        )
    return value


def _check_object(
    data: Any, who: str, required: frozenset[str], optional: frozenset[str]
) -> None:
    """D31: a JSON object with every required key and no unknown key."""
    if not isinstance(data, dict):
        raise ValueError(f"{who}: must be a JSON object, got {type(data).__name__}")
    missing = sorted(required - data.keys())
    if missing:
        raise ValueError(f"{who}: missing required field(s): {', '.join(missing)}")
    unknown = sorted(data.keys() - required - optional)
    if unknown:
        raise ValueError(f"{who}: unknown field(s): {', '.join(unknown)}")
