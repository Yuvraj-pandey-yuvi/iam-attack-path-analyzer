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


def _require_string(value: Any, who: str, field_name: str) -> str:
    """Required JSON text field: must be a non-empty string (D31)."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{who}: {field_name} must be non-empty text, got {value!r}")
    return value


INLINE_POLICY_FIELDS = frozenset({"name", "document"})


def _load_inline_policies(value: Any, who: str) -> tuple[InlinePolicy, ...]:
    """JSON list of {"name", "document"} objects -> tuple of InlinePolicy (D31)."""
    if not isinstance(value, list):
        raise ValueError(
            f"{who}: inline_policies must be a list, got {type(value).__name__}"
        )
    policies = []
    for position, item in enumerate(value):
        label = f"{who} inline_policies[{position}]"
        _check_object(item, label, INLINE_POLICY_FIELDS, frozenset())
        name = _require_string(item["name"], label, "name")
        document = item["document"]
        if not isinstance(document, dict):
            raise ValueError(
                f"{who} inline policy {name}: document must be a JSON object, "
                f"got {type(document).__name__}"
            )
        policies.append(InlinePolicy(name=name, document=document))
    return tuple(policies)


USER_REQUIRED = frozenset({"name", "arn"})
USER_OPTIONAL = frozenset(
    {
        "inline_policies",
        "managed_arns",
        "group_names",
        "access_key_count",
        "has_console_password",
    }
)


@dataclass(frozen=True)
class _IdentityBasics:
    """The fields every user, group and role has, already checked (D31)."""

    name: str
    arn: str
    who: str
    inline_policies: tuple[InlinePolicy, ...]
    managed_arns: tuple[str, ...]


def _load_identity_basics(
    data: Any,
    position: str,
    kind: str,
    required: frozenset[str],
    optional: frozenset[str],
) -> _IdentityBasics:
    """Shared first half of the user/group/role loaders (D31)."""
    _check_object(data, position, required, optional)
    name = _require_string(data["name"], position, "name")
    who = f"{kind}/{name}"
    return _IdentityBasics(
        name=name,
        arn=_require_string(data["arn"], who, "arn"),
        who=who,
        inline_policies=_load_inline_policies(data.get("inline_policies", []), who),
        managed_arns=_string_tuple(data.get("managed_arns", []), who, "managed_arns"),
    )


def _load_user(data: Any, position: str) -> User:
    """One JSON user object -> User (D29, D31). Errors name the user."""
    basics = _load_identity_basics(data, position, "user", USER_REQUIRED, USER_OPTIONAL)
    who = basics.who
    return User(
        name=basics.name,
        arn=basics.arn,
        inline_policies=basics.inline_policies,
        managed_arns=basics.managed_arns,
        group_names=_string_tuple(data.get("group_names", []), who, "group_names"),
        access_key_count=_optional_key_count(
            data.get("access_key_count"), who, "access_key_count"
        ),
        has_console_password=_optional_bool(
            data.get("has_console_password"), who, "has_console_password"
        ),
    )
