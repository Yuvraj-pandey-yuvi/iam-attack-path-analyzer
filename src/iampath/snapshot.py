"""Snapshot data: an AWS account's IAM data as small frozen dataclasses.

The collector (Phase 3) converts the raw AWS response into these.
Policy documents are stored raw, exactly as collected; the evaluator
normalises them when it needs them (D25).
"""

import re
from collections.abc import Callable
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
        document = _require_document(
            item["document"], f"{who} inline policy {name}", "document"
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


def _require_document(value: Any, who: str, field_name: str) -> PolicyDocument:
    """Policy document: must be a JSON object; contents are checked later (D25)."""
    if not isinstance(value, dict):
        raise ValueError(
            f"{who}: {field_name} must be a JSON object, got {type(value).__name__}"
        )
    return value


GROUP_REQUIRED = frozenset({"name", "arn"})
GROUP_OPTIONAL = frozenset({"inline_policies", "managed_arns"})


def _load_group(data: Any, position: str) -> Group:
    """One JSON group object -> Group (D31)."""
    basics = _load_identity_basics(
        data, position, "group", GROUP_REQUIRED, GROUP_OPTIONAL
    )
    return Group(
        name=basics.name,
        arn=basics.arn,
        inline_policies=basics.inline_policies,
        managed_arns=basics.managed_arns,
    )


ROLE_REQUIRED = frozenset({"name", "arn", "trust_document"})
ROLE_OPTIONAL = frozenset({"inline_policies", "managed_arns"})


def _load_role(data: Any, position: str) -> Role:
    """One JSON role object -> Role (D23, D31). Trust policy kept raw."""
    basics = _load_identity_basics(data, position, "role", ROLE_REQUIRED, ROLE_OPTIONAL)
    return Role(
        name=basics.name,
        arn=basics.arn,
        trust_document=_require_document(
            data["trust_document"], basics.who, "trust_document"
        ),
        inline_policies=basics.inline_policies,
        managed_arns=basics.managed_arns,
    )


POLICY_VERSION_FIELDS = frozenset({"version_id", "document"})


def _load_policy_versions(value: Any, who: str) -> tuple[PolicyVersion, ...]:
    """JSON list of {"version_id", "document"} objects -> tuple (D28, D32)."""
    if not isinstance(value, list):
        raise ValueError(
            f"{who}: inactive_versions must be a list, got {type(value).__name__}"
        )
    versions = []
    for position, item in enumerate(value):
        label = f"{who} inactive_versions[{position}]"
        _check_object(item, label, POLICY_VERSION_FIELDS, frozenset())
        version_id = _require_string(item["version_id"], label, "version_id")
        document = _require_document(
            item["document"], f"{who} version {version_id}", "document"
        )
        versions.append(PolicyVersion(version_id=version_id, document=document))
    return tuple(versions)


MANAGED_POLICY_REQUIRED = frozenset({"arn", "default_document"})
MANAGED_POLICY_OPTIONAL = frozenset({"inactive_versions"})


@dataclass(frozen=True)
class _LoadedManagedPolicy:
    """A managed policy and its inactive versions, kept apart (D28, D32)."""

    policy: ManagedPolicy
    inactive_versions: tuple[PolicyVersion, ...]


def _load_managed_policy(data: Any, position: str) -> _LoadedManagedPolicy:
    """One JSON managed policy -> policy + its inactive versions, separated (D32)."""
    _check_object(data, position, MANAGED_POLICY_REQUIRED, MANAGED_POLICY_OPTIONAL)
    arn = _require_string(data["arn"], position, "arn")
    who = f"policy {arn}"
    return _LoadedManagedPolicy(
        policy=ManagedPolicy(
            arn=arn,
            default_document=_require_document(
                data["default_document"], who, "default_document"
            ),
        ),
        inactive_versions=_load_policy_versions(data.get("inactive_versions", []), who),
    )


def _optional_string(value: Any, who: str, field_name: str) -> str | None:
    """Optional JSON text field: missing/null -> None, else non-empty text (D31)."""
    if value is None:
        return None
    return _require_string(value, who, field_name)


MAX_ROLES_PER_INSTANCE_PROFILE = 1  # AWS hard limit
INSTANCE_PROFILE_REQUIRED = frozenset({"name", "arn"})
INSTANCE_PROFILE_OPTIONAL = frozenset({"role_names"})


def _load_instance_profile(data: Any, position: str) -> InstanceProfile:
    """One JSON instance profile -> InstanceProfile (D29, D31)."""
    _check_object(data, position, INSTANCE_PROFILE_REQUIRED, INSTANCE_PROFILE_OPTIONAL)
    name = _require_string(data["name"], position, "name")
    who = f"instance-profile/{name}"
    arn = _require_string(data["arn"], who, "arn")
    role_names = _string_tuple(data.get("role_names", []), who, "role_names")
    if len(role_names) > MAX_ROLES_PER_INSTANCE_PROFILE:
        raise ValueError(
            f"{who}: role_names can hold at most {MAX_ROLES_PER_INSTANCE_PROFILE} "
            f"role, got {len(role_names)}"
        )
    return InstanceProfile(name=name, arn=arn, role_names=role_names)


LAMBDA_FUNCTION_FIELDS = frozenset({"name", "arn", "role_arn"})


def _load_lambda_function(data: Any, position: str) -> LambdaFunction:
    """One JSON Lambda function -> LambdaFunction (D29, D31)."""
    _check_object(data, position, LAMBDA_FUNCTION_FIELDS, frozenset())
    name = _require_string(data["name"], position, "name")
    who = f"function/{name}"
    return LambdaFunction(
        name=name,
        arn=_require_string(data["arn"], who, "arn"),
        role_arn=_require_string(data["role_arn"], who, "role_arn"),
    )


EC2_INSTANCE_REQUIRED = frozenset({"instance_id", "arn"})
EC2_INSTANCE_OPTIONAL = frozenset({"instance_profile_arn", "ssm_managed"})


def _load_ec2_instance(data: Any, position: str) -> Ec2Instance:
    """One JSON EC2 instance -> Ec2Instance (D29, D30, D31)."""
    _check_object(data, position, EC2_INSTANCE_REQUIRED, EC2_INSTANCE_OPTIONAL)
    instance_id = _require_string(data["instance_id"], position, "instance_id")
    who = f"instance/{instance_id}"
    return Ec2Instance(
        instance_id=instance_id,
        arn=_require_string(data["arn"], who, "arn"),
        # missing = no profile attached (always known; see the class comment)
        instance_profile_arn=_optional_string(
            data.get("instance_profile_arn"), who, "instance_profile_arn"
        ),
        # missing = unknown (D29/D30)
        ssm_managed=_optional_bool(data.get("ssm_managed"), who, "ssm_managed"),
    )


def _load_list(
    data: dict[str, Any], list_name: str, loader: Callable[[Any, str], Any]
) -> tuple[Any, ...]:
    """Top-level JSON list -> tuple; each item gets its position label (D31)."""
    value = data.get(list_name, [])
    if not isinstance(value, list):
        raise ValueError(
            f"snapshot: {list_name} must be a list, got {type(value).__name__}"
        )
    items = []
    for position, item in enumerate(value):
        items.append(loader(item, f"{list_name}[{position}]"))
    return tuple(items)


def _reject_duplicates(items: tuple[Any, ...], list_name: str, key_name: str) -> None:
    """Two entries with the same name/ARN would make every lookup ambiguous (D31)."""
    seen = set()
    for item in items:
        key = getattr(item, key_name)
        if key in seen:
            raise ValueError(f"snapshot: {list_name} has duplicate {key_name} {key!r}")
        seen.add(key)


ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{12}")


def _load_account_id(value: Any) -> str:
    """AWS account IDs are always exactly 12 ASCII digits (D31)."""
    account_id = _require_string(value, "snapshot", "account_id")
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ValueError(
            f"snapshot: account_id must be exactly 12 digits, got {account_id!r}"
        )
    return account_id
