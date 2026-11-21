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
