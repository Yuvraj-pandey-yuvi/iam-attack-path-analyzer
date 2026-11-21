"""Snapshot data: an AWS account's IAM data as small frozen dataclasses.

The collector (Phase 3) converts the raw AWS response into these.
Policy documents are stored raw, exactly as collected; the evaluator
normalises them when it needs them (D25).
"""

from dataclasses import dataclass
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


@dataclass(frozen=True)
class Role:
    name: str
    arn: str
    trust_document: PolicyDocument
    inline_policies: tuple[InlinePolicy, ...] = ()
    managed_arns: tuple[str, ...] = ()
