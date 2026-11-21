"""Phase 2 step 1: snapshot v2 shape (D28, D29)."""

import dataclasses

import pytest

from iampath.snapshot import Snapshot, User

ACCOUNT_ID = "111122223333"
ERIN_ARN = "arn:aws:iam::111122223333:user/erin"


def test_unknown_user_facts_default_to_none():
    erin = User(name="erin", arn=ERIN_ARN)
    assert erin.access_key_count is None
    assert erin.has_console_password is None


def test_snapshot_defaults_are_empty():
    snapshot = Snapshot(account_id=ACCOUNT_ID)
    assert snapshot.users == ()
    assert snapshot.groups == ()
    assert snapshot.roles == ()
    assert snapshot.managed_policies == ()
    assert snapshot.inactive_versions_by_arn == {}
    assert snapshot.instance_profiles == ()
    assert snapshot.lambda_functions == ()
    assert snapshot.ec2_instances == ()


def test_each_snapshot_gets_its_own_versions_dict():
    first = Snapshot(account_id=ACCOUNT_ID)
    second = Snapshot(account_id=ACCOUNT_ID)
    assert first.inactive_versions_by_arn is not second.inactive_versions_by_arn


def test_snapshot_is_frozen():
    snapshot = Snapshot(account_id=ACCOUNT_ID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.users = ()
