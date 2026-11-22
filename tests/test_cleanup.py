# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Safety checks in 99_cleanup.py, with a stubbed S3 client."""
import importlib.util
import os
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("cleanup", os.path.join(ROOT, "99_cleanup.py"))
cleanup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cleanup)


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    exceptions = types.SimpleNamespace(ClientError=ClientError)

    def __init__(self, tags=None, lock="Enabled"):
        self.tags, self.lock, self.deleted = tags, lock, []

    def get_bucket_tagging(self, Bucket):
        if self.tags is None:
            raise ClientError("NoSuchTagSet")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def get_object_lock_configuration(self, Bucket):
        if self.lock is None:
            raise ClientError("ObjectLockConfigurationNotFoundError")
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": self.lock}}

    def get_paginator(self, name):
        raise AssertionError("must not list or delete objects")

    def delete_bucket(self, Bucket):
        self.deleted.append(Bucket)


@pytest.mark.parametrize("tags", [{"ledger-stack": "ledger"}, {"aws:cloudformation:stack-name": "ledger"}])
def test_bucket_of_this_stack_with_object_lock_is_accepted(tags):
    assert cleanup.bucket_belongs_to_stack(FakeS3(tags), "b", "ledger") is None


@pytest.mark.parametrize("s3, reason", [
    (FakeS3(None), "cannot read its tags"),
    (FakeS3({"purpose": "something-else"}), "not tagged as part of stack"),
    (FakeS3({"ledger-stack": "other-stack"}), "not tagged as part of stack"),
    (FakeS3({"ledger-stack": "ledger"}, lock=None), "no Object Lock"),
])
def test_other_buckets_are_refused(s3, reason):
    assert reason in cleanup.bucket_belongs_to_stack(s3, "b", "ledger")


def test_empty_bucket_refuses_a_foreign_bucket_without_touching_it():
    s3 = FakeS3({"ledger-stack": "other-stack"})
    ctx = types.SimpleNamespace(client=lambda name: s3, names=types.SimpleNamespace(stack="ledger"))
    with pytest.raises(SystemExit, match="Refusing to empty bucket"):
        cleanup.empty_bucket(ctx, "someone-elses-bucket", assume_yes=True)
    assert s3.deleted == []


def test_confirmation(monkeypatch):
    cleanup.confirm("do it", "ledger", assume_yes=True)          # --yes skips the prompt
    monkeypatch.setattr(cleanup.sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit, match="--yes"):
        cleanup.confirm("do it", "ledger", assume_yes=False)
    monkeypatch.setattr(cleanup.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "ledgr")
    with pytest.raises(SystemExit, match="Not confirmed"):
        cleanup.confirm("do it", "ledger", assume_yes=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "ledger")
    cleanup.confirm("do it", "ledger", assume_yes=False)
