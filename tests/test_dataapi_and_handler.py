# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Data API wrapper and anchoring function with stubbed AWS clients."""
import base64
import datetime as dt
import decimal
import importlib
import json
import os
import sys
import types

import pytest

from ledger import dataapi

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FakeError(Exception):
    def __init__(self, code, message="x"):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeRdsData:
    def __init__(self, fail_first=0, code="DatabaseResumingException"):
        self.calls, self.fail_first, self.code = [], fail_first, code

    def execute_statement(self, **kw):
        self.calls.append(("exec", kw))
        if self.fail_first:
            self.fail_first -= 1
            raise FakeError(self.code, "boom")
        return {"formattedRecords": json.dumps([{"n": 1}])}

    def begin_transaction(self, **kw):
        self.calls.append(("begin", kw)); return {"transactionId": "tx1"}

    def commit_transaction(self, **kw):
        self.calls.append(("commit", kw))

    def rollback_transaction(self, **kw):
        self.calls.append(("rollback", kw))


def api(client):
    return dataapi.DataApi(client, "arn:cluster", "arn:secret", sleep=lambda _s: None)


def test_param_types():
    assert dataapi._param("a", None)["value"] == {"isNull": True}
    assert dataapi._param("a", True)["value"] == {"booleanValue": True}
    assert dataapi._param("a", 5)["value"] == {"longValue": 5}
    assert dataapi._param("a", "x")["value"] == {"stringValue": "x"}
    d = dataapi._param("a", decimal.Decimal("1.50"))
    assert d["value"] == {"stringValue": "1.50"} and d["typeHint"] == "DECIMAL"


def test_retries_while_cluster_resumes():
    c = FakeRdsData(fail_first=2)
    assert api(c).query("SELECT 1") == [{"n": 1}]
    assert len(c.calls) == 3


@pytest.mark.parametrize("code", ["BadRequestException", "DatabaseErrorException"])
def test_database_errors_become_sql_error(code):
    with pytest.raises(dataapi.SqlError, match="boom"):
        api(FakeRdsData(fail_first=1, code=code)).query("SELECT 1")


def test_transaction_commits_or_rolls_back():
    c = FakeRdsData()
    with api(c).transaction() as tx:
        api(c).query("SELECT 1", tx=tx)
    assert [k for k, _ in c.calls] == ["begin", "exec", "commit"]
    c = FakeRdsData()
    with pytest.raises(RuntimeError):
        with api(c).transaction():
            raise RuntimeError("stop")
    assert [k for k, _ in c.calls] == ["begin", "rollback"]


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for k, v in {"CLUSTER_ARN": "arn:aws:rds:us-east-1:123456789012:cluster:demo-db", "SECRET_ARN": "arn:secret",
                 "SIGNING_KEY_ARN": "arn:key", "ANCHOR_BUCKET": "bucket"}.items():
        monkeypatch.setenv(k, v)
    sys.path.insert(0, os.path.join(ROOT, "lambda_anchor"))
    mod = importlib.import_module("handler")
    sys.path.pop(0)
    calls = {}

    class Rds:
        def execute_statement(self, **kw):
            if "seal_all" in kw["sql"]:
                return {"formattedRecords": json.dumps([{"sealed": 3}])}
            if "list_checkpoints" in kw["sql"]:
                return {"formattedRecords": json.dumps([{"id": 1, "chain_id": "a", "chain_seq": 5, "chain_hash": "cc",
                                                         "source": '{"type": "example"}'}])}
            return {"formattedRecords": json.dumps([{"chain_id": "z", "last_seq": 2, "last_hash": "bb"},
                                                    {"chain_id": "a", "last_seq": 9, "last_hash": "aa"}])}

    class Kms:
        def sign(self, **kw):
            calls["sign"] = kw; return {"Signature": b"sig", "KeyId": "arn:key"}

    class S3:
        def put_object(self, **kw):
            calls["put"] = kw; return {"VersionId": "v1"}

    monkeypatch.setattr(mod, "_rdsdata", Rds())
    monkeypatch.setattr(mod, "_kms", Kms())
    monkeypatch.setattr(mod, "_s3", S3())
    return mod, calls


def test_handler_signs_and_writes_manifest(handler):
    mod, calls = handler
    out = mod.lambda_handler({}, types.SimpleNamespace(aws_request_id="abcdef12-3456"))
    assert out["sealed"] == 3 and out["chains"] == 2 and out["version_id"] == "v1"
    body = json.loads(calls["put"]["Body"])
    m = body["manifest"]
    assert [c["chain_id"] for c in m["chains"]] == ["a", "z"] and m["db_cluster"] == "demo-db"
    assert m["checkpoints"] == [{"id": 1, "chain_id": "a", "chain_seq": 5, "chain_hash": "cc", "source": {"type": "example"}}]
    assert calls["sign"]["Message"] == mod.manifest_message(m) and calls["sign"]["SigningAlgorithm"] == "ECDSA_SHA_256"
    assert base64.b64decode(body["signature_b64"]) == b"sig"
    assert calls["put"]["Bucket"] == "bucket" and calls["put"]["Key"].startswith("anchors/")
    assert calls["put"]["Key"].endswith("-abcdef12.json")


def test_anchor_key_format(handler):
    mod, _ = handler
    now = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
    assert mod.anchor_key(now, "0123456789") == "anchors/2026/01/02/030405-01234567.json"


def test_handler_needs_configuration(handler, monkeypatch):
    mod, _ = handler
    monkeypatch.delenv("ANCHOR_BUCKET")
    with pytest.raises(RuntimeError, match="ANCHOR_BUCKET"):
        mod.lambda_handler({}, types.SimpleNamespace(aws_request_id="x"))


def test_activity_split_and_classify():
    from ledger import activity
    body = '{"type": "a", "x": 1}{"type": "b"}\n {"type": "c"}'
    assert [r["type"] for r in activity.split_records(body)] == ["a", "b", "c"]
    assert activity.classify("ALTER EVENT TRIGGER ledger_ddl_guard DISABLE") == ["event_trigger"]
    assert activity.classify("ALTER TABLE ledger.history DISABLE TRIGGER x") == ["disable_trigger"]
    assert activity.classify("UPDATE ledger.history SET doc = '{}'") == ["write_history"]
    assert activity.classify("SET session_replication_role = replica") == ["replication_role"]
    assert activity.classify("UPDATE ledger.migration_checkpoint SET source = 1") == ["write_history"]
    assert activity.classify("CREATE OR REPLACE FUNCTION ledger.capture_change() ...") == ["replace_ledger_function"]
    assert activity.classify("SELECT * FROM ledger.account") == []
