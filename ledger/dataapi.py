# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Small wrapper around the RDS Data API.

The cluster has no network path from your workstation; every SQL statement goes through the Data
API over HTTPS with IAM authorization, as one of the database users whose credentials are in
Secrets Manager. The wrapper retries while an auto-paused Aurora Serverless v2 cluster resumes.
"""
import contextlib
import decimal
import json
import time

RESUME_WAIT_SECONDS = 180
# Error codes the Data API uses for statements PostgreSQL rejected.
SQL_ERROR_CODES = ("DatabaseErrorException", "BadRequestException")


class SqlError(Exception):
    """A statement was rejected by PostgreSQL (the message is the database error)."""


def _param(name, value):
    if value is None:
        v = {"isNull": True}
    elif isinstance(value, bool):
        v = {"booleanValue": value}
    elif isinstance(value, int):
        v = {"longValue": value}
    elif isinstance(value, float):
        v = {"doubleValue": value}
    elif isinstance(value, decimal.Decimal):
        return {"name": name, "value": {"stringValue": str(value)}, "typeHint": "DECIMAL"}
    else:
        v = {"stringValue": str(value)}
    return {"name": name, "value": v}


def _is_resuming(exc):
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    message = str(exc)
    return code == "DatabaseResumingException" or "resuming after being auto-paused" in message


class DataApi:
    def __init__(self, client, cluster_arn, secret_arn, database="postgres", sleep=time.sleep):
        self.client, self.cluster_arn, self.secret_arn, self.database = client, cluster_arn, secret_arn, database
        self._sleep = sleep

    def _call(self, fn, **kw):
        deadline = time.monotonic() + RESUME_WAIT_SECONDS
        while True:
            try:
                return fn(resourceArn=self.cluster_arn, secretArn=self.secret_arn, **kw)
            except Exception as exc:  # botocore raises service-specific subclasses
                if _is_resuming(exc) and time.monotonic() < deadline:
                    self._sleep(5)
                    continue
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in SQL_ERROR_CODES:
                    raise SqlError(getattr(exc, "response", {}).get("Error", {}).get("Message", str(exc))) from exc
                raise

    def query(self, sql, params=None, tx=None):
        """Run one statement; return rows as dicts (empty list for statements without a result set)."""
        kw = {"database": self.database, "sql": sql, "formatRecordsAs": "JSON"}
        if params:
            kw["parameters"] = [_param(k, v) for k, v in params.items()]
        if tx:
            kw["transactionId"] = tx
        out = self._call(self.client.execute_statement, **kw)
        return json.loads(out["formattedRecords"]) if out.get("formattedRecords") else []

    def scalar(self, sql, params=None, tx=None):
        rows = self.query(sql, params, tx)
        return next(iter(rows[0].values())) if rows else None

    @contextlib.contextmanager
    def transaction(self):
        """Pin a session for several statements; commit on success, roll back on any error."""
        tx = self._call(self.client.begin_transaction, database=self.database)["transactionId"]
        try:
            yield tx
        except BaseException:
            with contextlib.suppress(Exception):
                self._call(self.client.rollback_transaction, transactionId=tx)
            raise
        self._call(self.client.commit_transaction, transactionId=tx)

    def run_script(self, statements):
        """Run a list of statements in one transaction."""
        with self.transaction() as tx:
            for sql in statements:
                self.query(sql, tx=tx)
