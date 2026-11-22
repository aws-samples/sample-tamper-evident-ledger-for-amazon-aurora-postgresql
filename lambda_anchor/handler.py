# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Seal and anchor the ledger (invoked every minute by EventBridge Scheduler).

1. Through the RDS Data API, as the ledger_sealer database user: seal_all() hashes rows of
   asynchronous chains, list_digests() returns the latest (sequence, hash) of every chain, and
   list_checkpoints() returns migration checkpoints.
2. The digests go into one manifest, which AWS KMS signs with an asymmetric key (ECDSA P-256).
   The key policy allows only this function's role to sign.
3. The signed manifest is written to an S3 bucket with Object Lock in compliance mode, so neither
   database administrators nor account administrators can change or delete it before it expires.
"""
import base64
import datetime as dt
import json
import os

import boto3

ALGORITHM = "ECDSA_SHA_256"
_rdsdata = boto3.client("rds-data")
_kms = boto3.client("kms")
_s3 = boto3.client("s3")


def _config():
    names = ("CLUSTER_ARN", "SECRET_ARN", "SIGNING_KEY_ARN", "ANCHOR_BUCKET")
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        raise RuntimeError(f"missing environment variables: {missing}")
    return {n: os.environ[n] for n in names}


def _sql(cfg, sql):
    out = _rdsdata.execute_statement(resourceArn=cfg["CLUSTER_ARN"], secretArn=cfg["SECRET_ARN"],
                                     database="postgres", sql=sql, formatRecordsAs="JSON")
    return json.loads(out.get("formattedRecords") or "[]")


def build_manifest(chains, checkpoints, cluster_arn, now):
    return {
        "anchored_at": now.isoformat(timespec="microseconds"),
        "db_cluster": cluster_arn.rsplit(":", 1)[-1],
        "chains": [{"chain_id": c["chain_id"], "last_seq": int(c["last_seq"]), "last_hash": c["last_hash"]}
                   for c in sorted(chains, key=lambda c: c["chain_id"])],
        # Migration checkpoints (for example the final digest of the ledger the data came from).
        "checkpoints": [{"id": int(c["id"]), "chain_id": c["chain_id"], "chain_seq": int(c["chain_seq"]),
                         "chain_hash": c["chain_hash"], "source": json.loads(c["source"])}
                        for c in sorted(checkpoints, key=lambda c: int(c["id"]))],
    }


def manifest_message(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def anchor_key(now, request_id):
    return f"anchors/{now:%Y/%m/%d/%H%M%S}-{request_id[:8]}.json"


def lambda_handler(_event, context):
    cfg = _config()
    sealed = _sql(cfg, "SELECT ledger.seal_all(20000) AS sealed")[0]["sealed"]
    chains = _sql(cfg, "SELECT chain_id, last_seq, last_hash FROM ledger.list_digests()")
    checkpoints = _sql(cfg, "SELECT id, chain_id, chain_seq, chain_hash, source FROM ledger.list_checkpoints()")
    now = dt.datetime.now(dt.timezone.utc)
    manifest = build_manifest(chains, checkpoints, cfg["CLUSTER_ARN"], now)
    sig = _kms.sign(KeyId=cfg["SIGNING_KEY_ARN"], Message=manifest_message(manifest),
                    MessageType="RAW", SigningAlgorithm=ALGORITHM)
    anchor = {"manifest": manifest, "algorithm": ALGORITHM, "kms_key_arn": sig["KeyId"],
              "signature_b64": base64.b64encode(sig["Signature"]).decode("ascii")}
    key = anchor_key(now, context.aws_request_id)
    put = _s3.put_object(Bucket=cfg["ANCHOR_BUCKET"], Key=key, Body=json.dumps(anchor, indent=2).encode("utf-8"),
                         ContentType="application/json", ChecksumAlgorithm="SHA256")
    result = {"sealed": sealed, "chains": len(chains), "key": key, "version_id": put["VersionId"]}
    print(json.dumps(result))
    return result
