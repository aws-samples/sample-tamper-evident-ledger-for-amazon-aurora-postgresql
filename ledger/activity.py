# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Database Activity Streams: start the stream, archive it with Amazon Data Firehose, read the archive.

Database Activity Streams is controlled through IAM, outside the database: database users, including
the master user, cannot stop it or read its records. It needs a provisioned instance class (it is not
available on Aurora Serverless v2), so 01_deploy.py --activity-stream switches the instance class.
"""
import base64
import json
import re
import zlib

from ledger.waiting import pause

HIGH_RISK = {
    "event_trigger": re.compile(r"\b(ALTER|DROP)\s+EVENT\s+TRIGGER\b", re.I),
    "disable_trigger": re.compile(r"\bDISABLE\s+TRIGGER\b", re.I),
    "replication_role": re.compile(r"\bsession_replication_role\b", re.I),
    "write_history": re.compile(r"\b(UPDATE|DELETE\s+FROM|TRUNCATE)\s+(TABLE\s+)?ledger\.(history|chain_head|migration_checkpoint)\b", re.I),
    "replace_ledger_function": re.compile(r"\bCREATE\s+OR\s+REPLACE\s+(FUNCTION|PROCEDURE)\s+ledger(_guard)?\.", re.I),
    "register_table": re.compile(r"\bledger_guard\.register_table\b", re.I),
    "pgaudit_setting": re.compile(r"\bpgaudit\.", re.I),
}


def firehose_name(stack):
    return f"{stack}-activity-archive"


def start_stream(ctx):
    rds, out = ctx.client("rds"), ctx.outputs()
    cluster = rds.describe_db_clusters(DBClusterIdentifier=out["ClusterIdentifier"])["DBClusters"][0]
    if cluster.get("ActivityStreamStatus") not in ("started", "starting"):
        rds.start_activity_stream(ResourceArn=out["ClusterArn"], Mode="async",
                                  KmsKeyId=out["ActivityStreamKeyArn"], ApplyImmediately=True)
    print("Waiting for Database Activity Streams to start (10 to 20 minutes) ...")
    for _ in range(120):
        cluster = rds.describe_db_clusters(DBClusterIdentifier=out["ClusterIdentifier"])["DBClusters"][0]
        if cluster.get("ActivityStreamStatus") == "started":
            print(f"Activity stream started: {cluster['ActivityStreamKinesisStreamName']}")
            return cluster["ActivityStreamKinesisStreamName"]
        pause(20)
    raise SystemExit("Database Activity Streams did not start within 40 minutes")


def create_archive(ctx, stream_name):
    """Firehose reads the Kinesis stream and writes the encrypted records unchanged to the archive bucket."""
    fh, out = ctx.client("firehose"), ctx.outputs()
    name = firehose_name(ctx.names.stack)
    try:
        fh.describe_delivery_stream(DeliveryStreamName=name)
        print(f"Firehose stream {name} exists")
        return
    except fh.exceptions.ResourceNotFoundException:
        pass
    stream_arn = f"arn:{ctx.partition}:kinesis:{ctx.region}:{ctx.account}:stream/{stream_name}"
    for attempt in range(10):   # a new IAM role can take a few seconds before Firehose can assume it
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name, DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration={"KinesisStreamARN": stream_arn, "RoleARN": out["ActivityFirehoseRoleArn"]},
                ExtendedS3DestinationConfiguration={
                    "RoleARN": out["ActivityFirehoseRoleArn"], "BucketARN": f"arn:{ctx.partition}:s3:::{out['ActivityArchiveBucket']}",
                    "Prefix": "das/", "ErrorOutputPrefix": "das-error/", "CompressionFormat": "UNCOMPRESSED",
                    "BufferingHints": {"SizeInMBs": 5, "IntervalInSeconds": 60}},
                Tags=ctx.names.tags())
            break
        except fh.exceptions.InvalidArgumentException as exc:
            if attempt == 9:
                raise
            print(f"Waiting for the Firehose role ({exc})")
            pause(15)
    print(f"Firehose stream {name} created; records reach the archive about one minute after they occur")


def split_records(body):
    """Firehose concatenates JSON records without separators."""
    dec, i, n, out = json.JSONDecoder(), 0, len(body), []
    while i < n:
        while i < n and body[i].isspace():
            i += 1
        if i >= n:
            break
        rec, i = dec.raw_decode(body, i)
        out.append(rec)
    return out


def decrypt_record(kms, record, resource_id):
    """Decrypt one Database Activity Streams record (envelope: KMS data key + AWS Encryption SDK message)."""
    import aws_encryption_sdk
    from aws_encryption_sdk import CommitmentPolicy
    from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
    from aws_encryption_sdk.internal.crypto import WrappingKey
    from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

    class _DataKey(RawMasterKeyProvider):
        provider_id = "BC"

        def __new__(cls, *args, **kwargs):
            return super(RawMasterKeyProvider, cls).__new__(cls)

        def __init__(self, plain_key):
            RawMasterKeyProvider.__init__(self)
            self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                            wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)

        def _get_raw_key(self, key_id):
            return self.wrapping_key

    data_key = kms.decrypt(CiphertextBlob=base64.b64decode(record["key"]),
                           EncryptionContext={"aws:rds:dbc-id": resource_id})["Plaintext"]
    provider = _DataKey(data_key)
    provider.add_master_key("DataKey")
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    plain, _ = client.decrypt(source=base64.b64decode(record["databaseActivityEvents"]), key_provider=provider)
    return json.loads(zlib.decompress(plain, zlib.MAX_WBITS + 16))


def classify(command_text):
    return sorted(name for name, pattern in HIGH_RISK.items() if pattern.search(command_text or ""))
