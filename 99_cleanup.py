#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Delete the schedule, the anchoring function and the stack. Run with --help.

Stops Database Activity Streams and its Firehose stream if they exist. The anchor bucket (and the
activity archive bucket) are retained: objects in Object Lock compliance mode cannot be deleted by
anyone until their retention expires, and they keep incurring S3 storage charges until then. Run
again with --empty-anchor-bucket after that.
The KMS signing key is scheduled for deletion (7-day waiting period) with the stack. Keep the
exported public key (results/) if you may need to verify the anchors later.

Both actions ask you to type the stack or bucket name; --yes skips the prompt (for automation).
--empty-anchor-bucket only works on a bucket that this stack created (tag ledger-stack or
aws:cloudformation:stack-name equal to --stack-name) and that has Object Lock enabled.
"""
import sys

from ledger import activity
from ledger.waiting import pause
from ledger.context import Context, base_parser


def delete_schedule_and_function(ctx):
    sch, lam = ctx.client("scheduler"), ctx.client("lambda")
    try:
        sch.delete_schedule(Name=ctx.names.schedule)
        print(f"Schedule {ctx.names.schedule} deleted")
    except sch.exceptions.ResourceNotFoundException:
        pass
    try:
        lam.delete_function(FunctionName=ctx.names.function)
        print(f"Function {ctx.names.function} deleted")
    except lam.exceptions.ResourceNotFoundException:
        pass


def stop_activity_stream(ctx):
    """Stop Database Activity Streams (it deletes its Kinesis stream) and delete the Firehose stream."""
    fh, rds = ctx.client("firehose"), ctx.client("rds")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=activity.firehose_name(ctx.names.stack))
        print("Firehose stream deleted")
    except fh.exceptions.ResourceNotFoundException:
        pass
    try:
        out = ctx.outputs()
    except ctx.client("cloudformation").exceptions.ClientError:
        return
    cluster = rds.describe_db_clusters(DBClusterIdentifier=out["ClusterIdentifier"])["DBClusters"][0]
    if cluster.get("ActivityStreamStatus") in ("started", "starting"):
        rds.stop_activity_stream(ResourceArn=out["ClusterArn"], ApplyImmediately=True)
        print("Stopping Database Activity Streams ...")
    while rds.describe_db_clusters(DBClusterIdentifier=out["ClusterIdentifier"])["DBClusters"][0] \
            .get("ActivityStreamStatus") in ("starting", "stopping"):
        pause(20)


def delete_stack(ctx):
    cfn, rds = ctx.client("cloudformation"), ctx.client("rds")
    try:
        out = ctx.outputs()
    except cfn.exceptions.ClientError:
        print("Stack not found")
        return None
    buckets = [b for b in (out.get("AnchorBucket"), out.get("ActivityArchiveBucket")) if b]
    rds.modify_db_cluster(DBClusterIdentifier=out["ClusterIdentifier"], DeletionProtection=False, ApplyImmediately=True)
    cfn.delete_stack(StackName=ctx.names.stack)
    print(f"Deleting stack {ctx.names.stack} ...")
    cfn.get_waiter("stack_delete_complete").wait(StackName=ctx.names.stack,
                                                 WaiterConfig={"Delay": 15, "MaxAttempts": 160})
    print("Stack deleted")
    return buckets


def confirm(what, name, assume_yes):
    """Ask the user to type `name` before an irreversible action."""
    if assume_yes:
        return
    if not sys.stdin.isatty():
        sys.exit(f"Refusing to {what} without confirmation; run in a terminal or pass --yes.")
    answer = input(f"This will {what}. Type {name!r} to continue: ")
    if answer.strip() != name:
        sys.exit("Not confirmed; nothing was changed.")


def bucket_belongs_to_stack(s3, bucket, stack):
    """Return None if the bucket was created by this stack and has Object Lock, otherwise the reason."""
    try:
        tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    except s3.exceptions.ClientError as exc:
        return f"cannot read its tags ({exc.response['Error']['Code']})"
    if stack not in (tags.get("ledger-stack"), tags.get("aws:cloudformation:stack-name")):
        return f"it is not tagged as part of stack {stack} (tag ledger-stack or aws:cloudformation:stack-name)"
    try:
        lock = s3.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
    except s3.exceptions.ClientError as exc:
        return f"it has no Object Lock configuration ({exc.response['Error']['Code']})"
    if lock.get("ObjectLockEnabled") != "Enabled":
        return "Object Lock is not enabled on it"
    return None


def empty_bucket(ctx, bucket, assume_yes=False):
    s3 = ctx.client("s3")
    reason = bucket_belongs_to_stack(s3, bucket, ctx.names.stack)
    if reason:
        sys.exit(f"Refusing to empty bucket {bucket}: {reason}. Nothing was changed.")
    confirm(f"permanently delete every expired object version in bucket {bucket}, then the bucket", bucket,
            assume_yes)
    locked = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            out = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000], "Quiet": True},
                                    ChecksumAlgorithm="SHA256")
            locked += len(out.get("Errors", []))
    if locked:
        print(f"{locked} object versions are still under Object Lock retention; run again after they expire")
        return
    s3.delete_bucket(Bucket=bucket)
    print(f"Bucket {bucket} deleted")


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--empty-anchor-bucket", metavar="BUCKET",
                        help="delete every anchor version whose retention has expired, then the bucket "
                             "(only a bucket created by this stack)")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = parser.parse_args()
    ctx = Context(args)
    if args.empty_anchor_bucket:
        empty_bucket(ctx, args.empty_anchor_bucket, args.yes)
        return
    confirm(f"delete the anchoring schedule and function, stop Database Activity Streams, turn off deletion "
            f"protection and delete stack {ctx.names.stack} with its database", ctx.names.stack, args.yes)
    delete_schedule_and_function(ctx)
    stop_activity_stream(ctx)
    for bucket in delete_stack(ctx) or []:
        print(f"Retained: bucket {bucket}. Its objects cannot be deleted, and keep incurring S3 storage "
              f"charges, until their Object Lock retention expires. After that, run:\n"
              f"  python 99_cleanup.py --expected-account {ctx.account} --region {ctx.region} "
              f"--stack-name {ctx.names.stack} --empty-anchor-bucket {bucket}")


if __name__ == "__main__":
    main()
