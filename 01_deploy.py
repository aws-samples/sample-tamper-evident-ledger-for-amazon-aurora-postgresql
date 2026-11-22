#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deploy the stack (network, Aurora PostgreSQL with pgAudit, KMS signing key, Object Lock bucket,
database user secrets, IAM roles), the anchoring function, and its schedule (disabled until the
ledger schema exists). Exports the signing public key.

--activity-stream also starts Database Activity Streams and archives it to a second Object Lock
bucket. Activity streams need a provisioned instance class, so the cluster then runs on
db.r6g.large (by default) instead of Aurora Serverless v2 and no longer pauses when idle.
Run with --help.
"""
from ledger import activity, deploy
from ledger.context import Context, base_parser


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--anchor-retention-days", type=int, default=1,
                        help="Object Lock compliance-mode retention for anchors (default 1). Nobody can delete "
                             "an anchor, or the bucket, until it expires.")
    parser.add_argument("--max-capacity", type=int, default=2, help="maximum Aurora capacity units (default 2)")
    parser.add_argument("--engine-version", default="17.11", help="Aurora PostgreSQL version (default 17.11)")
    parser.add_argument("--alarm-email", default="", help="email subscribed to the alarm topic (optional)")
    parser.add_argument("--activity-stream", action="store_true",
                        help="start Database Activity Streams and archive it (uses a provisioned instance class)")
    parser.add_argument("--instance-class", help="instance class (default db.serverless, or db.r6g.large with "
                                                 "--activity-stream)")
    args = parser.parse_args()
    if not 1 <= args.anchor_retention_days <= 36500:
        parser.error("--anchor-retention-days must be between 1 and 36500")
    instance_class = args.instance_class or ("db.r6g.large" if args.activity_stream else "db.serverless")
    if args.activity_stream and instance_class == "db.serverless":
        parser.error("Database Activity Streams is not available on db.serverless; choose a provisioned class")
    ctx = Context(args)
    deploy.deploy_stack(ctx, {"AnchorRetentionDays": args.anchor_retention_days,
                              "MaxCapacity": args.max_capacity, "EngineVersion": args.engine_version,
                              "InstanceClass": instance_class, "AlarmEmail": args.alarm_email,
                              "EnableActivityStreamArchive": str(args.activity_stream).lower()})
    deploy.deploy_function(ctx, deploy.build_zip())
    if args.activity_stream:
        activity.create_archive(ctx, activity.start_stream(ctx))
    deploy.put_schedule(ctx)   # new: disabled until 02_init_ledger.py; existing: state unchanged
    deploy.export_public_key(ctx)
    print("Next: 02_init_ledger.py")


if __name__ == "__main__":
    main()
