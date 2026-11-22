#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""List high-risk statements from the Database Activity Streams archive (needs 01_deploy.py --activity-stream).

Reads the encrypted records that Firehose wrote to the archive bucket, decrypts them with the activity
stream KMS key, and prints statements that turn off the DDL guard, disable triggers, bypass triggers,
write ledger history, replace ledger functions or re-register tables, with user, client address and
time. Writes all matches to a JSON report. Run with --help.
"""
import datetime as dt
import json
import os

from ledger import activity
from ledger.context import Context, base_parser


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--hours", type=float, default=24, help="look at archive objects from the last N hours (default 24)")
    parser.add_argument("--all", action="store_true", help="print every recorded statement, not only high-risk ones")
    args = parser.parse_args()
    ctx = Context(args)
    out = ctx.outputs()
    if "ActivityArchiveBucket" not in out:
        raise SystemExit("The stack has no activity stream archive. Deploy with 01_deploy.py --activity-stream.")
    s3, kms = ctx.client("s3"), ctx.client("kms")
    bucket, resource_id = out["ActivityArchiveBucket"], out["ClusterResourceId"]
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.hours)
    events, objects = [], 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="das/"):
        for obj in page.get("Contents", []):
            if obj["LastModified"] < since:
                continue
            objects += 1
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8")
            for record in activity.split_records(body):
                if record.get("type") != "DatabaseActivityMonitoringRecords":
                    continue
                for e in activity.decrypt_record(kms, record, resource_id).get("databaseActivityEventList", []):
                    if e.get("type") == "heartbeat":
                        continue
                    risk = activity.classify(e.get("commandText"))
                    if risk or args.all:
                        events.append({"logTime": e.get("logTime"), "dbUserName": e.get("dbUserName"),
                                       "remoteHost": e.get("remoteHost"), "command": e.get("command"),
                                       "risk": risk, "commandText": (e.get("commandText") or "")[:2000]})
    events.sort(key=lambda e: e["logTime"] or "")
    for e in events:
        print(f"{e['logTime']}  {e['dbUserName']:<14} {e['remoteHost'] or '-':<15} {','.join(e['risk']) or '-':<24} "
              f"{' '.join(e['commandText'].split())[:110]}")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(args.results_dir, f"activity-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, ensure_ascii=False)
    print(f"{len(events)} {'statements' if args.all else 'high-risk statements'} in {objects} archive objects "
          f"(report: {path})")


if __name__ == "__main__":
    main()
