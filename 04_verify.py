#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Run the auditor's three checks on the whole ledger and write a JSON report.

Uses only the read-only `auditor` database user, read access to the anchor bucket, and the public
key exported by 01_deploy.py (or --public-key). Exits with status 1 if any check fails, including a
chain that has rows but no anchor, or whose newest anchor is older than --max-anchor-age-minutes.
Chains and tables created by 03_tamper_demo.py (demo_*) are skipped unless --include-demo.
Run with --help.
"""
import datetime as dt
import json
import os
import sys

from ledger import audit
from ledger.context import Context, base_parser


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--public-key", help="PEM public key to verify anchors with (default: the file "
                                             "01_deploy.py exported into the results directory)")
    parser.add_argument("--include-demo", action="store_true", help="also check the demo_* tables")
    parser.add_argument("--max-anchor-age-minutes", type=int, default=60,
                        help="fail a chain whose newest anchor is older than this (default 60; the schedule "
                             "anchors every minute). Keep it well below the anchor retention. 0 turns the check off")
    args = parser.parse_args()
    ctx = Context(args)
    with open(args.public_key or ctx.public_key_path(), "rb") as f:
        pem = f.read()
    report = audit.run_checks(ctx.db("auditor"), ctx.client("s3"), ctx.outputs()["AnchorBucket"], pem,
                              skip_prefix=None if args.include_demo else "demo_",
                              max_anchor_age=dt.timedelta(minutes=args.max_anchor_age_minutes)
                              if args.max_anchor_age_minutes > 0 else None)

    print(f"Invalid anchor objects: {len(report['invalid_anchor_objects'])}")
    for chain, c in report["chains"].items():
        status = "OK " if c["self_consistent"] and not c["anchor_problems"] else "BAD"
        print(f"[{status}] chain {chain}: {c['rows_verified']} rows verified, {c['anchors_checked']} anchors checked"
              + (f"; {c['reason']} at seq {c['first_bad_seq']}" if not c["self_consistent"] else ""))
        print(f"       newest anchor {c['newest_anchor_at'] or 'none'} at seq {c['newest_anchored_seq']}; "
              f"{c['rows_after_newest_anchor']} rows after it are not anchored yet")
        for p in c["anchor_problems"]:
            print(f"       {p}")
    for chain in report["missing_chains"]:
        print(f"[BAD] chain {chain} was anchored but no longer exists in the database")
    if "checkpoints_checked" in report:
        print(f"[{'OK ' if not report['checkpoint_problems'] else 'BAD'}] migration checkpoints: "
              f"{report['checkpoints_checked']} checked")
        for p in report["checkpoint_problems"]:
            print(f"       {p}")
    for table, issues in report["reconcile"].items():
        print(f"[{'OK ' if not issues else 'BAD'}] table {table}: {len(issues)} rows differ from their last revision")
        for i in issues[:10]:
            print(f"       {i['pk']}: {i['issue']}")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(args.results_dir, f"verify-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"{'ALL CHECKS PASSED' if report['ok'] else 'CHECKS FAILED'}  (report: {path})")
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
