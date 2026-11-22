#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Record a migration checkpoint: link history imported from another ledger to a chain position.

Use it after migrating data into a ledger table and running its initial baseline. The checkpoint
stores the chain's current (sequence, hash) together with a JSON description of the source, for
example the final digest of an Amazon QLDB ledger (QLDB GetDigest output) and the export IDs used
for the migration. The checkpoint table is append-only, and the anchoring function signs every
checkpoint into each manifest, so later tampering with the imported baseline is detected by
04_verify.py. Run as the cluster master user. Run with --help.
"""
import json

from ledger.context import Context, base_parser


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--chain", required=True, help="chain ID that received the imported history")
    parser.add_argument("--source-file", required=True,
                        help="JSON file describing the source (for example the QLDB digest and export IDs)")
    args = parser.parse_args()
    with open(args.source_file, encoding="utf-8") as f:
        source = json.load(f)
    if not isinstance(source, dict):
        parser.error("--source-file must contain a JSON object")
    ctx = Context(args)
    master = ctx.db("master")
    head = master.query("SELECT last_seq, encode(last_hash, 'hex') AS last_hash FROM ledger.chain_head WHERE chain_id = :c",
                        {"c": args.chain})
    if not head or not head[0]["last_seq"]:
        raise SystemExit(f"Chain {args.chain} has no sealed rows; import the data and run the baseline first")
    if master.scalar("SELECT count(*) AS n FROM ledger.history WHERE chain_id = :c AND row_hash IS NULL", {"c": args.chain}):
        raise SystemExit(f"Chain {args.chain} has unsealed rows; wait for the next anchor (or invoke it) and retry")
    row = master.query(
        "INSERT INTO ledger.migration_checkpoint (chain_id, chain_seq, chain_hash, source) "
        "VALUES (:c, :seq, :h, CAST(:src AS jsonb)) RETURNING id",
        {"c": args.chain, "seq": head[0]["last_seq"], "h": head[0]["last_hash"],
         "src": json.dumps(source, sort_keys=True)})[0]
    print(f"Checkpoint {row['id']}: chain {args.chain} seq {head[0]['last_seq']} hash {head[0]['last_hash'][:16]}...")
    print("Anchoring now:", ctx.invoke_anchor())


if __name__ == "__main__":
    main()
