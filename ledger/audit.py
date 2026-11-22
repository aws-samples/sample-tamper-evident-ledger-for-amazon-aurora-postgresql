# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The auditor's three checks, using the read-only `auditor` database user and read access to S3.

1. Chain self-consistency: recompute every chain from genesis outside the database.
2. Chain vs. anchors: every signed anchor must agree with the recomputed chain, every chain with
   rows must be covered by at least one anchor, and the newest anchor must be recent enough.
3. Reconcile: each row of a registered table must equal its last history revision.
"""
import datetime as dt
import json
from multiprocessing.pool import ThreadPool

from ledger import verify
from ledger.settings import ANCHOR_PREFIX

# Registered tables that hold business rows (history and checkpoints are ledger internals).
REGISTERED_TABLES_SQL = ("SELECT tbl_name FROM ledger_guard.ledger_tables "
                         "WHERE tbl_name NOT IN ('ledger.history', 'ledger.migration_checkpoint') ORDER BY 1")

HISTORY_SQL = """
SELECT chain_seq, chain_id, table_name, pk, op, changed_by,
       to_char(changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS changed_at_utc,
       txid, doc::text AS doc, encode(prev_hash, 'hex') AS prev_hash, encode(row_hash, 'hex') AS row_hash
FROM ledger.history
WHERE chain_id = :chain AND chain_seq > :after
ORDER BY chain_seq
LIMIT 500
"""


def fetch_history(api, chain_id):
    rows, after = [], 0
    while True:
        page = api.query(HISTORY_SQL, {"chain": chain_id, "after": after})
        rows += page
        if len(page) < 500:
            return rows
        after = page[-1]["chain_seq"]


def load_anchors(s3, bucket, public_key_pem, workers=16):
    """Every version of every anchor object, with its signature checked. Returns (valid, invalid).

    Objects are downloaded in parallel: with one anchor a minute there are about 1,440 a day.
    """
    versions = [(v["Key"], v["VersionId"])
                for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=ANCHOR_PREFIX)
                for v in page.get("Versions", [])]

    def check(kv):
        key, vid = kv
        body = s3.get_object(Bucket=bucket, Key=key, VersionId=vid)["Body"].read()
        try:
            anchor = json.loads(body)
        except ValueError:
            return None, f"{key}?versionId={vid}"
        if isinstance(anchor, dict) and "manifest" in anchor and verify.verify_signature(public_key_pem, anchor):
            return anchor, None
        return None, f"{key}?versionId={vid}"

    valid, invalid = [], []
    with ThreadPool(workers) as pool:
        for anchor, bad in pool.imap(check, versions):
            if anchor is not None:
                valid.append(anchor)
            else:
                invalid.append(bad)
    return valid, invalid


def anchored_by_chain(anchors):
    out = {}
    for a in anchors:
        m = a["manifest"]
        for c in m["chains"]:
            out.setdefault(c["chain_id"], []).append((m["anchored_at"], c["last_seq"], c["last_hash"]))
    return out


def run_checks(auditor_api, s3, bucket, public_key_pem, chains=None, tables=None, skip_prefix=None,
               max_anchor_age=None, now=None):
    """Run all three checks.

    chains / tables: check only these (default: every chain and every registered table).
    skip_prefix: ignore chains, tables and missing chains whose name starts with it (for demo tables).
    max_anchor_age: datetime.timedelta; fail a chain whose newest anchor is older (None: no age check).
    now: current time (for tests); default the current UTC time.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    def keep(name):
        return not skip_prefix or not name.startswith(skip_prefix)

    report = {"chains": {}, "invalid_anchor_objects": [], "missing_chains": [], "reconcile": {},
              "checkpoint_problems": []}
    results = {}
    anchors, invalid = load_anchors(s3, bucket, public_key_pem)
    report["invalid_anchor_objects"] = invalid
    anchored = anchored_by_chain(anchors)
    db_chains = [r["chain_id"] for r in auditor_api.query("SELECT chain_id FROM ledger.chain_head ORDER BY 1")]
    for chain_id in sorted(c for c in (chains or db_chains) if keep(c)):
        result = results[chain_id] = verify.verify_chain(fetch_history(auditor_api, chain_id))
        chain_anchors = anchored.get(chain_id, [])
        problems = verify.compare_with_anchors(chain_id, result, chain_anchors)
        coverage, coverage_problems = verify.anchor_coverage(chain_id, result, chain_anchors, now, max_anchor_age)
        report["chains"][chain_id] = {
            "self_consistent": result.ok, "rows_verified": result.checked,
            "first_bad_seq": result.first_bad_seq, "reason": result.reason,
            "anchors_checked": len(chain_anchors), **coverage, "anchor_problems": problems + coverage_problems}
    if chains is None:
        db_cps = auditor_api.query("SELECT * FROM ledger.list_checkpoints()")
        for c in db_cps:   # checkpoints refer to chains that the skip prefix may have excluded
            if c["chain_id"] not in results and c["chain_id"] in db_chains:
                results[c["chain_id"]] = verify.verify_chain(fetch_history(auditor_api, c["chain_id"]))
        # Every distinct anchored copy counts: a later anchor of a forged checkpoint must not hide the original.
        anchored_cps = {json.dumps(c, sort_keys=True): c for a in anchors for c in a["manifest"].get("checkpoints", [])}
        report["checkpoints_checked"] = len(db_cps)
        report["checkpoint_problems"] = verify.check_checkpoints(db_cps, results, list(anchored_cps.values()))
        report["missing_chains"] = [c for c in verify.missing_chains(anchored, db_chains) if keep(c)]
    if tables is None:
        tables = [r["tbl_name"] for r in auditor_api.query(REGISTERED_TABLES_SQL)]
    for t in tables:
        if keep(t.split(".", 1)[-1]):
            report["reconcile"][t] = auditor_api.query(
                "SELECT pk, issue FROM ledger.reconcile(CAST(:t AS regclass))", {"t": t})
    report["ok"] = (not invalid and not report["missing_chains"] and not report["checkpoint_problems"]
                    and all(c["self_consistent"] and not c["anchor_problems"] for c in report["chains"].values())
                    and not any(report["reconcile"].values()))
    return report
