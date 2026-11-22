# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Independent verification: hash chain, anchor signatures, chain-vs-anchor comparison.

Nothing here talks to AWS or to the database. An auditor can run these functions on exported
history rows, the anchor objects and the public key, without AWS credentials.
"""
import base64
import dataclasses
import datetime as dt
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

GENESIS = "00" * 32


def _j(value):
    return json.dumps(value, ensure_ascii=False)


def canonical(seq, row, prev_hex):
    """Hash input text. Must match ledger.canonical() in sql/01_ledger.sql.

    PostgreSQL prints a jsonb array with ", " between elements and JSON-escaped strings; `doc` is
    the jsonb text exactly as the database returns it (doc::text).
    """
    parts = [str(seq), _j(row["chain_id"]), _j(row["table_name"]), _j(row["pk"]), _j(row["op"]),
             _j(row["changed_by"]), _j(row["changed_at_utc"]), str(row["txid"]),
             row["doc"] if row["doc"] is not None else "null", _j(prev_hex)]
    return "[" + ", ".join(parts) + "]"


def row_hash(seq, row, prev_hex):
    return hashlib.sha256(canonical(seq, row, prev_hex).encode("utf-8")).hexdigest()


@dataclasses.dataclass
class ChainResult:
    ok: bool
    checked: int
    first_bad_seq: int = None
    reason: str = None
    last_hash: str = GENESIS
    hash_at: dict = dataclasses.field(default_factory=dict, repr=False)   # seq -> recomputed hash


def verify_chain(rows):
    """Recompute a chain from genesis. `rows` must be ordered by chain_seq."""
    prev, hash_at = GENESIS, {}
    for i, r in enumerate(rows, 1):
        if r["chain_seq"] != i:
            return ChainResult(False, i - 1, i, "missing sequence number", prev, hash_at)
        if r["prev_hash"] != prev:
            return ChainResult(False, i - 1, i, "prev_hash does not match the previous row", prev, hash_at)
        h = row_hash(i, r, prev)
        if h != r["row_hash"]:
            return ChainResult(False, i - 1, i, "row_hash does not match the row content", prev, hash_at)
        hash_at[i] = prev = h
    return ChainResult(True, len(rows), last_hash=prev, hash_at=hash_at)


def manifest_message(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_signature(public_key_pem, anchor):
    """True if the anchor's signature over its manifest is valid for the public key."""
    key = serialization.load_pem_public_key(public_key_pem)
    try:
        key.verify(base64.b64decode(anchor["signature_b64"]), manifest_message(anchor["manifest"]),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def compare_with_anchors(chain_id, result, anchored):
    """Compare a recomputed chain with every anchored (seq, hash) for it.

    `anchored` is a list of (anchored_at, last_seq, last_hash) taken from valid, signed manifests.
    Returns a list of problems; an empty list means the database agrees with every anchor.
    """
    problems = []
    for at, seq, h in sorted(anchored):
        if seq == 0:
            continue
        if seq > result.checked:
            problems.append(f"{chain_id}: anchor at {at} covers seq {seq}, but only {result.checked} rows verify "
                            "(rows removed, chain rolled back, or an earlier row was altered)")
        elif result.hash_at.get(seq) != h:
            problems.append(f"{chain_id}: hash at seq {seq} differs from the anchor taken at {at} "
                            "(history was rewritten)")
    seqs = [seq for _, seq, _ in sorted(anchored)]
    if any(b < a for a, b in zip(seqs, seqs[1:])):
        problems.append(f"{chain_id}: anchored sequence numbers go backwards over time {seqs}")
    return problems


def anchor_coverage(chain_id, result, anchored, now, max_age=None):
    """How well the signed anchors cover a chain, and whether that is enough.

    Without an anchor that covers it, a row can be rewritten together with the rest of the chain and
    still pass the self-consistency check. Anchors whose Object Lock retention has expired can be
    deleted, so a chain that has rows but no anchor, or only old anchors, must not pass.
    result: ChainResult; anchored: list of (anchored_at ISO 8601, last_seq, last_hash) from valid anchors;
    now: timezone-aware datetime; max_age: datetime.timedelta, or None to skip the age check.
    Returns (coverage, problems). coverage has newest_anchor_at, newest_anchored_seq and
    rows_after_newest_anchor (rows not yet covered by any anchor).
    """
    newest_at = max((dt.datetime.fromisoformat(at) for at, _, _ in anchored), default=None)
    newest_seq = max((seq for _, seq, _ in anchored), default=0)
    coverage = {"newest_anchor_at": newest_at.isoformat() if newest_at else None,
                "newest_anchored_seq": newest_seq,
                "rows_after_newest_anchor": max(result.checked - newest_seq, 0)}
    problems = []
    if result.checked and newest_seq == 0:
        problems.append(f"{chain_id}: {result.checked} rows but no valid anchor covers any of them "
                        "(anchoring never ran for this chain, or its anchors were deleted after their retention "
                        "expired); a rewrite of the whole chain cannot be detected")
    if max_age is not None and newest_at is not None and now - newest_at > max_age:
        problems.append(f"{chain_id}: newest anchor is from {newest_at.isoformat()}, older than the allowed "
                        f"{max_age} (is the anchoring schedule running?)")
    return coverage, problems


def missing_chains(anchored_chain_ids, database_chain_ids):
    """Chains that were anchored at some point but no longer exist in the database."""
    return sorted(set(anchored_chain_ids) - set(database_chain_ids))


def check_checkpoints(db_checkpoints, results, anchored_checkpoints):
    """Migration checkpoints link imported history to a chain position.

    db_checkpoints: rows from ledger.list_checkpoints(); results: chain_id -> ChainResult;
    anchored_checkpoints: checkpoints found in valid, signed manifests.
    Returns a list of problems.
    """
    problems = []
    in_db = {int(c["id"]): c for c in db_checkpoints}
    for c in db_checkpoints:
        r = results.get(c["chain_id"])
        if r is None:
            problems.append(f"checkpoint {c['id']}: chain {c['chain_id']} was not verified")
        elif r.hash_at.get(int(c["chain_seq"])) != c["chain_hash"]:
            problems.append(f"checkpoint {c['id']}: chain {c['chain_id']} hash at seq {c['chain_seq']} does not match")
    for a in anchored_checkpoints:
        c = in_db.get(int(a["id"]))
        if c is None:
            problems.append(f"checkpoint {a['id']} was anchored but is missing from the database")
        elif (c["chain_id"], int(c["chain_seq"]), c["chain_hash"], json.loads(c["source"])) != \
                (a["chain_id"], int(a["chain_seq"]), a["chain_hash"], a["source"]):
            problems.append(f"checkpoint {a['id']} differs from its anchored copy")
    return problems
