# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Hash-chain and anchor verification on synthetic data (no AWS, no database)."""
import base64
import copy
import datetime as dt

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ledger import verify


def make_chain(n=9, chain_id="account"):
    rows, prev = [], verify.GENESIS
    for seq in range(1, n + 1):
        r = {"chain_seq": seq, "chain_id": chain_id, "table_name": "account", "pk": f"A{seq:03d}", "op": "I",
             "changed_by": "app_user", "changed_at_utc": f"2026-01-01T00:00:{seq:02d}.000000Z", "txid": 1000 + seq,
             "doc": '{"id": "A%03d", "balance": %d}' % (seq, seq * 100), "prev_hash": prev}
        r["row_hash"] = prev = verify.row_hash(seq, r, prev)
        rows.append(r)
    return rows


def rehash(rows):
    prev = verify.GENESIS
    for r in rows:
        r["prev_hash"] = prev
        r["row_hash"] = prev = verify.row_hash(r["chain_seq"], r, prev)
    return rows


def test_canonical_matches_postgres_jsonb_array_text():
    row = {"chain_id": "acc|1", "table_name": "account", "pk": 'x"y', "op": "U", "changed_by": "app_user",
           "changed_at_utc": "2026-01-01T00:00:00.000001Z", "txid": 42, "doc": '{"a": "\\n", "k": 1.50}'}
    assert verify.canonical(7, row, "ab") == (
        '[7, "acc|1", "account", "x\\"y", "U", "app_user", "2026-01-01T00:00:00.000001Z", 42, '
        '{"a": "\\n", "k": 1.50}, "ab"]')


def test_non_ascii_is_kept_verbatim():
    row = {"chain_id": "c", "table_name": "t", "pk": "中文😀", "op": "I", "changed_by": "u",
           "changed_at_utc": "x", "txid": 1, "doc": None}
    assert '"中文😀"' in verify.canonical(1, row, verify.GENESIS)
    assert ", null, " in verify.canonical(1, row, verify.GENESIS)


def test_intact_chain_verifies():
    res = verify.verify_chain(make_chain())
    assert res.ok and res.checked == 9 and res.hash_at[9] == res.last_hash


def test_edited_row_is_detected():
    rows = make_chain()
    rows[0]["doc"] = '{"id": "A001", "balance": 999999}'
    res = verify.verify_chain(rows)
    assert not res.ok and res.first_bad_seq == 1 and "row_hash" in res.reason


def test_missing_row_is_detected():
    rows = make_chain()
    del rows[3]
    res = verify.verify_chain(rows)
    assert not res.ok and res.first_bad_seq == 4 and "sequence" in res.reason


def anchors_for(rows, at="2026-01-01T00:01:00"):
    res = verify.verify_chain(rows)
    return [(at, res.checked, res.last_hash)]


def test_full_rewrite_passes_self_check_but_not_anchor():
    rows = make_chain()
    anchored = anchors_for(rows)
    rows[0]["doc"] = '{"id": "A001", "balance": 999999}'
    rehash(rows)
    res = verify.verify_chain(rows)
    assert res.ok
    problems = verify.compare_with_anchors("account", res, anchored)
    assert problems and "rewritten" in problems[0]


def test_truncated_tail_is_detected_by_anchor():
    rows = make_chain()
    anchored = anchors_for(rows)
    res = verify.verify_chain(rows[:6])
    assert res.ok
    assert "only 6 rows verify" in verify.compare_with_anchors("account", res, anchored)[0]


def test_rollback_to_older_state_is_detected():
    rows = make_chain()
    anchored = anchors_for(rows[:3], "t1") + anchors_for(rows, "t2")
    res = verify.verify_chain(rows[:3])          # database restored from an old snapshot
    problems = verify.compare_with_anchors("account", res, anchored)
    assert len(problems) == 1 and "seq 9" in problems[0]


def test_later_rewrite_is_caught_by_earlier_anchor():
    """Even if a later anchor captured the rewritten state, an earlier anchor disagrees with it."""
    rows = make_chain()
    honest = anchors_for(rows, "t1")
    rows[0]["doc"] = '{"id": "A001", "balance": 1}'
    rehash(rows)
    tampered = anchors_for(rows, "t2")
    res = verify.verify_chain(rows)
    problems = verify.compare_with_anchors("account", res, honest + tampered)
    assert len(problems) == 1 and "t1" in problems[0]


def test_anchored_sequence_going_backwards_is_reported():
    rows = make_chain()
    res = verify.verify_chain(rows)
    anchored = [("t1", 9, res.hash_at[9]), ("t2", 5, res.hash_at[5])]
    assert any("backwards" in p for p in verify.compare_with_anchors("account", res, anchored))


def test_missing_chains():
    assert verify.missing_chains(["a", "b", "c"], ["a", "c"]) == ["b"]


def signed_anchor(key, manifest):
    sig = key.sign(verify.manifest_message(manifest), ec.ECDSA(hashes.SHA256()))
    return {"manifest": manifest, "signature_b64": base64.b64encode(sig).decode()}


def pem_of(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_signature_verification():
    key = ec.generate_private_key(ec.SECP256R1())
    manifest = {"anchored_at": "t", "db_cluster": "c", "chains": [{"chain_id": "a", "last_seq": 9, "last_hash": "ff"}]}
    anchor = signed_anchor(key, manifest)
    assert verify.verify_signature(pem_of(key), anchor)
    forged = copy.deepcopy(anchor)
    forged["manifest"]["chains"][0]["last_seq"] = 6
    assert not verify.verify_signature(pem_of(key), forged)
    assert not verify.verify_signature(pem_of(ec.generate_private_key(ec.SECP256R1())), anchor)
    anchor["signature_b64"] = "not base64!"
    assert not verify.verify_signature(pem_of(key), anchor)


def test_manifest_message_is_key_order_independent():
    assert verify.manifest_message({"b": 1, "a": [1, 2]}) == verify.manifest_message({"a": [1, 2], "b": 1}) \
        == b'{"a":[1,2],"b":1}'


def checkpoint(seq, h, cid=1, chain="account", source='{"type": "example"}'):
    return {"id": cid, "chain_id": chain, "chain_seq": seq, "chain_hash": h, "source": source}


def test_checkpoint_matches_chain_and_anchor():
    res = verify.verify_chain(make_chain())
    cp = checkpoint(5, res.hash_at[5])
    anchored = dict(cp, source={"type": "example"})
    assert verify.check_checkpoints([cp], {"account": res}, [anchored]) == []


def test_checkpoint_problems():
    res = verify.verify_chain(make_chain())
    good = checkpoint(5, res.hash_at[5])
    anchored = dict(good, source={"type": "example"})
    assert "does not match" in verify.check_checkpoints([checkpoint(5, "00")], {"account": res}, [])[0]
    assert "missing" in verify.check_checkpoints([], {"account": res}, [anchored])[0]
    changed = dict(good, source='{"type": "forged"}')
    assert "differs" in verify.check_checkpoints([changed], {"account": res}, [anchored])[0]


def test_forged_checkpoint_is_caught_by_its_earlier_anchor():
    res = verify.verify_chain(make_chain())
    honest = dict(checkpoint(5, res.hash_at[5]), source={"type": "example"})
    forged_db = checkpoint(5, res.hash_at[5], source='{"type": "forged"}')
    later_anchor = dict(forged_db, source={"type": "forged"})
    problems = verify.check_checkpoints([forged_db], {"account": res}, [honest, later_anchor])
    assert len(problems) == 1 and "differs" in problems[0]


NOW = dt.datetime(2026, 1, 2, 12, 0, tzinfo=dt.timezone.utc)


def test_chain_with_rows_but_no_anchor_fails():
    """A full rewrite of an unanchored chain passes the self-check, so the chain must not pass."""
    rows = make_chain()
    rows[0]["doc"] = '{"id": "A001", "balance": 999999}'
    res = verify.verify_chain(rehash(rows))
    assert res.ok
    coverage, problems = verify.anchor_coverage("account", res, [], NOW, dt.timedelta(hours=1))
    assert len(problems) == 1 and "no valid anchor" in problems[0]
    assert coverage == {"newest_anchor_at": None, "newest_anchored_seq": 0, "rows_after_newest_anchor": 9}


def test_anchor_that_only_covers_an_empty_chain_does_not_count():
    res = verify.verify_chain(make_chain())
    anchored = [("2026-01-02T11:59:00+00:00", 0, verify.GENESIS)]
    _, problems = verify.anchor_coverage("account", res, anchored, NOW, None)
    assert len(problems) == 1 and "no valid anchor" in problems[0]


def test_empty_chain_without_anchor_is_fine():
    _, problems = verify.anchor_coverage("account", verify.verify_chain([]), [], NOW, dt.timedelta(hours=1))
    assert problems == []


def test_recent_anchor_reports_unanchored_tail():
    rows = make_chain()
    res = verify.verify_chain(rows)
    anchored = [("2026-01-02T11:00:00+00:00", 3, res.hash_at[3]), ("2026-01-02T11:59:00+00:00", 6, res.hash_at[6])]
    coverage, problems = verify.anchor_coverage("account", res, anchored, NOW, dt.timedelta(hours=1))
    assert problems == []
    assert coverage == {"newest_anchor_at": "2026-01-02T11:59:00+00:00", "newest_anchored_seq": 6,
                        "rows_after_newest_anchor": 3}


def test_stale_anchor_fails_only_with_an_age_limit():
    rows = make_chain()
    res = verify.verify_chain(rows)
    anchored = [("2026-01-01T00:00:00+00:00", 9, res.hash_at[9])]
    _, problems = verify.anchor_coverage("account", res, anchored, NOW, dt.timedelta(hours=1))
    assert len(problems) == 1 and "older than the allowed" in problems[0]
    assert verify.anchor_coverage("account", res, anchored, NOW, None)[1] == []
