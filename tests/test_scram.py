# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import base64
import hashlib
import hmac

import pytest

from ledger.scram import verifier


def test_matches_rfc7677_test_vector():
    # RFC 7677 section 3: user "user", password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==, 4096 iterations.
    v = verifier("pencil", salt=base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="))
    salted = hashlib.pbkdf2_hmac("sha256", b"pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096)
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    # The RFC's server signature for its exchange is derived from this ServerKey.
    auth = (b"n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
            b"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
    assert base64.b64encode(hmac.new(server_key, auth, hashlib.sha256).digest()) == b"6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    assert v.startswith("SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$") and v.endswith(base64.b64encode(server_key).decode())


def test_random_salt_and_no_password_in_output():
    pw = "Abc" + "x" * 29
    a, b = verifier(pw), verifier(pw)
    assert a != b and pw not in a


@pytest.mark.parametrize("bad", ["", "with space", "naïve"])
def test_rejects_non_ascii_or_empty(bad):
    with pytest.raises(ValueError):
        verifier(bad)
