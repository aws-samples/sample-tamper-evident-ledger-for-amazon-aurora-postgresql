# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SCRAM-SHA-256 password verifier in PostgreSQL's format (RFC 5802 / RFC 7677).

02_init_ledger.py sends this verifier, not the password, to ALTER ROLE ... PASSWORD. Statement text
and bind parameters can be recorded by Database Activity Streams; the verifier is what PostgreSQL
stores in pg_authid and cannot be used to log in.
"""
import base64
import hashlib
import hmac
import os

ITERATIONS = 4096


def verifier(password, salt=None, iterations=ITERATIONS):
    # SASLprep is the identity for printable ASCII; the stack generates alphanumeric passwords.
    if not password or not all(33 <= ord(ch) <= 126 for ch in password):
        raise ValueError("password must be non-empty printable ASCII")
    salt = salt or os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"
