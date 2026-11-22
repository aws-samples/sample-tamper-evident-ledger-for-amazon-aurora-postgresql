#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Create the ledger schema, the DDL guard and two example tables; set the database user passwords
from Secrets Manager; write example transactions as the application user; enable the anchoring
schedule and anchor once. Run with --help.
"""
import os
from decimal import Decimal

from ledger import deploy
from ledger.context import REPO_ROOT, Context, base_parser
from ledger.scram import verifier
from ledger.settings import DB_USERS
from ledger.sqlsplit import split_statements

SQL_FILES = ("01_ledger.sql", "02_ddl_guard.sql", "03_sample_tables.sql")
# Role names are fixed identifiers from DB_USERS, never user input. The database receives a SCRAM-SHA-256
# verifier, never the password: bind parameters are visible to Database Activity Streams. The verifier
# travels as a bind parameter into a transaction-local setting, so it is not part of any SQL text.
SET_PASSWORD = (  # nosec B105 - SQL template, the password is a bind parameter
    "DO $$ BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L', '{role}', "
    "current_setting('ledger_sample.secret')); END $$")
RESET = ["DROP EVENT TRIGGER IF EXISTS ledger_ddl_guard",
         "DROP SCHEMA IF EXISTS ledger CASCADE",
         "DROP SCHEMA IF EXISTS ledger_guard CASCADE"]


def schema_statements():
    out = []
    for name in SQL_FILES:
        with open(os.path.join(REPO_ROOT, "sql", name), encoding="utf-8") as f:
            out += split_statements(f.read())
    return out


def set_passwords(ctx, master):
    for role in DB_USERS:
        with master.transaction() as tx:
            master.query("SELECT set_config('ledger_sample.secret', :v, true)",
                         {"v": verifier(ctx.secret_password(role))}, tx)
            master.query(SET_PASSWORD.format(role=role), tx=tx)  # nosec B608 - role is a fixed identifier
    print(f"Passwords set for {', '.join(DB_USERS)}")


def seed(app):
    """Example business activity: open accounts, a transfer, an attribute change, a closure, positions."""
    with app.transaction() as tx:
        for i in range(1, 6):
            app.query("INSERT INTO ledger.account (id, owner, balance, attrs) VALUES (:id, :owner, :bal, CAST(:attrs AS jsonb))",
                      {"id": f"A{i:03d}", "owner": f"Customer {i}", "bal": Decimal(1000 * i),
                       "attrs": '{"tier": "%s"}' % ("gold" if i % 2 else "silver")}, tx)
    with app.transaction() as tx:   # a transfer is two updates in one transaction
        app.query("UPDATE ledger.account SET balance = balance - 300, updated_at = now() WHERE id = 'A001'", tx=tx)
        app.query("UPDATE ledger.account SET balance = balance + 300, updated_at = now() WHERE id = 'A002'", tx=tx)
    app.query("""UPDATE ledger.account SET attrs = attrs || '{"kyc": "verified"}' WHERE id = 'A003'""")
    app.query("DELETE FROM ledger.account WHERE id = 'A005'")
    for acct, sym, qty in (("A001", "AAPL", 10), ("A001", "MSFT", 5), ("A002", "AAPL", 7)):
        app.query("INSERT INTO ledger.position VALUES (:a, :s, :q)", {"a": acct, "s": sym, "q": Decimal(qty)})
    app.query("UPDATE ledger.position SET quantity = quantity + 1 WHERE acct = 'A001' AND symbol = 'AAPL'")
    print("Example transactions written as app_user")


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--reset", action="store_true",
                        help="drop and recreate the ledger (all history is lost; existing anchors in S3 will no "
                             "longer match and 04_verify.py will report the chains as missing)")
    parser.add_argument("--no-seed", action="store_true", help="do not write the example transactions")
    args = parser.parse_args()
    ctx = Context(args)
    master = ctx.db("master")
    exists = master.scalar("SELECT to_regnamespace('ledger') IS NOT NULL AS exists")
    if exists and args.reset:
        master.run_script(RESET)
        print("Existing ledger dropped")
        exists = False
    if exists:
        print("Ledger schema already exists; skipping schema creation (use --reset to recreate)")
    else:
        statements = schema_statements()
        master.run_script(statements)
        print(f"Ledger schema, DDL guard and example tables created ({len(statements)} statements)")
    set_passwords(ctx, master)
    if not args.no_seed and not master.scalar("SELECT count(*) AS n FROM ledger.history"):
        seed(ctx.db("app_user"))
    deploy.put_schedule(ctx, enabled=True)
    print("Anchoring once now:", ctx.invoke_anchor())
    print("Next: 03_tamper_demo.py, then 04_verify.py")


if __name__ == "__main__":
    main()
