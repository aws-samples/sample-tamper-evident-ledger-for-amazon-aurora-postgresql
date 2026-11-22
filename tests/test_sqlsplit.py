# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import glob
import os

import pytest

from ledger.sqlsplit import split_statements

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_simple_split_and_comments():
    assert split_statements("SELECT 1; -- note; here\nSELECT 2;\n/* a; b */") == ["SELECT 1", "-- note; here\nSELECT 2"]


def test_semicolons_inside_quotes_and_identifiers():
    s = "SELECT 'a;b', 'it''s;', \"we;ird\"; SELECT 3"
    assert split_statements(s) == ["SELECT 'a;b', 'it''s;', \"we;ird\"", "SELECT 3"]


def test_dollar_quoted_bodies():
    s = ("CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN 1; END $$;\n"
         "DO $q$ BEGIN EXECUTE format($f$SELECT %1$I;$f$, 'x'); END $q$;\nSELECT $1")
    out = split_statements(s)
    assert len(out) == 3 and out[0].endswith("END $$") and out[1].endswith("END $q$") and out[2] == "SELECT $1"


def test_nested_block_comment():
    assert split_statements("/* a /* b; */ c; */ SELECT 1") == ["/* a /* b; */ c; */ SELECT 1"]


@pytest.mark.parametrize("bad", ["SELECT 'oops", "DO $$ BEGIN", "/* never closed"])
def test_unterminated_input_raises(bad):
    with pytest.raises(ValueError):
        split_statements(bad)


def test_repository_sql_files_split_cleanly():
    files = sorted(glob.glob(os.path.join(ROOT, "sql", "*.sql")))
    assert [os.path.basename(f) for f in files] == ["01_ledger.sql", "02_ddl_guard.sql", "03_sample_tables.sql"]
    for f in files:
        statements = split_statements(open(f, encoding="utf-8").read())
        assert statements, f
        for s in statements:
            first = [ln for ln in s.splitlines() if ln.strip() and not ln.strip().startswith("--")][0].split()[0].upper()
            assert first in {"CREATE", "DO", "GRANT", "REVOKE", "SET", "RESET", "ALTER", "SELECT"}, (f, s[:60])
