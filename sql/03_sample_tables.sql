-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
-- SPDX-License-Identifier: MIT-0
--
-- Two example ledger tables. Replace them with your own; the pattern is the same:
-- create the table with a primary key, attach a capture trigger, grant the application, register.

SET LOCAL ROLE ledger_owner;

-- Synchronous chain: every committed change is hashed before the transaction commits.
CREATE TABLE ledger.account (
  id         text PRIMARY KEY,
  owner      text NOT NULL,
  balance    numeric(20, 2) NOT NULL,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER account_ledger AFTER INSERT OR UPDATE OR DELETE ON ledger.account
  FOR EACH ROW EXECUTE FUNCTION ledger.capture_change('account');

-- Asynchronous chain with a composite key: rows are hashed by the anchoring function (seal_all).
CREATE TABLE ledger.position (
  acct     text NOT NULL,
  symbol   text NOT NULL,
  quantity numeric(20, 4) NOT NULL,
  PRIMARY KEY (acct, symbol)
);
CREATE TRIGGER position_ledger AFTER INSERT OR UPDATE OR DELETE ON ledger.position
  FOR EACH ROW EXECUTE FUNCTION ledger.capture_change_async('position');

GRANT SELECT, INSERT, UPDATE, DELETE ON ledger.account, ledger.position TO app_user;
RESET ROLE;

SELECT (ledger_guard.register_table('ledger.account')).tbl_name;
SELECT (ledger_guard.register_table('ledger.position')).tbl_name;
