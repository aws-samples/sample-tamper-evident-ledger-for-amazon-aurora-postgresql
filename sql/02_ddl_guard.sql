-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
-- SPDX-License-Identifier: MIT-0
--
-- DDL guard. After every DDL statement, an event trigger rolls the statement back if it
--   * changes the ledger's own tables (ledger.history, ledger.migration_checkpoint) in any way:
--     ALTER TABLE (including ALTER COLUMN ... TYPE ... USING, which rewrites rows without firing
--     row triggers), new triggers, rules, policies, constraints or indexes;
--   * changes the primary key of a registered table, or changes the number of enabled ledger
--     triggers on it (dropped, disabled or added);
--   * drops a registered table, or replaces a function in the ledger or ledger_guard schema.
-- Other DDL on business tables (for example ALTER COLUMN ... TYPE ... USING) is allowed: it can
-- change rows without writing history, and the reconcile check then reports those rows.
-- The guard objects belong to the master user, so the schema owner (ledger_owner, the role a
-- migration tool would use) cannot change or drop them. The master user can; that action is
-- visible in Database Activity Streams if you enable it (see README).

CREATE TABLE ledger_guard.ledger_tables (
  tbl           oid PRIMARY KEY,
  tbl_name      text NOT NULL,
  pk_cols       text[] NOT NULL,
  n_triggers    int NOT NULL,
  registered_at timestamptz NOT NULL DEFAULT now(),
  registered_by text NOT NULL DEFAULT session_user
);
REVOKE ALL ON ledger_guard.ledger_tables FROM PUBLIC;
GRANT SELECT ON ledger_guard.ledger_tables TO auditor, ledger_owner;   -- ledger_owner: for ledger.reconcile()

-- Register or re-register a ledger table (master user only). Records its primary key and the
-- number of enabled ledger triggers on it.
CREATE FUNCTION ledger_guard.register_table(p regclass) RETURNS ledger_guard.ledger_tables
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE c text[] := ledger_guard.pk_cols(p); n int; r ledger_guard.ledger_tables;
BEGIN
  IF c IS NULL THEN RAISE EXCEPTION 'ledger guard: % has no primary key', p; END IF;
  SELECT count(*) INTO n FROM pg_trigger tg JOIN pg_proc f ON f.oid = tg.tgfoid
    JOIN pg_namespace ns ON ns.oid = f.pronamespace
    WHERE tg.tgrelid = p AND NOT tg.tgisinternal AND ns.nspname = 'ledger' AND tg.tgenabled IN ('O', 'A');
  IF n = 0 THEN RAISE EXCEPTION 'ledger guard: % has no enabled ledger trigger', p; END IF;
  -- History stores the table name without its schema, so registered names must be unique.
  IF EXISTS (SELECT 1 FROM ledger_guard.ledger_tables g JOIN pg_class o ON o.oid = g.tbl
              WHERE g.tbl <> p AND o.relname = (SELECT relname FROM pg_class WHERE oid = p)) THEN
    RAISE EXCEPTION 'ledger guard: another registered table is already named %', p; END IF;
  INSERT INTO ledger_guard.ledger_tables(tbl, tbl_name, pk_cols, n_triggers) VALUES (p, p::text, c, n)
  ON CONFLICT (tbl) DO UPDATE SET tbl_name = EXCLUDED.tbl_name, pk_cols = EXCLUDED.pk_cols,
                                  n_triggers = EXCLUDED.n_triggers, registered_at = now(),
                                  registered_by = session_user
  RETURNING * INTO r;
  RETURN r;
END $$;
REVOKE ALL ON FUNCTION ledger_guard.register_table(regclass) FROM PUBLIC;

CREATE FUNCTION ledger_guard.check_ddl() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE t record; cur text[]; n int; f text;
BEGIN
  SELECT string_agg(object_identity, ', ') INTO f FROM pg_event_trigger_ddl_commands()
   WHERE object_type IN ('function', 'procedure') AND schema_name IN ('ledger', 'ledger_guard');
  IF f IS NOT NULL THEN
    RAISE EXCEPTION 'ledger guard: changing ledger function(s) % is blocked', f; END IF;
  -- Any DDL whose target is one of the ledger's own tables. Resolve each object to its table.
  SELECT string_agg(DISTINCT d.command_tag || ' ' || d.object_identity, ', ') INTO f
    FROM pg_event_trigger_ddl_commands() d
   WHERE CASE d.classid
           WHEN 'pg_class'::regclass THEN
             (SELECT CASE WHEN c.relkind = 'i' THEN (SELECT indrelid FROM pg_index WHERE indexrelid = c.oid)
                          ELSE c.oid END FROM pg_class c WHERE c.oid = d.objid)
           WHEN 'pg_trigger'::regclass THEN (SELECT tgrelid FROM pg_trigger WHERE oid = d.objid)
           WHEN 'pg_rewrite'::regclass THEN (SELECT ev_class FROM pg_rewrite WHERE oid = d.objid)
           WHEN 'pg_policy'::regclass THEN (SELECT polrelid FROM pg_policy WHERE oid = d.objid)
           WHEN 'pg_constraint'::regclass THEN (SELECT conrelid FROM pg_constraint WHERE oid = d.objid)
         END IN (SELECT tbl FROM ledger_guard.ledger_tables
                  WHERE tbl_name IN ('ledger.history', 'ledger.migration_checkpoint'));
  IF f IS NOT NULL THEN
    RAISE EXCEPTION 'ledger guard: changing the ledger''s own tables is blocked (%)', f; END IF;
  FOR t IN SELECT * FROM ledger_guard.ledger_tables LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = t.tbl) THEN
      RAISE EXCEPTION 'ledger guard: ledger table % would be dropped (blocked)', t.tbl_name; END IF;
    cur := ledger_guard.pk_cols(t.tbl::regclass);
    IF cur IS DISTINCT FROM t.pk_cols THEN
      RAISE EXCEPTION 'ledger guard: primary key of % changed % -> % (blocked)', t.tbl_name, t.pk_cols, cur; END IF;
    SELECT count(*) INTO n FROM pg_trigger tg JOIN pg_proc f2 ON f2.oid = tg.tgfoid
      JOIN pg_namespace ns ON ns.oid = f2.pronamespace
      WHERE tg.tgrelid = t.tbl AND NOT tg.tgisinternal AND ns.nspname = 'ledger' AND tg.tgenabled IN ('O', 'A');
    IF n <> t.n_triggers THEN
      RAISE EXCEPTION 'ledger guard: enabled ledger triggers on % changed (% instead of %, blocked)',
        t.tbl_name, n, t.n_triggers; END IF;
  END LOOP;
END $$;

CREATE EVENT TRIGGER ledger_ddl_guard ON ddl_command_end EXECUTE FUNCTION ledger_guard.check_ddl();
-- ALWAYS: also fires when a session sets session_replication_role = replica.
ALTER EVENT TRIGGER ledger_ddl_guard ENABLE ALWAYS;

SELECT (ledger_guard.register_table('ledger.history')).tbl_name;
SELECT (ledger_guard.register_table('ledger.migration_checkpoint')).tbl_name;
