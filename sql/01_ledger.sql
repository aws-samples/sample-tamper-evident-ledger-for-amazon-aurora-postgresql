-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
-- SPDX-License-Identifier: MIT-0
--
-- Tamper-evident ledger: append-only history table with a per-row SHA-256 hash chain.
-- Run as the cluster master user, in one transaction (02_init_ledger.py does this).
-- Role switches use SET LOCAL so nothing leaks into a pooled Data API session.

-- pgAudit (loaded by the cluster parameter group) writes DDL and role changes to the PostgreSQL
-- log, which the cluster exports to CloudWatch Logs.
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- ---------- Roles (passwords are set later from Secrets Manager) ----------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ledger_owner')  THEN CREATE ROLE ledger_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user')      THEN CREATE ROLE app_user LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor')       THEN CREATE ROLE auditor LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ledger_sealer') THEN CREATE ROLE ledger_sealer LOGIN; END IF;
END $$;
GRANT ledger_owner TO CURRENT_USER;

-- ---------- Primary-key lookup (lives in ledger_guard, owned by the master user) ----------
CREATE SCHEMA ledger_guard;
REVOKE ALL ON SCHEMA ledger_guard FROM PUBLIC;
GRANT USAGE ON SCHEMA ledger_guard TO PUBLIC;

-- Primary-key columns in key order. PL/pgSQL so the plan is cached across calls.
CREATE FUNCTION ledger_guard.pk_cols(p regclass) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
DECLARE c text[];
BEGIN
  SELECT array_agg(a.attname::text ORDER BY k.ord) INTO c
  FROM pg_index i
  CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
  WHERE i.indrelid = p AND i.indisprimary;
  RETURN c;
END $$;
GRANT EXECUTE ON FUNCTION ledger_guard.pk_cols(regclass) TO PUBLIC;

CREATE SCHEMA ledger AUTHORIZATION ledger_owner;
SET LOCAL ROLE ledger_owner;
SET LOCAL search_path = ledger;

-- One row per hash chain: latest sequence number and hash.
CREATE TABLE chain_head (
  chain_id  text PRIMARY KEY,
  mode      text NOT NULL DEFAULT 'sync' CHECK (mode IN ('sync', 'async')),
  last_seq  bigint NOT NULL DEFAULT 0,
  last_hash bytea  NOT NULL DEFAULT decode(repeat('00', 32), 'hex')   -- genesis: 32 zero bytes
);

-- Append-only history. One row per insert, update or delete on a ledger table.
CREATE TABLE history (
  id         bigserial PRIMARY KEY,
  chain_id   text        NOT NULL,
  chain_seq  bigint,                         -- assigned at write time (sync) or when sealed (async)
  table_name text        NOT NULL,
  pk         text        NOT NULL,           -- single key: the value; composite key: JSON array text
  op         char(1)     NOT NULL CHECK (op IN ('I', 'U', 'D')),
  doc        jsonb,                          -- full row after the change (before it, for deletes)
  changed_by text        NOT NULL,
  changed_at timestamptz NOT NULL,
  txid       bigint      NOT NULL,
  prev_hash  bytea,
  row_hash   bytea,
  UNIQUE (chain_id, chain_seq)
);
CREATE INDEX history_pk_idx ON history (table_name, pk, id);
CREATE INDEX history_unsealed_idx ON history (chain_id, id) WHERE row_hash IS NULL;

-- Hash input. Independent verifiers must build exactly the same text (see ledger/verify.py):
-- jsonb array [chain_seq, chain_id, table_name, pk, op, changed_by, changed_at UTC, txid, doc, prev_hash hex]
CREATE FUNCTION canonical(h history, p_seq bigint, p_prev bytea) RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT jsonb_build_array(p_seq, h.chain_id, h.table_name, h.pk, h.op, h.changed_by,
                           to_char(h.changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                           h.txid, h.doc, encode(p_prev, 'hex'))::text
$$;

-- Single key: the value as text. Composite key: JSON array text such as ["A1", "AAPL"]. No key: NULL.
CREATE FUNCTION pk_text(p regclass, r jsonb) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
DECLARE c text[] := ledger_guard.pk_cols(p);
BEGIN
  IF c IS NULL THEN RETURN NULL; END IF;
  IF array_length(c, 1) = 1 THEN RETURN r ->> c[1]; END IF;
  RETURN (SELECT jsonb_agg(r -> x ORDER BY o)::text FROM unnest(c) WITH ORDINALITY AS u(x, o));
END $$;

-- Row trigger for synchronous chains: lock the chain head, hash, append.
-- TG_ARGV[0] = chain name; TG_ARGV[1] = optional shard count (>1 splits the table into N chains by key).
CREATE FUNCTION capture_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
DECLARE
  v_row   jsonb := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  v_pk    text  := ledger.pk_text(TG_RELID, v_row);
  v_shard int   := coalesce(nullif(TG_ARGV[1], '')::int, 1);
  v_chain text;
  v_mode  text; v_seq bigint; v_prev bytea; h history;
BEGIN
  IF v_pk IS NULL THEN
    RAISE EXCEPTION 'ledger: table % has no primary key, change rejected', TG_TABLE_NAME;
  END IF;
  v_chain := TG_ARGV[0] || CASE WHEN v_shard > 1 THEN '-' || (abs(hashtext(v_pk)) % v_shard)::text ELSE '' END;
  h.chain_id := v_chain; h.table_name := TG_TABLE_NAME; h.pk := v_pk; h.op := left(TG_OP, 1);
  h.doc := v_row; h.changed_by := session_user; h.changed_at := clock_timestamp(); h.txid := txid_current();

  SELECT mode, last_seq, last_hash INTO v_mode, v_seq, v_prev FROM chain_head WHERE chain_id = v_chain FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO chain_head(chain_id) VALUES (v_chain) ON CONFLICT DO NOTHING;
    SELECT mode, last_seq, last_hash INTO v_mode, v_seq, v_prev FROM chain_head WHERE chain_id = v_chain FOR UPDATE;
  END IF;
  IF v_mode = 'sync' THEN
    h.chain_seq := v_seq + 1; h.prev_hash := v_prev;
    h.row_hash  := sha256(convert_to(canonical(h, h.chain_seq, v_prev), 'UTF8'));
    UPDATE chain_head SET last_seq = h.chain_seq, last_hash = h.row_hash WHERE chain_id = v_chain;
  END IF;
  INSERT INTO history (chain_id, chain_seq, table_name, pk, op, doc, changed_by, changed_at, txid, prev_hash, row_hash)
  VALUES (h.chain_id, h.chain_seq, h.table_name, h.pk, h.op, h.doc, h.changed_by, h.changed_at, h.txid, h.prev_hash, h.row_hash);
  RETURN NULL;
END $$;

-- Row trigger for asynchronous chains: append only, no lock. seal() hashes later.
CREATE FUNCTION capture_change_async() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
DECLARE
  v_row jsonb := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  v_pk  text  := ledger.pk_text(TG_RELID, v_row);
BEGIN
  IF v_pk IS NULL THEN
    RAISE EXCEPTION 'ledger: table % has no primary key, change rejected', TG_TABLE_NAME;
  END IF;
  INSERT INTO history (chain_id, table_name, pk, op, doc, changed_by, changed_at, txid)
  VALUES (TG_ARGV[0], TG_TABLE_NAME, v_pk, left(TG_OP, 1), v_row, session_user, clock_timestamp(), txid_current());
  RETURN NULL;
END $$;

-- Assign sequence numbers and hashes to unsealed rows of one chain, in write order.
CREATE FUNCTION seal(p_chain text, p_batch int DEFAULT 10000) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
DECLARE v_seq bigint; v_prev bytea; r history; n int := 0;
BEGIN
  SELECT last_seq, last_hash INTO v_seq, v_prev FROM chain_head WHERE chain_id = p_chain FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO chain_head(chain_id, mode) VALUES (p_chain, 'async');
    v_seq := 0; v_prev := decode(repeat('00', 32), 'hex');
  END IF;
  FOR r IN SELECT * FROM history WHERE chain_id = p_chain AND row_hash IS NULL ORDER BY id LIMIT p_batch LOOP
    v_seq := v_seq + 1;
    r.row_hash := sha256(convert_to(canonical(r, v_seq, v_prev), 'UTF8'));
    UPDATE history SET chain_seq = v_seq, prev_hash = v_prev, row_hash = r.row_hash WHERE id = r.id;
    v_prev := r.row_hash; n := n + 1;
  END LOOP;
  UPDATE chain_head SET last_seq = v_seq, last_hash = v_prev WHERE chain_id = p_chain;
  RETURN n;
END $$;

CREATE FUNCTION seal_all(p_batch int DEFAULT 10000) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
DECLARE c text; n int := 0;
BEGIN
  FOR c IN SELECT DISTINCT chain_id FROM history WHERE row_hash IS NULL LOOP
    n := n + seal(c, p_batch);
  END LOOP;
  RETURN n;
END $$;

-- History is append-only. The only allowed update fills in the hash of an unsealed row.
CREATE FUNCTION history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.row_hash IS NULL AND NEW.row_hash IS NOT NULL
     AND (OLD.chain_id, OLD.table_name, OLD.pk, OLD.op, OLD.doc, OLD.changed_by, OLD.changed_at, OLD.txid)
     IS NOT DISTINCT FROM (NEW.chain_id, NEW.table_name, NEW.pk, NEW.op, NEW.doc, NEW.changed_by, NEW.changed_at, NEW.txid)
  THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'ledger.history is append-only (% blocked)', TG_OP;
END $$;
CREATE TRIGGER history_no_update_delete BEFORE UPDATE OR DELETE ON history FOR EACH ROW EXECUTE FUNCTION history_guard();
CREATE TRIGGER history_no_truncate BEFORE TRUNCATE ON history FOR EACH STATEMENT EXECUTE FUNCTION history_guard();

-- In-database chain check (the independent check is ledger/verify.py).
CREATE FUNCTION verify_chain(p_chain text, p_upto bigint DEFAULT NULL)
RETURNS TABLE (ok boolean, checked bigint, first_bad_seq bigint, reason text, last_hash text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
DECLARE r history; v_prev bytea := decode(repeat('00', 32), 'hex'); v_exp bigint := 0; v_h bytea;
BEGIN
  FOR r IN SELECT * FROM history WHERE chain_id = p_chain AND chain_seq IS NOT NULL
           AND (p_upto IS NULL OR chain_seq <= p_upto) ORDER BY chain_seq LOOP
    v_exp := v_exp + 1;
    IF r.chain_seq <> v_exp THEN
      RETURN QUERY SELECT false, v_exp - 1, v_exp, 'missing seq', encode(v_prev, 'hex'); RETURN; END IF;
    IF r.prev_hash IS DISTINCT FROM v_prev THEN
      RETURN QUERY SELECT false, v_exp - 1, r.chain_seq, 'prev_hash mismatch', encode(v_prev, 'hex'); RETURN; END IF;
    v_h := sha256(convert_to(canonical(r, r.chain_seq, v_prev), 'UTF8'));
    IF v_h IS DISTINCT FROM r.row_hash THEN
      RETURN QUERY SELECT false, v_exp - 1, r.chain_seq, 'row_hash mismatch', encode(v_prev, 'hex'); RETURN; END IF;
    v_prev := v_h;
  END LOOP;
  RETURN QUERY SELECT true, v_exp, NULL::bigint, NULL::text, encode(v_prev, 'hex');
END $$;

-- Migration checkpoints: links history imported from another ledger (for example the final digest of
-- an Amazon QLDB ledger) to the chain position reached by the initial baseline. Append-only; the
-- anchoring function signs every checkpoint into each manifest. Written by 05_import_checkpoint.py.
CREATE TABLE migration_checkpoint (
  id          bigserial PRIMARY KEY,
  chain_id    text        NOT NULL,
  chain_seq   bigint      NOT NULL,
  chain_hash  text        NOT NULL,
  source      jsonb       NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  recorded_by text        NOT NULL DEFAULT session_user
);
CREATE FUNCTION checkpoint_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ledger.migration_checkpoint is append-only (% blocked)', TG_OP;
END $$;
CREATE TRIGGER checkpoint_no_update_delete BEFORE UPDATE OR DELETE ON migration_checkpoint
  FOR EACH ROW EXECUTE FUNCTION checkpoint_guard();
CREATE TRIGGER checkpoint_no_truncate BEFORE TRUNCATE ON migration_checkpoint
  FOR EACH STATEMENT EXECUTE FUNCTION checkpoint_guard();

CREATE FUNCTION list_checkpoints() RETURNS TABLE (id bigint, chain_id text, chain_seq bigint, chain_hash text,
                                                  source text, recorded_at text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
  SELECT id, chain_id, chain_seq, chain_hash, source::text,
         to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  FROM migration_checkpoint ORDER BY id
$$;

-- Digests of all chains, for the anchoring function.
CREATE FUNCTION list_digests() RETURNS TABLE (chain_id text, mode text, last_seq bigint, last_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
  SELECT chain_id, mode, last_seq, encode(last_hash, 'hex') FROM chain_head ORDER BY chain_id
$$;

-- Current table state vs. the last history revision of each row. Finds changes made with the
-- capture trigger bypassed (for example session_replication_role = replica).
-- Only registered business tables (ledger_guard.ledger_tables) are accepted, so the auditor cannot use
-- this function to read other tables. History records the table name without its schema;
-- register_table() therefore keeps registered table names unique, and this function checks it again.
CREATE FUNCTION reconcile(p_table regclass)
RETURNS TABLE (pk text, issue text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ledger, pg_temp AS $$
DECLARE v_name text := (SELECT relname FROM pg_catalog.pg_class WHERE oid = p_table);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ledger_guard.ledger_tables WHERE tbl = p_table
                  AND tbl_name NOT IN ('ledger.history', 'ledger.migration_checkpoint')) THEN
    RAISE EXCEPTION 'ledger: % is not a registered ledger table', p_table; END IF;
  IF (SELECT count(*) FROM ledger_guard.ledger_tables g JOIN pg_catalog.pg_class c ON c.oid = g.tbl
       WHERE c.relname = v_name) > 1 THEN
    RAISE EXCEPTION 'ledger: more than one registered table is named %', v_name; END IF;
  RETURN QUERY EXECUTE format($q$
    WITH last AS (
      SELECT DISTINCT ON (h.pk) h.pk, h.op, h.doc FROM ledger.history h
      WHERE h.table_name = %L ORDER BY h.pk, h.id DESC),
    cur AS (SELECT ledger.pk_text(%L::regclass, to_jsonb(t)) AS pk, to_jsonb(t) AS doc FROM %s t)
    SELECT coalesce(c.pk, l.pk),
           CASE WHEN l.pk IS NULL THEN 'row has no history'
                WHEN c.pk IS NULL AND l.op <> 'D' THEN 'row missing but not deleted in history'
                WHEN c.pk IS NOT NULL AND l.op = 'D' THEN 'row exists but deleted in history'
                ELSE 'current state differs from last history revision' END
    FROM cur c FULL JOIN last l ON l.pk = c.pk
    WHERE l.pk IS NULL OR (c.pk IS NULL AND l.op <> 'D') OR (c.pk IS NOT NULL AND l.op = 'D')
       OR (c.pk IS NOT NULL AND c.doc IS DISTINCT FROM l.doc)$q$,
    v_name, p_table::text, p_table);
END $$;

-- Re-baseline after DDL, or when an existing table joins the ledger: no-op update in key order,
-- committing every p_batch rows. Do not use one big UPDATE on a synchronous chain: the chain head
-- stays locked until commit and the cost grows faster than linearly. Call outside a transaction.
CREATE PROCEDURE rebaseline_batched(p_table regclass, p_batch int DEFAULT 1000, p_pk text DEFAULT 'id')
LANGUAGE plpgsql AS $$
DECLARE v_last text := ''; v_max text; n int;
BEGIN
  LOOP
    EXECUTE format('SELECT max(k), count(*) FROM (SELECT %1$I::text AS k FROM %2$s WHERE %1$I::text > $1 ORDER BY 1 LIMIT $2) s',
                   p_pk, p_table) INTO v_max, n USING v_last, p_batch;
    EXIT WHEN n = 0;
    EXECUTE format('UPDATE %2$s SET %1$I = %1$I WHERE %1$I::text > $1 AND %1$I::text <= $2', p_pk, p_table)
      USING v_last, v_max;
    v_last := v_max;
    COMMIT;
  END LOOP;
END $$;

-- ---------- Least privilege ----------
REVOKE ALL ON ALL TABLES IN SCHEMA ledger FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ledger FROM PUBLIC;
REVOKE ALL ON ALL PROCEDURES IN SCHEMA ledger FROM PUBLIC;
GRANT USAGE ON SCHEMA ledger TO app_user, auditor, ledger_sealer;
GRANT SELECT ON history, chain_head, migration_checkpoint TO auditor;
GRANT EXECUTE ON FUNCTION verify_chain(text, bigint), reconcile(regclass), list_digests(), list_checkpoints() TO auditor;
GRANT EXECUTE ON FUNCTION seal(text, int), seal_all(int), list_digests(), list_checkpoints() TO ledger_sealer;
RESET ROLE;
