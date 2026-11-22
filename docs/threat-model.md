# Threat model

Scope: the sample as deployed by `infra/ledger.yaml` and `01_deploy.py`, in one AWS account and
Region. The goal of the design is **tamper evidence**: any change to recorded history after it was
anchored is detected by an auditor who holds the public key. It is not tamper *prevention* against
the database master user.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Activity stream records | Kinesis (created by Database Activity Streams), archived by Firehose to an Object Lock bucket, encrypted with a KMS key | Record of what database users, including the master user, ran |
| Migration checkpoints | `ledger.migration_checkpoint`, signed into every manifest | Link imported history to the source ledger's final digest |
| pgAudit log | CloudWatch Logs log group `/aws/rds/cluster/<stack>-db/postgresql` | DDL and role changes |
| Ledger history and chain heads | `ledger.history`, `ledger.chain_head` in Aurora | The record being protected |
| Signing private key | AWS KMS (`ECC_NIST_P256`, never leaves KMS) | Whoever can sign can create anchors |
| Anchors | S3 bucket, Object Lock compliance mode | Fixed reference the database is compared with |
| Public key | `results/<stack>-anchor-public-key.pem`, given to auditors | Used to check anchor signatures |
| Database credentials | Secrets Manager: master (RDS managed), `app_user`, `auditor`, `ledger_sealer` | Database access |
| DDL guard | `ledger_guard` schema and `ledger_ddl_guard` event trigger | Stops schema changes that weaken the ledger |

## Trust boundaries and actors

| Actor | Trusted for | Not trusted for |
|---|---|---|
| Application (`app_user`) | Writing correct business data | Touching history or chain heads |
| Schema owner / migration tool (`ledger_owner`) | Routine DDL on business tables | Any DDL on `ledger.history` or `ledger.migration_checkpoint`; primary-key changes, adding, removing or disabling ledger triggers, replacing ledger functions |
| Database master user / DBA | Operating the database | Leaving history unchanged |
| Anchoring function role | Signing and writing anchors | — (it is the trust anchor; protect its code and role) |
| Account administrators | Managing AWS resources | Leaving anchors and signing rights unchanged without leaving a trace |
| Auditor | Running the checks | Write access to anything |

## Threats and mitigations

| # | Threat | Mitigation in the sample | Residual risk / production advice |
|---|---|---|---|
| T1 | Application edits or deletes history | No privileges on `ledger.history` or `ledger.chain_head`; capture triggers run as `SECURITY DEFINER` | — |
| T2 | Schema owner edits history | Append-only triggers reject `UPDATE`/`DELETE`/`TRUNCATE` | — |
| T3 | Schema owner disables, drops or adds triggers, drops the table, changes the primary key, replaces `capture_change` with a no-op, or alters `ledger.history` / `ledger.migration_checkpoint` (for example `ALTER COLUMN ... TYPE ... USING`, which rewrites rows without firing row triggers) | DDL guard event trigger (`ENABLE ALWAYS`) rolls the statement back; guard objects belong to the master user | Guard covers registered tables only: register every ledger table. Other DDL on business tables (such as `ALTER COLUMN ... TYPE ... USING`) is allowed; rows it changes without history are reported by reconciliation (T6) |
| T4 | Master user edits a history row | Hash chain: chain check fails (demo B) | — |
| T5 | Master user rewrites the whole chain, or truncates it | Anchor check against every signed anchor fails (demo C, D) | Changes newer than the last anchor are not covered (≤ 1 minute by default) |
| T6 | Master user changes business rows with triggers bypassed (`session_replication_role = replica`) | Reconciliation finds rows that differ from their last revision (demo E) | Not detected until reconciliation runs; record master-user activity with Database Activity Streams |
| T7 | Master user turns off the DDL guard | Possible by design (owner). Then T4–T6 apply and are detected as above. With `--activity-stream`, the statements are recorded outside the database and `06_activity_report.py` lists them | Restrict `rds:StopActivityStream`, the activity stream key, the Kinesis stream and the archive bucket to a security team; add near-real-time alerting |
| T8 | Restore an old snapshot (rollback) | Anchor check: chains shorter than anchored, or chains missing | Protect backups with AWS Backup Vault Lock; restrict restore permissions |
| T9 | Forge an anchor | Key policy denies `kms:Sign` to everyone but the anchoring function role, including administrators; bucket policy denies `s3:PutObject` to everyone else; the verifier rejects anchors with invalid signatures | Principals with `kms:PutKeyPolicy`, `s3:PutBucketPolicy`, `lambda:UpdateFunctionCode` or `iam:PassRole` on these resources can bypass this; restrict to a security team and monitor in CloudTrail |
| T10 | Delete or overwrite anchors | Object Lock compliance mode; an overwrite creates a new version and the verifier checks all versions | Retention must match your records policy. Retention of anchors already written cannot be shortened, but a principal with `s3:PutBucketObjectLockConfiguration` can shorten the default retention of future anchors; restrict it to a security team and monitor it in CloudTrail |
| T11 | Stop anchoring (delete the schedule or break the function) | CloudWatch alarms on function errors and on 5 minutes without invocations notify the SNS topic `<stack>-alarms` (subscribe with `01_deploy.py --alarm-email`); `04_verify.py` fails a chain whose newest anchor is older than `--max-anchor-age-minutes` (default 60) | Subscribe the security team to the topic |
| T12 | Asynchronous rows changed before sealing | Sealed every minute; the append-only trigger still applies | Use synchronous chains where the window matters |
| T13 | Ambiguous hash input (separator injection) | Hash input is a JSON array; unit tests cover quotes, separators, newlines and non-ASCII text | — |
| T14 | Credential theft | Data API with IAM; no network path to the cluster (no ingress, no internet gateway); per-role secrets with least privilege | Enable secret rotation; consider IAM database authentication for applications |
| T15 | Data in transit or at rest exposed | Data API over TLS; bucket policy denies non-TLS; storage encrypted with AWS managed keys | Use customer managed keys if required |
| T16 | Correct chain, wrong data | Out of scope: a valid chain proves history did not change, not that it was right | Application-level validation |
| T17 | Master user alters a migration checkpoint (the link to the source ledger) | Checkpoint table is append-only and registered with the DDL guard; every manifest signs all checkpoints; the verifier compares each checkpoint with every anchored copy | — |
| T18 | Secrets exposed in activity records | Database Activity Streams records bind parameters; role passwords are sent as SCRAM-SHA-256 verifiers; pgAudit redacts `PASSWORD` | Apply the same rule to application code |
| T19 | Activity archive deleted or altered | Object Lock compliance mode; bucket policy lets only the Firehose role write; records stay encrypted with the activity stream key | — |
| T20 | Anchors deleted after their retention expires, then the chain rewritten | Anyone with `s3:DeleteObject` can delete expired anchors. `04_verify.py` fails a chain that has rows but no valid anchor, and a chain whose newest anchor is older than `--max-anchor-age-minutes`; the report shows, per chain, the newest anchor time and the rows after the newest anchored sequence | Choose a retention longer than the period over which you need proof; run the verifier regularly; restrict `s3:DeleteObject` on the anchor bucket |
| T21 | Auditor uses `reconcile()` to read other tables | `ledger.reconcile()` accepts only registered business tables; registered table names must be unique across schemas | — |

## Security-relevant files

| File | Content |
|---|---|
| `infra/ledger.yaml` | VPC without internet path, Aurora cluster, KMS key policy, bucket and bucket policy, secrets, IAM roles, alarms |
| `sql/01_ledger.sql` | Roles and grants, capture triggers, append-only trigger, hash function, verification and reconciliation functions |
| `sql/02_ddl_guard.sql` | DDL guard event trigger and table registry |
| `lambda_anchor/handler.py` | Sealing, signing, anchor writing |
| `ledger/verify.py` | Hash-chain recomputation, signature check, anchor comparison |
| `02_init_ledger.py`, `ledger/scram.py` | Sets database role passwords from Secrets Manager as SCRAM-SHA-256 verifiers |
| `ledger/activity.py`, `06_activity_report.py` | Starts Database Activity Streams, creates the Firehose archive, decrypts and classifies records |
| `05_import_checkpoint.py` | Writes migration checkpoints |
| `99_cleanup.py` | Deletes the stack after confirmation; empties only buckets tagged for this stack that have Object Lock enabled |
