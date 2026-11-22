# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Static checks on the template and the repository that guard the sample's security posture."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = open(os.path.join(ROOT, "infra", "ledger.yaml"), encoding="utf-8").read()


def source_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "results", "__pycache__")]
        for f in files:
            if f.endswith((".py", ".yaml", ".md", ".txt", ".ini", ".sql", ".json")):
                yield os.path.join(base, f)


def test_template_has_no_internet_path_and_no_public_database():
    for forbidden in ("AWS::EC2::InternetGateway", "AWS::EC2::NatGateway", "0.0.0.0/0", "MapPublicIpOnLaunch: true",
                      "PubliclyAccessible: true"):
        assert forbidden not in TEMPLATE
    assert "PubliclyAccessible: false" in TEMPLATE
    assert "SecurityGroupIngress" not in TEMPLATE


def test_anchor_bucket_is_worm_and_private():
    assert "Mode: COMPLIANCE" in TEMPLATE and "ObjectLockEnabled: true" in TEMPLATE
    assert "DeletionPolicy: Retain" in TEMPLATE
    for flag in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"):
        assert f"{flag}: true" in TEMPLATE
    assert "aws:SecureTransport" in TEMPLATE


def test_activity_archive_is_worm_and_written_only_by_firehose():
    assert TEMPLATE.count("Mode: COMPLIANCE") == 2
    assert "Sid: OnlyFirehoseWritesArchive" in TEMPLATE
    assert "role/${AWS::StackName}-activity-firehose" in TEMPLATE


def test_pgaudit_is_loaded_and_logs_are_kept():
    assert "shared_preload_libraries: pgaudit" in TEMPLATE and "pgaudit.log: ddl,role" in TEMPLATE
    assert "EnableCloudwatchLogsExports: [postgresql]" in TEMPLATE and "RetentionInDays: !Ref AuditLogRetentionDays" in TEMPLATE


def test_only_anchor_role_can_sign_and_write_anchors():
    assert TEMPLATE.count("role/${AWS::StackName}-anchor-function") == 2      # key policy and bucket policy
    assert "Sid: OnlyAnchorFunctionMaySign" in TEMPLATE and "Sid: OnlyAnchorFunctionWritesAnchors" in TEMPLATE


def test_no_wildcard_actions_outside_key_admin_and_tls_deny():
    actions = re.findall(r'Action:\s*"([^"]*\*[^"]*)"', TEMPLATE)
    assert sorted(actions) == ["kms:*", "kms:*", "s3:*", "s3:*"]   # key admin and TLS-only deny, per key and bucket
    assert "secretsmanager:*" not in TEMPLATE and "rds-data:*" not in TEMPLATE


def test_scripts_never_make_databases_public():
    for path in source_files():
        if path.endswith(".py") and os.sep + "tests" + os.sep not in path:
            text = open(path, encoding="utf-8").read()
            assert "PubliclyAccessible=True" not in text, path


def test_every_source_file_has_spdx_header():
    for path in source_files():
        if path.endswith((".py", ".yaml", ".sql")):
            head = open(path, encoding="utf-8").read(400)
            assert "SPDX-License-Identifier: MIT-0" in head, path


def test_no_real_account_ids():
    allowed = {"123456789012"}
    for path in source_files():
        for match in re.findall(r"(?<!\d)\d{12}(?!\d)", open(path, encoding="utf-8").read()):
            assert match in allowed, f"{path}: {match}"


def test_readmes_state_non_production_and_make_no_compliance_claims():
    for name in ("README.md", "README.zh-CN.md"):
        text = open(os.path.join(ROOT, name), encoding="utf-8").read()
        assert "This is sample code, for non-production usage." in text, name
        for claim in ("17a-4", "FINRA", "Cohasset", "CFTC"):
            assert claim not in text, (name, claim)


def test_service_trust_policies_are_bound_to_their_source():
    """The scheduler role is bound to the default schedule group, the Firehose role to this stack's stream."""
    from ledger import activity
    stream = activity.firehose_name("stack").replace("stack", "${AWS::StackName}", 1)
    assert ":schedule-group/default\"" in TEMPLATE      # Scheduler's source ARN is the schedule group
    assert f"deliverystream/{stream}\"" in TEMPLATE
    assert TEMPLATE.count("aws:SourceArn:") == 2


def test_no_hardcoded_partition_in_scripts():
    for path in source_files():
        if path.endswith(".py") and os.sep + "tests" + os.sep not in path:
            with open(path, encoding="utf-8") as f:
                assert '"arn:aws:' not in f.read(), path
