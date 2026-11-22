# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Names, tags and constants shared by the scripts."""
import re

PURPOSE_TAG = ("purpose", "tamper-evident-ledger-sample")
STACK_TAG_KEY = "ledger-stack"
DEFAULT_STACK = "tamper-ledger"
STACK_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{2,29}$")
LAMBDA_RUNTIME = "python3.13"
DATABASE = "postgres"
ANCHOR_PREFIX = "anchors/"
SIGNING_ALGORITHM = "ECDSA_SHA_256"
# Database roles that have a Secrets Manager secret in the stack (see infra/ledger.yaml).
DB_USERS = ("app_user", "auditor", "ledger_sealer")


class Names:
    """Resource names derived from the CloudFormation stack name."""

    def __init__(self, stack):
        if not STACK_NAME_RE.match(stack) or "--" in stack or stack.endswith("-"):
            raise ValueError("stack name must be 3-30 characters: lowercase letters, digits and single hyphens, "
                             "starting with a letter")
        self.stack = stack
        self.function = f"{stack}-anchor"
        self.schedule = f"{stack}-anchor-every-minute"

    def tags(self):
        return [{"Key": PURPOSE_TAG[0], "Value": PURPOSE_TAG[1]}, {"Key": STACK_TAG_KEY, "Value": self.stack}]

    def tag_map(self):
        return {t["Key"]: t["Value"] for t in self.tags()}
