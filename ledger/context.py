# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Command-line plumbing shared by the numbered scripts: arguments, account guard, stack outputs."""
import argparse
import json
import os
import sys

import boto3

from ledger.dataapi import DataApi
from ledger.settings import DATABASE, DEFAULT_STACK, Names

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_OUTPUTS = {"master": "MasterSecretArn", "app_user": "AppUserSecretArn",
                  "auditor": "AuditorSecretArn", "ledger_sealer": "SealerSecretArn"}


class AccountMismatch(SystemExit):
    pass


def base_parser(description):
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--expected-account", required=True,
                   help="12-digit AWS account ID to run in. The script stops if the credentials resolve to "
                        "any other account.")
    p.add_argument("--region", required=True, help="AWS Region, for example us-east-1")
    p.add_argument("--profile", help="named AWS CLI profile (default: standard credential chain)")
    p.add_argument("--stack-name", default=DEFAULT_STACK, help=f"CloudFormation stack name (default {DEFAULT_STACK})")
    p.add_argument("--results-dir", default=os.path.join(REPO_ROOT, "results"),
                   help="where reports and the exported public key are written (default ./results)")
    return p


def check_account(actual, expected):
    if actual != expected:
        raise AccountMismatch(f"Credentials belong to account {actual}, expected {expected}. Stopping without "
                              "making any change.")


class Context:
    def __init__(self, args):
        self.args = args
        self.names = Names(args.stack_name)
        self.session = boto3.Session(profile_name=args.profile, region_name=args.region)
        ident = self.session.client("sts").get_caller_identity()
        check_account(ident["Account"], args.expected_account)
        self.account, self.region = ident["Account"], args.region
        self.partition = ident["Arn"].split(":")[1]   # aws, aws-cn, aws-us-gov, ...
        print(f"Account {self.account}  Region {self.region}  Caller {ident['Arn']}  Stack {self.names.stack}",
              file=sys.stderr)
        self._outputs = None
        os.makedirs(args.results_dir, exist_ok=True)

    def client(self, name):
        return self.session.client(name)

    def outputs(self):
        if self._outputs is None:
            stack = self.client("cloudformation").describe_stacks(StackName=self.names.stack)["Stacks"][0]
            self._outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        return self._outputs

    def db(self, user):
        """Data API session as one of: master, app_user, auditor, ledger_sealer."""
        out = self.outputs()
        return DataApi(self.client("rds-data"), out["ClusterArn"], out[SECRET_OUTPUTS[user]], DATABASE)

    def secret_password(self, user):
        value = self.client("secretsmanager").get_secret_value(SecretId=self.outputs()[SECRET_OUTPUTS[user]])
        return json.loads(value["SecretString"])["password"]

    def public_key_path(self):
        return os.path.join(self.args.results_dir, f"{self.names.stack}-anchor-public-key.pem")

    def invoke_anchor(self):
        """Run the anchoring function once and return its result (used by the demo and verify scripts)."""
        out = self.client("lambda").invoke(FunctionName=self.names.function, InvocationType="RequestResponse")
        payload = json.loads(out["Payload"].read())
        if out.get("FunctionError"):
            raise SystemExit(f"Anchoring function failed: {payload}")
        return payload
