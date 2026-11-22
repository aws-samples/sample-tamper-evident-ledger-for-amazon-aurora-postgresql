# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deployment steps used by 01_deploy.py and 02_init_ledger.py."""
import io
import os
import zipfile

from cryptography.hazmat.primitives import serialization

from ledger.context import REPO_ROOT
from ledger.settings import LAMBDA_RUNTIME
from ledger.waiting import pause

TEMPLATE = os.path.join(REPO_ROOT, "infra", "ledger.yaml")
HANDLER = os.path.join(REPO_ROOT, "lambda_anchor", "handler.py")


def stack_exists(ctx):
    cfn = ctx.client("cloudformation")
    try:
        status = cfn.describe_stacks(StackName=ctx.names.stack)["Stacks"][0]["StackStatus"]
    except cfn.exceptions.ClientError as exc:
        if "does not exist" in str(exc):
            return False
        raise
    return status != "DELETE_COMPLETE"


def deploy_stack(ctx, parameters):
    """Create or update the stack. A new stack is created with deletion protection off, so that a
    failed first deployment can roll back, and protection is turned on once creation succeeds."""
    protect = parameters.get("DeletionProtection", "true")
    if not stack_exists(ctx) and protect == "true":
        _deploy(ctx, dict(parameters, DeletionProtection="false"))
        ctx._outputs = None
    _deploy(ctx, dict(parameters, DeletionProtection=protect))


def _deploy(ctx, parameters):
    cfn = ctx.client("cloudformation")
    with open(TEMPLATE, encoding="utf-8") as f:
        body = f.read()
    kw = {"StackName": ctx.names.stack, "TemplateBody": body, "Capabilities": ["CAPABILITY_NAMED_IAM"],
          "Tags": ctx.names.tags(),
          "Parameters": [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in parameters.items()]}
    try:
        cfn.describe_stacks(StackName=ctx.names.stack)
        try:
            cfn.update_stack(**kw)
            waiter = "stack_update_complete"
        except cfn.exceptions.ClientError as exc:
            if "No updates are to be performed" not in str(exc):
                raise
            print("Stack is up to date")
            return
    except cfn.exceptions.ClientError as exc:
        if "does not exist" not in str(exc):
            raise
        cfn.create_stack(**kw)
        waiter = "stack_create_complete"
    print(f"Waiting for stack {ctx.names.stack} (about 10 minutes on first deployment) ...")
    cfn.get_waiter(waiter).wait(StackName=ctx.names.stack, WaiterConfig={"Delay": 15, "MaxAttempts": 160})
    print("Stack ready")


def build_zip():
    """The function uses only the AWS SDK that the Lambda runtime provides, so the zip is one file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(HANDLER, "handler.py")
    return buf.getvalue()


def deploy_function(ctx, zip_bytes):
    lam = ctx.client("lambda")
    out = ctx.outputs()
    config = {
        "Role": out["AnchorFunctionRoleArn"], "Runtime": LAMBDA_RUNTIME, "Handler": "handler.lambda_handler",
        "Timeout": 120, "MemorySize": 256,
        "Environment": {"Variables": {"CLUSTER_ARN": out["ClusterArn"], "SECRET_ARN": out["SealerSecretArn"],
                                      "SIGNING_KEY_ARN": out["SigningKeyArn"], "ANCHOR_BUCKET": out["AnchorBucket"]}},
        "Description": "Seals and anchors the tamper-evident ledger (sample, non-production)",
    }
    try:
        lam.get_function(FunctionName=ctx.names.function)
        lam.update_function_code(FunctionName=ctx.names.function, ZipFile=zip_bytes)
        lam.get_waiter("function_updated_v2").wait(FunctionName=ctx.names.function)
        lam.update_function_configuration(FunctionName=ctx.names.function, **config)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(10):  # a new IAM role can take a few seconds before Lambda can assume it
            try:
                lam.create_function(FunctionName=ctx.names.function, Code={"ZipFile": zip_bytes},
                                    Architectures=["arm64"], Tags=ctx.names.tag_map(), **config)
                break
            except lam.exceptions.InvalidParameterValueException as exc:
                if "role" not in str(exc).lower() or attempt == 9:
                    raise
                pause(10)
    lam.get_waiter("function_active_v2").wait(FunctionName=ctx.names.function)
    lam.get_waiter("function_updated_v2").wait(FunctionName=ctx.names.function)
    # One run at a time: two overlapping seal_all() calls would only wait on each other.
    lam.put_function_concurrency(FunctionName=ctx.names.function, ReservedConcurrentExecutions=1)
    print(f"Function {ctx.names.function} ready")


def put_schedule(ctx, enabled=None):
    """Create or update the schedule. enabled=None keeps the current state (disabled if new)."""
    sch = ctx.client("scheduler")
    if enabled is None:
        try:
            enabled = sch.get_schedule(Name=ctx.names.schedule)["State"] == "ENABLED"
        except sch.exceptions.ResourceNotFoundException:
            enabled = False
    out = ctx.outputs()
    fn_arn = ctx.client("lambda").get_function(FunctionName=ctx.names.function)["Configuration"]["FunctionArn"]
    kw = {"Name": ctx.names.schedule, "ScheduleExpression": "rate(1 minute)",
          "FlexibleTimeWindow": {"Mode": "OFF"}, "State": "ENABLED" if enabled else "DISABLED",
          "Description": "Anchor the tamper-evident ledger every minute (sample)",
          "Target": {"Arn": fn_arn, "RoleArn": out["SchedulerRoleArn"], "RetryPolicy": {"MaximumRetryAttempts": 2}}}
    try:
        sch.get_schedule(Name=ctx.names.schedule)
        sch.update_schedule(**kw)
    except sch.exceptions.ResourceNotFoundException:
        sch.create_schedule(**kw)
    print(f"Schedule {ctx.names.schedule} {kw['State']}")


def export_public_key(ctx):
    """Save the signing key's public key as PEM: this is what you hand to an auditor."""
    der = ctx.client("kms").get_public_key(KeyId=ctx.outputs()["SigningKeyArn"])["PublicKey"]
    pem = serialization.load_der_public_key(der).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    path = ctx.public_key_path()
    with open(path, "wb") as f:
        f.write(pem)
    print(f"Public key written to {path}")
    return path
