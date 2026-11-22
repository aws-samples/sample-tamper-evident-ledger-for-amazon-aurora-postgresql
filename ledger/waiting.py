# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The one place where the scripts wait.

Used between polls of long-running AWS operations that have no boto3 waiter (Database Activity
Streams state, Firehose and Lambda accepting a just-created IAM role).
"""
import time


def pause(seconds):
    """Wait before the next poll or retry."""
    time.sleep(seconds)  # nosemgrep: python.lang.best-practice.sleep.arbitrary-sleep, arbitrary-sleep
