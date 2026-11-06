# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test helpers shared by the negative caching tests.

This module MUST NOT import the MPL; the negative cache tests do not need it.
"""
import botocore.exceptions


class FakeClock:  # pylint: disable=too-few-public-methods
    """A clock the test advances by hand."""

    def __init__(self, now=1000.0):
        """Start at ``now``."""
        self.now = now

    def __call__(self):
        """Return the current fake time."""
        return self.now


def kms_error(code="AccessDeniedException", operation="Decrypt"):
    """Return the botocore ``ClientError`` AWS KMS would raise with ``code``."""
    return botocore.exceptions.ClientError({"Error": {"Code": code, "Message": "test " + code}}, operation)
