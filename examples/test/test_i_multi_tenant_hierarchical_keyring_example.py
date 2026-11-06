# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the multi-tenant hierarchical keyring example."""
import uuid

import boto3
import botocore.session
import pytest

from ..src.multi_tenant_hierarchical_keyring_example import encrypt_and_decrypt_with_keyring
from .branch_key_cleanup import cleanup_branch_keys

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using an AWS KMS Key Store and Hierarchical Keyring per tenant."""
    key_store_table_name = "KeyStoreDdbTable"
    kms_key_id = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
    # The test environment has one identity; real tenants would each have their own credentials.
    credentials = botocore.session.Session().get_credentials()
    # Assigned by the application, as most applications do; unique per run, so runs never collide.
    # UUID version 4: the standard library's uuid7 is new in Python 3.14, and this package supports 3.8.
    branch_key_ids = {
        "TenantA": "esdk-python-example-tenant-A-{}".format(uuid.uuid4()),
        "TenantB": "esdk-python-example-tenant-B-{}".format(uuid.uuid4()),
    }
    try:
        encrypt_and_decrypt_with_keyring(
            key_store_table_name=key_store_table_name,
            logical_key_store_name=key_store_table_name,
            tenant_kms_key_ids={"TenantA": kms_key_id, "TenantB": kms_key_id},
            tenant_credentials={"TenantA": credentials, "TenantB": credentials},
            tenant_branch_key_ids=branch_key_ids,
        )
    finally:
        # Clean up the Branch Keys the example created, best effort, to keep the example table from growing.
        # Branch Keys SHOULD NOT be deleted in production: deleting a Branch Key
        # cryptographically shreds every message it protected.
        ddb_client = boto3.client("dynamodb", region_name="us-west-2")
        try:
            cleanup_branch_keys(ddb_client, key_store_table_name, branch_key_ids)
        finally:
            ddb_client.close()
