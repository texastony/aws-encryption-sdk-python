# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Negative caching against real AWS KMS and Amazon DynamoDB, with static Branch Keys.

Uses two static hierarchy version 1 Branch Keys, test fixtures of the AWS Cryptographic Material Providers Library,
in the ``KeyStoreDdbTable`` table; both MUST NOT be deleted or versioned:

- ``GOOD_BRANCH_KEY_ID``: protected by ``KMS_KEY_ARN``; the CI role decrypts it.
- ``LYING_BRANCH_KEY_ID``: its items say it is protected by the postalHorn KMS key,
  but it was created under ``KMS_KEY_ARN`` (the MPL's ``cfn/lyingBranchKeyCreation.md``).
  A Discovery Key Store calls ``kms:Decrypt`` with the item's KMS key, so AWS KMS rejects it with
  ``IncorrectKeyException``, a Denial (negative_caching.md 5); the MPL's ``TestLyingBranchKey.dfy`` asserts the same.

Every request uses the CI role's credentials, so this does not test isolation between tenants' credentials;
the DynamoDB Local tests do, with a fake AWS KMS (multi_tenant/test_ddblocal_hierarchical.py).
"""
# pylint: disable=redefined-outer-name
import boto3
import botocore.session
import pytest
from aws_cryptographic_material_providers.keystore.models import Discovery, KMSConfigurationDiscovery
from aws_cryptographic_material_providers.mpl.errors import OpaqueWithTextError

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ..src.multi_tenant import KmsTransport
from ..src.multi_tenant.tenant_keyring_factory import TenantKeyringFactory

pytestmark = [pytest.mark.examples]

REGION = "us-west-2"
TABLE = "KeyStoreDdbTable"
# THESE ARE TESTING RESOURCES; DO NOT USE IN A PRODUCTION ENVIRONMENT, AND DO NOT DELETE OR VERSION THEM.
KMS_KEY_ARN = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
GOOD_BRANCH_KEY_ID = "3f43a9af-08c5-4317-b694-3d3e883dcaef"
LYING_BRANCH_KEY_ID = "kms-arn-attribute-is-lying"


@pytest.fixture
def remote_calls():
    """Create a DynamoDB client and a KMS transport, each counting the requests it sends."""
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb_calls = []
    ddb.meta.events.register("before-call.dynamodb", lambda **kwargs: ddb_calls.append(kwargs["model"].name))
    transport = KmsTransport()
    kms_calls = []
    send = transport.call

    def counting_call(**kwargs):
        kms_calls.append(kwargs["operation_name"])
        return send(**kwargs)

    transport.call = counting_call
    try:
        yield {"ddb": ddb, "ddb_calls": ddb_calls, "transport": transport, "kms_calls": kms_calls}
    finally:
        transport.close()
        ddb.close()


@pytest.fixture
def factory(remote_calls):
    return TenantKeyringFactory(
        transport=remote_calls["transport"],
        ddb_client=remote_calls["ddb"],
        ddb_table_name=TABLE,
        logical_key_store_name=TABLE,
        kms_configuration=KMSConfigurationDiscovery(value=Discovery()),
        region_name=REGION,
    )


@pytest.fixture
def credentials():
    # The test environment has one identity; real tenants would each have their own credentials.
    return botocore.session.Session().get_credentials()


@pytest.fixture
def esdk():
    return aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)


def test_good_static_branch_key_encrypts_and_decrypts(factory, credentials, esdk):
    keyring = factory.keyring_for("tenant-a", GOOD_BRANCH_KEY_ID, credentials)
    ciphertext, _ = esdk.encrypt(source=b"tenant data", keyring=keyring)
    assert esdk.decrypt(source=ciphertext, keyring=keyring)[0] == b"tenant data"
    assert factory.negative_cache_for("tenant-a", GOOD_BRANCH_KEY_ID).get() is None


def test_a_real_denial_is_negatively_cached(factory, remote_calls, credentials, esdk):
    lying = factory.keyring_for("tenant-a", LYING_BRANCH_KEY_ID, credentials)

    # 1. A cache miss: DynamoDB, then kms:Decrypt with the item's KMS key, which AWS KMS rejects.
    #    The MPL models IncorrectKeyException, so the error it raises loses the code (negative_caching.md 4.3);
    #    the negative cache has the error AWS KMS returned.
    with pytest.raises(Exception) as first:  # pylint: disable=broad-except
        esdk.encrypt(source=b"tenant data", keyring=lying)
    assert remote_calls["kms_calls"] == ["Decrypt"]
    assert remote_calls["ddb_calls"] == ["GetItem"]
    entry = factory.negative_cache_for("tenant-a", LYING_BRANCH_KEY_ID).get()
    assert entry is not None
    assert entry.error.response["Error"]["Code"] == "IncorrectKeyException"
    assert getattr(first.value, "obj", None) is not entry.error  # raised by the MPL, not the Cache Guard

    # 2. Every later request for the Tenant and Branch Key ID, through any keyring, fails without a call.
    for keyring in (lying, factory.keyring_for("tenant-a", LYING_BRANCH_KEY_ID, credentials)):
        with pytest.raises(OpaqueWithTextError) as excinfo:
            esdk.encrypt(source=b"tenant data", keyring=keyring)
        assert excinfo.value.obj is entry.error
    assert remote_calls["kms_calls"] == ["Decrypt"]
    assert remote_calls["ddb_calls"] == ["GetItem"]

    # 3. The Denial is isolated to its Branch Key ID (Requirement 2) and to its Tenant.
    good = factory.keyring_for("tenant-a", GOOD_BRANCH_KEY_ID, credentials)
    ciphertext, _ = esdk.encrypt(source=b"tenant data", keyring=good)
    assert esdk.decrypt(source=ciphertext, keyring=good)[0] == b"tenant data"
    tenant_b = factory.negative_cache_for("tenant-b", LYING_BRANCH_KEY_ID)
    assert tenant_b.get() is None
    kms_calls_before = len(remote_calls["kms_calls"])
    with pytest.raises(Exception) as excinfo:  # pylint: disable=broad-except
        esdk.encrypt(source=b"tenant data", keyring=factory.keyring_for("tenant-b", LYING_BRANCH_KEY_ID, credentials))
    # Tenant B called AWS KMS itself, rather than failing on tenant A's Denial, and was Denied in turn.
    assert getattr(excinfo.value, "obj", None) is not entry.error
    assert remote_calls["kms_calls"][kms_calls_before:] == ["Decrypt"]
    assert tenant_b.get() is not None
    assert tenant_b.get().error is not entry.error
