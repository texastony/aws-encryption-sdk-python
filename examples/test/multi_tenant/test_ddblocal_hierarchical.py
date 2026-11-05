# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests of the multi-tenant Hierarchical Keyring against DynamoDB Local, with the fake KMS.

These need DynamoDB Local, but no AWS credentials or network access to AWS:

    podman run --rm -p 8000:8000 docker.io/amazon/dynamodb-local:3.3.2
    tox -e mplddblocal-mpl

``DDB_LOCAL_ENDPOINT`` (default ``http://localhost:8000``) points the tests at DynamoDB Local.
They are marked only ``ddblocal``, so the ``examples`` and ``local`` test runs do not select them.
"""
# pylint: disable=redefined-outer-name
import collections
import os
import uuid

import boto3
import pytest
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import (
    CreateKeyInput,
    CreateKeyStoreInput,
    KMSConfigurationKmsKeyArn,
    VersionKeyInput,
)
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateAwsKmsHierarchicalKeyringInput
from botocore.credentials import Credentials

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ...src import multi_tenant_hierarchical_keyring_example as example
from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ..branch_key_cleanup import cleanup_branch_keys, delete_branch_key
from . import fake_kms

pytestmark = [pytest.mark.ddblocal]

ENDPOINT = os.environ.get("DDB_LOCAL_ENDPOINT", "http://localhost:8000")
REGION = "us-west-2"
KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
KEY_B = "arn:aws:kms:us-west-2:444455556666:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TENANT_A = Credentials("AKIATENANTA", "secret-a")
TENANT_B = Credentials("AKIATENANTB", "secret-b")


@pytest.fixture
def ddb_env(monkeypatch):
    """Point every DynamoDB client, including the examples' own, at DynamoDB Local.

    One set of fake credentials is used throughout: without -sharedDb,
    DynamoDB Local keeps a separate database per access key id and region.
    """
    monkeypatch.setenv("AWS_ENDPOINT_URL_DYNAMODB", ENDPOINT)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ddblocal")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ddblocal")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def ddb(ddb_env):  # pylint: disable=unused-argument
    """Yield a DynamoDB Local client, and every DynamoDB operation made with it."""
    client = boto3.client("dynamodb", region_name=REGION)
    calls = collections.Counter()
    client.meta.events.register("before-call.dynamodb", lambda **kwargs: calls.update([kwargs["model"].name]))
    yield client, calls
    client.close()


@pytest.fixture
def kms():
    """Yield a transport to the fake KMS, which authorizes each tenant for its own KMS key only."""
    transport = KmsTransport()
    fake = fake_kms.install(transport)
    fake.add_key(KEY_A, TENANT_A.access_key)
    fake.add_key(KEY_B, TENANT_B.access_key)
    yield transport, fake
    transport.close()


def key_store(ddb_client, table, transport, credentials, kms_key):
    return KeyStore(
        config=KeyStoreConfig(
            ddb_client=ddb_client,
            ddb_table_name=table,
            logical_key_store_name=table,
            kms_client=TenantKmsClient(transport, REGION, credentials),
            kms_configuration=KMSConfigurationKmsKeyArn(value=kms_key),
        )
    )


@pytest.fixture
def table(ddb, kms):
    """Create a Key Store table, unique to the test, and delete it afterwards."""
    client, calls = ddb
    name = "KeyStore-" + uuid.uuid4().hex[:12]
    key_store(client, name, kms[0], TENANT_A, KEY_A).create_key_store(input=CreateKeyStoreInput())
    calls.clear()
    yield name
    client.delete_table(TableName=name)


def item_types(ddb_client, table, branch_key_id):
    items = ddb_client.query(
        TableName=table,
        KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={"#pk": "branch-key-id"},
        ExpressionAttributeValues={":pk": {"S": branch_key_id}},
    )["Items"]
    return sorted(item["type"]["S"].rsplit(":", 1)[0] if item["type"]["S"].startswith("branch:version:")
                  else item["type"]["S"] for item in items)


def test_create_key_writes_active_version_and_beacon_items(ddb, kms, table):
    client, _ = ddb
    transport, fake = kms
    branch_key_id = key_store(client, table, transport, TENANT_A, KEY_A).create_key(
        input=CreateKeyInput()
    ).branch_key_identifier
    assert item_types(client, table, branch_key_id) == ["beacon:ACTIVE", "branch:ACTIVE", "branch:version"]
    # The Key Store's KMS operations, through the Tenant KMS Client, signed by the tenant.
    assert [(r["operation"], r["access_key"]) for r in fake.requests] == [
        ("GenerateDataKeyWithoutPlaintext", "AKIATENANTA"),
        ("ReEncrypt", "AKIATENANTA"),
        ("GenerateDataKeyWithoutPlaintext", "AKIATENANTA"),
    ]
    assert delete_branch_key(client, table, branch_key_id) is True


def test_multi_tenant_example_end_to_end(monkeypatch, ddb, kms, table):
    client, _ = ddb
    transport, fake = kms
    monkeypatch.setattr(example, "KmsTransport", lambda: transport)
    branch_key_ids = {}
    try:
        example.encrypt_and_decrypt_with_keyring(
            key_store_table_name=table,
            logical_key_store_name=table,
            tenant_kms_key_ids={"TenantA": KEY_A, "TenantB": KEY_B},
            tenant_credentials={"TenantA": TENANT_A, "TenantB": TENANT_B},
            branch_key_ids=branch_key_ids,
        )
    finally:
        assert not cleanup_branch_keys(client, table, branch_key_ids)

    assert set(branch_key_ids) == {"TenantA", "TenantB"}
    # Per tenant: create its Branch Key, then a cache miss on encrypt (active) and on decrypt (version);
    # every request signed with that tenant's credentials.
    per_tenant = [
        "GenerateDataKeyWithoutPlaintext", "ReEncrypt", "GenerateDataKeyWithoutPlaintext", "Decrypt", "Decrypt",
    ]
    assert [(r["operation"], r["access_key"]) for r in fake.requests] == (
        [(operation, "AKIATENANTA") for operation in per_tenant]
        + [(operation, "AKIATENANTB") for operation in per_tenant]
    )
    for branch_key_id in branch_key_ids.values():
        assert item_types(client, table, branch_key_id) == []


def test_version_key_and_cleanup_of_every_version(ddb, kms, table):
    client, _ = ddb
    transport, _ = kms
    store = key_store(client, table, transport, TENANT_A, KEY_A)
    branch_key_id = store.create_key(input=CreateKeyInput()).branch_key_identifier
    store.version_key(input=VersionKeyInput(branch_key_identifier=branch_key_id))
    assert item_types(client, table, branch_key_id) == [
        "beacon:ACTIVE", "branch:ACTIVE", "branch:version", "branch:version"
    ]
    assert delete_branch_key(client, table, branch_key_id) is True
    assert item_types(client, table, branch_key_id) == []


def test_without_negative_caching_every_denied_attempt_calls_dynamodb_and_kms(ddb, kms, table):
    """Record the behavior negative caching exists to prevent (negative_caching.md, Background)."""
    client, calls = ddb
    transport, fake = kms
    branch_key_id = key_store(client, table, transport, TENANT_A, KEY_A).create_key(
        input=CreateKeyInput()
    ).branch_key_identifier
    fake.requests.clear()
    calls.clear()
    try:
        # Tenant B's credentials, tenant A's Branch Key: the fake KMS denies every Decrypt.
        mat_prov = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())
        keyring = mat_prov.create_aws_kms_hierarchical_keyring(
            input=CreateAwsKmsHierarchicalKeyringInput(
                key_store=key_store(client, table, transport, TENANT_B, KEY_A),
                branch_key_id=branch_key_id,
                ttl_seconds=600,
            )
        )
        esdk = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        )
        for _ in range(3):
            with pytest.raises(Exception, match="AccessDeniedException"):  # pylint: disable=broad-except
                esdk.encrypt(source=b"tenant data", keyring=keyring)
        assert calls["GetItem"] == 3
        assert [(r["operation"], r["access_key"]) for r in fake.requests] == [("Decrypt", "AKIATENANTB")] * 3
    finally:
        assert delete_branch_key(client, table, branch_key_id) is True
