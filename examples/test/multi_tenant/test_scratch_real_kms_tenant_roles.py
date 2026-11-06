# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
r"""SCRATCH, for review; to be removed: tenants with their own IAM roles, against real AWS KMS and DynamoDB Local.

Skipped unless ``SCRATCH_REAL_KMS=1``, so CI never runs it. It needs:

- the two tenant roles of ``scratch_kms_tenant_roles.yaml`` (deployed as ``esdk-python-multi-tenant-scratch``),
  whose ARNs are ``SCRATCH_TENANT_A_ROLE_ARN`` and ``SCRATCH_TENANT_B_ROLE_ARN``;
  each allows the KMS data plane actions on ``KMS_KEY_ARN`` only when the encryption context has
  ``aws-crypto-ec:tenant`` set to that tenant;
- default AWS credentials for the principal those roles trust; used only to assume them;
- DynamoDB Local, at ``DDB_LOCAL_ENDPOINT``.

Run::

    SCRATCH_REAL_KMS=1 DDB_LOCAL_ENDPOINT=http://localhost:8000 \
    SCRATCH_TENANT_A_ROLE_ARN=arn:aws:iam::<account>:role/esdk-python-scratch-tenant-a \
    SCRATCH_TENANT_B_ROLE_ARN=arn:aws:iam::<account>:role/esdk-python-scratch-tenant-b \
        python -m pytest -m ddblocal examples/test/multi_tenant/test_scratch_real_kms_tenant_roles.py

Each tenant's credentials are botocore's refreshable assume role credentials, as an application would use:
the role is assumed on first use, and again before the credentials expire.

The test key's key policy refuses ``kms:GenerateDataKeyWithoutPlaintext`` and ``kms:ReEncrypt`` to other accounts,
so the AWS KMS Key Store cannot create a Branch Key with them. Instead, each tenant's Branch Key is written as the
AWS KMS Key Store writes one (``branch-key-store.md``, Encryption Context), through real AWS KMS with that tenant's
credentials: ``kms:GenerateDataKey`` under its version's encryption context, then ``kms:Encrypt`` of the same
plaintext under its ACTIVE encryption context, discarding the plaintext. Each has the custom encryption context
``{"tenant": <tenant>}``, as the multi-tenant Hierarchical Keyring example creates it, which AWS KMS sees as
``aws-crypto-ec:tenant``.

One Discovery Tenant Keyring Factory, over one shared ``KmsTransport``, vends every keyring:

1. Each tenant's keyring encrypts and decrypts with its own Branch Key: kms:Decrypt of its ACTIVE item, then of
   its version item, each signed with that tenant's assumed role credentials, and never the other's.
2. A keyring with tenant-b's credentials and tenant-a's Branch Key is Denied by AWS KMS itself
   (``AccessDeniedException``: the role's policy requires ``aws-crypto-ec:tenant`` = ``tenant-b``); the Denial is
   negatively cached, enforced with no DynamoDB or KMS call, and isolated: tenant-a, and tenant-b's own Branch Key,
   are unaffected.
"""
# pylint: disable=redefined-outer-name
import datetime
import os
import uuid

import boto3
import botocore.session
import pytest
from aws_cryptographic_material_providers.keystore.models import Discovery, KMSConfigurationDiscovery
from aws_cryptographic_material_providers.mpl.errors import KeyStore as KeyStoreError, OpaqueWithTextError
from botocore.credentials import AssumeRoleCredentialFetcher, DeferredRefreshableCredentials

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ...src.multi_tenant.tenant_keyring_factory import TenantKeyringFactory
from ...src.multi_tenant_hierarchical_keyring_example import denied_kms_error

ROLE_ARNS = {
    "tenant-a": os.environ.get("SCRATCH_TENANT_A_ROLE_ARN"),
    "tenant-b": os.environ.get("SCRATCH_TENANT_B_ROLE_ARN"),
}
pytestmark = [
    pytest.mark.ddblocal,
    pytest.mark.skipif(
        os.environ.get("SCRATCH_REAL_KMS") != "1" or not all(ROLE_ARNS.values()),
        reason="scratch: needs SCRATCH_REAL_KMS=1, the tenant role ARNs, and AWS credentials",
    ),
]

REGION = "us-west-2"
ENDPOINT = os.environ.get("DDB_LOCAL_ENDPOINT", "http://localhost:8000")
# The AWS Encryption SDK's public test key; the tenant roles' default KmsKeyArn.
KMS_KEY_ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"


def assumed_role_credentials(role_arn, session_name):
    """Return refreshable credentials for a role: assumed on first use, and again before they expire."""
    session = botocore.session.Session()
    fetcher = AssumeRoleCredentialFetcher(
        client_creator=session.create_client,
        source_credentials=session.get_credentials(),
        role_arn=role_arn,
        extra_args={"RoleSessionName": session_name},
    )
    return DeferredRefreshableCredentials(method="assume-role", refresh_using=fetcher.fetch_credentials)


def write_branch_key(ddb, table, transport, credentials, tenant):  # pylint: disable=too-many-locals
    """Write a tenant's Branch Key, its version and ACTIVE items, through AWS KMS with the tenant's credentials."""
    branch_key_id = "esdk-python-example-{}-{}".format(tenant, uuid.uuid4())
    version = "branch:version:" + str(uuid.uuid4())
    create_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    shared = {
        "branch-key-id": branch_key_id,
        "create-time": create_time,
        "tablename": table,
        "kms-arn": KMS_KEY_ARN,
        "hierarchy-version": "1",
        "aws-crypto-ec:tenant": tenant,
    }
    version_context = dict(shared, type=version)
    active_context = dict(shared, type="branch:ACTIVE", version=version)
    kms = TenantKmsClient(transport=transport, region_name=REGION, credentials=credentials)
    generated = kms.generate_data_key(KeyId=KMS_KEY_ARN, NumberOfBytes=32, EncryptionContext=version_context)
    active = kms.encrypt(KeyId=KMS_KEY_ARN, Plaintext=generated.pop("Plaintext"), EncryptionContext=active_context)
    del generated["ResponseMetadata"]

    def item(context, ciphertext):
        attributes = {name: {"S": value} for name, value in context.items() if name != "tablename"}
        attributes["hierarchy-version"] = {"N": "1"}
        attributes["enc"] = {"B": ciphertext}
        return attributes

    ddb.put_item(TableName=table, Item=item(version_context, generated["CiphertextBlob"]))
    ddb.put_item(TableName=table, Item=item(active_context, active["CiphertextBlob"]))
    return branch_key_id


@pytest.fixture
def remote_calls():
    """Create a DynamoDB Local client, with a table, and a real KMS transport; each counts the requests it sends."""
    ddb = boto3.client(
        "dynamodb", region_name=REGION, endpoint_url=ENDPOINT, aws_access_key_id="ddblocal",
        aws_secret_access_key="ddblocal",
    )
    ddb_calls = []
    ddb.meta.events.register("before-call.dynamodb", lambda **kwargs: ddb_calls.append(kwargs["model"].name))
    transport = KmsTransport()
    kms_calls = []
    send = transport.call

    def counting_call(**kwargs):
        outcome = "error"
        try:
            response = send(**kwargs)
            outcome = "ok"
            return response
        finally:
            access_key = kwargs["credentials"].get_frozen_credentials().access_key
            kms_calls.append((kwargs["operation_name"], access_key, outcome))

    transport.call = counting_call
    table = "Scratch-KeyStore-" + uuid.uuid4().hex[:12]
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "branch-key-id", "AttributeType": "S"},
            {"AttributeName": "type", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "branch-key-id", "KeyType": "HASH"},
            {"AttributeName": "type", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    try:
        yield {"ddb": ddb, "ddb_calls": ddb_calls, "transport": transport, "kms_calls": kms_calls, "table": table}
    finally:
        ddb.delete_table(TableName=table)
        transport.close()
        ddb.close()


@pytest.fixture
def tenants(remote_calls):
    """Assume each tenant's role, write its Branch Key, and build the factory; the setup's calls are not counted."""
    found = {}
    for tenant, role_arn in ROLE_ARNS.items():
        credentials = assumed_role_credentials(role_arn, "esdk-python-scratch-" + tenant)
        branch_key_id = write_branch_key(
            remote_calls["ddb"], remote_calls["table"], remote_calls["transport"], credentials, tenant
        )
        found[tenant] = {
            "credentials": credentials,
            "branch_key_id": branch_key_id,
            "access_key": credentials.get_frozen_credentials().access_key,
        }
    factory = TenantKeyringFactory(
        transport=remote_calls["transport"],
        ddb_client=remote_calls["ddb"],
        ddb_table_name=remote_calls["table"],
        logical_key_store_name=remote_calls["table"],
        kms_configuration=KMSConfigurationDiscovery(value=Discovery()),
        region_name=REGION,
    )
    remote_calls["ddb_calls"].clear()
    remote_calls["kms_calls"].clear()
    return {"factory": factory, **found}


@pytest.fixture
def esdk():
    return aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)


def test_scratch_the_tenants_have_distinct_assumed_role_credentials(tenants):
    a, b = tenants["tenant-a"]["access_key"], tenants["tenant-b"]["access_key"]
    assert a != b
    assert a.startswith("ASIA") and b.startswith("ASIA")  # temporary credentials, from sts:AssumeRole
    source = botocore.session.Session().get_credentials().get_frozen_credentials().access_key
    assert source not in (a, b)


def test_scratch_each_tenant_round_trips_with_its_own_role(tenants, remote_calls, esdk):
    factory = tenants["factory"]
    for tenant in ("tenant-a", "tenant-b"):
        before = len(remote_calls["kms_calls"])
        keyring = factory.keyring_for(tenant, tenants[tenant]["branch_key_id"], tenants[tenant]["credentials"])
        ciphertext, _ = esdk.encrypt(source=b"data of " + tenant.encode(), keyring=keyring)
        plaintext, _ = esdk.decrypt(source=ciphertext, keyring=keyring)
        assert plaintext == b"data of " + tenant.encode()
        # The ACTIVE item on encrypt, the version item on decrypt; both signed with this tenant's credentials.
        assert remote_calls["kms_calls"][before:] == [
            ("Decrypt", tenants[tenant]["access_key"], "ok"),
            ("Decrypt", tenants[tenant]["access_key"], "ok"),
        ]


def test_scratch_a_tenant_role_is_denied_another_tenants_branch_key(tenants, remote_calls, esdk):
    factory = tenants["factory"]
    branch_key_a = tenants["tenant-a"]["branch_key_id"]
    credentials_b = tenants["tenant-b"]["credentials"]
    misconfigured = factory.keyring_for("tenant-b", branch_key_a, credentials_b)

    # 1. AWS KMS Denies tenant-b's role tenant-a's Branch Key: its encryption context says tenant-a.
    with pytest.raises(KeyStoreError) as first:
        esdk.encrypt(source=b"tenant-b data", keyring=misconfigured)
    # Its message is a nested MPL error; str() of either is the ClientError's text, which names the code.
    assert "AccessDeniedException" in str(first.value)
    assert remote_calls["kms_calls"] == [("Decrypt", tenants["tenant-b"]["access_key"], "error")]
    assert remote_calls["ddb_calls"] == ["GetItem"]
    entry = factory.negative_cache_for("tenant-b", branch_key_a).get()
    assert entry is not None
    assert entry.error.response["Error"]["Code"] == "AccessDeniedException"

    # 2. Enforced: later requests, through any keyring for tenant-b and that Branch Key ID, call nothing.
    for keyring in (misconfigured, factory.keyring_for("tenant-b", branch_key_a, credentials_b)):
        with pytest.raises(OpaqueWithTextError) as cached:
            esdk.encrypt(source=b"tenant-b data", keyring=keyring)
        assert denied_kms_error(cached.value) is entry.error
    assert len(remote_calls["kms_calls"]) == 1
    assert len(remote_calls["ddb_calls"]) == 1

    # 3. Isolated: tenant-a, with that Branch Key, and tenant-b, with its own, are unaffected.
    for tenant, branch_key_id in (("tenant-a", branch_key_a), ("tenant-b", tenants["tenant-b"]["branch_key_id"])):
        keyring = factory.keyring_for(tenant, branch_key_id, tenants[tenant]["credentials"])
        ciphertext, _ = esdk.encrypt(source=b"data", keyring=keyring)
        assert esdk.decrypt(source=ciphertext, keyring=keyring)[0] == b"data"
        assert factory.negative_cache_for(tenant, branch_key_id).get() is None
    assert all(call[2] == "ok" for call in remote_calls["kms_calls"][1:])
