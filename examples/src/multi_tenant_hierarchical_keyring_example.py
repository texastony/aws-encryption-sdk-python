# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example vends a Hierarchical Keyring per tenant from one Tenant Keyring Factory,
where each tenant's AWS KMS key MUST be called with that tenant's AWS credentials,
without constructing a boto3 Session or KMS client per tenant.

The Tenant Keyring Factory holds what every tenant shares:

- one ``KmsTransport``, which owns the only connection pool;
  each tenant's KMS requests are signed with that tenant's credentials by a ``TenantKmsClient``,
  a few references the factory creates per keyring
- one DynamoDB client, and the AWS KMS Key Store's configuration
- one storm tracking cache, shared by every tenant's Hierarchical Keyring,
  so its thundering herd mitigation (a cap on simultaneous fetches of Branch Keys) applies across all tenants,
  and one entry capacity bounds the memory of every tenant's cached Branch Keys;
  its parameters are explained in ``multi_tenant/tenant_keyring_factory.py``,
  and applications SHOULD tune them to their own usage pattern

Each keyring's Partition ID is its tenant's identifier,
which isolates tenants within the shared cache.
Cached entries are identified by the tenant's identifier and Branch Key ID, not its credentials:
the application MUST pass the identifier of the tenant it authenticated, never one taken from the request,
and the Branch Key ID it assigned that tenant.

When AWS KMS denies a tenant's Branch Key, the factory's keyrings fail that tenant's requests for that Branch Key,
without calling DynamoDB or KMS, for the Negative TTL (5 minutes by default);
see ``multi_tenant/negative_caching.md``.

A Denied request raises an error of the AWS Cryptographic Material Providers Library (MPL),
as the MPL is implemented in Dafny, and converts every error to and from Dafny:

- The request that AWS KMS Denied raises an MPL ``KeyStore`` error; the ``ClientError`` itself is not kept.
  Its ``message`` may itself be a nested MPL error; ``str(error)`` is the text.
  For codes the MPL does not model, that is the ``ClientError``'s text, which names the code;
  for ``DisabledException``, ``KMSInvalidStateException``, ``NotFoundException``, and ``IncorrectKeyException``,
  it is only AWS KMS's message, and the code is lost.
  Recording the Denial logs a warning naming the Branch Key ID and the code.
  To get the code at once, ask the factory for the Denial it recorded:
  ``factory.negative_cache_for(tenant_id, branch_key_id).get().error`` is the ``ClientError`` AWS KMS returned
  (``get()`` returns None if the failure was not a Denial).
- Every request after it, until the Negative TTL expires, raises
  ``aws_cryptographic_material_providers.mpl.errors.OpaqueWithTextError``, without calling DynamoDB or KMS.
  Its ``obj`` is the ``botocore.exceptions.ClientError`` AWS KMS returned, the same object, so
  ``error.obj.response["Error"]["Code"]`` is the code; its ``obj_message`` is that error's text.
  Its own ``str()`` is empty; log ``obj_message``, or ``obj``.

``denied_kms_error``, below, unwraps it.

The AWS KMS Key Store calls AWS KMS to create a Branch Key
(``GenerateDataKeyWithoutPlaintext`` and ``ReEncrypt``)
and to decrypt a Branch Key on a cache miss (``Decrypt``);
every one of those requests is signed with the tenant's credentials.

The tenant's KMS key is the isolation boundary;
a Branch Key Item is useless without ``kms:Decrypt`` on the KMS key that protects it,
so sharing the DynamoDB client does not let one tenant use another's Branch Key.
The factory's AWS KMS Key Store is therefore configured for Discovery:
it decrypts each Branch Key with the KMS key recorded in its item,
and AWS KMS authorizes the tenant's credentials for that key.
Creating a Branch Key requires the KMS key, so onboarding uses a Key Store configured with the tenant's KMS key.

If your tenants do not require distinct KMS credentials,
one AWS KMS Key Store and a Branch Key ID Supplier is simpler;
see ``hierarchical_keyring_example.py``.

See ``multi_tenant/design.md`` and ``multi_tenant/negative_caching.md`` for the options considered
and the decisions made.

This example requires access to the DDB Table where you are storing the Branch Keys. This
table must be configured with the following primary key configuration: - Partition key is named
"branch-key-id" with type (S) - Sort key is named "type" with type (S).

This example creates a Branch Key per tenant, with the Branch Key ID the caller assigns that tenant.
Branch Keys SHOULD NOT be deleted in production: deleting a Branch Key cryptographically shreds
every message it protected. This example's test deletes them only to keep the example table from growing.

This example also requires, for each tenant, credentials with the following access on that tenant's KMS key:
- GenerateDataKeyWithoutPlaintext
- ReEncrypt
- Decrypt

Every tenant's KMS key MUST be in the same AWS Region; use one factory per Region.
"""
import boto3
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import (
    CreateKeyInput,
    Discovery,
    KMSConfigurationDiscovery,
    KMSConfigurationKmsKeyArn,
)
from aws_cryptographic_material_providers.mpl.errors import OpaqueWithTextError
from aws_cryptographic_material_providers.mpl.references import IKeyring
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
from typing import Dict, Optional  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from .multi_tenant import KmsTransport, TenantKmsClient
from .multi_tenant.tenant_keyring_factory import TenantKeyringFactory

EXAMPLE_DATA: bytes = b"Hello World"


def _region(kms_key_arn: str) -> str:
    return kms_key_arn.split(":")[3]


def denied_kms_error(error: Exception) -> Optional[ClientError]:
    """Returns the AWS KMS error a negatively cached request failed with, or None.

    While a tenant's Branch Key is Denied, its keyring raises an ``OpaqueWithTextError``,
    whose ``obj`` is the ``ClientError`` AWS KMS returned for the Denied request.

    :param error: An error raised by encrypt or decrypt with a keyring from the Tenant Keyring Factory
    :returns: The ``ClientError``; its ``response["Error"]["Code"]`` is the KMS error code
    """
    if isinstance(error, OpaqueWithTextError) and isinstance(error.obj, ClientError):
        return error.obj
    return None


def encrypt_and_decrypt_with_keyring(
    key_store_table_name: str,
    logical_key_store_name: str,
    tenant_kms_key_ids: Dict[str, str],
    tenant_credentials: Dict[str, Credentials],
    tenant_branch_key_ids: Dict[str, str],
    ddb_region: str = "us-west-2",
) -> None:
    """Creates each tenant's Branch Key, then encrypts and decrypts a message for each tenant.

    :param key_store_table_name: Name of the DynamoDB table backing the AWS KMS Key Store
    :param logical_key_store_name: Logical name of the AWS KMS Key Store
    :param tenant_kms_key_ids: Map of tenant identifier to the ARN of that tenant's KMS key;
        every KMS key MUST be in the same AWS Region
    :param tenant_credentials: Map of tenant identifier to that tenant's credentials
    :param tenant_branch_key_ids: Map of tenant identifier to the Branch Key ID the application assigned that tenant;
        this example creates each, and fails if one already exists
    :param ddb_region: Region of the DynamoDB table
    :raises ValueError: if the tenants' KMS keys are in more than one AWS Region
    """
    kms_regions = {_region(kms_key_id) for kms_key_id in tenant_kms_key_ids.values()}
    if len(kms_regions) != 1:
        raise ValueError("Every tenant's KMS key must be in the same AWS Region; use one factory per Region")
    (kms_region,) = kms_regions

    # 1. Instantiate the encryption SDK client once, and share it.
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    # 2. Create one DynamoDB client, shared by every tenant's AWS KMS Key Store,
    #    and one transport for every tenant's KMS requests.
    ddb_client = boto3.client("dynamodb", region_name=ddb_region)
    transport = KmsTransport()

    try:
        # 3. Create one Tenant Keyring Factory, shared by every tenant.
        #    It creates the storm tracking cache every tenant's keyring shares,
        #    with the settings of default_storm_tracking_cache(), unless given others;
        #    it vends keyrings with a 600 second ttl_seconds, and a 300 second Negative TTL.
        #    Its AWS KMS Key Store is configured for Discovery, so one factory serves every tenant's KMS key.
        factory = TenantKeyringFactory(
            transport=transport,
            ddb_client=ddb_client,
            ddb_table_name=key_store_table_name,
            logical_key_store_name=logical_key_store_name,
            kms_configuration=KMSConfigurationDiscovery(value=Discovery()),
            region_name=kms_region,
        )

        for tenant, kms_key_id in tenant_kms_key_ids.items():
            # 4. Onboard the tenant: create its Branch Key, with the Branch Key ID the application assigned it.
            #    This calls kms:GenerateDataKeyWithoutPlaintext and kms:ReEncrypt, with this tenant's credentials,
            #    through an AWS KMS Key Store configured with the tenant's KMS key, as creating a Branch Key needs it.
            #    Applications usually create a tenant's Branch Key once, when the tenant is onboarded,
            #    with a Branch Key ID they choose, rather than one the AWS KMS Key Store generates.
            #    Branch Keys SHOULD NOT be deleted in production: deleting a Branch Key
            #    cryptographically shreds every message it protected. This example creates a new
            #    Branch Key per tenant on every run, so its test deletes them, to keep the table from growing.
            onboarding_key_store: KeyStore = KeyStore(
                config=KeyStoreConfig(
                    ddb_client=ddb_client,
                    ddb_table_name=key_store_table_name,
                    logical_key_store_name=logical_key_store_name,
                    kms_client=TenantKmsClient(
                        transport=transport,
                        region_name=kms_region,
                        credentials=tenant_credentials[tenant],
                    ),
                    kms_configuration=KMSConfigurationKmsKeyArn(value=kms_key_id),
                )
            )
            branch_key_id: str = onboarding_key_store.create_key(
                input=CreateKeyInput(
                    branch_key_identifier=tenant_branch_key_ids[tenant],
                    # Required with a chosen Branch Key ID. It is added to every AWS KMS request's encryption context,
                    # prefixed with "aws-crypto-ec:", so the tenant's KMS key policy can require it.
                    encryption_context={"tenant": tenant},
                )
            ).branch_key_identifier
            assert branch_key_id == tenant_branch_key_ids[tenant]

            # 5. Vend this tenant's Hierarchical Keyring.
            #    Its Partition ID is the tenant's identifier, and its Branch Key ID is static.
            #    The tenant identifier MUST be that of the tenant the application authenticated,
            #    and the Branch Key ID the one the application assigned that tenant:
            #    keyrings vended for the same pair share cache entries, whatever their credentials.
            #    A vended keyring is a few references; applications MAY vend one per request.
            hierarchical_keyring: IKeyring = factory.keyring_for(
                tenant_id=tenant,
                branch_key_id=branch_key_id,
                credentials=tenant_credentials[tenant],
            )

            # 6. Encrypt and decrypt with the tenant's keyring.
            #    On a Branch Key cache miss, the AWS KMS Key Store calls kms:Decrypt with the tenant's credentials.
            #    If AWS KMS denies it, this tenant's requests for this Branch Key fail for the Negative TTL,
            #    without calling DynamoDB or KMS, raising an OpaqueWithTextError; see denied_kms_error.
            encryption_context: Dict[str, str] = {
                "tenant": tenant,
                "encryption": "context",
                "is not": "secret",
            }
            ciphertext, _ = client.encrypt(
                source=EXAMPLE_DATA,
                keyring=hierarchical_keyring,
                encryption_context=encryption_context,
            )
            assert ciphertext != EXAMPLE_DATA, \
                "Ciphertext and plaintext data are the same. Invalid encryption"

            plaintext, _ = client.decrypt(
                source=ciphertext,
                keyring=hierarchical_keyring,
                encryption_context=encryption_context,
            )
            assert plaintext == EXAMPLE_DATA, \
                "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
    finally:
        # 7. Close the transport and the DynamoDB client only when the application shuts down.
        #    Both are shared by every tenant; this example owns them, and every tenant is done with them here.
        #    An application MUST NOT close either while any tenant's keyring may still use it:
        #    in-flight requests complete, but every pooled connection is dropped,
        #    so every tenant pays a new TLS handshake on its next request.
        transport.close()
        ddb_client.close()
