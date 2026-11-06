# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the per-tenant KMS client."""
# pylint: disable=redefined-outer-name,protected-access
import botocore.exceptions
import pytest
from botocore.credentials import Credentials

from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ...src.multi_tenant.negative_cache import DENIAL_ERROR_CODES, BranchKeyNegativeCache
from ...src.multi_tenant.tenant_kms_client import METHOD_TO_API_MAPPING
from . import fake_kms

# Offline: no network access, so these also run as local tests (tox: exampleslocal, mplexampleslocal).
pytestmark = [pytest.mark.examples, pytest.mark.local]

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
KEY_A2 = "arn:aws:kms:us-west-2:111122223333:key/a2a2a2a2-a2a2-a2a2-a2a2-a2a2a2a2a2a2"
KEY_B = "arn:aws:kms:us-west-2:444455556666:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TENANT_A = Credentials("AKIATENANTA", "secret-a", "token-a")
TENANT_B = Credentials("AKIATENANTB", "secret-b")
EC = {"tenant": "A"}


@pytest.fixture
def transport():
    return KmsTransport()


@pytest.fixture
def kms(transport):
    fake = fake_kms.install(transport)
    fake.add_key(KEY_A, TENANT_A.access_key)
    fake.add_key(KEY_A2, TENANT_A.access_key)
    fake.add_key(KEY_B, TENANT_B.access_key)
    return fake


@pytest.fixture
def client_a(transport, kms):  # pylint: disable=unused-argument
    return TenantKmsClient(transport=transport, region_name="us-west-2", credentials=TENANT_A)


@pytest.fixture
def client_b(transport, kms):  # pylint: disable=unused-argument
    return TenantKmsClient(transport=transport, region_name="us-west-2", credentials=TENANT_B)


def test_all_operations_round_trip_bytes(client_a, kms):
    generated = client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32, EncryptionContext=EC)
    assert isinstance(generated["Plaintext"], bytes) and len(generated["Plaintext"]) == 32
    assert isinstance(generated["CiphertextBlob"], bytes)
    assert generated["ResponseMetadata"]["HTTPStatusCode"] == 200

    decrypted = client_a.decrypt(CiphertextBlob=generated["CiphertextBlob"], EncryptionContext=EC, KeyId=KEY_A)
    assert decrypted["Plaintext"] == generated["Plaintext"]

    encrypted = client_a.encrypt(KeyId=KEY_A, Plaintext=b"\x00\x01data", EncryptionContext=EC)
    assert client_a.decrypt(CiphertextBlob=encrypted["CiphertextBlob"], EncryptionContext=EC)["Plaintext"] == (
        b"\x00\x01data"
    )

    without = client_a.generate_data_key_without_plaintext(KeyId=KEY_A, KeySpec="AES_256", EncryptionContext=EC)
    assert "Plaintext" not in without

    re_encrypted = client_a.re_encrypt(
        CiphertextBlob=without["CiphertextBlob"],
        SourceKeyId=KEY_A,
        SourceEncryptionContext=EC,
        DestinationKeyId=KEY_A2,
        DestinationEncryptionContext={"tenant": "A", "version": "2"},
    )
    assert re_encrypted["SourceKeyId"] == KEY_A
    assert re_encrypted["KeyId"] == KEY_A2

    assert [request["operation"] for request in kms.requests] == [
        "GenerateDataKey", "Decrypt", "Encrypt", "Decrypt", "GenerateDataKeyWithoutPlaintext", "ReEncrypt",
    ]
    assert {request["access_key"] for request in kms.requests} == {"AKIATENANTA"}


def test_each_tenant_signs_with_its_own_credentials(client_a, client_b, kms):
    client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    client_b.generate_data_key(KeyId=KEY_B, NumberOfBytes=32)
    client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    assert [request["access_key"] for request in kms.requests] == ["AKIATENANTA", "AKIATENANTB", "AKIATENANTA"]


def test_tenant_cannot_use_another_tenants_key(client_a, client_b):
    ciphertext = client_a.encrypt(KeyId=KEY_A, Plaintext=b"secret", EncryptionContext=EC)["CiphertextBlob"]
    with pytest.raises(botocore.exceptions.ClientError) as excinfo:
        client_b.decrypt(CiphertextBlob=ciphertext, EncryptionContext=EC)
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"


def test_unknown_and_missing_parameters_fail_before_any_request(client_a, kms):
    with pytest.raises(botocore.exceptions.ParamValidationError) as excinfo:
        client_a.decrypt(CiphertextBlob=b"x", aws_access_key_id="AKIAOTHER")
    assert "aws_access_key_id" in str(excinfo.value)
    with pytest.raises(botocore.exceptions.ParamValidationError) as excinfo:
        client_a.re_encrypt(CiphertextBlob=b"x")
    assert "DestinationKeyId" in str(excinfo.value)
    with pytest.raises(botocore.exceptions.ParamValidationError) as excinfo:
        client_a.encrypt(KeyId=KEY_A, Plaintext=12345)
    assert "12345" not in str(excinfo.value)
    assert not kms.requests


def test_meta_matches_what_the_mpl_and_mkps_touch(client_a):
    assert client_a.meta.region_name == "us-west-2"
    assert client_a.meta.config.user_agent_extra is None
    client_a.meta.config.user_agent_extra = "AwsCryptographicMPL/Python"
    assert set(client_a.meta.method_to_api_mapping) == set(METHOD_TO_API_MAPPING)
    for method_name in client_a.meta.method_to_api_mapping:
        assert callable(getattr(client_a, method_name))


def test_user_agent_extra_is_read_per_request(client_a, kms):
    client_a.meta.config.user_agent_extra = "AwsCryptographicMPL/Python"
    client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    assert kms.requests[0]["user_agent"].endswith(" AwsCryptographicMPL/Python")


def test_repr_never_includes_credentials(client_a):
    text = repr(client_a)
    assert "us-west-2" in text
    for secret in ("AKIATENANTA", "secret-a", "token-a"):
        assert secret not in text


@pytest.mark.parametrize("kwargs, error", [
    ({"transport": object(), "region_name": "us-west-2", "credentials": TENANT_A}, TypeError),
    ({"region_name": "evil.example.com", "credentials": TENANT_A}, ValueError),
    ({"region_name": "us-west-2", "credentials": "AKIATENANTA"}, TypeError),
])
def test_invalid_construction(transport, kwargs, error):
    kwargs.setdefault("transport", transport)
    with pytest.raises(error):
        TenantKmsClient(**kwargs)


# Recording Denials (negative_caching.md 3.3, 6).


@pytest.fixture
def negative():
    return BranchKeyNegativeCache("bk-a")


def _guarded_client(transport, credentials, negative):
    return TenantKmsClient(
        transport=transport, region_name="us-west-2", credentials=credentials, negative_cache=negative
    )


def _ciphertext_under(client_a, encryption_context):
    response = client_a.encrypt(KeyId=KEY_A, Plaintext=b"branch key", EncryptionContext=encryption_context)
    return response["CiphertextBlob"]


@pytest.mark.usefixtures("kms")  # installs the fake KMS on the transport
def test_a_decrypt_denial_is_recorded_as_the_same_error(transport, client_a, negative):
    ciphertext = _ciphertext_under(client_a, {"branch-key-id": "bk-a"})
    client_b = _guarded_client(transport, TENANT_B, negative)  # tenant B's credentials cannot use KEY_A
    with pytest.raises(botocore.exceptions.ClientError) as excinfo:
        client_b.decrypt(CiphertextBlob=ciphertext, EncryptionContext={"branch-key-id": "bk-a"})
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"
    assert negative.get() is not None
    assert negative.get().error is excinfo.value  # recorded, and re-raised, as is


@pytest.mark.parametrize("code", sorted(DENIAL_ERROR_CODES))
def test_every_denial_code_on_decrypt_is_recorded(transport, kms, negative, code):
    kms.scripted = [fake_kms.FakeResponse(400, {"__type": "com.amazonaws.kms#" + code, "message": "denied"})]
    client = _guarded_client(transport, TENANT_A, negative)
    with pytest.raises(botocore.exceptions.ClientError):
        client.decrypt(CiphertextBlob=b"x", EncryptionContext={"branch-key-id": "bk-a"})
    assert negative.get().error.response["Error"]["Code"] == code


@pytest.mark.parametrize("failure", [
    fake_kms.FakeResponse(400, {"__type": "ThrottlingException", "message": "slow down"}),
    fake_kms.FakeResponse(500, {"__type": "KMSInternalException", "message": "oops"}),
])
def test_transient_failures_are_not_recorded(transport, kms, negative, failure):
    kms.scripted = [failure] * 3  # every attempt
    client = _guarded_client(transport, TENANT_A, negative)
    with pytest.raises(botocore.exceptions.ClientError):
        client.decrypt(CiphertextBlob=b"x", EncryptionContext={"branch-key-id": "bk-a"})
    assert negative.get() is None


@pytest.mark.parametrize("method, params", [
    ("generate_data_key", {"KeyId": KEY_A, "NumberOfBytes": 32}),
    ("generate_data_key_without_plaintext", {"KeyId": KEY_A, "NumberOfBytes": 32}),
    ("encrypt", {"KeyId": KEY_A, "Plaintext": b"x"}),
    ("re_encrypt", {"CiphertextBlob": b"x", "DestinationKeyId": KEY_A}),
])
def test_denials_of_other_operations_are_not_recorded(transport, kms, negative, method, params):
    # A Denial is a failure to decrypt a Branch Key; creating or versioning one is not that.
    kms.scripted = [fake_kms.FakeResponse(400, {"__type": "AccessDeniedException", "message": "denied"})]
    client = _guarded_client(transport, TENANT_A, negative)
    with pytest.raises(botocore.exceptions.ClientError):
        getattr(client, method)(**params)
    assert negative.get() is None


def test_a_denial_of_another_branch_key_id_is_not_recorded(transport, kms, negative):
    kms.scripted = [fake_kms.FakeResponse(400, {"__type": "AccessDeniedException", "message": "denied"})]
    client = _guarded_client(transport, TENANT_A, negative)
    with pytest.raises(botocore.exceptions.ClientError):
        client.decrypt(CiphertextBlob=b"x", EncryptionContext={"branch-key-id": "bk-other"})
    assert negative.get() is None


@pytest.mark.parametrize("encryption_context", [None, {}, {"aws-crypto-ec:department": "admin"}])
def test_a_denial_without_a_branch_key_id_in_the_encryption_context_is_recorded(
    transport, kms, negative, encryption_context
):
    # The AWS KMS Key Store always includes branch-key-id (hierarchy version 1, the only one shipped);
    # without it, the Denial is attributed to the Branch Key ID the client is bound to.
    kms.scripted = [fake_kms.FakeResponse(400, {"__type": "AccessDeniedException", "message": "denied"})]
    client = _guarded_client(transport, TENANT_A, negative)
    params = {"CiphertextBlob": b"x"}
    if encryption_context is not None:
        params["EncryptionContext"] = encryption_context
    with pytest.raises(botocore.exceptions.ClientError):
        client.decrypt(**params)
    assert negative.get() is not None


def test_without_a_negative_cache_nothing_is_recorded_and_the_error_is_unchanged(kms, client_a):
    kms.scripted = [fake_kms.FakeResponse(400, {"__type": "AccessDeniedException", "message": "denied"})]
    assert client_a.negative_cache is None
    with pytest.raises(botocore.exceptions.ClientError) as excinfo:
        client_a.decrypt(CiphertextBlob=b"x")
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"


def test_negative_cache_must_be_a_branch_key_negative_cache(transport):
    with pytest.raises(TypeError):
        TenantKmsClient(transport=transport, region_name="us-west-2", credentials=TENANT_A, negative_cache=object())
