# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the Cache Guard (negative_caching.md, Design Question 4.3).

The end-to-end tests seed the shared cache under the cache identifiers the specification defines
(aws-kms-hierarchical-keyring.md, Appendix A), so a real Hierarchical Keyring encrypts and decrypts
from cache hits; any call to Amazon DynamoDB or AWS KMS is counted, and asserted to be zero.
"""
# pylint: disable=redefined-outer-name
import threading
import uuid

import boto3
import pytest
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import KMSConfigurationKmsKeyArn
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.errors import EntryDoesNotExist, OpaqueWithTextError
from aws_cryptographic_material_providers.mpl.models import (
    CacheTypeDefault,
    CacheTypeShared,
    CreateAwsKmsHierarchicalKeyringInput,
    CreateCryptographicMaterialsCacheInput,
    DefaultCache,
    DeleteCacheEntryInput,
    GetCacheEntryInput,
    UpdateUsageMetadataInput,
)
from aws_cryptographic_material_providers.mpl.references import ICryptographicMaterialsCache
from botocore.credentials import Credentials
from botocore.stub import Stubber

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ...src.multi_tenant.cache_guard import CacheGuard
from ...src.multi_tenant.negative_cache import BranchKeyNegativeCache
from . import fake_kms
from .helpers import FakeClock, kms_error
from .keyring_helpers import branch_key_materials, decrypt_cache_id, denial_within, encrypt_cache_id, put_input

# Offline: no network access, so these also run as local tests (tox: mplexampleslocal).
pytestmark = [pytest.mark.examples, pytest.mark.local]

KMS_KEY = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TABLE = "KeyStoreTable"
TENANT = Credentials("AKIATENANTA", "secret-a")


class SpyCache(ICryptographicMaterialsCache):
    """A native cache that records every call, and misses unless given an output."""

    def __init__(self, output=None):
        """Return ``output`` from get_cache_entry, or miss."""
        self.output = output
        self.calls = []

    def get_cache_entry(self, param):
        """Record, then hit or miss."""
        self.calls.append(("get", param))
        if self.output is None:
            raise EntryDoesNotExist(message="miss")
        return self.output

    def put_cache_entry(self, param):
        """Record."""
        self.calls.append(("put", param))

    def update_usage_metadata(self, param):
        """Record."""
        self.calls.append(("update", param))

    def delete_cache_entry(self, param):
        """Record."""
        self.calls.append(("delete", param))


@pytest.fixture
def mat_prov():
    return AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())


@pytest.fixture
def shared_cache(mat_prov):
    return mat_prov.create_cryptographic_materials_cache(
        input=CreateCryptographicMaterialsCacheInput(cache=CacheTypeDefault(value=DefaultCache(entry_capacity=100)))
    )


@pytest.fixture
def clock():
    return FakeClock()


# Construction


def test_construction(shared_cache):
    negative = BranchKeyNegativeCache("bk-a")
    guard = CacheGuard(delegate=shared_cache, negative_cache=negative)
    assert isinstance(guard, ICryptographicMaterialsCache)
    assert guard.negative_cache is negative


@pytest.mark.parametrize("kwargs", [
    {"delegate": object()},
    {"negative_cache": object()},
])
def test_invalid_construction(shared_cache, kwargs):
    arguments = {"delegate": shared_cache, "negative_cache": BranchKeyNegativeCache("bk-a")}
    arguments.update(kwargs)
    with pytest.raises(TypeError):
        CacheGuard(**arguments)


# Native interface, with no Denial: every operation is delegated.


def test_hit_passes_through_the_real_shared_cache(shared_cache):
    guard = CacheGuard(delegate=shared_cache, negative_cache=BranchKeyNegativeCache("bk-a"))
    materials = branch_key_materials("bk-a", str(uuid.uuid4()))
    guard.put_cache_entry(put_input(b"\x01" * 48, materials))
    output = guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x01" * 48))
    assert output.materials.value.branch_key == materials.branch_key


def test_miss_passes_through_as_entry_does_not_exist(shared_cache):
    guard = CacheGuard(delegate=shared_cache, negative_cache=BranchKeyNegativeCache("bk-a"))
    with pytest.raises(EntryDoesNotExist):
        guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x02" * 48))


def test_put_update_and_delete_are_delegated_as_is():
    spy = SpyCache()
    guard = CacheGuard(delegate=spy, negative_cache=BranchKeyNegativeCache("bk-a"))
    put = put_input(b"\x03" * 48, branch_key_materials("bk-a", str(uuid.uuid4())))
    update = UpdateUsageMetadataInput(identifier=b"\x03" * 48, bytes_used=1)
    delete = DeleteCacheEntryInput(identifier=b"\x03" * 48)
    guard.put_cache_entry(put)
    guard.update_usage_metadata(update)
    guard.delete_cache_entry(delete)
    assert spy.calls == [("put", put), ("update", update), ("delete", delete)]


# Native interface, with a Denial.


def test_denied_raises_the_recorded_error_wrapped_without_consulting_the_shared_cache():
    spy = SpyCache()
    negative = BranchKeyNegativeCache("bk-a")
    guard = CacheGuard(delegate=spy, negative_cache=negative)
    error = kms_error()
    negative.record(error)
    with pytest.raises(OpaqueWithTextError) as excinfo:
        guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x04" * 48))
    assert excinfo.value.obj is error  # the same object, as is
    assert excinfo.value.obj_message == str(error)
    assert "AccessDeniedException" in excinfo.value.obj_message
    assert not spy.calls


def test_each_denied_lookup_raises_a_new_wrapper():
    # Re-raising one exception object grows its traceback on every raise; a new wrapper per raise does not.
    negative = BranchKeyNegativeCache("bk-a")
    guard = CacheGuard(delegate=SpyCache(), negative_cache=negative)
    error = kms_error()
    negative.record(error)
    raised = []
    for _ in range(3):
        with pytest.raises(OpaqueWithTextError) as excinfo:
            guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x04" * 48))
        raised.append(excinfo.value)
    assert len({id(wrapper) for wrapper in raised}) == 3
    assert all(wrapper.obj is error for wrapper in raised)
    assert error.__traceback__ is None


def test_denied_refuses_a_cached_hit(shared_cache):
    # Requirement 3: while Denied, the Branch Key ID's cached materials MUST NOT be used.
    negative = BranchKeyNegativeCache("bk-a")
    guard = CacheGuard(delegate=shared_cache, negative_cache=negative)
    guard.put_cache_entry(put_input(b"\x05" * 48, branch_key_materials("bk-a", str(uuid.uuid4()))))
    negative.record(kms_error())
    with pytest.raises(OpaqueWithTextError):
        guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x05" * 48))


def test_delegates_again_once_the_negative_ttl_expires(shared_cache, clock):
    negative = BranchKeyNegativeCache("bk-a", negative_ttl=60, clock=clock)
    guard = CacheGuard(delegate=shared_cache, negative_cache=negative)
    guard.put_cache_entry(put_input(b"\x06" * 48, branch_key_materials("bk-a", str(uuid.uuid4()))))
    negative.record(kms_error())
    clock.now += 60
    assert guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x06" * 48)) is not None


def test_a_denial_does_not_affect_another_branch_key_on_the_same_shared_cache(shared_cache):
    # Requirement 2.
    negative_a = BranchKeyNegativeCache("bk-a")
    guard_a = CacheGuard(delegate=shared_cache, negative_cache=negative_a)
    guard_b = CacheGuard(delegate=shared_cache, negative_cache=BranchKeyNegativeCache("bk-b"))
    guard_b.put_cache_entry(put_input(b"\x07" * 48, branch_key_materials("bk-b", str(uuid.uuid4()))))
    negative_a.record(kms_error())
    with pytest.raises(OpaqueWithTextError):
        guard_a.get_cache_entry(GetCacheEntryInput(identifier=b"\x08" * 48))
    assert guard_b.get_cache_entry(GetCacheEntryInput(identifier=b"\x07" * 48)) is not None


def _lookup_once(guard, error, failures):
    """Look up once; anything but the spy's miss or the recorded error is a failure."""
    try:
        guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x09" * 48))
    except EntryDoesNotExist:
        pass  # not Denied: the spy's miss
    except OpaqueWithTextError as raised:
        if raised.obj is not error:
            failures.append(raised)
    except Exception as unexpected:  # pylint: disable=broad-except
        failures.append(unexpected)


def _toggle(negative, error, times):
    """Alternately record and clear the Denial."""
    for i in range(times):
        if i % 2:
            negative.record(error)
        else:
            negative.clear()


def test_thread_safety():
    # Requirement 8: lookups on any thread while Denials are recorded and cleared.
    negative = BranchKeyNegativeCache("bk-a")
    guard = CacheGuard(delegate=SpyCache(), negative_cache=negative)
    error = kms_error()
    failures = []
    start = threading.Barrier(9)

    def lookups():
        start.wait()
        for _ in range(1000):
            _lookup_once(guard, error, failures)

    def toggles():
        start.wait()
        _toggle(negative, error, 1000)

    threads = [threading.Thread(target=lookups) for _ in range(8)] + [threading.Thread(target=toggles)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures

    # The toggler's last action (i == 999, odd) records the Denial; so the guard ends Denied.
    with pytest.raises(OpaqueWithTextError) as excinfo:
        guard.get_cache_entry(GetCacheEntryInput(identifier=b"\x09" * 48))
    assert excinfo.value.obj is error


# End to end: a real Hierarchical Keyring, with the Cache Guard as its CacheTypeShared cache.


@pytest.fixture
def remote_calls():
    """Count every DynamoDB and KMS request the keyring makes; the tests assert there are none."""
    ddb = boto3.client("dynamodb", region_name="us-west-2", aws_access_key_id="AKIAFAKE", aws_secret_access_key="x")
    ddb_calls = []
    ddb.meta.events.register(
        # provide-client-params: the first event, before the Stubber rejects an unstubbed call
        "provide-client-params.dynamodb", lambda **kwargs: ddb_calls.append(kwargs["model"].name)
    )
    transport = KmsTransport()
    kms = fake_kms.install(transport)
    with Stubber(ddb):  # no responses queued: a DynamoDB call fails, and is counted
        yield {"ddb": ddb, "ddb_calls": ddb_calls, "transport": transport, "kms": kms}


@pytest.fixture
def guarded(mat_prov, shared_cache, remote_calls):
    """Build a Tenant Hierarchical Keyring with a Cache Guard, and seed its Branch Key in the shared cache."""
    branch_key_id, version, partition_id = "bk-a", str(uuid.uuid4()), "tenant-a"
    materials = branch_key_materials(branch_key_id, version)
    shared_cache.put_cache_entry(put_input(encrypt_cache_id(partition_id, TABLE, branch_key_id), materials))
    shared_cache.put_cache_entry(put_input(decrypt_cache_id(partition_id, TABLE, branch_key_id, version), materials))

    negative = BranchKeyNegativeCache(branch_key_id)
    key_store = KeyStore(
        config=KeyStoreConfig(
            ddb_client=remote_calls["ddb"],
            ddb_table_name=TABLE,
            logical_key_store_name=TABLE,
            kms_client=TenantKmsClient(remote_calls["transport"], "us-west-2", TENANT),
            kms_configuration=KMSConfigurationKmsKeyArn(value=KMS_KEY),
        )
    )
    keyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=CreateAwsKmsHierarchicalKeyringInput(
            key_store=key_store,
            branch_key_id=branch_key_id,
            ttl_seconds=600,
            cache=CacheTypeShared(value=CacheGuard(delegate=shared_cache, negative_cache=negative)),
            partition_id=partition_id,
        )
    )
    esdk = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
    return {"keyring": keyring, "negative": negative, "esdk": esdk}


def assert_no_remote_calls(remote_calls):
    assert remote_calls["ddb_calls"] == []
    assert remote_calls["kms"].requests == []


def test_keyring_accepts_the_cache_guard_and_uses_cached_hits(guarded, remote_calls):
    esdk, keyring = guarded["esdk"], guarded["keyring"]
    ciphertext, _ = esdk.encrypt(source=b"tenant data", keyring=keyring)
    plaintext, _ = esdk.decrypt(source=ciphertext, keyring=keyring)
    assert plaintext == b"tenant data"
    assert_no_remote_calls(remote_calls)


@pytest.mark.parametrize("code", ["AccessDeniedException", "DisabledException"])
def test_denied_keyring_fails_encrypt_without_calling_dynamodb_or_kms(guarded, remote_calls, code):
    # Requirement 1, and Requirement 3: the cached hit is refused.
    # DisabledException is a KMS error the MPL models; it would lose its code as a ComAmazonawsKms error.
    error = kms_error(code)
    guarded["negative"].record(error)
    with pytest.raises(OpaqueWithTextError) as excinfo:
        guarded["esdk"].encrypt(source=b"tenant data", keyring=guarded["keyring"])
    # The cause is reachable, the same object, after the MPL's conversion to and from Dafny (negative_caching.md 4.3).
    assert excinfo.value.obj is error
    assert code in excinfo.value.obj_message
    assert_no_remote_calls(remote_calls)


@pytest.mark.parametrize("code", ["AccessDeniedException", "DisabledException"])
def test_denied_keyring_fails_decrypt_without_calling_dynamodb_or_kms(guarded, remote_calls, code):
    # Encrypt and decrypt are treated the same (negative_caching.md 4.3).
    ciphertext, _ = guarded["esdk"].encrypt(source=b"tenant data", keyring=guarded["keyring"])
    error = kms_error(code)
    guarded["negative"].record(error)
    with pytest.raises(aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError) as excinfo:
        guarded["esdk"].decrypt(source=ciphertext, keyring=guarded["keyring"])
    denial = denial_within(excinfo.value)
    assert denial is not None, "the Cache Guard's error is not within the ESDK's"
    assert denial.obj is error
    assert code in denial.obj_message
    assert_no_remote_calls(remote_calls)


def test_keyring_recovers_when_the_denial_is_cleared(guarded, remote_calls):
    guarded["negative"].record(kms_error())
    with pytest.raises(OpaqueWithTextError):
        guarded["esdk"].encrypt(source=b"tenant data", keyring=guarded["keyring"])
    guarded["negative"].clear()
    ciphertext, _ = guarded["esdk"].encrypt(source=b"tenant data", keyring=guarded["keyring"])
    plaintext, _ = guarded["esdk"].decrypt(source=ciphertext, keyring=guarded["keyring"])
    assert plaintext == b"tenant data"
    assert_no_remote_calls(remote_calls)
