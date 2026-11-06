# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the Tenant Keyring Factory (negative_caching.md, Design Question 7.2).

The end-to-end tests seed the shared cache under the specification's cache identifiers,
with the Partition ID the factory derives from the Tenant, so vended keyrings encrypt and decrypt from cache hits;
any call to Amazon DynamoDB or AWS KMS is counted, and asserted to be zero.
"""
# pylint: disable=redefined-outer-name
import threading
import uuid

import boto3
import pytest
from aws_cryptographic_material_providers.keystore.models import KMSConfigurationKmsKeyArn
from aws_cryptographic_material_providers.mpl.errors import OpaqueWithTextError
from aws_cryptographic_material_providers.mpl.models import StormTrackingCache, TimeUnits
from aws_cryptographic_material_providers.mpl.references import ICryptographicMaterialsCache
from botocore.credentials import Credentials
from botocore.stub import Stubber

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ...src.multi_tenant import KmsTransport
from ...src.multi_tenant.negative_cache import BranchKeyNegativeCache
from ...src.multi_tenant.tenant_keyring_factory import (
    DEFAULT_TTL_SECONDS,
    TenantKeyringFactory,
    default_storm_tracking_cache,
    tenant_partition_id,
)
from ...src.multi_tenant_hierarchical_keyring_example import denied_kms_error
from . import fake_kms
from .helpers import FakeClock, kms_error
from .keyring_helpers import branch_key_materials, decrypt_cache_id, encrypt_cache_id, put_input

# Offline: no network access, so these also run as local tests (tox: mplexampleslocal).
pytestmark = [pytest.mark.examples, pytest.mark.local]

KMS_KEY = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TABLE = "KeyStoreTable"
TENANT_A = Credentials("AKIATENANTA", "secret-a")
TENANT_B = Credentials("AKIATENANTB", "secret-b")


# tenant_partition_id (negative_caching.md 8)


def test_partition_id_is_the_tenant_id_as_is():
    # Not a secret, so not digested (negative_caching.md 8); stable across credential refreshes.
    assert tenant_partition_id("tenant-a") == "tenant-a"
    assert tenant_partition_id("tenant-a") != tenant_partition_id("tenant-b")


def test_partition_id_rejects_an_empty_tenant():
    with pytest.raises(ValueError):
        tenant_partition_id("")


# Construction


@pytest.fixture
def remote_calls():
    """Count every DynamoDB and KMS request; the end-to-end tests assert there are none."""
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
def clock():
    return FakeClock()


def factory_arguments(remote_calls, clock, overrides=None):
    arguments = {
        "transport": remote_calls["transport"],
        "ddb_client": remote_calls["ddb"],
        "ddb_table_name": TABLE,
        "logical_key_store_name": TABLE,
        "kms_configuration": KMSConfigurationKmsKeyArn(value=KMS_KEY),
        "region_name": "us-west-2",
        "negative_ttl": 60,
        "clock": clock,
    }
    # A dict, not **overrides: an override named like a parameter here (clock)
    # would make this function raise TypeError itself, and pass a test expecting one.
    arguments.update(overrides or {})
    return arguments


@pytest.fixture
def factory(remote_calls, clock):
    return TenantKeyringFactory(**factory_arguments(remote_calls, clock))


def test_defaults(remote_calls):
    arguments = factory_arguments(remote_calls, None)
    del arguments["negative_ttl"], arguments["clock"]
    factory = TenantKeyringFactory(**arguments)
    assert factory.negative_ttl == 300
    assert DEFAULT_TTL_SECONDS == 600


def test_default_storm_tracking_cache_settings():
    # The values, and why, are design.md 10.1.1.
    settings = default_storm_tracking_cache()
    assert isinstance(settings, StormTrackingCache)
    assert (settings.entry_capacity, settings.entry_pruning_tail_size) == (1000, 1)
    assert (settings.grace_period, settings.grace_interval) == (10_000, 1_000)
    assert (settings.fan_out, settings.in_flight_ttl, settings.sleep_milli) == (100, 5_000, 20)
    assert settings.time_units == TimeUnits.MILLISECONDS
    assert default_storm_tracking_cache() is not settings  # a new object; callers may change theirs


def test_the_factory_creates_and_owns_one_shared_cache(factory):
    shared_cache = factory.shared_cache
    assert isinstance(shared_cache, ICryptographicMaterialsCache)
    assert factory.shared_cache is shared_cache  # one cache, created once


def test_custom_storm_tracking_cache_settings_are_accepted(remote_calls, clock):
    settings = default_storm_tracking_cache()
    settings.fan_out = 7
    factory = TenantKeyringFactory(**factory_arguments(remote_calls, clock, {"storm_tracking_cache": settings}))
    assert isinstance(factory.shared_cache, ICryptographicMaterialsCache)


def test_grace_period_just_under_the_cache_limit_ttl_is_accepted(remote_calls, clock):
    # The default grace period is 10,000 milliseconds: 10 seconds.
    TenantKeyringFactory(**factory_arguments(remote_calls, clock, {"ttl_seconds": 11}))


def _seconds_storm(grace_period):
    settings = default_storm_tracking_cache()
    settings.time_units = TimeUnits.SECONDS
    settings.grace_period, settings.grace_interval, settings.in_flight_ttl = grace_period, 1, 1
    return settings


@pytest.mark.parametrize("overrides, error", [
    ({"transport": object()}, TypeError),
    ({"storm_tracking_cache": object()}, TypeError),
    # The specification: the grace period MUST be less than the cache limit TTL.
    ({"ttl_seconds": 10}, ValueError),  # equal: 10,000 milliseconds is 10 seconds
    ({"ttl_seconds": 600, "storm_tracking_cache": _seconds_storm(600)}, ValueError),  # equal, in seconds
    ({"ttl_seconds": 600, "storm_tracking_cache": _seconds_storm(700)}, ValueError),
    ({"ddb_table_name": ""}, ValueError),
    ({"logical_key_store_name": ""}, ValueError),
    ({"region_name": "evil.example.com"}, ValueError),
    ({"ttl_seconds": 0}, ValueError),
    ({"negative_ttl": 0}, ValueError),
])
def test_invalid_construction(remote_calls, clock, overrides, error):
    with pytest.raises(error):
        TenantKeyringFactory(**factory_arguments(remote_calls, clock, overrides))


# negative_cache_for


def test_negative_cache_is_one_object_per_tenant_and_branch_key_id(factory):
    negative = factory.negative_cache_for("tenant-a", "bk-a")
    assert isinstance(negative, BranchKeyNegativeCache)
    assert negative.branch_key_id == "bk-a"
    assert negative.negative_ttl == 60
    assert factory.negative_cache_for("tenant-a", "bk-a") is negative
    assert factory.negative_cache_for("tenant-a", "bk-b") is not negative
    # Keyed by Tenant too: a misconfigured Tenant's Denial MUST NOT deny the Branch Key ID to its owner.
    assert factory.negative_cache_for("tenant-b", "bk-a") is not negative


def test_negative_caches_use_the_factory_clock(factory, clock):
    negative = factory.negative_cache_for("tenant-a", "bk-a")
    negative.record(kms_error())
    clock.now += 60
    assert negative.get() is None


def test_negative_cache_for_is_thread_safe(factory):
    # Requirement 8: concurrent requests for one Tenant and Branch Key ID MUST share one negative cache.
    found, start = [], threading.Barrier(16)

    def lookup():
        start.wait()
        found.append(factory.negative_cache_for("tenant-a", "bk-a"))

    threads = [threading.Thread(target=lookup) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len({id(negative) for negative in found}) == 1


# keyring_for, end to end: vended keyrings encrypt and decrypt from the shared cache.


def seed(shared_cache, tenant_id, branch_key_id):
    """Put a Branch Key in the shared cache under the Tenant's Partition ID; returns its materials."""
    version = str(uuid.uuid4())
    materials = branch_key_materials(branch_key_id, version)
    partition_id = tenant_partition_id(tenant_id)
    shared_cache.put_cache_entry(put_input(encrypt_cache_id(partition_id, TABLE, branch_key_id), materials))
    shared_cache.put_cache_entry(put_input(decrypt_cache_id(partition_id, TABLE, branch_key_id, version), materials))
    return materials


@pytest.fixture
def esdk():
    return aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)


def assert_no_remote_calls(remote_calls):
    assert remote_calls["ddb_calls"] == []
    assert remote_calls["kms"].requests == []


def test_vended_keyring_uses_the_shared_cache_under_the_tenant_partition(factory, remote_calls, esdk):
    seed(factory.shared_cache, "tenant-a", "bk-a")
    keyring = factory.keyring_for("tenant-a", "bk-a", TENANT_A)
    ciphertext, _ = esdk.encrypt(source=b"tenant data", keyring=keyring)
    plaintext, _ = esdk.decrypt(source=ciphertext, keyring=keyring)
    assert plaintext == b"tenant data"
    assert_no_remote_calls(remote_calls)


def test_vended_keyring_is_guarded_by_its_negative_cache(factory, remote_calls, esdk):
    seed(factory.shared_cache, "tenant-a", "bk-a")
    keyring = factory.keyring_for("tenant-a", "bk-a", TENANT_A)
    error = kms_error("AccessDeniedException")
    factory.negative_cache_for("tenant-a", "bk-a").record(error)
    with pytest.raises(OpaqueWithTextError) as excinfo:
        esdk.encrypt(source=b"tenant data", keyring=keyring)
    assert excinfo.value.obj is error
    assert_no_remote_calls(remote_calls)
    # The example's documented way to unwrap it.
    assert denied_kms_error(excinfo.value) is error
    assert denied_kms_error(excinfo.value).response["Error"]["Code"] == "AccessDeniedException"


def test_denied_kms_error_is_none_for_other_errors():
    assert denied_kms_error(ValueError("not a Denial")) is None
    assert denied_kms_error(OpaqueWithTextError(obj=ValueError("not from AWS KMS"), obj_message="x")) is None


def test_keyrings_vended_for_one_tenant_and_branch_key_share_a_denial(factory, remote_calls, esdk):
    seed(factory.shared_cache, "tenant-a", "bk-a")
    first = factory.keyring_for("tenant-a", "bk-a", TENANT_A)
    second = factory.keyring_for("tenant-a", "bk-a", TENANT_A)
    factory.negative_cache_for("tenant-a", "bk-a").record(kms_error())
    for keyring in (first, second):
        with pytest.raises(OpaqueWithTextError):
            esdk.encrypt(source=b"tenant data", keyring=keyring)
    assert_no_remote_calls(remote_calls)


def test_a_denial_is_isolated_to_its_tenant_and_branch_key(factory, remote_calls, esdk):
    # Requirement 2, per Branch Key ID; and per Tenant (see negative_cache_for).
    seed(factory.shared_cache, "tenant-a", "bk-a")
    seed(factory.shared_cache, "tenant-a", "bk-other")
    seed(factory.shared_cache, "tenant-b", "bk-a")
    factory.negative_cache_for("tenant-b", "bk-a").record(kms_error())  # tenant B, misconfigured with bk-a
    for tenant_id, branch_key_id, credentials in (
        ("tenant-a", "bk-a", TENANT_A),
        ("tenant-a", "bk-other", TENANT_A),
    ):
        keyring = factory.keyring_for(tenant_id, branch_key_id, credentials)
        ciphertext, _ = esdk.encrypt(source=b"tenant data", keyring=keyring)
        assert esdk.decrypt(source=ciphertext, keyring=keyring)[0] == b"tenant data"
    with pytest.raises(OpaqueWithTextError):
        esdk.encrypt(source=b"tenant data", keyring=factory.keyring_for("tenant-b", "bk-a", TENANT_B))
    assert_no_remote_calls(remote_calls)


def test_tenants_do_not_share_cache_entries(factory, remote_calls, esdk):
    # tenant-b's keyring for bk-a misses tenant-a's entries (another Partition ID), so it calls DynamoDB.
    seed(factory.shared_cache, "tenant-a", "bk-a")
    with pytest.raises(Exception) as excinfo:  # pylint: disable=broad-except
        esdk.encrypt(source=b"tenant data", keyring=factory.keyring_for("tenant-b", "bk-a", TENANT_B))
    assert excinfo.value is not None  # the stubbed DynamoDB client has no response for it
    assert remote_calls["ddb_calls"] == ["GetItem"]
