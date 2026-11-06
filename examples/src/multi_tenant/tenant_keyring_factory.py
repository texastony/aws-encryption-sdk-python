# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Tenant Keyring Factory: vends Tenant Hierarchical Keyrings with negative caching.

See negative_caching.md in this directory, Design Question 7.2.

One factory per process holds everything every Tenant Hierarchical Keyring shares:
the Shared Transport, the storm tracking cache shared by every Tenant (which it creates),
the DynamoDB client, the AWS KMS Key Store configuration (other than its KMS client),
the cache limit TTL, and the Negative TTL.

Given a Tenant, a Branch Key ID, and the Tenant's Credentials, it vends a Tenant Hierarchical Keyring, built with:

- a Tenant KMS Client, recording Denials in the negative cache of that Tenant and Branch Key ID
- an AWS KMS Key Store, using that Tenant KMS Client
- a Cache Guard, enforcing that negative cache, delegating to the shared cache
- the Branch Key ID, statically
- a Partition ID derived from the Tenant's identifier, which, unlike its credentials, is stable (negative_caching.md 8)

It takes the Branch Key ID Supplier's place:
the application selects the Branch Key ID, and asks the factory for its keyring.

The factory, and everything it vends, is thread safe (Requirement 8).

This module imports the MPL.
"""
import threading
import time

from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    CacheTypeShared,
    CacheTypeStormTracking,
    CreateAwsKmsHierarchicalKeyringInput,
    CreateCryptographicMaterialsCacheInput,
    StormTrackingCache,
    TimeUnits,
)

from .cache_guard import CacheGuard
from .kms_transport import KmsTransport, validate_region_name
from .negative_cache import DEFAULT_NEGATIVE_TTL_SECONDS, BranchKeyNegativeCache, validate_negative_ttl
from .tenant_kms_client import TenantKmsClient

#: The default cache limit TTL of the vended Hierarchical Keyrings, in seconds.
DEFAULT_TTL_SECONDS = 600


def default_storm_tracking_cache():
    """Returns the default settings of the storm tracking cache a factory creates and shares.

    The values, and why, are design.md 10.1.1.
    These are illustrative; applications SHOULD tune every one of them to their own usage pattern.

    :rtype: aws_cryptographic_material_providers.mpl.models.StormTrackingCache
    """
    return StormTrackingCache(
        # Maximum Branch Keys cached, across every Tenant.
        entry_capacity=1000,
        entry_pruning_tail_size=1,
        grace_period=10_000,
        grace_interval=1_000,
        # Shared by every Tenant: the MPL default of 20 would serialize a burst of Tenants missing at once.
        fan_out=100,
        # A failed fetch holds its fan out slot this long; lowered from the MPL default of 10 seconds.
        in_flight_ttl=5_000,
        sleep_milli=20,
        # MUST be set: a StormTrackingCache defaults to seconds.
        time_units=TimeUnits.MILLISECONDS,
    )


def tenant_partition_id(tenant_id):
    """Returns the Partition ID of a Tenant's Hierarchical Keyrings: the Tenant's identifier, as is.

    Derived from the Tenant's identifier, so it is constant across credential refreshes,
    unlike a Partition ID derived from the credentials (negative_caching.md 8).

    :param str tenant_id: The Tenant's stable identifier
    :rtype: str
    :raises ValueError: if ``tenant_id`` is empty
    """
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id must be a non-empty string")
    return tenant_id


def _validate_name(name, value):
    if not isinstance(value, str) or not value:
        raise ValueError("{} must be a non-empty string".format(name))


def _grace_period_seconds(settings):
    """The storm tracking cache's grace period, in seconds; a StormTrackingCache defaults to seconds."""
    if settings.time_units == TimeUnits.MILLISECONDS:
        return settings.grace_period / 1000
    return settings.grace_period


class TenantKeyringFactory(object):  # pylint: disable=too-many-instance-attributes
    """Vends Tenant Hierarchical Keyrings that share one transport, cache, DynamoDB client, and Key Store configuration.

    The factory creates, and owns, the storm tracking cache every Tenant shares,
    so it can require its grace period be less than the keyrings' cache limit TTL,
    as the specification does (aws-kms-hierarchical-keyring.md, Initialization).

    :param transport: The Shared Transport
    :type transport: KmsTransport
    :param ddb_client: The DynamoDB client, shared by every Tenant's AWS KMS Key Store
    :param str ddb_table_name: The AWS KMS Key Store's DynamoDB table
    :param str logical_key_store_name: The AWS KMS Key Store's Logical Key Store Name
    :param kms_configuration: The AWS KMS Key Store's AWS KMS Configuration, including Discovery and MRDiscovery
    :param str region_name: The AWS Region of the Tenant KMS Clients
    :param int ttl_seconds: The vended Hierarchical Keyrings' cache limit TTL (default 600)
    :param float negative_ttl: Seconds a Negative Cache Entry is honored (default 300)
    :param storm_tracking_cache: Settings of the storm tracking cache the factory creates and shares
        (default ``default_storm_tracking_cache()``)
    :type storm_tracking_cache: aws_cryptographic_material_providers.mpl.models.StormTrackingCache
    :param clock: Returns the current time in seconds, for the negative caches; for tests (default ``time.monotonic``)
    :raises TypeError: if ``transport`` is not a ``KmsTransport``,
        or ``storm_tracking_cache`` is not a ``StormTrackingCache``
    :raises ValueError: if a name is empty, the region is invalid, a TTL is not greater than zero,
        or the storm tracking cache's grace period is not less than ``ttl_seconds``
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        transport,
        ddb_client,
        ddb_table_name,
        logical_key_store_name,
        kms_configuration,
        region_name,
        ttl_seconds=DEFAULT_TTL_SECONDS,
        negative_ttl=DEFAULT_NEGATIVE_TTL_SECONDS,
        storm_tracking_cache=None,
        clock=time.monotonic,
    ):
        """Validates what every vended keyring shares, and creates the shared cache."""
        if not isinstance(transport, KmsTransport):
            raise TypeError("transport must be a KmsTransport")
        _validate_name("ddb_table_name", ddb_table_name)
        _validate_name("logical_key_store_name", logical_key_store_name)
        validate_region_name(region_name)
        # An int: the Hierarchical Keyring's ttl_seconds is a whole number of seconds.
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be an integer greater than zero")
        validate_negative_ttl(negative_ttl)
        if storm_tracking_cache is None:
            storm_tracking_cache = default_storm_tracking_cache()
        if not isinstance(storm_tracking_cache, StormTrackingCache):
            raise TypeError("storm_tracking_cache must be a StormTrackingCache")
        # The specification: the grace period MUST be less than the cache limit TTL
        # (aws-kms-hierarchical-keyring.md, Initialization). Only the factory knows both.
        if _grace_period_seconds(storm_tracking_cache) >= ttl_seconds:
            raise ValueError("the storm tracking cache's grace period must be less than ttl_seconds")

        self._transport = transport
        self._ddb_client = ddb_client
        self._ddb_table_name = ddb_table_name
        self._logical_key_store_name = logical_key_store_name
        self._kms_configuration = kms_configuration
        self._region_name = region_name
        self._ttl_seconds = ttl_seconds
        self._negative_ttl = negative_ttl
        self._clock = clock
        self._mpl = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())
        # Created here, from the settings, so every vended keyring shares this one cache.
        self._shared_cache = self._mpl.create_cryptographic_materials_cache(
            input=CreateCryptographicMaterialsCacheInput(cache=CacheTypeStormTracking(value=storm_tracking_cache))
        )
        # Guards _negative_caches: concurrent requests for a Tenant and Branch Key ID get one negative cache.
        # Needed even with the GIL, as the lookup and the insert are separate steps; and free threaded CPython
        # has no GIL. It is held only for that lookup and insert: keyring_for builds the Key Store and keyring
        # outside it. Whether one lock contends at service startup is an open question (negative_caching.md).
        self._lock = threading.Lock()
        self._negative_caches = {}

    @property
    def shared_cache(self):
        """The storm tracking cache shared by every Tenant, which this factory created.

        :rtype: aws_cryptographic_material_providers.mpl.references.ICryptographicMaterialsCache
        """
        return self._shared_cache

    @property
    def negative_ttl(self):
        """Seconds a Negative Cache Entry is honored.

        :rtype: float
        """
        return self._negative_ttl

    def negative_cache_for(self, tenant_id, branch_key_id):
        """Returns the negative cache of a Tenant and Branch Key ID; the same object on every call.

        Keyed by Tenant as well as Branch Key ID:
        a Tenant misconfigured with another Tenant's Branch Key ID,
        and so Denied, MUST NOT deny that Branch Key ID to the Tenant that owns it.

        :param str tenant_id: The Tenant's stable identifier
        :param str branch_key_id: The Branch Key ID
        :rtype: BranchKeyNegativeCache
        :raises ValueError: if ``tenant_id`` or ``branch_key_id`` is empty
        """
        key = (tenant_partition_id(tenant_id), branch_key_id)
        with self._lock:
            negative_cache = self._negative_caches.get(key)
            if negative_cache is None:
                negative_cache = BranchKeyNegativeCache(
                    branch_key_id, negative_ttl=self._negative_ttl, clock=self._clock
                )
                self._negative_caches[key] = negative_cache
            return negative_cache

    def keyring_for(self, tenant_id, branch_key_id, credentials):
        """Vends a Tenant Hierarchical Keyring for a Tenant's Branch Key ID.

        Every keyring vended for the same Tenant and Branch Key ID shares one negative cache,
        so a Denial recorded through one is enforced by all.

        A vended keyring is a few references; applications MAY vend one per request or per tenant connection,
        rather than caching them.
        Every keyring vended for the same ``tenant_id`` and ``branch_key_id`` shares the same cache entries,
        whatever its credentials: while an entry is cached, it is served without AWS KMS authorizing those
        credentials. So the application MUST pass the ``tenant_id`` of the Tenant it authenticated,
        never one taken from the request, and the ``branch_key_id`` it assigned that Tenant
        (negative_caching.md 8).

        :param str tenant_id: The Tenant's stable identifier
        :param str branch_key_id: The Branch Key ID
        :param credentials: The Tenant's Credentials
        :type credentials: botocore.credentials.Credentials
        :rtype: aws_cryptographic_material_providers.mpl.references.IKeyring
        :raises ValueError: if ``tenant_id`` or ``branch_key_id`` is empty
        """
        negative_cache = self.negative_cache_for(tenant_id, branch_key_id)
        # Records Denials of this Branch Key ID, for this Tenant, in its negative cache.
        kms_client = TenantKmsClient(
            transport=self._transport,
            region_name=self._region_name,
            credentials=credentials,
            negative_cache=negative_cache,
        )
        key_store = KeyStore(
            config=KeyStoreConfig(
                ddb_client=self._ddb_client,
                ddb_table_name=self._ddb_table_name,
                logical_key_store_name=self._logical_key_store_name,
                kms_client=kms_client,
                kms_configuration=self._kms_configuration,
            )
        )
        return self._mpl.create_aws_kms_hierarchical_keyring(
            input=CreateAwsKmsHierarchicalKeyringInput(
                key_store=key_store,
                branch_key_id=branch_key_id,
                ttl_seconds=self._ttl_seconds,
                # Enforces the negative cache before every lookup, delegating to the shared cache.
                cache=CacheTypeShared(value=CacheGuard(self._shared_cache, negative_cache)),
                partition_id=tenant_partition_id(tenant_id),
            )
        )


__all__ = ("TenantKeyringFactory", "tenant_partition_id", "default_storm_tracking_cache", "DEFAULT_TTL_SECONDS")
