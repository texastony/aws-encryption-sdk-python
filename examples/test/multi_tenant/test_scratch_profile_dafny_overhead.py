# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
r"""SCRATCH, for review; to be removed: how much time the Dafny generated code and its translation layers take.

Skipped unless opted in, as ``test_scratch_real_kms_tenant_roles.py``, whose fixtures it uses (real AWS KMS,
DynamoDB Local, and each tenant's assumed role). Run with ``-s`` to see the report::

    SCRATCH_REAL_KMS=1 DDB_LOCAL_ENDPOINT=http://localhost:8000 \
    SCRATCH_TENANT_A_ROLE_ARN=... SCRATCH_TENANT_B_ROLE_ARN=... \
        python -m pytest -s -m ddblocal examples/test/multi_tenant/test_scratch_profile_dafny_overhead.py

It measures a vended Tenant Hierarchical Keyring, 1 KiB messages:

- warm: the Branch Key is cached; no DynamoDB or KMS call. The steady state.
- vend: vending a keyring, with no request; building the AWS KMS Key Store and Hierarchical Keyring is MPL work.
- cold: a cache miss on every operation, forced by vending each keyring under a new Tenant identifier
  (so a new Partition ID): one DynamoDB GetItem and one real kms:Decrypt each. Includes vending the keyring.

For each, the wall time per operation without a profiler; then, under cProfile, each function's own time
(tottime) by where its code lives. A built-in (C) function's time is charged to the bucket of its caller,
so (for example) bytes handling called by Dafny generated code counts as Dafny.

For scale, the same ESDK operations with a native Python ``RawMasterKeyProvider``, which uses neither the MPL
nor Dafny. It is not like for like: it wraps the data key under a static AES key, with no Branch Key derivation.

cProfile's own overhead is per call, so it inflates code that makes many small calls, as generated code does;
the profiled shares are an upper bound on the Dafny buckets. The unprofiled wall times are the ground truth.
"""
# pylint: disable=redefined-outer-name,unused-import
import collections
import cProfile
import os
import pstats
import time

from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

from .test_scratch_real_kms_tenant_roles import esdk, pytestmark, remote_calls, tenants  # noqa: F401

MESSAGE = os.urandom(1024)
WARM_OPERATIONS = 300
COLD_OPERATIONS = 20

# (bucket, path fragments); the first match wins, so more specific fragments come first.
BUCKETS = (
    ("our code (multi_tenant)", ("/examples/src/",)),
    ("Dafny generated code", ("/internaldafny/generated/", "/smithy_dafny_standard_library/")),
    ("Dafny externs (hand written, called by Dafny)", ("/internaldafny/extern/",)),
    ("Dafny runtime (_dafny)", ("/_dafny/",)),
    (
        "Smithy translation and MPL Python wrappers",
        ("/smithygenerated/", "/smithy_python/", "/aws_cryptographic_material_providers/mpl/",
         "/aws_cryptographic_material_providers/keystore/"),
    ),
    ("ESDK (aws_encryption_sdk)", ("/aws_encryption_sdk/",)),
    ("cryptography / OpenSSL", ("/cryptography/",)),
    ("botocore (signing, DynamoDB client)", ("/botocore/", "/boto3/")),
    ("network (urllib3, ssl, socket)", ("/urllib3/", "/ssl.py", "/socket.py", "/http/client.py", "/selectors.py")),
)
OTHER = "Python standard library, other"


def bucket_of(filename):
    for name, fragments in BUCKETS:
        if any(fragment in filename for fragment in fragments):
            return name
    return OTHER


def self_time_by_bucket(profile):
    """Sum each function's own time by bucket, charging a built-in's time to its callers' buckets."""
    stats = pstats.Stats(profile).stats
    totals = collections.Counter()
    for (filename, _, _), (_, _, own, _, callers) in stats.items():
        if filename != "~":
            totals[bucket_of(filename)] += own
            continue
        charged = 0.0
        for (caller_filename, _, _), (_, _, own_from_caller, _) in callers.items():
            totals[bucket_of(caller_filename) if caller_filename != "~" else OTHER] += own_from_caller
            charged += own_from_caller
        totals[OTHER] += max(own - charged, 0.0)
    return totals


def measure(label, operation, count):
    """Time count operations without a profiler, then profile another count; print both."""
    start = time.perf_counter()
    for _ in range(count):
        operation()
    unprofiled = (time.perf_counter() - start) / count

    profile = cProfile.Profile()
    profile.enable()
    for _ in range(count):
        operation()
    profile.disable()
    totals = self_time_by_bucket(profile)
    profiled_total = sum(totals.values())

    print("\n{}: {:.3f} ms per operation, unprofiled ({} operations)".format(label, unprofiled * 1000, count))
    print("  profiled: {:.3f} ms per operation; own time by bucket:".format(profiled_total / count * 1000))
    for name, seconds in totals.most_common():
        print("    {:5.1f}%  {:8.3f} ms/op  {}".format(100 * seconds / profiled_total, seconds / count * 1000, name))
    return unprofiled, totals


def dafny_share(totals):
    dafny = sum(seconds for name, seconds in totals.items() if "Dafny" in name or "Smithy" in name)
    return dafny / sum(totals.values())


def test_scratch_profile_vended_keyring(tenants, esdk):  # noqa: F811 pylint: disable=too-many-locals
    factory = tenants["factory"]
    tenant = tenants["tenant-a"]
    keyring = factory.keyring_for("tenant-a", tenant["branch_key_id"], tenant["credentials"])
    ciphertext, _ = esdk.encrypt(source=MESSAGE, keyring=keyring)
    assert esdk.decrypt(source=ciphertext, keyring=keyring)[0] == MESSAGE  # both cache entries are now warm

    print("\n=== Tenant Hierarchical Keyring, {} byte messages ===".format(len(MESSAGE)))
    _, warm_encrypt = measure("warm encrypt", lambda: esdk.encrypt(source=MESSAGE, keyring=keyring), WARM_OPERATIONS)
    _, warm_decrypt = measure("warm decrypt", lambda: esdk.decrypt(source=ciphertext, keyring=keyring), WARM_OPERATIONS)

    counter = iter(range(10 ** 6))
    # Vending a keyring builds a Tenant KMS Client, an AWS KMS Key Store, and a Hierarchical Keyring, through the MPL;
    # each cold operation below includes it.
    vend = measure("vend a keyring (no request)", lambda: factory.keyring_for(
        "tenant-a-vend-{}".format(next(counter)), tenant["branch_key_id"], tenant["credentials"]), WARM_OPERATIONS)[1]

    def cold_keyring():
        # A new Tenant identifier is a new Partition ID: every lookup misses the shared cache.
        return factory.keyring_for("tenant-a-cold-{}".format(next(counter)), tenant["branch_key_id"],
                                   tenant["credentials"])

    _, cold_encrypt = measure("cold encrypt", lambda: esdk.encrypt(source=MESSAGE, keyring=cold_keyring()),
                              COLD_OPERATIONS)
    _, cold_decrypt = measure("cold decrypt", lambda: esdk.decrypt(source=ciphertext, keyring=cold_keyring()),
                              COLD_OPERATIONS)

    print("\n=== For scale: native Python RawMasterKeyProvider (no MPL, no Dafny) ===")
    provider = _NativeStaticKeyProvider()
    provider.add_master_key("static-key")
    native_ciphertext, _ = esdk.encrypt(source=MESSAGE, key_provider=provider)
    measure("native encrypt", lambda: esdk.encrypt(source=MESSAGE, key_provider=provider), WARM_OPERATIONS)
    measure("native decrypt", lambda: esdk.decrypt(source=native_ciphertext, key_provider=provider), WARM_OPERATIONS)

    print("\n=== Dafny generated code + runtime + externs + Smithy translation, share of profiled own time ===")
    for label, totals in (("vend a keyring", vend), ("warm encrypt", warm_encrypt), ("warm decrypt", warm_decrypt),
                          ("cold encrypt", cold_encrypt), ("cold decrypt", cold_decrypt)):
        print("  {:13s} {:5.1f}%".format(label, 100 * dafny_share(totals)))


class _NativeStaticKeyProvider(RawMasterKeyProvider):
    """A RawMasterKeyProvider with one static AES-256 key: the ESDK's native Python path."""

    provider_id = "scratch-static"
    _KEY = os.urandom(32)

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=self._KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )
