# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test helpers for the negative caching tests that use the MPL.

Branch Key materials, cache entries, the specification's cache identifiers, and finding the Cache Guard's error.
"""
import hashlib
import os
import time

from aws_cryptographic_material_providers.keystore.models import BranchKeyMaterials
from aws_cryptographic_material_providers.mpl.errors import OpaqueWithTextError
from aws_cryptographic_material_providers.mpl.models import MaterialsBranchKey, PutCacheEntryInput


def branch_key_materials(branch_key_id, version):
    return BranchKeyMaterials(
        branch_key_identifier=branch_key_id,
        branch_key_version=version,
        encryption_context={},
        branch_key=os.urandom(32),
    )


def put_input(identifier, materials, now=None):
    now = int(time.time()) if now is None else now
    return PutCacheEntryInput(
        identifier=identifier,
        materials=MaterialsBranchKey(value=materials),
        creation_time=now,
        expiry_time=now + 600,
        messages_used=0,
        bytes_used=0,
    )


def denial_within(raised):
    """Return the Cache Guard's OpaqueWithTextError within ``raised``, or None.

    On encrypt, the ESDK raises it; on decrypt, it is within the MPL's CollectionOfErrors,
    within the ESDK's AWSEncryptionSDKClientError (negative_caching.md 4.3).
    """
    pending, seen = [raised], set()
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        if isinstance(error, OpaqueWithTextError):
            return error
        for attribute in ("list", "args"):
            value = getattr(error, attribute, None) or ()
            pending.extend(child for child in value if isinstance(child, BaseException))
    return None


def encrypt_cache_id(partition_id, logical_key_store_name, branch_key_id):
    """aws-kms-hierarchical-keyring.md, Appendix A, Encryption Materials."""
    return hashlib.sha384(
        b"\x02\x00\x01\x00" + partition_id.encode() + b"\x00" + logical_key_store_name.encode()
        + b"\x00" + branch_key_id.encode()
    ).digest()


def decrypt_cache_id(partition_id, logical_key_store_name, branch_key_id, version):
    """aws-kms-hierarchical-keyring.md, Appendix A, Decryption Materials."""
    return hashlib.sha384(
        b"\x02\x00\x02\x00" + partition_id.encode() + b"\x00" + logical_key_store_name.encode()
        + b"\x00" + branch_key_id.encode() + b"\x00" + version.encode()
    ).digest()
