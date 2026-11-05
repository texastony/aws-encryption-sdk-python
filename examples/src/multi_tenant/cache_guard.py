# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Cache Guard: fails a Hierarchical Keyring's cache lookups for a Denied Branch Key ID.

See negative_caching.md in this directory, Design Question 4.3.

A ``CacheGuard`` is a Cryptographic Materials Cache, one per Tenant Hierarchical Keyring,
wrapping the cache shared by every Tenant. It is passed to the keyring as ``CacheTypeShared``.

While its ``BranchKeyNegativeCache`` has an honored Negative Cache Entry,
``get_cache_entry`` raises the error AWS KMS returned, the same object,
wrapped so that it survives the MPL's conversion to and from Dafny (negative_caching.md 4.3),
before consulting the shared cache; so a cached hit is not returned (Requirement 3).
The MPL treats any error other than ``EntryDoesNotExist`` as a failure,
and the Hierarchical Keyring fails without calling Amazon DynamoDB or AWS KMS (Requirement 1).
Otherwise, every operation is delegated to the shared cache.

The Cache Guard is a lightweight object: it holds a reference to the shared cache
and a reference to its Branch Key ID's negative cache.

This module imports the MPL; ``negative_cache.py`` does not.
"""
from aws_cryptographic_material_providers.mpl.errors import OpaqueWithTextError
from aws_cryptographic_material_providers.mpl.references import ICryptographicMaterialsCache

from .negative_cache import BranchKeyNegativeCache


class CacheGuard(ICryptographicMaterialsCache):
    """A Cryptographic Materials Cache that fails lookups for a Denied Branch Key ID.

    :param delegate: The cache shared by every Tenant; an MPL cache
        (from ``create_cryptographic_materials_cache``) or any ``ICryptographicMaterialsCache``
    :type delegate: aws_cryptographic_material_providers.mpl.references.ICryptographicMaterialsCache
    :param negative_cache: The negative cache of this keyring's Branch Key ID
    :type negative_cache: BranchKeyNegativeCache
    :raises TypeError: if ``delegate`` is not an ``ICryptographicMaterialsCache``,
        or ``negative_cache`` is not a ``BranchKeyNegativeCache``
    """

    def __init__(self, delegate, negative_cache):  # pylint: disable=super-init-not-called
        """Validates and stores the shared cache and the negative cache."""
        if not isinstance(delegate, ICryptographicMaterialsCache):
            raise TypeError("delegate must be an ICryptographicMaterialsCache")
        if not isinstance(negative_cache, BranchKeyNegativeCache):
            raise TypeError("negative_cache must be a BranchKeyNegativeCache")
        self._delegate = delegate
        self._negative_cache = negative_cache

    @property
    def negative_cache(self):
        """The negative cache of this keyring's Branch Key ID.

        :rtype: BranchKeyNegativeCache
        """
        return self._negative_cache

    def get_cache_entry(self, param):
        """Raises the Denial's error, wrapped, while it is honored; otherwise delegates.

        :param param: The lookup
        :type param: aws_cryptographic_material_providers.mpl.models.GetCacheEntryInput
        :rtype: aws_cryptographic_material_providers.mpl.models.GetCacheEntryOutput
        :raises aws_cryptographic_material_providers.mpl.errors.OpaqueWithTextError:
            while Denied; ``obj`` is the Negative Cache Entry's error, the same object,
            and ``obj_message`` is its text, which names the AWS KMS error code
        :raises aws_cryptographic_material_providers.mpl.errors.EntryDoesNotExist: from the shared cache, on a miss
        """
        # Checked before the shared cache: a Denied Branch Key ID's cached materials MUST NOT be used,
        # and a miss in a storm tracking cache would block concurrent callers (negative_caching.md 4.3).
        entry = self._negative_cache.get()
        if entry is not None:
            # OpaqueWithTextError, because it survives the MPL's conversion to and from Dafny intact:
            # Dafny's opaque errors carry the Python object itself, so `obj` is the error AWS KMS returned,
            # the same object; and `obj_message` keeps its text, which names the KMS error code.
            # A ComAmazonawsKms error would lose both: Dafny keeps only its data, and for the KMS errors
            # the MPL models (DisabledException, KMSInvalidStateException, NotFoundException,
            # IncorrectKeyException) only their message, without the code (negative_caching.md 4.3).
            # A new wrapper per raise also keeps the error's own traceback from growing on every raise.
            raise OpaqueWithTextError(obj=entry.error, obj_message=str(entry.error))
        return self._delegate.get_cache_entry(param)

    def put_cache_entry(self, param):
        """Delegates to the shared cache.

        :param param: The entry
        :type param: aws_cryptographic_material_providers.mpl.models.PutCacheEntryInput
        """
        return self._delegate.put_cache_entry(param)

    def update_usage_metadata(self, param):
        """Delegates to the shared cache.

        :param param: The usage
        :type param: aws_cryptographic_material_providers.mpl.models.UpdateUsageMetadataInput
        """
        return self._delegate.update_usage_metadata(param)

    def delete_cache_entry(self, param):
        """Delegates to the shared cache.

        :param param: The entry to delete
        :type param: aws_cryptographic_material_providers.mpl.models.DeleteCacheEntryInput
        """
        return self._delegate.delete_cache_entry(param)


__all__ = ("CacheGuard", "BranchKeyNegativeCache")
