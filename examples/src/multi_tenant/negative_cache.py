# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Negative Cache Entries: records that AWS KMS Denied a Branch Key ID, honored for a Negative TTL.

See negative_caching.md in this directory for the options considered and the decisions made.

A ``BranchKeyNegativeCache`` holds the Negative Cache Entry, if any, of exactly one Branch Key ID.
One is shared by the Tenant KMS Client that records a Denial
and the Cache Guard that enforces it, for the same Tenant Hierarchical Keyring.

This module MUST NOT import the AWS Cryptographic Material Providers Library (MPL),
as the Tenant KMS Client, which records Denials, does not.
"""
import collections
import logging
import math
import threading
import time

import botocore.exceptions

_LOGGER = logging.getLogger(__name__)

#: Default Negative TTL, in seconds (negative_caching.md, Definitions).
DEFAULT_NEGATIVE_TTL_SECONDS = 300

#: AWS KMS error codes that are Denials (negative_caching.md, Design Question 5).
DENIAL_ERROR_CODES = frozenset(
    [
        # The Tenant's KMS Key, and its Key Policy or Grants
        "AccessDeniedException",
        "DisabledException",
        "KMSInvalidStateException",
        "NotFoundException",
        "IncorrectKeyException",
        # The Tenant's Credentials (negative_caching.md 5.1, 5.2)
        "ExpiredTokenException",
        "UnrecognizedClientException",
        "InvalidSignatureException",
    ]
)


class NegativeCacheEntry(
    collections.namedtuple("NegativeCacheEntry", ("branch_key_id", "error", "denied_at", "expires_at"))
):
    """A record that a Branch Key ID was Denied.

    Times are from the ``BranchKeyNegativeCache``'s clock (by default ``time.monotonic``), in seconds.

    :param str branch_key_id: The Denied Branch Key ID
    :param Exception error: The error AWS KMS returned, passed through as is by the Cache Guard
    :param float denied_at: When the Denial was recorded
    :param float expires_at: When the entry stops being honored; ``denied_at`` plus the Negative TTL
    """

    def is_honored(self, now):
        """Returns True if the entry is honored at ``now``; that is, ``now < expires_at``.

        :param float now: A time from the same clock as ``denied_at``
        :rtype: bool
        """
        return now < self.expires_at


def error_code(error):
    """Returns the AWS KMS error code of ``error``, or its type name if it is not a ``ClientError``.

    :param Exception error: Any error
    :rtype: str
    """
    if isinstance(error, botocore.exceptions.ClientError):
        return error.response.get("Error", {}).get("Code") or type(error).__name__
    return type(error).__name__


def is_denial(error):
    """Returns True if ``error`` is an AWS KMS error that is a Denial.

    Only a ``botocore.exceptions.ClientError`` whose ``response["Error"]["Code"]``
    is in ``DENIAL_ERROR_CODES`` is a Denial; every other error, including transport failures, is not.

    :param Exception error: Any error
    :rtype: bool
    """
    if not isinstance(error, botocore.exceptions.ClientError):
        return False
    return error_code(error) in DENIAL_ERROR_CODES


def validate_negative_ttl(negative_ttl):
    """Rejects a Negative TTL that is not a number greater than zero.

    :param float negative_ttl: Seconds a Negative Cache Entry is honored
    :raises ValueError: if ``negative_ttl`` is not a number greater than zero
    """
    # NaN is rejected explicitly: every comparison with NaN is False, so `negative_ttl <= 0` would accept it.
    if (
        isinstance(negative_ttl, bool)
        or not isinstance(negative_ttl, (int, float))
        or math.isnan(negative_ttl)
        or negative_ttl <= 0
    ):
        raise ValueError("negative_ttl must be a number greater than zero")


class BranchKeyNegativeCache(object):
    """The Negative Cache Entry, if any, of one Branch Key ID.

    Thread safe: Denials are recorded by a Tenant KMS Client and read by a Cache Guard, on any thread.

    :param str branch_key_id: The Branch Key ID this negative cache is for
    :param float negative_ttl: Seconds a Negative Cache Entry is honored; MUST be greater than zero
    :param clock: Returns the current time in seconds; for tests (default ``time.monotonic``)
    :raises ValueError: if ``branch_key_id`` is empty, or ``negative_ttl`` is not greater than zero
    """

    def __init__(self, branch_key_id, negative_ttl=DEFAULT_NEGATIVE_TTL_SECONDS, clock=time.monotonic):
        """Validates the Branch Key ID and Negative TTL."""
        if not isinstance(branch_key_id, str) or not branch_key_id:
            raise ValueError("branch_key_id must be a non-empty string")
        validate_negative_ttl(negative_ttl)
        self._branch_key_id = branch_key_id
        self._negative_ttl = negative_ttl
        self._clock = clock
        # Guards _entry. get() holds it across checking expiry and discarding,
        # so it never discards a Denial recorded after the entry it found expired.
        self._lock = threading.Lock()
        self._entry = None

    @property
    def branch_key_id(self):
        """The Branch Key ID this negative cache is for.

        :rtype: str
        """
        return self._branch_key_id

    @property
    def negative_ttl(self):
        """Seconds a Negative Cache Entry is honored.

        :rtype: float
        """
        return self._negative_ttl

    def record(self, error):
        """Records a Denial, replacing any existing Negative Cache Entry.

        The caller decides whether ``error`` is a Denial (see ``is_denial``); this does not.

        Logs a warning naming the Branch Key ID, the AWS KMS error code, the Negative TTL,
        and the error's text, AWS KMS's message included; which MAY name account ids or role ARNs,
        neither of which is secret.
        The Cache Guard's error does not name the code in its ``str()`` (negative_caching.md 4.3),
        so this is where an operator sees it.

        :param Exception error: The error AWS KMS returned
        :returns: The new Negative Cache Entry
        :rtype: NegativeCacheEntry
        """
        with self._lock:
            now = self._clock()
            entry = NegativeCacheEntry(
                branch_key_id=self._branch_key_id, error=error, denied_at=now, expires_at=now + self._negative_ttl
            )
            self._entry = entry
        _LOGGER.warning(
            "AWS KMS Denied Branch Key ID %s (%s); failing its requests for %s seconds: %s",
            self._branch_key_id,
            error_code(error),
            self._negative_ttl,
            error,
        )
        return entry

    def get(self):
        """Returns the honored Negative Cache Entry, if any.

        An entry that is no longer honored is discarded.

        :returns: The honored entry, or None
        :rtype: NegativeCacheEntry or None
        """
        with self._lock:
            entry = self._entry
            if entry is None:
                return None
            if entry.is_honored(self._clock()):
                return entry
            self._entry = None
            return None

    def clear(self):
        """Discards the Negative Cache Entry, if any."""
        with self._lock:
            self._entry = None
