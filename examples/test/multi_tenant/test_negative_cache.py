# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for Negative Cache Entries (negative_caching.md)."""
# pylint: disable=redefined-outer-name
import logging
import threading

import botocore.exceptions
import pytest

from ...src.multi_tenant.negative_cache import (
    DEFAULT_NEGATIVE_TTL_SECONDS,
    DENIAL_ERROR_CODES,
    BranchKeyNegativeCache,
    NegativeCacheEntry,
    error_code,
    is_denial,
)
from .helpers import FakeClock, kms_error

# Offline: no network access, so these also run as local tests (tox: mplexampleslocal).
pytestmark = [pytest.mark.examples, pytest.mark.local]

BKID = "bbb9baf1-03e6-4716-a586-6bf29995314b"


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def negative(clock):
    return BranchKeyNegativeCache(BKID, negative_ttl=60, clock=clock)


# Design Question 5: what is a Denial.


def test_denial_codes_are_exactly_the_design():
    assert DENIAL_ERROR_CODES == {
        "AccessDeniedException",
        "DisabledException",
        "KMSInvalidStateException",
        "NotFoundException",
        "IncorrectKeyException",
        "ExpiredTokenException",
        "UnrecognizedClientException",
        "InvalidSignatureException",
    }


@pytest.mark.parametrize("code", sorted(DENIAL_ERROR_CODES))
def test_denials(code):
    assert is_denial(kms_error(code)) is True


@pytest.mark.parametrize("code", ["ThrottlingException", "KMSInternalException", "DependencyTimeoutException", "500"])
def test_transient_kms_errors_are_not_denials(code):
    assert is_denial(kms_error(code)) is False


@pytest.mark.parametrize("error", [
    botocore.exceptions.EndpointConnectionError(endpoint_url="https://kms.us-west-2.amazonaws.com"),
    botocore.exceptions.ReadTimeoutError(endpoint_url="https://kms.us-west-2.amazonaws.com"),
    botocore.exceptions.NoCredentialsError(),
    ValueError("not a KMS error"),
])
def test_other_errors_are_not_denials(error):
    assert is_denial(error) is False


def test_error_code():
    assert error_code(kms_error("DisabledException")) == "DisabledException"
    assert error_code(ValueError("not a KMS error")) == "ValueError"


# NegativeCacheEntry


def test_entry_is_honored_until_it_expires():
    error = kms_error("AccessDeniedException")
    entry = NegativeCacheEntry(branch_key_id=BKID, error=error, denied_at=10.0, expires_at=70.0)
    assert entry.is_honored(10.0)
    assert entry.is_honored(69.999)
    assert not entry.is_honored(70.0)
    assert not entry.is_honored(100.0)


# BranchKeyNegativeCache


def test_defaults():
    negative = BranchKeyNegativeCache(BKID)
    assert negative.branch_key_id == BKID
    assert negative.negative_ttl == DEFAULT_NEGATIVE_TTL_SECONDS == 300
    assert negative.get() is None


@pytest.mark.parametrize("kwargs", [
    {"branch_key_id": ""},
    {"branch_key_id": BKID, "negative_ttl": 0},
    {"branch_key_id": BKID, "negative_ttl": -1},
    {"branch_key_id": BKID, "negative_ttl": float("nan")},
])
def test_invalid_construction(kwargs):
    with pytest.raises(ValueError):
        BranchKeyNegativeCache(**kwargs)


def test_nothing_recorded(negative):
    assert negative.get() is None


def test_record_then_get(negative):
    error = kms_error("AccessDeniedException")
    entry = negative.record(error)
    assert entry == NegativeCacheEntry(branch_key_id=BKID, error=error, denied_at=1000.0, expires_at=1060.0)
    assert negative.get() == entry
    assert negative.get().error is error  # the same object, passed through as is


def test_entry_expires_after_the_negative_ttl(negative, clock):
    negative.record(kms_error("AccessDeniedException"))
    clock.now = 1059.9
    assert negative.get() is not None
    clock.now = 1060.0
    assert negative.get() is None
    # Discarded, not merely hidden: it stays gone even if the clock went backwards.
    clock.now = 1000.0
    assert negative.get() is None


def test_record_replaces_the_entry_and_restarts_the_negative_ttl(negative, clock):
    negative.record(kms_error("AccessDeniedException"))
    clock.now = 1050.0
    second = kms_error("DisabledException")
    entry = negative.record(second)
    assert entry.denied_at == 1050.0 and entry.expires_at == 1110.0
    clock.now = 1100.0
    assert negative.get().error is second


def test_record_logs_one_warning_naming_the_branch_key_code_and_message(negative, caplog):
    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "arn:aws:sts::111122223333:assumed-role/Tenant is not"}},
        "Decrypt",
    )
    with caplog.at_level(logging.WARNING, logger="examples.src.multi_tenant.negative_cache"):
        negative.record(error)
        negative.get()  # reads do not log
    records = [record for record in caplog.records if record.name.endswith("multi_tenant.negative_cache")]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert BKID in records[0].getMessage() and "AccessDeniedException" in records[0].getMessage()
    assert "60" in records[0].getMessage()
    # AWS KMS's message, account id and role ARN included; neither is secret.
    assert "arn:aws:sts::111122223333:assumed-role/Tenant is not" in records[0].getMessage()


def test_clear(negative):
    negative.record(kms_error("AccessDeniedException"))
    negative.clear()
    assert negative.get() is None
    negative.clear()  # clearing nothing is fine


def test_record_does_not_classify(negative):
    # The Tenant KMS Client decides what is a Denial (is_denial); record() trusts its caller.
    negative.record(kms_error("ThrottlingException"))
    assert negative.get() is not None


def test_thread_safety():
    # Requirement 8: Denials are recorded and read on any thread.
    negative = BranchKeyNegativeCache(BKID, negative_ttl=60)
    errors = [kms_error(code) for code in sorted(DENIAL_ERROR_CODES)]
    failures = []
    start = threading.Barrier(16)

    def worker(index):
        try:
            start.wait()
            for i in range(2000):
                action = (index + i) % 3
                if action == 0:
                    entry = negative.record(errors[(index + i) % len(errors)])
                    # The real clock: times are floats, so the TTL is compared approximately.
                    assert entry.branch_key_id == BKID and entry.expires_at - entry.denied_at == pytest.approx(60)
                elif action == 1:
                    entry = negative.get()
                    assert entry is None or entry.error in errors
                else:
                    negative.clear()
        except Exception as error:  # pylint: disable=broad-except
            failures.append(error)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures
    final = negative.record(errors[0])
    assert negative.get() == final


class RacingClock(FakeClock):  # pylint: disable=too-few-public-methods
    """A fake clock that, once armed, runs ``on_tick`` the next time the arming thread reads it.

    ``get()`` reads the clock to decide whether an entry has expired;
    so ``on_tick`` runs inside ``get()``, between reading the entry and discarding it.
    """

    def __init__(self, now=1000.0):
        """Start disarmed."""
        super().__init__(now)
        self.on_tick = None
        self.armed_thread = None

    def arm(self, on_tick):
        """Run ``on_tick`` on this thread's next read of the clock."""
        self.on_tick = on_tick
        self.armed_thread = threading.current_thread()

    def __call__(self):
        """Return the current fake time, after running ``on_tick`` if armed for this thread."""
        if self.on_tick is not None and threading.current_thread() is self.armed_thread:
            on_tick, self.on_tick = self.on_tick, None
            on_tick()
        return self.now


def test_discarding_an_expired_entry_does_not_erase_a_concurrent_denial():
    """A get() that discards an expired entry MUST NOT erase a Denial recorded concurrently.

    Deterministic, rather than a stress test: while get() is deciding the old entry has expired,
    another thread records a new Denial. An implementation that discards unconditionally,
    or without holding its lock across the check and the discard, erases the new Denial,
    and a denied Branch Key ID would be retried. With a lock held across both,
    record() blocks until get() returns, the bounded wait below times out, and the new Denial survives.

    This catches the pattern of reading the entry, then the clock, then discarding;
    an unlocked implementation that reads the clock before the entry has a window this cannot reach.
    """
    clock = RacingClock()
    negative = BranchKeyNegativeCache(BKID, negative_ttl=60, clock=clock)
    negative.record(kms_error("AccessDeniedException"))
    clock.now = 2000.0  # the first Denial has expired
    new_error = kms_error("DisabledException")
    recorded = threading.Event()

    def record_concurrently():
        negative.record(new_error)
        recorded.set()

    racer = threading.Thread(target=record_concurrently)

    def start_racer():
        racer.start()
        recorded.wait(timeout=0.2)  # bounded: a correctly locked record() is still waiting for get()

    clock.arm(start_racer)
    negative.get()  # discards the expired entry; its result depends on the interleaving
    racer.join(timeout=5)
    assert not racer.is_alive()

    survivor = negative.get()
    assert survivor is not None, "a concurrent Denial was erased by the discard of an expired entry"
    assert survivor.error is new_error
