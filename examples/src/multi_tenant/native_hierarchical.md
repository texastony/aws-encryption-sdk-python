[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: Apache-2.0"

# A Native Python Multi-Tenant Hierarchical Master Key Provider, for High Throughput Systems

DRAFT: a sketch, for discussion.

# Definitions

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

This document builds on [design.md](./design.md) and [negative_caching.md](./negative_caching.md);
their definitions of Tenant, Tenant Credentials, Shared Transport, Tenant KMS Client,
AWS KMS Key Store, Branch Key ID, Denial, Negative Cache Entry, Negative TTL,
and Tenant Keyring Factory apply here.

## MPL path

Encrypting or decrypting with the ESDK
through a keyring of the AWS Cryptographic Material Providers Library (MPL):
the MPL's Cryptographic Materials Manager, Hierarchical Keyring, cache, and AWS KMS Key Store,
all generated from Dafny,
called through the MPL's Smithy generated translation layer.

## Native path

Encrypting or decrypting with the ESDK
through a Master Key Provider (MKP) and the ESDK's own `DefaultCryptoMaterialsManager`;
Python throughout, with no MPL and no Dafny.

## Multi-Tenant Hierarchical MKP

The Master Key Provider this document designs:
for one Tenant and one Branch Key ID,
it wraps and unwraps data keys as the AWS KMS Hierarchical Keyring does,
so that each can decrypt what the other encrypted.

## Branch Key Cache

The native cache of Branch Key materials this document designs,
shared by every Multi-Tenant Hierarchical MKP in a process.

## Fetch

Reading a Branch Key version from the AWS KMS Key Store:
one DynamoDB `GetItem`, then one `kms:Decrypt` of its `enc` attribute,
signed with the Tenant's Credentials.

# Background

The scratch profile on PR #6 (since reverted; its results are in that commit's message)
measured a Tenant Hierarchical Keyring vended by the Tenant Keyring Factory,
against real AWS KMS and DynamoDB Local, with 1 KiB messages,
on Python 3.14 and MPL 1.11.3:

| ms per operation, unprofiled | MPL path (Tenant Hierarchical Keyring) | Native path (`RawMasterKeyProvider`) |
| ---------------------------- | -------------------------------------- | ------------------------------------ |
| encrypt, Branch Key cached   | 3.9                                    | 1.3                                  |
| decrypt, Branch Key cached   | 4.0                                    | 1.7                                  |
| encrypt, cache miss          | 117                                    | n/a                                  |
| decrypt, cache miss          | 99.5                                   | n/a                                  |

Under cProfile,
the Dafny generated code, the Dafny runtime, its externs, and the Smithy translation layer
were 80% to 84% of a cached operation's own time,
and 23% of a cache miss's,
which is dominated by the round trip to AWS KMS.
The Dafny runtime (`_dafny`) alone was about 47% of a cached operation;
the cryptography itself was under 1%.

`RawMasterKeyProvider` wraps under a static AES key,
so it is not like for like;
but a Branch Key cache hit is a dictionary lookup, a key derivation, and one AES-GCM operation,
so a native path SHOULD come close to it.

In a high throughput system,
nearly every operation is a cache hit;
so the MPL path costs on the order of 2.5 ms of CPU per message,
three times the ESDK's own cost.

The MPL path is formally verified;
the native path will not be.
This is the trade this document weighs.

# Requirements

1. The Multi-Tenant Hierarchical MKP MUST decrypt every message
   the AWS KMS Hierarchical Keyring encrypts for the same Branch Key,
   and the AWS KMS Hierarchical Keyring MUST decrypt every message
   the Multi-Tenant Hierarchical MKP encrypts
   ([3](#3-wire-compatibility)).

2. The native path MUST NOT import the MPL,
   for encrypt or decrypt.
   Creating and versioning Branch Keys MAY still use the MPL's AWS KMS Key Store.

3. Every object shared between threads MUST be thread safe,
   without relying on the Global Interpreter Lock:
   free threaded CPython (3.13 and later, built without the GIL) MUST be supported
   ([5](#5-thread-safety)).

4. A Branch Key version MUST be Fetched at most once at a time per process,
   per Tenant and Branch Key ID,
   however many threads miss it at once
   ([5.3](#53-single-flight-fetches)).

5. A cache hit MUST NOT wait on any Fetch,
   and SHOULD NOT wait on any lock but a short, uncontended one
   ([5.2](#52-the-branch-key-cache)).

6. Negative caching MUST behave as in [negative_caching.md](./negative_caching.md),
   Requirements 1 through 4,
   per Tenant and Branch Key ID.

7. Tenants MUST be isolated as in [negative_caching.md 8](./negative_caching.md#8-the-partition-id-revisited):
   cached materials are identified by Tenant, Logical Key Store Name, Branch Key ID, and version;
   never by credentials.

8. Thread safety MUST be tested,
   including on free threaded CPython
   ([8](#8-verification)).

9. The native Branch Key reader MUST offer strongly consistent reads, as an option
   ([4.1](#41-read-consistency)).

10. The native path MUST be annotated with Duvet,
    citing the specification as the MPL's Dafny does, wherever it can;
    and every citation of the MPL's Dafny on the paths it replaces
    MUST be cited, or excepted with a reason
    ([9](#9-specification-compliance-duvet)).

# Out of Scope

- Creating, versioning, and mutating Branch Keys:
  rare, off the hot path, and already safe through the MPL's AWS KMS Key Store.
- Sharing cache entries with MPL keyrings in the same process:
  the Branch Key Cache is native only.
- Hierarchy version 2 Branch Keys, which were never shipped.
- The MPL's Required Encryption Context CMM, and other MPL only features
  ([2](#2-keyring-or-master-key-provider)).
- More than one AWS Region, in the first version: every Tenant's KMS key, and the AWS KMS Key Store's table,
  are in one Region, per Tenant MKP Factory. Multi-Region Key replicas (`MRDiscovery`) are a later addition,
  which SHOULD be straightforward: the replica Region rewriting of `branch-key-store.md`'s AWS KMS Branch Key Decryption.
- A Branch Key ID supplier, in the first version: each Multi-Tenant Hierarchical MKP is for one Tenant
  and one Branch Key ID. How a supplier would combine with the per Tenant factory is not yet designed.

# Design Questions

## 1 What must be native?

Everything on the encrypt and decrypt path.
Each piece, and what replaces it:

| MPL path, Dafny                              | Native replacement                         | On the hot path?   |
| -------------------------------------------- | ------------------------------------------ | ------------------ |
| Cryptographic Materials Manager              | the ESDK's `DefaultCryptoMaterialsManager` | every operation    |
| AWS KMS Hierarchical Keyring                 | the Multi-Tenant Hierarchical MKP and its Master Key | every operation |
| Storm tracking Cryptographic Materials Cache | the Branch Key Cache                       | every operation    |
| Cache Guard, Negative Cache Entries          | part of the Branch Key Cache               | every operation    |
| AWS KMS Key Store, `GetActiveBranchKey`      | a native Branch Key reader                 | every cache miss   |
| AWS KMS Key Store, `GetBranchKeyVersion`     | the same reader                            | every cache miss   |
| AWS KMS Key Store, `CreateKey`, `VersionKey` | unchanged: the MPL's AWS KMS Key Store     | no                 |
| KDF in Counter Mode, AES-GCM                 | `cryptography`                             | every operation    |

Already native, and unchanged:
the Shared Transport, the Tenant KMS Client, Negative Cache Entries' Denial classification
(`negative_cache.py`, which does not import the MPL),
and the DynamoDB client.

The Tenant Keyring Factory becomes a Tenant MKP Factory:
the same shared state ([negative_caching.md 7.2](./negative_caching.md#72-a-tenant-keyring-factory)),
vending Multi-Tenant Hierarchical MKPs instead of keyrings.

## 2 Keyring, or Master Key Provider?

### 2.1 A native `IKeyring`

The MPL accepts a native Python `IKeyring`.
However,
the ESDK then calls it through the MPL's Cryptographic Materials Manager,
which is Dafny;
so the CMM's cost, and the translation of materials to and from Dafny on every operation, remain.

### 2.2 A Master Key Provider

The ESDK's native path calls a `MasterKeyProvider`
through its own `DefaultCryptoMaterialsManager`,
which is Python.
A `MasterKey` subclass implements
`_generate_data_key`, `_encrypt_data_key`, and `_decrypt_data_key`
(`src/aws_encryption_sdk/key_providers/base.py`),
which map onto the Hierarchical Keyring's OnEncrypt and OnDecrypt:

- its provider ID is `aws-kms-hierarchy`
- its key ID, the encrypted data key's provider info, is the Branch Key ID
- `owns_data_key` matches both, as OnDecrypt's filter does

MKPs are the ESDK's legacy interface,
but supported in every ESDK 4.x release.

What the native path does not support:
the MPL's Required Encryption Context CMM,
and other CMMs and keyrings of the MPL.
A message encrypted with required encryption context keys
does not store those keys,
so the native path cannot decrypt it;
an application that uses them MUST stay on the MPL path.

### 2.3 Author's conclusion

A Master Key Provider (2.2).

## 3 Wire compatibility

The Multi-Tenant Hierarchical MKP MUST produce, and accept,
exactly what the AWS KMS Hierarchical Keyring does
(`aws-kms-hierarchical-keyring.md`, Structure and Operation):

**Encrypted data key**:  
provider ID `aws-kms-hierarchy`;
provider info the UTF-8 Branch Key ID;
ciphertext, big endian, in order:

| Field              | Length (bytes) |
| ------------------ | -------------- |
| Salt               | 16             |
| IV                 | 12             |
| Version            | 16, the Branch Key version UUID's bytes |
| Encrypted key      | the algorithm suite's data key length |
| Authentication tag | 16             |

**Derived Branch Key**:  
a NIST SP 800-108 KDF in Counter Mode, HMAC-SHA256, 32 bytes;
as the MPL's `KdfCtr.dfy` implements it:
`HMAC-SHA256(branchKey, counter ‖ label ‖ 0x00 ‖ salt ‖ L)`,
with a 4 byte big endian counter starting at 1,
the label the UTF-8 bytes of `aws-kms-hierarchy`,
and `L` the output length in bits (256) as 4 big endian bytes;
one iteration, for 32 bytes.
`cryptography`'s `KBKDFHMAC`
(counter location `BeforeFixed`, `rlen` 4, `llen` 4, that label, the salt as context)
produces the same bytes:
for 200 random Branch Keys and salts,
it, the formula above computed by hand, and the MPL's own `kdf_counter_mode` agreed on every one.
That check MUST be kept as a test.

**Wrapping**:  
AES-256-GCM, keyed by the derived Branch Key,
with the 12 byte IV,
and AAD `aws-kms-hierarchy` ‖ Branch Key ID ‖ version (16 bytes) ‖ the serialized encryption context.

**Encryption context**:  
the AAD includes the message's encryption context,
which for signing algorithm suites includes `aws-crypto-public-key`.
The ESDK's `DefaultCryptoMaterialsManager` adds it before calling the master keys
(`src/aws_encryption_sdk/materials_managers/default.py`),
as the MPL's CMM does before calling keyrings;
the interoperability tests MUST cover signing and non signing suites
([8](#8-verification)).

## 4 Reading Branch Keys

A native reader replaces `GetActiveBranchKey` and `GetBranchKeyVersion`.
It MUST implement the AWS KMS Key Store's read path
(`branch-key-store.md`, AWS KMS Branch Key Decryption), including:

- one DynamoDB `GetItem` of the `branch:ACTIVE` item, or of the `branch:version:<version>` item
- the encryption context built from every item attribute but `enc`,
  plus `tablename`, the Logical Key Store Name;
  custom encryption context attributes are already prefixed `aws-crypto-ec:`
- `hierarchy-version` MUST be 1
- the `kms-arn` rules of the configured AWS KMS Configuration:
  compatible with the configured KMS Key for `KMS Key ARN`;
  not an alias, for `Discovery`
- `kms:Decrypt` with `KeyId` and that encryption context, through the Tenant KMS Client;
  the plaintext MUST be 32 bytes
- Branch Key materials: the Branch Key ID, the version, the 32 byte key, and the custom encryption context

The MPL's static test Branch Keys, including the lying Branch Key,
and its `TestLyingBranchKey.dfy` and `TestDiscoveryGetKeys.dfy` cases,
SHOULD be ported as tests.

### 4.1 Read consistency

The MPL's AWS KMS Key Store reads eventually consistently:
its `GetItem` requests leave `ConsistentRead` unset
(`DDBKeystoreOperations.dfy`),
and it offers no option to change that.
This is a common complaint of high throughput services.

The specification proposes an option for it:
[aws-encryption-sdk-specification#302](https://github.com/awslabs/aws-encryption-sdk-specification/pull/302),
"Define Branch Key Store read consistency semantics",
adds an optional `Require Consistent Reads` input to the Branch Key Store's Initialization;
when it is `true`, `GetActiveBranchKey`, `GetBranchKeyVersion`, `GetBeaconKey`,
and `VersionKey`'s read of the active version
MUST set `ConsistentRead` to `true`;
and all operations MUST use the same setting.
The MPL's implementation is
[aws-cryptographic-material-providers-library#1645](https://github.com/aws/aws-cryptographic-material-providers-library/pull/1645)
(`requireConsistentReads` in `KeyStore.smithy`).
Both are open, as of this writing, and neither is released.

**What eventually consistent reads cost them**:  
a read shortly after a write may not see it.
In particular:

- after `CreateKey`, a `GetActiveBranchKey` on another host
  may find no ACTIVE item, and fail, though the Branch Key exists;
  so a Tenant's first request after onboarding can fail
- after `VersionKey`, a `GetActiveBranchKey` may still return the previous version,
  so new messages are encrypted under it
- a message encrypted under a new version,
  decrypted on another host before the version item is visible there,
  fails `GetBranchKeyVersion`

**Decision**:  
the native reader takes a `require_consistent_reads` option,
the specification's `Require Consistent Reads`, with its semantics,
applied to every `GetItem` it makes:

- `False`, the default: read operations MAY return stale results, as the MPL's AWS KMS Key Store reads today
- `True`: every `GetItem` sets `ConsistentRead` to `true`, for applications that create or version Branch Keys
  and use them at once, on any host

If #1645 is released,
an application SHOULD give the MPL's AWS KMS Key Store, which creates and versions its Branch Keys,
the same setting.

It is configured per Tenant MKP Factory,
so every Tenant's reader in a process reads the same way.

**What it does not change**:  

- Only Fetches read DynamoDB.
  An entry already in the Branch Key Cache is served until it expires,
  so after `VersionKey`, a host keeps encrypting under the version it cached,
  for up to the cache's TTL, whatever the consistency.
  Strongly consistent reads make each Fetch current;
  the cache's TTL bounds how stale an entry can be.
- A strongly consistent read costs twice the read capacity of an eventually consistent one,
  per Fetch; Fetches are rare, so this is usually small.
- On a DynamoDB global table,
  a strongly consistent read is consistent only with writes made in the same Region's replica;
  a Branch Key created in another Region may still not be visible.
- A strongly consistent read MAY fail where an eventually consistent one would not,
  for example while a partition is unavailable;
  such failures are DynamoDB's, not AWS KMS's,
  so they are not Denials, and are not negatively cached
  ([negative_caching.md, Out of Scope](./negative_caching.md#why-not-amazon-dynamodb-failures)).

The interoperability tests MUST run with both settings,
and a test MUST assert each `GetItem`'s `ConsistentRead` parameter.

## 5 Thread safety

The reason for the native path is throughput;
so many threads, and many Tenants, share every object at once.
None of this design MAY rely on the GIL for correctness (Requirement 3):
on free threaded CPython,
any read and write of shared mutable state may interleave.

### 5.1 What is shared, and how

| Object                     | Shared by                          | Mutable after construction? | Safe because |
| -------------------------- | ---------------------------------- | --------------------------- | ------------ |
| Shared Transport           | every Tenant                       | its connection pool          | urllib3's pool is thread safe |
| DynamoDB client            | every Tenant                       | no (boto3 clients)           | boto3 clients are thread safe; resources and sessions are not shared |
| Tenant KMS Client          | one Tenant's MKPs                  | no                           | immutable references; botocore's `RefreshableCredentials` lock their own refresh |
| Branch Key Cache           | every Tenant                       | yes                          | [5.2](#52-the-branch-key-cache) |
| Negative cache             | one Tenant and Branch Key ID       | yes                          | one lock, as today ([negative_caching.md 4.3](./negative_caching.md#43-a-cache-guard)) |
| Multi-Tenant Hierarchical MKP    | MAY be shared, or one per request  | MUST NOT be                  | [5.4](#54-the-master-key-provider) |
| Tenant MKP Factory         | every Tenant                       | its map of negative caches   | one short lock, as today |

### 5.2 The Branch Key Cache

Entries are keyed by (Tenant, Logical Key Store Name, Branch Key ID, version),
and, for encrypt, (Tenant, Logical Key Store Name, Branch Key ID, ACTIVE).

**Entries are immutable**:  
an entry (the Branch Key materials, and its expiry) is a frozen object;
it is replaced, never changed.
A reader that finds an entry needs nothing further from the cache.

**Lock striping**:  
the map is split into stripes, a power of two of them (for example, 64),
each a dictionary with its own lock, chosen by the key's hash.
A lookup takes one stripe's lock for a dictionary get;
threads looking up different Tenants rarely contend.
One global lock would serialize every operation of every Tenant;
on free threaded CPython that is the bottleneck this design exists to remove.

**Expiry**:  
by `time.monotonic()`, never wall clock;
checked by the reader, with the entry in hand, outside the lock.

**Capacity and eviction: an LRU with a TTL**:  
a bound on entries, across every Tenant, as the storm tracking cache's `entry_capacity`;
when it is reached, the least recently used entry is evicted.
Every entry also expires at its TTL, the cache limit TTL, whether or not it is used.
Each stripe is an LRU (an `OrderedDict`) of its share of the capacity;
a hit moves its entry to the end, under the stripe's lock,
which is a short, constant time write.
Thus eviction is least recently used within a stripe, an approximation of a global LRU,
in exchange for never taking a global lock.
An approximate policy that makes a hit a read only (CLOCK) was considered, and rejected;
the stress test ([8](#8-verification)) measures the stripe locks' contention.

### 5.3 Single flight Fetches

On a miss,
the first thread places an in flight marker in the stripe
(a `concurrent.futures.Future`, or an `Event` and a result slot),
under the stripe's lock,
then releases the lock and Fetches.
A thread that finds the marker waits on it, outside the lock,
for at most the in flight TTL;
then takes the result, or the error.
When the Fetch completes,
the fetcher replaces the marker with the entry, under the lock,
and completes the marker.

Thus a Fetch runs at most once at a time per key (Requirement 4),
no lock is held across I/O,
and a cache hit never waits on a Fetch (Requirement 5).

**Errors**:  
a failed Fetch's error is given to every thread waiting on it,
and the marker removed,
so the next request Fetches again;
unless it is a Denial,
which is recorded in the Tenant and Branch Key ID's negative cache first (Requirement 6),
so the next request fails without a Fetch.

**A fetcher that never returns**:  
waiters stop waiting after the in flight TTL;
the marker is then stale,
and the next thread to find it MAY replace it and Fetch.
The Tenant KMS Client's and DynamoDB client's timeouts bound how long that can be.

**Refresh before expiry**:  
as the storm tracking cache's grace period:
within the grace period before an entry expires,
the first thread to see it places a refresh marker beside the entry and Fetches;
every other thread keeps using the entry.
So a hot Branch Key never makes every thread miss at once when it expires.

**Fan out**:  
the storm tracking cache bounds concurrent Fetches across every key (`fan_out`).
A semaphore around the Fetch does the same;
it SHOULD be bounded,
as a burst of Tenants missing at once (for example, at startup) is a burst of DynamoDB and KMS requests.

### 5.4 The Master Key Provider

The ESDK's `MasterKeyProvider` base class mutates itself on use:
`master_key_for_decrypt` checks, then inserts into, `_decrypt_key_index`,
and `add_master_key` appends to `_members`,
without a lock (`src/aws_encryption_sdk/key_providers/base.py`).
Two threads adding the same key could both append it,
and an encrypt would then wrap the data key twice.

So a Multi-Tenant Hierarchical MKP MUST be immutable once vended:
the factory constructs it with its one Master Key, for its one Branch Key ID,
before any other thread can see it;
and it overrides `_new_master_key` and `master_key_for_decrypt`
to return that Master Key, or refuse,
without touching the base class's indexes.

The Master Key itself holds only references
(the Branch Key ID, the Tenant, the Branch Key Cache, the reader);
its operations' state (the data key, the salt, the IV) is local to each call.

A vended MKP is a few references,
so applications MAY vend one per request, as with keyrings today
([negative_caching.md 8](./negative_caching.md#8-the-partition-id-revisited));
or share one per Tenant and Branch Key ID across threads.

### 5.5 The dependencies, on free threaded CPython

The native path depends on the ESDK's runtime dependencies,
and on botocore's, for the Tenant KMS Client and the DynamoDB client;
not on the MPL.
As of this writing (their latest releases, on PyPI):

| Package          | Free threaded support                                                        |
| ---------------- | ---------------------------------------------------------------------------- |
| `cryptography`   | `cp314t` (abi3t) wheels; classifier "Free Threading :: 3 - Stable"            |
| `boto3`, `botocore` | pure Python; classifier "Free Threading :: 2 - Beta"                      |
| `urllib3`, `s3transfer`, `python-dateutil` | pure Python; classifier "Free Threading :: 2 - Beta" |
| `wrapt`          | `cp314t` and `cp315t` wheels, and a pure Python fallback; no classifier      |
| `attrs`, `jmespath`, `six` | pure Python; no classifier                                         |

So free threaded CPython is practical from 3.14t:
`cryptography` publishes no `cp313t` wheel, so 3.13t builds it from source.
The classifiers are each project's own claim;
the ESDK makes none,
and its `MasterKeyProvider` base class is not safe on free threaded CPython ([5.4](#54-the-master-key-provider)).
So the free threaded CI job ([8](#8-verification)) is the evidence, not the classifiers.

### 5.6 Randomness, and keys in memory

Salts, IVs, and data keys come from `os.urandom`, which is thread safe.
`cryptography`'s `AESGCM` and `KBKDFHMAC` objects are created per call, not shared.

Branch Keys and derived keys are Python `bytes`,
which cannot be zeroed;
the MPL path has the same property.

## 6 Negative caching

The Cache Guard is no longer a separate object:
the Branch Key Cache checks the Tenant and Branch Key ID's negative cache
before any lookup (Requirement 6, and [negative_caching.md](./negative_caching.md) Requirement 3),
and a Fetch that is Denied records it, as in [5.3](#53-single-flight-fetches).

The native path has one advantage:
no conversion to and from Dafny,
so the error a Denied request raises can be the `ClientError` AWS KMS returned,
with its code,
from the first request on;
not the MPL's `KeyStore` and `OpaqueWithTextError` wrapping
(the multi-tenant Hierarchical Keyring example's docstring).

## 7 Where does it live?

### 7.1 In the examples

Alongside the Tenant Keyring Factory, in `examples/src/multi_tenant/`.
Applications copy it, and own it.

### 7.2 In the ESDK

A supported Master Key Provider of `aws_encryption_sdk`.
Then it is the ESDK team's to maintain and to keep compatible,
which the formal verification of the MPL path was meant to avoid.

### 7.3 Author's conclusion

To be decided; 7.1 first, to measure.

## 8 Verification

The MPL path's correctness is proven;
the native path's MUST be tested:

- **Interoperability**, both directions:
  the Multi-Tenant Hierarchical MKP decrypts the AWS KMS Hierarchical Keyring's messages, and the reverse;
  every committing algorithm suite, signing and not;
  empty, small, and large encryption contexts; one and many encrypted data keys.
- **The KDF**, against the MPL's `KdfCtr`, for random inputs.
- **Test vectors**: the MPL's Hierarchical Keyring test vectors, where they apply.
- **The reader**: the Key Store's validation cases, ported (4).
- **Thread safety**:
  - deterministic tests that force each interleaving of [5.3](#53-single-flight-fetches),
    with injected pauses, as `test_negative_cache.py`'s thread safety test does
  - a stress test: many threads, many Tenants, a counting fake AWS KMS;
    asserting exactly one Fetch per key and expiry, and no lost or duplicated entries
  - the suite run on free threaded CPython (`python3.13t` or later, `PYTHON_GIL=0`), in CI
- **Performance**: the scratch profile, kept as a benchmark,
  comparing the MPL path and the native path, cached and not, single and multi threaded.
- **Specification compliance**: Duvet, matching the MPL's Dafny ([9](#9-specification-compliance-duvet)).

## 9 Specification compliance (Duvet)

The MPL's Dafny cites the specification with [Duvet](https://github.com/awslabs/duvet):
a `//=` line names the section, and `//#` lines quote its text,
above the code that implements it;
`duvet report` checks every quote against the specification,
and reports each requirement as cited, tested, excepted, or missing.
Formal verification proves the Dafny meets its own specification;
Duvet is how a reviewer sees that specification is the AWS Encryption SDK Specification.
The native path has no proofs,
so its Duvet annotations, and its tests' (`type=test`), carry more of the weight.

### 9.1 The same citations, where they can be

The native path MUST carry the citations the MPL's Dafny carries,
on the code that does the same thing:
the same section, and the same quoted text.
On the paths it replaces, at the MPL's `v1.11.3`, those are:

| Specification section                                                          | Citations | MPL Dafny source                |
| ------------------------------------------------------------------------------ | --------- | ------------------------------- |
| `aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping`                  | 11        | `AwsKmsHierarchicalKeyring.dfy` |
| `aws-kms/aws-kms-hierarchical-keyring.md#onencrypt`                            | 7         | `AwsKmsHierarchicalKeyring.dfy` |
| `aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt`                            | 4         | `AwsKmsHierarchicalKeyring.dfy` |
| `aws-kms/aws-kms-hierarchical-keyring.md#initialization`                       | 3         | `AwsKmsHierarchicalKeyring.dfy` |
| `aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad` | 2       | `AwsKmsHierarchicalKeyring.dfy` |
| `aws-kms/aws-kms-hierarchical-keyring.md#interface`, `#encryption-materials`, `#decryption-materials` | 3 | `AwsKmsHierarchicalKeyring.dfy` |
| `branch-key-store.md#aws-kms-branch-key-decryption`                            | 14        | `GetKeys.dfy`                   |
| `branch-key-store.md#getactivebranchkey`                                       | 7         | `GetKeys.dfy`                   |
| `branch-key-store.md#getbranchkeyversion`                                      | 7         | `GetKeys.dfy`                   |
| `branch-key-store.md#encryption-context`                                       | 10        | `Structure.dfy`                 |
| `branch-key-store.md#branch-key-materials-from-authenticated-encryption-context` | 8       | `Structure.dfy`                 |
| `branch-key-store.md#custom-encryption-context`                                | 6         | `Structure.dfy`                 |
| `branch-key-store.md#active-encryption-context`                                | 3         | `Structure.dfy`                 |
| `branch-key-store.md#record-format`                                            | 2         | `Structure.dfy`                 |

In Python, as the MPL's own report reads `#` comments (`(# //=,# //#)`):

```python
# //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
# //# 1. Generate a 16 byte random `salt` using a secure source of randomness
salt = os.urandom(16)
```

**A parity check**:  
a script MUST extract every (section, quote) the MPL's Dafny cites in those sources,
at the MPL version the native path matches,
and fail if the native sources neither cite it nor except it.
It runs in CI, beside `duvet report`;
so a citation the MPL adds, or the native path drops, is caught.

### 9.2 Where they cannot be

The native path is a Master Key Provider, not a keyring,
and has its own cache;
so some citations cannot apply as written.
Each MUST be a `type=exception` (or `type=implication`), with its reason, in a compliance exceptions file,
as this repository's `compliance_exceptions/` already does. For example:

- `#initialization`'s "MUST initialize a cryptographic-materials-cache ... with the configured cache limit TTL
  and the max cache size": the Tenant MKP Factory owns one Branch Key Cache, shared by every MKP it vends;
  and its Branch Key Supplier: the factory vends an MKP per Branch Key ID instead
- `#appendix-a-cache-entry-identifier-formulas`:
  the Branch Key Cache is not shared with MPL keyrings, so it does not use their identifiers
- the keyring interface's materials structures, where the MKP interface's `DataKey` and
  `EncryptedDataKey` carry the same fields under the ESDK's names (`type=implication`)

The native path's own behavior, that the specification does not describe
(the Branch Key Cache's thread safety, single flight Fetches, negative caching),
is not cited; this document, and its tests, cover it.

`Require Consistent Reads` ([4.1](#41-read-consistency)) is not in the specification yet;
its citations are `type=todo` until
[aws-encryption-sdk-specification#302](https://github.com/awslabs/aws-encryption-sdk-specification/pull/302)
is merged.

### 9.3 Which specification

Quotes MUST match the specification revision they cite, exactly.
This repository's `aws-encryption-sdk-specification` submodule is pinned at `c35fbd9` (2021-06-18),
which predates the AWS KMS Hierarchical Keyring;
the MPL, at `v1.11.3` and on `main`, pins `8f4afff` (2024-06-05).
The native path MUST cite the revision the MPL version it matches pins,
so that its quotes, and the MPL's, are the same text.

That revision lags the MPL itself:
at `8f4afff`, the AWS KMS Hierarchical Keyring's Initialization has no `Partition ID` or `Cache Type`,
and there is no Shared Cache Considerations section,
though the MPL implements both, and the specification's current `master` describes them.
The native path's Tenant isolation ([negative_caching.md 8](./negative_caching.md#8-the-partition-id-revisited))
can be cited only against a newer revision.
Either this repository's submodule is updated,
which changes the text its existing citations quote,
or the native path's report uses a second checkout, pinned to the MPL's revision;
see [Open Questions](#open-questions).

UPDATE: A second checkout of the specification, pinned to the MPL's revision,
used only by the native path's `duvet extract` and `duvet report`;
this repository's existing submodule, and its citations, are unchanged.
When the native path is matched to a newer MPL release, its pin moves to that release's.

### 9.4 The tool

This repository's existing citations use the older Duvet form
(`# //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8`, against extracted text, by section number).
The MPL uses the current Duvet (`cargo install duvet`),
which extracts the specification's Markdown (`duvet extract -f MARKDOWN`)
and cites it by heading anchor (`.md#branch-key-wrapping`).
The native path MUST use the current form, the MPL's,
so its citations can be compared with the MPL's (9.1);
its `duvet report` runs over the native sources and tests only,
and its HTML report is a CI artifact, as the MPL's `duvet.yaml` produces.

# Open Questions

1. **The cache's eviction policy**: per stripe LRU, CLOCK, or TTL only; measured under contention.

   UPDATE: An LRU with a TTL ([5.2](#52-the-branch-key-cache)).

2. **`MRDiscovery`**: the replica region rewriting of `branch-key-store.md`;
   needed by any Tenant using multi-Region keys.

   UPDATE: The first version is single Region ([Out of Scope](#out-of-scope));
   multi-Region support SHOULD be straightforward to add, if needed.

3. **DynamoDB consistency**: the MPL's AWS KMS Key Store reads eventually consistently
   (`ConsistentRead` unset, `DDBKeystoreOperations.dfy`);
   the native reader SHOULD match it, unless an application needs a rotated Branch Key's
   new ACTIVE version seen at once, which a strongly consistent read costs twice as much for.

   UPDATE: The native reader offers strongly consistent reads, as an option;
   the default matches the MPL ([4.1](#41-read-consistency)).

4. **Supported Python versions**: the ESDK supports 3.8;
   free threaded CPython is 3.13 and later;
   whether the native path targets the ESDK's versions, or newer.

   UPDATE: The dependencies support free threaded CPython, practically from 3.14t
   ([5.5](#55-the-dependencies-on-free-threaded-cpython)).
   Which versions the native path supports, with the GIL, remains open.

5. **Branch Key creation**: whether onboarding stays on the MPL's AWS KMS Key Store,
   so that the MPL remains a dependency of the application, though not of its hot path.

   UPDATE: Onboarding stays on the MPL's AWS KMS Key Store, for now.
   It MAY be ported later, for the native path's better errors ([6](#6-negative-caching)).

6. **One Branch Key ID per MKP**: as the Tenant Keyring Factory vends today;
   or a Branch Key ID supplier, if a Tenant has several.

   UPDATE: One Branch Key ID per Multi-Tenant Hierarchical MKP; no supplier, for now
   ([Out of Scope](#out-of-scope)). How a supplier combines with the per Tenant factory is not yet designed.

7. **The specification revision for Duvet** ([9.3](#93-which-specification)):
   update this repository's `aws-encryption-sdk-specification` submodule to the MPL's pin,
   and re-extract its existing citations' text;
   or check out the MPL's pin a second time, for the native path's report only.

   UPDATE: A second checkout, at the MPL's pin ([9.3](#93-which-specification)).

# Consequences

- Every citation the MPL adds to the paths the native path replaces
  is a requirement of the native path; the parity check ([9.1](#91-the-same-citations-where-they-can-be)) enforces it.
- The hot path loses formal verification;
  interoperability and thread safety tests replace it, and MUST be kept.
- The native path's correctness depends on matching the MPL's wire format exactly,
  including its KDF;
  a change to either MUST be made to both.
- MKPs are the ESDK's legacy interface;
  MPL only features are unavailable on the native path.
- Applications SHOULD measure their own workload first:
  the gain is per cached operation,
  and a workload dominated by cache misses gains little.
