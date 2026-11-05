[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: Apache-2.0"

# Negative Caching for Multi-Tenant AWS KMS Hierarchical Keyrings

# Definitions

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

This document builds on [design.md](./design.md);
its definitions of Tenant, Tenant Credentials, Heavy Object,
Shared Transport, Tenant KMS Client, and AWS KMS Key Store apply here.

## Branch Key ID (BKID)

The identifier of a Branch Key in an AWS KMS Key Store;
the `branch-key-id` attribute of every Branch Key item,
and the partition key of the AWS KMS Key Store's DynamoDB table.

A Branch Key ID identifies every version of a Branch Key.

## Denial

A failure, returned by AWS KMS,
to decrypt a Branch Key on behalf of a Tenant,
that is caused by the Tenant owned resources
(the KMS Key, and its Key Policy or Grants)
and that will not resolve by retrying.

See [Design Question 5](#5-what-is-a-denial).

## Negative Cache Entry

A record that a Branch Key ID was Denied,
with the error AWS KMS returned,
the time it was Denied,
and the time it expires.

## Negative TTL

How long a Negative Cache Entry is honored.
While it is honored,
no request is made to Amazon DynamoDB or AWS KMS for that Branch Key ID.

The Negative TTL is configured per [Tenant Keyring Factory](#tenant-keyring-factory),
and defaults to 5 minutes.

## Cache Guard

A [Cryptographic Materials Cache](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cryptographic-materials-cache.md)
that wraps the cache shared by every Tenant,
and fails a lookup for a Branch Key ID with an honored Negative Cache Entry,
rather than returning a cache miss.

One per Tenant Hierarchical Keyring.

## Tenant Keyring Factory

An object, one per process,
that holds everything every Tenant Hierarchical Keyring shares
(the Shared Transport, the shared cache, the DynamoDB client, and the AWS KMS Key Store configuration),
and that vends a Tenant Hierarchical Keyring
given a Branch Key ID and Tenant Credentials.

See [Design Question 7](#7-who-builds-a-tenant-hierarchical-keyring).

# Background

[design.md](./design.md) lets an application call AWS KMS
with per-Tenant credentials over one connection pool,
and gives every Tenant's Hierarchical Keyring one shared cache.

It does not address a Tenant whose KMS Key stops being available:
the Tenant revokes the application's access,
disables the KMS Key,
or schedules it for deletion.

The Hierarchical Keyring only records a Branch Key in its cache on success.
Thus,
every request for that Tenant's Branch Key
misses the cache,
reads the Branch Key from Amazon DynamoDB,
calls `kms:Decrypt`,
and fails;
every time,
for as long as the KMS Key is unavailable.

These requests are not free:

- They consume the application's DynamoDB capacity, though the cause is the Tenant's.
- They consume KMS request quota, and the latency of a round trip that is known to fail.
- With the storm tracking cache of [design.md 10.1](./design.md#101-one-shared-cache),
  a failed fetch holds one of the fan out slots every Tenant shares for the in flight TTL
  ([design.md 10.1.1](./design.md#1011-why-not-the-mpls-defaultcache)),
  and concurrent callers for the failing Branch Key block,
  rather than fail.

Negative caching records the failure,
and fails subsequent requests for that Branch Key ID immediately,
for a configurable time,
without calling Amazon DynamoDB or AWS KMS.

This document records the options considered,
and the decisions made,
to implement negative caching
without changing the source of the ESDK-Python or the MPL;
only by implementing the public, extendable interfaces
(Keyrings, Master Key Providers, Cryptographic Materials Managers, and Cryptographic Materials Caches).

# Requirements

1. After a Denial for a Branch Key ID,
   the Tenant Hierarchical Keyring MUST NOT call Amazon DynamoDB or AWS KMS for that Branch Key ID
   until the Negative TTL expires.

2. A Denial for a Branch Key ID MUST NOT affect any other Branch Key ID,
   including Branch Key IDs protected by the same KMS Key.

3. While a Negative Cache Entry is honored,
   the Branch Key ID's cached materials MUST NOT be used,
   for encrypt or decrypt,
   for any version of the Branch Key.

4. Only a [Denial](#5-what-is-a-denial) MUST create a Negative Cache Entry;
   transient failures (throttling, server errors, timeouts, expired credentials) MUST NOT.

5. The ESDK-Python and MPL source MUST NOT be changed;
   only their public, extendable interfaces MAY be implemented.

6. Every AWS KMS Configuration of the AWS KMS Key Store MUST be supported,
   including `Discovery` and `MRDiscovery`.

7. Every Tenant's Hierarchical Keyring MUST still share one cache
   ([design.md 10.1](./design.md#101-one-shared-cache)).

8. The Tenant Keyring Factory, and every object it vends, MUST be thread safe,
   and this SHOULD be tested.

# Out of Scope

- Keyrings other than the AWS KMS Hierarchical Keyring,
  the KMS Master Key Providers,
  and the Caching Cryptographic Materials Manager.
- Failures of Amazon DynamoDB, including a missing Branch Key item.
- A Branch Key ID Supplier selecting among Branch Key IDs within one keyring;
  see [Design Question 7](#7-who-builds-a-tenant-hierarchical-keyring).

## Why not Amazon DynamoDB failures?

The DynamoDB table is owned by the application, not the Tenant.
A DynamoDB failure is the application's to resolve,
and is not a statement about any one Tenant.

# Design Questions

## 1 Where does the Hierarchical Keyring call AWS KMS?

Traced through the specification
(`framework/aws-kms/aws-kms-hierarchical-keyring.md`,
`framework/branch-key-store.md`,
`framework/cryptographic-materials-cache.md`,
`framework/storm-tracking-cryptographic-materials-cache.md`)
and the MPL
(`AwsKmsHierarchicalKeyring.dfy`, `v1.11.3`):

```
OnEncrypt                                       OnDecrypt (each matching EDK; errors collected)
  cacheId = SHA384(0x02, 0x01, partition,         cacheId = SHA384(0x02, 0x02, partition,
                   logicalKeyStoreName, BKID)                      logicalKeyStoreName, BKID, version)
  cache.GetCacheEntry(cacheId)                    cache.GetCacheEntry(cacheId)
   |- error, not EntryDoesNotExist -> FAIL         |- error, not EntryDoesNotExist -> FAIL
   |- hit, within TTL -> wrap                      |- hit, within TTL -> unwrap
   `- miss, or expired                             `- miss, or expired
       KeyStore.GetActiveBranchKey(BKID)               KeyStore.GetBranchKeyVersion(BKID, version)
         1. DynamoDB GetItem (branch:ACTIVE)             1. DynamoDB GetItem (branch:version:<version>)
         2. kms:Decrypt                                  2. kms:Decrypt
       |- failure -> FAIL; the cache is not told       |- failure -> FAIL; the cache is not told
       `- success -> PutCacheEntry                     `- success -> PutCacheEntry
```

Thus:

**AWS KMS is only called on a cache miss**:  
and only through the AWS KMS Key Store.

**Amazon DynamoDB is always called first**:  
A failing KMS Key costs a DynamoDB read on every attempt.

**The cache never learns of a failure**:  
`PutCacheEntry` is only called on success
(`AwsKmsHierarchicalKeyring.dfy`, `GetActiveHierarchicalMaterials`;
the Key Store's failure returns through `:-` before the cache is called).

**A cache error other than a miss fails the keyring immediately**:  
If `GetCacheEntry` fails with any error other than `EntryDoesNotExist`,
the keyring returns that error,
without calling the AWS KMS Key Store
(`AwsKmsHierarchicalKeyring.dfy`, both `GetCacheEntry` call sites).

**The cache identifier is opaque**:  
It is a SHA-384 digest;
it does not include the KMS Key ARN,
and a cache cannot recover the Branch Key ID from it.

**The storm tracking cache is an accidental, and poor, rate limit**:  
A failed fetch never calls `PutCacheEntry`,
so the Branch Key stays in flight.
While it is,
concurrent callers block,
and at most one retry is made per grace interval;
once a caller has waited the in flight TTL,
`GetCacheEntry` fails.
Failing Tenants slow every Tenant,
rather than failing fast.

## 2 Which interfaces can be extended?

| Interface | Native Python implementation accepted? | Sees a KMS failure? | Knows the Branch Key ID? | Can prevent the DynamoDB and KMS calls? |
| --------- | -------------------------------------- | ------------------- | ------------------------ | --------------------------------------- |
| Cryptographic Materials Cache (`ICryptographicMaterialsCache`, passed as `CacheTypeShared`) | Yes | No | No; the cache identifier is a digest | Yes; by failing `GetCacheEntry` |
| AWS KMS Key Store | **No** | — | — | — |
| KMS client (the Tenant KMS Client) | Yes; duck typed ([design.md 4.1](./design.md#41-keyrings-client-suppliers-and-the-aws-kms-key-store)) | **Yes**; the error code, exactly | Only if bound to it ([6](#6-why-the-branch-key-id-and-not-the-kms-key-arn)) | No; DynamoDB is called first |
| Keyring (an `IKeyring` delegating to the Hierarchical Keyring) | Yes | Indirectly; nested in Key Store and collection errors | Yes | Yes; but before the cache, so cache hits are lost |

**The cache accepts native implementations**:  
`aws_cryptography_materialproviders_CryptographicMaterialsCacheReference`
passes any object without an `_impl` attribute to Dafny unchanged;
`ICryptographicMaterialsCache` provides the Dafny facing methods,
which call the native `get_cache_entry` and friends.

**Native errors keep their meaning**:  
Those Dafny facing methods map native exceptions with `_smithy_error_to_dafny_error`:
a native `EntryDoesNotExist` becomes a Dafny `EntryDoesNotExist`,
which the keyring treats as a miss;
any other exception becomes another error,
which the keyring returns immediately.

**The AWS KMS Key Store does not**:  
`aws_cryptography_materialproviders_KeyStoreReference`
requires the MPL's `KeyStore`
(`native_input._config.dafnyImplInterface.impl`);
there is no Python interface to implement.

**Keyrings accept native implementations**:  
`aws_cryptography_materialproviders_KeyringReference`
passes any object without an `_impl` attribute unchanged.

## 3 Where is a Denial detected?

### 3.1 The cache

Not possible;
the cache is never told of a failure ([1](#1-where-does-the-hierarchical-keyring-call-aws-kms)).

A cache could infer one from a miss that is not followed by `PutCacheEntry`;
but it cannot distinguish a failure from a slow fetch,
nor a Denial from throttling.

### 3.2 A keyring wrapper

A keyring delegating to the Hierarchical Keyring
receives the failure as an exception,
after the fact.

**Con, the error is nested**:  
The KMS error is wrapped by the AWS KMS Key Store's error,
and on decrypt,
in a collection of every encrypted data key's errors.
Classifying it means unpicking MPL error structures
that are not a stable interface.

### 3.3 The Tenant KMS Client

The Tenant KMS Client receives every KMS response,
before the MPL wraps it.

**Pro, exact**:  
The KMS error code is in hand,
unwrapped,
and the request that caused it.

**Pro, already ours**:  
The example already supplies every KMS client the AWS KMS Key Store uses.

**Con, coupling**:  
Negative caching depends on the Tenant KMS Client;
an application using boto3's KMS client would not get it.
For an example built on [design.md](./design.md),
this is acceptable.

### 3.4 Author's conclusion

3.3.

## 4 Where is a Negative Cache Entry enforced?

### 4.1 The Tenant KMS Client

It could fail a `Decrypt` immediately,
without a network request.

**Con, Amazon DynamoDB is still called**:  
The AWS KMS Key Store reads the Branch Key before calling KMS,
violating Requirement 1.

### 4.2 A keyring wrapper

It could fail `OnEncrypt` and `OnDecrypt` before the Hierarchical Keyring is called.

**Con, a second interface for a single behavior**:  
The Cache Guard ([4.3](#43-a-cache-guard)) achieves the same at the cache,
which the Hierarchical Keyring already consults before any remote call.

### 4.3 A Cache Guard

A cache,
one per Tenant Hierarchical Keyring,
wrapping the cache every Tenant shares.

`GetCacheEntry` fails,
with an error other than `EntryDoesNotExist`,
while its Branch Key ID has an honored Negative Cache Entry;
the Hierarchical Keyring then fails without calling the AWS KMS Key Store.
Otherwise,
every operation is delegated to the shared cache.

**The Cache Guard checks before the shared cache**:  
Requirement 3 means a Denied Branch Key ID's cached materials MUST NOT be used;
so the Negative Cache Entry is checked first,
and a hit in the shared cache is not returned.

This also avoids the storm tracking cache:
checked after,
a miss would mark the Branch Key in flight,
and block concurrent callers,
before the Cache Guard could fail them.

A Denial for one Branch Key ID does not affect another (Requirement 2),
even one protected by the same KMS Key;
see [6](#6-why-the-branch-key-id-and-not-the-kms-key-arn).

**One Cache Guard per keyring**:  
The cache identifier is opaque;
a cache shared by every Tenant cannot tell which Branch Key ID a lookup is for.
A Cache Guard per Tenant Hierarchical Keyring is bound to that keyring's Branch Key ID,
and delegates to the one shared cache,
satisfying Requirement 7.

**The Cache Guard is a lightweight object**:  
A cache is normally a Heavy Object
([design.md, Heavy Object](./design.md#heavy-object));
it holds every entry.
While the Cache Guard is a cache,
it holds only its Branch Key ID's Negative Cache Entry, if any,
and a reference to the shared cache;
one per Tenant Hierarchical Keyring costs nothing of note.

**The Cache Guard passes through the error it received**:  
The Cache Guard fails `GetCacheEntry`
by raising the error the Tenant KMS Client received from AWS KMS,
as is,
from the Negative Cache Entry.

_Note_: The MPL maps an error raised by a native cache
with `_smithy_error_to_dafny_error`;
an error that is not an MPL error,
such as botocore's `ClientError`,
becomes an opaque error carrying it.
Thus,
the first Denial surfaces wrapped by the AWS KMS Key Store's error,
and later failures as an opaque error carrying the original;
the original error is the same in both.

**Encrypt and decrypt are treated the same**:  
A Denial from `GetActiveBranchKey` (encrypt)
and from `GetBranchKeyVersion` (decrypt)
create the same Negative Cache Entry for the Branch Key ID,
and the Cache Guard fails every lookup for that Branch Key ID,
for encrypt and decrypt,
and for every version (Requirement 3).

### 4.4 Author's conclusion

4.3.

## 5 What is a Denial?

These KMS errors are Denials:

| KMS error | Cause |
| --------- | ----- |
| `AccessDeniedException` | The Key Policy, a Grant, or an IAM Policy does not allow the request; including conditions on the encryption context |
| `DisabledException` | The KMS Key is disabled |
| `KMSInvalidStateException` | The KMS Key is pending deletion, pending import, or otherwise unusable |
| `NotFoundException` | The KMS Key does not exist |
| `IncorrectKeyException` | The Branch Key was not encrypted under the KMS Key requested |

These are not:

**Transient failures**:  
Throttling (`ThrottlingException`),
KMS server errors (`KMSInternalException`, `DependencyTimeoutException`, HTTP 5xx),
and transport failures.
These are retried by the Shared Transport
([design.md 6](./design.md#6-retries)),
and say nothing about the Tenant's resources.

**Failures of the Tenant's credentials**:  
`UnrecognizedClientException` SHOULD never happen;
the credentials were issued for the Tenant.
An expired security token SHOULD cause the Tenant's credentials to be refreshed,
not the Branch Key ID to be Denied.

## 6 Why the Branch Key ID, and not the KMS Key ARN?

One KMS Key MAY protect many Branch Keys;
each Branch Key has its own encryption context.

KMS evaluates the encryption context of each request:
a Key Policy or Grant MAY allow `kms:Decrypt`
only for requests whose encryption context matches a condition
(for example, `kms:EncryptionContext:branch-key-id`,
or a custom `aws-crypto-ec:` attribute).
Thus,
KMS MAY deny a fraction of the Branch Keys protected by one KMS Key,
and allow the rest.

A Denial is therefore a statement about a Branch Key,
not about a KMS Key;
keyed by KMS Key ARN,
one Denied Branch Key would deny every Branch Key protected by that KMS Key,
violating Requirement 2.

Keying by Branch Key ID also satisfies Requirement 6:
the Cache Guard never needs the KMS Key ARN,
which `Discovery` and `MRDiscovery` only learn from the DynamoDB item.

**The Branch Key ID is bound, not parsed**:  
For hierarchy version 1,
the KMS encryption context includes `branch-key-id`
(`framework/branch-key-store.md`, Encryption Context);
the Tenant KMS Client could read it from each `Decrypt` request.

However,
hierarchy version 2 uses the Branch Key's encryption context, untransformed,
as the KMS encryption context;
it need not include `branch-key-id`.

Thus,
the Tenant Keyring Factory binds the Branch Key ID
to the Tenant KMS Client it vends with each keyring,
and the Tenant KMS Client records a Denial against that Branch Key ID.
Where the request's encryption context includes `branch-key-id`,
the Tenant KMS Client SHOULD check it matches.

As a Tenant KMS Client is a few references
([design.md, Tenant KMS Client](./design.md#tenant-kms-client)),
one per Tenant Hierarchical Keyring,
rather than one per Tenant,
costs nothing of note.

## 7 Who builds a Tenant Hierarchical Keyring?

The Cache Guard,
the Tenant KMS Client,
and the Negative Cache Entries they share,
MUST be wired together per Branch Key ID;
and every Tenant Hierarchical Keyring MUST share
the Shared Transport,
the shared cache,
and the DynamoDB client.

### 7.1 A Branch Key ID Supplier

The [Branch Key ID Supplier](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-supplier)
selects a Branch Key ID per request,
from the encryption context,
within one keyring.

**Con, one keyring, many Branch Key IDs**:  
The Cache Guard and the Tenant KMS Client are bound to one Branch Key ID ([6](#6-why-the-branch-key-id-and-not-the-kms-key-arn));
a keyring whose Branch Key ID varies per request cannot bind them.

**Con, one AWS KMS Key Store, one KMS client**:  
A keyring has one AWS KMS Key Store,
and an AWS KMS Key Store one KMS client;
so a keyring serving many Tenants calls KMS with one set of credentials,
which [design.md](./design.md) exists to avoid.

### 7.2 A Tenant Keyring Factory

One per process.
It holds:

- the Shared Transport
- the shared cache
- the DynamoDB client
- the AWS KMS Key Store configuration,
  other than the KMS client
  (table name, Logical Key Store Name, AWS KMS Configuration, grant tokens)
- the Negative TTL (default 5 minutes)

Given a Branch Key ID,
the Tenant's Credentials,
and a stable Tenant identity ([8](#8-the-partition-id-revisited)),
it vends a Tenant Hierarchical Keyring,
built with:

- a Tenant KMS Client, bound to the Branch Key ID
- an AWS KMS Key Store, using that Tenant KMS Client
- a Cache Guard, bound to the Branch Key ID, delegating to the shared cache
- the Branch Key ID, statically
- a Partition ID derived from the stable Tenant identity

**This changes the guidance of [design.md 10](./design.md#10-the-hierarchical-keyring)**:  
which offers a Branch Key ID Supplier as the simpler multi-tenant design
when Tenants do not require distinct KMS credentials.
With negative caching,
the Branch Key ID MUST be static per keyring,
and the factory takes the Branch Key ID Supplier's place:
the application selects the Branch Key ID,
and asks the factory for that Branch Key ID's keyring.

### 7.3 Author's conclusion

7.2.

## 8 The Partition ID, revisited

[design.md 10.2](./design.md#102-the-partition-id) derives the Partition ID
from the SHA-384 digest of the Tenant's secret access key.

**No part of refreshed credentials is constant**:  
botocore's `RefreshableCredentials` replaces
the access key,
the secret key,
and the session token
on every refresh
(`botocore/credentials.py`, `_set_from_data`);
every STS issuance
(`AssumeRole`, `AssumeRoleWithWebIdentity`, and the like)
returns a new temporary access key id, secret, and session token.
Only long term IAM user keys are constant,
until they are rotated.

Thus,
with refreshable credentials,
every Tenant's Partition ID changes on every refresh,
roughly hourly with STS's default session duration;
and every Tenant misses the shared cache once per refresh.
[design.md 10.2](./design.md#102-the-partition-id) called this miss intended;
in practice it is a periodic, synchronized cache miss for every Tenant,
which the shared cache exists to soften.

**What the Partition ID protects**:  
A keyring with Tenant B's credentials and Tenant A's Branch Key ID,
through misconfiguration,
MUST NOT be served Tenant A's cached materials
without KMS authorizing Tenant B.
A Partition ID per Tenant identity provides this;
a Partition ID per credential issuance is not needed for it.

**Decision**:  
The Partition ID SHOULD be derived from a stable Tenant identity
(for example, the Tenant's identifier, or the ARN of the role its credentials assume)
supplied to the Tenant Keyring Factory,
rather than from the Tenant's Credentials.

As with any cache,
a revoked KMS authorization is not noticed until a cached entry expires;
once a fetch is Denied,
the Cache Guard enforces it (Requirement 3).

UPDATE: The fix to the existing example is deferred to a later change;
[design.md 10.2](./design.md#102-the-partition-id) records this.

## 9 The storm tracking cache

The Cache Guard sits in front of the storm tracking cache,
and does not change its configuration
([design.md 10.1.1](./design.md#1011-why-not-the-mpls-defaultcache)).

**The first Denial still holds a fan out slot**:  
The fetch that is Denied
was made after the storm tracking cache returned a miss,
and so holds its fan out slot until the in flight TTL;
the Cache Guard prevents every later fetch,
so it holds no more.

**Blocked callers are not released early**:  
Callers that were already blocked in the storm tracking cache,
on the same Branch Key,
when the Denial occurred,
remain blocked until the in flight TTL.
Callers after the Denial are failed by the Cache Guard,
without reaching the storm tracking cache.

## 10 Should a `NotFoundException` propagate across Branch Key IDs?

A KMS Key that does not exist does not exist for every Branch Key it protects;
a `NotFoundException` for one Branch Key ID could create a Negative Cache Entry
for every Branch Key ID protected by that KMS Key.

**It requires mapping KMS Keys to Branch Key IDs**:  
which the Cache Guard does not otherwise need
([6](#6-why-the-branch-key-id-and-not-the-kms-key-arn)).
Under `Discovery` and `MRDiscovery`,
the KMS Key of a Branch Key is only known from its DynamoDB item.

**The KMS Key of a Branch Key is mutable**:  
A Branch Key's KMS Key is not fixed at creation.
The Branch Key Storage changes for Mutations
([aws-encryption-sdk-specification#287](https://github.com/awslabs/aws-encryption-sdk-specification/pull/287),
branch `tony/bks-storage-mutations`,
`changes/2025-01-17_key-store-storage-mutations/background.md`)
add operations that "facilitate changing the properties of all items of a Branch Key";
the MPL's `mutations/mutations` branch changes the KMS Key ARN of all items of a Branch Key
(`Mutations(TerminalKmsArn := ...)`;
`AwsCryptographyKeyStoreAdmin/test/Mutations/TestKmsArnChanged.dfy`).
Thus,
a mapping from KMS Keys to Branch Key IDs can become stale,
and would need to be kept consistent with mutations.

This is also why a Negative Cache Entry is bounded by the Negative TTL:
a Denied Branch Key MAY be mutated to a KMS Key the Tenant does allow,
and the Branch Key ID is retried once the Negative TTL expires.

**It is an optimization**:  
Each Branch Key ID is Denied on its own first failure regardless.

### 10.1 Author's conclusion

No;
each Branch Key ID is Denied on its own.

# Open Questions

1. **The Negative TTL**:
   its default, and whether it is configured per factory or per Branch Key ID.

   UPDATE: Configured per Tenant Keyring Factory; the default is 5 minutes.

2. **The error a Cache Guard raises**:
   its type,
   and whether it carries the original KMS error code
   (for example, as an MPL `ComAmazonawsKms` error, or with the code in its message).

   UPDATE: The Cache Guard passes through the error it received, as is
   ([4.3](#43-a-cache-guard)).

3. **Thread safety**:
   Negative Cache Entries are written by Tenant KMS Clients
   and read by Cache Guards,
   on any thread.

   UPDATE: There is no reason the Tenant Keyring Factory,
   and the objects it vends,
   are not thread safe;
   they MUST be (Requirement 8),
   and this SHOULD be tested.

4. **A Denial on encrypt versus decrypt**:
   whether a Denial on `GetActiveBranchKey` and on `GetBranchKeyVersion`
   are treated alike;
   Requirement 3 suggests they are.

   UPDATE: They are treated the same ([4.3](#43-a-cache-guard)).

# Consequences

- The fail fast behavior depends on the MPL returning a cache error,
  other than `EntryDoesNotExist`, without calling the AWS KMS Key Store
  ([1](#1-where-does-the-hierarchical-keyring-call-aws-kms));
  this is behavior, not a documented interface.
- Negative caching requires the Tenant KMS Client ([3.3](#33-the-tenant-kms-client)).
- Every Tenant Hierarchical Keyring has a static Branch Key ID ([7.2](#72-a-tenant-keyring-factory)).
