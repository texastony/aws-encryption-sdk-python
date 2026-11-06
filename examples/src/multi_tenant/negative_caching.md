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
or by the Tenant's Credentials
(expired, unrecognized, or not matching their signature),
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
   including Branch Key IDs protected by the same KMS Key;
   nor the same Branch Key ID for any other Tenant
   ([7.2](#72-a-tenant-keyring-factory)).

3. While a Negative Cache Entry is honored,
   the Branch Key ID's cached materials MUST NOT be used,
   for encrypt or decrypt,
   for any version of the Branch Key.

4. Only a [Denial](#5-what-is-a-denial) MUST create a Negative Cache Entry;
   transient failures (throttling, server errors, timeouts) MUST NOT.
   Expired, unrecognized, and mis-signed credentials are Denials
   ([5.1](#51-expired-credentials-are-a-denial), [5.2](#52-unrecognized-and-mis-signed-credentials-are-denials)).

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
with the error the Tenant KMS Client received from AWS KMS,
the same object,
from the Negative Cache Entry;
wrapped,
so it survives the MPL's conversion to and from Dafny:
it raises `OpaqueWithTextError(obj=error, obj_message=str(error))`.

UPDATE: An earlier revision raised the error itself.
The MPL converts an error raised by a native cache
with `_smithy_error_to_dafny_error`,
and converts it back with `_deserialize_error`
before the ESDK-Python raises it.
Raised as is,
a botocore `ClientError` became an `OpaqueError`,
whose `str()` is empty;
the code was only reachable inside it.

The author compared the wrappers for all eight Denial codes,
with a realistic AWS KMS message that does not contain its code,
through a real Hierarchical Keyring on encrypt and decrypt:

| Wrapper | The code survives | The original error, the same object | The code in the outermost `str()` |
| ------- | ----------------- | ----------------------------------- | --------------------------------- |
| `ComAmazonawsKms(message=error)` | 4 of 8 | never | 4 of 8, on encrypt only |
| `OpaqueWithTextError(obj=error, obj_message=str(error))` | 8 of 8 | 8 of 8 | never |

**A `ComAmazonawsKms` error loses the code of the KMS errors the MPL models**:  
It is converted by the MPL's AWS KMS shim,
as a real AWS KMS failure would be;
the KMS errors the MPL models
(`DisabledException`, `KMSInvalidStateException`, `NotFoundException`, `IncorrectKeyException`)
become typed errors that keep only their message,
and the code is lost.
Dafny keeps only the error's data,
so the original object is lost for every code.

**An `OpaqueWithTextError` keeps both**:  
Dafny's opaque errors carry the Python object itself;
`obj` is the original error, the same object,
and `obj_message` its text, which names the code.

**But not in `str()`**:  
The MPL generates `OpaqueWithTextError` with an empty message,
so its `str()` is always empty;
its `repr()`, and its `obj_message`, name the code.
On decrypt,
the ESDK-Python raises its own error
("No Configured KMS Key was able to decrypt the Data Key"),
with the Cache Guard's error within the MPL's `CollectionOfErrors`,
whichever wrapper is raised.
Thus,
the Branch Key ID, the code, and the error's text are logged when a Denial is recorded,
which is where an operator sees them.
AWS KMS's message MAY name account ids or role ARNs;
neither is secret.

**A new wrapper per raise**:  
Re-raising one exception object appends each raise's frames to its traceback;
it would grow without bound,
keeping every frame,
and its locals,
alive for as long as the Denial is honored.
A new wrapper per raise does not.

**The first Denial loses more**:  
The first Denial is a real cache miss:
AWS KMS's error passes through the MPL's AWS KMS shim,
and surfaces as the AWS KMS Key Store's error.
The author confirmed, against DynamoDB Local with the fake KMS,
that for the four KMS errors the MPL models
no `str()`, no `repr()`, and no object in the error names the code;
and that the original error is never kept.
Thus,
the Cache Guard's failures carry more than the first Denial's;
the code of the first Denial is in the log.

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
| `ExpiredTokenException` | The Tenant's Credentials have expired; see [5.1](#51-expired-credentials-are-a-denial) |
| `UnrecognizedClientException` | KMS does not recognize the access key id or the session token; see [5.2](#52-unrecognized-and-mis-signed-credentials-are-denials) |
| `InvalidSignatureException` | The request's signature does not match the credentials' secret, or its timestamp; see [5.2](#52-unrecognized-and-mis-signed-credentials-are-denials) |

These are not:

**Transient failures**:  
Throttling (`ThrottlingException`),
KMS server errors (`KMSInternalException`, `DependencyTimeoutException`, HTTP 5xx),
and transport failures.
These are retried by the Shared Transport
([design.md 6](./design.md#6-retries)),
and say nothing about the Tenant's resources.

### 5.1 Expired credentials are a Denial

UPDATE: An earlier revision of this document,
and of Requirement 4,
treated expired credentials as transient,
expecting them to cause the Tenant's Credentials to be refreshed.
Nothing does so;
they are a Denial.

**botocore only refreshes credentials proactively**:  
`RefreshableCredentials` checks its expiry whenever its credentials are read
(`get_frozen_credentials()`),
and refreshes them before they expire
(`botocore/credentials.py`, `_refresh` and `_protected_refresh`):

- within the advisory refresh window (15 minutes before expiry),
  one caller refreshes without blocking others;
  if the refresh fails, the current credentials keep being used
- within the mandatory refresh window (10 minutes before expiry),
  every caller blocks until a refresh succeeds;
  if the refresh fails, the error is raised to the caller,
  and no request is made

**botocore never refreshes credentials reactively**:  
No error code for an expired token
(`ExpiredToken`, `ExpiredTokenException`, `RequestExpired`, `InvalidClientTokenId`)
appears in botocore's source or its retry configuration (`data/_retry.json`);
the standard retry mode treats none of them as transient or throttling.
A request rejected for an expired token is neither retried nor followed by a refresh.

The Tenant KMS Client reads the Tenant's Credentials on every attempt
([design.md 8](./design.md#8-tenant-credentials)),
and so is refreshed exactly as a boto3 client would be.

**Thus, an expired token that reaches AWS KMS will not resolve by retrying**:  
It means botocore's proactive refresh is absent or failing:

- the credentials cannot be refreshed
  (for example, `Credentials` constructed from an STS response, without a refresh function)
- the refresh source has been failing through the advisory refresh window
- the local clock disagrees with AWS,
  so botocore believes the credentials have not expired

In each case the next request fails identically,
and,
were it not a Denial,
every request would call Amazon DynamoDB and AWS KMS,
which this design exists to prevent.

**Recovery is bounded by the Negative TTL**:  
Once the cause is resolved
(the refresh source recovers, the clock is corrected, the credentials are replaced),
the Branch Key ID remains Denied until its Negative Cache Entry expires;
at most the Negative TTL.

**Each Branch Key ID is Denied on its own**:  
Expired credentials affect every Branch Key ID the Tenant uses;
as with [10](#10-should-a-notfoundexception-propagate-across-branch-key-ids),
each Branch Key ID is Denied on its own first failure,
rather than propagating the Denial across a Tenant's Branch Key IDs.

**AWS KMS returns `ExpiredTokenException`**:  
The author signed an AWS KMS `GenerateDataKey` request,
through the Tenant KMS Client,
with temporary credentials from `sts:GetSessionToken`
one minute after they expired;
AWS KMS returned HTTP 400,
`ExpiredTokenException`:
"The security token included in the request is expired".

### 5.2 Unrecognized and mis-signed credentials are Denials

UPDATE: An earlier revision of this document
excluded `UnrecognizedClientException`,
as it SHOULD never happen for credentials issued for the Tenant.
That remains true of correctly wired credentials;
but when it does happen,
it will not resolve by retrying,
which is the property that makes a failure a Denial.

The author probed AWS KMS (`us-west-2`, `GenerateDataKey`)
through the Tenant KMS Client,
varying one part of the credentials at a time:

| Credentials | AWS KMS error |
| ----------- | ------------- |
| An access key id that does not exist | `UnrecognizedClientException` |
| Long term keys, with a bogus session token | `UnrecognizedClientException` |
| Temporary credentials, without their session token | `UnrecognizedClientException` |
| Temporary credentials, with a corrupted session token | `UnrecognizedClientException` |
| A real access key id, with the wrong secret | `InvalidSignatureException` |
| Temporary credentials, with the wrong secret | `InvalidSignatureException` |
| Valid temporary credentials (`sts:GetSessionToken`) | success |

**`UnrecognizedClientException`**:  
AWS KMS does not recognize the access key id or the session token:
an access key id that was never issued, or was deleted;
a session token that is bogus, corrupted, or attached to long term keys;
or temporary credentials whose session token was dropped.
AWS also documents this error for session tokens issued by the global STS endpoint
(version 1 tokens, by default)
when used in a Region that must be enabled (opt-in Regions);
the author did not test this.

**`InvalidSignatureException`**:  
The request's signature does not match the credentials' secret access key.
AWS also documents this error for a request whose timestamp is too far from AWS's clock
(clock skew);
the author did not test this.

**These are usually the application's, not the Tenant's**:  
Unlike the KMS Key Denials,
these are most often caused by how the application obtains,
stores,
or passes the Tenant's Credentials,
or by its clock.
Negative caching does not fix them;
it stops every request from calling Amazon DynamoDB and AWS KMS.
The cause remains available:
the Branch Key ID and the code are logged when the Denial is recorded,
and the Cache Guard's error carries the original error, the same object
([4.3](#43-a-cache-guard)).

**Each Branch Key ID is Denied on its own**:  
as in [5.1](#51-expired-credentials-are-a-denial).

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

UPDATE: Hierarchy version 2 was never shipped;
hierarchy version 1 is the only hierarchy version,
and the AWS KMS Key Store's `Decrypt` always includes `branch-key-id`.
The Branch Key ID is still bound rather than parsed:
the Cache Guard needs it before any request is made,
and the binding does not depend on the encryption context's format.
The Tenant KMS Client checks the `branch-key-id`,
and its source says it assumes hierarchy version 1.

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
- the storm tracking cache shared by every Tenant, which it creates
- the DynamoDB client
- the AWS KMS Key Store configuration,
  other than the KMS client
  (table name, Logical Key Store Name, AWS KMS Configuration, grant tokens)
- the cache limit TTL of the keyrings it vends (default 10 minutes)
- the Negative TTL (default 5 minutes)

**The factory creates the shared cache**:  
It takes the storm tracking cache's settings
(default: those of [design.md 10.1.1](./design.md#1011-why-not-the-mpls-defaultcache)),
rather than a cache,
and creates the cache itself.
The specification requires the storm tracking cache's grace period
be less than the Hierarchical Keyring's cache limit TTL
(`framework/aws-kms/aws-kms-hierarchical-keyring.md`, Initialization);
only the factory knows both,
so only it can enforce this.
It also prevents a cache that is not a storm tracking cache,
or whose time units were not set,
from being shared by every Tenant.
The shared cache is exposed, read only, to the application and to tests.

Given a Tenant's identifier,
a Branch Key ID,
and the Tenant's Credentials,
it vends a Tenant Hierarchical Keyring,
built with:

- a Tenant KMS Client, recording Denials in the negative cache of that Tenant and Branch Key ID
- an AWS KMS Key Store, using that Tenant KMS Client
- a Cache Guard, enforcing that negative cache, delegating to the shared cache
- the Branch Key ID, statically
- the Tenant's identifier, as is, as the Partition ID ([8](#8-the-partition-id-revisited))

**Negative caches are per Tenant and Branch Key ID**:  
The factory holds one negative cache per Tenant and Branch Key ID,
and every keyring it vends for that Tenant and Branch Key ID shares it;
so a Denial recorded through one is enforced by all.

UPDATE: An earlier revision of this document keyed negative caches by Branch Key ID alone.
Then,
a Tenant misconfigured with another Tenant's Branch Key ID,
and so Denied by AWS KMS,
would deny that Branch Key ID to the Tenant that owns it;
one Tenant's misconfiguration MUST NOT deny another Tenant (Requirement 2).
The shared cache is already partitioned by Tenant ([8](#8-the-partition-id-revisited));
the negative caches now are too.

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

UPDATE: The Partition ID is the Tenant's identifier, as is;
it is not a secret, so there is no reason to digest it.

As with any cache,
a revoked KMS authorization is not noticed until a cached entry expires;
once a fetch is Denied,
the Cache Guard enforces it (Requirement 3).

UPDATE: The fix to the existing example is deferred to a later change;
[design.md 10.2](./design.md#102-the-partition-id) records this.

**The Tenant identifier is the authorization boundary of cached materials**:  
The shared cache's entries are identified by
the Partition ID,
the Logical Key Store Name,
and the Branch Key ID
([Appendix A](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas));
not by the credentials.
Thus,
a keyring vended for a Tenant identifier and Branch Key ID
is served the materials cached by any earlier keyring
vended for the same pair,
whatever credentials either was vended with,
until the entry expires or is Denied.

Vended keyrings are a few references
around the MPL's formally verified Hierarchical Keyring;
applications need not cache them,
and MAY vend one per request or per tenant connection.
An application that does
relies on each new keyring,
built with fresh credentials,
being served the entries of the keyrings before it.

This is a security decision of this design:
the consuming application's choice of Tenant identifier and Branch Key ID
is critical.
The application MUST pass the Tenant Keyring Factory
the identifier of the Tenant it authenticated,
never one taken from the request,
and the Branch Key ID it assigned to that Tenant.

**An alternative: the credentials as the Partition ID**:  
A Partition ID derived from the credentials,
as [design.md 10.2](./design.md#102-the-partition-id) does,
would make the credentials the boundary:
a keyring would be served only the entries
fetched with its own credentials.
To keep the cache from holding materials
for credentials no longer in use,
the Tenant Keyring Factory would additionally
delete a Branch Key's entries from the shared cache
when AWS KMS Denies it,
and when a vended keyring is cleaned up
(for example, on its tenant connection closing).
Its cost is
the cache miss per credential refresh described above,
and a vended keyring the application MUST clean up.
This design does not take it.

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

   UPDATE: As is, but wrapped in an `OpaqueWithTextError`,
   so the original error, the same object, and its code survive the MPL's conversion to and from Dafny;
   the code is also logged when the Denial is recorded ([4.3](#43-a-cache-guard)).

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

5. **Contention on the Tenant Keyring Factory's lock**:
   `negative_cache_for` takes one lock, per factory,
   to look up or create a Tenant and Branch Key ID's negative cache;
   the Key Store and keyring are built outside it.
   At service startup,
   a burst of keyrings vended at once contends on it.
   If that matters,
   a partitioned (striped) map,
   like that behind Guava's cache,
   would spread it.
   A stress test on the factory SHOULD decide.

# Consequences

- The fail fast behavior depends on the MPL returning a cache error,
  other than `EntryDoesNotExist`, without calling the AWS KMS Key Store
  ([1](#1-where-does-the-hierarchical-keyring-call-aws-kms));
  this is behavior, not a documented interface.
- Negative caching requires the Tenant KMS Client ([3.3](#33-the-tenant-kms-client)).
- Every Tenant Hierarchical Keyring has a static Branch Key ID ([7.2](#72-a-tenant-keyring-factory)).
- The Cache Guard's error depends on how the MPL converts native cache errors to and from Dafny,
  which is generated code, not a documented interface;
  its outermost `str()` does not name the code, and an operator relies on the log ([4.3](#43-a-cache-guard)).
