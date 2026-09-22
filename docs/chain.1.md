# Chain state and database deltas

This document describes the delta records in [arka/chain.py](../arka/chain.py)
and their relationship to [arka/block.py](../arka/block.py).
[block.1.md](block.1.md) specifies the block byte representation and hash
relations; [block.2.md](block.2.md) presents the data definitions and a concrete
serialized block. This document describes the corresponding state changes.

`chain.py` currently provides record definitions and input dispatch. Database
lookup, delta construction, validation, and application are largely unimplemented.
The state-transition relations below describe the intended interpretation of
`ref`, `old`, and `new`; they are not claims of an existing storage engine.

## Delta model

A delta identifies a logical collection, a reference within that collection,
and the value before and after a change:

`Delta = (collection, ref, old, new)`

The concrete update class selects the collection. `ref` selects its record.
`None` denotes record absence, not an amount of zero.

| `old` | `new` | Interpretation |
| --- | --- | --- |
| `None` | Value | Insert a previously absent record |
| Value | `None` | Remove an existing record |
| Value | Value | Replace an existing record |
| `None` | `None` | No state change; usefulness or rejection is unspecified |

For logical state `S` and result `S'`, the declarative application relation is:

`S[collection, ref] = old`

`S'[collection, ref] = new`

All other records retain their values. Absence on the right means removal.
The first relation is a consistency precondition: applying an update to a
state different from its recorded pre-state is not justified by that delta.
The implementation does not yet enforce this precondition.

Swapping `old` and `new` describes the inverse change. Reversing a sequence of
changes also requires reversing its order. These relations permit reversible
state descriptions but do not establish implemented rollback, fork handling,
or transaction atomicity.

## Record definitions

`AbstractDeltaItem` is an empty common base. It defines no application,
serialization, equality, or hashing operations.

Two state values are defined in `chain.py` rather than `block.py`:

```python
BlockReward(publisher: block.SignerKey | block.SignerHash, units: int)
ExecutiveFund(units: int)
```

All update constructors have the form below; `Key` and `Value` are descriptive
placeholders resolved by the table, not exported generic classes:

```python
Update(ref: Key, old: Value | None = None, new: Value | None = None)
```

| Update class | Reference type | Value type | Logical collection |
| --- | --- | --- | --- |
| `BlockRewardUpdate` | `int` | `chain.BlockReward` | Publisher rewards by block height |
| `ExecutiveFundUpdate` | `int` | `chain.ExecutiveFund` | Executive funds by block height |
| `ArkaUTXOUpdate` | `block.UTXORefByIndex` | `block.ArkaUTXO` | Unspent ARKA outputs |
| `AssetUTXOUpdate` | `block.UTXORefByIndex` | `block.AssetUTXO` | Unspent asset outputs |
| `ExecutiveDefinitionUpdate` | `block.Nonce_16` | `block.ExecutiveDefinition` | Executive definitions by identifier |
| `AssetDefinitionUpdate` | `block.Nonce_16` | `block.AssetDefinition` | Asset definitions by identifier |
| `ExecutiveVoteUpdate` | `block.Nonce_16` | `block.ExecutiveVote` | Executive votes by executive identifier |

These are logical collection names, not declared SQL tables or filesystem paths.
Constructors generally retain references directly and perform no validation or
copying. In particular, `old` and `new` are not immutable snapshots merely
because they occur in a delta. Preserving their before/after meaning requires
that their represented content remain unchanged while the delta is retained.

`BlockRewardUpdate` is currently an exception to the common record shape:
its constructor assigns `old = old` and `new = new`, without creating
`self.old` or `self.new`. The intended fields are visible in its signature and
consumer code, but are not stored by the current constructor.

## Relationship to transaction inputs

`Chain.transaction_input_delta(input)` dispatches by input type:

| `block.py` input | Chain method | Declared delta result | Reference source |
| --- | --- | --- | --- |
| `PublisherSpend` | `publisher_spend` | `BlockRewardUpdate` | `input.block` |
| `ExecutiveSpend` | `executive_spend` | `ExecutiveFundUpdate` | `input.block` |
| `UTXOSpend` | `utxo_spend` | `ArkaUTXOUpdate` or `AssetUTXOUpdate` | Resolved `input.utxo` |
| `ExecutiveDefinition` | `executive_definition` | `ExecutiveDefinitionUpdate` | `input.executive` |
| `AssetDefinition` | `asset_definition` | `AssetDefinitionUpdate` | `input.asset` |

The reference-source column describes the correspondence implied by the data
fields; the dispatched methods are stubs. They do not yet construct these
updates. Unsupported inputs fall through the dispatcher without an explicit
error, despite its annotated result type.

For a spend, `old` supplies the existing resource against which authorization
and available units can be checked. Removal is represented by `new=None`.
For a definition, `old=None` distinguishes initial registration from replacement
of a previous definition; `new` represents the resulting definition. The exact
replacement and deletion policy remains to be implemented.

### UTXO reference resolution

The block format admits both positional and hash-based UTXO references:

```python
UTXORefByIndex(block: int, tx: int, output: int)
UTXORefByHash(tx_hash: TransactionHash, output: int)
```

Both UTXO delta classes use positional references. The declared lookup boundary
is therefore:

```python
async def utxo_by_hash_to_index(
    self, ref: block.UTXORefByHash,
) -> block.UTXORefByIndex | None: ...

async def utxo_by_index(
    self, ref: block.UTXORefByIndex,
) -> block.ArkaUTXO | block.AssetUTXO | None: ...
```

The hash identifies a transaction using the signature-excluding digest described
in `block.1.md`; the output index selects an output within it. Resolving it to a
block position requires chain state beyond the transaction bytes. No persistent
hash-to-position index or its update format is currently defined.

## Relationship to outputs and headers

A transaction output becomes a state record in the context of its accepted block.
For block height `H`, transaction position `i`, and output position `j`, a new
UTXO has reference `UTXORefByIndex(H, i, j)`. The output itself does not contain
that reference; the containing sequences supply its position.

| Block data | Corresponding state description |
| --- | --- |
| `ArkaUTXO` output | Insert an ARKA UTXO using `ArkaUTXOUpdate` |
| `AssetUTXO` output | Insert an asset UTXO using `AssetUTXOUpdate` |
| `ExecutiveVote` output | Relates to `ExecutiveVoteUpdate` through its executive identifier |
| `BlockHeader.publisher` and applicable reward parameters | Supply information for a publisher reward record |
| Applicable executive-fund parameters | Supply information for an executive fund record |

Output dispatch and reward/fund creation are not implemented in `chain.py`.
An executive identifier alone does not distinguish multiple votes for that
executive. The present vote record does not specify aggregation, per-voter
identity, replacement, or expiration semantics; these cannot be inferred as
implemented database behavior.

`ArkaUTXO` also carries optional parameter votes. Their payload is retained when
an ARKA output is retained, but no separate delta class specifies vote totals.
There are likewise no dedicated header, parameter, transaction-index, or
chain-tip delta classes.

## Example: the transfer in block.2.md

The example block has height 101, one transaction at position 0, and one output
at position 0. Its input spends `(100, 0, 0)`. Conditional on successful
validation and an existing ARKA output at that reference, its UTXO changes are:

```python
from arka import block, chain

previous: block.ArkaUTXO  # Existing record at (100, 0, 0).
example: block.Block      # The example constructed in block.2.md.

changes = [
    chain.ArkaUTXOUpdate(
        ref=block.UTXORefByIndex(block=100, tx=0, output=0),
        old=previous,
        new=None,
    ),
    chain.ArkaUTXOUpdate(
        ref=block.UTXORefByIndex(block=101, tx=0, output=0),
        old=None,
        new=example.transactions.transactions[0].outputs[0],
    ),
]
```

The second value is the 1,000-unit output represented in the block bytes.
The first value comes from the database and is not reconstructed from the spend
input alone. Its units must support the transfer under the applicable fee and
validation rules. This is a declarative UTXO-change example, not the complete
block delta or a claim that the illustrative signature is valid.

The 307-byte serialization in `block.2.md` contains transaction instructions and
outputs. It contains neither these update wrappers nor their `old` snapshots.
Decoding that block therefore cannot, by itself, produce the database delta.

## Validation, ordering, and parameters

The declared chain entry point is:

```python
async def validate(self, tx: block.Transaction) -> list[AbstractDeltaItem]: ...
```

It is a stub. The partial consumer in
[consensus.py](../arka/consensus.py), `Consensus.transaction_delta`, obtains
input deltas, examines `old` records for signer and balance checks, and begins
signature verification. Its output branches are unfinished and it does not
return its annotated pair of delta lists. That annotation alone does not define
the meaning of two completed batches.

Input lookup results are paired with inputs in transaction order. A future
application layer must define how successive changes to the same reference
observe earlier changes, and how a failed transaction avoids partial updates.
Current code establishes no committed ordering, conflict resolution, or
all-or-nothing database write mechanism.

`BLOCKS_IN_EPOCH = 10_000`. `Chain.parameters(height)` selects the epoch using
`height // 10_000`; for epoch zero it returns `genesis.GENESIS.header.parameters`.
Later epochs raise `NotImplementedError`. With no height argument it uses
`self.height`. The parameter value is a `block.Parameters` record, whose compact
target and integer representation are documented in `block.1.md`.

## Persistence and implementation boundary

`Chain.__init__` expands the home path and creates its directory, defaulting to
`~/.arka/chain` with mode `0o700`. It does not initialize a database, `_height`,
or `_hash`. The `height` and `state` properties read those uninitialized fields
unless another caller supplies them. `forks` is a class-level dictionary, with
no implemented fork-storage protocol.

Reward/fund lookup, input delta construction, UTXO lookup and resolution,
`accept`, `expire`, `validate`, `checkpoint`, `fork`, `hash`, and `signer` remain
stubs. Their annotations describe intended interfaces, not completed effects.

No delta encoding, database schema, transaction log, commit operation, or delta
hash is specified. A `block.py` value with an `encode()` method may provide a
record payload, but that does not define collection tags, database keys,
old/new presence markers, or persistence framing. The block wire format and its
Merkle root must therefore not be treated as a database-delta serialization or
a hash of the database state.
