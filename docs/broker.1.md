# Central command broker

The central broker is the communication boundary between the network and the
database. All commands, incoming discoveries, outgoing replies, and database
events crossing that boundary are logged through it. The database coordinator
interprets those messages and distributes storage work among the database workers;
the broker does not itself validate transactions or decide which branch is canonical.

This document distinguishes the existing implementation in
[arka/broker.py](../arka/broker.py) from the logging and routing extensions
required by that architecture. Worker interfaces are described in
[db.2.md](db.2.md), persistence in [db.md](db.md), and concurrent branch handling
in [forks.md](forks.md).

## Existing broker interface

```python
Address = tuple[str, int]

class Broker(AbstractBroker):
    def __init__(self): ...
    def sub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue): ...
    def unsub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue): ...
    def pub(self, event: AbstractBrokerEvent): ...
```

`AbstractBroker` and `AbstractBrokerEvent` are empty base classes. `Broker`
maintains a mapping from event classes to sets of subscriber queues.

- `sub` adds a queue to the set for one event class. Repeated subscription of the
  same queue to the same class is idempotent.
- `unsub` discards that queue from the selected set.
- `pub` snapshots the subscriber set for `type(event)` and calls `put_nowait`
  on each queue. Subscribing to the base event class does not receive subclasses.
- A full subscriber queue is silently skipped. Publication returns no delivery
  acknowledgement or result.

These methods are synchronous and intended to be called in the owning event-loop
thread. There is no broker-owned task, persistent log, replay cursor, request ID,
or reply correlation table. Subscriber order is unspecified because subscriptions
are sets. Each queue receives the same mutable event object, not a copy.
Consequently, the present implementation is a best-effort notification bus, not
yet the reliable logged command boundary described above.

## Existing event definitions

Every current event contains `addr: Address` identifying the peer involved.

| Event | Additional fields | Meaning at the network boundary |
| --- | --- | --- |
| `PeerConnected` | None | Peer connection established |
| `PeerDisconnected` | None | Peer connection ended |
| `PeerTransactionsSubscribed` | None | Peer subscribed to transaction announcements |
| `PeerTransactionsUnsubscribed` | None | Peer cancelled that subscription |
| `PeerTransactionsPublished` | `tx_hashes: dict[int, TransactionHash]` | Peer advertised transaction identifiers and hashes |
| `PeerTransactionsRequested` | `ids: set[int]` | Peer requested transactions |
| `PeerTransactionsResponded` | `txs: dict[int, Transaction]` | Peer supplied transaction bodies |
| `PeerBlocksSubscribed` | None | Peer subscribed to block announcements |
| `PeerBlocksUnsubscribed` | None | Peer cancelled that subscription |
| `PeerBlocksPublished` | `id: int`, `hash: BlockHash` | Peer advertised a block height/identifier and hash |
| `PeerBlocksRequested` | `ids: set[int]`, `mode` | Peer requested headers, summaries, or blocks |
| `PeerBlocksResponded` | Homogeneous list of `Block`, `BlockHeader`, or `BlockSummary`; `mode` | Peer supplied the requested representation |

`mode` is one of `HEADER`, `SUMMARY`, or `BLOCK`. The constructors store their
arguments without validating payload consistency. Peer-advertised IDs must retain
peer/session context; an identifier alone is not a global transaction identity.
An announcement is evidence of what a peer claims to possess, not local validation.

In [net.py](../arka/net.py), decoded network messages generate these peer events.
Its broker consumer currently subscribes only to connection and disconnection
events for peer announcements. [consensus.py](../arka/consensus.py) subscribes to
the current event types and forwards block-related events to per-peer handlers;
several transaction paths only print messages. These consumers do not yet implement
the complete database coordinator and outbound command protocol.

There are currently no dedicated POW-chain events, extended-function I/O events,
or database-to-network transaction/block reply classes in `broker.py`. A header
can contain POW, but that is not a complete POW-chain request/reply protocol.

## Required communication flow

```text
peer -> network decoder -> central broker journal -> database coordinator
                                                     |
                                                     v
                                        candidate-local database workers
                                                     |
                                                     v
peer <- network encoder <- central broker journal <- replies and events
```

The network handles connections, wire framing, decoding, and sending. It reports
peer findings and requests through the broker. The coordinator chooses the
appropriate candidate/view, obtains lookups from workers, validates supplied data,
and sends replies or publishes events back through the broker. Workers do not
write directly to peer queues or sockets.

The broker records messages, identifies their destinations, and routes them.
The coordinator owns database task decomposition, consensus context, validation
scheduling, and result assembly. Internal worker lookups use the queue protocol
in `db.2.md`; they need not become public network messages. If internal tracing
is also retained, distinguish it from the network/database command journal.

### Coordinator task distribution

| Incoming message | Coordinator work |
| --- | --- |
| Transaction announcement | Compare hashes with known/pending transactions; request missing bodies |
| Transaction bodies | Validate independently on canonical and auxiliary candidates; resolve inputs, derive UTXO/vote deltas, reserve keys |
| Transaction request | Resolve requested IDs in the proper peer context; reply with available transaction bodies or explicit status |
| Block announcement | Compare advertised ancestry/tip with known candidates; schedule missing headers and bodies |
| Block/header/summary response | Associate with the pending request, check identity, and advance only a contiguous validated candidate prefix |
| Block request | Ask BlocksDB for the requested view and representation; assemble the network response |
| POW-chain announcement/response | Ask POWDB and BlocksDB about ancestry; schedule validation data without displacing canonical state |
| POW-chain request | Read a bounded chain segment from a pinned view and return it with its ancestry identity |
| Extended-function input | Dispatch to a registered handler with declared input/output schema and validation context |

UTXOsDB supplies unclaimed-output lookups; DeltasDB and VoteDeltasDB store derived
updates; the four ParameterDB instances maintain votes and epoch publications.
The coordinator combines these tasks into one coherent result. Merely delivering
a peer POW message cannot authorize POWDB to change the canonical tip.

## Commands, replies, and events

Extend the protocol with explicit direction and message role. A proposed common
envelope is:

```text
BrokerEnvelope:
    schema_version, message_type
    message_id, correlation_id | absent, causation_id | absent
    source, destination
    peer_address, peer_session_id | absent
    candidate_id, generation_id, view_revision | absent
    payload_bytes

JournalRecord:
    sequence_number, envelope, checksum
```

A command requests work and has a terminal reply. A reply echoes the relevant
correlation ID and identifies the answered request. An event reports a fact or
state transition and may have several subscribers. Long operations may emit
progress events followed by a terminal success/error reply; progress does not
constitute acceptance. Database events such as a canonical-tip change are emitted
only after the corresponding database commit becomes visible.

Keep inbound peer reports distinct from outbound commands. For example, an
outbound `SendTransactions` must not be republished as `PeerTransactionsResponded`
and accidentally re-enter validation as if the peer had sent it. Names for new
classes remain implementation choices; roles and direction must be unambiguous.

POW-chain messages need a starting ancestor, bounded sequence/range, claimed tip,
and request correlation. The coordinator validates ordering against headers and
tracks advertised versus fully validated progress. Extended-function messages
need a registered function identifier/version, invocation ID, typed input/output,
and success/error status. They do not authorize arbitrary Python execution or
unrestricted access to database files. Side-effecting handlers need the same
idempotency and commit discipline as other commands.

## Central communication journal

The required logging is a broker responsibility, not a print statement in a
subscriber. Use an append-only framed journal containing the envelope and enough
payload bytes to reconstruct the communication. A content-addressed payload
reference is sufficient only if the referenced immutable content is durably
retained for the journal's retention interval; a hash alone cannot replay a body.

Assign a monotonic broker sequence, durably record an accepted message, then make
it eligible for delivery. If recording fails, do not claim that the command was
accepted or silently forward it outside the journal. The concrete journal path,
codec, retention period, and durability batching are implementation decisions;
this journal is distinct from `db/deltas` and `db/vote_deltas`, which describe
state changes rather than communication.

Log both directions: incoming reports/requests and outgoing requests/replies/events.
An outbound intent is not proof of transmission. Record send failure or completion
separately, and distinguish local send completion from any peer acknowledgement.
Similarly, journal admission, subscriber delivery, database validation, and block
commit are different milestones.

Use immutable serialized payloads at journal admission so later subscriber
mutation cannot alter the recorded message. Preserve list order where meaningful;
use a defined ordering when encoding sets or maps for deterministic replay.
Validate message limits before accepting oversized input into the durable journal.

### Delivery and replay

The current `put_nowait`/skip behavior is insufficient for commands and replies.
Use per-consumer delivery cursors and bounded queues backed by the retained journal.
A full queue delays that consumer's delivery instead of discarding the command.
One slow auxiliary candidate or peer must not block canonical delivery: schedule
consumers independently and define bounded lag/retirement policies.

A reliable logger cannot be implemented merely by subscribing one queue to
`AbstractBrokerEvent`: exact-type dispatch would deliver nothing, and a bounded
logging queue could also drop events. Logging must occur in the central publication
path before fan-out, or through an explicit journal-first ingress API.

After a restart, replay undelivered commands using durable consumer progress and
idempotency keys. Do not promise exactly-once execution just because every message
has been logged. A consumer may have committed a result before its delivery cursor
was recorded. Database operations must detect an already-applied batch by identity;
network resends and extended-function side effects require their own retry rules.

Replayed historical tip events do not independently change canonical state: the
database's committed generation remains authoritative. Where database commit and
outbound event recording are separate durable operations, persist an outgoing
intent with the commit, or reconstruct a stable event ID from committed records
and journal it on recovery. This closes the crash gap between state publication
and its announcement without duplicating state effects.

## Examples

### Transaction discovered by a peer

```text
1. Network journals PeerTransactionsPublished(peer, {local_id: tx_hash}).
2. Coordinator finds the body missing and journals an outbound transaction request.
3. Network receives and journals PeerTransactionsResponded(peer, {local_id: tx}).
4. Coordinator correlates the response and fans immutable bytes to both candidates.
5. Candidates reply independently with accepted, rejected, conflict, or stale status.
6. Coordinator journals any network reply or announcement with its relevant context.
```

The broker journal preserves receipt order. It does not force both candidates to
have the same result or wait for each other. A rejection on one branch does not
become a global rejection of that transaction on every branch.

### Longer POW chain with slow block delivery

```text
peer reports a longer POW chain
    -> journal -> coordinator -> ancestry lookup and candidate registration
coordinator requests missing headers/blocks
    -> journal -> network -> peer
peer supplies individual responses
    -> journal -> coordinator -> auxiliary validation tasks
fully validated branch becomes longer than current canonical state
    -> coordinated generation publication -> journal canonical-tip event
```

Canonical transaction processing continues while auxiliary data arrives. Only
fully validated ancestry contributes to promotion. Neither the peer's statement
that it accepted a chain nor the journal's recording of that statement advances
the local canonical POW tip.

## Implementation sequence

Retain the existing peer event classes as the initial vocabulary. Add immutable
versioned envelopes, outbound command/reply types, POW-chain messages, and explicit
extended-function messages. Implement journal-first ingress, correlation,
consumer cursors, and backpressure before relying on reliable delivery. Connect
the network adapter and coordinator through this path; then connect the
coordinator to candidate-local worker groups.

Test exact-type subscription behavior, full queues, reconnect/session identity,
out-of-order replies, replay after a partial commit, failed outbound sends,
branch-qualified validation, and journaling failure. The central invariant is:
all accepted communication crossing the database/network boundary has a retained
broker record, while only validated, committed database results are announced
as accepted chain state.
