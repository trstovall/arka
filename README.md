
# Arka: A Shake256 transaction chain with Ed25519 signatures

## Bank

### Send / Request Payment (Layer 1)

### Send / Request Receipt (Layer 2)

### Manage accounts and receipts (Layer 3)

- Create
- Organize
- Export
- Import

## Chain consensus with PoW

### Block

    ---
    # common to blocks and transactions
    id: 0                                       # Sequential transaction id
    clock: 0 (0y 0d 0h 0.000s)                  # milliseconds since chain launch
    chain: ...shake256...                       # 32-byte digest of previous transaction in chain

    # common to all blocks
    worker: ...ed25519 key...                   # worker's public key - all proceeds from this tx go to key
    difficulty: 2 ** 32                         # 2-byte float from 0 to 2**256-1 ([1-256] * 2 ** [0-248] - 1)
    nonce: 0-32 bytes binary                    # H(H(tx - nonce) | nonce) ~= 0

    # exists only in readjustment blocks
    parameter:                                  # Adjusted parameters - decided by weighted median voting
      inflation: 100 * 1024 * 1024              # 100 coin to be generated by each authority transaction
      tax_rate: 1024                            # 1024 units per byte in each transaction is to be destroyed
      block_period: 60 * 1000                   # Target period in ms between blocks
      block_expiry: 2 ** 40                     # forget transactions past expiration (~35 years, in ms)
      work_ratio: 0.5                           # proportion of reward from work payments vs. blocks

    # exists only to prove a previous block.worker attempted double spend
    challenge:
      block: ...shake256...                     # identify authority transaction by hash
      tx1: ...shake256...                       # Just need to identify two transactions...
      tx2: ...shake256...                       # ...listing all can be pushed to another layer
    
### Transaction

    ---
    # common to blocks and transactions
    id: 1                                       # Sequential transaction id
    clock: 0 (0y 0d 0h 0.000s)                  # milliseconds since chain launch
    chain: ...shake256...                       # hash of previous transaction in chain

    # non-block transactions are signed by most recent block.worker
    signature: ...ed25519 signature...          # 64-byte result of ed25519-sign tx by most recent block.authority

    # each transaction includes one payment
    payment:                                    # identifies tx as a payment transaction

      from:                                     # sources are non-expired UTXOs and workstamps

      # spend a UTXO
      - tx_hash: ...shake256...                 # identify payment or authority transaction
        out:                                    # authority txs have one out, payment txs have many
        - index: 0                              # index of entry in `tx[tx_hash].to`
          key: ...ed25519 key...                # Present key that hashes to address of UTXO
          signature: ...ed25519 signature...    # Payment signed by `tx[tx_hash].to[index].address`

      # spend a workstamp
      - worker: ...ed25519 key...
        difficulty: 2**32                       # 2-byte float from 0 to 2**256-1
        nonce: 0-32 bytes binary                # H(worker | difficulty | nonce) ~= 0, unique
        signature: ...ed25519 signature...      # Payment signed by worker

      to:                                       # destinations are UTXOs

      # create a UTXO
      - address: 0-32 bytes shake256 digest     # Receipients public ed25519 key hashed with SHAKE256
        units: 0                                # 1 coin = 1024*1024 units
        memo: 0-MEMO_LIMIT bytes binary         # can be used for layer 2 protocols
        vote:                                   # override payment level votes, rest are inherited.
            inflation: 50 * 1024 * 1024         # 50 coin per authority transaction

      # commit data
      - memo: 0-MEMO_LIMIT bytes binary         # can be used for layer 2 protocols

      # vote to adjust parameters, `weight = sum(to.units for to in tx.payment.to)`
      vote:                                     # applied to each entry in `tx.payment.to`
        inflation: ~                            # Amount of coin generated by blocks
        tax_rate: ~                             # Fee per byte of data used by transaction.
        block_period: 60 * 1000                 # Target period in ms between blocks
        block_expiry: 2 ** 40                   # forget transactions past expiration (~35 years, in ms)
        work_ratio: 0.5                         # proportion of reward from work payments vs. blocks

### Consensus

The transaction chain is a linked list which begins with a particular authority transaction for the given chain followed by a sequence of payment transactions and authority transactions.

Authority transactions are generated periodically by random peers performing computational work.  If the hash digest of a valid authority transaction is a member of a relatively small set determined by the work `difficulty` consensus parameter, then the transaction represents a valid proof of work.  The elected `authority` then generates payment transactions, signing any pending payments and appending them to the transaction chain until a new authority transaction is added.  Miners, computational units aimed at generating transactions, should listen for transactions and adjust their own authority transactions accordingly.

To compute the hash digest of an authority transaction, deterministicly represent the transaction object, minus the `nonce` field, as a binary string.  Hash the string with SHAKE-256.  Then, concatenate the intermediate hash digest with the `nonce` and hash again with SHA256.  Difficulty consists of an 8-bit `base` and 8-bit `exp` such that `difficulty == (base + 1) * (2 ** exp) - 1`.  The proof of work is valid if the first 8-bit byte of the final hash digest is numerically greater than or equal to `base` and is followed by at least `exp` number of zero bits.

Transactions provide a `chain` field, which is the hash digest of the most recent previous transaction, forming a linked list transaction chain.  The transaction also provides a `prev_authority` field, which is the hash digest of the most recent previous authority transaction, forming a second chain that nodes can use to bootstrap their local chain data.  `offset` defines the number of milliseconds elapsed since the first miner began processing the transaction chain and is used to compute `difficulty` adjustments every 4096 blocks.  `difficulty` is adjusted proportionally to the time elapsed since the most recent previous adjustment (`new_difficulty := auth_period * sum(difficulty) / (2 * (median(clock) - old_clock))`).

The `payment` structure defines a set of unspent transaction outputs from previous transactions, and redistributes the total balance, minus transaction data tax, to a new set of outputs.  The `payment` structure also includes a set of votes which determine chain consensus parameters.  


## Network

    <Packet>:
      to: <PublicKey>
      from: <PublicKey>
      nonce: <bytes(len=32)>
      message: <EncryptedMessage(len=range(64, 1024, 64)[0])>

### UDP Hole punching

    <Registry>:
      ipv6: <public IP-v6 address>
      port: <port for arka protocol>
      key: <PublicKey>
      signature: <Signature>

    <Register>:
      payment:
        from:
        - worker: <PublicKey>
          difficulty: <Difficulty>
          nonce: <bytes(len=0..32)>
          signature: <Signature>
        to:
        - units: <int>
          memo:
            namespace: arka-registry
            key: <PublicKey>
            signature: <Signature>
      peer: <PublicKey>
      signature: <Signature>

    <Peer>:
      registry: <RegistryHash>
      key: <PublicKey>
      ipv6: <public IP-v6 address>
      port: <port for arka protocol>
      registered: <Signature>

### DC network for broadcasting payments and transactions

Based on [Herbivore](https://www.cs.cornell.edu/people/egs/herbivore/herbivore.pdf)
