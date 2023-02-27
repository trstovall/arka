
# Arka: A private and scalable transaction chain with monetary policy voting

## Features

- ___Arka monetary inflation is determined through stakeholder voting.___  Payment outputs are colored with votes that determine network parameter adjustments for each epoch.  The blockchain is a sequence of Work blocks and Payment blocks.  Every epoch (every 10,000 work blocks or about 1 week), the votes are collected from those blocks and the associated payment blocks, and the median for each network parameter is computed.  The result determines the network parameters for the next epoch.  The network parameters control the function of many features in Arka.
- To control the rate of inflation, you must first fairly measure time.  `target` is the only network parameter that is voted on by minters instead of stakeholders.  The miners are the time keepers, and are kept fair through proof of work voting.  In a proof-of-work, the target number of times a computation has been ran can be proven, without counting the iterations.  If you know approximately how long the computation takes, then you can fairly measure time.  Each work block has an associated timestamp, microseconds since 1970-01-01.  The timestamps in the epoch are collected and median voting determines the target for the next epoch.  The timestamps for each block are evaluated by the network when the work block is published to the network.  Each block is allowed a reward of `block_reward`.  The computation used is keccak-800 digest of the work block.
- Payment processing is stream oriented, not batch oriented like Bitcoin.  Work blocks elect minters who collect the monetary inflation allowed for the block period.  That money (arka coin) can be transferred between accounts in payment blocks.  Once one or more payments are broadcast to the network, the elected minter collects the payments into a payment block, signs the block with its identifier, and commits them to the Payment collection (blockchain).  The next elected minter confirms the commit by selecting a blockchain that includes the payment block and inserts a link to that blockchain in its work block.
- Offline minting can produce proof-of-work stamps that may be redeemed for arka coin.  This is useful for sending memos in the Arka network without associating the memo to an any particular payment activity.  It also provides a counterbalance to help stabilize the currency by providing a speculative asset that may be redeemed for the currency.  The offline minters should receive a reduced rate of reward when compared to the block minters, as block minting is crucial to network operation.  However, `stamp_reward` may be increased to reduce the rate of computation currently performed by the network and is used in conjuction with `block_reward`.
- ___Monetary supply may be deflated___.  Blockchain data users are charged a usage fee that is paid to no party.  It is simply removed from the supply.  The usage rate is provided by `data_fee`.
- Blocks in the blockchain are retired after an `expiry` number of epochs have passed.  This means that old and unspendable coin is reclaimed by the network, and data can be discarded.

## Chain consensus with PoW

### Work blocks

    ---
    # common to work blocks and payment blocks
    index: int                              # work block count, exclusive
    timestamp: int                          # microseconds since UNIX epoch, unique and increasing
    prev_block: bytes                       # 32-byte digest of most recent block (work or payment) in chain
    prev_link: bytes                        # hash digest of most recent block or payment link

    # common to all blocks
    uid: bytes                              # ed25519 public key of block link minter
    nonce: bytes                            # H(H({block} - {nonce}) | parameters.target | nonce) ~= 0

    # exists only in epoch links (every 10000th block link)
    parameters:                             # Adjusted parameters for epoch (10000 blocks)
      target: (byte, byte)                  # difficulty to mint a block link (average # of hashes)
      block_reward: int                     # 1000 coin minted by block link
      stamp_reward: int                     # reward = (stamp_reward * stamp.target) / target
      data_fee: int                         # units per byte in each transaction is to be destroyed
      expiry: int                           # forget transactions older than expiry number of epochs
    
### Payment blocks

    ---
    # common to work blocks and payment blocks
    index: int                              # payment block count since last work block, exclusive
    timestamp: int                          # hash digest of most recent block or payment link
    prev_block: bytes                       # 32-byte digest of most recent block (work or payment) in chain
    prev_work_block: bytes                  # 32-byte digest of most recent work block in chain

    # payment links are signed by prev_block.worker
    signature: bytes                        # 64-byte result of ed25519-sign of block digest by work block minter

    # each payment link includes a list of payments
    payments:                               # identifies link as a payment link

    - from:                                 # sources are non-expired UTXOs and workstamps

      # spend a UTXO
      - digest: bytes                       # block digest or H(link digest | payment index | output index)
        key: bytes                          # Present key that hashes to output address
        signature: bytes                    # 64-byte result of ed25519-sign of block digest by work block minter

      # spend a work stamp
      - uid: bytes                          # ed25519 public key used to spend work stamp
        target: bytes                       # 2-byte float from 0 to 2**256-1
        nonce: bytes                        # H(key | target | nonce) ~= 0, unique
        signature: bytes                    # 64-byte result of ed25519-sign of block digest by stamp minter

      to:                                   # destinations are UTXOs

      # create a UTXO
      - uid_hash: bytes                     # keccak-800 digest of receipient's public ed25519 key
        units: bytes                        # 1 coin = 2**30 units
        memo: bytes                         # can be used for layer 2 protocols

        # optional vote to adjust parameters, weighted by units and aggregated across epoch (10000 blocks)
        vote:
          block_reward: int                 # [-128:127] integer corresponding to +/- 10% adjustment
          stamp_reward: int                 # [-128:127] integer corresponding to +/- 10% adjustment
          data_fee: int                     # [-128:127] integer corresponding to +/- 10% adjustment
          expiry: int                       # [-128:127] integer corresponding to +/- 10% adjustment

      # commit data
      - memo: bytes                         # can be used for layer 2 protocols


### Consensus

The transaction chain is a linked list which begins with a particular authority transaction for the given chain followed by a sequence of payment transactions and authority transactions.

Authority transactions are generated periodically by random peers performing computational work.  If the hash digest of a valid authority transaction is a member of a relatively small set determined by the work `difficulty` consensus parameter, then the transaction represents a valid proof of work.  The elected `authority` then generates payment transactions, signing any pending payments and appending them to the transaction chain until a new authority transaction is added.  Miners, computational units aimed at generating transactions, should listen for transactions and adjust their own authority transactions accordingly.

To compute the hash digest of an authority transaction, deterministicly represent the transaction object, minus the `nonce` field, as a binary string.  Hash the string with SHAKE-256.  Then, concatenate the intermediate hash digest with the `nonce` and hash again with SHA256.  Difficulty consists of an 8-bit `base` and 8-bit `exp` such that `difficulty == (base + 1) * (2 ** exp) - 1`.  The proof of work is valid if the first 8-bit byte of the final hash digest is numerically greater than or equal to `base` and is followed by at least `exp` number of zero bits.

Transactions provide a `chain` field, which is the hash digest of the most recent previous transaction, forming a linked list transaction chain.  The transaction also provides a `prev_authority` field, which is the hash digest of the most recent previous authority transaction, forming a second chain that nodes can use to bootstrap their local chain data.  `offset` defines the number of milliseconds elapsed since the first miner began processing the transaction chain and is used to compute `difficulty` adjustments every 4096 blocks.  `difficulty` is adjusted proportionally to the time elapsed since the most recent previous adjustment (`new_difficulty := auth_period * sum(difficulty) / (2 * (median(clock) - old_clock))`).

The `payment` structure defines a set of unspent transaction outputs from previous transactions, and redistributes the total balance, minus transaction data tax, to a new set of outputs.  The `payment` structure also includes a set of votes which determine chain consensus parameters.  


## Network

    Packet(mtu=1300):
      sent: PacketHash
      to: Identifier
      from: Identifier | None
      timestamp: datetime
      nonce: bytes(16)
      data: decrypted(EncryptedFragments)

    Identifier = hash(PublicKey)

    EncryptedFragments = encrypted(list[Message | Fragment])

    Fragment:
      hash: FragmentHash
      message:
        hash: MessageHash
        nparts: int
      part: int
      data: bytes(range(64, 1024, 64)[0])
    
    Message = (
      TraceRequest | TraceResponse | ConnectRequest | ConnectResponse
      | Get | Put | JoinRequest | JoinResponse | LeaveRequest | LeaveResponse
      | ReserveRequest | ReserveResponse | SendRequest | SendResponse
      | Payment | Transaction | PaymentFragment | SignPayment | RevealCommits
    )

### UDP Hole punching

    <Registry>:
      id: <PublicKey>
      host: <static public IPv4 or DNS address>
      port: <UDP port for arka protocol>
      timestamp: <datetime>
      signature: <Signature>

    <UserAddress>:
      id: <PublicKey>
      host: <static or ephemeral public IPv4 or DNS address>
      port: <UDP port for arka protocol>
      timestamp: <datetime>
      signature: <Signature>

    <RegistryPayment>:
      to:
        units: <int>
        memo:
          type: user
          user: <UserAddress.id>
          veto: False
      from:
      - <UnspentTransactionOutput>

    <Register>:
      init:
      - <Registry>
      - <RegistryPayment>
      sequence:
      - <StartPacket from=predecessor to=registry data=GetAddress,RegistryPayment>
      - <ContinuePacket from=registry to=predecessor data=HasAddress>
      - <UserAddress>
      - <ContinuePacket from=predecessor to=registry data=GetSuccessor,UserAddress>
      - <ContinuePacket from=registry to=predecessor data=HasSuccessor>
      - <ContinuePacket from=registry to=successor data=HasSuccessor>
      - <StartPacket from=predecessor to=successor data=GetSuccessor>
      - <StartPacket from=successor to=predecessor data=GetSuccessor>
      - <ContinuePacket from=predecessor to=successor data=HasSuccessor>
      - <ContinuePacket to=predecessor data=HasSuccessor>
      

### DC network for broadcasting payments and transactions

Based on [Herbivore](https://www.cs.cornell.edu/people/egs/herbivore/herbivore.pdf)
