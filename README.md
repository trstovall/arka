
# arka - "Adaptive Sound Money (ASM)"

## A Community Managed Digital Money Supply

## Functions of Money

### Store of Value

The first function of money is to serve as a store of value - that is, to be desirable.  Money is a placeholder that replaces goods and services in a barter system.  There is the expectation that when you sell goods, like a chair, for money, at some future time, you can buy goods of equivalent value, like a chair of similar quality, with that money.

The primary selling point of Bitcoin is that the value of its money has not only kept its value over time, but it has gained value.  This is in stark contrast to centralized money like the US Dollar whose value has significantly and predictably decayed every year.

While the monetary supply in `arka` is not fixed like in Bitcoin, the supply is managed by the community who are incentivized to achieve the goal of `arka` becoming a store of value.

### Unit of Account

Units are fixed measurements.  Establishing a unit of account is required for understanding how much value is being offered when buying or selling.  Although the value of centralized money decays annually, that value is relatively predictable.  It is stable enough to establish an understanding of how much value is transferred in a monetary transaction.

The value of bitcoin has dramatically increased over time.  However, that history is marked by enormous increases and decreases in value, making it impossible to grasp how much value is transferred in a monetary transaction without converting to a currency whose value is better understood.  This is not expected to change.  The fixed supply of bitcoin encourages speculative bubbles and subsequent crashes, as demand for a currency is historically unstable.

Users of `arka` are empowered to set parameters that both inflate and deflate the supply of money.  They are incentivized to judge demand and set an appropriate supply of money that establishes a stable unit of account.  As the currency matures, stability will become self-reinforcing.

### Medium of Exchange

When money is used as a medium of exchange, a market is created where goods and services are bought and sold in exchange for the money instead of other goods and services.  Hence, the money must not only be desireable and attain a value that is understood, but it must be transferrable.  In the U.S., the Federal Reserve issues paper notes and coins, called cash, to use as a medium of exchange.  This cash may be used to buy and sell goods and services in person.  However, commerce is becoming increasingly digital and global.  So, a vast bank network has been established where users sell their cash to banks for bank credit, then use the bank credit to exchange online.

Bitcoin provides an alternative to this.  It is native to the digital world and globally available.  However, payment throughput is severely limited.  The developers of Bitcoin's software determine the maximum throughput of payments, and they have committed to selecting a low throughput to create an auction market for payments.  The network then prioritizes payments based on fees payed to the network, driving up the fees.  This greatly limits Bitcoin's potential as a medium of exchange.

`arka` is also a digital native.  Payment fees are set by the community and the default limit to payment throughput is roughly 80 times greater than with Bitcoin.  It is important to note that the `arka` community is empowered to determine payment throughput by setting the payment fees, and the software is merely configured to avoid network congestion.  This is in contrast to Bitcoin where throughput (and, consequently, fees) is determined by software developers.  The expectation for `arka` is to achieve a high throughput of payments with very low fees.

## "Better than Bitcoin"

For a long time, gold was used as money.  It is a scarce resource with a (somewhat) fixed supply.  However, governments around the world decided that the supply of gold was not adaptive enough to match the demand.  So, those governments replaced gold with "fiat" - money supplied by centralized governmental bodies and backed only by the promise that the monetary supply will be managed responsibly.

Bitcoin represents a reactionary return to gold, but for a modern world.  Bitcoiners insist that centralized money has not been managed responsibly.  So, instead, Bitcoin rejects the notion of a managed supply and reinstates a fixed supply.  Bitcoin is digital gold.

But, digital gold is as bad as gold.  Bitcoin isn't good money because it doesn't provide a stable unit of account.  `arka` users maintain that centralized money has not been managed responsibly.  `arka` presents an opportunity have the community manage the monetary supply, avoiding both the political influence that has corrupted centralized money and demand/supply mismatch that plagues Bitcoin and precious metals.

## Blocks

Updates to the `arka` database are structured as a fixed sequence of "blocks".  A block is an ordered list of the payments that have been published to the network since the last block.  This sequence of blocks forms a "blockchain", an openly auditable data structure that allows all users of the `arka` network to agree on the state of the database.  The structure of a block is as follows:

    ---
    # common to all blocks
    height: int                             # block id, strictly increasing
    timestamp: int                          # microseconds since UNIX epoch
    prev_block: bytes                       # hash digest of most recent block in chain
    uid: bytes                              # public key or truncated key hash digest of block creator
    nonce: bytes                            # H(H({block} - {nonce}) | nonce) ~= 0

    # exists only in epoch blocks (every 10000th block)
    parameters:                             # Adjusted parameters for epoch (10000 blocks)
      target: (byte, byte)                  # difficulty to create a block (average # of hashes)
      block_reward: int                     # units created by block creator
      utxo_fee: int                         # rate of decay of UTXOs (age of UTXO * UTXO units)
      data_fee: int                         # units per byte in each transaction are to be destroyed

    # each block includes a list of payments
    payments:

      - from:                                 # sources are non-expired UTXOs

        # spend a UTXO
        - index: (int, int, int)              # block index | payment index | output index
          spender: SpenderKey or SpenderList  # key set that hashes to or matches UTXO uid

        to:                                   # destinations are UTXOs

          # create a UTXO
          - uid: bytes                          # public key or truncated key hash digest of receipient
            units: int                          # 1 coin = 2**30 units
            memo: bytes                         # can be used for layer 2 protocols

            # optional vote to adjust parameters, weighted by units and aggregated across epoch (10000 blocks)
            vote:
              block_reward: int                 # units created by block creator
              utxo_fee: int                     # rate of decay of UTXOs (age of UTXO * UTXO units)
              data_fee: int                     # units per byte in each transaction are to be destroyed

          # commit data
          - memo: bytes                         # can be used for layer 2 protocols

        signatures: list[bytes]               # digital signatures of payment created by keys listed as spenders


## Blockchain consensus with Proof-of-Work (PoW)

The blockchain is a linked list which begins with a particular block that sets the parameters for the given chain followed by a sequence of blocks.  Blocks provide a `prev_block` field, which is the hash digest of the most recent previous block, forming a linked list block chain.  The chain is partitioned into subchains of 10,000 blocks that share the same parameters, as determined through voting.

Blocks are generated periodically by random peers performing computational work.  If the hash digest of a valid block is a member of a relatively small set determined by the work `target` consensus parameter, then the hash represents a valid proof of work.  The block adds a list of payments to the block chain.  Miners, computational units aimed at generating blocks, should listen for blocks and payments and adjust their own blocks accordingly.

To compute the hash digest of a block, deterministicly represent the object, minus the `nonce` field, as a binary string.  Hash the string with Keccak-f1600.  Then, concatenate the that hash digest with the `target` and `nonce` and hash again with Keccak-f800.  `target` consists of an 8-bit `base` and 8-bit `exp` such that `difficulty == base * (2 ** exp)`.  The proof of work is valid if the 8-bit prefix of the hash digest is numerically greater than or equal to `base` and is followed by at least `exp` number of zero bits.

The `payment` list defines `from`, a list of unspent transaction outputs from previous blocks that claim previous payment outputs, and redistributes the total balance, minus a data fee, to `to` a new list of payment outputs.  Payment outputs are optionally associated to a list of votes which determine chain consensus parameters.  
