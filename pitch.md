
# The Technology Innovation

The Arkatekt team is proposing the arka network, a digital money project similar to Bitcoin.  However, instead of a fixed supply like Bitcoin, the supply of arka is adaptive and determined by the community.

Three parameters influence the supply -- "block reward", "data fee", and "utxo fee".  These parameters are updated weekly based on median weighted voting.  Votes are optionally associated with payment transactions, and the votes are weighted by the amount of the payment.  The block reward is inflationary; it is an allowance paid at fixed intervals to network participants chosen by computational lottery.  The fees are deflationary; they are simply destroyed.  The data fee is proportional to the size (in bytes) of the payment.  It taxes the "medium of exchange" function of money.  The utxo fee is proportional to the age and value of the unspent transaction outputs claimed by a payment transaction.  This taxes the "store of value" function of money.

Thousands of Bitcoin-like digital money projects have been created in recent years.  Common to these Bitcoin clones is the design of either a fixed supply, or a supply that does not match demand.  This results in speculative bubbles and subsequent crashes leading to currencies that are unable to provide a stable unit of account.

A handful of existing projects recognize the need for an adaptive supply to maintain stability.  These "stablecoins" adopt various technical mechanisms to algorithmically stabilize the price of the currency.  Yet, they all tie the value of the currency to an external asset or centrally managed currency.

Instead, arka relies on the phenomenon of "the wisdom of the crowd" to determine responsible parameter values to allow and encourage a stable unit of account to emerge.

Bitcoin fails to provide a good medium of exchange.  Payment throughput is limited by the developers of network software.  Transaction costs are a function of this.  The developers compromise between high, unstable transaction costs as a result of low payment throughput, or easily spammed blockchains as a result of high payment throughput.

arka inverts this.  The community decides transaction costs directly -- granting it agency over blockchain size and payment throughput.

Like Bitcoin, arka utilizes a computational lottery called "proof-of-work mining".  Miners must invest substantial capital into specialized hardware and electricity to compete for the block reward.  This creates a network of nodes with a large financial interest in maintaining the integrity of the payment network.  Arguably, Bitcoin overpays for security, because the block reward was hard-coded into the software in 2009.  Since the arka community has direct agency over the block reward, it has an opportunity to be much greener, paying only for security that is "good enough".

Why will arka be adopted?  arka is the future of money -- a decentralized, independent, digital money that builds on the wisdom of the crowd to promise a high quality store of value, medium of exchange, and unit of account.

# The Technical Objectives and Challenges

The first technical objective is to determine and implement a digital signature algorithm responsible for securing digital ownership.  "ed25519" has been selected and fully implemented in a C extension to Python, delivering the performance of C with the exposure to Python.

The second objective is to specify the serialization format of transactions and blocks and implement serialization.

The third objective is to determine and implement a proof-of-work algorithm.  "keccak-800" has been selected and implemented based on the Keccak family of cryptographic hash algorithms described by the SHA3 specification.

The fourth objective is to create a set of on-disk indexes that replicate the information described by the blockchain but in a format that is computationally efficient to access and maintain.  This presents the first challenge.  The tail of the blockchain may be replaced.  So, a checkpoint is periodically established.  A historical index holds the information in the blockchain before the checkpoint, and a changelog holds the information after.

The fifth objective is to implement the weighted median algorithm to determine network parameters from votes.  The challenge is that the dataset is split into two large files and must be computed without loading the whole dataset into memory and must be fast enough to avoid adding latency to block mining.  The solution is to keep the historical partition sorted, and sort the changelog in memory.

The sixth objective is to implement a distributed network where each node seeks to position itself in the center of the network.  This way miners have low-latency access to the end of the blockchain, and merchants can quickly evaluate the probability that a payment transaction will be committed to the blockchain.  The challenge is to score peers based on connectivity.  The solution is to rank peers on the latency with which they broadcast transactions and the quality of blocks they broadcast.  Quality of blocks is a measure of how well new blocks meet expectations on committing payments to the blockchain.  Network communication is ordered by peer rank, pushing low performing nodes to the edge of the network.

The seventh objective is to implement a graphical user interface for sending payments.  The GUI will be available on mobile and desktop devices.  The challenge is to deliver a quality point-of-sale experience, and allow users to view account balances and vote on network parameters.  The "kivy" framework will be selected for the interface.  QR codes and NFC communication will arrange payment details.  Sliding scale elements will allow users to set voting preferences, and votes will be associated with payments.

The eighth and final objective is to deliver a well documented Python API for interacting with the arka network.  This will allow independent teams to spawn projects that "innovate at the edge".  Requirements are subject to community feedback.

# The Market Opportunity

Money is a necessity of nearly every person.  arka provides a revolutionary digital option.  For the first time, the community decides not just the demand for a currency, but the supply as well.  The customers are the people who want a direct voice in the governance of their money.

The ecosystem serves a broad range of users.  Merchants and businesses need a reliable, cost-effective payment system.  Everyday users want a digital cash without extreme volatility.  Investors and institutions seek a decentralized alternative to fiat-based stablecoins.  Developers and require a stable crypto-economic foundation.  Unbanked and underbanked populations seek financial access in unstable fiat regions.  Sovereign states seek independence from foreign monetary policy.

While Bitcoin has a fixed supply and high decentralization, it also has high volatility and high transaction fees, making it poorly suited for payments.  Stablecoins like USDT provide an alternative that have low volatility and low transaction fees making them well suited for payments, yet they are highly centralized and pegged to fiat.

arka can compete.  It allows its community to solve Bitcoin's economic flaws by eliminating extreme volatility and high fees.  It removes stablecoin reliance on fiat-backing while maintaining purchasing power stability.  It offers a decentralized and censorship-resistant alternative to both Bitcoin and traditional stablecoins.  It attracts businesses and developers with a stable, scalable economic foundation.  Its potential to revolutionize payments, investment, and decentralized applications positions it as a leading innovation in blockchain finance.

# The Company and Team

Arkatekt, Inc. is a brand new startup seeking to revolutionize digital finance.  The team proposing the arka project will be led by Primary Investigator Thomas Stovall.  Thomas will be assisted by a to-be-hired entry level Python developer.

Thomas is a veteran software engineer with over a decade of professional and academic experience developing solutions in Python and C.  He has contributed significantly to distributed network communication and computation, distributed database development, high performance computing, cloud computing, and cryptographic security.

Task 1 is to finish development of the network software.  Thomas has completed development of the necessary cryptographic libraries and data serialization library.  He has sketched out the network communication library and the indexed data persistence library, and he has contributed significant coding effort to those libraries.  Thomas estimates 6 months of effort to finish development, testing, and documentation of this software.

Task 2 is to implement a user interface (UI) that connects to the network and provides functionality to send and receive money, check account balances, etc.  This UI will be deployed to both desktop and mobile devices.  Thomas has limited experience in this area, but he has deployed proofs-of-concept and consulted with generative AI giving him confidence this task will take about 6 months of effort.

Task 3 is to deploy the network software and user interface to actual users, monitor network behavior, remedy software bugs, and implement priority functionality requests.  The to-be-hired Python developer will assist Thomas with this effort.  The task will be allocated 12 person-months.
