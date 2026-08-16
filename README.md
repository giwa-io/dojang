Markdown
# Dojang
**Trusted offchain facts, verifiably issued onchain.**

Dojang is a service that issues offchain information (outside the blockchain) as onchain attestations on the GIWA chain. It plays an important role in linking onchain wallet addresses with offchain information. This allows users to hold an onchain identity without revealing Personally Identifiable Information (PII) from their wallet.

Dojang aims to establish the trust layer of the GIWA ecosystem by leveraging Ethereum Attestation Service (EAS).

## Contracts

### GIWA Testnet (Sepolia)

- Schemas

| Schema Name      | Description                                          | Schema Content                                                                          | Schema ID                                                            | Schema UID                                                           |
|------------------|------------------------------------------------------|-----------------------------------------------------------------------------------------|----------------------------------------------------------------------|----------------------------------------------------------------------|
| Verified Address | Wallet address which is verified by a trusted issuer | `bool isVerified`                                                                       | `0x568eb581cdf80b03d3bdfa414f3203bfdcc4bba4e66355612bd0e879da812f06` | `0x072d75e18b2be4f89a13a7147240477481c4b526d5795802acba59046b426e08` |
| Balance Root     | Root of a Merkle tree of balances                    | `uint256 coinType,uint64 snapshotAt,uint192 leafCount,uint256 totalAmount,bytes32 root` | `0xf09c1384d860519bb4ea5bb2a45ab64b00a8d900d47fb79203663be6da21e06c` | `0x369faa9c2cd261c45be3db5e230b585f5f19eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK` |
| Verified Balance | User's balance verified by a trusted issuer          | `uint256 balance,bytes32 salt,bytes32[] proofs`                                         | `0x06c3bd846f5ea60b0b6f5a835ef85fd8253b53f67917d6c690be628d032f841b` | `0x77bf88ca262cc63e1b185dccd870aacc5320b8987ef6c7169920f265fe6ab5e9` |
| Verified Code    | Authentication code verified by a trusted issuer     | `bytes32 codeHash,string domain`                                                        | `0x68053e055c01ce9b3577f3162b36324bb195ebcb574c48e823480d205f06af9b` | `0x55ac1369dac97522d062b89ffdc4e752b48fbeba86915fdb956c7c2d0501d280` |

- Contracts

| Name                      | Description                                                           | Address                                                                                                                             | Version       |
|---------------------------|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|---------------|
| SchemaRegistry            | Handles schema registration and lookup                                | [`0x4208aa98d4aa139ac2dbfc5e5da4d7591f190020`](https://sepolia-explorer.giwa.io/address/0x4208aa98d4aa139ac2dbfc5e5da4d7591f190020) | v1.3.1-beta.2 |
| EAS                       | Issues, revokes, and fetches attestations                             | [`0x42088b084fd03014f5e4cce15c4901b3098e0021`](https://sepolia-explorer.giwa.io/address/0x42088b084fd03014f5e4cce15c4901b3098e0021) | 1.4.1-beta.3  |
| SchemaBook                | Manages the list of registered schemas                                | [`0x78c6718174052b23ae5c7658ef779804a3cb3ad6`](https://sepolia-explorer.giwa.io/address/0x78c6718174052b23ae5c7658ef779804a3cb3ad6) | v0.2.0        |
| DojangAttesterBook        | Manages the list of attesters used in Dojang                          | [`0xda22b919424d1e440763ca78737dfc1441d828b6`](https://sepolia-explorer.giwa.io/address/0xda22b919424d1e440763ca78737dfc1441d828b6) | v0.2.0        |
| AttestationIndexer        | Indexes all Dojang attestations for query                             | [`0x9c9b57d4289749606c6c401641d9fd7a41ff90ec`](https://sepolia-explorer.giwa.io/address/0x9c9b57d4289749606c6c401641d9fd7a41ff90ec) | v0.2.0        |
| AddressDojangResolver     | Triggered on issuance or revocation of a Verified Address attestation | [`0x692c283eeec8500f88634ffcb36dabfcda6a7f9e`](https://sepolia-explorer.giwa.io/address/0x692c283eeec8500f88634ffcb36dabfcda6a7f9e) | v0.2.0        |
| BalanceRootDojangResolver | Triggered on issuance or revocation of a Balance Root attestation     | [`0xd90fd00ae6e9c250830a0768b4d033cec9cfbed0`](https://sepolia-explorer.giwa.io/address/0xd90fd00ae6e9c250830a0768b4d033cec9cfbed0) | v0.4.0        |
| BalanceDojangResolver     | Triggered on issuance or revocation of a Verified Balance attestation | [`0x6ff71ffcb7c5f525ed2a40d7ff4f47f69c326dad`](https://sepolia-explorer.giwa.io/address/0x6ff71ffcb7c5f525ed2a40d7ff4f47f69c326dad) | v0.4.0        |
| VerifyCodeDojangResolver  | Triggered on issuance or revocation of a Verified Code attestation    | [`0x843c787015292d05db5d599bc07326d774d912df`](https://sepolia-explorer.giwa.io/address/0x843c787015292d05db5d599bc07326d774d912df) | v0.5.0        |
| DojangScroll              | Provides convenient read access to Dojang data                        | [`0xd502a43541695b844a10ea9fed6ee0cfa80217b9`](https://sepolia-explorer.giwa.io/address/0xd502a43541695b844a10ea9fed6ee0cfa80217b9) | v0.5.0        |


## Usage

### Install

```bash
npm install -g pnpm
pnpm install
curl -L [https://foundry.paradigm.xyz](https://foundry.paradigm.xyz) | bash
Build
Bash
pnpm dep        # install dependencies
pnpm build
CI
Test

Bash
pnpm test
Check Coverage

Bash
pnpm test:coverage
pnpm test:coverage-report
Lint

Bash
pnpm lint
pnpm lint:fix
Static Analysis  

Bash
pnpm slither
Deploy  
Bash
source .env
forge script script/deploy/00-Deploy.s.sol --rpc-url $RPC_URL --verifier blockscout --