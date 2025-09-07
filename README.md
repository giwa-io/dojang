# Dojang
**Trusted offchain facts, verifiably issued onchain.**

Dojang is a service that issues offchain information (outside the blockchain) as onchain attestations on the Giwa chain. It plays an important role in linking onchain wallet addresses with offchain information. This allows users to hold an onchain identity without revealing Personally Identifiable Information (PII) from their wallet.

Dojang aims to establish the trust layer of the Giwa ecosystem by leveraging Ethereum Attestation Service (EAS).

## Contracts

### Giwa Testnet (Sepolia)

- Schemas

| Schema Name      | Description                                          | Schema Content    | Schema ID                                                            | Schema UID                                                           |
|------------------|------------------------------------------------------|-------------------|----------------------------------------------------------------------|----------------------------------------------------------------------|
| Verified Address | Wallet address which is verified by a trusted issuer | `bool isVerified` | `0x568eb581cdf80b03d3bdfa414f3203bfdcc4bba4e66355612bd0e879da812f06` | `0x072d75e18b2be4f89a13a7147240477481c4b526d5795802acba59046b426e08` |


- Contracts

| Name                  | Description                                                           | Address                                                                                                                             | Version |
|-----------------------|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|---------|
| SchemaRegistry        | Handles schema registration and lookup                                | [`0x4200000000000000000000000000000000000020`](https://sepolia-explorer.giwa.io/address/0x4200000000000000000000000000000000000020) | v0.1.0  |
| EAS                   | Issues, revokes, and fetches attestations                             | [`0x4200000000000000000000000000000000000021`](https://sepolia-explorer.giwa.io/address/0x4200000000000000000000000000000000000021) | v0.1.0  |
| SchemaBook            | Manages the list of registered schemas                                | [`0x78cBb3413FBb6aF05EF1D21e646440e56baE3AD6`](https://sepolia-explorer.giwa.io/address/0x78cBb3413FBb6aF05EF1D21e646440e56baE3AD6) | v0.1.0  |
| DojangAttesterBook    | Manages the list of attesters used in Dojang                          | [`0xDA282E89244424E297Ce8e78089B54D043FB28B6`](https://sepolia-explorer.giwa.io/address/0xDA282E89244424E297Ce8e78089B54D043FB28B6) | v0.1.0  |
| AttestationIndexer    | Indexes all Dojang attestations for query                             | [`0x9C9Bf29880448aB39795a11b669e22A0f1d790ec`](https://sepolia-explorer.giwa.io/address/0x9C9Bf29880448aB39795a11b669e22A0f1d790ec) | v0.1.0  |
| AddressDojangResolver | Triggered on issuance or revocation of a Verified Address attestation | [`0x692009FE206C3F897867F6BF7B5B45506B747F9e`](https://sepolia-explorer.giwa.io/address/0x692009FE206C3F897867F6BF7B5B45506B747F9e) | v0.1.0  |
| DojangScroll          | Provides convenient read access to Dojang data                        | [`0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9`](https://sepolia-explorer.giwa.io/address/0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9) | v0.1.0  |


## Usage

### Install

```bash
npm install -g pnpm
pnpm install
curl -L https://foundry.paradigm.xyz | bash
```

### Build

```bash
pnpm dep        # install dependencies
pnpm build 
```

### CI

- Test

```bash
pnpm test
```

- Check Coverage

```bash
pnpm test:coverage
pnpm test:coverage-report
```

- Lint

```bash
pnpm lint
pnpm lint:fix
```

- Static Analysis

```bash
pnpm slither
```

### Deploy

```bash
source .env
forge script script/deploy/Deploy.s.sol --rpc-url $RPC_URL --verifier blockscout --verifier-url $EXPLORER_URL --broadcast --slow --verify   
```
