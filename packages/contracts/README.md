# @giwa-io/dojang-contracts

TypeScript ABI and addresses for Dojang contracts on the GIWA chain.

ABIs are exported as `as const` literals, enabling full type inference with [viem](https://viem.sh).

## Install

```bash
npm install @giwa-io/dojang-contracts
# or
pnpm add @giwa-io/dojang-contracts
```

## Usage

```typescript
import { createPublicClient, http } from 'viem';
import { dojangScrollAbi, addresses } from '@giwa-io/dojang-contracts';

const client = createPublicClient({ chain: giwaSepolia, transport: http() });

const verified = await client.readContract({
  address: addresses[91342].DojangScroll,
  abi: dojangScrollAbi,
  functionName: 'isVerified',  // ← autocomplete
  args: [addr, attesterId],    // ← type-checked
});
```

## Exported ABIs

| Export | Source Contract | Description |
|--------|---------------|-------------|
| `dojangScrollAbi` | `IDojangScroll` | Address verification, balance verification, code verification queries |
| `attestationIndexerAbi` | `IAttestationIndexer` | Attestation UID lookups |
| `schemaBookAbi` | `SchemaBook` | Schema UID resolution |
| `dojangAttesterBookAbi` | `DojangAttesterBook` | Attester address resolution |

## Addresses

Chain-specific contract addresses are exported via `addresses`:

```typescript
import { addresses } from '@giwa-io/dojang-contracts';

addresses[91342].DojangScroll     // '0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9'
addresses[91342].EAS              // '0x4200000000000000000000000000000000000021'
addresses[91342].SchemaRegistry   // '0x4200000000000000000000000000000000000020'
```

## Development

```bash
# Requires forge build artifacts in out/
pnpm generate   # Extract ABIs and addresses → src/abi.ts, src/addresses.ts
pnpm build      # generate + tsup (ESM/CJS/dts)
pnpm test       # Verify ABI correctness + type-level checks
```
