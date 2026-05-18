# Dojang Integration Example: Basic Attestation

This example demonstrates how to issue and verify attestations using Dojang on GIWA Testnet.

## Prerequisites

- Node.js v18+ installed
- Wallet with testnet ETH (get from [faucet](https://faucet.giwa.io))
- Basic understanding of Ethereum and attestations

## Installation

```bash
npm install ethers@^6.0.0
# or
yarn add ethers@^6.0.0
```

## Setup

### 1. Configuration

```typescript
// config.ts
export const GIWA_TESTNET_CONFIG = {
  chainId: 301824,  // GIWA Sepolia Testnet
  rpcUrl: "https://sepolia-rpc.giwa.io",
  explorerUrl: "https://sepolia-explorer.giwa.io",
  
  contracts: {
    EAS: "0x4200000000000000000000000000000000000021",
    SchemaRegistry: "0x4200000000000000000000000000000000000020",
    DojangAttesterBook: "0xDA282E89244424E297Ce8e78089B54D043FB28B6",
    AttestationIndexer: "0x9C9Bf29880448aB39795a11b669e22A0f1d790ec",
    AddressDojangResolver: "0x692009FE206C3F897867F6BF7B5B45506B747F9e",
    DojangScroll: "0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9",
  },
  
  schemas: {
    verifiedAddress: {
      uid: "0x072d75e18b2be4f89a13a7147240477481c4b526d5795802acba59046b426e08",
      schema: "bool isVerified"
    },
    balanceRoot: {
      uid: "0x369faa9c2cd261c45be3db5e230b585f5f1abecf8e12be575bb543e917e6db52",
      schema: "uint256 coinType,uint64 snapshotAt,uint192 leafCount,uint256 totalAmount,bytes32 root"
    },
    verifiedBalance: {
      uid: "0x77bf88ca262cc63e1b185dccd870aacc5320b8987ef6c7169920f265fe6ab5e9",
      schema: "uint256 balance,bytes32 salt,bytes32[] proofs"
    },
    verifiedCode: {
      uid: "0x55ac1369dac97522d062b89ffdc4e752b48fbeba86915fdb956c7c2d0501d280",
      schema: "bytes32 codeHash,string domain"
    }
  }
};
```

### 2. EAS Contract ABIs

```typescript
// abis.ts
export const EAS_ABI = [
  "function attest((bytes32 schema, (address recipient, uint64 expirationTime, bool revocable, bytes32 refUID, bytes data, uint256 value) data)) returns (bytes32)",
  "function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))",
  "function revoke((bytes32 schema, (bytes32 uid, uint256 value) data))",
];

export const SCHEMA_REGISTRY_ABI = [
  "function getSchema(bytes32 uid) view returns (tuple(bytes32 uid, address resolver, bool revocable, string schema))"
];

export const DOJANG_SCROLL_ABI = [
  "function isVerifiedAddress(address account) view returns (bool)",
  "function getVerifiedBalance(address account) view returns (uint256 balance, bytes32 salt, bytes32[] memory proofs)",
];
```

## Example 1: Issue a Verified Address Attestation

```typescript
// issue-address-attestation.ts
import { ethers } from "ethers";
import { GIWA_TESTNET_CONFIG, EAS_ABI } from "./config";

async function issueAddressAttestation() {
  // Connect to GIWA Testnet
  const provider = new ethers.JsonRpcProvider(GIWA_TESTNET_CONFIG.rpcUrl);
  
  // Load your attester wallet (must be registered in DojangAttesterBook)
  const attesterPrivateKey = process.env.ATTESTER_PRIVATE_KEY!;
  const attester = new ethers.Wallet(attesterPrivateKey, provider);
  
  console.log("Attester address:", attester.address);
  
  // Connect to EAS contract
  const eas = new ethers.Contract(
    GIWA_TESTNET_CONFIG.contracts.EAS,
    EAS_ABI,
    attester
  );
  
  // Address to verify
  const recipientAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
  
  // Encode attestation data: bool isVerified = true
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const attestationData = abiCoder.encode(
    ["bool"],
    [true]  // isVerified = true
  );
  
  // Create attestation request
  const attestationRequest = {
    schema: GIWA_TESTNET_CONFIG.schemas.verifiedAddress.uid,
    data: {
      recipient: recipientAddress,
      expirationTime: 0,  // No expiration
      revocable: true,
      refUID: ethers.ZeroHash,  // No reference UID
      data: attestationData,
      value: 0  // No ETH value
    }
  };
  
  console.log("Issuing attestation...");
  
  // Issue the attestation
  const tx = await eas.attest(attestationRequest);
  console.log("Transaction hash:", tx.hash);
  
  const receipt = await tx.wait();
  console.log("Attestation issued! Block:", receipt.blockNumber);
  
  // Extract attestation UID from events
  const attestationEvent = receipt.logs.find(
    (log: any) => log.topics[0] === ethers.id("Attested(address,address,bytes32,bytes32)")
  );
  
  if (attestationEvent) {
    const attestationUID = attestationEvent.topics[2];
    console.log("Attestation UID:", attestationUID);
    console.log(`View on explorer: ${GIWA_TESTNET_CONFIG.explorerUrl}/tx/${tx.hash}`);
  }
}

// Run the example
issueAddressAttestation()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

## Example 2: Verify an Address Attestation

```typescript
// verify-address.ts
import { ethers } from "ethers";
import { GIWA_TESTNET_CONFIG, DOJANG_SCROLL_ABI } from "./config";

async function verifyAddress(address: string) {
  const provider = new ethers.JsonRpcProvider(GIWA_TESTNET_CONFIG.rpcUrl);
  
  const dojangScroll = new ethers.Contract(
    GIWA_TESTNET_CONFIG.contracts.DojangScroll,
    DOJANG_SCROLL_ABI,
    provider
  );
  
  console.log(`Checking if ${address} is verified...`);
  
  const isVerified = await dojangScroll.isVerifiedAddress(address);
  
  if (isVerified) {
    console.log("✅ Address is verified!");
  } else {
    console.log("❌ Address is not verified");
  }
  
  return isVerified;
}

// Usage
const addressToCheck = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
verifyAddress(addressToCheck)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

## Example 3: Query Attestations from Indexer

```typescript
// query-attestations.ts
import { ethers } from "ethers";
import { GIWA_TESTNET_CONFIG, EAS_ABI } from "./config";

async function queryAttestations(recipient: string) {
  const provider = new ethers.JsonRpcProvider(GIWA_TESTNET_CONFIG.rpcUrl);
  
  const eas = new ethers.Contract(
    GIWA_TESTNET_CONFIG.contracts.EAS,
    EAS_ABI,
    provider
  );
  
  // In a real application, you would:
  // 1. Query the AttestationIndexer contract for attestation UIDs
  // 2. Or use The Graph subgraph if available
  // 3. Or listen to Attested events
  
  console.log(`Querying attestations for ${recipient}...`);
  
  // Example: Get specific attestation by UID
  const attestationUID = "0x...";  // Replace with actual UID
  
  try {
    const attestation = await eas.getAttestation(attestationUID);
    
    console.log("Attestation found:");
    console.log("- Schema:", attestation.schema);
    console.log("- Attester:", attestation.attester);
    console.log("- Recipient:", attestation.recipient);
    console.log("- Time:", new Date(Number(attestation.time) * 1000).toISOString());
    console.log("- Data:", attestation.data);
    console.log("- Revoked:", attestation.revocationTime > 0);
    
    return attestation;
  } catch (error) {
    console.error("Attestation not found or error occurred");
    throw error;
  }
}

// Usage
const recipientAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
queryAttestations(recipientAddress)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

## Example 4: Revoke an Attestation

```typescript
// revoke-attestation.ts
import { ethers } from "ethers";
import { GIWA_TESTNET_CONFIG, EAS_ABI } from "./config";

async function revokeAttestation(attestationUID: string) {
  const provider = new ethers.JsonRpcProvider(GIWA_TESTNET_CONFIG.rpcUrl);
  
  // Load your attester wallet (must be the original attester)
  const attesterPrivateKey = process.env.ATTESTER_PRIVATE_KEY!;
  const attester = new ethers.Wallet(attesterPrivateKey, provider);
  
  const eas = new ethers.Contract(
    GIWA_TESTNET_CONFIG.contracts.EAS,
    EAS_ABI,
    attester
  );
  
  console.log("Revoking attestation:", attestationUID);
  
  // Create revocation request
  const revocationRequest = {
    schema: GIWA_TESTNET_CONFIG.schemas.verifiedAddress.uid,
    data: {
      uid: attestationUID,
      value: 0
    }
  };
  
  const tx = await eas.revoke(revocationRequest);
  console.log("Transaction hash:", tx.hash);
  
  const receipt = await tx.wait();
  console.log("Attestation revoked! Block:", receipt.blockNumber);
}

// Usage
const uidToRevoke = "0x...";  // Replace with actual UID
revokeAttestation(uidToRevoke)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

## Testing

```bash
# Set your attester private key
export ATTESTER_PRIVATE_KEY="0x..."

# Run examples
npx ts-node issue-address-attestation.ts
npx ts-node verify-address.ts
npx ts-node query-attestations.ts
```

## Important Notes

1. **Attester Registration**: Your address must be registered in `DojangAttesterBook` to issue attestations
2. **Gas Fees**: Ensure you have enough testnet ETH for gas
3. **Schema UIDs**: Always use the correct schema UID for each attestation type
4. **Revocability**: Mark attestations as revocable if you might need to revoke them later
5. **Data Encoding**: Use ABI encoding for attestation data according to the schema

## Resources

- [GIWA Documentation](https://docs.giwa.io)
- [Ethereum Attestation Service Docs](https://docs.attest.sh/)
- [Testnet Explorer](https://sepolia-explorer.giwa.io)
- [Testnet Faucet](https://faucet.giwa.io)

## Next Steps

- Explore balance verification examples
- Implement custom resolvers
- Build a dApp using Dojang attestations
- Integrate with your authentication system

## Support

Questions or issues? 
- Open an issue: https://github.com/giwa-io/dojang/issues
- Email: support@giwa.io
