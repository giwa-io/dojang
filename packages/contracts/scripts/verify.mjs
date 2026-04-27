import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..', '..');
const SRC = join(__dirname, '..', 'src');

const ABI_TARGETS = [
  { source: 'IDojangScroll.sol/IDojangScroll.json', name: 'dojangScrollAbi' },
  { source: 'IAttestationIndexer.sol/IAttestationIndexer.json', name: 'attestationIndexerAbi' },
  { source: 'SchemaBook.sol/SchemaBook.json', name: 'schemaBookAbi' },
  { source: 'DojangAttesterBook.sol/DojangAttesterBook.json', name: 'dojangAttesterBookAbi' },
];

const PREDEPLOYS = {
  SchemaRegistry: '0x4200000000000000000000000000000000000020',
  EAS: '0x4200000000000000000000000000000000000021',
};

let failures = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failures++;
  } else {
    console.log(`PASS: ${message}`);
  }
}

// --- Verify ABI correctness ---

const abiFileContent = readFileSync(join(SRC, 'abi.ts'), 'utf-8');

for (const { source, name } of ABI_TARGETS) {
  const artifactPath = join(ROOT, 'out', source);
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'));
  const expectedAbi = JSON.stringify(artifact.abi, null, 2);

  // Extract the ABI from the generated file by matching the pattern
  const pattern = new RegExp(
    `export const ${name} = ([\\s\\S]*?) as const;`
  );
  const match = abiFileContent.match(pattern);

  assert(match !== null, `${name} exists in abi.ts`);

  if (match) {
    const generatedAbi = match[1].trim();
    assert(
      generatedAbi === expectedAbi,
      `${name} matches forge artifact (${source})`
    );
  }
}

// --- Verify addresses correctness ---

const addressesFileContent = readFileSync(join(SRC, 'addresses.ts'), 'utf-8');
const deployments = JSON.parse(
  readFileSync(join(ROOT, 'deployments', '91342-deploy.json'), 'utf-8')
);
const expectedAddresses = { ...deployments, ...PREDEPLOYS };

// Extract the addresses object from generated file
const addrMatch = addressesFileContent.match(
  /export const addresses = ([\s\S]*?) as const;/
);
assert(addrMatch !== null, 'addresses exists in addresses.ts');

if (addrMatch) {
  const generatedAddresses = JSON.parse(addrMatch[1]);
  const generated91342 = generatedAddresses['91342'];

  for (const [name, address] of Object.entries(expectedAddresses)) {
    assert(
      generated91342[name] === address,
      `address ${name} = ${address}`
    );
  }
}

// --- Verify as const is present ---

for (const { name } of ABI_TARGETS) {
  assert(
    abiFileContent.includes(`] as const;`),
    `abi.ts contains "as const" assertion`
  );
}

assert(
  addressesFileContent.includes(`} as const;`),
  'addresses.ts contains "as const" assertion'
);

// --- Summary ---

console.log('');
if (failures > 0) {
  console.error(`${failures} verification(s) failed`);
  process.exit(1);
} else {
  console.log('All verifications passed');
}
