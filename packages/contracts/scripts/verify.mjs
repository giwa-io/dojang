import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ABI_TARGETS, PREDEPLOYS, DEPLOYMENT_FILES } from './constants.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..', '..');
const SRC = join(__dirname, '..', 'src');

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

const addrMatch = addressesFileContent.match(
  /export const addresses = ([\s\S]*?) as const;/
);
assert(addrMatch !== null, 'addresses exists in addresses.ts');

if (addrMatch) {
  const generatedAddresses = JSON.parse(addrMatch[1]);

  for (const { file, chainId } of DEPLOYMENT_FILES) {
    const deployments = JSON.parse(
      readFileSync(join(ROOT, 'deployments', file), 'utf-8')
    );
    const expectedAddresses = { ...deployments, ...PREDEPLOYS };
    const generatedChain = generatedAddresses[String(chainId)];

    assert(generatedChain !== undefined, `chain ${chainId} exists in addresses.ts`);

    if (generatedChain) {
      for (const [name, address] of Object.entries(expectedAddresses)) {
        assert(
          generatedChain[name] === address,
          `address ${name} = ${address} (chain ${chainId})`
        );
      }
    }
  }
}

// --- Verify as const is present per ABI ---

for (const { name } of ABI_TARGETS) {
  const pattern = new RegExp(`export const ${name} = [\\s\\S]*?\\] as const;`);
  assert(
    pattern.test(abiFileContent),
    `${name} has "as const" assertion`
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
