// Shared constants for generate and verify scripts

export const ABI_TARGETS = [
  { source: 'IDojangScroll.sol/IDojangScroll.json', name: 'dojangScrollAbi' },
  { source: 'IAttestationIndexer.sol/IAttestationIndexer.json', name: 'attestationIndexerAbi' },
  { source: 'SchemaBook.sol/SchemaBook.json', name: 'schemaBookAbi' },
  { source: 'DojangAttesterBook.sol/DojangAttesterBook.json', name: 'dojangAttesterBookAbi' },
];

export const PREDEPLOYS = {
  SchemaRegistry: '0x4200000000000000000000000000000000000020',
  EAS: '0x4200000000000000000000000000000000000021',
};

export const DEPLOYMENT_FILES = [
  { file: '91342-deploy.json', chainId: 91342 },
];
