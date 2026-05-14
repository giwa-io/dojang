/**
 * Type-level verification for @giwa-io/dojang-contracts
 *
 * This file does NOT run — it only compiles.
 * `tsc --noEmit` on this file verifies that ABI and address exports
 * are narrowly typed (`as const`), which is required for viem to
 * infer function names, argument types, and return types.
 *
 * If `as const` is accidentally removed, these assertions fail at
 * compile time and the build breaks before a broken package ships.
 */

import {
  dojangScrollAbi,
  attestationIndexerAbi,
  schemaBookAbi,
  dojangAttesterBookAbi,
  addresses,
} from '../src/index.js';

// ── Helpers ──────────────────────────────────────────────────

/** true when T is a string literal, false when T is just `string` */
type IsLiteral<T extends string> = string extends T ? false : true;

/** Compile error when T is not `true` */
type Assert<T extends true> = T;

/** Extract the `name` field from function entries of an ABI */
type FnNames<A extends readonly Record<string, unknown>[]> = Extract<
  A[number],
  { type: 'function' }
> extends { name: infer N extends string } ? N : never;

// ── ABI narrowing checks ────────────────────────────────────
//
// If any ABI loses its `as const`, the function-name union
// widens to `string` and the corresponding Assert<…> line
// becomes Assert<false>, which is a compile error.

type _abiCheck1 = Assert<IsLiteral<FnNames<typeof dojangScrollAbi>>>;
type _abiCheck2 = Assert<IsLiteral<FnNames<typeof attestationIndexerAbi>>>;
type _abiCheck3 = Assert<IsLiteral<FnNames<typeof schemaBookAbi>>>;
type _abiCheck4 = Assert<IsLiteral<FnNames<typeof dojangAttesterBookAbi>>>;

// ── Address narrowing checks ────────────────────────────────
//
// Verify that chain IDs and addresses are literal types.

type _addrCheck1 = Assert<IsLiteral<keyof typeof addresses & string>>;
type _addrCheck2 = Assert<
  IsLiteral<(typeof addresses)['91342']['DojangScroll']>
>;

// ── Spot-check known function names exist ───────────────────

type HasIsVerified = Extract<
  (typeof dojangScrollAbi)[number],
  { type: 'function'; name: 'isVerified' }
>;
type _fnCheck1 = Assert<HasIsVerified extends never ? false : true>;

type HasGetAttestationUid = Extract<
  (typeof attestationIndexerAbi)[number],
  { type: 'function'; name: 'getAttestationUid' }
>;
type _fnCheck2 = Assert<HasGetAttestationUid extends never ? false : true>;
