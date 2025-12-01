// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Off-chain reference implementation for VerifyCode Dojang.
/// @dev This contract is NEVER deployed on-chain. It exists solely as a spec.
library VerifyCodeSpec {
    /// @notice Computes the codeHash from a user-facing code string.
    /// @dev Rule: codeHash = keccak256(bytes(code))
    function computeCodeHash(string memory code) internal pure returns (bytes32) {
        return keccak256(bytes(code));
    }

    /// @notice Canonicalizes a domain string for VerifyCode usage.
    /// @dev Rule: trim leading/trailing spaces, remove all internal spaces (0x20),
    ///      and lowercase ASCII characters only. Non-ASCII (e.g., Korean) characters are preserved as-is.
    function canonicalizeDomain(string memory domain) internal pure returns (string memory) {
        bytes memory b = bytes(domain);
        uint256 start = 0;
        uint256 end = b.length;

        // trim leading/trailing spaces (0x20)
        while (start < end && b[start] == 0x20) start++;
        while (end > start && b[end - 1] == 0x20) end--;

        // build canonicalized output: remove all spaces and lowercase ASCII
        bytes memory out = new bytes(end - start);
        uint256 n = 0;
        for (uint256 i = start; i < end; i++) {
            bytes1 c = b[i];
            // skip any whitespace (0x20)
            if (c == 0x20) continue;
            // lowercase ASCII only
            if (c >= 0x41 && c <= 0x5A) {
                c = bytes1(uint8(c) + 32);
            }
            out[n++] = c;
        }
        assembly { mstore(out, n) }
        return string(out);
    }
}
