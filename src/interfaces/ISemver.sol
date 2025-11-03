// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISemver {
    /// @notice Returns the current semantic version of the contract
    /// @return The semantic version string of the contract (e.g. `1.2.3`)
    function version() external view returns (string memory);
}
