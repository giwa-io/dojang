// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console2 as console} from "forge-std/console2.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Vm} from "forge-std/Vm.sol";

abstract contract DeployConfig {
    /// @notice Foundry cheatcode VM.
    Vm private constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string private _deployConfigJson;

    function setUp() public virtual {
        string memory deployConfigFilePath =
            string.concat(_vm.projectRoot(), "/deploy-config/", _vm.toString(block.chainid), ".json");
        _deployConfigJson = _vm.readFile(deployConfigFilePath);

        console.log("Fetching deploy config from %s", deployConfigFilePath);
        console.log("Connected to network with chainid %s", block.chainid);
    }

    function keyExists(string memory key) internal view returns (bool) {
        return stdJson.keyExists(_deployConfigJson, key);
    }

    function getAddress(string memory key) internal view returns (address) {
        return stdJson.readAddress(_deployConfigJson, key);
    }

    function getAddresses(string memory key) internal view returns (address[] memory) {
        return stdJson.readAddressArray(_deployConfigJson, key);
    }

    function getBytes32(string memory key) internal view returns (bytes32) {
        return stdJson.readBytes32(_deployConfigJson, key);
    }

    function getBytes(string memory key) internal view returns (bytes memory) {
        return stdJson.readBytes(_deployConfigJson, key);
    }
}
