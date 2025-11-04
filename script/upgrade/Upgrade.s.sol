// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console2 as console} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ISemver} from "../../src/interfaces/ISemver.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";
import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract Upgrade is Script, DeployConfig {
    uint256 internal deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    address internal deployer = vm.addr(deployerKey);

    uint256 internal upgraderKey = vm.envUint("UPGRADER_PRIVATE_KEY");
    address internal upgrader = vm.addr(upgraderKey);

    function run() public {
        upgradeUUPSContract(getAddress(".SchemaBook"), "SchemaBook.sol", new bytes(0), new bytes(0));
        upgradeUUPSContract(getAddress(".DojangAttesterBook"), "DojangAttesterBook.sol", new bytes(0), new bytes(0));
        upgradeUUPSContract(getAddress(".AttestationIndexer"), "AttestationIndexer.sol", new bytes(0), new bytes(0));
        upgradeUUPSContract(
            getAddress(".AddressDojangResolver"), "AddressDojangResolver.sol", new bytes(0), new bytes(0)
        );
        upgradeUUPSContract(
            getAddress(".BalanceDojangResolver"), "BalanceDojangResolver.sol", new bytes(0), new bytes(0)
        );
        upgradeUUPSContract(getAddress(".DojangScroll"), "DojangScroll.sol", new bytes(0), new bytes(0));
    }

    function upgradeUUPSContract(
        address proxy,
        string memory contractName,
        bytes memory constructorData,
        bytes memory initData
    )
        public
    {
        if (!_needsUpgrade(proxy, contractName, constructorData)) {
            return;
        }

        console.log("\nStarting upgrade for %s", contractName);

        vm.startBroadcast(deployerKey);
        address newImpl = vm.deployCode(contractName, constructorData);
        vm.stopBroadcast();

        console.log("New Implementation contract at %s", newImpl);

        vm.startBroadcast(upgraderKey);
        UUPSUpgradeable(proxy).upgradeToAndCall(newImpl, initData);
        vm.stopBroadcast();

        console.log("Upgrade complete \n");
    }

    function _needsUpgrade(
        address proxy,
        string memory contractName,
        bytes memory constructorData
    )
        internal
        returns (bool)
    {
        (VmSafe.CallerMode m,,) = vm.readCallers();
        require(m == VmSafe.CallerMode.None, "Only offchain");

        (bool success,) = proxy.staticcall(abi.encodeWithSelector(ISemver.version.selector));
        if (!success) {
            return true;
        }

        ISemver proxyContract = ISemver(proxy);
        ISemver newImplContract = ISemver(vm.deployCode(contractName, constructorData));

        return !Strings.equal(proxyContract.version(), newImplContract.version());
    }
}
