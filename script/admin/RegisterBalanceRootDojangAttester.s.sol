// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";
import {BalanceRootDojangResolver} from "../../src/BalanceRootDojangResolver.sol";
import {DojangAttesterBook} from "../../src/DojangAttesterBook.sol";
import {DojangAttesterId} from "../../src/libraries/Types.sol";

contract RegisterBalanceRootDojangAttester is Script, DeployConfig {
    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");

    function run(address attester, bytes32 attesterId) public {
        DojangAttesterBook dojangAttesterBook = DojangAttesterBook(getAddress(".DojangAttesterBook"));
        BalanceRootDojangResolver balanceRootDojangResolver =
            BalanceRootDojangResolver(payable(getAddress(".BalanceRootDojangResolver")));

        vm.startBroadcast(adminKey);
        dojangAttesterBook.register(DojangAttesterId.wrap(attesterId), attester);
        balanceRootDojangResolver.allowAttester(attester);
        vm.stopBroadcast();
    }
}
