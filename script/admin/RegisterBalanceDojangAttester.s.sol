// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";
import {BalanceDojangResolver} from "../../src/BalanceDojangResolver.sol";
import {DojangAttesterBook} from "../../src/DojangAttesterBook.sol";
import {DojangAttesterId} from "../../src/libraries/Types.sol";

contract RegisterBalanceDojangAttester is Script, DeployConfig {
    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");

    function run(address attester, bytes32 attesterId) public {
        DojangAttesterBook dojangAttesterBook = DojangAttesterBook(getAddress(".DojangAttesterBook"));
        BalanceDojangResolver balanceDojangResolver =
            BalanceDojangResolver(payable(getAddress(".BalanceDojangResolver")));

        vm.startBroadcast(adminKey);
        dojangAttesterBook.register(DojangAttesterId.wrap(attesterId), attester);
        balanceDojangResolver.allowAttester(attester);
        vm.stopBroadcast();
    }
}
