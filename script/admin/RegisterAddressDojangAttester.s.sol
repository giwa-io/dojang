// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";
import {AddressDojangResolver} from "../../src/AddressDojangResolver.sol";
import {DojangAttesterBook} from "../../src/DojangAttesterBook.sol";
import {DojangAttesterId} from "../../src/libraries/Types.sol";

contract RegisterAddressDojangAttester is Script, DeployConfig {
    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");

    function run(address attester, bytes32 attesterId) public {
        DojangAttesterBook dojangAttesterBook = DojangAttesterBook(getAddress(".DojangAttesterBook"));
        AddressDojangResolver addressDojangResolver =
            AddressDojangResolver(payable(getAddress(".AddressDojangResolver")));

        vm.startBroadcast(adminKey);
        dojangAttesterBook.register(DojangAttesterId.wrap(attesterId), attester);
        addressDojangResolver.allowAttester(attester);
        vm.stopBroadcast();
    }
}
