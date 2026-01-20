// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";
import {VerifyCodeDojangResolver} from "../../src/VerifyCodeDojangResolver.sol";
import {DojangAttesterBook} from "../../src/DojangAttesterBook.sol";
import {DojangAttesterId} from "../../src/libraries/Types.sol";

contract RevokeVerifyCodeDojangAttester is Script, DeployConfig {
    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");

    function run(address attester, bytes32 attesterId) public {
        DojangAttesterBook dojangAttesterBook = DojangAttesterBook(getAddress(".DojangAttesterBook"));
        VerifyCodeDojangResolver verifyCodeDojangResolver =
            VerifyCodeDojangResolver(payable(getAddress(".VerifyCodeDojangResolver")));

        vm.startBroadcast(adminKey);
        verifyCodeDojangResolver.removeAttester(attester);
        if (dojangAttesterBook.getAttester(DojangAttesterId.wrap(attesterId)) == attester) {
            dojangAttesterBook.unregister(DojangAttesterId.wrap(attesterId));
        }
        vm.stopBroadcast();
    }
}
