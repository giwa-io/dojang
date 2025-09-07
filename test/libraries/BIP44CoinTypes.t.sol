// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BIP44CoinTypes} from "../../src/libraries/Types.sol";

contract BIP44CoinTypesHelperForRevertTest {
    function callRequireValid(uint32 coinType) external pure {
        BIP44CoinTypes.requireValid(coinType);
    }
}

contract BIP44CoinTypes_Test is Test {
    function testFuzz_requireValid_revert_for_invalidCoinType(uint32 coinType) public {
        vm.assume(coinType >= (1 << 31));

        BIP44CoinTypesHelperForRevertTest helper = new BIP44CoinTypesHelperForRevertTest();
        vm.expectRevert(abi.encodeWithSelector(BIP44CoinTypes.InvalidCoinType.selector, coinType));
        helper.callRequireValid(coinType);
    }

    function testFuzz_requireValid_notRevert_for_validCoinType(uint32 coinType) public pure {
        vm.assume(coinType < (1 << 31));
        BIP44CoinTypes.requireValid(coinType);
        // No revert expected
    }

    function testFuzz_isValid_true_for_validCoinType(uint32 coinType) public pure {
        vm.assume(coinType < (1 << 31));
        assertTrue(BIP44CoinTypes.isValid(coinType));
    }

    function testFuzz_isValid_false_for_invalidCoinType(uint32 coinType) public pure {
        vm.assume(coinType >= (1 << 31));
        assertFalse(BIP44CoinTypes.isValid(coinType));
    }
}
