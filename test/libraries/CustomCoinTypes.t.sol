// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CustomCoinTypes} from "../../src/libraries/Types.sol";

contract CustomCoinTypesHelperForRevertTest {
    function callToCoinType(string memory ticker) external pure {
        CustomCoinTypes.toCoinType(ticker);
    }

    function callToTicker(uint256 coinType) external pure {
        CustomCoinTypes.toTicker(coinType);
    }

    function callRequireValid(uint256 coinType) external pure {
        CustomCoinTypes.requireValid(coinType);
    }
}

contract CustomCoinTypes_Test is Test {
    CustomCoinTypesHelperForRevertTest internal revertHelper = new CustomCoinTypesHelperForRevertTest();

    function _pack(string memory s) internal pure returns (uint256) {
        return CustomCoinTypes.toCoinType(s);
    }

    function test_roundtrip_ETH() public pure {
        string memory ticker = "ETH";
        uint256 coinType = CustomCoinTypes.toCoinType(ticker);
        string memory back = CustomCoinTypes.toTicker(coinType);
        assertEq(back, ticker);

        // Known canonical packing (len=3 at MSB, payload is little endian: 'H''T''E')
        uint256 expected = 0x0300000000000000000000000000000000000000000000000000000000485445;
        assertEq(coinType, expected);
        assertTrue(CustomCoinTypes.isValid(coinType));
    }

    function test_roundtrip_various_tickers() public pure {
        string[] memory tickers = new string[](4);
        tickers[0] = "T";
        tickers[1] = "MUSTAAAAAARD";
        tickers[2] = "USD1";
        tickers[3] = "ITOTon";

        for (uint256 i = 0; i < tickers.length; ++i) {
            uint256 coinType = CustomCoinTypes.toCoinType(tickers[i]);
            assertEq(CustomCoinTypes.toTicker(coinType), tickers[i]);
            assertTrue(CustomCoinTypes.isValid(coinType));
        }
    }

    function test_toCoinType_revert_lengthZero() public {
        vm.expectRevert(abi.encodeWithSelector(CustomCoinTypes.InvalidTickerLength.selector, 0));
        revertHelper.callToCoinType("");
    }

    function test_toCoinType_revert_lengthTooLong() public {
        bytes memory b = new bytes(32);
        for (uint256 i = 0; i < 32; ++i) {
            b[i] = 0x21;
        }
        vm.expectRevert(abi.encodeWithSelector(CustomCoinTypes.InvalidTickerLength.selector, 32));
        revertHelper.callToCoinType(string(b));
    }

    function test_toCoinType_revert_invalidCharBelowRange() public {
        vm.expectRevert(abi.encodeWithSelector(CustomCoinTypes.InvalidTickerChar.selector, uint8(0x20)));
        revertHelper.callToCoinType("A A");
    }

    function test_toCoinType_revert_invalidCharAboveRange() public {
        bytes memory b = hex"417F";
        vm.expectRevert(abi.encodeWithSelector(CustomCoinTypes.InvalidTickerChar.selector, uint8(0x7F)));
        revertHelper.callToCoinType(string(b));
    }

    function test_toTicker_revert_invalidFormat() public {
        // len is 1 but payload beyond len
        uint256 coinType = (uint256(1) << 248) | (uint256(uint8(bytes1("A"))) | (uint256(uint8(bytes1("B"))) << 8));
        vm.expectRevert(abi.encodeWithSelector(CustomCoinTypes.InvalidCoinType.selector, coinType));
        revertHelper.callToTicker(coinType);
    }

    function test_isValid_false_lengthZero() public pure {
        uint256 coinType = 0; // len=0
        assertFalse(CustomCoinTypes.isValid(coinType));
    }

    function test_isValid_false_lengthTooBig() public pure {
        uint256 coinType = (uint256(uint8(0xFF)) << 248);
        assertFalse(CustomCoinTypes.isValid(coinType));
    }

    function test_isValid_false_extraNonZeroBeyondLen() public pure {
        // len is 2 but payload has 3rd byte
        uint256 len = 2;
        uint256 payload =
            uint256(uint8(bytes1("A"))) | (uint256(uint8(bytes1("B"))) << 8) | (uint256(uint8(bytes1("C"))) << 16);
        uint256 coinType = (len << 248) | payload;
        assertFalse(CustomCoinTypes.isValid(coinType));
    }

    function test_isValid_false_invalidChar() public pure {
        uint256 len = 2;
        uint256 payload = uint256(uint8(bytes1("A"))) | (uint256(uint8(0x7F)) << 8);
        uint256 coinType = (len << 248) | payload;
        assertFalse(CustomCoinTypes.isValid(coinType));
    }

    function test_requireValid_ok() public pure {
        uint256 coinType = _pack("ETH");
        CustomCoinTypes.requireValid(coinType);
    }

    function test_requireValid_revert() public {
        uint256 coinType = 0;
        vm.expectRevert(abi.encodeWithSelector(CustomCoinTypes.InvalidCoinType.selector, coinType));
        revertHelper.callRequireValid(coinType);
    }
}
