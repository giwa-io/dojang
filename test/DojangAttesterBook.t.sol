// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {DojangAttesterBook} from "../src/DojangAttesterBook.sol";
import {DojangAttesterIds} from "../src/libraries/Types.sol";
import {ZeroAddress} from "../src/libraries/Common.sol";

contract DojangAttesterBook_Base is Test {
    DojangAttesterBook public attesterBook;
    address internal admin;
    address internal upgrader;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        upgrader = makeAddr("upgrader");
        alice = makeAddr("alice");

        address impl = address(new DojangAttesterBook());
        bytes memory initData = abi.encodeCall(DojangAttesterBook.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        attesterBook = DojangAttesterBook(proxy);

        vm.startPrank(admin);
        attesterBook.grantRole(attesterBook.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }
}

contract DojangAttesterBook_Init is DojangAttesterBook_Base {
    function test_initialize_revert_on_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        attesterBook.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new DojangAttesterBook());
        bytes memory initData = abi.encodeCall(DojangAttesterBook.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract DojangAttesterBookV2 is DojangAttesterBook {
    function version() public pure returns (uint8) {
        return 2;
    }
}

contract DojangAttesterBook_Upgrade is DojangAttesterBook_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new DojangAttesterBookV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, attesterBook.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        attesterBook.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        address newImpl = address(new DojangAttesterBookV2());

        vm.prank(upgrader);
        attesterBook.upgradeToAndCall(newImpl, bytes(""));
        DojangAttesterBookV2 newAttesterBook = DojangAttesterBookV2(address(attesterBook));

        assertEq(newAttesterBook.version(), 2);
    }
}

contract DojangAttesterBook_Test is DojangAttesterBook_Base {
    address internal constant ATTESTER = address(0xABCD);

    function test_register_revert_when_zeroAddress() public {
        vm.expectRevert(ZeroAddress.selector);
        vm.prank(admin);
        attesterBook.register(DojangAttesterIds.UPBIT_KOREA, address(0));
    }

    function test_register_succeeds() public {
        vm.expectEmit(true, true, true, true);
        emit DojangAttesterBook.AttesterRegistered(DojangAttesterIds.UPBIT_KOREA, ATTESTER);

        vm.prank(admin);
        attesterBook.register(DojangAttesterIds.UPBIT_KOREA, ATTESTER);

        assertEq(attesterBook.getAttester(DojangAttesterIds.UPBIT_KOREA), ATTESTER);
    }

    function test_unregister_succeeds() public {
        vm.prank(admin);
        attesterBook.register(DojangAttesterIds.UPBIT_KOREA, ATTESTER);

        vm.expectEmit(true, true, true, true);
        emit DojangAttesterBook.AttesterUnregistered(DojangAttesterIds.UPBIT_KOREA);

        vm.prank(admin);
        attesterBook.unregister(DojangAttesterIds.UPBIT_KOREA);

        assertEq(attesterBook.getAttester(DojangAttesterIds.UPBIT_KOREA), address(0));
    }
}
