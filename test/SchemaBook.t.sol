// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZeroAddress} from "../src/libraries/Common.sol";
import {Predeploys, DojangSchemaIds} from "../src/libraries/Types.sol";
import {SchemaBook} from "../src/SchemaBook.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {ISchemaRegistry, ISchemaResolver, SchemaRecord} from "@eas-contracts/contracts/ISchemaRegistry.sol";

contract SchemaBook_Base is Test {
    SchemaBook public schemaBook;
    address internal admin;
    address internal upgrader;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        upgrader = makeAddr("upgrader");
        alice = makeAddr("alice");

        address impl = address(new SchemaBook());
        bytes memory initData = abi.encodeCall(SchemaBook.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        schemaBook = SchemaBook(proxy);

        vm.startPrank(admin);
        schemaBook.grantRole(schemaBook.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }
}

contract SchemaBook_Init is SchemaBook_Base {
    function test_initialize_revert_for_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        schemaBook.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new SchemaBook());
        bytes memory initData = abi.encodeCall(SchemaBook.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract SchemaBookV2 is SchemaBook {
    function version() public pure returns (uint32) {
        return 2;
    }
}

contract SchemaBook_Upgrade is SchemaBook_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new SchemaBookV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, schemaBook.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        schemaBook.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        address newImpl = address(new SchemaBookV2());

        vm.prank(upgrader);
        schemaBook.upgradeToAndCall(newImpl, bytes(""));
        SchemaBookV2 newSchemaBook = SchemaBookV2(address(schemaBook));

        assertEq(newSchemaBook.version(), 2);
    }
}

contract SchemaBook_Test is SchemaBook_Base {
    bytes32 internal constant ADDRESS_SCHEMA_UID = bytes32("address");

    SchemaRecord internal addressSchema;

    function setUp() public override {
        super.setUp();

        addressSchema =
            SchemaRecord({uid: ADDRESS_SCHEMA_UID, schema: "", resolver: ISchemaResolver(address(0)), revocable: true});
    }

    function test_register_revert_when_zeroSchemaId() public {
        vm.expectRevert(SchemaBook.InvalidSchemaId.selector);
        vm.prank(admin);
        schemaBook.register(bytes32(0), ADDRESS_SCHEMA_UID);
    }

    function test_register_revert_when_zeroEASSchemaUid() public {
        vm.expectRevert(SchemaBook.InvalidEasSchemaUid.selector);
        vm.prank(admin);
        schemaBook.register(DojangSchemaIds.ADDRESS_DOJANG, bytes32(0));
    }

    function test_register_revert_when_notFoundEASSchema() public {
        addressSchema.uid = bytes32(0);
        vm.mockCall(
            Predeploys.SCHEMA_REGISTRY,
            abi.encodeWithSelector(ISchemaRegistry.getSchema.selector, ADDRESS_SCHEMA_UID),
            abi.encode(addressSchema)
        );

        vm.expectRevert(SchemaBook.InvalidEasSchemaUid.selector);
        vm.prank(admin);
        schemaBook.register(DojangSchemaIds.ADDRESS_DOJANG, ADDRESS_SCHEMA_UID);
    }

    function test_register_succeeds() public {
        vm.mockCall(
            Predeploys.SCHEMA_REGISTRY,
            abi.encodeWithSelector(ISchemaRegistry.getSchema.selector, ADDRESS_SCHEMA_UID),
            abi.encode(addressSchema)
        );

        vm.expectEmit(true, true, true, true);
        emit SchemaBook.SchemaRegistered(DojangSchemaIds.ADDRESS_DOJANG, ADDRESS_SCHEMA_UID);

        vm.prank(admin);
        schemaBook.register(DojangSchemaIds.ADDRESS_DOJANG, ADDRESS_SCHEMA_UID);

        assertEq(schemaBook.getSchemaUid(DojangSchemaIds.ADDRESS_DOJANG), ADDRESS_SCHEMA_UID);
    }

    function test_unregister_revert_when_zeroSchemaId() public {
        vm.expectRevert(SchemaBook.InvalidSchemaId.selector);
        vm.prank(admin);
        schemaBook.unregister(bytes32(0));
    }

    function test_unregister_succeeds() public {
        vm.mockCall(
            Predeploys.SCHEMA_REGISTRY,
            abi.encodeWithSelector(ISchemaRegistry.getSchema.selector, ADDRESS_SCHEMA_UID),
            abi.encode(addressSchema)
        );

        vm.prank(admin);
        schemaBook.register(DojangSchemaIds.ADDRESS_DOJANG, ADDRESS_SCHEMA_UID);

        vm.expectEmit(true, true, true, true);
        emit SchemaBook.SchemaUnregistered(DojangSchemaIds.ADDRESS_DOJANG);

        vm.prank(admin);
        schemaBook.unregister(DojangSchemaIds.ADDRESS_DOJANG);

        assertEq(schemaBook.getSchemaUid(DojangSchemaIds.ADDRESS_DOJANG), bytes32(0));
    }
}
