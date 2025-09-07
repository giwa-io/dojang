// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IndexerUpdated, ZeroAddress, InvalidIndexer} from "../src/libraries/Common.sol";
import {AddressDojangResolver} from "../src/AddressDojangResolver.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {AllowlistResolverUpgradeable} from "../src/abstract/AllowlistResolverUpgradeable.sol";
import {
    AttestationRequest,
    AttestationRequestData,
    RevocationRequest,
    RevocationRequestData
} from "@eas-contracts/contracts/IEAS.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";
import {SchemaRegistry} from "@eas-contracts/contracts/SchemaRegistry.sol";
import {EAS} from "@eas-contracts/contracts/EAS.sol";
import {Predeploys} from "../src/libraries/Types.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";

contract AddressDojangResolver_Base is Test {
    AddressDojangResolver public addressDojangResolver;
    address internal admin;
    address internal upgrader;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        upgrader = makeAddr("upgrader");
        alice = makeAddr("alice");

        address impl = address(new AddressDojangResolver());
        bytes memory initData = abi.encodeCall(AddressDojangResolver.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        addressDojangResolver = AddressDojangResolver(payable(proxy));

        vm.startPrank(admin);
        addressDojangResolver.grantRole(addressDojangResolver.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }
}

contract AddressDojangResolver_Init is AddressDojangResolver_Base {
    function test_initialize_revert_for_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        addressDojangResolver.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new AddressDojangResolver());
        bytes memory initData = abi.encodeCall(AddressDojangResolver.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract AddressDojangResolverV2 is AddressDojangResolver {
    function v2Function() public pure returns (bool) {
        return true;
    }
}

contract AddressDojangResolver_Upgrade is AddressDojangResolver_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new AddressDojangResolverV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, addressDojangResolver.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        addressDojangResolver.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        address newImpl = address(new AddressDojangResolverV2());

        vm.prank(upgrader);
        addressDojangResolver.upgradeToAndCall(newImpl, bytes(""));
        AddressDojangResolverV2 newAddressDojangResolver =
            AddressDojangResolverV2(payable(address(addressDojangResolver)));

        assertTrue(newAddressDojangResolver.v2Function());
    }
}

contract AddressDojangResolver_Configure is AddressDojangResolver_Base {
    function test_allowAttester_succeeds() public {
        address attester = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterAllowed(attester);

        vm.prank(admin);
        addressDojangResolver.allowAttester(attester);
    }

    function test_removeAttester_succeeds() public {
        address attester = vm.randomAddress();
        vm.prank(admin);
        addressDojangResolver.allowAttester(attester);

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterRemoved(attester);

        vm.prank(admin);
        addressDojangResolver.removeAttester(attester);
    }

    function test_setIndexer_succeeds() public {
        address indexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(address(0), indexer);

        vm.prank(admin);
        addressDojangResolver.setIndexer(indexer);
    }

    function test_version() public view {
        assertEq(addressDojangResolver.version(), "0.1.0");
    }
}

contract AddressDojangResolver_Test is AddressDojangResolver_Base {
    SchemaRegistry internal schemaRegistry;
    EAS internal eas;

    address internal attester;
    address internal constant INDEXER = address(0x1234);
    address internal constant ADDRESS = 0x685933139dE0F4153D32247376e068E156bBA440;

    bytes32 internal schemaUid;
    AttestationRequest internal attestationRequest;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        schemaRegistry = new SchemaRegistry();
        EAS tempEas = new EAS(schemaRegistry);
        vm.etch(Predeploys.EAS, address(tempEas).code);
        eas = EAS(Predeploys.EAS);

        attester = makeAddr("attester");

        vm.startPrank(admin);
        addressDojangResolver.allowAttester(attester);
        addressDojangResolver.setIndexer(INDEXER);
        vm.stopPrank();

        schemaUid = schemaRegistry.register("bool isVerified", addressDojangResolver, true);

        attestationRequest = AttestationRequest({
            schema: schemaUid,
            data: AttestationRequestData({
                recipient: ADDRESS,
                expirationTime: uint64(block.timestamp) + 12,
                revocable: true,
                refUID: 0x0,
                data: abi.encode(true),
                value: 0
            })
        });
    }

    function test_onAttest_false_when_notAllowedAttester() public {
        vm.expectRevert(EAS.InvalidAttestation.selector);

        vm.prank(alice);
        eas.attest(attestationRequest);
    }

    function test_onAttest_false_when_indexingFailed() public {
        vm.mockCallRevert(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32)")),
                keccak256(
                    abi.encodePacked(
                        attestationRequest.schema,
                        attestationRequest.data.recipient,
                        attester,
                        uint64(block.timestamp),
                        attestationRequest.data.expirationTime,
                        attestationRequest.data.revocable,
                        attestationRequest.data.refUID,
                        attestationRequest.data.data,
                        uint32(0)
                    )
                )
            ),
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(addressDojangResolver),
                bytes32(0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a)
            )
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(addressDojangResolver),
                bytes32(0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a)
            )
        );

        vm.prank(attester);
        eas.attest(attestationRequest);
    }

    function test_onAttest_true_when_byAllowedAttester_and_succeedsIndexing() public {
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32)")),
                keccak256(
                    abi.encodePacked(
                        attestationRequest.schema,
                        attestationRequest.data.recipient,
                        attester,
                        uint64(block.timestamp),
                        attestationRequest.data.expirationTime,
                        attestationRequest.data.revocable,
                        attestationRequest.data.refUID,
                        attestationRequest.data.data,
                        uint32(0)
                    )
                )
            ),
            bytes("")
        );

        vm.prank(attester);
        eas.attest(attestationRequest);
    }

    function test_onRevoke_true() public {
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32)")),
                keccak256(
                    abi.encodePacked(
                        attestationRequest.schema,
                        attestationRequest.data.recipient,
                        attester,
                        uint64(block.timestamp),
                        attestationRequest.data.expirationTime,
                        attestationRequest.data.revocable,
                        attestationRequest.data.refUID,
                        attestationRequest.data.data,
                        uint32(0)
                    )
                )
            ),
            bytes("")
        );
        vm.prank(attester);
        bytes32 attestationUid = eas.attest(attestationRequest);

        vm.prank(attester);
        eas.revoke(RevocationRequest({schema: schemaUid, data: RevocationRequestData({uid: attestationUid, value: 0})}));
    }
}
