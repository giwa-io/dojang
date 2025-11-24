// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BalanceRootDojangResolver} from "../src/BalanceRootDojangResolver.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {IndexerUpdated, ZeroAddress} from "../src/libraries/Common.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {SchemaRegistry} from "@eas-contracts/contracts/SchemaRegistry.sol";
import {EAS} from "@eas-contracts/contracts/EAS.sol";
import {
    AttestationRequest,
    AttestationRequestData,
    RevocationRequest,
    RevocationRequestData
} from "@eas-contracts/contracts/IEAS.sol";
import {AllowlistResolverUpgradeable} from "../src/abstract/AllowlistResolverUpgradeable.sol";
import {Predeploys} from "../src/libraries/Types.sol";

contract BalanceRootDojangResolver_Base is Test {
    BalanceRootDojangResolver public balanceRootDojangResolver;
    address internal admin;
    address internal upgrader;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        upgrader = makeAddr("upgrader");
        alice = makeAddr("alice");

        address impl = address(new BalanceRootDojangResolver());
        bytes memory initData = abi.encodeCall(BalanceRootDojangResolver.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        balanceRootDojangResolver = BalanceRootDojangResolver(payable(proxy));

        vm.startPrank(admin);
        balanceRootDojangResolver.grantRole(balanceRootDojangResolver.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }
}

contract BalanceRootDojangResolver_Init is BalanceRootDojangResolver_Base {
    function test_initialize_revert_for_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        balanceRootDojangResolver.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new BalanceRootDojangResolver());
        bytes memory initData = abi.encodeCall(BalanceRootDojangResolver.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract BalanceRootDojangResolverV2 is BalanceRootDojangResolver {
    function v2Function() public pure returns (bool) {
        return true;
    }
}

contract BalanceRootDojangResolver_Upgrade is BalanceRootDojangResolver_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new BalanceRootDojangResolverV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                alice,
                balanceRootDojangResolver.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        balanceRootDojangResolver.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        address newImpl = address(new BalanceRootDojangResolverV2());

        vm.prank(upgrader);
        balanceRootDojangResolver.upgradeToAndCall(newImpl, bytes(""));
        BalanceRootDojangResolverV2 newBalanceRootDojangResolver =
            BalanceRootDojangResolverV2(payable(address(balanceRootDojangResolver)));

        assertTrue(newBalanceRootDojangResolver.v2Function());
    }
}

contract BalanceRootDojangResolver_Configure is BalanceRootDojangResolver_Base {
    function test_allowAttester_succeeds() public {
        address attester = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterAllowed(attester);

        vm.prank(admin);
        balanceRootDojangResolver.allowAttester(attester);
    }

    function test_removeAttester_succeeds() public {
        address attester = vm.randomAddress();
        vm.prank(admin);
        balanceRootDojangResolver.allowAttester(attester);

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterRemoved(attester);

        vm.prank(admin);
        balanceRootDojangResolver.removeAttester(attester);
    }

    function test_setIndexer_succeeds() public {
        address indexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(address(0), indexer);

        vm.prank(admin);
        balanceRootDojangResolver.setIndexer(indexer);
    }

    function test_version() public view {
        assertEq(balanceRootDojangResolver.version(), "0.4.0");
    }
}

contract BalanceRootDojangResolver_Test is BalanceRootDojangResolver_Base {
    SchemaRegistry internal schemaRegistry;
    EAS internal eas;

    address internal attester;
    address internal constant INDEXER = address(0x1234);
    uint256 internal constant BTC_COIN_TYPE = 0x0300000000000000000000000000000000000000000000000000000000435442;
    uint64 internal constant SNAPSHOT_AT = 1_700_000_000 - 5 minutes;
    uint192 internal constant LEAF_COUNT = 1_000_000;
    uint256 internal constant TOTAL_AMOUNT = 10_000_000_000_000_000_000;
    bytes32 internal constant ROOT = keccak256("root");

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
        balanceRootDojangResolver.allowAttester(attester);
        balanceRootDojangResolver.setIndexer(INDEXER);
        vm.stopPrank();

        schemaUid = schemaRegistry.register(
            "uint256 coinType,uint64 snapshotAt,uint192 leafCount,uint256 totalAmount,bytes32 root",
            balanceRootDojangResolver,
            true
        );

        attestationRequest = AttestationRequest({
            schema: schemaUid,
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: true,
                refUID: 0x0,
                data: abi.encode(BTC_COIN_TYPE, SNAPSHOT_AT, LEAF_COUNT, TOTAL_AMOUNT, ROOT),
                value: 0
            })
        });
    }

    function test_onAttest_false_when_validationFailed() public {
        vm.expectRevert(EAS.InvalidAttestation.selector);

        attestationRequest.data.data = abi.encode(BTC_COIN_TYPE, block.timestamp + 1, LEAF_COUNT, TOTAL_AMOUNT, ROOT);

        vm.prank(attester);
        eas.attest(attestationRequest);
    }

    function test_onAttest_false_when_notAllowedAttester() public {
        vm.expectRevert(EAS.InvalidAttestation.selector);

        vm.prank(alice);
        eas.attest(attestationRequest);
    }

    function test_onAttest_false_when_indexingFailed() public {
        bytes32 key = keccak256(abi.encode(BTC_COIN_TYPE, SNAPSHOT_AT));
        vm.mockCallRevert(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32,bytes32)")),
                key,
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
                address(balanceRootDojangResolver),
                bytes32(0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a)
            )
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(balanceRootDojangResolver),
                bytes32(0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a)
            )
        );

        vm.prank(attester);
        eas.attest(attestationRequest);
    }

    function test_onAttest_true() public {
        bytes32 key = keccak256(abi.encode(BTC_COIN_TYPE, SNAPSHOT_AT));
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32,bytes32)")),
                key,
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
        bytes32 key = keccak256(abi.encode(BTC_COIN_TYPE, SNAPSHOT_AT));
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32,bytes32)")),
                key,
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
