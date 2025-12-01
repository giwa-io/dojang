// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IndexerUpdated, ZeroAddress} from "../src/libraries/Common.sol";
import {VerifyCodeDojangResolver} from "../src/VerifyCodeDojangResolver.sol";
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
import {SchemaRegistry} from "@eas-contracts/contracts/SchemaRegistry.sol";
import {EAS} from "@eas-contracts/contracts/EAS.sol";
import {Predeploys} from "../src/libraries/Types.sol";

contract VerifyCodeDojangResolver_Base is Test {
    VerifyCodeDojangResolver public verifyCodeDojangResolver;
    address internal admin;
    address internal upgrader;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        upgrader = makeAddr("upgrader");
        alice = makeAddr("alice");

        address impl = address(new VerifyCodeDojangResolver());
        bytes memory initData = abi.encodeCall(VerifyCodeDojangResolver.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        verifyCodeDojangResolver = VerifyCodeDojangResolver(payable(proxy));

        vm.startPrank(admin);
        verifyCodeDojangResolver.grantRole(verifyCodeDojangResolver.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }
}

contract VerifyCodeDojangResolver_Init is VerifyCodeDojangResolver_Base {
    function test_initialize_revert_for_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        verifyCodeDojangResolver.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new VerifyCodeDojangResolver());
        bytes memory initData = abi.encodeCall(VerifyCodeDojangResolver.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract VerifyCodeDojangResolverV2 is VerifyCodeDojangResolver {
    function v2Function() public pure returns (bool) {
        return true;
    }
}

contract VerifyCodeDojangResolver_Upgrade is VerifyCodeDojangResolver_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new VerifyCodeDojangResolverV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                alice,
                verifyCodeDojangResolver.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        verifyCodeDojangResolver.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        address newImpl = address(new VerifyCodeDojangResolverV2());

        vm.prank(upgrader);
        verifyCodeDojangResolver.upgradeToAndCall(newImpl, bytes(""));
        VerifyCodeDojangResolverV2 newVerifyCodeDojangResolver =
            VerifyCodeDojangResolverV2(payable(address(verifyCodeDojangResolver)));

        assertTrue(newVerifyCodeDojangResolver.v2Function());
    }
}

contract VerifyCodeDojangResolver_Configure is VerifyCodeDojangResolver_Base {
    function test_allowAttester_succeeds() public {
        address attester = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterAllowed(attester);

        vm.prank(admin);
        verifyCodeDojangResolver.allowAttester(attester);
    }

    function test_removeAttester_succeeds() public {
        address attester = vm.randomAddress();
        vm.prank(admin);
        verifyCodeDojangResolver.allowAttester(attester);

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterRemoved(attester);

        vm.prank(admin);
        verifyCodeDojangResolver.removeAttester(attester);
    }

    function test_setIndexer_succeeds() public {
        address indexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(address(0), indexer);

        vm.prank(admin);
        verifyCodeDojangResolver.setIndexer(indexer);
    }

    function test_version() public view {
        assertEq(verifyCodeDojangResolver.version(), "0.5.0");
    }
}

contract VerifyCodeDojangResolver_Test is VerifyCodeDojangResolver_Base {
    SchemaRegistry internal schemaRegistry;
    EAS internal eas;

    address internal attester;
    address internal constant INDEXER = address(0x1234);

    bytes32 internal schemaUid;
    AttestationRequest internal attestationRequest;

    // example verify-code payload
    bytes32 internal constant CODE_HASH = keccak256(bytes("rawcode"));
    string internal constant DOMAIN = "foo.bar";

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        schemaRegistry = new SchemaRegistry();
        EAS tempEas = new EAS(schemaRegistry);
        vm.etch(Predeploys.EAS, address(tempEas).code);
        eas = EAS(Predeploys.EAS);

        attester = makeAddr("attester");

        vm.startPrank(admin);
        verifyCodeDojangResolver.allowAttester(attester);
        verifyCodeDojangResolver.setIndexer(INDEXER);
        vm.stopPrank();

        // VerifyCode schema: (bytes32 codeHash, string domain)
        schemaUid = schemaRegistry.register("bytes32 codeHash,string domain", verifyCodeDojangResolver, true);

        attestationRequest = AttestationRequest({
            schema: schemaUid,
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: uint64(block.timestamp) + 12,
                revocable: true,
                refUID: 0x0,
                data: abi.encode(CODE_HASH, DOMAIN),
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
        bytes32 expectedKey = keccak256(abi.encode(CODE_HASH, DOMAIN));

        vm.mockCallRevert(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32,bytes32)")),
                expectedKey,
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
                address(verifyCodeDojangResolver),
                bytes32(0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a)
            )
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(verifyCodeDojangResolver),
                bytes32(0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a)
            )
        );

        vm.prank(attester);
        eas.attest(attestationRequest);
    }

    function test_onAttest_true() public {
        bytes32 expectedKey = keccak256(abi.encode(CODE_HASH, DOMAIN));

        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32,bytes32)")),
                expectedKey,
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
        bytes32 expectedKey = keccak256(abi.encode(CODE_HASH, DOMAIN));

        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("index(bytes32,bytes32)")),
                expectedKey,
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
