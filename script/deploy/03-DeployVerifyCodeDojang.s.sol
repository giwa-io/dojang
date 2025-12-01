// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Artifacts} from "../utils/Artifacts.s.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";
import {ISchemaRegistry} from "../../dependencies/@eas-contracts-1.4.0/contracts/ISchemaRegistry.sol";
import {IEAS} from "@eas-contracts/contracts/IEAS.sol";
import {Predeploys, DojangSchemaIds} from "../../src/libraries/Types.sol";
import {VerifyCodeDojangResolver} from "../../src/VerifyCodeDojangResolver.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/src/Upgrades.sol";
import {SchemaBook} from "../../src/SchemaBook.sol";
import {AttestationIndexer} from "../../src/AttestationIndexer.sol";

contract DeployVerifyCodeDojang is Script, Artifacts, DeployConfig {
    uint256 internal deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    address internal deployer = vm.addr(deployerKey);

    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");
    address internal admin = vm.addr(adminKey);

    uint256 internal upgraderKey = vm.envUint("UPGRADER_PRIVATE_KEY");
    address internal upgrader = vm.addr(upgraderKey);

    uint256 internal pauserKey = vm.envUint("PAUSER_PRIVATE_KEY");
    address internal pauser = vm.addr(pauserKey);

    string internal constant VERIFY_CODE_DOJANG_SCHEMA = "bytes32 codeHash,string domain";

    ISchemaRegistry internal schemaRegistry = ISchemaRegistry(Predeploys.SCHEMA_REGISTRY);
    IEAS internal eas = IEAS(Predeploys.EAS);

    modifier broadcast(uint256 privateKey) {
        vm.startBroadcast(privateKey);
        _;
        vm.stopBroadcast();
    }

    function setUp() public override(Artifacts, DeployConfig) {
        Artifacts.setUp();
        DeployConfig.setUp();
    }

    function run() public {
        deployVerifyCodeDojangResolver();
        grantRoleVerifyCodeDojangResolver();
        configure();
    }

    function deployVerifyCodeDojangResolver() public broadcast(deployerKey) {
        address proxy = Upgrades.deployUUPSProxy(
            "VerifyCodeDojangResolver.sol", abi.encodeCall(VerifyCodeDojangResolver.initialize, admin)
        );
        save("VerifyCodeDojangResolver", proxy);
    }

    function grantRoleVerifyCodeDojangResolver() public broadcast(adminKey) {
        VerifyCodeDojangResolver verifyCodeDojangResolver =
            VerifyCodeDojangResolver(mustGetAddress("VerifyCodeDojangResolver"));
        verifyCodeDojangResolver.grantRole(verifyCodeDojangResolver.UPGRADER_ROLE(), upgrader);
    }

    function configure() public broadcast(adminKey) {
        SchemaBook schemaBook = SchemaBook(getAddress(".SchemaBook"));
        AttestationIndexer attestationIndexer = AttestationIndexer(getAddress(".AttestationIndexer"));
        VerifyCodeDojangResolver verifyCodeDojangResolver =
            VerifyCodeDojangResolver(mustGetAddress("VerifyCodeDojangResolver"));

        verifyCodeDojangResolver.setIndexer(address(attestationIndexer));

        bytes32 verifyCodeSchemaUid = schemaRegistry.register(VERIFY_CODE_DOJANG_SCHEMA, verifyCodeDojangResolver, true);
        schemaBook.register(DojangSchemaIds.VERIFY_CODE_DOJANG, verifyCodeSchemaUid);
    }
}
