// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/src/Upgrades.sol";
import {ISchemaRegistry} from "@eas-contracts/contracts/ISchemaRegistry.sol";
import {IEAS} from "@eas-contracts/contracts/IEAS.sol";
import {Predeploys, DojangSchemaIds} from "src/libraries/Types.sol";
import {Artifacts} from "../utils/Artifacts.s.sol";
import {SchemaBook} from "src/SchemaBook.sol";
import {DojangAttesterBook} from "src/DojangAttesterBook.sol";
import {AttestationIndexer} from "src/AttestationIndexer.sol";
import {AddressDojangResolver} from "src/AddressDojangResolver.sol";
import {DojangScroll} from "src/DojangScroll.sol";
import {BalanceDojangResolver} from "../../src/BalanceDojangResolver.sol";
import {BalanceRootDojangResolver} from "../../src/BalanceRootDojangResolver.sol";
import {DeployConfig} from "../utils/DeployConfig.s.sol";

contract DeployBalanceRootDojang is Script, Artifacts, DeployConfig {
    uint256 internal deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    address internal deployer = vm.addr(deployerKey);

    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");
    address internal admin = vm.addr(adminKey);

    uint256 internal upgraderKey = vm.envUint("UPGRADER_PRIVATE_KEY");
    address internal upgrader = vm.addr(upgraderKey);

    uint256 internal pauserKey = vm.envUint("PAUSER_PRIVATE_KEY");
    address internal pauser = vm.addr(pauserKey);

    string internal constant BALANCE_ROOT_DOJANG_SCHEMA =
        "uint256 coinType,uint64 snapshotAt,uint192 leafCount,uint256 totalAmount,bytes32 root";
    string internal constant BALANCE_DOJANG_SCHEMA = "uint256 balance,bytes32 salt,bytes32[] proofs";

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
        deployBalanceRootDojangResolver();
        grantRoleAttestationIndexer();
        grantRoleBalanceRootDojangResolver();
        configure();
    }

    function deployBalanceRootDojangResolver() public broadcast(deployerKey) {
        address proxy = Upgrades.deployUUPSProxy(
            "BalanceRootDojangResolver.sol", abi.encodeCall(BalanceRootDojangResolver.initialize, admin)
        );
        save("BalanceRootDojangResolver", proxy);
    }

    function grantRoleAttestationIndexer() public broadcast(adminKey) {
        AttestationIndexer attestationIndexer = AttestationIndexer(mustGetAddress("AttestationIndexer"));
        address balanceRootDojangResolver = mustGetAddress("BalanceRootDojangResolver");
        attestationIndexer.grantRole(attestationIndexer.INDEXER_ROLE(), balanceRootDojangResolver);
    }

    function grantRoleBalanceRootDojangResolver() public broadcast(adminKey) {
        BalanceRootDojangResolver balanceRootDojangResolver =
            BalanceRootDojangResolver(mustGetAddress("BalanceRootDojangResolver"));
        balanceRootDojangResolver.grantRole(balanceRootDojangResolver.UPGRADER_ROLE(), upgrader);
    }

    function configure() public broadcast(adminKey) {
        SchemaBook schemaBook = SchemaBook(getAddress(".SchemaBook"));
        AttestationIndexer attestationIndexer = AttestationIndexer(getAddress(".AttestationIndexer"));
        BalanceDojangResolver balanceDojangResolver =
            BalanceDojangResolver(payable(getAddress(".BalanceDojangResolver")));

        BalanceRootDojangResolver balanceRootDojangResolver =
            BalanceRootDojangResolver(mustGetAddress("BalanceRootDojangResolver"));

        balanceRootDojangResolver.setIndexer(address(attestationIndexer));

        bytes32 balanceSchemaUid = schemaRegistry.register(BALANCE_DOJANG_SCHEMA, balanceDojangResolver, true);
        schemaBook.unregister(DojangSchemaIds.BALANCE_DOJANG);
        schemaBook.register(DojangSchemaIds.BALANCE_DOJANG, balanceSchemaUid);

        bytes32 balanceRootSchemaUid =
            schemaRegistry.register(BALANCE_ROOT_DOJANG_SCHEMA, balanceRootDojangResolver, true);
        schemaBook.register(DojangSchemaIds.BALANCE_ROOT_DOJANG, balanceRootSchemaUid);

        balanceDojangResolver.setBalanceRootSchemaUID(balanceRootSchemaUid);
    }
}
