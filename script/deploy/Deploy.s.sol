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

contract Deploy is Script, Artifacts {
    uint256 internal deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    address internal deployer = vm.addr(deployerKey);

    uint256 internal adminKey = vm.envUint("ADMIN_PRIVATE_KEY");
    address internal admin = vm.addr(adminKey);

    uint256 internal upgraderKey = vm.envUint("UPGRADER_PRIVATE_KEY");
    address internal upgrader = vm.addr(upgraderKey);

    uint256 internal pauserKey = vm.envUint("PAUSER_PRIVATE_KEY");
    address internal pauser = vm.addr(pauserKey);

    string internal constant ADDRESS_DOJANG_SCHEMA = "bool isVerified";
    string internal constant BALANCE_DOJANG_SCHEMA = "uint256 coinType,uint64 snapshotAt,uint256 balance";

    ISchemaRegistry internal schemaRegistry = ISchemaRegistry(Predeploys.SCHEMA_REGISTRY);
    IEAS internal eas = IEAS(Predeploys.EAS);

    modifier broadcast(uint256 privateKey) {
        vm.startBroadcast(privateKey);
        _;
        vm.stopBroadcast();
    }

    function run() public {
        /// deploy contracts
        deploySchemaBook();
        deployDojangAttesterBook();
        deployAttestationIndexer();
        deployAddressDojangResolver();
        deployBalanceDojangResolver();
        deployDojangScroll();

        /// grant role
        grantRoleSchemaBook();
        grantRoleDojangAttesterBook();
        grantRoleAttestationIndexer();
        grantRoleAddressDojangResolver();
        grantRoleBalanceDojangResolver();
        grantRoleDojangScroll();

        /// configure
        configure();
    }

    function deploySchemaBook() public broadcast(deployerKey) {
        address proxy = Upgrades.deployUUPSProxy("SchemaBook.sol", abi.encodeCall(SchemaBook.initialize, admin));
        save("SchemaBook", proxy);
    }

    function deployDojangAttesterBook() public broadcast(deployerKey) {
        address proxy =
            Upgrades.deployUUPSProxy("DojangAttesterBook.sol", abi.encodeCall(DojangAttesterBook.initialize, admin));
        save("DojangAttesterBook", proxy);
    }

    function deployAttestationIndexer() public broadcast(deployerKey) {
        address proxy =
            Upgrades.deployUUPSProxy("AttestationIndexer.sol", abi.encodeCall(AttestationIndexer.initialize, admin));
        save("AttestationIndexer", proxy);
    }

    function deployAddressDojangResolver() public broadcast(deployerKey) {
        address proxy = Upgrades.deployUUPSProxy(
            "AddressDojangResolver.sol", abi.encodeCall(AddressDojangResolver.initialize, admin)
        );
        save("AddressDojangResolver", proxy);
    }

    function deployBalanceDojangResolver() public broadcast(deployerKey) {
        address proxy = Upgrades.deployUUPSProxy(
            "BalanceDojangResolver.sol", abi.encodeCall(BalanceDojangResolver.initialize, admin)
        );
        save("BalanceDojangResolver", proxy);
    }

    function deployDojangScroll() public broadcast(deployerKey) {
        address proxy = Upgrades.deployUUPSProxy("DojangScroll.sol", abi.encodeCall(DojangScroll.initialize, admin));
        save("DojangScroll", proxy);
    }

    function grantRoleSchemaBook() public broadcast(adminKey) {
        SchemaBook schemaBook = SchemaBook(mustGetAddress("SchemaBook"));
        schemaBook.grantRole(schemaBook.UPGRADER_ROLE(), upgrader);
    }

    function grantRoleDojangAttesterBook() public broadcast(adminKey) {
        DojangAttesterBook dojangAttesterBook = DojangAttesterBook(mustGetAddress("DojangAttesterBook"));
        dojangAttesterBook.grantRole(dojangAttesterBook.UPGRADER_ROLE(), upgrader);
    }

    function grantRoleAttestationIndexer() public broadcast(adminKey) {
        AttestationIndexer attestationIndexer = AttestationIndexer(mustGetAddress("AttestationIndexer"));
        address addressDojangResolver = mustGetAddress("AddressDojangResolver");
        address balanceDojangResolver = mustGetAddress("BalanceDojangResolver");

        attestationIndexer.grantRole(attestationIndexer.PAUSER_ROLE(), pauser);
        attestationIndexer.grantRole(attestationIndexer.UPGRADER_ROLE(), upgrader);
        attestationIndexer.grantRole(attestationIndexer.INDEXER_ROLE(), addressDojangResolver);
        attestationIndexer.grantRole(attestationIndexer.INDEXER_ROLE(), balanceDojangResolver);
    }

    function grantRoleAddressDojangResolver() public broadcast(adminKey) {
        AddressDojangResolver addressDojangResolver = AddressDojangResolver(mustGetAddress("AddressDojangResolver"));
        addressDojangResolver.grantRole(addressDojangResolver.UPGRADER_ROLE(), upgrader);
    }

    function grantRoleBalanceDojangResolver() public broadcast(adminKey) {
        BalanceDojangResolver balanceDojangResolver = BalanceDojangResolver(mustGetAddress("BalanceDojangResolver"));
        balanceDojangResolver.grantRole(balanceDojangResolver.UPGRADER_ROLE(), upgrader);
    }

    function grantRoleDojangScroll() public broadcast(adminKey) {
        DojangScroll dojangScroll = DojangScroll(mustGetAddress("DojangScroll"));
        dojangScroll.grantRole(dojangScroll.UPGRADER_ROLE(), upgrader);
    }

    function configure() public broadcast(adminKey) {
        SchemaBook schemaBook = SchemaBook(mustGetAddress("SchemaBook"));
        DojangAttesterBook dojangAttesterBook = DojangAttesterBook(mustGetAddress("DojangAttesterBook"));
        AttestationIndexer attestationIndexer = AttestationIndexer(mustGetAddress("AttestationIndexer"));
        AddressDojangResolver addressDojangResolver = AddressDojangResolver(mustGetAddress("AddressDojangResolver"));
        BalanceDojangResolver balanceDojangResolver = BalanceDojangResolver(mustGetAddress("BalanceDojangResolver"));
        DojangScroll dojangScroll = DojangScroll(mustGetAddress("DojangScroll"));

        addressDojangResolver.setIndexer(address(attestationIndexer));
        balanceDojangResolver.setIndexer(address(attestationIndexer));

        dojangScroll.setSchemaBook(address(schemaBook));
        dojangScroll.setDojangAttesterBook(address(dojangAttesterBook));
        dojangScroll.setIndexer(address(attestationIndexer));

        bytes32 addressSchemaUid = schemaRegistry.register(ADDRESS_DOJANG_SCHEMA, addressDojangResolver, true);
        schemaBook.register(DojangSchemaIds.ADDRESS_DOJANG, addressSchemaUid);

        bytes32 balanceSchemaUid = schemaRegistry.register(BALANCE_DOJANG_SCHEMA, balanceDojangResolver, true);
        schemaBook.register(DojangSchemaIds.BALANCE_DOJANG, balanceSchemaUid);
    }
}
