// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console2 as console} from "forge-std/console2.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Vm} from "forge-std/Vm.sol";

struct Deployment {
    string name;
    address payable addr;
}

abstract contract Artifacts {
    /// @notice Foundry cheatcode VM.
    Vm private constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string internal _deploymentOutFile;
    mapping(string => Deployment) internal _namedDeployments;

    function setUp() public virtual {
        _deploymentOutFile =
            string.concat(_vm.projectRoot(), "/deployments/", _vm.toString(block.chainid), "-deploy.json");
        _ensurePath(_deploymentOutFile);
        console.log("Writing artifact to %s", _deploymentOutFile);

        console.log("Connected to network with chainid %s", block.chainid);
    }

    function save(string memory name, address deployed) public {
        console.log("Saving %s: %s", name, deployed);
        if (bytes(name).length == 0) {
            revert("empty name");
        }
        if (bytes(_namedDeployments[name].name).length > 0) {
            revert("already exists");
        }

        Deployment memory deployment = Deployment({name: name, addr: payable(deployed)});
        _namedDeployments[name] = deployment;
        _appendDeployment(deployment);
    }

    function mustGetAddress(string memory name) public view returns (address payable) {
        Deployment memory existing = _namedDeployments[name];
        if (existing.addr == address(0)) {
            revert("deployment does not exist");
        }

        return payable(existing.addr);
    }

    function _ensurePath(string memory path) private {
        string[] memory outputs = _vm.split(path, "/");
        string memory dir = "";
        for (uint256 i = 0; i < outputs.length - 1; i++) {
            dir = string.concat(dir, outputs[i], "/");
        }
        _vm.createDir(dir, true);
    }

    function _appendDeployment(Deployment memory deployment) internal {
        _vm.writeJson({json: stdJson.serialize("", deployment.name, deployment.addr), path: _deploymentOutFile});
    }
}
