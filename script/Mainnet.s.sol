// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "src/CCIP2ETH.sol";

contract CCIP2ETHMainnet is Script {
    function run() external {
        vm.startBroadcast();

        /// @dev : Deploy
        CCIP2ETH resolver = new CCIP2ETH();
        vm.stopBroadcast();
        resolver;
    }
}
