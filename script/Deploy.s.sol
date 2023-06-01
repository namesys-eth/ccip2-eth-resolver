// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "src/CCIP2ETH.sol";
import "src/GatewayManager.sol";

contract CCIP2ETHDeploy is Script {
    /// @dev : Deploy
    function run() external {
        vm.startBroadcast();
        GatewayManager manager = new GatewayManager();
        new CCIP2ETH(address(manager));
        vm.stopBroadcast();
    }
}
