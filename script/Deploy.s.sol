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
        //uint256 ChainID = uint256(5);
        //require(ChainID == uint256(1), "WARNING: Deploying with Goerli ChainID. Please double check [!]"); // Comment this for Goerli deploy
        new CCIP2ETH(address(manager), "5");
        vm.stopBroadcast();
    }
}
