import * as ccip2 from "../out/CCIP2ETH.sol/CCIP2ETH.json" assert { type: "json" };
import fs from 'fs';
fs.writeFile('./test/ccip2abi.js', `export const ccip2abi = ${JSON.stringify(ccip2.default.abi)};`,()=>{console.log});

import * as gateway from "../out/GatewayManager.sol/GatewayManager.json" assert { type: "json" };
fs.writeFile('./test/gatewayabi.js', `export const gatewayabi = ${JSON.stringify(gateway.default.abi)};`,()=>{console.log});