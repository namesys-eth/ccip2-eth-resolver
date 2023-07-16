import * as ccip2 from "../../out/CCIP2ETH.sol/CCIP2ETH.json" assert { type: "json" };
import * as gateway from "../../out/GatewayManager.sol/GatewayManager.json" assert { type: "json" };
import fs from 'fs';
fs.writeFile('./test/abi.js', `export const ccip2abi = ${JSON.stringify(ccip2.default.abi)};\nexport const ccip2_bytecode = ${JSON.stringify(ccip2.default.deployedBytecode["object"])};`, () => { console.log });

fs.appendFile('./test/abi.js', `\nexport const gatewayabi = ${JSON.stringify(gateway.default.abi)};\nexport const gateway_bytecode = ${JSON.stringify(gateway.default.deployedBytecode["object"])};`, () => { console.log });


