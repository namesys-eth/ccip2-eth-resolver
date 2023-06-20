import 'dotenv/config'
console.log(process.env)
import { normalize, namehash } from 'viem/ens'
import { toHex } from 'viem'
import { anvil, client, wallet } from './js/clients.js'
import {dnsEncode, supportsInterface} from './js/ccip2.js'
console.log("LL", await supportsInterface("0x12345678", "0xd32676dbD18ad202c6A4B75CDfa58FD3f195faAF"))

//import { ccip2abi, ccip2_bytecode, gatewayabi, gateway_bytecode } from './abi.js'
const [address] = await wallet.getAddresses()
console.log("---JS TEST RUN---")
console.log("TESTNET : Goerli")
const [account] = await wallet.getAddresses();
//wallet.account = account;
const ensAddress = await client.getEnsAddress({
	name: normalize('ccip2.eth'),
})
console.log(ensAddress)
import { parseTransaction, getContract, getContractAddress, parseAbi } from 'viem'
//let nonce = new Date().getTime() /1000 |0
//anvil.setNonce({
//  address: account,
//  nonce: nonce
//})
console.log(dnsEncode("eth.eth"))

//import * as web3 from 'micro-web3';
//import * as contracts from 'micro-web3/contracts/index.js';
//import * as net from 'micro-web3-net';
//const DEF_CONTRACTS = contracts.DEFAULT_CONTRACTS;

//console.log(wallet)
/*
try {
gatewayContract = client.getContract({
address: gatewayAddr,
abi: parseAbi(["function owner() view returns(address)"]),
client,
wallet
})
console.log(gatewayContract)
const owner = await client.readContract({
address: gatewayAddr,
abi: parseAbi(["function owner() view returns(address)"]),
//functionName: 'owner',
//args: ['0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC']
})
console.log(owner == devAddr, "ownerz")
let o2 = await getEnsOwner("ccip2.eth")
console.log(o2, o2 == "0x9F04bC8aA8932CafB9D6f6bF964612247E8B73e6", "O2")
//console.log(await gatewayContract.read.owner())
} catch (error) {
console.log("err..", error, gatewayAddr)
} finally {
//
}export async function getEnsOwner(domain) {
try {
const n = namehash(normalize(domain));
let owner = await client.readContract({
address: "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
abi: parseAbi(["function owner(bytes32) public view returns(address)"]),
args: [n]
})
console.log(BigInt(n).toString(10))
if (owner != "0x9F04bC8aA8932CafB9D6f6bF964612247E8B73e6") {
owner = await client.readContract({
address: "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
abi: parseAbi(["function ownerOf(uint256) public view returns(address)"]),
args: [BigInt(n).toString(10)]
})
}
return owner;
} catch (error) {
console.log(error)
}
}
try {
wallet.getContract({
ccip2abi,
account,
//args:[gatewayAddr],
bytecode: ccip2_bytecode,
}).then(console.log)

} catch (error) {
console.log("err..", error, ccip2Addr)
} finally{
//console.log(await wallet.g(hash))
}
*/