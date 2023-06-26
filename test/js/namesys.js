import { client } from './clients.js'
export const ADDRESS_ZERO = '0x0000000000000000000000000000000000000000';
export const REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';
export const WRAPPER = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

export const CCIP_GATEWAY = "0x73f820D469aE0642BBf399BEc8FF99da6fcfD845"
export const CCIP_RESOLVER = "0xd32676dbD18ad202c6A4B75CDfa58FD3f195faAF"
export const CCIP_DEV = "0x9F04bC8aA8932CafB9D6f6bF964612247E8B73e6"
import { normalize, namehash } from 'viem/ens'
import { parseAbi } from 'viem'

export async function supportsInterface(_contract, _sig) {
    return await client.readContract({
        address: _contract,
        abi: parseAbi(["function supportsInterface(bytes4 interfaceID) external view returns (bool)"]),
        args: [_sig]
    })
}

console.log("Interface Test", await supportsInterface("0x12345678", "0xd32676dbD18ad202c6A4B75CDfa58FD3f195faAF"))

export const utf8Decoder = new TextDecoder('utf-8')
export const utf8Encoder = new TextEncoder()

export async function getEnsOwner(domain) {
    try {
        const n = namehash(normalize(domain));
        let owner = await client.readContract({
            address: REGISTRY,
            abi: parseAbi(["function owner(bytes32) view returns(address)"]),
            args: [n]
        })
        if (owner == WRAPPER) {
            owner = await client.readContract({
                address: WRAPPER,
                abi: parseAbi(["function ownerOf(uint256) view returns(address)"]),
                args: [BigInt(n).toString(10)]
            })
        }
        return owner;
    } catch (error) {
        console.error(error)
    }
}
export async function resolve(domain, data, api = "http://127.0.0.1:8545") {

    try {
        fetch(api, {
            body: JSON.stringify({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": addr,
                    "data": data
                }, "latest"],
                "id": Date.now()
            }),
            method: 'POST',
            headers: {
                'content-type': 'application/json',
            }
        }).then((res) => {
            //if (res) return;
        })
    } catch (error) {

    }

}

export async function ethCall(addr, data, api = "http://127.0.0.1:8545", auth = "") {
    try {
        fetch(api, {
            body: JSON.stringify({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": addr,
                    "data": data
                }, "latest"],
                "id": Date.now()
            }),
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                //auth
            }
        }).then((res) => {
            //if (res) return;
        })
    } catch (error) {

    }

}
export async function ccipCall(addr, data, api = "http://127.0.0.1:8545", auth = "") {
    try {
        fetch(api, {
            body: JSON.stringify({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": addr,
                    "data": data
                }, "latest"],
                "id": Date.now()
            }),
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                //auth
            }
        }).then((res) => {
            //if (res) return;
        })
    } catch (error) {

    }
}

export async function gatewayCalls(gateways) {
    let _result = "";
    for (let i = 0; i < gateways.length; i++) {
        try {
            fetch(api, {
                body: JSON.stringify({
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{
                        "to": addr,
                        "data": data
                    }, "latest"],
                    "id": Date.now()
                }),
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    //auth
                }
            }).then((res) => {
                //if (res) return;
            })
        } catch (error) {

        }
        const element = array[i];
        break;
    }

}
/*
const ccip2eth = {
    _addr: {
        "mainnet": "0xaddr",
        "goerli": "0xaddr"
    },
    ethCall: async (addr, data) => {
        fetch("http://127.0.0.1:8545", {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                //auth
            },
            body: JSON.stringify({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": addr,
                    "data": data
                }, "latest"],
                "id": Date.now()
            })
        }).then((res) => {
            //if (res) return;
        })
    }
}*/