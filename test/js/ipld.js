import 'dotenv/config'

const DEV_KEY = process.env.GOERLI_PRIVATE_KEY;
const PRIV_KEY_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PRIV_KEY_b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
import { privateKeyToAccount } from 'viem/accounts'


import { createHelia } from 'helia'
import { dagCbor } from '@helia/dag-cbor'

const helia = await createHelia()
const dag = dagCbor(helia)

import { car } from '@helia/car'
import { CarReader, CarWriter } from '@ipld/car'
import { Readable } from 'node:stream'
import fs from 'node:fs'

/*
signed data format <bytes4>+<address>+<bytes>+<bytes>+<bytes>

    function signedRecord(
        address recordSigner, // Owner OR On-chain Manager OR Off-chain Manager
        bytes memory recordSignature, // Signature from signer for result value
        bytes memory approvedSignature, // bytes1(..) IF signer is owner or on-chain manager
        bytes memory result // ABI-encoded result
    ) external view returns (bytes memory);

    function signedRedirect(
        address recordSigner, // Owner OR On-chain Manager OR Off-chain Manager
        bytes memory recordSignature, // Signature from signer for redirect value
        bytes memory approvedSignature, // bytes1(..) IF signer is owner or on-chain manager
        bytes memory redirect // ABI-encoded recordhash OR DNS-encoded domain.eth to redirect
    ) external view returns (bytes memory);
 */
let record = {
    '.well-known': {
        eth: {
            ccip2: {
                address: {
                    '60': { // Ethereum
                        data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
                        address: "0x<plaintext address>",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    '1237': { // Nostr
                        data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
                        address: "npub<plaintext address>",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    "meta": [60, 1237] // list
                },
                text: {
                    "avatar": {
                        data: "...<abi encoded >",
                        text: "<plaintext avatar>",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    "github": {
                        data: "...<abi encoded >",
                        text: "@namesys-eth",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    "meta": ["avatar", "github"]
                }
            }
        }
    }
}
const eth = {
    data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
    address: "0x<plaintext address>",
    lastUpdated: '<timestamp>',
    slip44: 60,
    chainId: 1,
    symbol: "ETH",
    name: "Ethereum Mainnet",
    signedBy: "0x<signer>"
}
const ethipld = await dag.add(eth)

const nostr = {
    data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
    address: "npub<plaintext address>",
    slip44: 1237,
    chainId: false,
    symbol: "NOSTR",
    name: "Nostr Protocol",
    lastUpdated: '<timestamp>',
    signedBy: "0x<signer>"
}
const nostripld = await dag.add(nostr)

const addr = {
    "60": ethipld,
    "1237": nostripld,
    "metadata": [60, 1237]
}
//const object1 = { hello: 'world' }
const addrs = await dag.add(addr)

const _wellknown = {
    ".well-known": {
        eth: {
            domain: {
                address: addrs,
                "metadata": {
                    address: [60, 1237],
                    text: ["avatar", "twitter"]
                }
            }
        },
        "nostr.json": { // nip05
            "_": "0xpubkey", //"_" is blank prefix = domain.eth.limo = _@domain.eth.limo
            "name": "0xpubkey"// 32 bytes hex, name@domain.eth.limo
        }
    }
}

let r = {
    ".well-known": {
        "eth": {
            "domain": {
                "address": {
                    "/": "bafyreicwh6bd75rpyo65zg5ku76jhrrqsiwefezqtnx7ocsehya44si3je"
                },
                "metadata": {
                    "text": ["avatar", "twitter"],
                    "address": [60, 1237]
                }
            }
        }
    }
}
//,}
const _record = await dag.add(_wellknown)
console.log("1", _record)
console.log(typeof(_record))
const retrievedObject = await dag.get(_record)

console.log(typeof(retrievedObject))
console.log("2", JSON.stringify(retrievedObject))
let x = await dag.get(retrievedObject[".well-known"].eth.domain.address)
let y = await dag.get(x[60])
console.log("3", x)
console.log("4", y)

console.log("5", y.data)//await dag.get(y))
// { hello: 'world' }

//const fs = unixfs(helia)

// add some UnixFS data
//const cid = await fs.addBytes(fileData1)

export async function exportCarFile(_cid, _file = "record") {
    const c = car(helia)
    const { writer, out } = await CarWriter.create(_cid)
    Readable.from(out).pipe(fs.createWriteStream(`./test/${_file}.car`))
    await c.export(_cid, writer)
}

//export async function uploadCarFile(_cid, )
exportCarFile(_record)