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
                    '60.json': { // Ethereum
                        data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
                        address: "0x<plaintext address>",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    '1237.json': { // Nostr
                        data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
                        address: "npub<plaintext address>",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    "meta.json": [60, 1237] // list
                },
                text: {
                    "avatar.json": {
                        data: "...<abi encoded >",
                        text: "<plaintext avatar>",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    "github.json": {
                        data: "...<abi encoded >",
                        text: "@namesys-eth",
                        lastUpdated: '<timestamp>',
                        signedBy: "0x<signer>"
                    },
                    "meta.json": ["avatar", "github"]
                }
            }
        }
    }
}
const eth = {
    data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
    address: "0x<plaintext address>",
    lastUpdated: '<timestamp>',
    slip44:60,
    chainId:1,
    symbol:"ETH",
    name:"Ethereum Mainnet",
    signedBy: "0x<signer>"
}
const ethipld = await dag.add(eth)

const nostr = {
    data: "0x<prefix><record signer><record signature><approved signature><abi encoded result>",
    address: "npub<plaintext address>",
    slip44: 1237,
    chainId : false,
    symbol:"NOSTR",
    name:"Nostr Protocol",
    lastUpdated: '<timestamp>',
    signedBy: "0x<signer>"
}
const nostripld = await dag.add(nostr)

const addr = {
    "60.json": ethipld,
    "1237.json": nostripld,
    "metadata.json" : [60, 1237]
}
//const object1 = { hello: 'world' }
const myImmutableAddress1 = await dag.add(addr)

const object2 = { address: myImmutableAddress1 }
const myImmutableAddress2 = await dag.add(object2)
console.log("1",myImmutableAddress2)
const retrievedObject = await dag.get(myImmutableAddress2)
console.log("2",retrievedObject)
let x = await dag.get(retrievedObject.address)
console.log("3",x)
console.log("4",x["60.json"])

// { hello: 'world' }

//const fs = unixfs(helia)

// add some UnixFS data
//const cid = await fs.addBytes(fileData1)

export async function exportCarFile(_cid, _file="record") {
    const c = car(helia)
    const { writer, out } = await CarWriter.create(_cid)
    Readable.from(out).pipe(fs.createWriteStream(`./test/${_file}.car`))
    await c.export(_cid, writer)
}

exportCarFile(myImmutableAddress2)