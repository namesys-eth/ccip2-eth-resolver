import { sha256 } from '@noble/hashes/sha256'
import { wallet, anvil } from './clients.js'
import { privateKeyToAccount } from 'viem/accounts'

import fs from 'fs';
import {
    hexToBytes,
    bytesToHex
} from '@noble/hashes/utils';

export async function ed25519KeyRequest(domain, owner, password) {
    let caip10 = `eip155:1:${owner}`
    let msg =
        `Requesting Signature To Generate IPNS (ed25519) Key\n\nENS Domain: ${domain}\nKey Type : EdDSA/ed25519\nExtradata: 0x${bytesToHex(await sha256(`${caip10}:${domain}:${password}`))}\nSigned By: ${caip10}`
    try {
        return await wallet.signMessage({message: msg })
    } catch (error) {
        console.error("IPNS Sign Request ", error)
    }
}
//fs.writeFile('./test/sig.txt', msg, () => { console.log });

export async function secp256k1KeyRequest(signer, domain, owner, password) {
    //owner = account.address
    let caip10 = `eip155:1:${owner}`
    password = "0x"+bytesToHex(password ? await sha256(`${caip10}:${domain}:${password}`) : await sha256(`${caip10}:${domain}:`))
    const extradata = "0x"+bytesToHex(await sha256(`${caip10}:${domain}:${password}`))
    let msg = `Requesting Signature To Generate Off-Chain ENS Records Manager Key\n\nENS Domain: ${domain}\nKey Type : ECDSA/secp256k1\nExtradata: 0x${extradata}\nSigned By: ${caip10}`

   try {
        let sig = await signer.signMessage({message:msg})
        let full = `${caip10}:${domain}:${extradata}:${sig.slice(2)}`
        console.log("k",signer.address)
        //console.log(msg)
        //console.log(full)
        console.log("\n--hashKey --:", "0x"+bytesToHex(await sha256(`${caip10}:${domain}:${extradata}:${sig.slice(2)}`)))
    } catch (error) {
        console.error("secp256k1 Sign Request ", error)
    }
}

secp256k1KeyRequest(privateKeyToAccount("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "vitalik.eth", "0x00000000", "pass$#$#");