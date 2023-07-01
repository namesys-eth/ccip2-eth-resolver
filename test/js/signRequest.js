import { sha256 } from '@noble/hashes/sha256'
import { wallet } from './clients.js'
import { privateKeyToAccount, publicKeyToAddress } from 'viem/accounts'

import { hkdf } from '@noble/hashes/hkdf'

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
        return await wallet.signMessage({ message: msg })
    } catch (error) {
        console.error('IPNS Sign Request ', error)
    }
}
//fs.writeFile('./test/sig.txt', msg, () => { console.log });
//import * as ipns from 'ed25519-keygen/ipns';

import {
    ed25519
} from '@noble/curves/ed25519'

import {
    hashToPrivateScalar
} from '@noble/curves/abstract/modular';
export async function ed25519KeyGen(signer, domain, password = "") {
    try {
        const caip10 = `eip155:1:${signer.address}`
        const info = `${caip10}:${domain}`
        const pass = '0x' + bytesToHex(password ? await sha256(`${info}:${password}`) : await sha256(info))
        const extradata = '0x' + bytesToHex(await sha256(`${caip10}:${domain}:${pass}`)) // hash of hash
        let msg =
            `Requesting Signature To Generate IPNS Key\n\nENS Domain: ${domain}\nExtradata: 0x${extradata}\nSigned By: ${caip10}`
        const inputKey = await signer.signMessage({ message: msg })
        const salt = await sha256(`${info}:${pass}:${inputKey.slice(-64)}`)
        //const hashKey = await hkdf(sha256, inputKey, salt, info, 42)
        //const privateKey = hashToPrivateScalar(hashKey, ed25519.CURVE.n, true).toString(16).padStart(64, "0")
        const privateKey = bytesToHex(await sha256(`${info}:${salt}:${inputKey}`))
        const publicKey = bytesToHex(await ed25519.getPublicKey(privateKey))
        return {
            private: `0x08011240${privateKey}${publicKey}`,
            public: `0x${publicKey}`,
            base36: `k${BigInt(`0x0172002408011220${publicKey}`).toString(36)}`,
            base16: `f0172002408011220${publicKey}`,
            contenthash: `0xe5010172002408011220${publicKey}`,
        }
    } catch (error) {
        console.error('Error in KeyGen (ed25519):', error)
    }
}
const account = privateKeyToAccount('0x9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

ed25519KeyGen(account, 'vitalik.eth', '0x00000000000000000000000000000000000000000000000000', 'pass$#$#').then(console.log);


//secp256k1KeyRequest(0, 'vitalik.eth', '0x00000000000000000000000000000000000000000000000000', 'pass$#$#').then(console.log);