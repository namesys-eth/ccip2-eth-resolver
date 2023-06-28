// ED25519 : deterministic keygen
import {hkdf} from '@noble/hashes/hkdf'
import {sha256} from '@noble/hashes/sha256'
const {
    hexToBytes,
    bytesToHex
} = require('@noble/hashes/utils');
const {
    hkdf
} = require('@noble/hashes/hkdf');
const {
    sha256
} = require('@noble/hashes/sha256');

import {
    ed25519
} from '@noble/curves/ed25519'
//import {
//    hashToPrivateScalar
//} from '@noble/curves/abstract/modular';

import * as w3name from 'w3name';

export async function ed25519Keygen(domain, owner, password){
    let caip10 = `eip155:1:${owner}`
    password = password ? password : ''
    //domain = normalize(domain)
    let msg = `Requesting Signature To Generate Deterministic IPNS Key\n\nENS Domain: "${domain}"\nExtradata: 0x${bytesToHex(await sha256(domain, password, caip10))}\nSigned By: ${caip10}`;
    let sig = await App.SIGNER.signMessage(msg);
    let inputKey = sha256(
        hexToBytes(
            sig.toLowerCase().startsWith('0x') ? sig.slice(2) : sig
        )
    )
    let info = `${caip10}:${domain}`
    let salt = await sha256(`${info}:${password}:${sig.slice(-64)}`)
    let privateKey = await hkdf(sha256, inputKey, salt, info, 32)
    //let hashKey = await hkdf(sha256, inputKey, salt, info, 42)
    //let privateKey = hashToPrivateScalar(hashKey, ed25519.CURVE.n, true).toString(16).padStart(64, "0")
    // App.LOG.innerHTML += `<br>privkey: ${privateKey} -- ${privateKey.length}`
    let publicKey = bytesToHex(await ed25519.getPublicKey(privateKey))
    // App.LOG.innerHTML += `<br>pubkey: ${publicKey} -- ${publicKey.length}`
    let key = `08011240${privateKey}${publicKey}`
    let _ipns = await w3Name.from(hexToBytes(key))
    // App.LOG.innerHTML += `<br>IPNS: ${_ipns.toString()}<br>Key: ` + Buffer(_ipns.key.bytes).toString('hex')
    //console.log(_ipns, await w3Name.resolve(_ipns))
    //let revision = await w3Name.v0(_ipns, "/ipfs/bafybeiee2lzvemjxesych64jw75cypjvce7nzvcyznbl3ogrztrmz2vnii")
    let revision = await w3Name.resolve(_ipns);
    let _hash = '/ipfs/bafybeiee2lzvemjxesych64jw75cypjvce7nzvcyznbl3ogrztrmz2vnii';
    if (revision.value && revision.value != _hash) {
        revision = await w3Name.increment(revision, _hash);
        let k = await w3Name.publish(revision, _ipns.key);
        console.log("published", _hash, k)
    } else {
        //revision = await w3Name.v0(_ipns, _hash)
        //await w3Name.publish(revision, _ipns.key);
    }
    console.log(revision)
    //return [Stringify(privateKey), ed25519.utils.bytesToHex(publicKey)]
}