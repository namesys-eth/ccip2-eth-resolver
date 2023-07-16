//import "./style.css";
//import {
//    BrowserProvider, InfuraProvider
//} from "ethers"; // add viem

//const secp256k1 = require('@noble/secp256k1');
import * as secp256k1 from '@noble/secp256k1'
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
import {
    hashToPrivateScalar
} from '@noble/curves/abstract/modular';
//import {ed25519} from '@noble/curves/';
import * as x3Name from 'w3name';

import {
    gossipsub
} from '@chainsafe/libp2p-gossipsub'

import {
    kadDHT
} from '@libp2p/kad-dht'

import {
    createLibp2p
} from 'libp2p'

import {
    createHelia
} from 'helia'

import {
    ipns,
    ipnsValidator,
    ipnsSelector
} from '@helia/ipns'
import {
    dht,
    pubsub
} from '@helia/ipns/routing'
import {
    unixfs
} from '@helia/unixfs'
import {
    encode,
    decode
} from '@ipld/dag-cbor'

import * as DAG from '@ipld/dag-cbor'
import {
    CID
} from 'multiformats'

//import * as cbor from 'multiformats/codecs/cbor'

let App = {
    ED: false,
    SIGNER: false,
    ADDR: false,
    LOG: document.getElementById("logbook"),
    connect: async () => {
        if (window.ethereum) {
            let wallet = new BrowserProvider(window.ethereum)
            //new ethers.providers.Web3Provider(window.ethereum);
            let x = await wallet.send("eth_requestAccounts", []);
            App.SIGNER = await wallet.getSigner();
            App.ADDR = x[0];
            App.LOG.innerHTML += "<br>Address: " + x[0] + "<br>";
            document.getElementById("_connect").toggleAttribute("disabled")
            document.getElementById("_sign").toggleAttribute("disabled")
            App.ED = ed25519
            let _contenthashRecord = {
                data: "0x<bytes4>+<abi.encode(signer, signature, abi.encode(contenthash))>"
            }
            let contenthash = {};
            //_ipfs.dag.put(_contenthash, {
            //    storeCodec: 'dag-json'
            //}).then((e)=> {contenthash = e});

            let _avatarRecord = {
                "avatar.json": {
                    data: "0x<bytes4>+<abi.encode(signer, signature, abi.encode(avatar_string))>"
                }
            }
            //let resolver = await wallet.getResolver("bafybeiee2lzvemjxesych64jw75cypjvce7nzvcyznbl3ogrztrmz2vnii.ipfs2.istest.eth");
            //console.log(wallet, "Resolver:", resolver)
            //let content = await resolver.getContenthash();
            //console.log("IPFS", content)

            let avatar = {};
            //_ipfs.dag.put(_avatar, {
            //    storeCodec: 'dag-json'
            //}).then((e) => {
            //    avatar = e
            //});

            let _record = {
                ".well-known": {
                    eth: {
                        domain: {
                            "contenthash.json": {
                                contenthash
                            },
                            avatar
                        }
                    }
                }
            }
            let record = {};
            //_ipfs.dag.put(_record, {
            //    storeCodec: 'dag-json'
            //}).then((e)=> {record = e});

            const obj = {
                x: 1,
                /* CID instances are encoded as links */
                y: [2, 3, CID.parse('QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4')],
                z: {
                    a: CID.parse('QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4'),
                    b: null,
                    c: 'string'
                }
            }
            let data = encode(obj)
            let decoded = decode(data)
            //decoded.y[0] // 2
            const hash = await sha256(data)
            //let cid = CID.create(1, json.code, hash)
            console.log("hash", bytesToHex(hash), CID.asCID(decoded.z.a).toString()) // cid instance
            console.log(DAG, data, decoded)
        } else {
            console.log("NO MM")
        }
    },
    test1: async () => {
        //let msg = `Generate IPNS Keys for domain.eth\n\nSigned By: eip155:1:${App.ADDR}`;
        //let sig = await App.SIGNER.signMessage(msg);
        //App.LOG.innerHTML += `<br>Signature: ${sig} <br>`;
        let provider = new InfuraProvider("mainnet"); // mainnet
        let resolver = await provider.getResolver(
            "freetibet.istest.eth"
        );
        console.log("Resolver:", resolver);
        let content = {};
        resolver.getContentHash().then(((e) => {
            console.log("IPFS", e);
            content = e;
            App.LOG.innerHTML += `<br>xIPFS: ${JSON.stringify(content)} <br>`;
        }));
        App.LOG.innerHTML += `<br>IPFS: ${JSON.stringify(content)} <br>`;
    },
    w3n: async () => {

        //const myName = await Name.create()
        // myName.key.bytes can now be written to disk / database, etc.
        // App.LOG.innerHTML += `<br>IPNS: ${myName.toString()}<br>Key: ` + Buffer(myName.key.bytes).toString('hex')
        // let's pretend some time has passed and we want to load the
        let x = "080112400132f293196df88df8fd916d1ed8be07f69109cc7516aa9ab8e5bde6c7a04f5fb48b94cf6818573d58e71cfd2070920a11e5850394a1f69cbf4131e7755ee57d";
        // key from disk:
        //const loadedBytes = await fs.promises.readFile('myName.key')

        const myName2 = await x3Name.from(hexToBytes(x))
        App.LOG.innerHTML += `<br>IPNS: ${myName2.toString()}<br>Key: ` + Buffer(myName2.key.bytes).toString('hex')

    },
    edx: async () => {
        console.log(ed25519)
        let caip10 = `eip155:1:${App.ADDR}`
        let domain = "domain.eth"
        let password = "pass12#$"
        let msg = `Requesting Signature to Generate Deterministic IPNS Keys for "${domain}"\n\nWARNING:........\n\nExtradata: 0x${bytesToHex(await sha256(domain, password, caip10))}\nSigned By: ${caip10}`;
        let sig = await App.SIGNER.signMessage(msg);
        let inputKey = sha256(
            hexToBytes(
                sig.toLowerCase().startsWith('0x') ? sig.slice(2) : sig
            )
        )
        let info = `${caip10}:${domain}`
        let salt = await sha256(`${info}:${password ? password : ''}:${sig.slice(-64)}`)
        let hashKey = await hkdf(sha256, inputKey, salt, info, 42)
        let privateKey = hashToPrivateScalar(hashKey, ed25519.CURVE.n, true).toString(16).padStart(64, "0")
        App.LOG.innerHTML += `<br>privkey: ${privateKey} -- ${privateKey.length}`
        let publicKey = bytesToHex(await ed25519.getPublicKey(privateKey))
        App.LOG.innerHTML += `<br>pubkey: ${publicKey} -- ${publicKey.length}`
        let key = `08011240${privateKey}${publicKey}`
        let w3Name = await x3Name.from(hexToBytes(key))
        App.LOG.innerHTML += `<br>IPNS: ${w3Name.toString()}<br>Key: ` + Buffer(w3Name.key.bytes).toString('hex')
        //console.log(w3Name, await x3Name.resolve(w3Name))
        //let revision = await x3Name.v0(w3Name, "/ipfs/bafybeiee2lzvemjxesych64jw75cypjvce7nzvcyznbl3ogrztrmz2vnii")
        let revision = await x3Name.resolve(w3Name);
        let _hash = '/ipfs/bafybeiee2lzvemjxesych64jw75cypjvce7nzvcyznbl3ogrztrmz2vnii';
        if (revision.value && revision.value != _hash) {
            revision = await x3Name.increment(revision, _hash);
            let k = await x3Name.publish(revision, w3Name.key);
            console.log("published", _hash, k)
        } else {
            //revision = await x3Name.v0(w3Name, _hash)
            //await x3Name.publish(revision, w3Name.key);
        }
        console.log(revision)
        //return [Stringify(privateKey), ed25519.utils.bytesToHex(publicKey)]
    }
}

window.App = App

// 080112409b9da2926c90c2b592d129c74a7a1a91d84a0448a53cb89fc890ea5a00698154ffa142ada9a422283e65bcbd04a3f8f0432a8be799b3afc751ddd874d931bae6