import { gossipsub } from '@chainsafe/libp2p-gossipsub'
import { kadDHT } from '@libp2p/kad-dht'
import { createLibp2p } from 'libp2p'
import { identifyService } from 'libp2p/identify'
import { createHelia } from 'helia'
import { ipns, ipnsValidator, ipnsSelector } from '@helia/ipns'
import { dht, pubsub } from '@helia/ipns/routing'
import { unixfs } from '@helia/unixfs'
import { dagCbor } from '@helia/dag-cbor'
import { tcp } from '@libp2p/tcp'
import { webRTC } from '@libp2p/webrtc'
import { webTransport } from '@libp2p/webtransport'
import { webSockets } from '@libp2p/websockets'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { MemoryBlockstore } from 'blockstore-core'
import { MemoryDatastore } from 'datastore-core'
import { bootstrap } from '@libp2p/bootstrap'
import { CID } from 'multiformats/cid'

const blockstore = new MemoryBlockstore()

const datastore = new MemoryDatastore()

/*const libp2p = await createLibp2p({
    dht: kadDHT({
        validators: {
            ipns: ipnsValidator
        },
        transports: [
            tcp()
        ],
        selectors: {
            ipns: ipnsSelector
        }
    }),
    pubsub: gossipsub()
})*/
const libp2p = await createLibp2p({
    datastore,
    addresses: {
        listen: [
            //'/ip4/127.0.0.1/tcp/0'
        ]
    },
    dht: kadDHT({
        validators: {
            ipns: ipnsValidator
        },
        transports: [
            tcp(),
            webRTC(),
            webTransport(),
            webSockets(),
            //pubsub()
        ],
        selectors: {
            ipns: ipnsSelector
        }
    }),
    pubsub: gossipsub(),
    transports: [
        tcp(),
        webRTC(),
        webTransport(),
        webSockets()
    ],
    connectionEncryption: [
        noise()
    ],
    streamMuxers: [
        yamux()
    ],
    peerDiscovery: [
        bootstrap({
            list: [
                /*"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPT5iaBt7C1GEfG8eD29cBhChCsyWeyxoGPpEkGMMpa3f",
                "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWPT5iaBt7C1GEfG8eD29cBhChCsyWeyxoGPpEkGMMpa3f",
                "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport/certhash/uEiASidIgli9jVl6IAaOQsJvRJVLRiU0MnjPrAA-9NA50lA/certhash/uEiDYQzo7uGFRlnnxv_ufVQfwVv1iJ7S9z8ylnqk1uzSp7A/p2p/12D3KooWPT5iaBt7C1GEfG8eD29cBhChCsyWeyxoGPpEkGMMpa3f",
                '/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN',
                '/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa',
                '/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb',
                '/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt',
                "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
                "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
                
                "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
                "/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
                "/dns4/bootstrap-1.mainnet.filops.net/tcp/1347/p2p/12D3KooWCwevHg1yLCvktf2nvLu7L9894mcrJR4MsBCcm4syShVc",
                "/dns4/bootstrap-3.mainnet.filops.net/tcp/1347/p2p/12D3KooWKhgq8c7NQ9iGjbyK7v7phXvG6492HQfiDaGHLHLQjk7R",
                "/dns4/bootstrap-8.mainnet.filops.net/tcp/1347/p2p/12D3KooWScFR7385LTyR4zU1bYdzSiiAb5rnNABfVahPvVSzyTkR",
                "/dns4/bootstrap-0.ipfsmain.cn/tcp/34721/p2p/12D3KooWQnwEGNqcM2nAcPtRR9rAX8Hrg4k9kJLCHoTR5chJfz6d",
                "/dns4/bootstrap-0.mainnet.filops.net/tcp/1347/p2p/12D3KooWCVe8MmsEMes2FzgTpt9fXtmCY7wrq91GRiaC8PHSCCBj",
                "/dns4/bootstrap-2.mainnet.filops.net/tcp/1347/p2p/12D3KooWEWVwHGn2yR36gKLozmb4YjDJGerotAPGxmdWZx2nxMC4",
                "/dns4/bootstrap-5.mainnet.filops.net/tcp/1347/p2p/12D3KooWLFynvDQiUpXoHroV1YxKHhPJgysQGH2k3ZGwtWzR4dFH",
                "/dns4/bootstrap-6.mainnet.filops.net/tcp/1347/p2p/12D3KooWP5MwCiqdMETF9ub1P3MbCvQCcfconnYHbWg6sUJcDRQQ",
                "/dns4/bootstrap-1.starpool.in/tcp/12757/p2p/12D3KooWQZrGH1PxSNZPum99M1zNvjNFM33d1AAu5DcvdHptuU7u",
                "/dns4/lotus-bootstrap.ipfsforce.com/tcp/41778/p2p/12D3KooWGhufNmZHF3sv48aQeS13ng5XVJZ9E6qy2Ms4VzqeUsHk",
                "/dns4/bootstrap-0.starpool.in/tcp/12757/p2p/12D3KooWGHpBMeZbestVEWkfdnC9u7p6uFHXL1n7m1ZBqsEmiUzz",
                "/dns4/bootstrap-4.mainnet.filops.net/tcp/1347/p2p/12D3KooWL6PsFNPhYftrJzGgF5U18hFoaVhfGk7xwzD8yVrHJ3Uc",
                "/dns4/bootstrap-7.mainnet.filops.net/tcp/1347/p2p/12D3KooWRs3aY1p3juFjPy8gPN95PEQChm2QKGUCAdcDCC4EBMKf",
                "/dns4/node.glif.io/tcp/1235/p2p/12D3KooWBF8cpp65hp2u9LK5mh19x67ftAam84z9LsfaquTDSBpt",*/
                "/dns4/bootstrap-1.ipfsmain.cn/tcp/34723/p2p/12D3KooWMKxMkD5DMpSWsW7dBddKxKT7L2GgbNuckz9otxvkvByP"
            ]
        })
    ],
    services: {
        identify: identifyService({
            //agentVersion: "namesys/v0.0.1",
            //protocolPrefix: "namesys_eth"
        })
    }
})

console.log(identifyService())

const helia = await createHelia({
    datastore,
    blockstore,
    libp2p
})


const name = await ipns(helia, [
    dht(helia),
    //pubsub(helia)
])
import { identity } from "multiformats/bases/identity"

//console.log(await name.resolve(CID.parse("k51qzi5uqu5dhhcu1pop9pynjg2g3l6vrlt379x6huzy2zhyg54o1u6csnuwi3", base36.decoder)))
// create a public key to publish as an IPNS name
//const keyInfo = await helia.libp2p.keychain.createKey('my-key')
const peerId = await helia.libp2p.keychain.exportPeerId('self')
let x = await helia.libp2p.keychain.exportPeerId("self")

console.log(x)//await helia.libp2p.keychain.exportKey('self', ""))
let pkx = Buffer.from("mXYRhyP1hnkTO+IrTvrW8Cc3uRZerg+KFv2qUKrgEZTUqLfX3oxaj95m10J71CDY2klyMIuAi+UprGEdzbVCAYsBLQ2tTOQzhy1CRnCR2UY9wY2eZ17hGKOxQgz/yBfcsgJfSO578m1rO4uwXese5fA")
import crypto from 'node:crypto';
let kk1 = "302a300506032b65700321006d28cf8e17e4682fbe6285e72b21aa26f094d8dbd18f7828358f822b428d069f"
//let pp = await crypto.createPrivateKey({
//    format: 'der',
    //type: 'ed25519',
//    key: kk1
//})

const { publicKey, privateKey } = crypto.createPrivateKey({format:"der", type:"spki", key:"0x4c133828137cafea00e746b6b39f2795eacf40b01ab4a09f1c5560fcaeeef8fc"})// ('ed25519');
const der = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const rawHex = der.substring(32); // can serialize this / use it with libsodium etc...

console.log("N",der, rawHex)
console.log(await helia.libp2p.keychain.importKey("test", "mXYRhyP1hnkTO+IrTvrW8Cc3uRZerg+KFv2qUKrgEZTUqLfX3oxaj95m10J71CDY2klyMIuAi+UprGEdzbVCAYsBLQ2tTOQzhy1CRnCR2UY9wY2eZ17hGKOxQgz/yBfcsgJfSO578m1rO4uwXese5fA", ""))
//console.log(await CID.parse(x.toString(identity), identity.decoder ))
// store some data to publish
//const peerId = helia.libp2p.keychain.exportPeerId("self");
const dag = dagCbor(helia)
let cid = await dag.add({ "test": "x1fsdf" })
console.log(cid)
// publish the name
let k = await name.publish(peerId, cid)
console.log("published", k)
// resolve the name
cid = await name.resolve(peerId)
console.log(cid)
