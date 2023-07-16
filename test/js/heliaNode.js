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
import { webSockets} from '@libp2p/websockets'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { MemoryBlockstore } from 'blockstore-core'
import { MemoryDatastore } from 'datastore-core'
import { bootstrap } from '@libp2p/bootstrap'
import { CID } from 'multiformats/cid'

const blockstore = new MemoryBlockstore()

const datastore = new MemoryDatastore()

export const heliaNode = {
    
}