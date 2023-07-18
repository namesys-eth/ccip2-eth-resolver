[![](https://raw.githubusercontent.com/namesys-eth/ccip2-eth-resolver/main/.github/badge.svg?v=12345)](https://github.com/namesys-eth/ccip2-eth-resolver/actions/workflows/test.yml)

# `CCIP2.ETH`

### Off-Chain ENS Records Resolver

# Contracts

## [Install Foundry](https://getfoundry.sh/)
`curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup`

## Install dependency
`forge install foundry-rs/forge-std --no-commit --no-git`

## Goerli Testnet
 `./test/goerli.sh`

## Specification

### a) CCIP-Read Resolver (EIP-2544/EIP-3688)

This specification is an extension of ENSIP-10 (EIP-2544/EIP-3688) using mutable and immutable storage pointers for off-chain records storage.

```solidity
function resolve(bytes calldata name, bytes calldata data) external view returns(bytes memory result)
```

### b) Off-chain Records Storage Format

CCIP2 relies on IPNS hashes serving as proxies to upgradeable IPFS or IPLD content. In the parent IPNS directory, the records must be stored in the [RFC-8615](https://www.rfc-editor.org/rfc/rfc8615) compliant `.well-known` directory format. ENS records for any name `sub.domain.eth` must then be stored in JSON format under a [reverse-DNS](https://en.wikipedia.org/wiki/Reverse_domain_name_notation) style directory path using `/` instead of `.` as separator, i.e. in format `ipfs://<hash>/.well-known/eth/domain/sub/<record>.json`.

### c) Global records

CCIP2 also offers the experimental feature

**1. Some Examples:**

- ENS text record for `vitalik.eth`'s avatar is stored at `ipns://<ipns_hash>/.well-known/eth/vitalik/avatar.json` formatted as

```solidity
{ data: abi.encode(string("eip155:1/erc1155:0xb32979486938aa9694bfc898f35dbed459f44424/10063")) }
```

- ETH address record for `sub.domain.eth` is stored at `https://sub.domain.eth/.well-known/eth/domain/sub/_address/60.json` formatted as

```solidity
{ data: abi.encode(<_address/60>) }
```

Note: If the JSON data is signed by the Registrant of `domain.eth`, it must be prefixed with `bytes4` of `callback` function selector as,

```solidity
{ data: bytes.concat(Resolver.___callback.selector, <signed_data>}
```

**2. Resolver function → JSON file names:**

| Type | Function | JSON file |
| -- | -- | --- |
| Text Records ([ENSIP-05](https://docs.ens.domains/ens-improvement-proposals/ensip-5-text-records)) | `text(bytes32 node, string memory key)` | `<key>.json` |
| Ethereum Address | `addr(bytes32 node)` | `_address/60.json` |
| *Contenthash ([ENSIP-07](https://docs.ens.domains/ens-improvement-proposals/ensip-7-contenthash-field)) | `contenthash(bytes32 node)` | `contenthash.json` |
| Multichain Address ([ENSIP-09](https://docs.ens.domains/ens-improvement-proposals/ensip-9-multichain-address-resolution)) | `addr(bytes32 node, uint coinType)`| `_address/<coinType>.json` |
| Public Key | `pubkey(bytes32 node)`| `pubkey.json` |
| *Name | `name(bytes32 node)`| `pubkey.json` |
| Interface | `interfaceImplementer(bytes32 node, bytes4 _selector)`| `_interface/0x<bytes4 _selector>_.json` |
| ABI | `ABI(bytes32 node, uint256 contentTypes)`| `_abi/<contentTypes>.json` |
| Zonehash | `zonehash(bytes32 node)`| `_dnsrecord/zonehash.json` |
| DNS Record | `dnsRecord(bytes32 node, bytes32 name, uint16 resource) `| `_dnsrecord/<resource>.json` |
| DNS Record | `dnsRecord(bytes32 node, bytes name, uint16 resource) `| `_dnsrecord/<resource>.json` |

* Default Contenthash is set as Recordhash itself but users are free to update their web facing contenthash.
* Name isn't used for reverse address to domain.eth lookup, users have to use official/onchain reverse records for that feature.

### CCIP2.ETH Gateways

| Type | Identifier | Gateway URL |
| --- | --- | --- |
| `ipns://<contenthash>` | `0xe5` | `https://<base36-CID-v1>.ipns.dweb.link/.well-known/..` |
| `ipfs://<contenthash>` | `0xe3` | `https://<base32-CID-v1>.ipfs.dweb.link/.well-known/..` |
| ENS + IPNS Node| &nbsp; | `https://domain-eth.ipns.dweb.link/.well-known/..` |
| ENS | &nbsp; | `https://domain.eth.limo/.well-known/..` |
| ENS + IPFS2 resolver| `0xe3`, `0xe5` | `https://<CID-v1>.ipfs2.eth.limo/.well-known/..` |

## Code

### --

### Records manager process

- `signKey/0` (`K0`): EOA, owner key from connected wallet, secp256k1
- `signKey/N`: Deterministic records signer key/s under `K0`, secp256k1
  * a
- `ipnsKey/N`: Deterministic IPNS key/s under `K0`, ed25519
    * For future we could reuse secp256k1/signKey as `ipnsKey`
- `nostrKey/N`: Deterministic Nostr key/s under `K0`, secp256k1/schnorr
    * Nostr Keys can be used to send IPNS records to service/bots over public/private Nostr relays. It's part of future Whisper/AA designs.


A) Initial setup/Registration:
1) `TX1`: Owner of `domain.eth` should change their resolver address to `ccip2.eth` resolver in ENS contract
2) `ipnsKey/0`: Owner generates a new deterministic ipns key for `domain.eth`
   * Users are free to use any supported mutable and immutable storage pointers. IPFS, IPNS+IPFS, \*IPNS+IPLD, IPLD+Redirect. \*Other ENS contenthash types are also supported. (*@dev add tests for all, experimental)   
3) `TX2`: Owner sets `ipnsKey/0` as recordhash for `domain.eth`

B) Records Update Process (IPFS OR IPNS+IPFS)
1) Check recordhash for `domain.eth`, resolve and read `./.well-known/eth/domain/<ccip2-meta>.json` (* it's a json with all latest records so we don't have to resolve whole directory)
2) ..
