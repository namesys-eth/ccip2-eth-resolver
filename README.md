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

### CCIP-Read Resolver (EIP-2544/EIP-3688)

This specification is an extension of ENSIP-10 (EIP-2544/EIP-3688) using mutable and immutable storage pointers for off-chain records storage.

```solidity
function resolve(bytes calldata name, bytes calldata data) external view returns(bytes memory result)
```

### Off-Chain Records Storage Format

CCIP2 relies on IPNS hashes serving as proxies to upgradeable IPFS or IPLD content. In the parent IPNS directory (called a `recordhash`), the records must be stored in the [RFC-8615](https://www.rfc-editor.org/rfc/rfc8615) compliant `.well-known` directory format. ENS records for any name `sub.domain.eth` must then be stored in JSON format under a [reverse-DNS](https://en.wikipedia.org/wiki/Reverse_domain_name_notation) style directory path using `/` instead of `.` as separator, i.e. in format `ipfs://<hash>/.well-known/eth/domain/sub/<record>.json`.

#### Some Examples:

- ENS text record for `vitalik.eth`'s avatar is stored at `ipns://<ipns_hash>/.well-known/eth/vitalik/text/avatar.json` formatted as

```solidity
{ data: abi.encode(<avatar>) }
```

- ETH address record for `sub.domain.eth` is stored at `https://<ipns_hash>/.well-known/eth/domain/sub/address/60.json` formatted as

```solidity
{ data: abi.encode(<address/60>) }
```

### Global records [Experimental]

CCIP2 also offers the experimental feature of setting a global wallet-specific `recordhash` (called a `masterhash`), which stores common records that may be shared across many names in a wallet. This feature will be enabled in the CCIP2 client in the future. When `masterhash` is enabled, the reverse-DNS path is replaced with `eth:address(<owner>)` in storage pointers.

Note: If the JSON data is signed by the Registrant of `domain.eth`, it must be prefixed with `bytes4` of `callback` function selector as,

```solidity
{ data: bytes.concat(Resolver.___callback.selector, <signedData>}
```

### d) Security

To ensure secure record resolution, records must be signed by either the owner of a domain or a domain-specific signer (called `approvedSigner`) set by the owner. The `approvedSigner` may be stored on-chain or off-chain by the owner in the CCIP2 contract. Upon each resolution, CCIP2 resolver verifies the signature against on-chain and/or off-chain `approvedSigner`, aka on-chain signer and/or off-chain signer approved by the owner.

## Resolver Function → JSON Mapping

| Type | Function | JSON File |
| --- | --- | --- |
| Text Records | `text(bytes32 node, string memory key)` | `text/<key>.json` |
| Ethereum Address | `addr(bytes32 node)` | `address/60.json` |
| Contenthash* | `contenthash(bytes32 node)` | `contenthash.json` |
| Multichain Address | `addr(bytes32 node, uint coinType)`| `address/<coinType>.json` |
| Public Key | `pubkey(bytes32 node)`| `pubkey.json` |
| Name** | `name(bytes32 node)`| `name.json` |
| Interface | `interfaceImplementer(bytes32 node, bytes4 _selector)`| `interface/0x<bytes4Selector>.json` |
| ABI | `ABI(bytes32 node, uint256 contentTypes)`| `abi/<contentTypes>.json` |
| Zonehash | `zonehash(bytes32 node)`| `dnsrecord/zonehash.json` |
| DNS Record | `dnsRecord(bytes32 node, bytes name, uint16 resource) `| `dnsrecord/<resource>.json` |

\* This is the user's web-facing contenthash contained inside the recordhash or masterhash

\*\* Name is not implemented as reverse record; users must use the official ENS on-chain reverse record for that feature.

## CCIP2.ETH Gateways

| Type | Identifier | Gateway URL |
| --- | --- | --- |
| `ipns://<contenthash>` | `0xe5` | `https://<base36-CID-v1>.ipns.dweb.link/.well-known/..` |
| `ipfs://<contenthash>` | `0xe3` | `https://<base32-CID-v1>.ipfs.dweb.link/.well-known/..` |
| ENS + IPNS Node | &nbsp; | `https://domain-eth.ipns.dweb.link/.well-known/..` |
| ENS | &nbsp; | `https://domain.eth.limo/.well-known/..` |
| ENS + IPFS2 resolver| `0xe3`, `0xe5` | `https://<CID-v1>.ipfs2.eth.limo/.well-known/..` |

## Details of Setup, Signatures and Keys

| Key | Type | Nature |
| --- | --- | --- |
| `K_EOA` | `secp256k1` | Ethereum Wallet Key |
| `K_IPNS` | `ed25519` | Deterministic Key(gen) |
| `K_SIGN` | `secp256k1` | Deterministic Key(gen) |
| `K_N` | `schnorr` | Deterministic Key(gen) |
