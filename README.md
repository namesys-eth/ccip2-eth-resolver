# `CCIP2.ETH`

Off-chain ENS Records Resolver

# Contracts

## [Install Foundry](https://getfoundry.sh/)
`curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup`

## Install dependency
`forge install foundry-rs/forge-std --no-commit --no-git`

## Goerli Testnet
 `./test/goerli.sh`

## Specification

### a) CCIP2ETH Resolver Contract 

This specification is an extension of `ccip-read` ENSIP-10 (EIP2544/EIP3668) using IPNS, IPFS, IPLD and all ENS contenthash compatible data/storage pointers for off-chain ENS records storage.

```solidity
function resolve(bytes calldata name, bytes calldata data) external view returns(bytes memory result)
```

## b) Record Hash : 
RecordHash(RH) is `ContentHash` (CH) set by owner of domain.eth in CCIP2ETH resolver. it's fully compatible with all ENS contenthash types and also supports directly using string as bytes in base `16/32/36` format prefixed with `f/b/k` respectively.

eg, `bytes(string("fe5010172..."))` = `bytes(string("f0172..."))` = `bytes(hex"e5010172...")` = `bytes(string("ba...base32"))` = `bytes(string("k5...base36"))` = `bytes(hex"0172...")`. Owners and records managers are free to use their preferred storage type with recordhash formats.

- Supported Type/Codec

|Type|Format|Prefix|CH|f16|b32|k36|
|-|-|-|-|-|-|-|
|IPFS|dag-pb/raw|0xe30101\<70/55>..|✅|✅|✅|✅|
|IPNS|libp2p-key|0xe5010172..|✅|✅|✅|✅|
|IPLD|dag-cbor|0xe2010171..|✅|✅|✅|✅|
|Swarm|swarm-ns|0xe40101f..|✅|✅|🟡|🟡|
|Onion|-|0xbc03..|✅|✅|❌|❌|
|Onion3|-|0xbd03..|✅|✅|❌|❌|
|Skylink|-|0x90b2c6..|✅|✅|❌|❌|
|Arweave|-|0x90b2ca..|✅|✅|❌|❌|


~~|Base|Prefix|IPFS|IPNS|IPLD|Contenthash|
|-|-|-|-|-|-|
|16| |✅|✅|✅|✅|
|16|**f**|✅|✅|✅|✅|
|32|**b**|✅|✅|✅|❌|
|36|**k**|✅|✅|✅|❌|~~


## c) Gateway Manager Contract : 
 GM 

## d) Off-chain Records Storage Format
ENS records is stored in the [RFC-8615](https://www.rfc-editor.org/rfc/rfc8615) `.well-known` directory as [reverse-DNS](https://en.wikipedia.org/wiki/Reverse_domain_name_notation) style directory path using `/` as directory separator for subdomains. Prefix "_" is used for internal records directory.

e.g, ETH address record for `domain.eth` is stored in `.well-known/eth/domain/_address/60.json` & for `sub.domain.eth` it's stored in `.well-known/eth/domain/sub/_address/60.json`



 ENS records for any name `sub.domain.eth` must then be stored in JSON format under a [reverse-DNS](https://en.wikipedia.org/wiki/Reverse_domain_name_notation) style directory path using `/` instead of `.` as separator, i.e. in format `ipfs://<hash>/.well-known/eth/domain/sub/<record>.json`.

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
| Multichain Address ([ENSIP-09](https://docs.ens.domains/ens-improvement-proposals/ensip-9-multichain-address-resolution)) | `addr(bytes32 node, uint coinType)`| `_address/<coinType>.json` |
| Public Key | `pubkey(bytes32 node)`| `pubkey.json` |
| Contenthash ([ENSIP-07](https://docs.ens.domains/ens-improvement-proposals/ensip-7-contenthash-field)) | `contenthash(bytes32 node)` | `contenthash.json` |


### CCIP Gateways

| Type | Identifier | Gateway URL |
| --- | --- | --- |
| `ipns://<contenthash>` | `0xe5` | `https://<base36-CID-v1>.ipns.dweb.link/.well-known/..` |
| `ipfs://<contenthash>` | `0xe3` | `https://<base32-CID-v1>.ipfs.dweb.link/.well-known/..` |
| ENS + IPNS Node| &nbsp; | `https://domain-eth.ipns.dweb.link/.well-known/..` |
| ENS | &nbsp; | `https://domain.eth.limo/.well-known/..` |
| ENS + IPFS2 resolver| `0xe3`, `0xe5` | `https://<CID-v1>.ipfs2.eth.limo/.well-known/..` |

## Code

### --

```solidity
	//...

	funMap[iResolver.addr.selector] = "_address/60"; // eth address
	funMap[iResolver.pubkey.selector] = "pubkey";
	funMap[iResolver.name.selector] = "name";

	//...

	bytes4 fun = bytes4(data[: 4]); // 4 bytes identifier

	if (fun == iResolver.contenthash.selector) {
		if (level == 3) resolveContenthash(labels[0]);
		__lookup(HomeContenthash);
	}

	string memory jsonFile;
	if (fun == iResolver.text.selector) {
		jsonFile = abi.decode(data[36: ], (string));
	} else if (fun == iOverloadResolver.addr.selector) {
		jsonFile = string.concat(
			"addr-",
			uintToNumString(abi.decode(data[36: ], (uint)))
		);
	} else {
		jsonFile = funMap[fun];
		require(bytes(jsonFile).length != 0, "Invalid Resolver Function");
	}
```

### --

```solidity
	function resolve(bytes calldata name, bytes calldata data) external view returns(bytes memory) {
        uint level;
        uint len;
        bytes[] memory labels = new bytes[](3);
        //string memory _path;
        // dns decode
        for (uint i; name[i] > 0x0;) {
            len = uint8(bytes1(name[i: ++i]));
            labels[level] = name[i: i += len];
            //_path = string.concat(string(labels[level]), "/", _path);
            ++level;
        }
        bytes4 fun = bytes4(data[: 4]); // 4 bytes identifier
        if (fun == iResolver.contenthash.selector) {
            if (level == 3)
                resolveContenthash(labels[0]);

            __lookup(HomeContenthash);
        }
        string memory jsonFile;
        if (fun == iResolver.text.selector) {
            jsonFile = abi.decode(data[36: ], (string));
        } else if (fun == iOverloadResolver.addr.selector) {
            jsonFile = string.concat(
                "addr-",
                uintToNumString(abi.decode(data[36: ], (uint)))
            );
        } else {
            jsonFile = funMap[fun];
            require(bytes(jsonFile).length != 0, "Invalid Resolver Function");
        }

        string memory _prefix;
        if (level == 3) {
            _prefix = string.concat(
                "https://",
                string(labels[0]),
                ".",
                string(labels[1]),
                ".eth"
            );
        } else {
            _prefix = string.concat("https://", string(labels[0]), ".eth");
        }
        revert OffchainLookup(
            address(this), // callback contract
            listGate(_prefix, jsonFile), // gateway URL array
            "", // {data} field, blank//recheck
            IPFS2.__callback.selector, // callback function
            abi.encode( // extradata
                block.number, // checkpoint
                keccak256(data), // namehash + calldata
                keccak256(
                    abi.encodePacked(
                        blockhash(block.number - 1),
                        address(this),
                        msg.sender,
                        keccak256(data)
                    )
                )
            )
        );
    }

```