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

### a) CCIP-Read Resolver (EIP2544/EIP3688)

This specification is an extension of ENSIP-10 (EIP2544/EIP3688) using IPNS for off-chain records storage.

```solidity
function resolve(bytes calldata name, bytes calldata data) external view returns(bytes memory result)
```

where, the `_path` to query an ENS record and the full `_domain` as string shall be decoded from encoded `name` variable using `DNSDecode()` function:

```solidity
function DNSDecode(
    bytes calldata name
) public view returns (
    string memory _domain, string memory _path, string memory _label
){
    uint level = 1; // domain heirarchy level
    uint i = 1; // counter
    uint len uint8(bytes1(name[:1])); // length of label
    _label = string(name[1: i += len]); // final value is TLD ".eth"
    _path = _label; // suffix after /.well-known/
    _domain = _label; // full domain as string

    while(name[i] > 0x0) { // DNS Decode
        len = uint8(bytes1(name[i: ++i]));
        _label = string(name[i: i += len]);
        _domain = string.concat(_domain, ".", _label);
        _path = string.concat(_label, "/", _path);
        ++level;
    }
}
```

### b) Off-chain Records Storage Format

For this specification to make practical sense, we expect the `contenhash` to be of IPNS type, other storage pointers work out of box too. IPNS hashes are key-based decentralized storage pointers that only need to be added once to on-chain storage by the user. IPNS hashes can in turn serve as proxy and point to upgradeable IPFS or IPLD content. In the parent IPNS directory, the records must be stored in the [RFC-8615](https://www.rfc-editor.org/rfc/rfc8615) compliant `.well-known` directory format. ENS records for any name `sub.domain.eth` must then be stored in JSON format under a [reverse-DNS](https://en.wikipedia.org/wiki/Reverse_domain_name_notation) style directory path using `/` instead of `.` as separator, i.e. in format `ipfs://<hash>/.well-known/eth/domain/sub/<record>.json`.

**1. Some Examples:**

- ENS text record for `vitalik.eth`'s avatar is stored at `ipns://<ipns_hash>/.well-known/eth/vitalik/avatar.json` formatted as

```solidity
{ data: abi.encode(string("eip155:1/erc1155:0xb32979486938aa9694bfc898f35dbed459f44424/10063")) }
```

- ETH address record for `sub.domain.eth` is stored at `https://sub.domain.eth/.well-known/eth/domain/sub/addr-60.json` formatted as

```solidity
{ data: abi.encode(<addr-60>) }
```

Note: If the JSON data is signed by the Registrant of `domain.eth`, it must be prefixed with `bytes4` of `callback` function selector as,

```solidity
{ data: bytes.concat(Resolver.___callback.selector, <signed_data>}
```

**2. Resolver function → JSON file names:**

| Type | Function | JSON file |
| -- | -- | --- |
| Text Records ([ENSIP-05](https://docs.ens.domains/ens-improvement-proposals/ensip-5-text-records)) | `text(bytes32 node, string memory key)` | `<key>.json` |
| Ethereum Address | `addr(bytes32 node)` | `addr-60.json` |
| Multichain Address ([ENSIP-09](https://docs.ens.domains/ens-improvement-proposals/ensip-9-multichain-address-resolution)) | `addr(bytes32 node, uint coinType)`| `addr-<coinType>.json` |
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

	funMap[iResolver.addr.selector] = "addr-60"; // eth address
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
