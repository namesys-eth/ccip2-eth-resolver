// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

interface iCCIP {
    function resolve(
        bytes memory name,
        bytes memory data
    ) external view returns (bytes memory);
}

interface iOverloadResolver {
    function addr(
        bytes32 node,
        uint coinType
    ) external view returns (bytes memory);
}

interface iResolver {
    function contenthash(bytes32 node) external view returns (bytes memory);

    function addr(bytes32 node) external view returns (address payable);

    function pubkey(bytes32 node) external view returns (bytes32 x, bytes32 y);

    function text(
        bytes32 node,
        string calldata key
    ) external view returns (string memory);

    function name(bytes32 node) external view returns (string memory);

    function ABI(
        bytes32 node,
        uint256 contentTypes
    ) external view returns (uint256, bytes memory);

    function interfaceImplementer(
        bytes32 node,
        bytes4 interfaceID
    ) external view returns (address);

    function zonehash(bytes32 node) external view returns (bytes memory);
    //function dnsRecord(bytes32 node, bytes32 name, uint16 resource) external view returns (bytes memory);
    //function recordVersions(bytes32 node) external view returns (uint64);
}

interface iENS {
    function owner(bytes32 node) external view returns (address);

    function resolver(bytes32 node) external view returns (address);

    function ttl(bytes32 node) external view returns (uint64);

    function recordExists(bytes32 node) external view returns (bool);

    function isApprovedForAll(
        address owner,
        address operator
    ) external view returns (bool);

    function setResolver(bytes32 node, address resolver) external;
}

interface iERC165 {
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

interface iToken {
    function transferFrom(address from, address to, uint bal) external;

    function safeTransferFrom(address from, address to, uint bal) external;
}

/**
 * @title : CCIP2 : Off-chain ENS Records Manager
 * @author : 0xc0de4c0ffee.eth, sshmatrix.eth
 */
contract CCIP2ETH is iCCIP {
    address payable immutable THIS = payable(address(this));

    /// @dev contract owner/multisig address
    address payable public Owner;

    iENS public ENS;

    /// @dev root .eth namehash
    bytes32 public immutable roothash =
        keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

    /// @dev default contenthash for *.CCIP2.eth
    // 0 "bafzaajaiaejcapc2xjwjwucvux5beka4jbqyr3mk4k3o6oklhwmbwagrpjfvc424"
    bytes public DefaultContenthash =
        hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";

    /// @dev parent contenthash for CCIP2.eth
    /// @notice : ?unused variable
    // 1 "bafzaajaiaejcay3x7z7ftabmy4larbxphcgs5wt2djx32savmfjzoxsehlunabby"
    bytes public ParentContenthash =
        hex"e50101720024080112206377fe7e59802cc7160886ef388d2eda7a1a6fbd48156153975e443ae8d00438";

    /// @dev namehash of 'ccip2.eth'
    bytes32 public immutable namehash =
        keccak256(
            abi.encodePacked(
                keccak256(abi.encodePacked(bytes32(0), keccak256("eth"))),
                keccak256("ccip2")
            )
        );

    /// @dev CCIP Off-chain Lookup (https://eips.ethereum.org/EIPS/eip-3668)
    error OffchainLookup(
        address _from, // sender (this contract)
        string[] _gateways, // CCIP gateway URLs
        bytes _data, // {data} field; request value for HTTP call
        bytes4 _callbackFunction, // callback function
        bytes _extraData // callback extra data
    );
    error InvalidSignature(string _error);

    /// @dev Resolver function bytes4 selector → Off-chain record filename <name>.json
    mapping(bytes4 => string) public funcToFile;
    /// Other Mappings
    mapping(bytes32 => bytes) public contenthash; // contenthash; use IPNS for gasless dynamic record updates, or IPFS for static hosting
    mapping(bytes32 => bytes) public signedContenthash; // contenthash; signed by Owner (= approved in ENS)
    mapping(bytes32 => address) public approved;
    mapping(bytes32 => address) public isApprovedForAll;

    constructor() {
        funcToFile[iResolver.addr.selector] = "addr-60"; // Ethereum address
        funcToFile[iResolver.pubkey.selector] = "pubkey"; // Public key
        funcToFile[iResolver.name.selector] = "name"; // Reverse Record
        funcToFile[iResolver.zonehash.selector] = "zonehash"; // Zonehash
        Owner = payable(msg.sender);
    }

    /// @dev revert on fallback
    fallback() external payable {
        revert();
    }

    /// @dev revert on receive
    receive() external payable {
        revert();
    }

    /// @notice : ONLY TESTNET
    function immolate() external {
        require(msg.sender == Owner, "NOT_OWNER");
        selfdestruct(Owner);
    }

    /**
     * @dev withdraw Ether to Owner
     */
    function withdraw() external {
        Owner.transfer(THIS.balance);
    }

    /**
     * @dev to be used in case some fungible tokens get locked in the contract
     * @param _token : token address
     * @param _balance : amount to release
     */
    function withdraw(address _token, uint256 _balance) external {
        iToken(_token).transferFrom(THIS, Owner, _balance);
    }

    /**
     * @dev to be used in case some non-fungible tokens get locked in the contract
     * @param _token : token address
     * @param _tokenID : tokenID to release
     */
    function safeWithdraw(address _token, uint256 _tokenID) external {
        iToken(_token).safeTransferFrom(THIS, Owner, _tokenID);
    }

    /**
     * @dev checks if a signature is valid
     * @param digest : hash of signed message
     * @param signature : compact signature to verify
     */
    function isValid(
        bytes32 digest,
        bytes calldata signature
    ) external view returns (bool) {
        // First 32 bytes of signature
        bytes32 r = bytes32(signature[:32]);
        // Next 32 bytes of signature
        bytes32 s;
        // Last 1 byte
        uint8 v;
        if (signature.length > 64) {
            s = bytes32(signature[32:64]);
            v = uint8(uint256(bytes32(signature[64:])));
        } else if (signature.length == 64) {
            bytes32 vs = bytes32(signature[32:]);
            s =
                vs &
                bytes32(
                    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                );
            v = uint8((uint256(vs) >> 255) + 27);
        } else {
            revert InvalidSignature("BAD_SIG_LENGTH");
        }
        /// Check for bad signature
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) revert InvalidSignature("SIG_OVERFLOW");
        /// recover signer
        address _signer = ecrecover(digest, v, r, s);
        // @TODO : add check for _signer == owner
        return (_signer != address(0));
    }

    /**
     * @dev Interface Selector
     * @param interfaceID : interface identifier
     */
    function supportsInterface(
        bytes4 interfaceID
    ) external pure returns (bool) {
        return (interfaceID == iCCIP.resolve.selector ||
            interfaceID == iERC165.supportsInterface.selector);
    }

    /**
     * @dev contenthash callback
     * @param response : response of HTTP call
     * @param extraData : extra data for callback
     */
    function ___contenthash(
        bytes calldata response,
        bytes calldata extraData
    ) external view returns (bytes memory result) {
        bytes memory signature;
        if (bytes4(response[:4]) == CCIP2ETH.___contenthash.selector) {
            /// @dev ethers.js/CCIP reverts if the <result> is not ABI-encoded
            (result, signature) = abi.decode(response[4:], (bytes, bytes));
            /// @notice : check signature format; ?no validity
            if (
                !CCIP2ETH(THIS).isValid(
                    keccak256(
                        abi.encodePacked(hex"1900", THIS, namehash, result)
                    ),
                    signature
                )
            ) revert InvalidSignature("BAD_SIGNATURE");
        } else {
            result = response;
        }
        /// @dev timeout check
        (uint _blocknumber, bytes32 _contenthashCheck) = abi.decode(
            extraData,
            (uint, bytes32)
        );
        // timeout in 1 block
        require(
            block.number <= _blocknumber + 1 &&
                _contenthashCheck ==
                keccak256(
                    abi.encodePacked(
                        blockhash(--_blocknumber),
                        THIS,
                        msg.sender,
                        result
                    )
                ),
            "INVALID_CHECKSUM"
        );
    }

    /**
     * @dev Off-chain Lookup
     * @param _contenthash : required by callback extra data
     */
    function __lookup(bytes memory _contenthash) public view {
        string[] memory _urls = new string[](2);
        _urls[0] = 'data:text/plain,{"data":"{data}"}';
        _urls[1] = 'data:application/json,{"data":"{data}"}';
        revert OffchainLookup(
            THIS, // callback contract
            _urls, // CCIP gateway URLs
            _contenthash, // {data} field
            CCIP2ETH.___contenthash.selector, // callback function
            abi.encode( // callback extra data
                block.number, // check-point
                keccak256(
                    abi.encodePacked(
                        blockhash(block.number - 1),
                        THIS,
                        msg.sender,
                        _contenthash
                    )
                )
            )
        );
    }

    /**
     * @dev sets contenthash
     * @param node : token address
     * @param _contenthash : tokenID to release
     */
    function setContenthash(bytes32 node, bytes calldata _contenthash) public {
        address owner = ENS.owner(node);
        /// @notice : ?check namewrapper
        require(
            msg.sender == owner || ENS.isApprovedForAll(owner, msg.sender),
            "ONLY_OWNER"
        );
        contenthash[node] = _contenthash;
        delete signedContenthash[node];
    }

    /**
     * @dev sets contenthash for a subdomain
     * @param node : namehash of ENS domain
     * @param _labels : subdomain labels; MUST be ordered
     * @param _contenthash : contenthash value to set
     */
    function setSubContenthash(
        bytes32 node,
        string[] calldata _labels,
        bytes calldata _contenthash
    ) public {
        address owner = ENS.owner(node);
        /// @notice : ?check namewrapper
        require(
            msg.sender == owner || ENS.isApprovedForAll(owner, msg.sender),
            "ONLY_OWNER"
        );
        bytes32 _namehash = node;
        uint len = _labels.length;
        while (len > 0) {
            _namehash = keccak256(
                abi.encodePacked(_namehash, keccak256(bytes(_labels[--len])))
            );
        }
        contenthash[_namehash] = _contenthash;
        delete signedContenthash[_namehash];
    }

    /**
     * @dev sets contenthash signed by the owner
     * @param node : token address
     * @param _contenthash : tokenID to release
     * @param signature : signature of owner
     */
    function setSignedContenthash(
        bytes32 node,
        bytes calldata _contenthash,
        bytes calldata signature
    ) public {
        address owner = ENS.owner(node);
        // ?check namewrapper
        require(
            msg.sender == owner || ENS.isApprovedForAll(owner, msg.sender),
            "NOT_OWNER"
        );
        contenthash[node] = _contenthash;
        // @TODO: checking signature will add extra gas here
        // OR : depend on CCIP callback's revert for bad signature?
        // COMMENT: seems risky to keep bad signatures on-chain
        signedContenthash[node] = signature;
    }

    /**
     * @dev sets contenthash signed by the owner for a subdomain
     * @param node : namehash of ENS domain
     * @param _labels : subdomain labels; MUST be ordered
     * @param _contenthash : contenthash value to set
     * @param signature : signature of owner
     */
    function setSignedSubContenthash(
        bytes32 node,
        string[] calldata _labels,
        bytes calldata _contenthash,
        bytes calldata signature
    ) public {
        address owner = ENS.owner(node);
        require(
            msg.sender == owner || ENS.isApprovedForAll(owner, msg.sender),
            "NOT_OWNER_OR_MANAGER"
        );
        bytes32 _namehash = node;
        uint len = _labels.length;
        while (len > 0) {
            _namehash = keccak256(
                abi.encodePacked(_namehash, keccak256(bytes(_labels[--len])))
            );
        }
        contenthash[_namehash] = _contenthash;
        signedContenthash[_namehash] = signature;
    }

    /**
     * @dev core Resolve function
     * @param name : ENS name to resolve
     * @param data : data encoding specific resolver function
     */
    function resolve(
        bytes calldata name,
        bytes calldata data
    ) external view returns (bytes memory) {
        unchecked {
            uint index; // domain level index
            uint i = 1; // counter
            uint len = uint8(bytes1(name[:1])); // length of label
            bytes[] memory _labels = new bytes[](42); // maximum 42 allowed levels in sub.sub...domain.eth
            _labels[index++] = name[1:i += len];

            string memory _path = string(_labels[0]); // suffix after '/.well-known/'
            string memory _domain = _path; // full domain as string

            /// @dev DNSDecode()
            while (name[i] > 0x0) {
                len = uint8(bytes1(name[i:++i]));
                _labels[index] = name[i:i += len];
                _domain = string.concat(_domain, ".", string(_labels[index]));
                _path = string.concat(string(_labels[index]), "/", _path);
                ++index;
            }

            // check if the name contains .eth as root
            bool isRootETH = (keccak256(
                abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))
            ) == roothash);
            // 4-byte identifier of requested Resolver function
            bytes4 func = bytes4(data[:4]);

            if (isRootETH && func == iResolver.contenthash.selector) {
                // handle contenthash first
                bytes32 _namehash;
                bytes32 __namehash = keccak256(
                    abi.encodePacked(
                        bytes32(0),
                        keccak256(bytes(_labels[--index]))
                    )
                ); // MUST be equal to roothash of '.eth'
                bytes memory _data; // contenthash
                while (index > 0) {
                    __namehash = keccak256(
                        abi.encodePacked(
                            __namehash,
                            keccak256(bytes(_labels[--index]))
                        )
                    );
                    if (contenthash[__namehash].length != 0) {
                        _data = abi.encode(contenthash[__namehash]);
                        _namehash = __namehash;
                    }
                }
                // should never revert with ENSIP-10 compatible apps/wallets
                // require(_namehash == bytes32(data[4:36]), "BAD_NAMEHASH");

                if (_data.length == 0) {
                    _data = isRootETH
                        ? abi.encode(DefaultContenthash)
                        : abi.encodePacked(uint32(block.timestamp / 60) * 60);
                } else if (signedContenthash[_namehash].length > 0) {
                    // check owner's signature
                    _data = bytes.concat(
                        CCIP2ETH.___contenthash.selector,
                        abi.encode(_data, signedContenthash[_namehash])
                    );
                }

                string[] memory _urls = new string[](2);
                if (isRootETH) {
                    _urls[0] = 'data:text/plain,{"data":"{data}"}';
                    _urls[1] = 'data:application/json,{"data":"{data}"}';
                } else {
                    revert("NOT_ETH_ROOT");
                }
                revert OffchainLookup(
                    THIS, // callback contract
                    _urls, // CCIP gateway URLs
                    _data, // {data} field
                    CCIP2ETH.___contenthash.selector, // callback function
                    abi.encode( // callback extra data
                        block.number, // check-point
                        keccak256(
                            abi.encodePacked(
                                THIS,
                                blockhash(block.number - 1),
                                msg.sender,
                                _data
                            )
                        )
                    )
                );
            }

            string memory _pathJSON;

            if (func == iResolver.text.selector) {
                _pathJSON = abi.decode(data[36:], (string));
            } else if (func == iOverloadResolver.addr.selector) {
                _pathJSON = string.concat(
                    "addr-",
                    uintToNumString(abi.decode(data[36:], (uint)))
                );
            } else {
                _pathJSON = funcToFile[func];
                require(
                    bytes(_pathJSON).length != 0,
                    "RESOLVER_FUNC_NOT_IMPLEMENTED"
                );
            }

            string[] memory _gateways = new string[](3);
            // @TODO : change gateway storage from lists to updatable array; ?randomize weight
            _gateways[0] = string.concat(
                _domain,
                ".limo/.well-known/",
                _pathJSON,
                ".json?t={data}"
            );
            _gateways[1] = string.concat(
                _domain,
                ".casa/.well-known/",
                _pathJSON,
                ".json?t={data}"
            );
            _gateways[2] = string.concat(
                _domain,
                ".link/.well-known/",
                _pathJSON,
                ".json?t={data}"
            );
            revert OffchainLookup(
                THIS, // callback contract
                _gateways, // CCIP gateway URLs
                abi.encodePacked(uint32(block.timestamp / 60) * 60), // {data} = 0xtimestamp, not cached beyond 60 seconds
                CCIP2ETH.__callback.selector, // callback function
                abi.encode( // callback extra data
                    block.number, // check-point
                    keccak256(data), // namehash + calldata
                    keccak256(
                        abi.encodePacked(
                            THIS,
                            blockhash(block.number - 1),
                            msg.sender,
                            keccak256(data)
                        )
                    )
                )
            );
        }
    }

    /**
     * @dev callback function
     * @param response : response of HTTP call
     * @param extraData: extra data required by callback
     */
    function __callback(
        bytes calldata response,
        bytes calldata extraData
    ) external view returns (bytes memory) {
        (
            uint _blocknumber,
            bytes32 _domainhash,
            bytes32 _contenthashCheck
        ) = abi.decode(extraData, (uint, bytes32, bytes32));
        // timeout in 3 blocks
        // 3 * 13 ~ 39 seconds
        // check timeout > ipfs gateway timeout
        require(
            block.number <= _blocknumber + 3 &&
                _contenthashCheck ==
                keccak256(
                    abi.encodePacked(
                        blockhash(--_blocknumber),
                        THIS,
                        msg.sender,
                        _domainhash
                    )
                ),
            "INVALID_CHECKSUM"
        );
        /// JSON data MUST be ABI-encoded
        return response;
    }

    /**
     * @dev format/convert interger to string
     * @param value : value to format/convert
     */
    function uintToNumString(uint value) public pure returns (string memory) {
        if (value == 0) return "0";
        uint temp = value;
        uint digits;
        unchecked {
            while (temp != 0) {
                ++digits;
                temp /= 10;
            }
            bytes memory buffer = new bytes(digits);
            while (value != 0) {
                buffer[--digits] = bytes1(uint8(48 + (value % 10)));
                value /= 10;
            }
            return string(buffer);
        }
    }
}
