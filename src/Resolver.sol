// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";
/**
 * @title : ccip2.eth : Off-chain ENS Records Manager
 * @author : freetib.eth, sshmatrix.eth
 */

contract Resolver is iCCIP {
    address payable immutable THIS = payable(address(this));

    /// @dev contract owner/multisig address
    address payable public owner;

    /// @dev : ENS contract
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    /// @dev : ENS Namewrapper
    iToken public immutable WRAPPER = iToken(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);

    /// @dev root .eth namehash
    bytes32 public immutable roothash = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

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
        keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes32(0), keccak256("eth"))), keccak256("ccip2")));

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
    mapping(bytes32 => bool) public manager; // ??

    function approved(bytes32 node, address _addr) public view returns (bool) {
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        return manager[keccak256(abi.encodePacked(node, _owner, _addr))];
    }

    constructor() {
        funcToFile[iResolver.addr.selector] = "addr-60"; // Ethereum address
        funcToFile[iResolver.pubkey.selector] = "pubkey"; // Public key
        funcToFile[iResolver.name.selector] = "name"; // Name ? Reverse
        funcToFile[iResolver.name.selector] = "name"; // Reverse Record
        funcToFile[iResolver.zonehash.selector] = "zonehash"; // Zonehash
        owner = payable(msg.sender);
    }

    /**
     * @dev checks if a signature is valid
     * @param digest : hash of signed message
     * @param signature : signature to verify
     * signature is 64 bytes bytes32(R)+bytes32(VS) compact
     * or 65 bytes bytes32(R)+bytes32(S)+bytes1(V) long
     */
    function isValid(bytes32 digest, bytes calldata signature) external pure returns (address _signer) {
        // First 32 bytes of signature
        bytes32 r = bytes32(signature[:32]);
        // Next 32 bytes of signature
        bytes32 s;
        // Last 1 byte
        uint8 v;
        if (signature.length == 65) {
            s = bytes32(signature[32:64]);
            v = uint8(uint256(bytes32(signature[64:])));
        } else if (signature.length == 64) {
            bytes32 vs = bytes32(signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else {
            revert InvalidSignature("BAD_SIG_LENGTH");
        }
        // Check for bad S value in signature
        // > OR >= ?
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature("SIG_OVERFLOW");
        }
        /// recover signer
        _signer = ecrecover(digest, v, r, s);
        // @TODO : add check for _signer == owner
        if (_signer == address(0)) {
            revert InvalidSignature("BAD_SIGNATURE");
        }
    }

    /**
     * @dev Interface Selector
     * @param interfaceID : interface identifier
     */
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (interfaceID == iCCIP.resolve.selector || interfaceID == iERC165.supportsInterface.selector);
    }

    /**
     * @dev contenthash callback
     * @param response : response of HTTP call
     * @param extraData : extra data for callback
     */
    function ___contenthash(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory result)
    {
        bytes memory signature;
        if (bytes4(response[:4]) == Resolver.___contenthash.selector) {
            /// @dev ethers.js/CCIP reverts if the <result> is not ABI-encoded
            (result, signature) = abi.decode(response[4:], (bytes, bytes));
            /// @notice : check signature format; ?no validity
            address _signer =
                Resolver(THIS).isValid(keccak256(abi.encodePacked(hex"1900", THIS, namehash, result)), signature);
            {
                revert InvalidSignature("BAD_SIGNATURE");
            }
        } else {
            result = response;
        }
        /// @dev timeout check
        (uint256 _blocknumber, bytes32 _contenthashCheck) = abi.decode(extraData, (uint256, bytes32));
        // timeout in 1 block
        require(
            block.number <= _blocknumber + 1
                && _contenthashCheck == keccak256(abi.encodePacked(blockhash(--_blocknumber), THIS, msg.sender, result)),
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
            Resolver.___contenthash.selector, // callback function
            abi.encode( // callback extra data
                block.number, // check-point
                keccak256(abi.encodePacked(blockhash(block.number - 1), THIS, msg.sender, _contenthash))
            )
        );
    }

    /**
     * @dev sets contenthash
     * @param node : token address
     * @param _contenthash : tokenID to release
     */
    function setContenthash(bytes32 node, bytes calldata _contenthash) public {
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        require(msg.sender == _owner || ENS.isApprovedForAll(owner, msg.sender), "ONLY_OWNER");
        contenthash[node] = _contenthash;
    }

    /**
     * @dev core Resolve function
     * @param name : ENS name to resolve
     * @param data : data encoding specific resolver function
     */
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory) {
        unchecked {
            uint256 index; // domain level index
            uint256 i = 1; // counter
            uint256 len = uint8(bytes1(name[:1])); // length of label
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
            bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == roothash);
            // 4-byte identifier of requested Resolver function
            bytes4 func = bytes4(data[:4]);

            if (dotETH && func == iResolver.contenthash.selector) {
                // handle contenthash first
                bytes32 _namehash;
                bytes32 __namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(_labels[--index])))); // MUST be equal to roothash of '.eth'
                bytes memory _data; // contenthash
                while (index > 0) {
                    __namehash = keccak256(abi.encodePacked(__namehash, keccak256(bytes(_labels[--index]))));
                    if (contenthash[__namehash].length != 0) {
                        _data = abi.encode(contenthash[__namehash]);
                        _namehash = __namehash;
                    }
                }
                // should never revert with ENSIP-10 compatible apps/wallets
                // require(_namehash == bytes32(data[4:36]), "BAD_NAMEHASH");

                if (_data.length == 0) {
                    _data =
                        dotETH ? abi.encode(DefaultContenthash) : abi.encodePacked(uint32(block.timestamp / 60) * 60);
                }

                //else if (signedContenthash[_namehash].length > 0) {
                // handled in callback
                // check owner's signature
                //    _data =
                //        bytes.concat(Resolver.___contenthash.selector, abi.encode(_data, signedContenthash[_namehash]));
                //}

                string[] memory _urls = new string[](2);
                if (dotETH) {
                    _urls[0] = 'data:text/plain,{"data":"{data}"}';
                    _urls[1] = 'data:application/json,{"data":"{data}"}';
                } else {
                    revert("NOT_ETH_ROOT");
                }
                revert OffchainLookup(
                    THIS, // callback contract
                    _urls, // CCIP gateway URLs
                    _data, // {data} field
                    Resolver.___contenthash.selector, // callback function
                    abi.encode( // callback extra data
                        block.number, // check-point
                        keccak256(abi.encodePacked(THIS, blockhash(block.number - 1), msg.sender, _data))
                    )
                );
            }

            string memory _pathJSON;

            if (func == iResolver.text.selector) {
                _pathJSON = abi.decode(data[36:], (string));
            } else if (func == iOverloadResolver.addr.selector) {
                _pathJSON = string.concat("addr-", uintToNumString(abi.decode(data[36:], (uint256))));
            } else if (func == iResolver.ABI.selector) {
                _pathJSON = string.concat("abi-", uintToNumString(abi.decode(data[36:], (uint256))));
            } else if (func == iResolver.interfaceImplementer.selector) {
                _pathJSON = string.concat("addr-", uintToNumString(abi.decode(data[36:], (uint256))));
            } else {
                _pathJSON = funcToFile[func];
                require(bytes(_pathJSON).length != 0, "RESOLVER_FUNC_NOT_IMPLEMENTED");
            }

            string[] memory _gateways = new string[](3);
            // @TODO : change gateway storage from lists to updatable array; ?randomize weight
            _gateways[0] = string.concat(_domain, ".limo/.well-known/", _pathJSON, ".json?t={data}");
            _gateways[1] = string.concat(_domain, ".casa/.well-known/", _pathJSON, ".json?t={data}");
            _gateways[2] = string.concat(_domain, ".link/.well-known/", _pathJSON, ".json?t={data}");
            revert OffchainLookup(
                THIS, // callback contract
                _gateways, // CCIP gateway URLs
                abi.encodePacked(uint32(block.timestamp / 60) * 60), // {data} = 0xtimestamp, not cached beyond 60 seconds
                Resolver.__callback.selector, // callback function
                abi.encode( // callback extra data
                    block.number, // check-point
                    keccak256(data), // namehash + calldata
                    keccak256(abi.encodePacked(THIS, blockhash(block.number - 1), msg.sender, keccak256(data)))
                )
            );
        }
    }

    /**
     * @dev callback function
     * @param response : response of HTTP call
     * @param extraData: extra data required by callback
     */
    function __callback(bytes calldata response, bytes calldata extraData) external view returns (bytes memory) {
        (uint256 _blocknumber, bytes32 _domainhash, bytes32 _contenthashCheck) =
            abi.decode(extraData, (uint256, bytes32, bytes32));
        // timeout in 3 blocks
        // 3 * 13 ~ 39 seconds
        // check timeout > ipfs gateway timeout
        require(
            block.number <= _blocknumber + 3
                && _contenthashCheck
                    == keccak256(abi.encodePacked(blockhash(--_blocknumber), THIS, msg.sender, _domainhash)),
            "INVALID_CHECKSUM"
        );
        /// JSON data MUST be ABI-encoded
        return response;
    }

    /**
     * @dev format/convert interger to string
     * @param value : value to format/convert
     */
    function uintToNumString(uint256 value) public pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
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

    /// @dev : Resolver Management functions

    /// @notice : ONLY TESTNET
    /// TODO : Remove before mainnet deployment
    function immolate() external {
        require(msg.sender == owner, "NOT_OWNER");
        selfdestruct(owner);
    }

    /**
     * @dev withdraw Ether to owner
     */
    function withdraw() external {
        owner.transfer(THIS.balance);
    }

    /**
     * @dev to be used in case some fungible tokens get locked in the contract
     * @param _token : token address
     * @param _balance : amount to release
     */
    function withdraw(address _token, uint256 _balance) external {
        iToken(_token).transferFrom(THIS, owner, _balance);
    }

    /**
     * @dev to be used in case some non-fungible tokens get locked in the contract
     * @param _token : token address
     * @param _tokenID : tokenID to release
     */
    function safeWithdraw(address _token, uint256 _tokenID) external {
        iToken(_token).safeTransferFrom(THIS, owner, _tokenID);
    }
}
