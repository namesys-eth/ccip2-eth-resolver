// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";
import "./Gateway.sol";
/**
 * @title : ENS Off-chain Records Manager
 * @author : freetib.eth, sshmatrix.eth
 */

contract Resolver is iCCIP, Gateway {
    /// @notice : ONLY TESTNET
    /// TODO : Remove before mainnet deployment
    function immolate() external {
        require(msg.sender == owner, "NOT_OWNER");
        selfdestruct(owner);
    }

    /// @dev : ENS contract
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    /// @dev : ENS Namewrapper
    //iToken public WRAPPER = iToken(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);

    /// @dev constructor initial setup
    constructor() {
        funcToFile[iResolver.addr.selector] = "_address/60";
        funcToFile[iResolver.pubkey.selector] = "pubkey";
        funcToFile[iResolver.name.selector] = "name";
        funcToFile[iResolver.contenthash.selector] = "contenthash";
        funcToFile[iResolver.zonehash.selector] = "_dns/zonehash";
        owner = payable(msg.sender);
        Gateways.push("dweb.link");
        emit AddGateway("dweb.link");
        Gateways.push("ipfs.io");
        emit AddGateway("ipfs.io");
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdateWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);
    }

    event UpdateWrapper(address indexed _new, bool indexed _ok);
    /// @dev : dev only ??manage future upgrades in ENS wrapper??

    function updateWrapper(address _addr, bool _set) external onlyDev {
        require(_addr.code.length > 0, "Only Contract");
        isWrapper[_addr] = _set;
        emit UpdateWrapper(_addr, _set);
    }

    function updateWrappers(address[] calldata _addrs, bool[] calldata _sets) external onlyDev {
        uint256 len = _addrs.length;
        require(len == _sets.length, "Bad_Length");
        for (uint256 i = 0; i < len; i++) {
            require(_addrs[i].code.length > 0, "Only Contract");
            isWrapper[_addrs[i]] = _sets[i];
            emit UpdateWrapper(_addrs[i], _sets[i]);
        }
    }

    /// @dev ENSIP10 : CCIP-read Off-chain Lookup method (https://eips.ethereum.org/EIPS/eip-3668)
    error OffchainLookup(
        address _addr, // callback contract)
        string[] _gateways, // CCIP gateway URLs
        bytes _data, // {data} field; request value for HTTP call
        bytes4 _callbackFunction, // callback function
        bytes _extradata // callback extra data
    );

    error InvalidSignature(string _error);

    /// @dev Resolver function bytes4 selector → Off-chain record filename <name>.json
    mapping(bytes4 => string) public funcToFile;
    /// Other Mappings
    mapping(bytes32 => bytes) public contenthash; // contenthash; use IPNS for gasless dynamic record updates, or IPFS for static hosting
    mapping(bytes32 => bool) public manager; // ?? there are multiple approved/isApprovedForAll in all ENS
    mapping(address => bool) public isWrapper;
    // better add as approved/ is approved for all functions?

    function approved(bytes32 _node, address _signer) public view returns (bool) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        return manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))];
    }

    function approve(bytes32 _node, address _signer, bool _approved) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        require(
            _owner == msg.sender || manager[keccak256(abi.encodePacked("manage-all", _owner, msg.sender))],
            "ONLY_OWNER/FULL_MANAGER"
        );
        manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))] = _approved;
        // event ?
    }

    /**
     * @dev get signer from signature & digest
     * @param digest : hash of signed message
     * @param signature : signature to verify
     * signature is 64 bytes bytes32(R)+bytes32(VS) compact
     * or 65 bytes bytes32(R)+bytes32(S)+bytes1(V) long
     * TODO: signed by contract? or leave it for offchain only?
     */
    function signedBy(bytes32 digest, bytes calldata signature) external pure returns (address _addr) {
        bytes32 r = bytes32(signature[:32]);
        bytes32 s;
        uint8 v;
        if (signature.length == 64) {
            bytes32 vs = bytes32(signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else if (signature.length == 65) {
            s = bytes32(signature[32:64]);
            v = uint8(bytes1(signature[64:]));
        } else {
            revert InvalidSignature("BAD_LENGTH");
        }
        if (s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature("INVALID_S_VALUE");
        }
        _addr = ecrecover(digest, v, r, s);
        if (_addr == address(0)) {
            revert InvalidSignature("ZERO_ADDRESS");
        }
    }

    /**
     * @dev Interface Selector
     * @param interfaceID : interface identifier
     */
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (
            interfaceID == iCCIP.resolve.selector || interfaceID == iResolver.setContenthash.selector
                || interfaceID == iCCIP.__callback.selector || interfaceID == iERC165.supportsInterface.selector
        );
    }

    modifier isAuthorized(bytes32 _node) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        require(
            msg.sender == _owner || manager[keccak256(abi.encodePacked("manage-one", _node, _owner, msg.sender))]
                || manager[keccak256(abi.encodePacked("manage-all", _owner, msg.sender))],
            "ONLY_OWNER/MANAGER"
        );
        _;
    }
    /**
     * @dev sets contenthash
     * @param _node : ens mode
     * @param _contenthash : contenthash to set
     */

    function setContenthash(bytes32 _node, bytes calldata _contenthash) external isAuthorized(_node) {
        require(bytes4(_contenthash[:4]) == hex"e5010172" || bytes3(_contenthash[:3]) == hex"e30101", "IPFS/IPNS_ONLY");
        contenthash[_node] = _contenthash;
        // event
    }

    error ContenthashNotSet(bytes32 _node);
    /**
     * @dev core Resolve function
     * @param name : ENS name to resolve, DNS encoded
     * @param data : data encoding specific resolver function
     * @return result : data encoding specific resolver function
     */

    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory) {
        unchecked {
            uint256 index = 1; // domain level index
            uint256 n = 1; // counter
            uint256 len = uint8(bytes1(name[:1])); // length of label
            bytes[] memory _labels = new bytes[](42); // maximum *in theory* 42 levels of sub.sub...domain.eth
            _labels[0] = name[1:n += len];
            string memory _path = string(_labels[0]); // suffix after '/.well-known/'
            string memory _domain = _path; // full domain as string
            /// @dev DNSDecode()
            while (name[n] > 0x0) {
                len = uint8(bytes1(name[n:++n]));
                _labels[index] = name[n:n += len];
                _domain = string.concat(_domain, ".", string(_labels[index]));
                _path = string.concat(string(_labels[index]), "/", _path);
                ++index;
            }
            /// @dev : supports all domain.tlds in ENS
            // bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == roothash)

            bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(_labels[--index]))));
            bytes32 _node = keccak256(abi.encodePacked(_namehash, keccak256(bytes(_labels[--index]))));
            bytes memory _ipns = contenthash[_node]; // contenthash
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(bytes(_labels[--index]))));
                if (contenthash[_namehash].length > 0 || ENS.resolver(_namehash) == THIS) {
                    // recheck logic
                    _ipns = contenthash[_namehash];
                    _node = _namehash;
                }
            }

            /// @dev : sanity check ENSIP10 client
            // require(_namehash == bytes32(data[4:36]), "BAD_NAMEHASH");

            bytes4 func = bytes4(data[:4]);
            string memory _jsonPath;
            if (bytes(funcToFile[func]).length > 0) {
                _jsonPath = funcToFile[func];
            } else if (func == iResolver.text.selector) {
                _jsonPath = abi.decode(data[36:], (string));
            } else if (func == iOverloadResolver.addr.selector) {
                _jsonPath = string.concat("_address/", uintToString(abi.decode(data[36:], (uint256))));
            } else if (func == iResolver.interfaceImplementer.selector) {
                _jsonPath =
                    string.concat("_interface/0x", bytesToString(abi.encodePacked(abi.decode(data[36:], (bytes4))), 0));
            } else if (func == iResolver.ABI.selector) {
                _jsonPath = string.concat("_abi/", uintToString(abi.decode(data[36:], (uint256))));
            } else if (func == iResolver.dnsRecord.selector) {
                /// @dev : TODO, use latest ENS codes/ENSIP for DNS records
                (bytes32 _name, uint16 resource) = abi.decode(data[36:], (bytes32, uint16));
                _jsonPath =
                    string.concat("_dns/0x", bytesToString(abi.encodePacked(_name), 0), "/", uintToString(resource));
            } else {
                revert ResolverFunctionNotImplemented(func);
            }
            if (_ipns.length == 0) {
                revert ContenthashNotSet(_namehash);
            }
            n = block.number - 1;
            bytes32 _checkHash = keccak256(abi.encodePacked(THIS, blockhash(n), msg.sender, _domain, _jsonPath));
            revert OffchainLookup(
                THIS,
                randomGateways(
                    _ipns,
                    string.concat(
                        "f", bytesToString(_ipns, 2), "/.well-known/", _path, "/", _jsonPath, ".json?t={data}"
                    ),
                    uint256(_checkHash)
                ),
                abi.encodePacked(uint64(block.timestamp / 60) * 60),
                iCCIP.__callback.selector,
                abi.encode(
                    n,
                    _node,
                    func,
                    _domain,
                    _jsonPath,
                    _checkHash
                )
            );
        }
    }

    error ResolverFunctionNotImplemented(bytes4 func);
    /**
     * @dev callback function
     * @param response : response of HTTP call
     * @param extradata: extra data used by callback
     */

    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (
            uint256 _blocknumber,
            bytes32 _node,
            bytes4 _func,
            string memory _domain,
            string memory _jsonPath,
            bytes32 _checkHash
        ) = abi.decode(extradata, (uint256, bytes32, bytes4, string, string, bytes32));

        /// @dev: timeout in 3 blocks
        require(
            block.number <= _blocknumber + 3
                && _checkHash == keccak256(abi.encodePacked(THIS, blockhash(_blocknumber), msg.sender, _domain, _jsonPath)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        if (bytes4(response[:4]) == iCCIP.__callback.selector) {
            /// @dev ethers.js/CCIP reverts if the <result> is not ABI-encoded
            address _signer;
            bytes memory signature;
            (result, signature, _signer) = abi.decode(response[4:], (bytes, bytes, address));
            string memory _req = string.concat(
                "Requesting signature for off-chain ENS record\n\n",
                //"IMPORTANT: Please verify the integrity and authenticity of connected Off-chain ENS Records Manager before signing this message\n",
                "\nENS Domain: ",
                _domain,
                "\nRecord Type: ",
                _jsonPath,
                "\nRecord Hash: 0x",
                bytesToString(abi.encodePacked(keccak256(result)), 0),
                "\nSigned By: eip155:1:",
                toChecksumAddress(_signer)
            );
            bytes32 _digest =
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(_req).length), _req));
            if (_signer != iCCIP(THIS).signedBy(_digest, signature)) {
                revert InvalidSignature("BAD_SIGNER");
            }
            address _owner = ENS.owner(_node);
            if (isWrapper[_owner]) {
                _owner = iToken(_owner).ownerOf(uint256(_node));
            }
            require(
                _signer == _owner || manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))]
                    || manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))],
                "ONLY_OWNER/MANAGER_CAN_SIGN"
            );
        } else {
            /// TODO : make a list of $$/interface related records that MUST always be signed/eg, addr, contenthash
            /// OR disable ALL plaintext records as attackers on gateways can bypass records using plaintext.
            result = response;
        }
    }

    /**
     * @dev : uint to number string
     * @param value : uint value
     */
    function uintToString(uint256 value) public pure returns (string memory) {
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
    /// @dev : address to checksum address string

    function toChecksumAddress(address _addr) public pure returns (string memory) {
        bytes memory _buffer = abi.encodePacked(_addr);
        bytes memory result = new bytes(40); //bytes20*2
        bytes memory B16 = "0123456789ABCDEF";
        bytes memory b16 = "0123456789abcdef";
        bytes32 hash = keccak256(abi.encodePacked(bytesToString(_buffer, 0)));
        uint256 len = _buffer.length;
        uint256 high;
        uint256 low;
        for (uint256 i; i < len; i++) {
            high = uint8(_buffer[i]) / 16;
            low = uint8(_buffer[i]) % 16;
            result[i * 2] = uint8(hash[i]) / 16 > 7 ? B16[high] : b16[high];
            result[i * 2 + 1] = uint8(hash[i]) % 16 > 7 ? B16[low] : b16[low];
        }
        return string.concat("0x", string(result));
    }

    /// @dev : Resolver Management functions

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
     * @param _id : token ID to release
     */
    function safeWithdraw(address _token, uint256 _id) external {
        iToken(_token).safeTransferFrom(THIS, owner, _id);
    }
}
