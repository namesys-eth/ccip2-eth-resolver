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
    iToken public immutable WRAPPER = iToken(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);

    /// @dev : root .eth namehash
    bytes32 public immutable roothash = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

    /// @dev default contenthash for *.eth without contenthash
    // Used only if *..eth is pointing to this resolver but no ipns hash is set
    bytes public DefaultContenthash =
        hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";

    /// @dev constructor initial setup
    constructor() {
        funcToFile[iResolver.addr.selector] = "_address/60"; // Ethereum address
        funcToFile[iResolver.pubkey.selector] = "pubkey"; // Public key
        funcToFile[iResolver.name.selector] = "name"; // Name ? Reverse
        //funcToFile[iResolver.name.selector] = "name"; // Reverse Record
        funcToFile[iResolver.contenthash.selector] = "contenthash"; // contenthash record for web contents
        funcToFile[iResolver.zonehash.selector] = "_dnsrecord/zonehash"; // Zonehash
        owner = payable(msg.sender);
        Gateways.push("dweb.link");
        emit AddGateway("dweb.link");
        Gateways.push("ipfs.io");
        emit AddGateway("ipfs.io");
    }

    /// @dev CCIP Off-chain Lookup (https://eips.ethereum.org/EIPS/eip-3668)
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
    mapping(bytes32 => address) private manager; // ?? there are multiple approved/isApprovedForAll in all ENS

    // better add as approved/ is approved for all functions?

    function approved(bytes32 node, address _signer) public view returns (bool) {
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        return manager[keccak256(abi.encodePacked("manage-one", node, _owner, _signer))] == _signer;
    }

    function approve(bytes32 node, address _signer, bool _approved) external {
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        require(_owner == msg.sender);
        manager[keccak256(abi.encodePacked("manage-one", node, _owner, _signer))] = _approved ? _signer : address(0);
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
            revert InvalidSignature("BAD_SIGNATURE");
        }
    }

    /**
     * @dev Interface Selector
     * @param interfaceID : interface identifier
     */
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (
            interfaceID == iCCIP.resolve.selector || interfaceID == iResolver.setContenthash.selector
                || interfaceID == iERC165.supportsInterface.selector
        );
    }

    modifier isAuthorized(bytes32 node) {
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        require(
            _owner == manager[keccak256(abi.encodePacked("manage-one", node, owner, msg.sender))]
                || _owner == manager[keccak256(abi.encodePacked("manage-all", owner, msg.sender))] || msg.sender == _owner,
            "ONLY_OWNER/MANAGER"
        );
        _;
    }
    /**
     * @dev sets contenthash
     * @param node : token address
     * @param _contenthash : tokenID to release
     */

    function setContenthash(bytes32 node, bytes calldata _contenthash) public {
        require(bytes4(_contenthash[:4]) == hex"e5010172" || bytes3(_contenthash[:3]) == hex"e30101", "IPFS/IPNS_ONLY");
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        require(
            msg.sender == manager[keccak256(abi.encodePacked("manage-one", node, owner, msg.sender))]
                || msg.sender == manager[keccak256(abi.encodePacked("manage-all", owner, msg.sender))]
                || msg.sender == _owner,
            "ONLY_OWNER/MANAGER"
        );
        contenthash[node] = _contenthash;
        // event
    }

    function setSubContenthash(string calldata _subName, bytes32 node, bytes calldata _contenthash) public {
        require(bytes4(_contenthash[:4]) == hex"e5010172" || bytes3(_contenthash[:3]) == hex"e30101", "IPFS/IPNS_ONLY");
        address _owner = ENS.owner(node);
        if (_owner == address(WRAPPER)) {
            _owner = WRAPPER.ownerOf(uint256(node));
        }
        bytes32 _namehash = keccak256(abi.encodePacked(node , keccak256(bytes(_subName))));
        address _sub = manager[keccak256(abi.encodePacked("manage-sub", node, _owner))];
        if (_sub != address(0)) {
            // ?check if contract/ interface?
            _owner = iToken(_sub).ownerOf(uint256(_namehash));
        }
        require(
            msg.sender == manager[keccak256(abi.encodePacked("manage-one", node, owner, msg.sender))]
                || msg.sender == manager[keccak256(abi.encodePacked("manage-all", owner, msg.sender))]
                || msg.sender == _owner,
            "ONLY_OWNER/MANAGER"
        );
        contenthash[node] = _contenthash;
        // event
    }

    /**
     * @dev core Resolve function
     * @param name : ENS name to resolve, DNS encoded
     * @param data : data encoding specific resolver function
     * @return result : data encoding specific resolver function
     */
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory) {
        uint256 index = 1; // domain level index
        uint256 n = 1; // counter
        uint256 len = uint8(bytes1(name[:1])); // length of label
        bytes[] memory _labels = new bytes[](42); // maximum 42 allowed levels in sub.sub...domain.eth
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
        // bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == roothash);
        bytes4 func = bytes4(data[:4]);

        bytes32 _node;
        bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(_labels[--index])))); // MUST be equal to roothash of '.eth'
        bytes memory _ipns; // contenthash
        while (index > 0) {
            _namehash = keccak256(abi.encodePacked(_namehash, keccak256(bytes(_labels[--index]))));
            if (contenthash[_namehash].length != 0) {
                _ipns = contenthash[_namehash];
                _node = _namehash;
            }
        }
        // require(_node == bytes32(data[4:36]), "BAD_NAMEHASH");
        //if (_ipns.length == 0) {
        //    _ipns = DefaultContenthash;
        //    _node = _namehash;
        //}
        
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
            _jsonPath = string.concat("_dns/0x", bytesToString(abi.encodePacked(_name), 0), "/", uintToString(resource));
        } else {
            revert ResolverFunctionNotImplemented(func);
        }

        // skip first two bytes from contenthash
        _path = string.concat("f", bytesToString(_ipns, 2), "/.well-known/", _path, "/", _jsonPath, ".json?");
        n = block.number - 1; // reuse n for block num
        bytes32 _checkHash = keccak256(abi.encodePacked(THIS, blockhash(n), msg.sender, _domain));
        revert OffchainLookup(
            THIS, // callback contract
            randomGateways(_ipns, _path, uint256(_checkHash)), // CCIP gateway URLs
            abi.encodePacked(uint64(block.timestamp / 60) * 60), // {data} field reused as ..json?t1=0xcachetime
            iCCIP.__callback.selector, // callback function
            abi.encode( // callback extra data
                n, // check-point
                _node, // namehash of base records
                _namehash, // sub.domain's namehash
                _domain, // string full sub/..domain.eth
                _jsonPath, // 
                _checkHash
            )
        );
        //return result;
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
            uint256 _blocknumber, // block number used for extra check
            bytes32 _node, // base domain namehash
            bytes32 _namehash, // base/sub domain namehash
            string memory _domain, // full domain.eth string
            string memory _jsonPath, // short path before .json
            bytes32 _checkHash // timeout check
        ) = abi.decode(extradata, (uint256, bytes32, bytes32, string, string, bytes32));

        /// @dev: timeout in 3 blocks
        require(
            block.number <= _blocknumber + 3
                && _checkHash == keccak256(abi.encodePacked(THIS, blockhash(_blocknumber), msg.sender, _domain)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        if (bytes4(response[:4]) == iCCIP.__callback.selector) {
            // signed result in callback
            /// @dev ethers.js/CCIP reverts if the <result> is not ABI-encoded
            address _signer;
            bytes memory signature;
            (result, signature, _signer) = abi.decode(response[4:], (bytes, bytes, address));
            string memory _req = string.concat(
                "Requesting signature for off-chain ENS record\n\nDomain: ",
                _domain,
                "\nRecord Type: ",
                _jsonPath, // short file path e.g, "_address/60", "avatar"
                "\nRecord Hash: 0x",
                bytesToString(abi.encodePacked(keccak256(result)), 0), // long abi encoded result
                "\nSigned By: eip155:1:",
                toChecksumAddress(_signer) // checksum address
            );
            bytes32 _digest =
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(_req).length), _req));
            if (_signer != iCCIP(THIS).signedBy(_digest, signature)) {
                revert InvalidSignature("BAD_SIGNER");
            }
            address _owner = ENS.owner(_node);
            if (_owner == address(WRAPPER)) {
                _owner = WRAPPER.ownerOf(uint256(_node));
            }
            address _sub = manager[keccak256(abi.encodePacked("manage-sub", _node, _owner))];
            if (_sub != address(0)) {
                // ?check if contract/ interface?
                _owner = iToken(_sub).ownerOf(uint256(_namehash));
            }
            require(
                _signer == manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))]
                    || _signer == manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))] || _signer == _owner,
                "ONLY_OWNER/MANAGER_CAN_SIGN"
            );
        } else {
            result = response; // must be pre abi-encoded in json's data:..
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
