// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

/**
 * @title CCIP2ETH Gateway Manager
 * @author freetib.eth, sshmatrix.eth [https://github.com/namesys-eth]
 * Github : https://github.com/namesys-eth/ccip2-eth-resolver
 * Docs : https://ccip2.eth.limo
 * Client : https://namesys.eth.limo
 */
contract GatewayManager is iERC173, iGatewayManager {
    /// @dev - Events
    event Web3GatewayUpdated(string indexed _domain);
    event Web3GatewayRemoved(string indexed _domain);
    event Web2GatewayUpdated(string indexed _domain);
    event Web2GatewayRemoved(string indexed _domain);
    event FuncMapUpdated(bytes4 _func, string _name);

    /// @dev - Errors
    error ContenthashNotImplemented(bytes1 _type);
    error InvalidRequest(string _message);
    error FeatureNotImplemented(bytes4 func);

    /// @dev - Contract owner/multisig address
    address public owner;

    /// @dev - Modifer to allow only dev/admin access
    modifier onlyDev() {
        require(msg.sender == owner, "ONLY_DEV");
        _;
    }

    address immutable THIS = address(this);
    /// @dev - Primary IPFS gateway domain, ipfs2.eth.limo
    string public PrimaryGateway = "ipfs2.eth.limo";
    /// @dev - List of secondary gateway domains (default)
    string[] public Web3Gateways;
    /// @dev - List of web2 or L2 service gateway domains (fallback)
    string[] public Web2Gateways;
    /// @dev - Resolver function bytes4 selector → Off-chain record filename <name>.json
    mapping(bytes4 => string) public funcMap;

    /// @dev - Constructor
    constructor() {
        /// @dev - Set owner of contract
        owner = payable(msg.sender);
        /// @dev - Define all default records
        funcMap[iResolver.addr.selector] = "address/60";
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name";
        funcMap[iResolver.contenthash.selector] = "contenthash";
        funcMap[iResolver.zonehash.selector] = "dns/zonehash";
        /// @dev - Set initial list of secondary gateways
        Web3Gateways.push("dweb.link");
        emit Web3GatewayUpdated("dweb.link");
        Web3Gateways.push("ipfs.io");
        emit Web3GatewayUpdated("ipfs.io");
        Web2Gateways.push("ccip.namesys.xyz");
        emit Web2GatewayUpdated("ccip.namesys.xyz");
    }

    /**
     * @dev Selects and construct random gateways for CCIP resolution
     * @param _recordhash - Global recordhash for record storage
     * @param _path - Full path for <record>.json
     * @param seed - Pseudo-random seeding
     * @return gateways - Pseudo-random list of gateway URLs for CCIP-Read
     * Gateway URL e.g. https://gateway.tld/ipns/fe501017200...51735c/.well-known/eth/virgil/avatar.json?t=0x0123456789
     */
    function randomGateways(bytes memory _recordhash, string memory _path, uint256 seed)
        public
        view
        returns (string[] memory gateways)
    {
        /// @dev Filter IPNS versus Web2 gateway
        if (_recordhash.length == 0) {
            /// Default L2 or web2 Service fallback
            uint256 gateLen = Web2Gateways.length;
            gateways = new string[](gateLen);
            while (gateLen > 0) {
                --gateLen;
                gateways[gateLen] = string.concat(string("https://"), Web2Gateways[gateLen], _path, ".json?t={data}");
            }
            return gateways;
        } else if (_recordhash[0] == bytes1("h") && iGatewayManager(this).isWeb2(_recordhash)) {
            /// Trusted web2 gateway set by the owner
            gateways = new string[](1);
            gateways[0] = string.concat(string(_recordhash), _path, ".json?t={data}");
            return gateways;
        } else if (_recordhash.length == 32) {
            /// Short IPNS hash set by owner
            _recordhash = abi.encodePacked(hex"e5010172002408011220", _recordhash);
        }
        unchecked {
            uint256 gLen = Web3Gateways.length;
            uint256 len = (gLen / 2) + 2;
            if (len > 3) len = 3;
            gateways = new string[](len + 1);
            uint256 i;
            if (bytes(PrimaryGateway).length > 0) {
                gateways[i++] = string.concat(
                    "https://",
                    iGatewayManager(this).formatSubdomain(_recordhash),
                    ".",
                    PrimaryGateway,
                    _path,
                    ".json?t={data}"
                );
            }
            string memory _fullPath;
            bytes1 _prefix = _recordhash[0];
            if (_prefix == 0xe2) {
                _fullPath = string.concat(
                    "/api/v0/dag/get?arg=f",
                    bytesToHexString(_recordhash, _recordhash[1] == 0xe5 ? 3 : 2),
                    _path,
                    ".json?t={data}&format=dag-cbor"
                );
            } else if (_prefix == 0xe5) {
                _fullPath = string.concat("/ipns/f", bytesToHexString(_recordhash, 2), _path, ".json?t={data}");
            } else if (_prefix == 0xe3) {
                _fullPath = string.concat("/ipfs/f", bytesToHexString(_recordhash, 2), _path, ".json?t={data}");
            } else if (_prefix == bytes1("k")) {
                _fullPath = string.concat("/ipns/", string(_recordhash), _path, ".json?t={data}");
            } else if (_prefix == bytes1("b")) {
                _fullPath = string.concat("/ipfs/", string(_recordhash), _path, ".json?t={data}");
            } else {
                revert InvalidRequest("BAD_RECORDHASH");
            }
            while (i < len) {
                seed = uint256(keccak256(abi.encodePacked(block.number * i, seed)));
                gateways[i++] = string.concat("https://", Web3Gateways[seed % gLen], _fullPath);
            }
            gateways[len] = string.concat("https://", Web2Gateways[0], _fullPath); // Fallback
        }
    }

    /**
     * Note - Future Feature in CCIP2-v2
     */
    function __fallback(bytes calldata response, bytes calldata extradata) external view returns (bytes memory) {
        this;
        response;
        extradata;
        revert FeatureNotImplemented(iGatewayManager.__fallback.selector);
    }

    /**
     * @dev Checks if recordhash is a web2 gateway
     * @param _recordhash - Recordhash to check
     * @return - Bool
     */
    function isWeb2(bytes calldata _recordhash) external pure returns (bool) {
        return (bytes8(_recordhash[:8]) == bytes8("https://"));
    }

    /**
     * @dev Converts queried resolver function to off-chain record filename
     * @param data - Full path for <record>.json
     * @return _jsonPath - Path to the JSON file containing the queried record
     */
    function funcToJson(bytes calldata data) public view returns (string memory _jsonPath) {
        bytes4 func = bytes4(data[:4]);
        if (bytes(funcMap[func]).length > 0) {
            _jsonPath = funcMap[func];
        } else if (func == iResolver.text.selector) {
            (, string memory _key) = abi.decode(data[4:], (bytes32, string));
            _jsonPath = string.concat("text/", _key);
        } else if (func == iOverloadResolver.addr.selector) {
            _jsonPath = string.concat("address/", uintToString(abi.decode(data[36:], (uint256))));
        } else if (func == iResolver.interfaceImplementer.selector) {
            _jsonPath =
                string.concat("interface/0x", bytesToHexString(abi.encodePacked(abi.decode(data[36:], (bytes4))), 0));
        } else if (func == iResolver.ABI.selector) {
            _jsonPath = string.concat("abi/", uintToString(abi.decode(data[36:], (uint256))));
        } else if (func == iResolver.dnsRecord.selector || func == iOverloadResolver.dnsRecord.selector) {
            // e.g. .well-known/eth/domain/dns/<record>.json
            uint256 resource;
            if (data.length == 100) {
                // 4 + 32 + 32 + 32 = 100
                (resource) = abi.decode(data[68:], (uint256)); // Expect uint16
            } else {
                (,, resource) = abi.decode(data[4:], (bytes32, bytes, uint256));
            }
            _jsonPath = string.concat("dns/", uintToString(resource));
        } else {
            revert FeatureNotImplemented(func);
        }
    }

    /**
     * @dev Converts overflowing recordhash to valid subdomain label
     * @param _recordhash - Overflowing recordhash to convert
     * @return result - Valid subdomain label
     * Note - Compatible with *.ipfs2.eth.limo gateway only
     */
    function formatSubdomain(bytes calldata _recordhash) public pure returns (string memory result) {
        if (_recordhash[0] == bytes1("k") || _recordhash[0] == bytes1("b")) {
            return string(_recordhash);
        }
        uint256 len = _recordhash.length;
        uint256 pointer = len % 16;
        result = string.concat(bytesToHexString(_recordhash[:pointer], 0));
        while (pointer < len) {
            result = string.concat(result, ".", bytesToHexString(_recordhash[pointer:pointer += 16], 0));
        }
    }

    /**
     * @dev Converts uint type to string
     * @param value - Input uint value
     * @return - Output string-formatted uint
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

    /**
     * @dev Converts address to check-summed address string
     * @param _addr - Input address to convert
     * @return - Check-summed address; string-formatted
     */
    function toChecksumAddress(address _addr) public pure returns (string memory) {
        bytes memory _buffer = abi.encodePacked(_addr);
        bytes memory result = new bytes(40); //bytes20 * 2
        bytes memory B16 = "0123456789ABCDEF";
        bytes memory b16 = "0123456789abcdef";
        bytes32 hash = keccak256(abi.encodePacked(bytesToHexString(_buffer, 0)));
        uint256 high;
        uint256 low;
        for (uint256 i; i < 20; i++) {
            high = uint8(_buffer[i]) / 16;
            low = uint8(_buffer[i]) % 16;
            result[i * 2] = uint8(hash[i]) / 16 > 7 ? B16[high] : b16[high];
            result[i * 2 + 1] = uint8(hash[i]) % 16 > 7 ? B16[low] : b16[low];
        }
        return string.concat("0x", string(result));
    }

    /**
     * @dev Convert range of bytes to hex-formatted string
     * @param _buffer - Bytes buffer to convert
     * @param _start - Index to start conversion at (continues till the end)
     * @return - Output hex-formatted string
     */
    function bytesToHexString(bytes memory _buffer, uint256 _start) public pure returns (string memory) {
        uint256 len = _buffer.length - _start;
        bytes memory result = new bytes((len) * 2);
        bytes memory b16 = bytes("0123456789abcdef");
        uint8 _b;
        for (uint256 i = 0; i < len; i++) {
            _b = uint8(_buffer[i + _start]);
            result[i * 2] = b16[_b / 16];
            result[(i * 2) + 1] = b16[_b % 16];
        }
        return string(result);
    }

    /**
     * @dev Convert bytes32 to hex-formatted string
     * @param _buffer - Bytes32 buffer to convert
     * @return - Output hex-formatted string
     */
    function bytes32ToHexString(bytes32 _buffer) public pure returns (string memory) {
        bytes memory result = new bytes(64);
        bytes memory b16 = bytes("0123456789abcdef");
        uint8 _b;
        for (uint256 i = 0; i < 32; i++) {
            _b = uint8(_buffer[i]);
            result[i * 2] = b16[_b / 16];
            result[(i * 2) + 1] = b16[_b % 16];
        }
        return string(result);
    }

    /// @dev - Gateway Management Functions
    /**
     * @dev Adds a new record type by adding its bytes4 → filename mapping
     * @param _func - Selector bytes4 of new record type to add
     * @param _name - Label function; must start with "/" and string-formatted
     */
    function addFuncMap(bytes4 _func, string calldata _name) external onlyDev {
        funcMap[_func] = _name;
        emit FuncMapUpdated(_func, _name);
    }

    /**
     * @dev Shows list of web3 gateways
     * @return - List of web3 gateways
     */
    function listWeb3Gateways() external view returns (string[] memory) {
        return Web3Gateways;
    }

    /**
     * @dev Add a single web3 gateway
     * @param _domain - New web3 gateway domain to add
     */
    function addWeb3Gateway(string calldata _domain) external onlyDev {
        Web3Gateways.push(_domain);
        emit Web3GatewayUpdated(_domain);
    }

    /**
     * @dev Remove a single web3 gateway
     * @param _index - Gateway index to remove
     */
    function removeWeb3Gateway(uint256 _index) external onlyDev {
        if (Web3Gateways.length == 1) {
            revert InvalidRequest("LAST_GATEWAY");
        }
        emit Web3GatewayRemoved(Web3Gateways[_index]); // Emit first
        Web3Gateways[_index] = Web3Gateways[Web3Gateways.length - 1]; // Update later
        Web3Gateways.pop();
    }

    /**
     * @dev Replace a single web3 gateway
     * @param _index : Gateway index to replace
     * @param _domain : New gateway domain.tld
     */
    function replaceWeb3Gateway(uint256 _index, string calldata _domain) external onlyDev {
        emit Web3GatewayRemoved(Web3Gateways[_index]); // Emit first
        Web3Gateways[_index] = _domain; // Update later
        emit Web3GatewayUpdated(_domain);
    }

    /**
     * @dev Shows list of web2 gateways
     * @return - List of web2 gateways
     */
    function listWeb2Gateways() external view returns (string[] memory) {
        return Web2Gateways;
    }

    /**
     * @dev Add a single gateway
     * @param _domain - New gateway domain to add
     */
    function addWeb2Gateway(string calldata _domain) external onlyDev {
        Web2Gateways.push(_domain);
        emit Web2GatewayUpdated(_domain);
    }
    /**
     * @dev Remove a single web2 gateway
     * @param _index - Gateway index to remove
     */

    function removeWeb2Gateway(uint256 _index) external onlyDev {
        if (Web2Gateways.length == 1) {
            revert InvalidRequest("LAST_GATEWAY");
        }
        emit Web2GatewayRemoved(Web2Gateways[_index]);
        Web2Gateways[_index] = Web2Gateways[Web2Gateways.length - 1];
        Web2Gateways.pop();
    }

    /**
     * @dev Replace a single web2 gateway
     * @param _index : Gateway index to replace
     * @param _domain : New gateway domain.tld
     */
    function replaceWeb2Gateway(uint256 _index, string calldata _domain) external onlyDev {
        emit Web2GatewayRemoved(Web2Gateways[_index]); // Emit first
        Web2Gateways[_index] = _domain; // Update later
        emit Web2GatewayUpdated(_domain);
    }

    /**
     * @dev Transfer ownership of resolver contract
     * @param _newOwner - Address of new owner/multisig
     */
    function transferOwnership(address _newOwner) external onlyDev {
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /**
     * @dev Withdraw Ether to owner
     * Note - To be used for tips or in case some Ether gets locked in the contract
     */
    function withdraw() external {
        payable(owner).transfer(THIS.balance);
    }

    /**
     * @dev Withdraw ERC20 token to owner
     * Note To be used for tips or in case some fungible tokens get locked in the contract
     * @param _tokenContract - Token contract address
     * @param _balance - Token amount to release
     */
    function withdraw(address _tokenContract, uint256 _balance) external {
        iToken(_tokenContract).transferFrom(THIS, owner, _balance);
    }

    /**
     * @dev Withdraw ERC721 token to owner
     * Note To be used for tips or in case some non-fungible tokens get locked in the contract
     * @param _tokenContract - Token contract address
     * @param _tokenID - TokenID to release
     */
    function safeWithdraw(address _tokenContract, uint256 _tokenID) external {
        iToken(_tokenContract).safeTransferFrom(THIS, owner, _tokenID);
    }
}
