// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

contract Gateway is iERC173, iGateway {
    address immutable THIS = address(this);

    /// @dev : contract owner/multisig address
    address public owner;

    /// @dev : list of gateway domain
    string[] public Gateways;

    string public PrimaryGateway = "ipfs2.eth.limo";

    mapping(bytes4 => string) public funcMap; // setter function?

    error ResolverFunctionNotImplemented(bytes4 func);

    constructor() {
        funcMap[iResolver.addr.selector] = "_address/60";
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name";
        funcMap[iResolver.contenthash.selector] = "contenthash";
        funcMap[iResolver.zonehash.selector] = "_dns/zonehash";

        owner = payable(msg.sender);

        Gateways.push("dweb.link");
        emit AddGateway("dweb.link");
        Gateways.push("ipfs.io");
        emit AddGateway("ipfs.io");
    }
    /**
     * @dev Selects and construct random gateways for CCIP resolution
     * @param _path : full path for records.json
     * @param k : pseudo random seeding
     * @return gateways : pseudo random list of gateway URLs for CCIP-Read
     * Gateway URL e.g. https://gateway.tld/ipns/f<ipns-hash-hex>/.well-known/eth/virgil/<records>.json?t1=0x0123456789
     */

    function randomGateways(bytes calldata _ipnsStr, string memory _path, uint256 k)
        public
        view
        returns (string[] memory gateways)
    {
        unchecked {
            uint256 strLen = _ipnsStr.length;
            uint256 gLen = Gateways.length;
            uint256 len = (gLen / 2) + 1;
            if (len > 5) len = 5;
            gateways = new string[](len);
            uint256 i;
            if (bytes(PrimaryGateway).length > 0) {
                //bytesToHexString(_ipns, 2);
                gateways[i++] = string.concat("https://f", string(_ipnsStr[0:strLen - 128]), ".", PrimaryGateway, _path);
            }
            while (i < len) {
                k = uint256(keccak256(abi.encodePacked(block.number * i, k)));
                gateways[i++] = string.concat("https://", Gateways[k % gLen], _path);
            }
        }
    }
    /// @dev Resolver function bytes4 selector → Off-chain record filename <name>.json

    function funcToJson(bytes calldata data) public view returns (string memory _jsonPath) {
        bytes4 func = bytes4(data[:4]);
        if (bytes(funcMap[func]).length > 0) {
            _jsonPath = funcMap[func];
        } else if (func == iResolver.text.selector) {
            _jsonPath = abi.decode(data[36:], (string));
        } else if (func == iOverloadResolver.addr.selector) {
            _jsonPath = string.concat("_address/", uintToString(abi.decode(data[36:], (uint256))));
        } else if (func == iResolver.interfaceImplementer.selector) {
            _jsonPath =
                string.concat("_interface/0x", bytesToHexString(abi.encodePacked(abi.decode(data[36:], (bytes4))), 0));
        } else if (func == iResolver.ABI.selector) {
            _jsonPath = string.concat("_abi/", uintToString(abi.decode(data[36:], (uint256))));
        } else if (func == iResolver.dnsRecord.selector) {
            /// @dev : TODO, use latest ENS codes/ENSIP for DNS records
            (bytes32 _name, uint16 resource) = abi.decode(data[36:], (bytes32, uint16));
            _jsonPath =
                string.concat("_dns/0x", bytesToHexString(abi.encodePacked(_name), 0), "/", uintToString(resource));
        } else {
            revert ResolverFunctionNotImplemented(func);
        }
        _jsonPath = string.concat(_jsonPath, ".json?t={data}");
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

    error ContenthashNotImplemented(bytes1 _type);

    function bytesToHexString(bytes memory _buffer, uint256 _start) public pure returns (string memory) {
        uint256 len = _buffer.length - _start;
        bytes memory result = new bytes((len) * 2);
        bytes memory b16 = bytes("0123456789abcdef");
        uint8 _b;
        for (uint256 i = 0; i < len; i++) {
            _b = uint8(_buffer[i + _start]);
            result[i * 2] = b16[_b / 16];
            result[i * 2 + 1] = b16[_b % 16];
        }
        return string(result);
    }

    /// @dev : Gateway Management Functions

    modifier onlyDev() {
        require(msg.sender == owner, "Only Dev");
        _;
    }

    event AddGateway(string indexed domain);
    event RemoveGateway(string indexed domain);
    event UpdateFuncFile(bytes4 _func, string _name);

    function addFuncMap(bytes4 _func, string calldata _name) external onlyDev {
        funcMap[_func] = _name;
        emit UpdateFuncFile(_func, _name);
    }

    function listAllGateways() external view returns (string[] memory list) {
        return Gateways;
    }

    /**
     * @dev Add single gateway
     * @param _domain : new gateway domain
     */

    function addGateway(string calldata _domain) external onlyDev {
        Gateways.push(_domain);
        emit AddGateway(_domain);
    }

    /**
     * @dev add multiple gateways
     * @param _domains : list of gateway domains to add
     */

    function addGateways(string[] calldata _domains) external onlyDev {
        uint256 len = _domains.length;
        for (uint256 i = 0; i < len; i++) {
            Gateways.push(_domains[i]);
            emit AddGateway(_domains[i]);
        }
    }

    /**
     * @dev Remove single gateway
     * @param _index : gateway index to remove
     */
    function removeGateway(uint256 _index) external onlyDev {
        require(Gateways.length > 1, "Last Gateway");
        emit RemoveGateway(Gateways[_index]);
        Gateways[_index] = Gateways[Gateways.length - 1];
        Gateways.pop();
    }

    /**
     * @dev Remove gateways from the list
     * @param _indexes : gateway index to remove
     */
    function removeGateways(uint256[] memory _indexes) external onlyDev {
        uint256 len = _indexes.length;
        require(Gateways.length > len, "Last Gateway");
        for (uint256 i = 0; i < len; i++) {
            emit RemoveGateway(Gateways[_indexes[i]]);
            Gateways[_indexes[i]] = Gateways[Gateways.length - 1];
            Gateways.pop();
        }
    }

    /**
     * @dev Replace single gateway
     * @param _index : gateway index to replace
     * @param _domain : new gateway domain.tld
     */
    function replaceGateway(uint256 _index, string calldata _domain) external onlyDev {
        emit RemoveGateway(Gateways[_index]);
        Gateways[_index] = _domain;
        emit AddGateway(_domain);
    }

    /**
     * @dev Replace multiple gateways
     * @param _indexes : gateway index to replace
     * @param _domains : new gateway domain.tld
     */
    function replaceGateways(uint256[] calldata _indexes, string[] calldata _domains) external onlyDev {
        uint256 len = _indexes.length;
        require(len == _domains.length, "Bad input lengths");
        for (uint256 i = 0; i < len; i++) {
            emit RemoveGateway(Gateways[_indexes[i]]);
            Gateways[_indexes[i]] = _domains[i];
            emit AddGateway(_domains[i]);
        }
    }
    /**
     * Transfer ownership of resolver contract
     * @param _newOwner : address of new multisig
     */

    function transferOwnership(address _newOwner) external onlyDev {
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /**
     * @dev withdraw Ether to owner
     */
    function withdraw() external {
        payable(owner).transfer(THIS.balance);
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
