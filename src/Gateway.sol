// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

abstract contract Gateway {
    address immutable THIS = address(this);

    /// @dev : contract owner/multisig address
    address payable public owner;

    /// @dev : Gateway struct
    struct Gate {
        string domain; // "domain.tld" ipfs gateway
        uint8 _type; // 0 for hash.ipns.gateway.tld, >0 for gateway.tld/ipns/hash
    }

    ///
    Gate[] public Gateways;

    string[] private TEMP = ["t1", "t2", "t3", "t4", "t5"];
    /**
     * @dev Selects and construct random gateways for CCIP resolution
     * @param _ipns : name to resolve on testnet e.g. alice.eth
     * @param _path : full path for records.json
     * @param k : pseudo random seeding
     * @return gateways : pseudo random list of gateway URLs for CCIP-Read
     * Gateway URL e.g. https://gateway.tld/ipns/f<ipns-hash-hex>/.well-known/eth/virgil/<records>.json?t1=0x0123456789
     */

    function randomGateways(bytes memory _ipns, string memory _path, uint256 k)
        public
        view
        returns (string[] memory gateways)
    {
        uint256 gLen = Gateways.length;
        uint256 len = (gLen / 2) + 1;
        if (len > 5) len = 5; // max 5? make updatable max value?
        gateways = new string[](len);
        string memory _suffix = string.concat("f", bytes2HexString(_ipns, 2), "/", _path, ".json?");
        for (uint256 i; i < len;) {
            k = uint256(keccak256(abi.encodePacked(k, msg.sender))) % gLen;
            gateways[i++] = string.concat("https://", Gateways[k].domain, "/ipns/", _suffix, TEMP[i], "={data}");
        }
    }

    function bytes2HexString(bytes memory _buffer, uint256 index) public pure returns (string memory) {
        bytes memory result = new bytes(_buffer.length * 2);
        bytes memory B16 = "0123456789abcdef";
        uint256 len = _buffer.length;
        for (uint256 i = index; i < len; i++) {
            result[i * 2] = B16[uint8(_buffer[i]) / 16];
            result[i * 2 + 1] = B16[uint8(_buffer[i]) % 16];
        }
        return string(result);
    }

    /// @dev : Gateway Management Functions

    modifier onlyDev() {
        require(msg.sender == owner, "Only Dev");
        _;
    }

    event AddGateway(string indexed domain, uint8 indexed _type, address indexed _dev);
    event RemoveGateway(string indexed domain, uint8 indexed _type, address indexed _dev);
    /**
     * @dev Push new gateway to the list
     * @param _domain : new gateway domain
     * @param _type : type of new gateway
     */

    function addGateway(string calldata _domain, uint8 _type) external onlyDev {
        Gateways.push(Gate(_domain, _type));
        emit AddGateway(_domain, _type, msg.sender);
    }

    /**
     * @dev Remove gateway from the list
     * @param _index : gateway index to remove
     */
    function removeGateway(uint256 _index) external onlyDev {
        require(Gateways.length > 1, "Last Gateway");
        Gate memory _g = Gateways[_index];
        if (Gateways.length > _index + 1) {
            Gateways[_index] = Gateways[Gateways.length - 1];
        }
        Gateways.pop();
        emit RemoveGateway(_g.domain, _g._type, msg.sender);
    }

    /**
     * @dev Replace gateway for a given controller
     * @param _index : gateway index to replace
     * @param _type : type of gateway
     * @param _domain : new gateway domain.tld
     */
    function replaceGateway(uint256 _index, string calldata _domain, uint8 _type) external onlyDev {
        emit RemoveGateway(Gateways[_index].domain, Gateways[_index]._type, msg.sender);
        Gateways[_index] = Gate(_domain, _type);
        emit AddGateway(_domain, _type, msg.sender);
    }
}
