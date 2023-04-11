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

    /**
     * @dev Selects and construct random gateways for CCIP resolution
     * @param _ipns : name to resolve on testnet e.g. alice.eth
     * @return gateways : ordered list of gateway URLs for HTTP calls
     */

    function randomGateways(string memory _ipns, string memory _path) public view returns (string[] memory gateways) {
        uint256 gLen = Gateways.length;
        uint256 len = (gLen / 2) + 1;
        if (len > 5) len = 5;
        gateways = new string[](len);
        // pseudo random seeding
        uint256 k = uint256(keccak256(abi.encodePacked(_ipns, msg.sender, blockhash(block.number - 1))));
        for (uint256 i; i < len;) {
            k = uint256(keccak256(abi.encodePacked(k, msg.sender))) % gLen;
            // Gateway @ URL e.g. https://example.xyz/eip155:1/alice.eth/{data}
            gateways[i++] = Gateways[k]._type == 0
                ? string.concat("https://", _ipns, ".", Gateways[k].domain, "/", _path)
                : string.concat("https://", Gateways[k].domain, "/ipns/", _ipns, "/", _path);
            //string.concat("https://", Gateways[k]._domain, "/eip155", ":", chainID, "/", _ipns, "/{data}");
        }
    }

    function Base16(bytes memory _ipns) public pure returns (string memory) {
        bytes memory converted = new bytes(_ipns.length * 2);
        bytes memory _base = "0123456789abcdef";
        uint256 len = _ipns.length;
        for (uint256 i = 0; i < len; i++) {
            converted[i * 2] = _base[uint8(_ipns[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(_ipns[i]) % _base.length];
        }
        return string(abi.encodePacked("f", converted));
    }
    /// @dev : Gateway and Chain Management Functions

    modifier onlyDev() {
        require(msg.sender == owner, "Only Dev");
        _;
    }

    event AddGateway(string indexed domain, uint8 indexed _type, address indexed _dev);
    event RemoveGateway(string indexed domain, uint8 indexed _type, address indexed _dev);
    /**
     * @dev Push new gateway to the list
     * @param domain : new gateway domain
     * @param _type : type of new gateway
     */

    function addGateway(string calldata domain, uint8 _type) external onlyDev {
        Gateways.push(Gate(domain, _type));
        emit AddGateway(domain, _type, msg.sender);
    }

    /**
     * @dev Remove gateway from the list
     * @param _index : gateway index to remove
     */
    function removeGateway(uint256 _index) external onlyDev {
        require(Gateways.length > 1, "Last Gateway");
        Gate memory _g = Gateways[_index];
        unchecked {
            if (Gateways.length > _index + 1) {
                Gateways[_index] = Gateways[Gateways.length - 1];
            }
        }
        Gateways.pop();
        emit RemoveGateway(_g.domain, _g._type, msg.sender);
    }

    /**
     * @dev Replace gateway for a given controller
     * @param _index : gateway index to replace
     * @param _type : type of gateway
     * @param domain : new gateway domain
     */
    function replaceGateway(uint256 _index, string calldata domain, uint8 _type) external onlyDev {
        Gate memory _g = Gateways[_index];
        Gateways[_index] = Gate(domain, _type);
        emit AddGateway(domain, _type, msg.sender);
        emit RemoveGateway(_g.domain, _g._type, msg.sender);
    }
}
