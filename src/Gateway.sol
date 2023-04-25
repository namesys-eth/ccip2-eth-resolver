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

    /// @dev : list of gateway domain
    string[] public Gateways;

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
        for (uint256 i; i < len;) {
            k = uint256(keccak256(abi.encodePacked(k, msg.sender))) % gLen;
            gateways[i++] = string.concat("https://", Gateways[k], _ipns[0] == 0xe5 ? "/ipns/" : "/ipfs/", _path);
        }
    }

    error ContenthashNotImplemented(bytes1 _type);

    function bytesToString(bytes memory _buffer, uint256 _start) public pure returns (string memory) {
        uint256 len = _buffer.length;
        bytes memory result = new bytes((len - _start) * 2);
        bytes memory b16 = "0123456789abcdef";
        for (uint256 i = _start; i < len; i++) {
            result[i * 2] = b16[uint8(_buffer[i]) / 16];
            result[i * 2 + 1] = b16[uint8(_buffer[i]) % 16];
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
        //if (Gateways.length > _index + 1) {
        Gateways[_index] = Gateways[Gateways.length - 1];
        //}
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
            //if (Gateways.length > _indexes[i] + 1) {
            Gateways[_indexes[i]] = Gateways[Gateways.length - 1];
            //}
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
}
