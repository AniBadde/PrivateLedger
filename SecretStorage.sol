pragma solidity >=0.4.22 <0.7.0;

/**
 * @title Storage
 * @dev Store & retreive value in a variable
 */
contract Storage {
    
    mapping(address => bytes32) internal map;
    bytes encryptedFile;

     
    function add(address _key, bytes32 _value) public {
        map[_key] = _value;
    }
    
    function contains(address _key) public view returns (bool) {
        return map[_key] != 0;
    }
    
    function storeFile(bytes memory encFile) public {
        encryptedFile = encFile;
    }
    
    function retrieveFile() public view returns (bytes memory) {
        return encryptedFile;
    }

    /**
     * @dev Return value 
     * @return the key, mapping value
     */
    function retreiveMap(address _key) public view returns (address,bytes32){
        return (_key,map[_key]);
    }
}

