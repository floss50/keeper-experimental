pragma solidity 0.5.3;

import './DIDRegistryLibrary.sol';
import 'openzeppelin-eth/contracts/ownership/Ownable.sol';
import 'openzeppelin-eth/contracts/math/SafeMath.sol';
/**
 * @title DID Registry
 * @author Ocean Protocol Team
 *
 * @dev Implementation of the DID Registry.
 *      https://github.com/oceanprotocol/OEPs/tree/master/7#registry
 */
contract DIDRegistry is Ownable {
    using SafeMath for uint256;
    /**
     * @dev The DIDRegistry Library takes care of the basic storage functions.
     */
    using DIDRegistryLibrary for DIDRegistryLibrary.DIDRegisterList;

    /**
     * @dev state storage for the DID registry
     */
    DIDRegistryLibrary.DIDRegisterList internal didRegisterList;

    // registry of verifiers for decentralized data availability proof
    mapping (address => bool) internal verifiers;
    uint256 internal verifierCount;
    uint256 internal _requiredSignatures;

    struct challenge {
        address  owner;
        uint256  confirms;
        bool     finished;
        mapping (address => bool) voted;
    }
    mapping (bytes32 => challenge) did2challenge;

    // modifier
    modifier onlyVerifier() {
        require(
            verifiers[msg.sender] == true,
            'Invalid verifier'
        );
        _;
    }

    /**
     * @dev This implementation does not store _value on-chain,
     *      but emits DIDAttributeRegistered events to store it in the event log.
     */
    event DIDAttributeRegistered(
        bytes32 indexed _did,
        address indexed _owner,
        bytes32 indexed _checksum,
        string _value,
        address _lastUpdatedBy,
        uint256 _blockNumberUpdated
    );

    /**
     * @dev DIDRegistry Initializer
     *      Initialize Ownable. Only on contract creation.
     * @param _owner refers to the owner of the contract.
     */
    function initialize(
        address _owner
    )
        public
        initializer
    {
        Ownable.initialize(_owner);
    }

    /**
     * @notice Register DID attributes.
     *
     * @dev The first attribute of a DID registered sets the DID owner.
     *      Subsequent updates record _checksum and update info.
     *
     * @param _did refers to decentralized identifier (a bytes32 length ID).
     * @param _checksum includes a one-way HASH calculated using the DDO content.
     * @param _value refers to the attribute value, limited to 2048 bytes.
     * @return the size of the registry after the register action.
     */
    function registerAttribute (
        bytes32 _did,
        bytes32 _checksum,
        string memory _value
    )
        public
        returns (uint size)
    {
        require(
            didRegisterList.didRegisters[_did].owner == address(0x0) ||
            didRegisterList.didRegisters[_did].owner == msg.sender,
            'Attributes must be registered by the DID owners.'
        );
        require(
            //TODO: 2048 should be changed in the future
            bytes(_value).length <= 2048,
            'Invalid value size'
        );
        didRegisterList.update(_did, _checksum);

        /* emitting _value here to avoid expensive storage */
        emit DIDAttributeRegistered(
            _did,
            didRegisterList.didRegisters[_did].owner,
            _checksum,
            _value,
            msg.sender,
            block.number
        );

        return getDIDRegistrySize();
    }

    /**
     * @param _did refers to decentralized identifier (a bytes32 length ID).
     * @return last modified (update) block number of a DID.
     */
    function getBlockNumberUpdated(bytes32 _did)
        external view
        returns(uint updateAt)
    {
        return didRegisterList.didRegisters[_did].blockNumberUpdated;
    }

    /**
     * @param _did refers to decentralized identifier (a bytes32 length ID).
     * @return the address of the DID owner.
     */
    function getDIDOwner(bytes32 _did)
        external view
        returns(address didOwner)
    {
        return didRegisterList.didRegisters[_did].owner;
    }

    /**
     * @return the length of the DID registry.
     */
    function getDIDRegistrySize()
        public
        view
        returns (uint size)
    {
        return didRegisterList.didRegisterIds.length;
    }

    /**
     * @return the checksum of the DID registry.
     */
     function getDIDChecksum(bytes32 _did)
         public view
         returns(bytes32 checksum)
     {
         return didRegisterList.didRegisters[_did].lastChecksum;
     }

    /************  Verification Functions ************/

    /**
     * @dev owner add a new verifier
     */
     event VerifierAdded(address indexed _verifier);
     function addVerifier(address _verifier)
     external onlyOwner
     {
        require(_verifier != address(0));
        require(verifiers[_verifier] == false);
        verifiers[_verifier] = true;
        verifierCount = verifierCount.add(1);
        emit VerifierAdded(_verifier);
    }

    /**
     * @dev owner removes a new verifier
     */
     event VerifierRemoved(address indexed _verifier);
     function removeVerifier(address _verifier)
     external onlyOwner
     {
        require(_verifier != address(0));
        require(verifiers[_verifier] == true);
        verifiers[_verifier] = false;
        verifierCount = verifierCount.sub(1);
        emit VerifierRemoved(_verifier);
    }

    /**
     * @dev owner set required Signatures
     */
    event RequiredSignaturesChanged(uint256 _requiredSignatures);
    function setRequiredSignatures(uint256 requiredSignatures)
    external onlyOwner
    {
        require(verifierCount >= requiredSignatures);
        require(requiredSignatures != 0);
        _requiredSignatures = requiredSignatures;
        emit RequiredSignaturesChanged(_requiredSignatures);
    }

    /**
     * @dev create a verification challenge for dataset
     */
     event challengeCreated(bytes32 indexed _did);
     function createChallenge(bytes32 _did)
     external onlyOwner
     {
         require(didRegisterList.didRegisters[_did].owner != address(0), 'did is not valid');
         require(did2challenge[_did].owner == address(0) || did2challenge[_did].finished == true, 'allow to challenge');
         did2challenge[_did] = challenge({
             owner: msg.sender,
             confirms : 0,
             finished : false
             });
         emit challengeCreated(_did);
     }

     event signatureSubmitted(bytes32 indexed _did);
     event signatureConfirmed(bytes32 indexed _did);
     event challengeResolved(bytes32 indexed _did);

     function submitSignature(uint8 v, bytes32 r, bytes32 s, bytes32 checksum, bytes32 msgHash, bytes32 _did)
     public onlyVerifier
     {
         // ensure that `signature` is really `message` signed by `msg.sender`
         require(did2challenge[_did].owner != address(0) && did2challenge[_did].finished == false, 'challenge allows submission');
         require(msg.sender == ecrecover(msgHash, v, r, s));

         // log the signature
         did2challenge[_did].voted[msg.sender] = true;
         // verify checksum against on-chain record
         if(checksum == getDIDChecksum(_did)){
            did2challenge[_did].confirms = did2challenge[_did].confirms.add(1);
            emit signatureConfirmed(_did);
            // check whether enough signatures collected or not
            if(did2challenge[_did].confirms >= _requiredSignatures){
                did2challenge[_did].finished = true;
                emit challengeResolved(_did);
            }
         }

         emit signatureSubmitted(_did);
     }

    /************  View Functions ************/

    /**
     * @dev query the state of challenge
     */
    function isChallengeResolved(bytes32 _did) public view returns(bool) {
        return did2challenge[_did].finished;
    }

    /**
     * @dev query the requiredSignatures
     */
    function requiredSignatures() public view returns(uint256) {
        return _requiredSignatures;
    }
}
