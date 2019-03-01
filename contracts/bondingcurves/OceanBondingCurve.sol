pragma solidity 0.5.3;

import './BancorFormula.sol';
import '../OceanToken.sol';
import 'openzeppelin-eth/contracts/ownership/Ownable.sol';
/**
 * @title Ocean Bonding Curve
 * @dev Ocean token holders can stake on assets
 * through bonding curves and get bonded tokens.
 */

contract OceanBondingCurve is BancorFormula, Ownable {

    using SafeMath for uint256;
    using SafeMath for uint;

    // global variables
    OceanToken public  oceanToken;
    uint256 public  scale;
    // maximum gas price for bancor transactions
    uint256 public  gasPrice;
    // determine shape of bonding curve
    uint32 private reserveRatio;

    // bonding curve struct
    struct bondingCurve {
        address creator;
        // initial virtual supply of bonded tokens to avoid numeric error
        uint256 virtualSupply;
        // total amount of Ocean tokens deposited to purchase bonded tokens
        uint256 poolBalance;
        ERC20Token bondedToken;
    }
    // lookup table from DID to corresponding bondingCurve struct
    mapping(bytes32 => bondingCurve) did2BondingCurve;
    mapping(string => bool) nameExist;
    mapping(string => bool) symbolExist;

    event bondingCurveCreated(
        address indexed _creator,
        bytes32 indexed _did
    );
    event buyBondedTokens(
        address indexed _requester,
        uint256 _amountOcean,
        uint256 _tokens
    );
    event sellBondedTokens(
        address indexed _requester,
        uint256 _amountOcean,
        uint256 _tokens
    );

    // verifies that the gas price is lower than the universal limit
    modifier validGasPrice() {
        require(
            tx.gasprice <= gasPrice,
            'Invalid gasprice'
        );
        _;
    }

    modifier validBondingCurve(bytes32 did) {
        require(
            did2BondingCurve[did].creator != address(0),
            'Invalid DID'
        );
        _;
    }

    function initialize(
        address _owner,
        address _tokenAddress
    )
        external
        initializer
    {
        require(
            _owner != address(0) &&
            _tokenAddress != address(0),
            'Invalid address'
        );
        Ownable.initialize(_owner);
        // instantiate Ocean token contract
        oceanToken = OceanToken(_tokenAddress);
        // initialize variables
        scale = 1;
        reserveRatio = 700000;
        // MAX_WEIGHT = 1000000;
        gasPrice = 0 wei;
    }

    // Testing: request initial fund transfer
    function requestTokens(uint256 amount) public returns (uint256) {
        require(address(msg.sender) != address(0));
        require(oceanToken.transfer(msg.sender, amount));
        return amount;
    }

    // create new Bonding Curve
    function createBondingCurve(
        bytes32 did,
        string memory name,
        string memory symbol
    )
        public
        returns (bool success)
    {
        // prevent multiple bonding curves for the same asset
        require(
            did2BondingCurve[did].creator == address(0),
            'there must be only one BC per did'
        );
        require(
            nameExist[name] == false && symbolExist[symbol] == false,
            'name or symbol already exists.'
        );
        require(
            did != 0x0,
            'did is not valid'
        );

        // create bonded token
        ERC20Token _token = new ERC20Token(name, symbol);
        // set caller to be bondingCurve contract only!
        _token.setCallerContract(address(this));

        // create bonding curve
        did2BondingCurve[did] = bondingCurve({
            creator : msg.sender,
            virtualSupply : 10 * scale,
            poolBalance : 1 * scale,
            bondedToken : _token
            });

        // mint virtual supply tokens
        _token.mint(address(this), did2BondingCurve[did].virtualSupply);

        // emit message
        emit bondingCurveCreated(msg.sender, did);

        // update mapping
        nameExist[name] = true;
        symbolExist[symbol] = true;
        return true;
    }

    ///////////////////////////////////////////////////////////////////
    // Bonding Curve Module
    ///////////////////////////////////////////////////////////////////
    /**
     * @dev Buy tokens
     */
    function buy(
        bytes32 _did,
        uint256 _buyAmount
    )
        validBondingCurve(_did)
        validGasPrice()
        public
        returns (bool success)
    {
        ERC20Token drops = did2BondingCurve[_did].bondedToken;
        uint256 poolBalance = did2BondingCurve[_did].poolBalance;

        // calculate the amount bonded tokens to be minted:
        uint256 tokensToMint = calculatePurchaseReturn(
            drops.totalSupply().div(scale),
            poolBalance.div(scale),
            reserveRatio,
            _buyAmount.div(scale)
        );

        // transfer Ocean tokens into contract for purchase
        require(
            oceanToken.transferFrom(
                tx.origin,
                address(this),
                _buyAmount)
        );
        did2BondingCurve[_did].poolBalance = did2BondingCurve[_did]
            .poolBalance
            .add(_buyAmount);

        // mint new bonded tokens
        drops.mint(tx.origin, tokensToMint.mul(scale));

        emit buyBondedTokens(tx.origin, _buyAmount, tokensToMint);
        return true;
    }

    /**
     * @dev Sell tokens
     * @param _sellAmount Amount of tokens to withdraw
     */
    function sell(
        bytes32 _did,
        uint256 _sellAmount
    )
        validBondingCurve(_did)
        validGasPrice()
        public
        returns (bool success)
    {
        ERC20Token drops = did2BondingCurve[_did].bondedToken;
        require(
            _sellAmount > 0 && drops.balanceOf(tx.origin) >= _sellAmount,
            'sender has not enough balance.'
        );

        // calculate amount of Ocean tokens to withdraw
        uint256 poolBalance = did2BondingCurve[_did].poolBalance;
        uint256 amountOcean = calculateSaleReturn(
            drops.totalSupply().div(scale),
            poolBalance.div(scale),
            reserveRatio,
            _sellAmount.div(scale)
        ).mul(scale);

        require(
            oceanToken.balanceOf(address(this)) >= amountOcean,
            'contract has no enough Ocean token balance.'
        );

        // burn bonded tokens
        drops.burnFrom(tx.origin, _sellAmount);

        // release Ocean tokens
        require(oceanToken.transfer(tx.origin, amountOcean));
        did2BondingCurve[_did].poolBalance = did2BondingCurve[_did]
            .poolBalance
            .sub(amountOcean);

        emit sellBondedTokens(tx.origin, amountOcean, _sellAmount);
        return true;
    }

    /**
      @dev Allows the owner to update the gas price limit
      @param _gasPrice The new gas price limit
    */
    function setGasPrice(uint256 _gasPrice) public {
        require(_gasPrice > 0);
        gasPrice = _gasPrice;
    }

    ///////////////////////////////////////////////////////////////////
    //  query function
    ///////////////////////////////////////////////////////////////////
    function getTokenBalance(bytes32 did, address account)
        validBondingCurve(did)
        public view
        returns (uint256 balance)
    {
        return did2BondingCurve[did].bondedToken.balanceOf(account);
    }

    function getTokenAddress(bytes32 did)
        validBondingCurve(did)
        public view
        returns (address)
    {
        return address(did2BondingCurve[did].bondedToken);
    }
}


contract ERC20Token is ERC20 {

    string  private _name;
    string  private _symbol;
    uint8   private _decimals;
    address private _callerContract;

    modifier validCaller(address _addr) {
        require(_addr == _callerContract && isContract(_addr));
        _;
    }

    constructor (string memory name, string memory symbol) public {
        _name = name;
        _symbol = symbol;
        _decimals = 18;
    }

    function setCallerContract(address bondingContract) public {
        require(
            _callerContract == address(0),
            'bondingCurve contract address has been initialized.'
        );
        require(
            bondingContract != address(0) && isContract(bondingContract),
            'bondingContract address is not valid'
        );
        _callerContract = bondingContract;
    }

    function isContract(address _addr) private view returns (bool) {
        uint length;
        // solium-disable-next-line security/no-inline-assembly
        assembly {length := extcodesize(_addr)}
        return length > 0;
    }
    /**
     * @dev Function to mint tokens
     * @param to The address that will receive the minted tokens.
     * @param value The amount of tokens to mint.
     * @return A boolean that indicates if the operation was successful.
     */
    function mint(
        address to,
        uint256 value
    )
        public
        validCaller(msg.sender)
        returns (bool)
    {
        _mint(to, value);
        return true;
    }

    /**
     * @dev Burns a specific amount of tokens.
     * @param value The amount of token to be burned.
     */
    function burn(uint256 value)
        public
        validCaller(msg.sender)
    {
        _burn(msg.sender, value);
    }

    /**
     * @dev Burns a specific amount of tokens from the target address
     * and decrements allowance
     * @param from address The address which you want to send tokens from
     * @param value uint256 The amount of token to be burned
     */
    function burnFrom(address from, uint256 value)
        public
        validCaller(msg.sender)
    {
        _burnFrom(from, value);
    }

}
