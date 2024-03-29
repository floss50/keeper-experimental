pragma solidity 0.5.3;

import 'openzeppelin-eth/contracts/token/ERC20/ERC20Capped.sol';
import 'openzeppelin-eth/contracts/token/ERC20/ERC20Detailed.sol';
import 'openzeppelin-eth/contracts/ownership/Ownable.sol';

/**
 * @title Ocean Protocol ERC20 Token Contract
 * @author Ocean Protocol Team
 *
 * @dev Implementation of the Ocean Token.
 *      TODO: OEP
 */
contract OceanToken is Ownable, ERC20Detailed, ERC20Capped {

    using SafeMath for uint256;

    /**
    * @dev OceanToken Initializer
    *      Runs only on initial contract creation.
    * @param _owner refers to the owner of the contract
    * @param _initialMinter is the first token minter added
    */
    function initialize(
        address _owner,
        address _initialMinter
    )
        external
        initializer
    {
        uint256 CAP = 1410000000;
        uint256 TOTALSUPPLY = CAP.mul(10 ** 18);

        ERC20Detailed.initialize('OceanToken', 'OCEAN', 18);
        ERC20Capped.initialize(TOTALSUPPLY, _owner);
        Ownable.initialize(_owner);

        // set initial minter, this has to be renounced after the setup!
        _addMinter(_initialMinter);
    }
}
