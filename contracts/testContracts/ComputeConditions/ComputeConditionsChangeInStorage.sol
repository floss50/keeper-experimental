pragma solidity 0.4.25;

import '../../SEA/ComputeConditions.sol';
import 'zos-lib/contracts/Initializable.sol';


contract ComputeConditionsChangeInStorage is ComputeConditions {
    // keep track of how many times a function was called.
    mapping (address=>uint256) public called;
}