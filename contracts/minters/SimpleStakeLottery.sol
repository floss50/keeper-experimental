pragma solidity 0.5.3;

import 'openzeppelin-eth/contracts/math/SafeMath.sol';
import 'openzeppelin-eth/contracts/ownership/Ownable.sol';

import '../agreements/AgreementStoreManager.sol';
import '../conditions/ConditionStoreLibrary.sol';
import '../OceanToken.sol';

contract SimpleStakeLottery is Ownable {

    using SafeMath for uint256;
    using SafeMath for uint;

    OceanToken internal token;
    AgreementStoreManager internal agreementStoreManager;
    ConditionStoreManager internal conditionStoreManager;

    TicketList internal ticketList;
    uint256 public random;
    address public winner;
    mapping(bytes32 => bool) internal stakedAgreements;

    struct TicketList {
        mapping(address => uint256) tickets;
        address[] participants;
    }

    function initialize(
        address _owner,
        address _conditionStoreManagerAddress,
        address _agreementStoreManagerAddress,
        address _tokenAddress
    )
        external
        initializer()
    {
        require(
            _tokenAddress != address(0) &&
            _conditionStoreManagerAddress != address(0) &&
            _agreementStoreManagerAddress != address(0),
            'Invalid address'
        );
        Ownable.initialize(_owner);
        conditionStoreManager = ConditionStoreManager(
            _conditionStoreManagerAddress
        );
        agreementStoreManager = AgreementStoreManager(
            _agreementStoreManagerAddress
        );
        token = OceanToken(_tokenAddress);
    }

    function betStake(
        bytes32 _agreementId,
        uint256 _stakeAmount
    )
        external
    {
        require(
            stakedAgreements[_agreementId] == false,
            'Agreement already staked'
        );
        address templateId;
        bytes32[] memory conditionIds;
        ConditionStoreLibrary.ConditionState state;
        uint timeLock;
        address typeRef;

        (,,templateId, conditionIds,,) = agreementStoreManager
            .getAgreement(_agreementId);

        // check if escrowAgreement.reward is fulfilled
        require(
            conditionStoreManager.getConditionState(conditionIds[2]) ==
            ConditionStoreLibrary.ConditionState.Fulfilled,
            'Stake not fulfilled'
        );

        // get the timeLock of the release condition
        (,,timeLock,,,,) = conditionStoreManager
            .getCondition(conditionIds[0]);
        // get the type and state of the reward condition
        (typeRef,state,,,,,) = conditionStoreManager
            .getCondition(conditionIds[2]);

        // integrity check on the values supplied
        // must be a escrowReward configured as stake agreement
        bytes32 generatedId = keccak256(
            abi.encodePacked(
                _agreementId,
                typeRef,
                keccak256(
                    abi.encodePacked(
                        _stakeAmount,
                        msg.sender,
                        msg.sender,
                        conditionIds[1],
                        conditionIds[0]
                    )
                )
            )
        );
        require(
            generatedId == conditionIds[2],
            'Id does not match'
        );

        if (ticketList.tickets[msg.sender] == 0)
            ticketList.participants.push(msg.sender);
        // amount of lottery tickets generated ~ time staked
        ticketList.tickets[msg.sender] += _stakeAmount * timeLock;
        stakedAgreements[_agreementId] = true;
    }

    function probablyPoorPseudoRandom(uint256 max)
        public
        view
        returns (uint256)
    {
        // TODO: find a better random number generator
        // generate a random integer between 0 and max
        return uint256(blockhash(block.number-1)) % max;
    }

    function drawLottery() external {
        // TODO: only draw when totalTicket > threshold
        // get total size of tickets
        uint256 totalTicketSize = getTotalTicketSize();
        // choose a random number between 0 and totalTicket
        random = probablyPoorPseudoRandom(totalTicketSize);

        // reset the winner
        winner = address(0);

        // find the participant with ticket number == random
        uint256 aggregateTicket = 0;
        for (uint256 i = 0; i < ticketList.participants.length; i++) {
            aggregateTicket += ticketList.tickets[ticketList.participants[i]];
            // aggregate > random, so first occurance is flipping point
            if (winner == address(0) && aggregateTicket > random) {
                winner = ticketList.participants[i];
            }
            // clean up tickets for next lottery
            delete ticketList.tickets[ticketList.participants[i]];
        }
        // clean up participants for next lottery
        address[] memory newList;
        ticketList.participants = newList;

        // TODO: mint proportional to governed faucet
        // mint amount of tokens proportional to totalTicket
        require(
            token.mint(winner, totalTicketSize),
            'Could not mint token'
        );
    }

    function getTotalTicketSize() public view returns (uint256) {
        uint256 totalTicketSize = 0;
        for (uint256 i = 0; i < ticketList.participants.length; i++) {
            totalTicketSize += ticketList.tickets[ticketList.participants[i]];
        }
        return totalTicketSize;
    }

    function getTicket() public view returns (uint256) {
        return ticketList.tickets[msg.sender];
    }
}



