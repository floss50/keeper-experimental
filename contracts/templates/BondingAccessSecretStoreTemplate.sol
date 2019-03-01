pragma solidity 0.5.3;

import './AgreementTemplate.sol';
import '../conditions/AccessSecretStoreCondition.sol';
import '../conditions/LockBondingCondition.sol';
import '../conditions/ReleaseBondingCondition.sol';
import '../bondingcurves/OceanBondingCurve.sol';
import '../registry/DIDRegistry.sol';

contract BondingAccessSecretStoreTemplate is AgreementTemplate {

    DIDRegistry internal didRegistry;
    AccessSecretStoreCondition internal accessSecretStoreCondition;
    LockBondingCondition internal lockBondingCondition;
    ReleaseBondingCondition internal releaseBondingCondition;
    OceanBondingCurve internal oceanBondingCurve;

    AgreementData internal agreementData;

    struct AgreementDataModel {
        address accessConsumer;
        address accessProvider;
    }

    struct AgreementData {
        mapping(bytes32 => AgreementDataModel) agreementDataItems;
        bytes32[] agreementIds;
    }

    function initialize(
        address _owner,
        address _agreementStoreManagerAddress,
        address _didRegistryAddress,
        address _accessSecretStoreConditionAddress,
        address _lockBondingConditionAddress,
        address _releaseBondingConditionAddress,
        address _oceanBondingCurveAddress
    )
        external
        initializer()
    {
        require(
            _owner != address(0) &&
            _agreementStoreManagerAddress != address(0) &&
            _didRegistryAddress != address(0) &&
            _accessSecretStoreConditionAddress != address(0) &&
            _lockBondingConditionAddress != address(0) &&
            _releaseBondingConditionAddress != address(0) &&
            _oceanBondingCurveAddress != address(0),
            'Invalid address'
        );
        Ownable.initialize(_owner);

        agreementStoreManager = AgreementStoreManager(
            _agreementStoreManagerAddress
        );
        didRegistry = DIDRegistry(
            _didRegistryAddress
        );
        accessSecretStoreCondition = AccessSecretStoreCondition(
            _accessSecretStoreConditionAddress
        );
        lockBondingCondition = LockBondingCondition(
            _lockBondingConditionAddress
        );
        releaseBondingCondition = ReleaseBondingCondition(
            _releaseBondingConditionAddress
        );
        oceanBondingCurve = OceanBondingCurve(
            _oceanBondingCurveAddress
        );

        conditionTypes.push(address(accessSecretStoreCondition));
        conditionTypes.push(address(lockBondingCondition));
        conditionTypes.push(address(releaseBondingCondition));
    }

    function createAgreement(
        bytes32 _id,
        bytes32 _did,
        bytes32[] memory _conditionIds,
        uint[] memory _timeLocks,
        uint[] memory _timeOuts,
        address _accessConsumer
    )
        public
        returns (uint size)
    {
        super.createAgreement(
            _id,
            _did,
            _conditionIds,
            _timeLocks,
            _timeOuts
        );
        oceanBondingCurve.createBondingCurve(_did, 'aaa', 'AAA');
        return agreementData.agreementIds.length;
    }
}
