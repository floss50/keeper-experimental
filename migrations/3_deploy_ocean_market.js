/* global artifacts */
const OceanToken = artifacts.require('OceanToken.sol')
const OceanMarket = artifacts.require('OceanMarket.sol')
const { saveDefinition } = require('./helper')

const deployOceanMarket = async (deployer, network) => {
    const tokenAddress = OceanToken.address

    await deployer.deploy(
        OceanMarket,
        tokenAddress
    )

    saveDefinition(network, OceanMarket)
}

module.exports = deployOceanMarket
