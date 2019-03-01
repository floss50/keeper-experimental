/* eslint-env mocha */
/* eslint-disable no-console */
/* global artifacts, contract, describe, it, expect */

const chai = require('chai')
const { assert } = chai
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

const LockBondingCondition = artifacts.require('LockBondingCondition')
const ReleaseBondingCondition = artifacts.require('ReleaseBondingCondition')
const OceanBondingCurve = artifacts.require('OceanBondingCurve')
const BondingAccessSecretStoreTemplate = artifacts.require('BondingAccessSecretStoreTemplate')
const ERC20Token = artifacts.require('ERC20')

const constants = require('../../helpers/constants.js')
const deployConditions = require('../../helpers/deployConditions.js')
const deployManagers = require('../../helpers/deployManagers.js')
const getBalance = require('../../helpers/getBalance.js')
const increaseTime = require('../../helpers/increaseTime.js')

const scale = 1
const gasPrice = 22000000000

contract('Escrow Access Secret Store integration test', (accounts) => {
    let oceanToken,
        didRegistry,
        agreementStoreManager,
        conditionStoreManager,
        templateStoreManager,
        lockBondingCondition,
        releaseBondingCondition,
        oceanBondingCurve,
        accessSecretStoreCondition,
        bondingAccessSecretStoreTemplate

    async function setupTest({
        deployer = accounts[8],
        owner = accounts[9]
    } = {}) {
        ({
            oceanToken,
            didRegistry,
            agreementStoreManager,
            conditionStoreManager,
            templateStoreManager
        } = await deployManagers(
            deployer,
            owner
        ));

        ({
            accessSecretStoreCondition
        } = await deployConditions(
            deployer,
            owner,
            agreementStoreManager,
            conditionStoreManager,
            oceanToken
        ))

        oceanBondingCurve = await OceanBondingCurve.new()
        await oceanBondingCurve.initialize(
            owner,
            oceanToken.address,
            { from: deployer }
        )
        await oceanBondingCurve.setGasPrice(gasPrice, { from: owner })

        lockBondingCondition = await LockBondingCondition.new()
        await lockBondingCondition.initialize(
            owner,
            conditionStoreManager.address,
            oceanBondingCurve.address,
            { from: deployer }
        )

        releaseBondingCondition = await ReleaseBondingCondition.new()
        await releaseBondingCondition.initialize(
            owner,
            conditionStoreManager.address,
            oceanBondingCurve.address,
            { from: deployer }
        )

        bondingAccessSecretStoreTemplate = await BondingAccessSecretStoreTemplate.new()
        await bondingAccessSecretStoreTemplate.methods['initialize(address,address,address,address,address,address,address)'](
            owner,
            agreementStoreManager.address,
            didRegistry.address,
            accessSecretStoreCondition.address,
            lockBondingCondition.address,
            releaseBondingCondition.address,
            oceanBondingCurve.address,
            { from: deployer }
        )

        // propose and approve template
        const templateId = bondingAccessSecretStoreTemplate.address
        await templateStoreManager.proposeTemplate(templateId)
        await templateStoreManager.approveTemplate(templateId, { from: owner })

        return {
            // templateId,
            owner
        }
    }

    async function prepareBondingCurveAgreement({
        agreementId = constants.bytes32.one,
        sender = accounts[0],
        receiver = accounts[1],
        bondingAmount = 100000,
        timeLockAccess = 0,
        timeOutAccess = 0,
        timeLockBond = 0,
        did = constants.did[0],
        url = constants.registry.url,
        checksum = constants.bytes32.one
    } = {}) {
        // generate IDs from attributes
        const conditionIdAccess = await accessSecretStoreCondition.generateId(agreementId, await accessSecretStoreCondition.hashValues(did, sender))
        const conditionIdLock = await lockBondingCondition.generateId(agreementId, await lockBondingCondition.hashValues(did, bondingAmount))
        const conditionIdRelease = await releaseBondingCondition.generateId(agreementId, await releaseBondingCondition.hashValues(did))

        // construct agreement
        const agreement = {
            did: did,
            conditionIds: [
                conditionIdAccess,
                conditionIdLock,
                conditionIdRelease
            ],
            timeLocks: [timeLockAccess, 0, timeLockBond],
            timeOuts: [timeOutAccess, 0, 0],
            consumer: sender
        }
        return {
            agreementId,
            agreement,
            sender,
            receiver,
            bondingAmount,
            timeLockAccess,
            timeOutAccess,
            timeLockBond,
            checksum,
            url
        }
    }

    describe('create and fulfill bonding curve agreement', () => {
        it('should create bonding curve agreement and fulfill', async () => {
            const { owner } = await setupTest()

            // prepare: bonding curve agreement
            const { agreementId, agreement, sender, receiver, bondingAmount, timeLockBond, checksum, url } =
                await prepareBondingCurveAgreement({ timeLockBond: 10 })

            // register DID
            await didRegistry.registerAttribute(agreement.did, checksum, url, { from: receiver })

            // create agreement
            await bondingAccessSecretStoreTemplate.createAgreement(agreementId, ...Object.values(agreement))

            // check state of agreement and conditions
            expect((await agreementStoreManager.getAgreement(agreementId)).did)
                .to.equal(agreement.did)

            // fill up wallet
            await oceanToken.mint(sender, bondingAmount, { from: owner })
            // fulfill lock bonding
            await oceanToken.approve(oceanBondingCurve.address, bondingAmount, { from: sender })
            await lockBondingCondition.fulfill(agreementId, agreement.did, bondingAmount, { from: sender })
            let bondedBalance = await oceanBondingCurve.getTokenBalance(agreement.did, sender)
            let oceanBalance = await getBalance(oceanToken, sender)
            console.log('bonded token balance :=', bondedBalance / scale)
            console.log('ocean token balance :=', oceanBalance / scale)
            console.log(`sender buys bonded tokens at effective price of ${bondingAmount / bondedBalance} Ocean token per bonded token`)

            // fulfill access
            await accessSecretStoreCondition.fulfill(agreementId, agreement.did, sender, { from: receiver })

            // sell bonds
            const sellAmount = bondedBalance
            const tokenAddress = await oceanBondingCurve.getTokenAddress(agreement.did)
            const erc20token = await ERC20Token.at(tokenAddress)
            await erc20token.approve(oceanBondingCurve.address, sellAmount, { from: sender })

            await assert.isRejected(
                releaseBondingCondition.fulfill(agreementId, agreement.did, sellAmount, { from: sender }),
                constants.condition.epoch.error.isTimeLocked
            )
            await increaseTime(timeLockBond)
            await releaseBondingCondition.fulfill(agreementId, agreement.did, sellAmount, { from: sender })
            bondedBalance = await oceanBondingCurve.getTokenBalance(agreement.did, sender)
            oceanBalance = await getBalance(oceanToken, sender)
            console.log('bonded token balance :=', bondedBalance / scale)
            console.log('ocean token balance :=', oceanBalance / scale)
            console.log(`alice sells bonded tokens at effective price of ${sellAmount / bondingAmount} Ocean token per bonded token`)
        })

        it('should create bonding curve agreement, multi-bond and withdraw', async () => {
            const { owner } = await setupTest()

            // prepare: bonding curve agreement
            const { agreementId, agreement, sender, receiver, bondingAmount, timeLockBond, checksum, url } =
                await prepareBondingCurveAgreement({ timeLockBond: 20 })

            // register DID
            await didRegistry.registerAttribute(agreement.did, checksum, url, { from: receiver })

            // create agreement
            await bondingAccessSecretStoreTemplate.createAgreement(agreementId, ...Object.values(agreement))
            const tokenAddress = await oceanBondingCurve.getTokenAddress(agreement.did)
            const didToken = await ERC20Token.at(tokenAddress)

            const seedAmount = bondingAmount
            // receiver: fill up wallet
            await oceanToken.mint(receiver, seedAmount, { from: owner })
            // receiver: put some bonded tokens in there
            await oceanToken.approve(oceanBondingCurve.address, seedAmount, { from: receiver })

            console.log('receiver buys for ', seedAmount)
            await oceanBondingCurve.buy(agreement.did, seedAmount, { from: receiver })
            console.log('OCEAN curve := ', await getBalance(oceanToken, oceanBondingCurve.address))
            console.log('OCEAN sender := ', await getBalance(oceanToken, sender))
            console.log('OCEAN receiver := ', await getBalance(oceanToken, receiver))
            console.log('DROPS curve := ', (await didToken.totalSupply()).toNumber())
            console.log('DROPS sender := ', (await oceanBondingCurve.getTokenBalance(agreement.did, sender)).toNumber())
            console.log('DROPS receiver := ', (await oceanBondingCurve.getTokenBalance(agreement.did, receiver)).toNumber())

            // sender: fill up wallet
            await oceanToken.mint(sender, bondingAmount, { from: owner })
            // fulfill lock bonding
            await oceanToken.approve(oceanBondingCurve.address, bondingAmount, { from: sender })

            console.log('sender buys for ', bondingAmount)
            await lockBondingCondition.fulfill(agreementId, agreement.did, bondingAmount, { from: sender })
            console.log('OCEAN curve := ', await getBalance(oceanToken, oceanBondingCurve.address))
            console.log('OCEAN sender := ', await getBalance(oceanToken, sender))
            console.log('OCEAN receiver := ', await getBalance(oceanToken, receiver))
            console.log('DROPS curve := ', (await didToken.totalSupply()).toNumber())
            console.log('DROPS sender := ', (await oceanBondingCurve.getTokenBalance(agreement.did, sender)).toNumber())
            console.log('DROPS receiver := ', (await oceanBondingCurve.getTokenBalance(agreement.did, receiver)).toNumber())

            // fulfill access
            await accessSecretStoreCondition.fulfill(agreementId, agreement.did, sender, { from: receiver })

            // sell bonds
            let senderBalance = (await oceanBondingCurve.getTokenBalance(agreement.did, sender)).toNumber()
            let receiverBalance = (await oceanBondingCurve.getTokenBalance(agreement.did, receiver)).toNumber()
            await didToken.approve(oceanBondingCurve.address, receiverBalance, { from: receiver })
            await didToken.approve(oceanBondingCurve.address, senderBalance, { from: sender })
            await assert.isRejected(
                releaseBondingCondition.fulfill(agreementId, agreement.did, senderBalance, { from: sender }),
                constants.condition.epoch.error.isTimeLocked
            )

            console.log('receiver sells for ', receiverBalance)
            await oceanBondingCurve.sell(agreement.did, receiverBalance, { from: receiver })
            console.log('OCEAN curve := ', await getBalance(oceanToken, oceanBondingCurve.address))
            console.log('OCEAN sender := ', await getBalance(oceanToken, sender))
            console.log('OCEAN receiver := ', await getBalance(oceanToken, receiver))
            console.log('DROPS curve := ', (await didToken.totalSupply()).toNumber())
            console.log('DROPS sender := ', (await oceanBondingCurve.getTokenBalance(agreement.did, sender)).toNumber())
            console.log('DROPS receiver := ', (await oceanBondingCurve.getTokenBalance(agreement.did, receiver)).toNumber())

            await increaseTime(timeLockBond)
            console.log('sender sells for ', senderBalance)
            await releaseBondingCondition.fulfill(agreementId, agreement.did, senderBalance, { from: sender })
            console.log('OCEAN curve := ', await getBalance(oceanToken, oceanBondingCurve.address))
            console.log('OCEAN sender := ', await getBalance(oceanToken, sender))
            console.log('OCEAN receiver := ', await getBalance(oceanToken, receiver))
            console.log('DROPS curve := ', (await didToken.totalSupply()).toNumber())
            console.log('DROPS sender := ', (await oceanBondingCurve.getTokenBalance(agreement.did, sender)).toNumber())
            console.log('DROPS receiver := ', (await oceanBondingCurve.getTokenBalance(agreement.did, receiver)).toNumber())
        })
    })
})
