/* eslint-env mocha */
/* eslint-disable no-console */
/* global artifacts, contract, describe, it */

const chai = require('chai')
const { assert } = chai
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

const SimpleStakeLottery = artifacts.require('SimpleStakeLottery')

const constants = require('../../helpers/constants.js')
const deployConditions = require('../../helpers/deployConditions.js')
const deployManagers = require('../../helpers/deployManagers.js')
const getBalance = require('../../helpers/getBalance.js')
const testUtils = require('../../helpers/utils.js')

contract('Lottery', (accounts) => {
    let oceanToken,
        didRegistry,
        agreementStoreManager,
        conditionStoreManager,
        templateStoreManager,
        signCondition,
        lockRewardCondition,
        escrowReward,
        lottery

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
            signCondition,
            lockRewardCondition,
            escrowReward
        } = await deployConditions(
            deployer,
            owner,
            agreementStoreManager,
            conditionStoreManager,
            oceanToken
        ))

        lottery = await SimpleStakeLottery.new({ from: deployer })
        await lottery.methods['initialize(address,address,address,address)'](
            owner,
            conditionStoreManager.address,
            agreementStoreManager.address,
            oceanToken.address,
            { from: deployer }
        )

        await oceanToken.addMinter(lottery.address, { from: owner })
        await templateStoreManager.proposeTemplate(accounts[0])
        await templateStoreManager.approveTemplate(accounts[0], { from: owner })

        return {
            deployer,
            owner
        }
    }

    async function prepareStakeAgreement({
        agreementId = testUtils.generateId(),
        staker = accounts[0],
        stakeAmount = 1000,
        stakePeriod = 5,
        // uses signature as release, could also be hash of secret
        sign = constants.condition.sign.bytes32,
        did = constants.did[0],
        url = constants.registry.url,
        checksum = constants.bytes32.one
    } = {}) {
        // generate IDs from attributes

        const conditionIdSign = await signCondition.generateId(agreementId, await signCondition.hashValues(sign.message, sign.publicKey))
        const conditionIdLock = await lockRewardCondition.generateId(agreementId, await lockRewardCondition.hashValues(escrowReward.address, stakeAmount))
        const conditionIdEscrow = await escrowReward.generateId(agreementId, await escrowReward.hashValues(stakeAmount, staker, staker, conditionIdLock, conditionIdSign))

        // construct agreement
        const agreement = {
            did: did,
            conditionTypes: [
                signCondition.address,
                lockRewardCondition.address,
                escrowReward.address
            ],
            conditionIds: [
                conditionIdSign,
                conditionIdLock,
                conditionIdEscrow
            ],
            timeLocks: [stakePeriod, 0, 0],
            timeOuts: [0, 0, 0]
        }
        return {
            agreementId,
            agreement,
            stakeAmount,
            stakePeriod,
            sign,
            checksum,
            url
        }
    }

    async function fulfillStake(
        agreementId,
        agreement,
        staker,
        stakeAmount,
        stakePeriod,
        sign,
        oceanToken,
        agreementStoreManager,
        conditionStoreManager
    ) {
        // prepare: stake agreement
        // create agreement: as approved account - not for production ;)
        await agreementStoreManager.createAgreement(agreementId, ...Object.values(agreement), { from: accounts[0] })
        await oceanToken.approve(lockRewardCondition.address, stakeAmount, { from: staker })
        await lockRewardCondition.fulfill(agreementId, escrowReward.address, stakeAmount, { from: staker })
        await signCondition.fulfill(agreementId, sign.message, sign.publicKey, sign.signature, { from: staker })
        await escrowReward.fulfill(agreementId, stakeAmount, staker, staker, agreement.conditionIds[1], agreement.conditionIds[0], { from: staker })
        assert.strictEqual(
            (await conditionStoreManager.getConditionState(agreement.conditionIds[2])).toNumber(),
            constants.condition.state.fulfilled
        )
    }

    describe('buy lottery tickets', () => {
        it('correct buy should get data, agreement & conditions', async () => {
            const { owner } = await setupTest()

            const initialBalance = 1000
            const plays = 1

            // prepare: stake agreement
            const { checksum, url, agreement } =
                await prepareStakeAgreement()

            // register DID
            await didRegistry.registerAttribute(agreement.did, checksum, url)

            let participants = {}
            for (const participant of accounts) {
                participants[participant] = {
                    wins: [0],
                    tickets: [],
                    stake: []
                }
            }
            /* eslint-disable-next-line no-unused-vars */
            for (const play of [...Array(plays).keys()]) {
                for (const participant of Object.keys(participants)) {
                    const ticket = Math.floor(Math.random() * Math.floor(initialBalance / plays))
                    const { agreementId, stakeAmount, stakePeriod, sign, agreement } = await prepareStakeAgreement(
                        {
                            stakeAmount: ticket,
                            staker: participant,
                            stakePeriod: 2
                        })

                    await oceanToken.mint(participant, stakeAmount, { from: owner })
                    await fulfillStake(agreementId, agreement, participant, stakeAmount, stakePeriod, sign, oceanToken, agreementStoreManager, conditionStoreManager)

                    await lottery.betStake(agreementId, stakeAmount, { from: participant })
                    // saving some statistics
                    participants[participant].stake.push(stakeAmount)
                    participants[participant].tickets.push((await lottery.getTicket.call({ from: participant, gas: 200000 })).toNumber())
                }
                const pot = (await lottery.getTotalTicketSize.call({ gas: 200000 })).toNumber()
                await lottery.drawLottery()
                // saving some statistics
                participants[await lottery.winner()].wins.push(pot)
            }
            // statistics
            for (const participant of Object.keys(participants)) {
                const sumTickets = participants[participant].tickets.reduce((partialSum, a) => partialSum + a)
                const sumStake = participants[participant].stake.reduce((partialSum, a) => partialSum + a)
                const sumWins = participants[participant].wins.reduce((partialSum, a) => partialSum + a)
                const numWins = participants[participant].wins.length - 1
                participants[participant] = {
                    numWins,
                    wins: sumWins,
                    tickets: sumTickets,
                    stake: sumStake,
                    winPerTicket: sumWins / sumTickets,
                    balance: await getBalance(oceanToken, participant)
                }
            }
            // console.log(participants)
            assert.strictEqual(await getBalance(oceanToken, lottery.address), 0)
        })
    })
})
