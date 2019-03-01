/* eslint-env mocha */
/* eslint-disable no-console */
/* global artifacts, contract, describe, it */

const chai = require('chai')
const { assert } = chai
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

const ERC20Token = artifacts.require('ERC20')
const OceanBondingCurve = artifacts.require('OceanBondingCurve')

const deployManagers = require('../../helpers/deployManagers.js')
const getBalance = require('../../helpers/getBalance.js')
const testUtils = require('../../helpers/utils.js')

const scale = 1
const gasPrice = 22000000000

contract('OceanBondingCurve', (accounts) => {
    let bondingCurve,
        oceanToken
        // didRegistry,
        // agreementStoreManager,
        // conditionStoreManager,
        // templateStoreManager

    async function setupTest({
        deployer = accounts[8],
        owner = accounts[9]
    } = {}) {
        ({
            oceanToken
            // didRegistry,
            // agreementStoreManager,
            // conditionStoreManager,
            // templateStoreManager
        } = await deployManagers(
            deployer,
            owner
        ))

        bondingCurve = await OceanBondingCurve.new()
        await bondingCurve.initialize(
            owner,
            oceanToken.address,
            { from: deployer }
        )

        return {
            owner
        }
    }

    describe('Test OceanBondingCurve', () => {
        it('Should set gas price for buy/sell tx using bonding curve', async () => {
            const { owner } = await setupTest()
            // set gasPrice for buy/sell
            await bondingCurve.setGasPrice(gasPrice, { from: owner })
            assert.strictEqual(
                (await bondingCurve.gasPrice()).toNumber(),
                gasPrice)
        })

        it('Should mint initial Ocean tokens', async () => {
            const { owner } = await setupTest()
            const alice = accounts[0]
            const initialBalance = 1000
            await oceanToken.mint(alice, initialBalance, { from: owner })
            const balance = await getBalance(oceanToken, alice)
            assert.strictEqual(balance, initialBalance)
        })

        it('Should create new bonding curve', async () => {
            await setupTest()
            const name = 'BondingToken'
            const symbol = 'BT'
            const did = testUtils.generateId()
            await bondingCurve.createBondingCurve(did, name, symbol)
            const balance = await bondingCurve.getTokenBalance(did, bondingCurve.address)
            assert.strictEqual(balance / scale, 10, 'initial balance should be 10')
        })

        it('Should buy bonded tokens by sending ocean tokens', async () => {
            const { owner } = await setupTest()
            // approve withdraw of Ocean tokens from user's wallet
            const amount = 1000000
            const did = testUtils.generateId()
            const alice = accounts[0]
            const name = 'BondingToken'
            const symbol = 'BT'
            await bondingCurve.setGasPrice(gasPrice, { from: owner })
            await bondingCurve.createBondingCurve(did, name, symbol)

            await oceanToken.mint(alice, amount, { from: owner })
            await oceanToken.approve(bondingCurve.address, amount, { from: alice })
            await bondingCurve.buy(did, amount)
            const balance = await bondingCurve.getTokenBalance(did, alice)
            console.log('bonded token balance :=', balance / scale)
            console.log(`alice buys bonded tokens at effective price of ${amount / balance} Ocean token per bonded token`)
        })

        it('Should sell bonded tokens to withdraw ocean tokens', async () => {
            const { owner } = await setupTest()
            // approve withdraw of Ocean tokens from user's wallet
            const buyAmount = 1000000
            const did = testUtils.generateId()
            const alice = accounts[0]
            const name = 'BondingToken'
            const symbol = 'BT'
            await bondingCurve.setGasPrice(gasPrice, { from: owner })
            await bondingCurve.createBondingCurve(did, name, symbol)

            await oceanToken.mint(alice, buyAmount, { from: owner })
            await oceanToken.approve(bondingCurve.address, buyAmount, { from: alice })
            let bondedBalance = await bondingCurve.getTokenBalance(did, alice)
            let oceanBalance = await getBalance(oceanToken, alice)
            console.log('bonded token balance :=', bondedBalance / scale)
            console.log('ocean token balance :=', oceanBalance / scale)

            await bondingCurve.buy(did, buyAmount)
            bondedBalance = await bondingCurve.getTokenBalance(did, alice)
            oceanBalance = await getBalance(oceanToken, alice)
            console.log('bonded token balance :=', bondedBalance / scale)
            console.log('ocean token balance :=', oceanBalance / scale)
            console.log(`alice buys bonded tokens at effective price of ${buyAmount / bondedBalance} Ocean token per bonded token`)

            const sellAmount = bondedBalance
            const tokenAddress = await bondingCurve.getTokenAddress(did)
            const erc20token = await ERC20Token.at(tokenAddress)
            await erc20token.approve(bondingCurve.address, sellAmount, { from: alice })
            await bondingCurve.sell(did, sellAmount, { from: alice })
            bondedBalance = await bondingCurve.getTokenBalance(did, alice)
            oceanBalance = await getBalance(oceanToken, alice)
            console.log('bonded token balance :=', bondedBalance / scale)
            console.log('ocean token balance :=', oceanBalance / scale)
            console.log(`alice sells bonded tokens at effective price of ${sellAmount / buyAmount} Ocean token per bonded token`)
        })
    })
})
