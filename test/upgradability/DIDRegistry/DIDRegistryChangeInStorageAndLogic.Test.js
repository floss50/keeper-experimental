/* eslint-env mocha */
/* global web3, artifacts, assert, contract, describe, it, before, beforeEach */

const testUtils = require('../../helpers/utils.js')
const ZeppelinHelper = require('../../helpers/ZeppelinHelper.js')

const DIDRegistry = artifacts.require('DIDRegistry')
const DIDRegistryChangeInStorageAndLogic = artifacts.require('DIDRegistryChangeInStorageAndLogic')

contract('DIDRegistry', (accounts) => {
    let zos
    let dIDRegistryAddress

    before('Restore zos before all tests', async function() {
        zos = new ZeppelinHelper('DIDRegistry')
        await zos.restoreState(accounts[9])
    })

    beforeEach('Deploy with zos before each tests', async function() {
        zos = new ZeppelinHelper('DIDRegistry')
        await zos.initialize(accounts[0], true)
        dIDRegistryAddress = zos.getProxyAddress('DIDRegistry')
    })

    describe('Test upgradability for DIDRegistry', () => {
        it('Should be possible to append storage variables and change logic', async () => {
            // register attribute
            let registry = await DIDRegistry.at(dIDRegistryAddress)
            let did = web3.utils.sha3('did:ocn:test-attr')
            const checksum = testUtils.generateId()
            const value = 'https://exmaple.com/did/ocean/test-attr-example.txt'

            let result = await registry.registerAttribute(did, checksum, value)

            testUtils.assertEmitted(result, 1, 'DIDAttributeRegistered')

            let payload = result.logs[0].args
            assert.strictEqual(did, payload.did)
            assert.strictEqual(accounts[0], payload.owner)
            assert.strictEqual(checksum, payload.checksum)
            assert.strictEqual(value, payload.value)

            // should not be possible to read storage variables before upgrade is approved
            await zos.upgradeToNewContract('DIDRegistryChangeInStorageAndLogic')
            let p = await DIDRegistryChangeInStorageAndLogic.at(dIDRegistryAddress)
            // should not be able to be called before upgrade is approved
            await testUtils.assertRevert(p.timeOfRegister(did))

            // Approve and call again
            await zos.approveLatestTransaction()
            let n = await p.timeOfRegister(did)
            assert.equal(n.toNumber(), 0, 'Error calling added storage variable')

            // check new functionality works
            did = web3.utils.sha3('did:ocn:test-attrN')
            result = await registry.registerAttribute(did, checksum, value)

            testUtils.assertEmitted(result, 1, 'DIDAttributeRegistered')

            payload = result.logs[0].args
            assert.strictEqual(did, payload.did)
            assert.strictEqual(accounts[0], payload.owner)
            assert.strictEqual(checksum, payload.checksum)
            assert.strictEqual(value, payload.value)

            await p.timeOfRegister(did).then(i => { n = i })
            assert.equal(n.toNumber() > 0, true, 'time of registry not created')
        })
    })
})