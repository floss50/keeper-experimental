/* eslint-env mocha */
/* global artifacts, contract, describe, it */
const chai = require('chai')
const { assert } = chai
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

const ethers = require('ethers')
/* aws js sdk & settings */
var AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});
s3 = new AWS.S3({apiVersion: '2006-03-01'});
var params = {
  Bucket: "spectrexps",
  Key: "data.csv"
 };

const DIDRegistryLibrary = artifacts.require('DIDRegistryLibrary')
const DIDRegistry = artifacts.require('DIDRegistry')
const testUtils = require('../../helpers/utils.js')
const constants = require('../../helpers/constants.js')
let etag = "fa3dc03fc4f1a2196783a326afeec4b9"
let didRegistry

function toHex(str) {
   var hex = ''
   for(var i=0;i<str.length;i++) {
    hex += ''+str.charCodeAt(i).toString(16)
   }
   return hex
}

contract('DIDRegistry', (accounts) => {
    async function setupTest({
        owner = accounts[1]
    } = {}) {
        const didRegistryLibrary = await DIDRegistryLibrary.new()
        await DIDRegistry.link('DIDRegistryLibrary', didRegistryLibrary.address)
        const didRegistry = await DIDRegistry.new()

        await didRegistry.initialize(owner)

        return {
            didRegistry,
            owner
        }
    }

    async function getEtag({} = {}) {
      s3.headObject(params, function(err, data) {
       if (err){
         console.log(err, err.stack); // an error occurred
       } else {
         etag = data.ETag;           // successful response
         console.log("etag : " + data.ETag);           // successful response
       }
     });
    }

    describe('Register decentralised identifiers with attributes, fetch attributes by DID', () => {
        it('Should register one DID record', async () => {
            const { didRegistry } = await setupTest()
            const did = constants.did[0]
            const checksum = web3.utils.sha3(etag)
            console.log(checksum)
            const value = 'spectrexps/data.csv'
            const result = await didRegistry.registerAttribute(did, checksum, value)

            testUtils.assertEmitted(result, 1, 'DIDAttributeRegistered')

            const payload = result.logs[0].args
            assert.strictEqual(did, payload._did)
            assert.strictEqual(accounts[0], payload._owner)
            assert.strictEqual(checksum, payload._checksum)
            assert.strictEqual(value, payload._value)
        })

        it('Should register poa nodes and setup requiredSignatures', async () => {
            const { didRegistry } = await setupTest()
            await didRegistry.addVerifier(accounts[2], {from: accounts[1]})
            await didRegistry.addVerifier(accounts[3], {from: accounts[1]})
            await didRegistry.setRequiredSignatures(2, {from: accounts[1]})
        })


        it('Should run end-to-end testing', async () => {
          const { didRegistry } = await setupTest()
          const did = constants.did[0]
          const msg = await web3.utils.sha3(etag)
          const value = 'spectrexps/data.csv'
          const result = await didRegistry.registerAttribute(did, msg, value)
          console.log("msg:" + msg)
          // register verifiers
          await didRegistry.addVerifier(accounts[2], {from: accounts[1]})
          await didRegistry.addVerifier(accounts[3], {from: accounts[1]})
          await didRegistry.setRequiredSignatures(2, {from: accounts[1]})
          // owner should create a challenge
          let receipt = await didRegistry.createChallenge(did, {from: accounts[1]})
          testUtils.assertEmitted(receipt, 1, 'challengeCreated')
          // each verifier query etag from AWS and submit signatures
          const prefix = '0x'
          const hexString = Buffer.from(msg).toString('hex')
          console.log("hexString: " + hexString)

          // first verifier generates signature
          const signature = await web3.eth.sign(`${prefix}${hexString}`,  accounts[2])
          const sig = await ethers.utils.splitSignature(signature)
          const fixedMsg = `\x19Ethereum Signed Message:\n${msg.length}${msg}`
          console.log("message: " + fixedMsg)
          const fixedMsgSha = web3.utils.sha3(fixedMsg)
          console.log("hash of message: " + fixedMsgSha)

          receipt = await didRegistry.submitSignature(sig.v, sig.r, sig.s, msg, fixedMsgSha, did,  { from: accounts[2] })
          testUtils.assertEmitted(receipt, 1, 'signatureSubmitted')



          // second verifier submits signature
          const signature2 = await web3.eth.sign(`${prefix}${hexString}`,  accounts[3])
          const sig2 = await ethers.utils.splitSignature(signature2)
          const fixedMsg2 = `\x19Ethereum Signed Message:\n${msg.length}${msg}`
          const fixedMsgSha2 = web3.utils.sha3(fixedMsg2)
          receipt = await didRegistry.submitSignature(sig2.v, sig2.r, sig2.s, msg, fixedMsgSha2, did,  { from: accounts[3] })
          testUtils.assertEmitted(receipt, 1, 'signatureSubmitted')

          testUtils.assertEmitted(receipt, 1, 'challengeResolved')

          const settle = await didRegistry.isChallengeResolved(did)
          assert.strictEqual(settle, true)

        })

      })
})
