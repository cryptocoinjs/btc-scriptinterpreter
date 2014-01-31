var ScriptInterpreter = require('../').ScriptInterpreter
var Script = require('btc-script');
var binConv = require('binstring');
var Transaction = require('btc-transaction').Transaction
var BigInt = require('bigi')
var sha256 = require('sha256')

var ecdsa = require('ecdsa')

require('terst')

var exampleHex = '01000000010149c11ea99b6369dcd6cf9991fa0eb20a9501c7a348330e2db782e3884b9a2f000000008b483045022001c4c20a97cef3d2ff60bba1780409159e122a0b75eee99f87257a6ef3f5795e022100c5c0fd78408ebff9bc020a91e5f423994294efb18f50c2f496c4d35163acbb93014104e1934263e84e202ebffca95246b63c18c07cd369c4f02de76dbd1db89e6255dacb3ab1895af0422e24e1d1099e80f01b899cfcdf9b947575352dbc1af57466b5ffffffff01a0860100000000001976a914a5319d469e1ddd9558bd558a50e95f74b3da58c988ac00000000'

// --- test fixtures --
// exampleTx reference:
// tx
// https://helloblock.io/testnet/transactions/c68d98aaff4630ec37ca360b61a690796183e8a1b14cf123c00f0913eed6107f

// prevout
// https://helloblock.io/testnet/transactions/2f9a4b88e382b72d0e3348a3c701950ab20efa9199cfd6dc69639ba91ec14901
// --- test fixtures --

var prevOutScriptPubkey = '76a914cf0dfe6e0fa6ea5dda32c58ff699071b672e1faf88ac'
describe('ScriptInterpreter', function() {
  describe('', function() {
    it('', function(done) {
      var txBuffer = binConv(exampleHex, { in : 'hex',
        out: 'buffer'
      })
      var tx = Transaction.deserialize(txBuffer)

      // test variables
      var inputIndex = 0
      var hashType = 1

      var input = tx.ins[inputIndex]
      var scriptSig = input.script
      var scriptPubkey = new Script(prevOutScriptPubkey)

      ScriptInterpreter.verify(scriptSig, scriptPubkey, tx, inputIndex, hashType, function(e, result) {
        console.log(result)
        T(result, 'Tx Should be verified')
        done()
      })

    })
  })
})
