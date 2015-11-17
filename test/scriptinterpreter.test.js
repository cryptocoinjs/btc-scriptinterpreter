var ScriptInterpreter = require('../').ScriptInterpreter
var Script = require('btc-script');
var binConv = require('binstring');
var Transaction = require('btc-transaction').Transaction
var BigInt = require('bigi')
var sha256 = require('sha256')
var ecdsa = require('ecdsa')
var async = require('async')
var assert = require('chai').assert
require('terst')

var fixtures = require('./fixtures')

describe('ScriptInterpreter', function() {
  describe('Valid transactions:', function() {
    fixtures.valid.forEach(function (fixture, testIndex) {
      it('Should return true on valid transactions', function (done) {
        var txBuffer = binConv(fixture.tx, { in : 'hex',
          out: 'buffer'
        })
        var tx = Transaction.deserialize(txBuffer)
        var previousOutputs = fixture.previousOutputs
        var hashType = 0
        async.eachSeries(tx.ins, function (input, cb) {
          var inputIndex = tx.ins.indexOf(input)
          var txid = input.outpoint.hash
          var index = input.outpoint.index
          var prevOut = previousOutputs[inputIndex]
          var scriptSig = input.script
          var scriptPubkey = new Script(prevOut)
          ScriptInterpreter.verify(scriptSig, scriptPubkey, tx, inputIndex, hashType, function (err, result) {
            if (err) {
              console.error(testIndex, err)
              return cb(err)
            }
            if (!result)  {
              return cb('Input '+inputIndex+' not verified.')
            }
            // console.log('Input '+inputIndex+' '+result+'.')
            cb()
          })
        },
        function (err) {
          if (err) return done(err)
          return done()
        })
      })  
    })
  })
 
  describe('Invalid transactions:', function() {
    fixtures.invalid.forEach(function (fixture) {
      it('Should return false on invalid transactions', function (done) {
        var txBuffer = binConv(fixture.tx, { in : 'hex',
          out: 'buffer'
        })
        var tx = Transaction.deserialize(txBuffer)
        var previousOutputs = fixture.previousOutputs
        var hashType = 0
        async.each(tx.ins, function (input, cb) {
          var inputIndex = tx.ins.indexOf(input)
          var txid = input.outpoint.hash
          var index = input.outpoint.index
          var prevOut = previousOutputs[inputIndex]
          var scriptSig = input.script
          var scriptPubkey = new Script(prevOut)
          ScriptInterpreter.verify(scriptSig, scriptPubkey, tx, inputIndex, hashType, function (err, result) {
            if (err) {
              return cb(err)
            }
            if (!result)  {
              return cb('Input '+inputIndex+' not verified.')
            }
            // console.log('Input '+inputIndex+' '+result+'.')
            cb()
          })
        },
        function (err) {
          assert.isNotNull(err, 'there was an error')
          return done()
        })
      })  
    })
  })
})
