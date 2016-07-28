var Opcode = require('btc-opcode')
var bignum = require('bigi');
var Script = require('btc-script');
var cryptoHash = require('crypto-hashing')
var ecdsa = require('ecdsa')
var Transaction = require('btc-transaction').Transaction

var binConv = require('binstring')
require('buffertools').extend();

// TODO: Move this back into script once we find a browser friendly buffer tools module
Script.prototype.findAndDelete = function(chunk) {
  var dirty = false;
  if (Buffer.isBuffer(chunk)) {
    for (var i = 0, l = this.chunks.length; i < l; i++) {
      if (Buffer.isBuffer(this.chunks[i]) &&
        this.chunks[i].compare(chunk) == 0) {
        this.chunks.splice(i, 1);
        dirty = true;
      }
    }
  } else if ("number" === typeof chunk) {
    for (var i = 0, l = this.chunks.length; i < l; i++) {
      if (this.chunks[i] === chunk) {
        this.chunks.splice(i, 1);
        dirty = true;
      }
    }
  } else {
    throw new Error("Invalid chunk datatype.");
  }

  if (dirty) {
    this.buffer = Script.fromChunks(this.chunks).buffer
  }
};
//

// Make opcodes available as pseudo-constants
for (var i in Opcode.map) {
  eval(i + " = " + Opcode.map[i] + ";");
}

var ScriptInterpreter = exports.ScriptInterpreter =
  function ScriptInterpreter() {
    this.stack = [];
    this.disableUnsafeOpcodes = true;
};

ScriptInterpreter.prototype.eval = function eval(script, tx, inIndex, hashType, callback) {
  if ("function" !== typeof callback) {
    throw new Error("ScriptInterpreter.eval() requires a callback");
  }

  var pc = 0;

  var execStack = [];
  var altStack = [];
  var hashStart = 0;
  var opCount = 0;

  if (script.buffer.length > 10000) {
    callback(new Error("Oversized script (> 10k bytes)"));
    return this;
  }

  // Start execution by running the first step
  executeStep.call(this, callback);

  function executeStep(cb) {
    // Once all chunks have been processed, execution ends
    if (pc >= script.chunks.length) {
      // Execution stack must be empty at the end of the script
      if (execStack.length) {
        cb(new Error("Execution stack ended non-empty"));
        return;
      }

      // Execution successful (Note that we still have to check whether the
      // final stack contains a truthy value.)
      cb(null);
      return;
    }

    try {
      // The execution bit is true if there are no "false" values in the
      // execution stack. (A "false" value indicates that we're in the
      // inactive branch of an if statement.)
      var exec = !~execStack.indexOf(false);

      var opcode = script.chunks[pc++];

      if (opcode.length > 520) {
        throw new Error("Max push value size exceeded (>520)");
      }

      if (opcode > OP_16 && ++opCount > 201) {
        throw new Error("Opcode limit exceeded (>200)");
      }

      if (this.disableUnsafeOpcodes &&
        "number" === typeof opcode &&
        (opcode === OP_CAT ||
          opcode === OP_SUBSTR ||
          opcode === OP_LEFT ||
          opcode === OP_RIGHT ||
          opcode === OP_INVERT ||
          opcode === OP_AND ||
          opcode === OP_OR ||
          opcode === OP_XOR ||
          opcode === OP_2MUL ||
          opcode === OP_2DIV ||
          opcode === OP_MUL ||
          opcode === OP_DIV ||
          opcode === OP_MOD ||
          opcode === OP_LSHIFT ||
          opcode === OP_RSHIFT)) {
        throw new Error("Encountered a disabled opcode");
      }

      // btc-transaction serialize into byte arrays
      if (Array.isArray(opcode)) {
        opcode = new Buffer(opcode)
      }

      if (exec && Buffer.isBuffer(opcode))
        this.stack.push(opcode);
      else
      if (exec || (OP_IF <= opcode && opcode <= OP_ENDIF))
        switch (opcode) {
          case OP_0:
            this.stack.push(new Buffer([]));
            break;

          case OP_1NEGATE:
          case OP_1:
          case OP_2:
          case OP_3:
          case OP_4:
          case OP_5:
          case OP_6:
          case OP_7:
          case OP_8:
          case OP_9:
          case OP_10:
          case OP_11:
          case OP_12:
          case OP_13:
          case OP_14:
          case OP_15:
          case OP_16:
            this.stack.push(bigintToBuffer(opcode - OP_1 + 1));
            break;

          case OP_NOP:
          case OP_NOP1:
          case OP_NOP2:
          case OP_NOP3:
          case OP_NOP4:
          case OP_NOP5:
          case OP_NOP6:
          case OP_NOP7:
          case OP_NOP8:
          case OP_NOP9:
          case OP_NOP10:
            break;

          case OP_IF:
          case OP_NOTIF:
            // <expression> if [statements] [else [statements]] endif
            var value = false;
            if (exec) {
              value = castBool(this.stackPop());
              if (opcode === OP_NOTIF) {
                value = !value;
              }
            }
            execStack.push(value);
            break;

          case OP_ELSE:
            if (execStack.length < 1) {
              throw new Error("Unmatched OP_ELSE");
            }
            execStack[execStack.length - 1] = !execStack[execStack.length - 1];
            break;

          case OP_ENDIF:
            if (execStack.length < 1) {
              throw new Error("Unmatched OP_ENDIF");
            }
            execStack.pop();
            break;

          case OP_VERIFY:
            var value = castBool(this.stackTop());
            if (value) {
              this.stackPop();
            } else {
              throw new Error("OP_VERIFY negative");
            }
            break;

          case OP_RETURN:
            throw new Error("OP_RETURN");

          case OP_TOALTSTACK:
            altStack.push(this.stackPop());
            break;

          case OP_FROMALTSTACK:
            if (altStack.length < 1) {
              throw new Error("OP_FROMALTSTACK with alt stack empty");
            }
            this.stack.push(altStack.pop());
            break;

          case OP_2DROP:
            // (x1 x2 -- )
            this.stackPop();
            this.stackPop();
            break;

          case OP_2DUP:
            // (x1 x2 -- x1 x2 x1 x2)
            var v1 = this.stackTop(2);
            var v2 = this.stackTop(1);
            this.stack.push(v1);
            this.stack.push(v2);
            break;

          case OP_3DUP:
            // (x1 x2 -- x1 x2 x1 x2)
            var v1 = this.stackTop(3);
            var v2 = this.stackTop(2);
            var v3 = this.stackTop(1);
            this.stack.push(v1);
            this.stack.push(v2);
            this.stack.push(v3);
            break;

          case OP_2OVER:
            // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
            var v1 = this.stackTop(4);
            var v2 = this.stackTop(3);
            this.stack.push(v1);
            this.stack.push(v2);
            break;

          case OP_2ROT:
            // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
            var v1 = this.stackTop(6);
            var v2 = this.stackTop(5);
            this.stack.splice(this.stack.length - 6, 2);
            this.stack.push(v1);
            this.stack.push(v2);
            break;

          case OP_2SWAP:
            // (x1 x2 x3 x4 -- x3 x4 x1 x2)
            this.stackSwap(4, 2);
            this.stackSwap(3, 1);
            break;

          case OP_IFDUP:
            // (x - 0 | x x)
            var value = this.stackTop();
            if (castBool(value)) {
              this.stack.push(value);
            }
            break;

          case OP_DEPTH:
            // -- stacksize
            var value = bignum(this.stack.length);
            this.stack.push(bigintToBuffer(value));
            break;

          case OP_DROP:
            // (x -- )
            this.stackPop();
            break;

          case OP_DUP:
            // (x -- x x)
            this.stack.push(this.stackTop());
            break;

          case OP_NIP:
            // (x1 x2 -- x2)
            if (this.stack.length < 2) {
              throw new Error("OP_NIP insufficient stack size");
            }
            this.stack.splice(this.stack.length - 2, 1);
            break;

          case OP_OVER:
            // (x1 x2 -- x1 x2 x1)
            this.stack.push(this.stackTop(2));
            break;

          case OP_PICK:
          case OP_ROLL:
            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
            var n = castInt(this.stackPop());
            if (n < 0 || n >= this.stack.length) {
              throw new Error("OP_PICK/OP_ROLL insufficient stack size");
            }
            var value = this.stackTop(n + 1);
            if (opcode === OP_ROLL) {
              this.stack.splice(this.stack.length - n - 1, 1);
            }
            this.stack.push(value);
            break;

          case OP_ROT:
            // (x1 x2 x3 -- x2 x3 x1)
            //  x2 x1 x3  after first swap
            //  x2 x3 x1  after second swap
            this.stackSwap(3, 2);
            this.stackSwap(2, 1);
            break;

          case OP_SWAP:
            // (x1 x2 -- x2 x1)
            this.stackSwap(2, 1);
            break;

          case OP_TUCK:
            // (x1 x2 -- x2 x1 x2)
            if (this.stack.length < 2) {
              throw new Error("OP_TUCK insufficient stack size");
            }
            this.stack.splice(this.stack.length - 2, 0, this.stackTop());
            break;

          case OP_CAT:
            // (x1 x2 -- out)
            var v1 = this.stackTop(2);
            var v2 = this.stackTop(1);
            this.stackPop();
            this.stackPop();
            this.stack.push(v1.concat(v2));
            break;

          case OP_SUBSTR:
            // (in begin size -- out)
            var buf = this.stackTop(3);
            var start = castInt(this.stackTop(2));
            var len = castInt(this.stackTop(1));
            if (start < 0 || len < 0) {
              throw new Error("OP_SUBSTR start < 0 or len < 0");
            }
            if ((start + len) >= buf.length) {
              throw new Error("OP_SUBSTR range out of bounds");
            }
            this.stackPop();
            this.stackPop();
            this.stack[this.stack.length - 1] = buf.slice(start, start + len);
            break;

          case OP_LEFT:
          case OP_RIGHT:
            // (in size -- out)
            var buf = this.stackTop(2);
            var size = castInt(this.stackTop(1));
            if (size < 0) {
              throw new Error("OP_LEFT/OP_RIGHT size < 0");
            }
            if (size > buf.length) {
              size = buf.length;
            }
            this.stackPop();
            if (opcode === OP_LEFT) {
              this.stack[this.stack.length - 1] = buf.slice(0, size);
            } else {
              this.stack[this.stack.length - 1] = buf.slice(buf.length - size);
            }
            break;

          case OP_SIZE:
            // (in -- in size)
            var value = bignum(this.stackTop().length);
            this.stack.push(bigintToBuffer(value));
            break;

          case OP_INVERT:
            // (in - out)
            var buf = this.stackTop();
            for (var i = 0, l = buf.length; i < l; i++) {
              buf[i] = ~buf[i];
            }
            break;

          case OP_AND:
          case OP_OR:
          case OP_XOR:
            // (x1 x2 - out)
            var v1 = this.stackTop(2);
            var v2 = this.stackTop(1);
            this.stackPop();
            this.stackPop();
            var out = new Buffer(Math.max(v1.length, v2.length));
            if (opcode === OP_AND) {
              for (var i = 0, l = out.length; i < l; i++) {
                out[i] = v1[i] & v2[i];
              }
            } else if (opcode === OP_OR) {
              for (var i = 0, l = out.length; i < l; i++) {
                out[i] = v1[i] | v2[i];
              }
            } else if (opcode === OP_XOR) {
              for (var i = 0, l = out.length; i < l; i++) {
                out[i] = v1[i] ^ v2[i];
              }
            }
            this.stack.push(out);
            break;

          case OP_EQUAL:
          case OP_EQUALVERIFY:
            //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
            // (x1 x2 - bool)
            var v1 = this.stackTop(2);
            var v2 = this.stackTop(1);
            // console.log('v1', v1)
            console.log('v1', v1.toString('hex'))
            // console.log('v2', v2)
            console.log('v2', v2.toString('hex'))
            var value = v1.compare(v2) == 0;
            // console.log('v1.compare(v2)', v1.compare(v2))
            // console.log('value', value)
            // OP_NOTEQUAL is disabled because it would be too easy to say
            // something like n != 1 and have some wiseguy pass in 1 with extra
            // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
            //if (opcode == OP_NOTEQUAL)
            //    fEqual = !fEqual;

            this.stackPop();
            this.stackPop();
            this.stack.push(new Buffer([value ? 1 : 0]));
            if (opcode === OP_EQUALVERIFY) {
              if (value) {
                this.stackPop();
              } else {
                throw new Error("OP_EQUALVERIFY negative");
              }
            }
            break;

          case OP_1ADD:
          case OP_1SUB:
          case OP_2MUL:
          case OP_2DIV:
          case OP_NEGATE:
          case OP_ABS:
          case OP_NOT:
          case OP_0NOTEQUAL:
            // (in -- out)
            var num = castBigint(this.stackTop());
            switch (opcode) {
              case OP_1ADD:
                num = num.add(bignum(1));
                break;
              case OP_1SUB:
                num = num.sub(bignum(1));
                break;
              case OP_2MUL:
                num = num.mul(bignum(2));
                break;
              case OP_2DIV:
                num = num.div(bignum(2));
                break;
              case OP_NEGATE:
                num = num.negate();
                break;
              case OP_ABS:
                num = num.abs();
                break;
              case OP_NOT:
                num = bignum(num.compareTo(bignum('0')) == 0 ? 1 : 0);
                break;
              case OP_0NOTEQUAL:
                num = bignum(num.compareTo(bignum('0')) == 0 ? 0 : 1);
                break;
            }
            this.stack[this.stack.length - 1] = bigintToBuffer(num);
            break;

          case OP_ADD:
          case OP_SUB:
          case OP_MUL:
          case OP_DIV:
          case OP_MOD:
          case OP_LSHIFT:
          case OP_RSHIFT:
          case OP_BOOLAND:
          case OP_BOOLOR:
          case OP_NUMEQUAL:
          case OP_NUMEQUALVERIFY:
          case OP_NUMNOTEQUAL:
          case OP_LESSTHAN:
          case OP_GREATERTHAN:
          case OP_LESSTHANOREQUAL:
          case OP_GREATERTHANOREQUAL:
          case OP_MIN:
          case OP_MAX:
            // (x1 x2 -- out)
            var v1 = castBigint(this.stackTop(2));
            var v2 = castBigint(this.stackTop(1));
            var num;
            switch (opcode) {
              case OP_ADD:
                num = v1.add(v2);
                break;
              case OP_SUB:
                num = v1.sub(v2);
                break;
              case OP_MUL:
                num = v1.mul(v2);
                break;
              case OP_DIV:
                num = v1.div(v2);
                break;
              case OP_MOD:
                num = v1.mod(v2);
                break;

              case OP_LSHIFT:
                if (v2.compareTo(bignum('0')) < 0 || v2.compareTo(2048) > 0) {
                  throw new Error("OP_LSHIFT parameter out of bounds");
                }
                num = v1.shiftLeft(v2);
                break;

              case OP_RSHIFT:
                if (v2.compareTo(bignum('0')) < 0 || v2.compareTo(2048) > 0) {
                  throw new Error("OP_RSHIFT parameter out of bounds");
                }
                num = v1.shiftRight(v2);
                break;

              case OP_BOOLAND:
                num = bignum((v1.compareTo(bignum('0')) != 0 && v2.compareTo(bignum('0')) != 0) ? 1 : 0);
                break;

              case OP_BOOLOR:
                num = bignum((v1.compareTo(bignum('0')) != 0 || v2.compareTo(bignum('0')) != 0) ? 1 : 0);
                break;

              case OP_NUMEQUAL:
              case OP_NUMEQUALVERIFY:
                num = bignum(v1.compareTo(v2) == 0 ? 1 : 0);
                break;

              case OP_NUMNOTEQUAL:
                ;
                num = bignum(v1.compareTo(v2) != 0 ? 1 : 0);
                break;

              case OP_LESSTHAN:
                num = bignum(v1.lt(v2) ? 1 : 0);
                break;

              case OP_GREATERTHAN:
                num = bignum(v1.gt(v2) ? 1 : 0);
                break;

              case OP_LESSTHANOREQUAL:
                num = bignum(v1.gt(v2) ? 0 : 1);
                break;

              case OP_GREATERTHANOREQUAL:
                num = bignum(v1.lt(v2) ? 0 : 1);
                break;

              case OP_MIN:
                num = (v1.lt(v2) ? v1 : v2);
                break;
              case OP_MAX:
                num = (v1.gt(v2) ? v1 : v2);
                break;
            }
            this.stackPop();
            this.stackPop();
            this.stack.push(bigintToBuffer(num));

            if (opcode === OP_NUMEQUALVERIFY) {
              if (castBool(this.stackTop())) {
                this.stackPop();
              } else {
                throw new Error("OP_NUMEQUALVERIFY negative");
              }
            }
            break;

          case OP_WITHIN:
            // (x min max -- out)
            var v1 = castBigint(this.stackTop(3));
            var v2 = castBigint(this.stackTop(2));
            var v3 = castBigint(this.stackTop(1));
            this.stackPop();
            this.stackPop();
            this.stackPop();
            var value = v1.compareTo(v2) >= 0 && v1.compareTo(v3) < 0;
            this.stack.push(bigintToBuffer(value ? 1 : 0));
            break;

          case OP_RIPEMD160:
          case OP_SHA1:
          case OP_SHA256:
          case OP_HASH160:
          case OP_HASH256:
            // (in -- hash)
            var value = this.stackPop();
            var hash;
            if (opcode === OP_RIPEMD160) {
              hash = cryptoHash.ripemd160(value);
            } else if (opcode === OP_SHA1) {
              throw "TODO: Implement sha1"
              // hash = Util.sha1(value);
            } else if (opcode === OP_SHA256) {
              hash = cryptoHash.sha256(value);
            } else if (opcode === OP_HASH160) {
              hash = cryptoHash.ripemd160(cryptoHash.sha256(value));
            } else if (opcode === OP_HASH256) {
              hash = cryptoHash.sha256.x2(value);
            }
            this.stack.push(hash);
            break;

          case OP_CODESEPARATOR:
            // Hash starts after the code separator
            hashStart = pc;
            break;

          case OP_CHECKSIG:
          case OP_CHECKSIGVERIFY:
            // (sig pubkey -- bool)
            var sig = this.stackTop(2);
            var pubkey = this.stackTop(1);

            // Get the part of this script since the last OP_CODESEPARATOR
            var scriptChunks = script.chunks.slice(hashStart);

            // Convert to binary
            var scriptCode = Script.fromChunks(scriptChunks);

            // Remove signature if present (a signature can't sign itself)
            scriptCode.findAndDelete(sig);
            // Verify signature
            checkSig(sig, pubkey, scriptCode, tx, inIndex, hashType, function(e, result) {
              try {
                var success;

                if (e) {
                  // We intentionally ignore errors during signature verification and
                  // treat these cases as an invalid signature.
                  success = false;
                } else {
                  success = result;
                }

                // Update stack
                this.stackPop();
                this.stackPop();
                this.stack.push(new Buffer([success ? 1 : 0]));
                if (opcode === OP_CHECKSIGVERIFY) {
                  if (success) {
                    this.stackPop();
                  } else {
                    throw new Error("OP_CHECKSIGVERIFY negative");
                  }
                }

                // Run next step
                executeStep.call(this, cb);
              } catch (e) {
                cb(e);
                return;
              }
            }.bind(this));

            // Note that for asynchronous opcodes we have to return here to prevent
            // the next opcode from being executed.
            return;

          case OP_CHECKMULTISIG:
          case OP_CHECKMULTISIGVERIFY:
            // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
            var keysCount = castInt(this.stackPop());
            if (keysCount < 0 || keysCount > 20) {
              throw new Error("OP_CHECKMULTISIG keysCount out of bounds");
            }
            opCount += keysCount;
            if (opCount > 201) {
              throw new Error("Opcode limit exceeded (>200)");
            }
            var keys = [];
            for (var i = 0, l = keysCount; i < l; i++) {
              keys.push(this.stackPop());
            }
            var sigsCount = castInt(this.stackPop());
            if (sigsCount < 0 || sigsCount > keysCount) {
              throw new Error("OP_CHECKMULTISIG sigsCount out of bounds");
            }
            var sigs = [];
            for (var i = 0, l = sigsCount; i < l; i++) {
              sigs.push(this.stackPop());
            }

            // The original client has a bug where it pops an extra element off the
            // stack. It can't be fixed without causing a chain split and we need to
            // imitate this behavior as well.
            this.stackPop();

            // Get the part of this script since the last OP_CODESEPARATOR
            var scriptChunks = script.chunks.slice(hashStart);

            // Convert to binary
            var scriptCode = Script.fromChunks(scriptChunks);

            // Drop the signatures, since a signature can't sign itself
            sigs.forEach(function(sig) {
              scriptCode.findAndDelete(sig);
            });

            var success = true,
              isig = 0,
              ikey = 0;
            checkMultiSigStep.call(this);

            function checkMultiSigStep() {
              try {
                if (success && sigsCount > 0) {
                  var sig = sigs[isig];
                  var key = keys[ikey];

                  checkSig(sig, key, scriptCode, tx, inIndex, hashType, function(e, result) {
                    try {
                      if (!e && result) {
                        isig++;
                        sigsCount--;
                      } else {
                        ikey++;
                        keysCount--;

                        // If there are more signatures than keys left, then too many
                        // signatures have failed
                        if (sigsCount > keysCount) {
                          success = false;
                        }
                      }

                      checkMultiSigStep.call(this);
                    } catch (e) {
                      cb(e);
                      return
                    }
                  }.bind(this));
                } else {
                  this.stack.push(new Buffer([success ? 1 : 0]));
                  if (opcode === OP_CHECKMULTISIGVERIFY) {
                    if (success) {
                      this.stackPop();
                    } else {
                      throw new Error("OP_CHECKMULTISIGVERIFY negative");
                    }
                  }

                  // Run next step
                  executeStep.call(this, cb);
                }
              } catch (e) {
                cb(e);
                return;
              }
            };

            // Note that for asynchronous opcodes we have to return here to prevent
            // the next opcode from being executed.
            return;

          default:
            throw new Error("Unknown opcode encountered");
        }

      // Size limits
      if ((this.stack.length + altStack.length) > 1000) {
        throw new Error("Maximum stack size exceeded");
      }

      // Run next step
      if (pc % 100) {
        // V8 allows for much deeper stacks than Bitcoin's scripting language,
        // but just to be safe, we'll reset the stack every 100 steps
        process.nextTick(executeStep.bind(this, cb));
      } else {
        executeStep.call(this, cb);
      }
    } catch (e) {
      // console.log("Script aborted: " +
      //   (e.message ? e : e));
      cb(e);
      return;
    }
  }
};

ScriptInterpreter.prototype.evalTwo =
  function evalTwo(scriptSig, scriptPubkey, tx, n, hashType, callback) {
    var self = this;
    var scripthash = scriptPubkey.getOutType() === 'scripthash'
    self.eval(scriptSig, tx, n, hashType, function (err) {
      if (err) {
        callback(err)
        return;
      }
      if (scripthash) {
        self.stackCopy = self.stack.map(function (elem) {return elem} )
      }
      self.eval(scriptPubkey, tx, n, hashType, function (err) {
        if (err) {
          return callback(err)
        }
        if (!scripthash) return callback()
        if (!castBool(self.stack.pop())) return callback("Eval of scriptPubkey returned false before redeemScript eval.")
        self.stack = self.stackCopy.map(function (elem) {return elem} )
        
        if (!self.stack.length) return callback("Stack cannot be empty.")
        var redeemScript = self.stackPop()
        redeemScript = new Script(redeemScript.toString('hex'))
        self.eval(redeemScript, tx, n, hashType, callback)
      });
    });
};

/**
 * Get the top element of the stack.
 *
 * Using the offset parameter this function can also access lower elements
 * from the stack.
 */
ScriptInterpreter.prototype.stackTop = function stackTop(offset) {
  offset = +offset || 1;
  if (offset < 1) offset = 1;

  if (offset > this.stack.length) {
    throw new Error('ScriptInterpreter.stackTop(): Stack underrun');
  }

  return this.stack[this.stack.length - offset];
};

/**
 * Pop the top element off the stack and return it.
 */
ScriptInterpreter.prototype.stackPop = function stackPop() {
  if (this.stack.length < 1) {
    throw new Error('ScriptInterpreter.stackTop(): Stack underrun');
  }

  return this.stack.pop();
};

ScriptInterpreter.prototype.stackSwap = function stackSwap(a, b) {
  if (this.stack.length < a || this.stack.length < b) {
    throw new Error('ScriptInterpreter.stackTop(): Stack underrun');
  }

  var s = this.stack,
    l = s.length;

  var tmp = s[l - a];
  s[l - a] = s[l - b];
  s[l - b] = tmp;
};

/**
 * Returns a version of the stack with only primitive types.
 *
 * The return value is an array. Any single byte buffer is converted to an
 * integer. Any longer Buffer is converted to a hex string.
 */
ScriptInterpreter.prototype.getPrimitiveStack = function getPrimitiveStack() {
  return this.stack.map(function(entry) {
    if (entry.length > 2) {
      return entry.slice(0).toHex();
    }
    var num = castBigint(entry);
    if (num.compareTo(-128) >= 0 && num.compareTo(127) <= 0) {
      return num.toNumber();
    } else {
      return entry.slice(0).toHex();
    }
  });
};

var castBool = ScriptInterpreter.castBool = function castBool(v) {
  for (var i = 0, l = v.length; i < l; i++) {
    if (v[i] != 0) {
      // Negative zero is still zero
      if (i == (l - 1) && v[i] == 0x80) {
        return false;
      }
      return true;
    }
  }
  return false;
};
var castInt = ScriptInterpreter.castInt = function castInt(v) {
  return parseInt(castBigint(v).toString());
};
var castBigint = ScriptInterpreter.castBigint = function castBigint(v) {
  if (!v.length) {
    return bignum(0);
  }

  // Arithmetic operands must be in range [-2^31...2^31]
  if (v.length > 4) {
    throw new Error("Bigint cast overflow (> 4 bytes)");
  }

  var w = new Buffer(v.length);
  v.copy(w);
  w.reverse();
  if (w[0] & 0x80) {
    w[0] &= 0x7f;
    return bignum.fromBuffer(w).negate();
  } else {
    // Positive number
    return bignum.fromBuffer(w);
  }
};
var bigintToBuffer = ScriptInterpreter.bigintToBuffer = function bigintToBuffer(v) {
  if ("number" === typeof v) {
    v = bignum(''+v);
  }

  var b, c;

  var cmp = v.compareTo(bignum('0'));
  if (cmp > 0) {
    b = v.toBuffer();
    if (b[0] & 0x80) {
      c = new Buffer(b.length + 1);
      b.copy(c, 1);
      c[0] = 0;
      return c.reverse();
    } else {
      return b.reverse();
    }
  } else if (cmp == 0) {
    return new Buffer([]);
  } else {
    b = v.negate().toBuffer();
    if (b[0] & 0x80) {
      c = new Buffer(b.length + 1);
      b.copy(c, 1);
      c[0] = 0x80;
      return c.reverse();
    } else {
      b[0] |= 0x80;
      return b.reverse();
    }
  }
};

ScriptInterpreter.prototype.getResult = function getResult() {
  if (this.stack.length === 0) {
    throw new Error("Empty stack after script evaluation");
  }
  if (this.stack.length !== 1) {
    throw new Error("More then one objects in the stack after script evaluation"); 
  }
  return castBool(this.stack[this.stack.length - 1]);
};

ScriptInterpreter.verify =
  function verify(scriptPubKey, txTo, n, hashType, callback) {
    console.log('verify')
    if ("function" !== typeof callback) {
      throw new Error("ScriptInterpreter.verify() requires a callback");
    }
    if (typeof txTo === 'string') {
      var txBuffer = binConv(txTo, { in : 'hex',
        out: 'buffer'
      })
      var txTo = Transaction.deserialize(txBuffer)
    }
    var scriptSig = txTo.ins[n].script
    if (typeof scriptPubKey === 'string') {
      scriptPubKey = new Script(scriptPubKey)
    }
    // Create execution environment
    var si = new ScriptInterpreter();

    // Evaluate scripts
    si.evalTwo(scriptSig, scriptPubKey, txTo, n, hashType, function (err) {
      if (err) {
        callback(err);
        return;
      }

      // Cast result to bool
      var result
      try {
        result = si.getResult();
      } catch (err) {
        callback(err);
        return;
      }

      return callback(null, result);
    });

    return si;
};

var checkSig = ScriptInterpreter.checkSig =
  function(sig, pubkey, scriptCode, tx, n, hashType, callback) {
    if (!sig.length) {
      callback(null, false);
      return;
    }

    if (hashType == 0) {
      hashType = sig[sig.length - 1];
    } else if (hashType != sig[sig.length - 1]) {
      callback(null, false);
      return;
    }
    var signature = sig.slice(0, sig.length - 1);

    try {
      // Signature verification requires a special hash procedure
      var hash = tx.hashTransactionForSignature(scriptCode, n, hashType);
      // Verify signature
      signature = ecdsa.parseSig(signature)

      var sigResult = ecdsa.verify(hash, signature, pubkey)
      callback(null, sigResult)
    } catch (err) {
      callback(null, false);
    }
};
