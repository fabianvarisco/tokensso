'use strict';

const assert = require('assert');
const crypto = require('crypto');

function verify(publicKey, data, sing) {
  assert(publicKey);
  assert(data);
  assert(sing);

  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(data);
  const result = verify.verify(publicKey, sing);
  console.log('verify result:', result);
  return result;
}

module.exports = { verify };
