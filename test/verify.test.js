
'use strict';

require('dotenv').config();
const verify = require('../verify.js');
const pkh = require('../publicKeyHelper.js');
const auth = require('./auth.mock.js');

test('verify', () => {
  const publicKey = auth.publicKey;
  expect.anything(publicKey);

  const data1 = 'something to sign and verify';
  const signature1 = auth.sign(data1);

  const data2 = data1 + 'x';
  const signature2 = auth.sign(data2);

  for (var i = 0; i < 4; i++) {
    expect(verify.verify(publicKey, data1, signature1)).toBeTruthy();

    expect(verify.verify(publicKey, data1, signature2)).toBeFalsy();

    expect(verify.verify(publicKey, data2, signature1)).toBeFalsy();

    expect(verify.verify(publicKey, data2, signature2)).toBeTruthy();
  }

  const publicKeyFromEnv = pkh.fromEnv();
  expect.anything(publicKeyFromEnv);
  expect(verify.verify(publicKeyFromEnv, data1, signature1)).toBeFalsy();
  expect(verify.verify(publicKeyFromEnv, data2, signature2)).toBeFalsy();
});
